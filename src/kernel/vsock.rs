//! AF_VSOCK, as far as the Android Emulator's guest needs it: the ranchu
//! HALs reach "the host" through libqemupipe, which connects a vsock stream
//! to CID 2, port 5000, and writes the service name ("pipe:qemud:sensors"
//! and its NUL). droidrt is that host. Services it does not provide close
//! the connection, as the emulator does.
//!
//! qemud services frame each message with its length in four hex digits.
//! The clipboard pipe has binary framing, but droidrt has nothing to say on
//! it and drops what it hears.
//!
//! A guest can also listen, which is how host adb reaches adbd: the host side
//! offers connections to a port here (adb.rs).

use super::files::{File, Kind};
use super::hostio::Io;
use super::wait::EVENTS;
use super::{ERESTARTSYS, IDLE, Kernel, Thread};
use crate::arch::Sysno;
use crate::errno::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

pub const AF_VSOCK: u64 = 40;
const VMADDR_CID_HOST: u32 = 2;
const VMADDR_CID_ANY: u32 = u32::MAX;
const PIPE_PORT: u32 = 5000;
/// The guest's address, in what accept and getsockname say. adbd drops a connection
/// unless the two ends' addresses differ, and neither is CID 1.
const GUEST_CID: u32 = 3;
/// Where a host connection appears to come from.
const HOST_CLIENT_PORT: u32 = 49152;

/// Bound sockets by port.
static BOUND: LazyLock<Mutex<HashMap<u32, Weak<Vsock>>>> = LazyLock::new(Mutex::default);

pub struct Vsock {
    st: Mutex<State>,
}

/// A sockaddr_vm: family, reserved, port, cid, flags and padding.
fn sockaddr_vm(port: u32, cid: u32) -> [u8; 16] {
    let mut a = [0; 16];
    a[0..2].copy_from_slice(&(AF_VSOCK as u16).to_le_bytes());
    a[4..8].copy_from_slice(&port.to_le_bytes());
    a[8..12].copy_from_slice(&cid.to_le_bytes());
    a
}

#[derive(Default)]
struct State {
    connected: bool,
    /// The service name being written, up to its NUL.
    name: Vec<u8>,
    service: Option<Service>,
    /// Bytes for the guest to read.
    out: VecDeque<u8>,
    /// The host side closed (an unknown service): reads see EOF.
    closed: bool,
    /// Incoming qemud bytes not yet a whole frame.
    inbuf: Vec<u8>,
    bound: Option<u32>,
    /// listen(2): connections waiting for accept.
    backlog: Option<VecDeque<Arc<Io>>>,
    /// An accepted connection, rather than a pipe to a host service.
    stream: Option<Arc<Io>>,
    /// The port it was accepted on.
    local_port: u32,
}

impl Drop for Vsock {
    fn drop(&mut self) {
        let st = self.st.get_mut().unwrap();
        for io in st.backlog.iter().flatten().chain(st.stream.iter()) {
            io.close();
        }
    }
}

/// Offers a connection from the host to whoever listens on `port`. It comes back if
/// no one does yet.
pub fn offer(port: u32, io: Arc<Io>) -> Result<(), Arc<Io>> {
    let Some(listener) = BOUND.lock().unwrap().get(&port).and_then(Weak::upgrade) else { return Err(io) };
    let mut st = listener.st.lock().unwrap();
    let Some(backlog) = &mut st.backlog else { return Err(io) };
    backlog.push_back(io);
    drop(st);
    EVENTS.bump_key(Arc::as_ptr(&listener) as usize);
    Ok(())
}

/// A host service's name, and the most a message to or from a simple one can come to.
const MAX_NAME: usize = 256;
const MAX_MESSAGE: usize = 64 << 10;

enum Service {
    Sensors(Sensors),
    /// Answers a list request with an empty list.
    BootProperties,
    /// QemuMiscPipe: each message, a length and then its bytes, gets "OK" the same way.
    /// qemu-props says "heartbeat" every few seconds, and waits for the answer.
    Misc,
    /// Stays open and says nothing: a client reads until it gets what it came for,
    /// and hammers a connection that's closed. These only speak when the host has news,
    /// a change to the clipboard or a touch on the fingerprint sensor, and never does.
    Silent,
}

#[derive(Default)]
struct Sensors {
    /// Bits of the sensors the guest turned on (sensor_list.cpp order).
    enabled: u32,
    delay_ms: u64,
    streaming: bool,
}

/// What the host reports, in sensor_list.cpp bit order: accelerometer,
/// gyroscope, magnetic field, orientation, temperature, proximity, light,
/// pressure, humidity.
const SENSORS: u32 = 0x1ff;

/// A phone lying still, screen up: gravity on z, the Earth's field, room
/// light and temperature, nothing near the proximity sensor.
fn readings(enabled: u32) -> Vec<String> {
    let all: [(u32, &str); 9] = [
        (0, "acceleration:0.00:0.00:9.81"),
        (1, "gyroscope:0.00:0.00:0.00"),
        (2, "magnetic:0.00:5.90:-48.40"),
        (3, "orientation:0.00:0.00:0.00"),
        (4, "temperature:25.00"),
        (5, "proximity:1.00"),
        (6, "light:400.00"),
        (7, "pressure:1013.25"),
        (8, "humidity:50.00"),
    ];
    all.iter().filter(|(bit, _)| enabled & 1 << bit != 0).map(|(_, s)| s.to_string()).collect()
}

fn frame(out: &mut VecDeque<u8>, msg: &str) {
    out.extend(format!("{:04x}{msg}", msg.len()).bytes());
}

impl Vsock {
    pub fn new() -> Arc<Vsock> {
        Arc::new(Vsock { st: Mutex::new(State::default()) })
    }

    /// connect(2): only the emulator pipe port on the host answers.
    pub fn connect(&self, addr: &[u8]) -> Result<(), i64> {
        if addr.len() < 16 || u16::from_le_bytes([addr[0], addr[1]]) as u64 != AF_VSOCK {
            return Err(EINVAL);
        }
        let port = u32::from_le_bytes(addr[4..8].try_into().unwrap());
        let cid = u32::from_le_bytes(addr[8..12].try_into().unwrap());
        if cid != VMADDR_CID_HOST || port != PIPE_PORT {
            return Err(ECONNREFUSED);
        }
        let mut st = self.st.lock().unwrap();
        if st.connected {
            return Err(EISCONN);
        }
        st.connected = true;
        Ok(())
    }

    fn io(&self) -> Option<Arc<Io>> {
        self.st.lock().unwrap().stream.clone()
    }

    /// What a poller of this watches.
    pub fn mask(self: &Arc<Self>) -> u64 {
        use super::wait::key_bit;
        key_bit(Arc::as_ptr(self) as usize) | self.io().map_or(0, |io| key_bit(io.key()))
    }

    /// Host services' streams are always ready to take more, and a stream writes
    /// what there's room for. True if this is a stream, whose EPIPE raises SIGPIPE.
    pub fn is_stream(&self) -> bool {
        self.st.lock().unwrap().stream.is_some()
    }

    /// poll(2)'s view.
    pub fn poll(&self) -> u16 {
        use super::hostio::{POLLIN, POLLOUT};
        let st = self.st.lock().unwrap();
        if let Some(backlog) = &st.backlog {
            return if backlog.is_empty() { 0 } else { POLLIN };
        }
        if let Some(io) = &st.stream {
            return io.readiness();
        }
        POLLOUT | if !st.out.is_empty() || st.closed { POLLIN } else { 0 }
    }

    pub fn write(self: &Arc<Self>, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
        if let Some(io) = self.io() {
            return write_stream(&io, t, data, nonblock);
        }
        let mut st = self.st.lock().unwrap();
        if !st.connected {
            return Err(ENOTCONN);
        }
        if st.closed {
            return Err(EPIPE);
        }
        let mut rest = data;
        if st.service.is_none() {
            let end = rest.iter().position(|&b| b == 0);
            st.name.extend_from_slice(&rest[..end.unwrap_or(rest.len())]);
            if st.name.len() > MAX_NAME {
                st.closed = true;
                EVENTS.bump_key(Arc::as_ptr(self) as usize);
                return Ok(data.len());
            }
            let Some(end) = end else { return Ok(data.len()) };
            rest = &rest[end + 1..];
            let name = String::from_utf8_lossy(&st.name).into_owned();
            match name.as_str() {
                "pipe:qemud:sensors" => st.service = Some(Service::Sensors(Sensors { delay_ms: 200, ..Default::default() })),
                "pipe:qemud:boot-properties" => st.service = Some(Service::BootProperties),
                "pipe:QemuMiscPipe" => st.service = Some(Service::Misc),
                "pipe:clipboard" | "pipe:qemud:fingerprintlisten" => st.service = Some(Service::Silent),
                _ => {
                    eprintln!("droidrt: no host service {name}");
                    st.closed = true;
                    EVENTS.bump_key(Arc::as_ptr(self) as usize);
                    return Ok(data.len());
                }
            }
        }
        if matches!(st.service, Some(Service::Silent)) {
            return Ok(data.len());
        }
        st.inbuf.extend_from_slice(rest);
        if matches!(st.service, Some(Service::Misc)) {
            let mut at = 0;
            while st.inbuf.len() - at >= 4 {
                let len = u32::from_le_bytes(st.inbuf[at..at + 4].try_into().unwrap()) as usize;
                // Nonsense, or a client that isn't reading what it's sent: real messages
                // are a few words, and answered before the next.
                if len > MAX_MESSAGE || st.out.len() > MAX_MESSAGE {
                    st.closed = true;
                    break;
                }
                if st.inbuf.len() - at - 4 < len {
                    break;
                }
                at += 4 + len;
                st.out.extend(3u32.to_le_bytes());
                st.out.extend(b"OK\0");
            }
            st.inbuf.drain(..at);
            drop(st);
            EVENTS.bump_key(Arc::as_ptr(self) as usize);
            return Ok(data.len());
        }
        let mut start_stream = false;
        let mut at = 0;
        while st.inbuf.len() - at >= 4 {
            let len = std::str::from_utf8(&st.inbuf[at..at + 4]).ok().and_then(|h| usize::from_str_radix(h, 16).ok());
            let Some(len) = len else {
                st.closed = true; // a binary-length frame, or garbage: hang up
                break;
            };
            if st.out.len() > MAX_MESSAGE && matches!(st.service, Some(Service::BootProperties)) {
                st.closed = true; // asking over and over, and reading none of it
                break;
            }
            if st.inbuf.len() - at - 4 < len {
                break;
            }
            let msg = String::from_utf8_lossy(&st.inbuf[at + 4..at + 4 + len]).into_owned();
            at += 4 + len;
            let State { service, out, .. } = &mut *st;
            match service {
                Some(Service::Sensors(s)) => start_stream |= sensors_message(s, out, &msg),
                // A lone NUL ends the list of properties, and there are none to add.
                Some(Service::BootProperties) => out.extend(b"0001\0"),
                _ => {}
            }
        }
        st.inbuf.drain(..at);
        drop(st);
        if start_stream {
            stream(Arc::downgrade(self));
        }
        EVENTS.bump_key(Arc::as_ptr(self) as usize);
        Ok(data.len())
    }

    pub fn read(&self, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if let Some(io) = self.io() {
            return read_stream(&io, t, count, nonblock);
        }
        loop {
            let seen = EVENTS.watch_key(self as *const Self as usize);
            {
                let mut st = self.st.lock().unwrap();
                if !st.connected {
                    return Err(ENOTCONN);
                }
                if !st.out.is_empty() {
                    let n = count.min(st.out.len());
                    return Ok(st.out.drain(..n).collect());
                }
                if st.closed {
                    return Ok(Vec::new());
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, super::POLL);
        }
    }

}

fn read_stream(io: &Arc<Io>, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
    loop {
        let seen = EVENTS.watch_key(io.key());
        match io.read(count, false) {
            Err(EAGAIN) if !nonblock => {}
            r => return r,
        }
        if t.interrupted() {
            return Err(ERESTARTSYS);
        }
        EVENTS.wait(seen, IDLE);
    }
}

fn write_stream(io: &Arc<Io>, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
    let mut done = 0;
    loop {
        let seen = EVENTS.watch_key(io.key());
        match io.write(&data[done..], done > 0) {
            Ok(n) => {
                done += n;
                if done == data.len() {
                    return Ok(done);
                }
                // Look again: what's going out may have made room since. Only a sender
                // that saw the queue full is sure of being told.
                continue;
            }
            Err(EAGAIN) => {}
            Err(_) if done > 0 => return Ok(done),
            Err(e) => return Err(e),
        }
        if nonblock {
            return if done > 0 { Ok(done) } else { Err(EAGAIN) };
        }
        if t.interrupted() {
            return if done > 0 { Ok(done) } else { Err(ERESTARTSYS) };
        }
        EVENTS.wait(seen, IDLE);
    }
}

impl Kernel {
    /// What a vsock can do besides the read and write every file can.
    pub(super) fn vsock_syscall(&self, no: Sysno, t: &Arc<Thread>, f: &Arc<File>, v: &Arc<Vsock>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        const IO_MAX: u64 = 1 << 31;
        const MSG_DONTWAIT: u64 = 0x40;
        const SOCK_NONBLOCK: u64 = 0o4000;
        const SOCK_CLOEXEC: u64 = 0o2000000;
        const SOL_SOCKET: u64 = 1;
        const SO_TYPE: u64 = 3;
        const SO_ERROR: u64 = 4;
        const SO_DOMAIN: u64 = 39;
        let put_addr = |t: &Thread, addr: u64, len_p: u64, sa: [u8; 16]| -> Result<(), i64> {
            if addr == 0 {
                return Ok(());
            }
            let mut mm = t.proc.mm();
            let room = mm.read_u32(len_p)? as usize;
            mm.write(addr, &sa[..room.min(16)])?;
            mm.write_u32(len_p, 16)
        };
        match no {
            connect => {
                let addr = t.proc.mm().read_vec(a[1], (a[2] as usize).min(128))?;
                v.connect(&addr).map(|_| 0)
            }
            bind => {
                let addr = t.proc.mm().read_vec(a[1], (a[2] as usize).min(128))?;
                if addr.len() < 16 || u16::from_le_bytes([addr[0], addr[1]]) as u64 != AF_VSOCK {
                    return Err(EINVAL);
                }
                let port = u32::from_le_bytes(addr[4..8].try_into().unwrap());
                let cid = u32::from_le_bytes(addr[8..12].try_into().unwrap());
                if cid != VMADDR_CID_ANY && cid != GUEST_CID {
                    return Err(EADDRNOTAVAIL);
                }
                let mut bound = BOUND.lock().unwrap();
                if bound.get(&port).is_some_and(|w| w.strong_count() > 0) {
                    return Err(EADDRINUSE);
                }
                let mut st = v.st.lock().unwrap();
                if st.bound.is_some() {
                    return Err(EINVAL);
                }
                st.bound = Some(port);
                bound.insert(port, Arc::downgrade(v));
                Ok(0)
            }
            listen => {
                let mut st = v.st.lock().unwrap();
                let Some(port) = st.bound else { return Err(EINVAL) };
                st.backlog.get_or_insert_with(VecDeque::new);
                drop(st);
                if port == super::adb::GUEST_PORT {
                    super::adb::guest_listening();
                }
                Ok(0)
            }
            accept | accept4 => {
                let flags = if no == accept4 { a[3] } else { 0 };
                let (io, port) = loop {
                    let seen = EVENTS.watch_key(Arc::as_ptr(v) as usize);
                    {
                        let mut st = v.st.lock().unwrap();
                        let port = st.bound.unwrap_or(0);
                        let backlog = st.backlog.as_mut().ok_or(EINVAL)?;
                        if let Some(io) = backlog.pop_front() {
                            break (io, port);
                        }
                    }
                    if f.nonblock() {
                        return Err(EAGAIN);
                    }
                    if t.interrupted() {
                        return Err(ERESTARTSYS);
                    }
                    EVENTS.wait(seen, IDLE);
                };
                put_addr(t, a[1], a[2], sockaddr_vm(HOST_CLIENT_PORT, VMADDR_CID_HOST))?;
                let conn = Vsock::new();
                {
                    let mut st = conn.st.lock().unwrap();
                    st.connected = true;
                    st.stream = Some(io);
                    st.local_port = port;
                }
                let file = File::new(Kind::Vsock(conn), (flags & SOCK_NONBLOCK) as u32);
                t.files().alloc(file, flags & SOCK_CLOEXEC != 0, 0)
            }
            getsockname => {
                let st = v.st.lock().unwrap();
                let port = if st.stream.is_some() { st.local_port } else { st.bound.unwrap_or(u32::MAX) };
                drop(st);
                put_addr(t, a[1], a[2], sockaddr_vm(port, GUEST_CID)).map(|_| 0)
            }
            getpeername => {
                let st = v.st.lock().unwrap();
                let peer = if st.stream.is_some() {
                    sockaddr_vm(HOST_CLIENT_PORT, VMADDR_CID_HOST)
                } else if st.connected {
                    sockaddr_vm(PIPE_PORT, VMADDR_CID_HOST)
                } else {
                    return Err(ENOTCONN);
                };
                drop(st);
                put_addr(t, a[1], a[2], peer).map(|_| 0)
            }
            sendto => {
                let data = t.proc.mm().read_vec(a[1], a[2].min(IO_MAX) as usize)?;
                v.write(t, &data, f.nonblock() || a[3] & MSG_DONTWAIT != 0).map(|n| n as i64)
            }
            recvfrom if a[4] == 0 => {
                let data = v.read(t, a[2] as usize, f.nonblock() || a[3] & MSG_DONTWAIT != 0)?;
                t.proc.mm().write(a[1], &data)?;
                Ok(data.len() as i64)
            }
            shutdown => {
                if a[1] > 2 {
                    return Err(EINVAL);
                }
                if let Some(io) = v.io() {
                    io.shutdown(a[1]);
                }
                Ok(0)
            }
            setsockopt => Ok(0),
            getsockopt if a[1] == SOL_SOCKET => {
                let value: u32 = match a[2] {
                    SO_TYPE => 1,
                    SO_DOMAIN => AF_VSOCK as u32,
                    SO_ERROR => 0,
                    _ => return Err(ENOPROTOOPT),
                };
                let mut mm = t.proc.mm();
                let room = mm.read_u32(a[4])? as usize;
                mm.write(a[3], &value.to_le_bytes()[..room.min(4)])?;
                mm.write_u32(a[4], 4)?;
                Ok(0)
            }
            _ => Err(EOPNOTSUPP),
        }
    }
}

/// One message from the sensors HAL; true when streaming should start.
fn sensors_message(s: &mut Sensors, out: &mut VecDeque<u8>, msg: &str) -> bool {
    if msg == "list-sensors" {
        frame(out, &SENSORS.to_string());
        return false;
    }
    if let Some(ms) = msg.strip_prefix("set-delay:") {
        s.delay_ms = ms.parse().unwrap_or(200);
    } else if let Some(rest) = msg.strip_prefix("set:") {
        const NAMES: [&str; 9] = ["acceleration", "gyroscope", "magnetic-field", "orientation", "temperature", "proximity", "light", "pressure", "humidity"];
        if let Some((name, on)) = rest.rsplit_once(':')
            && let Some(bit) = NAMES.iter().position(|n| *n == name)
        {
            if on == "1" {
                s.enabled |= 1 << bit;
            } else {
                s.enabled &= !(1 << bit);
            }
        }
    }
    // time:<ns> needs nothing back.
    if s.enabled != 0 && !s.streaming {
        s.streaming = true;
        return true;
    }
    false
}

/// Sends the enabled sensors' readings every set-delay, as the emulator's
/// sensors thread does, until the connection goes away.
fn stream(conn: Weak<Vsock>) {
    let _ = std::thread::Builder::new().name("qemud-sensors".into()).spawn(move || {
        let start = std::time::Instant::now();
        loop {
            let delay = {
                let Some(c) = conn.upgrade() else { return };
                let mut st = c.st.lock().unwrap();
                let State { service, out, .. } = &mut *st;
                let Some(Service::Sensors(s)) = service else { return };
                // Keep the guest's queue short if nobody reads.
                if out.len() < 4096 {
                    for r in readings(s.enabled) {
                        frame(out, &r);
                    }
                    frame(out, &format!("sync:{}", start.elapsed().as_micros()));
                }
                s.delay_ms.clamp(10, 1000)
            };
            EVENTS.bump_key(conn.as_ptr() as usize);
            std::thread::sleep(Duration::from_millis(delay));
        }
    });
}
