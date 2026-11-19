//! AF_VSOCK, as far as the Android Emulator's guest needs it: the ranchu
//! HALs reach "the host" through libqemupipe, which connects a vsock stream
//! to CID 2, port 5000, and writes the service name ("pipe:qemud:sensors"
//! and its NUL). zeroemu is that host. Services it does not provide close
//! the connection, as the emulator does.
//!
//! qemud services frame each message with its length in four hex digits.
//! The clipboard pipe has binary framing, but zeroemu has nothing to say on
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
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

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
        if matches!(st.service, Some(Service::Sensors(_))) {
            SENSOR_PIPES.lock().unwrap().retain(|w| w.strong_count() > 0);
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
}

/// What the host reports, in sensor_list.cpp bit order: accelerometer,
/// gyroscope, magnetic field, orientation, temperature, proximity, light,
/// pressure, humidity.
const SENSORS: u32 = 0x1ff;
/// The ones whose readings change when the phone turns: accelerometer, magnetic
/// field and orientation.
const TURNING: u32 = 1 << 0 | 1 << 2 | 1 << 3;

/// How the phone is held: quarter turns counterclockwise from upright, or FLAT
/// until the window first turns it.
static POSTURE: AtomicU8 = AtomicU8::new(FLAT);
const FLAT: u8 = u8::MAX;

/// The open sensors pipes, so that a turn reaches the HAL at once. The HAL keeps
/// one, and opens another only if that one breaks.
static SENSOR_PIPES: Mutex<Vec<Weak<Vsock>>> = Mutex::new(Vec::new());

/// What a still phone's accelerometer, magnetometer and orientation sensor read
/// in each posture. First lying flat, screen up, its top to the north: where
/// every boot starts. Then held upright, facing the user, who looks north. Then
/// turned a quarter at a time counterclockwise, as the user sees it.
///
/// Only the phone moves. Gravity and the field the flat phone reads (5.9 µT
/// north, 48.4 µT down) stay put, and each reading is their size along the
/// phone's own axes: x to the right of the screen, y to its top, z out of it.
/// The accelerometer reads the push that holds the phone up against gravity, so
/// +9.81 on whichever axis points up (SensorEvent.java).
///
/// Android picks the screen's rotation from the accelerometer alone: -atan2(-x, y),
/// rounded to a quarter turn (WindowOrientationListener.java). So a phone turned
/// q times gets ROTATION_0 + q, and x = 9.81 is ROTATION_90, "rotate CCW" in
/// config.xml. The Android Emulator turns its model the same way: landscape is
/// +90° about z, and reads x > 0 (android/hw-sensors.cpp, physics/PhysicalModel.cpp).
///
/// The orientation sensor's angles are azimuth, pitch and roll as SensorEvent.java
/// defines them, in the order sensorservice's OrientationSensor.cpp takes them
/// apart: azimuth about z, then roll about y, then pitch about x. A phone on its
/// side has roll ±90°, where azimuth and pitch become one angle; there pitch is 0,
/// and azimuth is where the top points.
const POSES: [[&str; 3]; 5] = [
    ["acceleration:0.00:0.00:9.81", "magnetic:0.00:5.90:-48.40", "orientation:0.00:0.00:0.00"],
    ["acceleration:0.00:9.81:0.00", "magnetic:0.00:-48.40:-5.90", "orientation:0.00:-90.00:0.00"],
    ["acceleration:9.81:0.00:0.00", "magnetic:-48.40:0.00:-5.90", "orientation:270.00:0.00:90.00"],
    ["acceleration:0.00:-9.81:0.00", "magnetic:0.00:48.40:-5.90", "orientation:180.00:90.00:0.00"],
    ["acceleration:-9.81:0.00:0.00", "magnetic:48.40:0.00:-5.90", "orientation:90.00:0.00:-90.00"],
];

/// Turns the phone: `turns` quarter turns counterclockwise from upright portrait,
/// as the user looking at the screen sees it. 1 is on its side with its top to
/// the left, 2 upside down, 3 top to the right; more than 3 goes round again.
/// Android turns its screen to match when auto-rotate is on, as a phone does.
/// Until this is first called the phone lies flat, as it always did.
pub fn set_posture(turns: u8) {
    POSTURE.store(turns % 4, Ordering::Relaxed);
    let pipes: Vec<Arc<Vsock>> = SENSOR_PIPES.lock().unwrap().iter().filter_map(Weak::upgrade).collect();
    for pipe in pipes {
        let mut st = pipe.st.lock().unwrap();
        let State { service: Some(Service::Sensors(s)), out, closed: false, .. } = &mut *st else { continue };
        if s.enabled & TURNING == 0 {
            continue;
        }
        // The posture is read again under the pipe's lock, as a sensor being turned
        // on reads it, so the HAL ends up with the last one whichever goes first.
        // The HAL keeps a continuous sensor's last reading and posts it again at
        // the rate Android asked for (multihal_sensors.cpp), so one is enough.
        report(out, s.enabled & TURNING, posture());
        drop(st);
        EVENTS.bump_key(Arc::as_ptr(&pipe) as usize);
    }
}

/// How the phone is held: quarter turns counterclockwise from upright, or None
/// while it still lies flat.
pub fn posture() -> Option<u8> {
    match POSTURE.load(Ordering::Relaxed) {
        FLAT => None,
        q => Some(q),
    }
}

/// A phone held still in `posture` (POSES), so not spinning, in a lit room at
/// room temperature, with nothing near the proximity sensor.
fn readings(enabled: u32, posture: Option<u8>) -> Vec<String> {
    let [acceleration, magnetic, orientation] = POSES[posture.map_or(0, |q| 1 + q as usize % 4)];
    let all: [(u32, &str); 9] = [
        (0, acceleration),
        (1, "gyroscope:0.00:0.00:0.00"),
        (2, magnetic),
        (3, orientation),
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

/// Queues the readings of the sensors in `bits`, then the "sync:<µs>" line that
/// ends each batch the emulator sends (android/hw-sensors.cpp).
fn report(out: &mut VecDeque<u8>, bits: u32, posture: Option<u8>) {
    for r in readings(bits, posture) {
        frame(out, &r);
    }
    frame(out, &format!("sync:{}", super::monotonic_ns() / 1000));
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

    /// FIONREAD: bytes waiting to be read.
    pub fn unread(&self) -> usize {
        let st = self.st.lock().unwrap();
        match &st.stream {
            Some(io) => io.queued().0,
            None => st.out.len(),
        }
    }

    /// What a poller of this watches.
    pub fn mask(self: &Arc<Self>) -> super::wait::Mask {
        use super::wait::key_mask;
        let own = key_mask(Arc::as_ptr(self) as usize);
        self.io().map_or(own, |io| own | key_mask(io.key()))
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
                "pipe:qemud:sensors" => {
                    st.service = Some(Service::Sensors(Sensors { delay_ms: 200, ..Default::default() }));
                    SENSOR_PIPES.lock().unwrap().push(Arc::downgrade(self));
                }
                "pipe:qemud:boot-properties" => st.service = Some(Service::BootProperties),
                "pipe:QemuMiscPipe" => st.service = Some(Service::Misc),
                "pipe:clipboard" | "pipe:qemud:fingerprintlisten" => st.service = Some(Service::Silent),
                _ => {
                    if super::verbose() {
                        eprintln!("zeroemu: no host service {name}");
                    }
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
                Some(Service::Sensors(s)) => sensors_message(s, out, &msg, posture()),
                // A lone NUL ends the list of properties, and there are none to add.
                Some(Service::BootProperties) => out.extend(b"0001\0"),
                _ => {}
            }
        }
        st.inbuf.drain(..at);
        drop(st);
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
        const IO_MAX: u64 = 16 << 20;
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

/// One message from the sensors HAL. A sensor's reading goes back when the HAL turns it
/// on, and otherwise only when the phone turns (set_posture): nothing else changes the
/// readings, and the HAL makes a continuous sensor's events itself, at the rate Android
/// asked for, from the last reading it got (its batch thread); an on-change sensor
/// reports when its value changes. The emulator sends every sensor at the fastest rate
/// anything asks for, and the HAL turns them all on, so that was ten messages every
/// 10 ms, each waking the HAL, with nothing new in any of them.
fn sensors_message(s: &mut Sensors, out: &mut VecDeque<u8>, msg: &str, posture: Option<u8>) {
    if msg == "list-sensors" {
        frame(out, &SENSORS.to_string());
        return;
    }
    if let Some(ms) = msg.strip_prefix("set-delay:") {
        let was = s.delay_ms;
        s.delay_ms = ms.parse().unwrap_or(200);
        if s.delay_ms != was && std::env::var_os("ZEROEMU_SENSOR_TRACE").is_some() {
            eprintln!("zeroemu: sensors asked for every {} ms", s.delay_ms);
        }
    } else if let Some(rest) = msg.strip_prefix("set:") {
        const NAMES: [&str; 9] = ["acceleration", "gyroscope", "magnetic-field", "orientation", "temperature", "proximity", "light", "pressure", "humidity"];
        if let Some((name, on)) = rest.rsplit_once(':')
            && let Some(bit) = NAMES.iter().position(|n| *n == name)
        {
            if on == "1" {
                if s.enabled & 1 << bit == 0 {
                    s.enabled |= 1 << bit;
                    report(out, 1 << bit, posture);
                }
            } else {
                s.enabled &= !(1 << bit);
            }
        }
    }
    // time:<ns> needs nothing back.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The messages queued in `out`, without their length prefixes.
    fn messages(out: &VecDeque<u8>) -> Vec<String> {
        let bytes: Vec<u8> = out.iter().copied().collect();
        let mut got = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = usize::from_str_radix(std::str::from_utf8(&bytes[at..at + 4]).unwrap(), 16).unwrap();
            got.push(String::from_utf8(bytes[at + 4..at + 4 + len].to_vec()).unwrap());
            at += 4 + len;
        }
        got
    }

    /// The three numbers of a reading like "acceleration:0.00:9.81:0.00".
    fn vec3(reading: &str) -> [f64; 3] {
        let (_, values) = reading.split_once(':').unwrap();
        let v: Vec<f64> = values.split(':').map(|n| n.parse().unwrap()).collect();
        v.try_into().unwrap()
    }

    fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
        a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
    }

    #[test]
    fn android_turns_the_screen_with_the_phone() {
        // WindowOrientationListener.java: the tilt is asin(z / |a|), and the
        // screen's rotation is -atan2(-x, y) in degrees, to the nearest quarter turn.
        let tilt = |[x, y, z]: [f64; 3]| (z / dot([x, y, z], [x, y, z]).sqrt()).asin().to_degrees().round();
        let flat = vec3(&readings(1, None)[0]);
        assert_eq!(flat, [0.0, 0.0, 9.81], "the same as before the phone could turn");
        assert_eq!(tilt(flat), 90.0, "flat, so Android picks no rotation");
        for q in 0..4 {
            let [x, y, z] = vec3(&readings(1, Some(q))[0]);
            assert_eq!(tilt([x, y, z]), 0.0, "upright");
            let mut angle = (-(-x).atan2(y)).to_degrees().round() as i32;
            if angle < 0 {
                angle += 360;
            }
            assert_eq!((angle + 45) / 90 % 4, q as i32, "posture {q}");
        }
        assert_eq!(readings(1, Some(5)), readings(1, Some(1)));
    }

    #[test]
    fn every_reading_is_one_pose_of_the_same_world() {
        // The world is east, north, up. The flat phone reads gravity's push up z and
        // the field 5.9 µT north and 48.4 µT down.
        let up = [0.0, 0.0, 9.81];
        let field = [0.0, 5.9, -48.4];
        let add = |u: [f64; 3], s: f64, v: [f64; 3], t: f64| [u[0] * s + v[0] * t, u[1] * s + v[1] * t, u[2] * s + v[2] * t];
        for posture in [None, Some(0), Some(1), Some(2), Some(3)] {
            let got = readings(TURNING, posture);
            let [azimuth, pitch, roll] = vec3(&got[2]).map(f64::to_radians);
            // The phone's axes in the world after its orientation angles (SensorEvent.java).
            // Azimuth is where y points, clockwise from north seen from above.
            let (x, y, z) = ([azimuth.cos(), -azimuth.sin(), 0.0], [azimuth.sin(), azimuth.cos(), 0.0], [0.0, 0.0, 1.0]);
            // Positive roll moves x toward z.
            let (x, z) = (add(x, roll.cos(), z, roll.sin()), add(x, -roll.sin(), z, roll.cos()));
            // Positive pitch moves z toward y.
            let (y, z) = (add(y, pitch.cos(), z, -pitch.sin()), add(z, pitch.cos(), y, pitch.sin()));
            let seen = |v: [f64; 3]| [dot(x, v), dot(y, v), dot(z, v)];
            for (want, reading) in [(seen(up), &got[0]), (seen(field), &got[1])] {
                let have = vec3(reading);
                assert!((0..3).all(|i| (have[i] - want[i]).abs() < 0.01), "{posture:?}: {reading}, but its angles give {want:?}");
            }
        }
    }

    #[test]
    fn a_sensor_turned_on_gets_its_reading_then_a_sync() {
        let mut s = Sensors::default();
        let mut out = VecDeque::new();
        sensors_message(&mut s, &mut out, "list-sensors", None);
        assert_eq!(out.drain(..).collect::<Vec<u8>>(), b"0003511");
        sensors_message(&mut s, &mut out, "set:acceleration:1", Some(1));
        assert!(out.iter().copied().collect::<Vec<u8>>().starts_with(b"001bacceleration:9.81:0.00:0.00"));
        let got = messages(&out);
        assert_eq!(got.len(), 2);
        assert!(got[1].strip_prefix("sync:").unwrap().parse::<u64>().is_ok(), "{}", got[1]);
        out.clear();
        sensors_message(&mut s, &mut out, "set:acceleration:1", Some(1));
        assert!(out.is_empty(), "on already");
        sensors_message(&mut s, &mut out, "set:magnetic-field:1", None);
        assert_eq!(messages(&out)[0], "magnetic:0.00:5.90:-48.40");
    }

    #[test]
    fn a_turn_reaches_each_pipe_that_listens() {
        // A sensors pipe as write() leaves it once the HAL has named the service.
        let pipe = |enabled| {
            let v = Vsock::new();
            {
                let mut st = v.st.lock().unwrap();
                st.connected = true;
                st.service = Some(Service::Sensors(Sensors { enabled, delay_ms: 200 }));
            }
            SENSOR_PIPES.lock().unwrap().push(Arc::downgrade(&v));
            v
        };
        let accelerometer = pipe(1);
        let all = pipe(SENSORS);
        let other = pipe(1 << 4);
        drop(pipe(1));
        set_posture(5);
        assert_eq!(posture(), Some(1), "five quarter turns are one");
        let got = messages(&accelerometer.st.lock().unwrap().out);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "acceleration:9.81:0.00:0.00");
        assert!(got[1].starts_with("sync:"));
        let got = messages(&all.st.lock().unwrap().out);
        assert_eq!(got[..3], ["acceleration:9.81:0.00:0.00", "magnetic:-48.40:0.00:-5.90", "orientation:270.00:0.00:90.00"]);
        assert!(got[3].starts_with("sync:") && got.len() == 4);
        assert!(other.st.lock().unwrap().out.is_empty(), "nothing it reports moved");
        assert!(SENSOR_PIPES.lock().unwrap().iter().all(|w| w.strong_count() > 0), "the closed pipe left the list");
    }
}
