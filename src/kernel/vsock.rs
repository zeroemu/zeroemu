//! AF_VSOCK, as far as the Android Emulator's guest needs it: the ranchu
//! HALs reach "the host" through libqemupipe, which connects a vsock stream
//! to CID 2, port 5000, and writes the service name ("pipe:qemud:sensors"
//! and its NUL). droidrt is that host. Services it does not provide close
//! the connection, as the emulator does.
//!
//! qemud services frame each message with its length in four hex digits.
//! The clipboard pipe has binary framing, but droidrt has nothing to say on
//! it and drops what it hears.

use super::wait::EVENTS;
use super::{ERESTARTSYS, Thread};
use crate::errno::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

pub const AF_VSOCK: u64 = 40;
const VMADDR_CID_HOST: u32 = 2;
const PIPE_PORT: u32 = 5000;

pub struct Vsock {
    st: Mutex<State>,
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
}

enum Service {
    Sensors(Sensors),
    /// Stays open and silent: the guest's monitor blocks reading the host's
    /// clipboard, and hammers the connection if it is closed.
    Clipboard,
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

    pub fn write(self: &Arc<Self>, data: &[u8]) -> Result<usize, i64> {
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
            let Some(end) = end else { return Ok(data.len()) };
            rest = &rest[end + 1..];
            let name = String::from_utf8_lossy(&st.name).into_owned();
            match name.as_str() {
                "pipe:qemud:sensors" => st.service = Some(Service::Sensors(Sensors { delay_ms: 200, ..Default::default() })),
                "pipe:clipboard" => st.service = Some(Service::Clipboard),
                _ => {
                    eprintln!("droidrt: no host service {name}");
                    st.closed = true;
                    EVENTS.bump_key(Arc::as_ptr(self) as usize);
                    return Ok(data.len());
                }
            }
        }
        if matches!(st.service, Some(Service::Clipboard)) {
            return Ok(data.len());
        }
        st.inbuf.extend_from_slice(rest);
        let mut start_stream = false;
        while st.inbuf.len() >= 4 {
            let len = std::str::from_utf8(&st.inbuf[..4]).ok().and_then(|h| usize::from_str_radix(h, 16).ok());
            let Some(len) = len else {
                st.closed = true; // a binary-length frame, or garbage: hang up
                break;
            };
            if st.inbuf.len() < 4 + len {
                break;
            }
            let msg = String::from_utf8_lossy(&st.inbuf[4..4 + len]).into_owned();
            st.inbuf.drain(..4 + len);
            let State { service, out, .. } = &mut *st;
            if let Some(Service::Sensors(s)) = service {
                start_stream |= sensors_message(s, out, &msg);
            }
        }
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

    pub fn readable(&self) -> bool {
        let st = self.st.lock().unwrap();
        !st.out.is_empty() || st.closed
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
