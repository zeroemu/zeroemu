//! /dev/input/event*: the touchscreen and keyboard Android's EventHub reads.
//! The window feeds them (gpu/window_macos.rs). They carry the names the image's
//! input configuration expects: /vendor/usr/idc/virtio_input_multi_touch_1.idc
//! makes the first a touchscreen, and qwerty2.idc the second a full keyboard.
//!
//! DROIDRT_INPUT_FIFO=<path>: lines from this host FIFO are injected as if they
//! came from the window, for testing without the host's mouse: `down X Y`,
//! `move X Y` and `up X Y` with X and Y from 0 to 1, and `key CODE 1|0`.

use super::wait::EVENTS;
use super::{ERESTARTSYS, IDLE, Thread};
use crate::errno::*;
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const INPUT_MAJOR: u32 = 13;
const FIRST_MINOR: u32 = 64;

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_ABS: u16 = 3;
const SYN_REPORT: u16 = 0;

const BTN_TOUCH: u16 = 0x14a;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const ABS_MT_SLOT: u16 = 0x2f;
const ABS_MT_POSITION_X: u16 = 0x35;
const ABS_MT_POSITION_Y: u16 = 0x36;
const ABS_MT_TRACKING_ID: u16 = 0x39;
/// Positions are scaled to this. Android maps the axis range onto the display.
const ABS_MAX: i32 = 32767;

const INPUT_PROP_DIRECT: u32 = 1;
const BUS_VIRTUAL: u16 = 6;

/// sizeof(struct input_event) on a 64-bit guest.
const EVENT_SIZE: usize = 24;
/// As Linux's EVDEV_BUF_PACKETS: a client that falls behind loses the oldest.
const QUEUE_MAX: usize = 4096;

/// EVIOCSCLOCKID: CLOCK_MONOTONIC. Anything else reads as CLOCK_REALTIME.
const CLOCK_MONOTONIC: i32 = 1;

struct Device {
    minor: u32,
    name: &'static str,
    ev_bits: u32,
    key_bits: Vec<u8>,
    abs_bits: Vec<u8>,
    /// (axis, minimum, maximum) of each absolute axis.
    abs: Vec<(u16, i32, i32)>,
    props: u32,
    clients: Mutex<Vec<Weak<Client>>>,
    /// The key and absolute state a new client can read (EVIOCGKEY, EVIOCGABS).
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    keys: Vec<u8>,
    abs: Vec<(u16, i32)>,
    tracking_id: i32,
}

/// One open of a device.
pub struct Client {
    device: &'static Device,
    queue: Mutex<VecDeque<(Duration, u16, u16, i32)>>,
    clock: Mutex<i32>,
}

fn bits(codes: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut b = vec![0u8; 96];
    for c in codes {
        b[c as usize / 8] |= 1 << (c % 8);
    }
    b
}

static TOUCH: LazyLock<Device> = LazyLock::new(|| Device {
    minor: FIRST_MINOR,
    name: "virtio_input_multi_touch_1",
    ev_bits: 1 << EV_SYN | 1 << EV_KEY | 1 << EV_ABS,
    key_bits: bits([BTN_TOUCH]),
    abs_bits: bits([ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TRACKING_ID]),
    abs: vec![(ABS_X, 0, ABS_MAX), (ABS_Y, 0, ABS_MAX), (ABS_MT_SLOT, 0, 0), (ABS_MT_POSITION_X, 0, ABS_MAX), (ABS_MT_POSITION_Y, 0, ABS_MAX), (ABS_MT_TRACKING_ID, 0, 65535)],
    props: 1 << INPUT_PROP_DIRECT,
    clients: Mutex::default(),
    state: Mutex::default(),
});

static KEYBOARD: LazyLock<Device> = LazyLock::new(|| Device {
    minor: FIRST_MINOR + 1,
    name: "qwerty2",
    ev_bits: 1 << EV_SYN | 1 << EV_KEY,
    key_bits: bits(1..=248),
    abs_bits: bits([]),
    abs: Vec::new(),
    props: 0,
    clients: Mutex::default(),
    state: Mutex::default(),
});

/// The /dev/input entries to create: (name, rdev).
pub fn nodes() -> [(&'static str, u64); 2] {
    [("event0", rdev(FIRST_MINOR)), ("event1", rdev(FIRST_MINOR + 1))]
}

fn rdev(minor: u32) -> u64 {
    super::block::makedev(INPUT_MAJOR, minor)
}

pub fn open(devt: u64) -> Option<Arc<Client>> {
    let device: &'static Device = [&*TOUCH, &*KEYBOARD].into_iter().find(|d| rdev(d.minor) == devt)?;
    let c = Arc::new(Client { device, queue: Mutex::default(), clock: Mutex::new(0) });
    let mut clients = device.clients.lock().unwrap();
    clients.retain(|w| w.strong_count() > 0);
    clients.push(Arc::downgrade(&c));
    Some(c)
}

static BOOT: LazyLock<Instant> = LazyLock::new(Instant::now);

impl Device {
    /// Queues one packet of events, ending in SYN_REPORT, for every reader.
    fn post(&self, events: &[(u16, u16, i32)]) {
        let now = BOOT.elapsed();
        let clients = self.clients.lock().unwrap();
        for c in clients.iter().filter_map(Weak::upgrade) {
            let mut q = c.queue.lock().unwrap();
            for &(ty, code, value) in events.iter().chain(&[(EV_SYN, SYN_REPORT, 0)]) {
                if q.len() >= QUEUE_MAX {
                    q.pop_front();
                }
                q.push_back((now, ty, code, value));
            }
        }
        drop(clients);
        EVENTS.bump();
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Touch {
    Down,
    Move,
    Up,
}

fn scale(v: f64) -> i32 {
    (v.clamp(0.0, 1.0) * ABS_MAX as f64) as i32
}

/// A touch at (x, y), each from 0 to 1 across the display.
pub fn touch(phase: Touch, x: f64, y: f64) {
    let (x, y) = (scale(x), scale(y));
    let d = &*TOUCH;
    let mut st = d.state.lock().unwrap();
    let events: Vec<(u16, u16, i32)> = match phase {
        Touch::Down => {
            st.tracking_id = st.tracking_id.wrapping_add(1) & 0xffff;
            vec![
                (EV_ABS, ABS_MT_SLOT, 0),
                (EV_ABS, ABS_MT_TRACKING_ID, st.tracking_id),
                (EV_KEY, BTN_TOUCH, 1),
                (EV_ABS, ABS_MT_POSITION_X, x),
                (EV_ABS, ABS_MT_POSITION_Y, y),
                (EV_ABS, ABS_X, x),
                (EV_ABS, ABS_Y, y),
            ]
        }
        Touch::Move => vec![(EV_ABS, ABS_MT_POSITION_X, x), (EV_ABS, ABS_MT_POSITION_Y, y), (EV_ABS, ABS_X, x), (EV_ABS, ABS_Y, y)],
        Touch::Up => vec![(EV_ABS, ABS_MT_TRACKING_ID, -1), (EV_KEY, BTN_TOUCH, 0)],
    };
    st.keys.resize(96, 0);
    if phase != Touch::Move {
        let b = BTN_TOUCH as usize;
        if phase == Touch::Down {
            st.keys[b / 8] |= 1 << (b % 8);
        } else {
            st.keys[b / 8] &= !(1 << (b % 8));
        }
    }
    drop(st);
    d.post(&events);
}

/// A key, by Linux KEY_* code.
pub fn key(code: u16, down: bool) {
    let d = &*KEYBOARD;
    let mut st = d.state.lock().unwrap();
    st.keys.resize(96, 0);
    let b = code as usize;
    if b / 8 < st.keys.len() {
        if down {
            st.keys[b / 8] |= 1 << (b % 8);
        } else {
            st.keys[b / 8] &= !(1 << (b % 8));
        }
    }
    drop(st);
    d.post(&[(EV_KEY, code, down as i32)]);
}

/// Serves DROIDRT_INPUT_FIFO, if set.
pub fn start_input_fifo() {
    let Ok(path) = std::env::var("DROIDRT_INPUT_FIFO") else { return };
    let _ = std::thread::Builder::new().name("input-fifo".into()).spawn(move || {
        use std::io::BufRead;
        loop {
            // Blocks until a writer opens it, and ends when the last one closes it.
            let Ok(f) = std::fs::File::open(&path) else { return };
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                let w: Vec<&str> = line.split_whitespace().collect();
                match w.as_slice() {
                    ["down" | "move" | "up", x, y] => {
                        let phase = match w[0] {
                            "down" => Touch::Down,
                            "move" => Touch::Move,
                            _ => Touch::Up,
                        };
                        if let (Ok(x), Ok(y)) = (x.parse(), y.parse()) {
                            touch(phase, x, y);
                        }
                    }
                    ["key", code, state] => {
                        if let Ok(code) = code.parse() {
                            key(code, *state != "0");
                        }
                    }
                    _ => eprintln!("droidrt: bad input line {line:?}"),
                }
            }
        }
    });
}

impl Client {
    pub fn readable(&self) -> bool {
        !self.queue.lock().unwrap().is_empty()
    }

    fn encode(&self, (at, ty, code, value): (Duration, u16, u16, i32), out: &mut Vec<u8>) {
        let t = if *self.clock.lock().unwrap() == CLOCK_MONOTONIC {
            at
        } else {
            let since_boot = BOOT.elapsed().saturating_sub(at);
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().saturating_sub(since_boot)
        };
        out.extend_from_slice(&t.as_secs().to_le_bytes());
        out.extend_from_slice(&(t.subsec_micros() as u64).to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    }

    pub fn read(&self, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        if count < EVENT_SIZE {
            return Err(EINVAL);
        }
        loop {
            let seen = EVENTS.current();
            {
                let mut q = self.queue.lock().unwrap();
                if !q.is_empty() {
                    let n = q.len().min(count / EVENT_SIZE);
                    let events: Vec<_> = q.drain(..n).collect();
                    drop(q);
                    let mut out = Vec::with_capacity(n * EVENT_SIZE);
                    for e in events {
                        self.encode(e, &mut out);
                    }
                    return Ok(out);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, IDLE);
        }
    }

    /// EVIOC*. What it returns is the result and the bytes to copy to `arg`.
    pub fn ioctl(&self, cmd: u64, input: impl FnOnce() -> Result<i32, i64>) -> Result<(i64, Vec<u8>), i64> {
        let d = self.device;
        let (dir, ty, nr, size) = ((cmd >> 30) & 3, (cmd >> 8) & 0xff, cmd & 0xff, ((cmd >> 16) & 0x3fff) as usize);
        if ty != b'E' as u64 {
            return Err(ENOTTY);
        }
        const READ: u64 = 2;
        let sized = |bytes: &[u8]| -> Result<(i64, Vec<u8>), i64> {
            let n = bytes.len().min(size);
            Ok((n as i64, bytes[..n].to_vec()))
        };
        let exact = |bytes: Vec<u8>| -> Result<(i64, Vec<u8>), i64> { Ok((0, bytes)) };
        match (dir, nr) {
            (READ, 0x01) => exact(0x0001_0001u32.to_le_bytes().to_vec()),
            (READ, 0x02) => {
                let mut b = Vec::new();
                for v in [BUS_VIRTUAL, 0x1af4, 0x1040 + d.minor as u16, 1] {
                    b.extend_from_slice(&v.to_le_bytes());
                }
                exact(b)
            }
            (READ, 0x03) => exact([250u32.to_le_bytes(), 33u32.to_le_bytes()].concat()), // EVIOCGREP
            (READ, 0x06) => sized(&[d.name.as_bytes(), b"\0"].concat()),
            (READ, 0x07) => sized(format!("virtio{}/input0\0", d.minor - FIRST_MINOR).as_bytes()),
            (READ, 0x08) => sized(b"\0"),
            (READ, 0x09) => sized(&d.props.to_le_bytes()),
            (READ, 0x18) => {
                let st = d.state.lock().unwrap();
                sized(&st.keys)
            }
            (READ, 0x19..=0x1b) => sized(&[0u8; 96]),
            (READ, 0x20) => sized(&d.ev_bits.to_le_bytes()),
            (READ, 0x21) => sized(&d.key_bits),
            (READ, 0x23) => sized(&d.abs_bits),
            (READ, 0x22 | 0x24..=0x3f) => sized(&[0u8; 96]),
            (READ, 0x40..=0x7f) => {
                let axis = (nr - 0x40) as u16;
                let &(_, min, max) = d.abs.iter().find(|a| a.0 == axis).ok_or(EINVAL)?;
                let value = d.state.lock().unwrap().abs.iter().find(|a| a.0 == axis).map_or(0, |a| a.1);
                let mut b = Vec::new();
                for v in [value, min, max, 0, 0, 0] {
                    b.extend_from_slice(&v.to_le_bytes());
                }
                sized(&b)
            }
            (READ, 0x84) => exact(0u32.to_le_bytes().to_vec()), // EVIOCGEFFECTS
            (_, 0x90 | 0x91) => Ok((0, Vec::new())),            // EVIOCGRAB, EVIOCREVOKE
            (_, 0xa0) => {
                let id = input()?;
                if !matches!(id, 0 | 1 | 7) {
                    return Err(EINVAL);
                }
                *self.clock.lock().unwrap() = id;
                Ok((0, Vec::new()))
            }
            (_, 0x03 | 0x92 | 0x93) => Ok((0, Vec::new())), // EVIOCSREP, EVIOCGMASK, EVIOCSMASK
            _ => Err(EINVAL),
        }
    }
}
