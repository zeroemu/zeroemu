//! /dev/input/event*: the touchscreen, keyboard and buttons Android's EventHub
//! reads. The window feeds them (gpu/window_macos.rs). The first two carry the
//! names the image's input configuration expects:
//! /vendor/usr/idc/virtio_input_multi_touch_1.idc makes the first a touchscreen,
//! and qwerty2.idc the second a full keyboard. The third, the device's buttons, has
//! a name no file in the image has, so Android gives it its stock key layout,
//! /system/usr/keylayout/Generic.kl. That has keys qwerty2.kl lacks: mute, the
//! notification shade, the screenshot key and Settings.
//!
//! ZEROEMU_INPUT_FIFO=<path>: lines from this host FIFO are injected as if they
//! came from the window, for testing without the host's mouse: `down X Y`,
//! `move X Y` and `up X Y` with X and Y from 0 to 1, `wheel X Y DX DY` with the
//! same scale, `key CODE 1|0` on the keyboard, `button CODE 1|0` on the buttons,
//! `usage USAGE CODE 1|0` for a button sent with a HID usage in hex (0x0c019f is
//! Settings), `resize W H` for the window's content in points, and `shot PATH`, which
//! writes the frame on show. Lines that start with `action`, `menu`, `toolbar`,
//! `keyeq`, `click` or `location` go to the window's controls (gpu::control_line).

use super::wait::EVENTS;
use super::{ERESTARTSYS, IDLE, Thread};
use crate::errno::*;
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

pub const INPUT_MAJOR: u32 = 13;
const FIRST_MINOR: u32 = 64;

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_ABS: u16 = 3;
const EV_MSC: u16 = 4;
const SYN_REPORT: u16 = 0;
const MSC_SCAN: u16 = 4;
/// KEY_CNT (include/uapi/linux/input-event-codes.h): every key code is below it.
/// Android's EventHub aborts on one that isn't (EventHub.cpp, trackInputEvent),
/// which takes system_server down.
const KEY_CNT: usize = 0x300;

const BTN_TOUCH: u16 = 0x14a;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const ABS_MT_SLOT: u16 = 0x2f;
const ABS_MT_POSITION_X: u16 = 0x35;
const ABS_MT_POSITION_Y: u16 = 0x36;
const ABS_MT_TRACKING_ID: u16 = 0x39;
const ABS_MT_FIRST: u16 = 0x30;
const ABS_MT_LAST: u16 = 0x3d;
/// ABS_MT_SLOT's range is 0 to this less one.
const SLOTS: i32 = 10;
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
    msc_bits: u8,
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
    /// Absolute axes' values. MT axes hold slot 0's, the only slot in use so far.
    abs: Vec<(u16, i32)>,
    /// The last tracking id given out; the finger's own is in `abs`.
    last_id: i32,
}

impl State {
    fn abs(&self, axis: u16) -> Option<i32> {
        self.abs.iter().find(|a| a.0 == axis).map(|a| a.1)
    }

    fn set_abs(&mut self, axis: u16, value: i32) {
        match self.abs.iter_mut().find(|a| a.0 == axis) {
            Some(a) => a.1 = value,
            None => self.abs.push((axis, value)),
        }
    }
}

/// One open of a device.
pub struct Client {
    device: &'static Device,
    queue: Mutex<VecDeque<(Duration, u16, u16, i32)>>,
    clock: Mutex<i32>,
}

fn bits(codes: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut b = vec![0u8; KEY_CNT / 8];
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
    msc_bits: 0,
    abs_bits: bits([ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TRACKING_ID]),
    abs: vec![(ABS_X, 0, ABS_MAX), (ABS_Y, 0, ABS_MAX), (ABS_MT_SLOT, 0, SLOTS - 1), (ABS_MT_POSITION_X, 0, ABS_MAX), (ABS_MT_POSITION_Y, 0, ABS_MAX), (ABS_MT_TRACKING_ID, 0, 65535)],
    props: 1 << INPUT_PROP_DIRECT,
    clients: Mutex::default(),
    state: Mutex::default(),
});

static KEYBOARD: LazyLock<Device> = LazyLock::new(|| Device {
    minor: FIRST_MINOR + 1,
    name: "qwerty2",
    ev_bits: 1 << EV_SYN | 1 << EV_KEY,
    // What a keyboard has, and what qwerty2.kl gives meaning to beyond that.
    key_bits: bits((1..=248).chain([399, 452, 453, 580])),
    msc_bits: 0,
    abs_bits: bits([]),
    abs: Vec::new(),
    props: 0,
    clients: Mutex::default(),
    state: Mutex::default(),
});

/// KEY_CONTROLPANEL. Generic.kl doesn't map it, so alone it means nothing. It carries
/// the HID usage for Settings, as a USB keyboard's Settings key does:
/// drivers/hid/hid-input.c turns consumer usage 0x19f (AL Control Panel) into it.
pub const KEY_CONTROLPANEL: u16 = 579;

/// The buttons' keys, and what Generic.kl makes of each: SYSRQ (a screenshot),
/// VOLUME_MUTE, VOLUME_DOWN, VOLUME_UP, POWER, SLEEP, BACK, KEY_HOMEPAGE as HOME,
/// KEY_DASHBOARD as NOTIFICATION, KEY_CONTROLPANEL, and KEY_APPSELECT as APP_SWITCH.
/// No letters: Android counts a device that has Q as an alphabetic keyboard
/// (EventHub.cpp), and pressing a letter makes it one (keyboard_classifier.rs). Any
/// key of an alphabetic keyboard wakes the device (KeyboardInputMapper.cpp). Without
/// letters only Power and the keys Android itself treats as wake keys do, as on a
/// phone (PhoneWindowManager.java).
const BUTTON_KEYS: [u16; 11] = [99, 113, 114, 115, 116, 142, 158, 172, 204, KEY_CONTROLPANEL, 580];

static BUTTONS: LazyLock<Device> = LazyLock::new(|| Device {
    minor: FIRST_MINOR + 2,
    name: "zeroemu_buttons",
    // EV_MSC for MSC_SCAN, which carries a HID usage (button_usage).
    ev_bits: 1 << EV_SYN | 1 << EV_KEY | 1 << EV_MSC,
    key_bits: bits(BUTTON_KEYS),
    msc_bits: 1 << MSC_SCAN,
    abs_bits: bits([]),
    abs: Vec::new(),
    props: 0,
    clients: Mutex::default(),
    state: Mutex::default(),
});

/// The /dev/input entries to create: (name, rdev).
pub fn nodes() -> [(&'static str, u64); 3] {
    [("event0", rdev(FIRST_MINOR)), ("event1", rdev(FIRST_MINOR + 1)), ("event2", rdev(FIRST_MINOR + 2))]
}

fn rdev(minor: u32) -> u64 {
    super::block::makedev(INPUT_MAJOR, minor)
}

pub fn open(devt: u64) -> Option<Arc<Client>> {
    let device: &'static Device = [&*TOUCH, &*KEYBOARD, &*BUTTONS].into_iter().find(|d| rdev(d.minor) == devt)?;
    let c = Arc::new(Client { device, queue: Mutex::default(), clock: Mutex::new(0) });
    let mut clients = device.clients.lock().unwrap();
    clients.retain(|w| w.strong_count() > 0);
    clients.push(Arc::downgrade(&c));
    Some(c)
}

/// CLOCK_MONOTONIC's zero, fixed by whoever asks first (hv::clock::zero), as the
/// Instant deadlines count from.
pub fn boot_instant() -> Instant {
    crate::hv::clock::zero().1
}

/// CLOCK_MONOTONIC now (kernel/clock.rs). Event times must be on that clock:
/// InputDispatcher drops anything it thinks is more than ten seconds old.
pub(crate) fn since_boot() -> Duration {
    super::clock::monotonic()
}

impl Device {
    /// Queues one packet of events, ending in SYN_REPORT, for every reader.
    fn post(&self, events: &[(u16, u16, i32)]) {
        let now = since_boot();
        let clients = self.clients.lock().unwrap();
        let mut woken = Vec::new();
        for c in clients.iter().filter_map(Weak::upgrade) {
            woken.push(Arc::as_ptr(&c) as usize);
            let mut q = c.queue.lock().unwrap();
            for &(ty, code, value) in events.iter().chain(&[(EV_SYN, SYN_REPORT, 0)]) {
                if q.len() >= QUEUE_MAX {
                    q.pop_front();
                }
                q.push_back((now, ty, code, value));
            }
        }
        drop(clients);
        for c in woken {
            EVENTS.bump_key(c);
        }
    }

    /// Linux passes on only the keys a device says it has (input_get_disposition,
    /// drivers/input/input.c).
    fn has_key(&self, code: u16) -> bool {
        let b = code as usize;
        b < KEY_CNT && self.key_bits[b / 8] & 1 << (b % 8) != 0
    }

    /// A key going down or up, after `before` in the same packet.
    fn press(&self, code: u16, down: bool, before: &[(u16, u16, i32)]) {
        if !self.has_key(code) {
            eprintln!("zeroemu: {} has no key {code}", self.name);
            return;
        }
        let mut st = self.state.lock().unwrap();
        st.keys.resize(KEY_CNT / 8, 0);
        let b = code as usize;
        if down {
            st.keys[b / 8] |= 1 << (b % 8);
        } else {
            st.keys[b / 8] &= !(1 << (b % 8));
        }
        drop(st);
        let mut events = before.to_vec();
        events.push((EV_KEY, code, down as i32));
        self.post(&events);
    }

    /// The keys that are down.
    fn held(&self) -> Vec<u16> {
        let st = self.state.lock().unwrap();
        (0..st.keys.len() * 8).filter(|c| st.keys[c / 8] & 1 << (c % 8) != 0).map(|c| c as u16).collect()
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
            st.last_id = st.last_id.wrapping_add(1) & 0xffff;
            vec![
                (EV_ABS, ABS_MT_SLOT, 0),
                (EV_ABS, ABS_MT_TRACKING_ID, st.last_id),
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
    // What a reader asks for after resetting (InputReader does, when the display
    // changes): without it a finger that is down looks like it is not.
    for &(ty, code, value) in &events {
        if ty == EV_ABS {
            st.set_abs(code, value);
        }
    }
    st.keys.resize(KEY_CNT / 8, 0);
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

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scroll {
    /// A trackpad gesture's fingers landed.
    Begin,
    /// A trackpad gesture moved.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // only the macOS window has a trackpad
    Change,
    /// A trackpad gesture's fingers lifted.
    End,
    /// A mouse wheel, whose gestures have no end but silence.
    Wheel,
}

/// The finger a scroll is being played as.
struct ScrollFinger {
    /// Where it lands, and lands again when it runs out of screen.
    start: (f64, f64),
    /// Where it is, if it has landed.
    at: Option<(f64, f64)>,
    /// Travel before landing.
    pending: (f64, f64),
    last: Instant,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // read by scroll_idle
    wheel: bool,
}

static SCROLLING: Mutex<Option<ScrollFinger>> = Mutex::new(None);

/// How far a scroll must go before there is a finger: less would be a tap, or at
/// rest a long press, on whatever is under the pointer. Android's own touch slop is
/// a third of this on a phone-sized display.
const SCROLL_SLOP: f64 = 0.01;
/// A finger keeps out of the screen's edges, where gestures of their own start.
const SCROLL_INSET: f64 = 0.1;
/// A trackpad gesture that never said it ended.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // read by scroll_idle
const SCROLL_LOST: Duration = Duration::from_secs(1);

fn clamp_to_screen(p: (f64, f64)) -> (f64, f64) {
    (p.0.clamp(0.0, 1.0), p.1.clamp(0.0, 1.0))
}

/// Android has no scrolling on a touchscreen but a finger dragging, so a scroll at
/// (x, y) by (dx, dy), all from 0 to 1 across the display, is played as one. Lifting
/// at the gesture's speed flings, so the host's own momentum events aren't needed.
pub fn scroll(phase: Scroll, x: f64, y: f64, dx: f64, dy: f64) {
    let mut held = SCROLLING.lock().unwrap();
    if phase == Scroll::End {
        lift(&mut held);
        return;
    }
    if phase == Scroll::Begin {
        lift(&mut held); // the last gesture never said it ended
    }
    let f = held.get_or_insert_with(|| ScrollFinger {
        start: (x.clamp(SCROLL_INSET, 1.0 - SCROLL_INSET), y.clamp(SCROLL_INSET, 1.0 - SCROLL_INSET)),
        at: None,
        pending: (0.0, 0.0),
        last: Instant::now(),
        wheel: phase == Scroll::Wheel,
    });
    f.last = Instant::now();
    match f.at {
        None => {
            f.pending = (f.pending.0 + dx, f.pending.1 + dy);
            if f.pending.0.abs().max(f.pending.1.abs()) >= SCROLL_SLOP {
                let to = clamp_to_screen((f.start.0 + f.pending.0, f.start.1 + f.pending.1));
                touch(Touch::Down, f.start.0, f.start.1);
                touch(Touch::Move, to.0, to.1);
                f.at = Some(to);
            }
        }
        Some(at) => {
            let to = (at.0 + dx, at.1 + dy);
            if (0.0..=1.0).contains(&to.0) && (0.0..=1.0).contains(&to.1) {
                touch(Touch::Move, to.0, to.1);
                f.at = Some(to);
            } else {
                // Out of screen: a person would pick their finger up and start again.
                touch(Touch::Up, at.0, at.1);
                touch(Touch::Down, f.start.0, f.start.1);
                let to = clamp_to_screen((f.start.0 + dx, f.start.1 + dy));
                touch(Touch::Move, to.0, to.1);
                f.at = Some(to);
            }
        }
    }
}

fn lift(held: &mut Option<ScrollFinger>) {
    if let Some(ScrollFinger { at: Some(at), .. }) = held.take() {
        touch(Touch::Up, at.0, at.1);
    }
}

/// Lifts a scroll's finger now: something else is about to use the slot, or the
/// window is no longer in charge.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // called by the macOS window
pub fn scroll_cancel() {
    lift(&mut SCROLLING.lock().unwrap());
}

/// Lifts a mouse wheel's finger once the wheel has been still for `after`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // called by the macOS window
pub fn scroll_idle(after: Duration) {
    let mut held = SCROLLING.lock().unwrap();
    if held.as_ref().is_some_and(|f| f.last.elapsed() >= if f.wheel { after } else { SCROLL_LOST }) {
        lift(&mut held);
    }
}

/// Lets go of every key and button that is down: the window will not see them
/// released.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // called by the macOS window
pub fn release_keys() {
    for d in [&*KEYBOARD, &*BUTTONS] {
        for code in d.held() {
            d.press(code, false, &[]);
        }
    }
}

/// A key, by Linux KEY_* code. One the keyboard doesn't have is dropped, as Linux
/// drops it.
pub fn key(code: u16, down: bool) {
    KEYBOARD.press(code, down, &[]);
}

/// A button, by Linux KEY_* code: one of BUTTON_KEYS. Others are dropped.
pub fn button(code: u16, down: bool) {
    BUTTONS.press(code, down, &[]);
}

/// A button sent with a HID usage, which Android looks up in the key layout before
/// the key code (KeyLayoutMap.cpp, getKey). The usage goes first, as EV_MSC MSC_SCAN
/// in the same packet, as drivers/hid/hid-input.c sends it; Android forgets it at the
/// packet's end (HidUsageAccumulator.cpp). Settings is usage 0x0c019f on
/// KEY_CONTROLPANEL. A release needs no usage: Android gives the key up the key
/// code it gave the key down (KeyboardInputMapper.cpp).
pub fn button_usage(usage: u32, code: u16, down: bool) {
    BUTTONS.press(code, down, &[(EV_MSC, MSC_SCAN, usage as i32)]);
}

/// Serves ZEROEMU_INPUT_FIFO, if set.
pub fn start_input_fifo() {
    let Ok(path) = std::env::var("ZEROEMU_INPUT_FIFO") else { return };
    let _ = std::thread::Builder::new().name("input-fifo".into()).spawn(move || {
        use std::io::BufRead;
        loop {
            // Blocks until a writer opens it, and ends when the last one closes it.
            let f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("zeroemu: ZEROEMU_INPUT_FIFO {path}: {e}");
                    return;
                }
            };
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                input_line(&line);
            }
        }
    });
}

/// One ZEROEMU_INPUT_FIFO line.
fn input_line(line: &str) {
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
        ["wheel", x, y, dx, dy] => {
            if let (Ok(x), Ok(y), Ok(dx), Ok(dy)) = (x.parse(), y.parse(), dx.parse(), dy.parse()) {
                scroll(Scroll::Wheel, x, y, dx, dy);
            }
        }
        ["resize", w, h] => {
            if let (Ok(w), Ok(h)) = (w.parse(), h.parse()) {
                crate::gpu::resize_window(w, h);
            }
        }
        ["shot", path] => {
            if let Err(e) = crate::gpu::save_shown_frame(path) {
                eprintln!("zeroemu: shot {path}: {e}");
            }
        }
        ["key", code, state] => match code.parse() {
            Ok(code) => key(code, *state != "0"),
            Err(_) => eprintln!("zeroemu: bad input line {line:?}"),
        },
        ["button", code, state] => match code.parse() {
            Ok(code) => button(code, *state != "0"),
            Err(_) => eprintln!("zeroemu: bad input line {line:?}"),
        },
        ["usage", usage, code, state] => {
            let hex = usage.strip_prefix("0x").unwrap_or(usage);
            match (u32::from_str_radix(hex, 16), code.parse()) {
                (Ok(usage), Ok(code)) => button_usage(usage, code, *state != "0"),
                _ => eprintln!("zeroemu: bad input line {line:?}"),
            }
        }
        // The window's toolbar and menu, which it owns: a test drives the same table.
        ["action" | "menu" | "toolbar" | "keyeq" | "click" | "location", ..] => crate::gpu::control_line(line),
        _ => eprintln!("zeroemu: bad input line {line:?}"),
    }
}

impl Client {
    pub fn readable(&self) -> bool {
        !self.queue.lock().unwrap().is_empty()
    }

    fn encode(&self, (at, ty, code, value): (Duration, u16, u16, i32), out: &mut Vec<u8>) {
        let t = if *self.clock.lock().unwrap() == CLOCK_MONOTONIC {
            at
        } else {
            // CLOCK_REALTIME, as the guest reads it (kernel/clock.rs).
            Duration::from_nanos(super::clock::realtime_at(at.as_nanos() as u64))
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
            let seen = EVENTS.watch_key(self as *const Self as usize);
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
            // EVIOCGMTSLOTS: the axis asked about, then its value in each slot.
            (READ, 0x0a) => {
                let axis = input()?;
                if !(ABS_MT_FIRST as i32..=ABS_MT_LAST as i32).contains(&axis) || !d.abs.iter().any(|a| a.0 == ABS_MT_SLOT) {
                    return Err(EINVAL);
                }
                let idle = if axis == ABS_MT_TRACKING_ID as i32 { -1 } else { 0 };
                let slot0 = d.state.lock().unwrap().abs(axis as u16).unwrap_or(idle);
                let mut b = axis.to_le_bytes().to_vec();
                b.extend_from_slice(&slot0.to_le_bytes());
                for _ in 1..SLOTS {
                    b.extend_from_slice(&idle.to_le_bytes());
                }
                b.truncate(size);
                exact(b)
            }
            // EVIOCGKEY: the whole bitmap, as Linux copies it, even before any key.
            (READ, 0x18) => {
                let mut keys = d.state.lock().unwrap().keys.clone();
                keys.resize(KEY_CNT / 8, 0);
                sized(&keys)
            }
            (READ, 0x19..=0x1b) => sized(&[0u8; 96]),
            (READ, 0x20) => sized(&d.ev_bits.to_le_bytes()),
            (READ, 0x21) => sized(&d.key_bits),
            (READ, 0x23) => sized(&d.abs_bits),
            // EVIOCGBIT(EV_MSC): MSC_MAX is 7, so Linux copies one long (bits_to_user,
            // drivers/input/evdev.c).
            (READ, 0x24) => sized(&(d.msc_bits as u64).to_le_bytes()),
            (READ, 0x22 | 0x25..=0x3f) => sized(&[0u8; 96]),
            (READ, 0x40..=0x7f) => {
                let axis = (nr - 0x40) as u16;
                let &(_, min, max) = d.abs.iter().find(|a| a.0 == axis).ok_or(EINVAL)?;
                let value = d.state.lock().unwrap().abs(axis).unwrap_or(if axis == ABS_MT_TRACKING_ID { -1 } else { 0 });
                let mut b = Vec::new();
                for v in [value, min, max, 0, 0, 0] {
                    b.extend_from_slice(&v.to_le_bytes());
                }
                b.truncate(size);
                exact(b) // unlike the string and bitmap reads, it returns 0
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The devices are global, so these can't run at once.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn drain(c: &Client) -> Vec<(u16, u16, i32)> {
        c.queue.lock().unwrap().drain(..).map(|e| (e.1, e.2, e.3)).filter(|e| e.0 != EV_SYN).collect()
    }

    fn slots(c: &Client, axis: u16) -> Vec<i32> {
        let cmd = 2u64 << 30 | 44 << 16 | (b'E' as u64) << 8 | 0x0a;
        let (ret, bytes) = c.ioctl(cmd, || Ok(axis as i32)).unwrap();
        assert_eq!(ret, 0);
        bytes.chunks_exact(4).map(|b| i32::from_le_bytes(b.try_into().unwrap())).collect()
    }

    #[test]
    fn slots_report_the_finger() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR)).unwrap();
        touch(Touch::Down, 0.5, 0.25);
        let got = slots(&c, ABS_MT_TRACKING_ID);
        assert_eq!(got.len(), 11);
        assert_eq!(got[0], ABS_MT_TRACKING_ID as i32, "the axis stays where it was");
        assert!(got[1] >= 0, "the finger's id in slot 0");
        assert!(got[2..].iter().all(|&v| v == -1), "the rest are free: {got:?}");
        assert_eq!(slots(&c, ABS_MT_POSITION_Y)[1], scale(0.25));
        touch(Touch::Up, 0.5, 0.25);
        assert_eq!(slots(&c, ABS_MT_TRACKING_ID)[1], -1);
        let unknown = c.ioctl(2u64 << 30 | 44 << 16 | (b'E' as u64) << 8 | 0x0a, || Ok(ABS_X as i32));
        assert_eq!(unknown.err(), Some(EINVAL), "not an MT axis");
    }

    #[test]
    fn a_wheel_is_a_drag_that_lifts_when_still() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR)).unwrap();
        scroll(Scroll::Wheel, 0.5, 0.5, 0.0, 0.1);
        scroll(Scroll::Wheel, 0.5, 0.5, 0.0, 0.1);
        let got = drain(&c);
        assert!(got.contains(&(EV_KEY, BTN_TOUCH, 1)), "landed: {got:?}");
        assert_eq!(got.iter().filter(|e| e.1 == ABS_MT_TRACKING_ID).count(), 1, "one gesture");
        assert!(got.contains(&(EV_ABS, ABS_MT_POSITION_Y, scale(0.7))), "moved by both: {got:?}");
        scroll_idle(Duration::from_secs(60));
        assert!(drain(&c).is_empty(), "the wheel hasn't been still that long");
        scroll_idle(Duration::ZERO);
        assert!(drain(&c).contains(&(EV_KEY, BTN_TOUCH, 0)), "lifted");
    }

    #[test]
    fn a_scroll_too_small_to_be_one_touches_nothing() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR)).unwrap();
        scroll(Scroll::Begin, 0.5, 0.5, 0.0, 0.0);
        scroll(Scroll::Change, 0.5, 0.5, 0.0, SCROLL_SLOP / 4.0);
        scroll(Scroll::End, 0.5, 0.5, 0.0, 0.0);
        assert!(drain(&c).is_empty(), "no tap on what's under the pointer");
        scroll(Scroll::Wheel, 0.5, 0.5, 0.0, 0.0);
        scroll_idle(Duration::ZERO);
        assert!(drain(&c).is_empty(), "nor from a wheel that didn't move");
    }

    #[test]
    fn every_landing_is_followed_by_travel() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR)).unwrap();
        // Low on the screen, moving off it: never a press and release in one place.
        scroll(Scroll::Wheel, 0.5, 0.98, 0.0, 0.03);
        let got = drain(&c);
        assert!(got.contains(&(EV_ABS, ABS_MT_POSITION_Y, scale(0.9))), "kept out of the edge: {got:?}");
        assert_eq!(got.last(), Some(&(EV_ABS, ABS_Y, scale(0.93))), "moved: {got:?}");
        scroll(Scroll::Wheel, 0.5, 0.98, 0.0, 0.2);
        let got = drain(&c);
        assert!(got.contains(&(EV_KEY, BTN_TOUCH, 0)) && got.contains(&(EV_KEY, BTN_TOUCH, 1)), "lifted and landed: {got:?}");
        assert!(got.contains(&(EV_ABS, ABS_MT_POSITION_Y, scale(0.9))), "back at the start: {got:?}");
        assert_eq!(got.last(), Some(&(EV_ABS, ABS_Y, scale(1.0))), "and moved from it: {got:?}");
        scroll_cancel();
        assert!(drain(&c).contains(&(EV_KEY, BTN_TOUCH, 0)), "cancelling lifts");
        scroll_cancel();
        assert!(drain(&c).is_empty(), "nothing left to lift");
    }

    #[test]
    fn held_keys_are_let_go() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR + 1)).unwrap();
        key(30, true);
        key(42, true);
        key(30, false);
        drain(&c);
        release_keys();
        assert_eq!(drain(&c), vec![(EV_KEY, 42, 0)]);
        release_keys();
        assert!(drain(&c).is_empty());
    }

    /// An EVIOC* read of `size` bytes: what it copies out.
    fn ioc_read(c: &Client, nr: u64, size: u64) -> Vec<u8> {
        c.ioctl(2u64 << 30 | size << 16 | (b'E' as u64) << 8 | nr, || Err(EINVAL)).unwrap().1
    }

    fn set_bits(bytes: &[u8]) -> Vec<u16> {
        (0..bytes.len() * 8).filter(|&b| bytes[b / 8] & 1 << (b % 8) != 0).map(|b| b as u16).collect()
    }

    /// The events queued, SYN_REPORTs and all.
    fn drain_all(c: &Client) -> Vec<(u16, u16, i32)> {
        c.queue.lock().unwrap().drain(..).map(|e| (e.1, e.2, e.3)).collect()
    }

    #[test]
    fn the_buttons_have_only_their_keys() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR + 2)).unwrap();
        assert_eq!(nodes()[2], ("event2", rdev(FIRST_MINOR + 2)));
        assert_eq!(ioc_read(&c, 0x06, 256), b"zeroemu_buttons\0");
        let id: Vec<u16> = ioc_read(&c, 0x02, 8).chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())).collect();
        assert_eq!(id, [BUS_VIRTUAL, 0x1af4, 0x1082, 1], "the bus, vendor and version of the others");
        assert_eq!(set_bits(&ioc_read(&c, 0x20, 8)), [EV_SYN, EV_KEY, EV_MSC]);
        // No letter (keyboard_classifier.rs's 16-27, 30-41, 43-53) and no Q above all.
        assert_eq!(set_bits(&ioc_read(&c, 0x21, 96)), [99, 113, 114, 115, 116, 142, 158, 172, 204, KEY_CONTROLPANEL, 580]);
        // EventHub reads EV_MSC's bits into four bytes.
        assert_eq!(set_bits(&ioc_read(&c, 0x24, 4)), [MSC_SCAN]);
        assert_eq!(ioc_read(&c, 0x24, 64).len(), 8);
        assert_eq!(ioc_read(&c, 0x18, 128).len(), 96, "EVIOCGKEY is the whole bitmap");
        for minor in [FIRST_MINOR, FIRST_MINOR + 1] {
            let other = open(rdev(minor)).unwrap();
            assert!(set_bits(&ioc_read(&other, 0x24, 4)).is_empty(), "only the buttons send usages");
        }
    }

    #[test]
    fn keys_a_device_lacks_are_dropped() {
        let _g = SERIAL.lock().unwrap();
        let kb = open(rdev(FIRST_MINOR + 1)).unwrap();
        let c = open(rdev(FIRST_MINOR + 2)).unwrap();
        // EventHub aborts on these.
        key(0x300, true);
        key(u16::MAX, true);
        button(0x300, true);
        button_usage(0x000c_019f, 0x300, true);
        // A letter would make the buttons an alphabetic keyboard.
        button(30, true);
        key(KEY_CONTROLPANEL, true);
        assert!(drain_all(&kb).is_empty());
        assert!(drain_all(&c).is_empty());
        assert!(set_bits(&ioc_read(&kb, 0x18, 96)).is_empty());
        assert!(set_bits(&ioc_read(&c, 0x18, 96)).is_empty());
    }

    #[test]
    fn a_usage_goes_before_its_key() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR + 2)).unwrap();
        button_usage(0x000c_019f, KEY_CONTROLPANEL, true);
        button_usage(0x000c_019f, KEY_CONTROLPANEL, false);
        let settings = |v| [(EV_MSC, MSC_SCAN, 0x000c_019f), (EV_KEY, KEY_CONTROLPANEL, v), (EV_SYN, SYN_REPORT, 0)];
        assert_eq!(drain_all(&c), [settings(1), settings(0)].concat());
        button(158, true);
        button(158, false);
        assert_eq!(drain_all(&c), [(EV_KEY, 158, 1), (EV_SYN, SYN_REPORT, 0), (EV_KEY, 158, 0), (EV_SYN, SYN_REPORT, 0)]);
    }

    #[test]
    fn held_buttons_are_let_go() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR + 2)).unwrap();
        button(116, true);
        button_usage(0x000c_019f, KEY_CONTROLPANEL, true);
        assert_eq!(set_bits(&ioc_read(&c, 0x18, 96)), [116, KEY_CONTROLPANEL]);
        drain(&c);
        release_keys();
        assert_eq!(drain(&c), [(EV_KEY, 116, 0), (EV_KEY, KEY_CONTROLPANEL, 0)]);
        assert!(set_bits(&ioc_read(&c, 0x18, 96)).is_empty());
        release_keys();
        assert!(drain(&c).is_empty());
    }

    #[test]
    fn fifo_lines_reach_the_buttons() {
        let _g = SERIAL.lock().unwrap();
        let c = open(rdev(FIRST_MINOR + 2)).unwrap();
        input_line("usage 0x0c019f 579 1");
        input_line("usage c019f 579 0");
        input_line("button 204 1");
        input_line("button 204 0");
        input_line("button x 1");
        input_line("usage 0xzz 579 1");
        let got = drain(&c);
        assert_eq!(got, [(EV_MSC, MSC_SCAN, 0x000c_019f), (EV_KEY, 579, 1), (EV_MSC, MSC_SCAN, 0x000c_019f), (EV_KEY, 579, 0), (EV_KEY, 204, 1), (EV_KEY, 204, 0)]);
    }
}
