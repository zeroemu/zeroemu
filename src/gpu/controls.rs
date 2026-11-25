//! Device controls: what the window's toolbar and menu bar, and the test FIFO, ask of
//! the device. Each is a press of a phone's button or a key Android knows, sent from
//! a buttons-only input device that Android gives its stock Generic.kl key layout
//! (src/kernel/evdev.rs), a turn of the whole phone, which the accelerometer reports
//! (src/kernel/vsock.rs) and the window shows, or a picture of the screen saved on
//! the host. The window decides how they look; this file decides what they do, the
//! same on every host.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Back,
    Home,
    Recents,
    Notifications,
    Settings,
    VolumeUp,
    VolumeDown,
    Mute,
    Power,
    Lock,
    PowerMenu,
    RotateLeft,
    RotateRight,
    Screenshot,
    AndroidScreenshot,
}

/// A menu shortcut: a character or an arrow, with Command and maybe Shift.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shortcut {
    pub key: Key,
    pub shift: bool,
}

const fn cmd(c: char) -> Option<Shortcut> {
    Some(Shortcut { key: Key::Char(c), shift: false })
}

const fn shift_cmd(c: char) -> Option<Shortcut> {
    Some(Shortcut { key: Key::Char(c), shift: true })
}

const fn cmd_key(key: Key) -> Option<Shortcut> {
    Some(Shortcut { key, shift: false })
}

impl Action {
    pub const ALL: [Action; 15] = [
        Action::Back,
        Action::Home,
        Action::Recents,
        Action::Notifications,
        Action::Settings,
        Action::VolumeUp,
        Action::VolumeDown,
        Action::Mute,
        Action::Power,
        Action::Lock,
        Action::PowerMenu,
        Action::RotateLeft,
        Action::RotateRight,
        Action::Screenshot,
        Action::AndroidScreenshot,
    ];

    /// Its name for the test FIFO (`action NAME`) and its toolbar item's identifier.
    pub fn name(self) -> &'static str {
        match self {
            Action::Back => "back",
            Action::Home => "home",
            Action::Recents => "recents",
            Action::Notifications => "notifications",
            Action::Settings => "settings",
            Action::VolumeUp => "volume-up",
            Action::VolumeDown => "volume-down",
            Action::Mute => "mute",
            Action::Power => "power",
            Action::Lock => "lock",
            Action::PowerMenu => "power-menu",
            Action::RotateLeft => "rotate-left",
            Action::RotateRight => "rotate-right",
            Action::Screenshot => "screenshot",
            Action::AndroidScreenshot => "android-screenshot",
        }
    }

    pub fn from_name(name: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.name() == name)
    }

    /// Menus and toolbar items carry it as their tag, which starts at 1: 0 is every
    /// item's default.
    pub fn tag(self) -> i64 {
        Action::ALL.iter().position(|&a| a == self).unwrap() as i64 + 1
    }

    pub fn from_tag(tag: i64) -> Option<Action> {
        Action::ALL.get(usize::try_from(tag.checked_sub(1)?).ok()?).copied()
    }

    /// Its menu item's title.
    pub fn title(self) -> &'static str {
        match self {
            Action::Back => "Back",
            Action::Home => "Home",
            Action::Recents => "Recent Apps",
            Action::Notifications => "Notifications",
            Action::Settings => "Android Settings",
            Action::VolumeUp => "Volume Up",
            Action::VolumeDown => "Volume Down",
            Action::Mute => "Mute",
            Action::Power => "Power Button",
            Action::Lock => "Lock Screen",
            Action::PowerMenu => "Power Menu",
            Action::RotateLeft => "Rotate Left",
            Action::RotateRight => "Rotate Right",
            Action::Screenshot => "Save Screenshot",
            Action::AndroidScreenshot => "Take Screenshot in Android",
        }
    }

    /// Its toolbar item's label: short, as toolbar labels go.
    pub fn label(self) -> &'static str {
        match self {
            Action::Recents => "Recents",
            Action::Settings => "Settings",
            Action::Power => "Power",
            Action::Lock => "Lock",
            Action::RotateRight => "Rotate",
            Action::Screenshot => "Screenshot",
            Action::AndroidScreenshot => "Android Screenshot",
            a => a.title(),
        }
    }

    /// What its toolbar item's tooltip says.
    pub fn tooltip(self) -> &'static str {
        match self {
            Action::Back => "Go back (Esc)",
            Action::Home => "Go to the Home screen (F1)",
            Action::Recents => "Show recent apps (F2)",
            Action::Notifications => "Open or close the notifications",
            Action::Settings => "Open Android's Settings",
            Action::VolumeUp => "Turn the volume up",
            Action::VolumeDown => "Turn the volume down",
            Action::Mute => "Mute or unmute the sound",
            Action::Power => "Press the power button: sleep or wake the screen",
            Action::Lock => "Lock the screen",
            Action::PowerMenu => "Show the menu to power off or restart",
            Action::RotateLeft => "Turn the device to the left",
            Action::RotateRight => "Turn the device to the right",
            Action::Screenshot => "Save a picture of the screen to your Mac",
            Action::AndroidScreenshot => "Have Android take a screenshot, saved on the device",
        }
    }

    /// An SF Symbol present since macOS 11 (`imageWithSystemSymbolName:`), drawn the
    /// Mac's way rather than with Android's navigation glyphs.
    pub fn symbol(self) -> &'static str {
        match self {
            Action::Back => "chevron.backward",
            Action::Home => "house",
            Action::Recents => "square.on.square",
            Action::Notifications => "bell",
            Action::Settings => "gearshape",
            Action::VolumeUp => "speaker.wave.3",
            Action::VolumeDown => "speaker.wave.1",
            Action::Mute => "speaker.slash",
            Action::Power => "power",
            Action::Lock => "lock",
            Action::PowerMenu => "power.circle",
            Action::RotateLeft => "rotate.left",
            Action::RotateRight => "rotate.right",
            Action::Screenshot => "camera",
            Action::AndroidScreenshot => "camera.viewfinder",
        }
    }

    /// Its menu shortcut, always with Command. Where Android has a Meta shortcut for
    /// the same thing (InputGestureManager.java: Meta+N notifications, Meta+I
    /// settings, Meta+L lock, Meta+S screenshot), it's the same letter. Home is ⇧⌘H,
    /// as ⌘H hides a Mac app; volume and rotation take the arrows, as in Apple's
    /// Simulator.
    pub fn shortcut(self) -> Option<Shortcut> {
        match self {
            Action::Back => cmd('['),
            Action::Home => shift_cmd('h'),
            Action::Recents => shift_cmd('r'),
            Action::Notifications => cmd('n'),
            Action::Settings => cmd('i'),
            Action::VolumeUp => cmd_key(Key::Up),
            Action::VolumeDown => cmd_key(Key::Down),
            Action::Power => shift_cmd('p'),
            Action::Lock => cmd('l'),
            Action::RotateLeft => cmd_key(Key::Left),
            Action::RotateRight => cmd_key(Key::Right),
            Action::Screenshot => cmd('s'),
            Action::Mute | Action::PowerMenu | Action::AndroidScreenshot => None,
        }
    }
}

/// Linux key codes on the buttons device, as Generic.kl maps them.
const KEY_SYSRQ: u16 = 99; // SYSRQ: Android's own screenshot
const KEY_MUTE: u16 = 113; // VOLUME_MUTE
const KEY_VOLUMEDOWN: u16 = 114;
const KEY_VOLUMEUP: u16 = 115;
const KEY_POWER: u16 = 116;
const KEY_SLEEP: u16 = 142; // SLEEP: sleeps the device and never wakes it
const KEY_BACK: u16 = 158;
const KEY_HOMEPAGE: u16 = 172; // HOME
const KEY_DASHBOARD: u16 = 204; // NOTIFICATION
const KEY_APPSELECT: u16 = 580; // APP_SWITCH
/// KEYCODE_SETTINGS has only a HID usage in Generic.kl (`key usage 0x0c019F
/// SETTINGS`), which KeyLayoutMap.cpp looks up before the scan code.
const USAGE_SETTINGS: u32 = 0x000c_019f;

fn press(code: u16) {
    use crate::kernel::evdev;
    evdev::button(code, true);
    evdev::button(code, false);
}

/// Does what the user asked for. From any thread.
pub fn perform(a: Action) {
    use crate::kernel::evdev;
    match a {
        Action::Back => press(KEY_BACK),
        Action::Home => press(KEY_HOMEPAGE),
        Action::Recents => press(KEY_APPSELECT),
        Action::Notifications => press(KEY_DASHBOARD),
        Action::Settings => {
            evdev::button_usage(USAGE_SETTINGS, evdev::KEY_CONTROLPANEL, true);
            evdev::button_usage(USAGE_SETTINGS, evdev::KEY_CONTROLPANEL, false);
        }
        Action::VolumeUp => press(KEY_VOLUMEUP),
        Action::VolumeDown => press(KEY_VOLUMEDOWN),
        Action::Mute => press(KEY_MUTE),
        Action::Power => press(KEY_POWER),
        Action::Lock => press(KEY_SLEEP),
        Action::AndroidScreenshot => press(KEY_SYSRQ),
        Action::PowerMenu => {
            // A long press of Power is the assistant on this image
            // (config_longPressOnPowerBehavior=5); Volume Up and Power together are the
            // power menu (config_keyChordPowerVolumeUp=2, KeyGestureController.java).
            // Letting go cancels the menu if it isn't up yet (PhoneWindowManager's
            // cancelGlobalActionsAction), so they are held for as long as a person
            // would hold them, even while Android is busy.
            let _ = std::thread::Builder::new().name("power menu".into()).spawn(|| {
                evdev::button(KEY_VOLUMEUP, true);
                evdev::button(KEY_POWER, true);
                std::thread::sleep(std::time::Duration::from_millis(1500));
                evdev::button(KEY_POWER, false);
                evdev::button(KEY_VOLUMEUP, false);
            });
        }
        Action::RotateLeft => rotate(1),
        Action::RotateRight => rotate(3),
        Action::Screenshot => save_screenshot(),
    }
}

/// How many quarter turns counterclockwise the phone has been turned from upright, as
/// the user sees it on the Mac's screen.
static TURNS: AtomicU8 = AtomicU8::new(0);

pub fn turns() -> u8 {
    TURNS.load(Ordering::Relaxed)
}

/// Turns the phone `by` quarter turns counterclockwise. Its accelerometer says so,
/// and Android turns what it draws if it wants to, as a phone does: an app that
/// keeps to portrait stays sideways. The window shows the panel turned the same way.
fn rotate(by: u8) {
    // The UI thread and the test FIFO's may both turn it: one turn at a time, so the
    // accelerometer ends up where the window does.
    static TURNING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = TURNING.lock().unwrap_or_else(|p| p.into_inner());
    let now = (turns() + by) % 4;
    TURNS.store(now, Ordering::Relaxed);
    crate::kernel::vsock::set_posture(now);
    super::turned();
}

/// The panel's shape as the window shows it, turned `turns` quarter turns: its own
/// width and height, swapped while it's on its side. A turn swaps whatever shape the
/// panel has: a tablet's is wide to begin with (its natural orientation is
/// landscape), so on its side it's tall.
pub fn shown_size(panel: (u32, u32), turns: u8) -> (u32, u32) {
    if turns % 2 == 1 { (panel.1, panel.0) } else { panel }
}

/// Whether a window `window` points in size is the other way round from the picture
/// it shows, of shape `shown`: wide where the picture is tall, or tall where it's
/// wide. Turning the device gives such a window the picture's shape; a square window
/// or picture keeps its own.
pub fn other_way_round(window: (f64, f64), shown: (u32, u32)) -> bool {
    let (w, h) = (shown.0 as f64, shown.1 as f64);
    (window.0 > window.1 && w < h) || (window.0 < window.1 && w > h)
}

/// Where a point shown on the Mac lands on the panel: (u, v) from the shown picture's
/// top left, as fractions of its width and height, to (x, y) on the panel, from its
/// top left. The picture is the panel turned `turns` quarter turns counterclockwise.
/// Android takes touches in the panel's own coordinates and turns them itself
/// (virtio_input_multi_touch_1.idc has touch.orientationAware = 1).
pub fn to_panel(turns: u8, u: f64, v: f64) -> (f64, f64) {
    match turns % 4 {
        0 => (u, v),
        1 => (1.0 - v, u),
        2 => (1.0 - u, 1.0 - v),
        _ => (v, 1.0 - u),
    }
}

/// A movement on the shown picture as a movement on the panel, as `to_panel` maps points.
pub fn delta_to_panel(turns: u8, du: f64, dv: f64) -> (f64, f64) {
    match turns % 4 {
        0 => (du, dv),
        1 => (-dv, du),
        2 => (-du, -dv),
        _ => (dv, -du),
    }
}

/// Top-down rows of 4-byte pixels turned `turns` quarter turns counterclockwise.
/// Returns the new width and height.
pub fn rotate_pixels(w: u32, h: u32, px: &[u8], turns: u8) -> (u32, u32, Vec<u8>) {
    let (w, h) = (w as usize, h as usize);
    let turns = turns % 4;
    if turns == 0 {
        return (w as u32, h as u32, px.to_vec());
    }
    let (ow, oh) = if turns % 2 == 1 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; ow * oh * 4];
    for oy in 0..oh {
        for ox in 0..ow {
            // The panel pixel this one shows: to_panel, in whole pixels.
            let (x, y) = match turns {
                1 => (w - 1 - oy, ox),
                2 => (w - 1 - ox, h - 1 - oy),
                _ => (oy, h - 1 - ox),
            };
            let (o, i) = ((oy * ow + ox) * 4, (y * w + x) * 4);
            out[o..o + 4].copy_from_slice(&px[i..i + 4]);
        }
    }
    (ow as u32, oh as u32, out)
}

/// Saves the screen as the Mac shows it, upright, as a PNG where the Mac saves its
/// own screenshots. Off the UI thread: reading the frame back waits for the GPU's
/// thread, which may be waiting for the UI thread.
fn save_screenshot() {
    let turns = turns();
    let _ = std::thread::Builder::new().name("screenshot".into()).spawn(move || match super::save_screenshot(turns) {
        Ok(path) => eprintln!("zeroemu: saved a screenshot to {}", path.display()),
        Err(e) => eprintln!("zeroemu: couldn't save a screenshot: {e}"),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_tags_and_shortcuts_are_each_used_once() {
        for a in Action::ALL {
            assert_eq!(Action::from_name(a.name()), Some(a));
            assert_eq!(Action::from_tag(a.tag()), Some(a));
        }
        assert_eq!(Action::from_tag(0), None);
        assert_eq!(Action::from_tag(Action::ALL.len() as i64 + 1), None);
        let keys: Vec<Shortcut> = Action::ALL.iter().filter_map(|a| a.shortcut()).collect();
        for (i, k) in keys.iter().enumerate() {
            assert!(!keys[i + 1..].contains(k), "{k:?} is taken twice");
            // The Mac's own: ⌘H hide, ⌘Q quit, ⌘M minimize, ⌘W close.
            if let (Key::Char(c), false) = (k.key, k.shift) {
                assert!(!"hqmw".contains(c), "⌘{c} is the Mac's");
            }
        }
    }

    /// The four corners of the shown picture land on the panel's, each turn the right way.
    #[test]
    fn points_go_back_onto_the_panel() {
        // Turned left (counterclockwise), the panel's top edge is on the left: the
        // shown top left is the panel's top right.
        assert_eq!(to_panel(1, 0.0, 0.0), (1.0, 0.0));
        assert_eq!(to_panel(1, 0.0, 1.0), (0.0, 0.0));
        // Turned right, the shown top left is the panel's bottom left.
        assert_eq!(to_panel(3, 0.0, 0.0), (0.0, 1.0));
        assert_eq!(to_panel(2, 0.0, 0.0), (1.0, 1.0));
        for t in 0..4 {
            let (x0, y0) = to_panel(t, 0.25, 0.5);
            let (x1, y1) = to_panel(t, 0.25 + 0.1, 0.5 - 0.2);
            let (dx, dy) = delta_to_panel(t, 0.1, -0.2);
            assert!((x1 - x0 - dx).abs() < 1e-9 && (y1 - y0 - dy).abs() < 1e-9, "turn {t}");
        }
    }

    /// A turn swaps the panel's own shape, a phone's tall one or a tablet's wide one,
    /// and a window the other way round from what it shows is turned to match.
    #[test]
    fn turns_swap_the_panels_own_shape() {
        let phone = (1080, 2400);
        let tablet = (2560, 1600);
        assert_eq!(shown_size(phone, 0), (1080, 2400));
        assert_eq!(shown_size(phone, 1), (2400, 1080));
        assert_eq!(shown_size(phone, 2), (1080, 2400));
        assert_eq!(shown_size(tablet, 0), (2560, 1600));
        assert_eq!(shown_size(tablet, 3), (1600, 2560));
        assert_eq!(shown_size(tablet, 6), (2560, 1600));
        // The first window has the unturned panel's shape: nothing to change.
        assert!(!other_way_round((405.0, 900.0), shown_size(phone, 0)));
        assert!(!other_way_round((1280.0, 800.0), shown_size(tablet, 0)));
        // A quarter turn: the phone's window becomes wide, the tablet's tall.
        assert!(other_way_round((405.0, 900.0), shown_size(phone, 1)));
        assert!(other_way_round((1280.0, 800.0), shown_size(tablet, 1)));
        // Upside down is the panel's own shape again.
        assert!(!other_way_round((1280.0, 800.0), shown_size(tablet, 2)));
        // A turned window turning back.
        assert!(other_way_round((800.0, 1280.0), shown_size(tablet, 0)));
        // Square: nothing to swap.
        assert!(!other_way_round((600.0, 600.0), shown_size(tablet, 1)));
        assert!(!other_way_round((900.0, 405.0), shown_size((1600, 1600), 1)));
    }

    /// Pixels move as points do, and four turns are none.
    #[test]
    fn pixels_turn_as_points_do() {
        let (w, h) = (3u32, 2u32);
        let px: Vec<u8> = (0..w * h).flat_map(|i| [i as u8, 0, 0, 255]).collect();
        for t in 0..4u8 {
            let (ow, oh, out) = rotate_pixels(w, h, &px, t);
            assert_eq!((ow, oh), if t % 2 == 1 { (h, w) } else { (w, h) });
            for oy in 0..oh {
                for ox in 0..ow {
                    let (x, y) = to_panel(t, (ox as f64 + 0.5) / ow as f64, (oy as f64 + 0.5) / oh as f64);
                    let (x, y) = ((x * w as f64) as u32, (y * h as f64) as u32);
                    assert_eq!(out[((oy * ow + ox) * 4) as usize], (y * w + x) as u8, "turn {t} at {ox},{oy}");
                }
            }
        }
        let mut cur = (w, h, px.clone());
        for _ in 0..4 {
            cur = rotate_pixels(cur.0, cur.1, &cur.2, 1);
        }
        assert_eq!(cur, (w, h, px));
    }
}
