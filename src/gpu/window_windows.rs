//! Win32 window for gfxstream. The loader (LoadLibraryExW) is real; creating
//! the HWND is not, so a display open fails with a TODO instead of a black box.
//! TODO: CreateWindowExW, pump a message loop, pass the HWND to
//! gfxstream_backend_setup_window.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// TODO: a window for a device screen of `display`, scaled to fit, as on macOS.
pub fn open(display: super::Display) -> Result<(), String> {
    let _ = display;
    Err("gfxstream: Win32 window is not implemented (CreateWindowExW)".into())
}

/// TODO: draw frames once the Win32 window exists.
pub fn present(w: u32, h: u32, stride: u32, fourcc: u32, pixels: &[u8]) {
    let _ = (w, h, stride, fourcc, pixels);
}

/// TODO: the newest frame, once there is a window to give one to.
pub fn shown_frame() -> Option<(u32, u32, Vec<u8>)> {
    None
}

/// TODO: the frame's size, once there is a window to fit it to.
pub fn set_shown_size(w: u32, h: u32) {
    let _ = (w, h);
}

pub fn window_id() -> Option<u64> {
    None
}

pub fn pump_until(done: &AtomicBool) {
    while !done.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn pump_for(secs: f64) {
    std::thread::sleep(Duration::from_secs_f64(secs));
}

/// TODO: whether the window can be seen, once there is one.
pub fn on_screen() -> bool {
    true
}
