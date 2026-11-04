//! Win32 window for gfxstream. The loader (LoadLibraryExW) is real; creating
//! the HWND is not, so a display open fails with a TODO instead of a black box.
//! TODO: CreateWindowExW, pump a message loop, pass the HWND to
//! gfxstream_backend_setup_window.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct NativeWindow {
    pub handle: *mut c_void,
    pub width: i32,
    pub height: i32,
    pub px_width: i32,
    pub px_height: i32,
}

pub fn open(fb_w: u32, fb_h: u32) -> Result<NativeWindow, String> {
    let _ = (fb_w, fb_h);
    Err("gfxstream: Win32 window is not implemented (CreateWindowExW)".into())
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
