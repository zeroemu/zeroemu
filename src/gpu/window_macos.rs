//! AppKit window the gfxstream renderer draws into. Every call here runs on
//! the process main thread: AppKit is not safe anywhere else, and gfxstream's
//! repaint is dispatched back onto this thread.

use std::ffi::{CString, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Clone, Copy)]
struct NSPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NSSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NSRect {
    origin: NSPoint,
    size: NSSize,
}

pub struct NativeWindow {
    pub handle: *mut c_void,
    /// Content size in points. `setupWindow` uses this as the NSView frame;
    /// a pixel size is placed in point coordinates and hangs off the window
    /// (on a 2x display, 810x1800 at y=-900, so only a quarter of it shows).
    pub width: i32,
    pub height: i32,
    /// Same content size in pixels. The guest display matches the view's
    /// backing store, so a Retina window is 1:1 with what Android renders.
    pub px_width: i32,
    pub px_height: i32,
}

static APP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static WINDOW_ID: AtomicU64 = AtomicU64::new(0);

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const i8) -> *mut c_void;
    fn sel_registerName(name: *const i8) -> *mut c_void;
    fn objc_msgSend();
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    static NSDefaultRunLoopMode: *mut c_void;
}

fn cls(name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    unsafe { objc_getClass(c.as_ptr()) }
}

fn sel(name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    unsafe { sel_registerName(c.as_ptr()) }
}

unsafe fn msg0(obj: *mut c_void, sel: *mut c_void) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_void(obj: *mut c_void, sel: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_id(obj: *mut c_void, sel: *mut c_void, a: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_i64(obj: *mut c_void, sel: *mut c_void, a: i64) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, i64) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_bool(obj: *mut c_void, sel: *mut c_void, a: i8) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, i8) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_f64_ret(obj: *mut c_void, sel: *mut c_void) -> f64 {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> f64 = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_f64_id(obj: *mut c_void, sel: *mut c_void, a: f64) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, f64) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_i64_ret(obj: *mut c_void, sel: *mut c_void) -> i64 {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> i64 = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_rect(obj: *mut c_void, sel: *mut c_void) -> NSRect {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> NSRect = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_init_window(obj: *mut c_void, sel: *mut c_void, rect: NSRect, style: u64, backing: u64, defer: i8) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, NSRect, u64, u64, i8) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, rect, style, backing, defer) }
}

unsafe fn msg_next_event(app: *mut c_void, sel: *mut c_void, mask: u64, until: *mut c_void, mode: *mut c_void, dequeue: i8) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, *mut c_void, *mut c_void, i8) -> *mut c_void =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(app, sel, mask, until, mode, dequeue) }
}

pub fn open(fb_w: u32, fb_h: u32) -> Result<NativeWindow, String> {
    if unsafe { libc::pthread_main_np() } == 0 {
        return Err("gfxstream window must be created on the main thread".into());
    }
    unsafe {
        let app = msg0(cls("NSApplication"), sel("sharedApplication"));
        if app.is_null() {
            return Err("NSApplication sharedApplication failed".into());
        }
        // NSApplicationActivationPolicyRegular = 0, so the process can come forward.
        msg_i64(app, sel("setActivationPolicy:"), 0);
        APP.store(app, Ordering::Release);

        let screen = msg0(cls("NSScreen"), sel("mainScreen"));
        let vis = if screen.is_null() {
            NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: fb_w as f64, height: fb_h as f64 } }
        } else {
            msg_rect(screen, sel("visibleFrame"))
        };
        let max_w = (vis.size.width - 48.0).max(320.0);
        let max_h = (vis.size.height - 48.0).max(320.0);
        let fit = (max_w / fb_w as f64).min(max_h / fb_h as f64).min(1.0);
        let win_w = (fb_w as f64 * fit).floor().max(1.0);
        let win_h = (fb_h as f64 * fit).floor().max(1.0);
        let mut dpr = if screen.is_null() { 1.0 } else { msg_f64_ret(screen, sel("backingScaleFactor")) };
        if dpr < 1.0 {
            dpr = 1.0;
        }
        let rect = NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: win_w, height: win_h } };
        // titled | closable | miniaturizable | resizable, buffered, don't defer.
        let window = msg_init_window(msg0(cls("NSWindow"), sel("alloc")), sel("initWithContentRect:styleMask:backing:defer:"), rect, 15, 2, 0);
        if window.is_null() {
            return Err("NSWindow init failed".into());
        }
        let title = msg_cstr(cls("NSString"), sel("stringWithUTF8String:"), "droidrt");
        msg_id(window, sel("setTitle:"), title);
        msg_void(window, sel("center"));
        msg_id(window, sel("makeKeyAndOrderFront:"), std::ptr::null_mut());
        msg_bool(app, sel("activateIgnoringOtherApps:"), 1);
        msg_void(app, sel("finishLaunching"));
        // createSubWindow messages this pointer with frame / contentRectForFrameRect:
        // / contentView / makeKeyAndOrderFront:, which are NSWindow methods, then
        // inserts its own EmuGLView into the content view.
        if msg0(window, sel("contentView")).is_null() {
            return Err("NSWindow contentView is null".into());
        }
        let number = msg_i64_ret(window, sel("windowNumber"));
        WINDOW.store(window, Ordering::Release);
        if number > 0 {
            WINDOW_ID.store(number as u64, Ordering::Release);
        }
        let px_w = (win_w * dpr).round().max(1.0);
        let px_h = (win_h * dpr).round().max(1.0);
        eprintln!("droidrt: window {win_w:.0}x{win_h:.0} points ({px_w:.0}x{px_h:.0} px, dpr {dpr}) for {fb_w}x{fb_h} (id {number})");
        Ok(NativeWindow {
            handle: window,
            width: win_w as i32,
            height: win_h as i32,
            px_width: px_w as i32,
            px_height: px_h as i32,
        })
    }
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> *mut c_void;
    fn CGColorSpaceRelease(cs: *mut c_void);
    fn CGDataProviderCreateWithCFData(data: *mut c_void) -> *mut c_void;
    fn CGDataProviderRelease(p: *mut c_void);
    fn CGImageCreate(w: usize, h: usize, bpc: usize, bpp: usize, bpr: usize, cs: *mut c_void, info: u32, provider: *mut c_void, decode: *const f64, interpolate: bool, intent: i32) -> *mut c_void;
    fn CGImageRelease(img: *mut c_void);
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(alloc: *const c_void, bytes: *const u8, len: isize) -> *mut c_void;
    fn CFRelease(obj: *const c_void);
}

struct Frame {
    w: u32,
    h: u32,
    stride: u32,
    fourcc: u32,
    data: Vec<u8>,
}

/// The newest frame from the guest, shown by the UI thread when it pumps.
static FRAME: Mutex<Option<Frame>> = Mutex::new(None);
static FRAME_NEW: AtomicBool = AtomicBool::new(false);

/// Called from any thread with a scanout's pixels.
pub fn present(w: u32, h: u32, stride: u32, fourcc: u32, pixels: &[u8]) {
    // Debugging: DROIDRT_SAVE_FRAMES=<dir> keeps every 8th frame shown (60 at
    // most) as raw pixels, named by time since the first.
    if let Ok(dir) = std::env::var("DROIDRT_SAVE_FRAMES") {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let t = T0.get_or_init(Instant::now).elapsed().as_millis();
        if n.is_multiple_of(8) && n < 480 {
            let _ = std::fs::write(format!("{dir}/f{n:04}_{t:06}ms_{w}x{h}_{stride}_{fourcc:x}.raw"), pixels);
        }
    }
    let mut slot = FRAME.lock().unwrap_or_else(|p| p.into_inner());
    match slot.as_mut() {
        Some(f) if f.data.len() == pixels.len() => {
            f.data.copy_from_slice(pixels);
            (f.w, f.h, f.stride, f.fourcc) = (w, h, stride, fourcc);
        }
        _ => *slot = Some(Frame { w, h, stride, fourcc, data: pixels.to_vec() }),
    }
    FRAME_NEW.store(true, Ordering::Release);
}

/// Puts the newest frame into the window's layer (UI thread only).
fn show_frame() {
    if !FRAME_NEW.swap(false, Ordering::AcqRel) {
        return;
    }
    let window = WINDOW.load(Ordering::Acquire);
    let slot = FRAME.lock().unwrap_or_else(|p| p.into_inner());
    let (Some(f), false) = (slot.as_ref(), window.is_null()) else { return };
    // DRM fourccs name the 32-bit word: ARGB8888/XRGB8888 are B,G,R,A bytes
    // in memory; ABGR8888/XBGR8888 (and anything else) are R,G,B,A.
    const BGRA: [u32; 2] = [0x3432_5241, 0x3432_5258];
    let info = if BGRA.contains(&f.fourcc) { (2 << 12) | 6 } else { 5 }; // 32Little|NoneSkipFirst, or NoneSkipLast
    unsafe {
        let data = CFDataCreate(std::ptr::null(), f.data.as_ptr(), f.data.len() as isize);
        let provider = CGDataProviderCreateWithCFData(data);
        let cs = CGColorSpaceCreateDeviceRGB();
        let img = CGImageCreate(f.w as usize, f.h as usize, 8, 32, f.stride as usize, cs, info, provider, std::ptr::null(), false, 0);
        drop(slot);
        let view = msg0(window, sel("contentView"));
        msg_bool(view, sel("setWantsLayer:"), 1);
        let layer = msg0(view, sel("layer"));
        if !layer.is_null() && !img.is_null() {
            msg_id(layer, sel("setContents:"), img);
            msg_id(layer, sel("setContentsGravity:"), msg_cstr(cls("NSString"), sel("stringWithUTF8String:"), "resizeAspect"));
            msg_void(cls("CATransaction"), sel("flush"));
        }
        if !img.is_null() {
            CGImageRelease(img);
        }
        CGColorSpaceRelease(cs);
        CGDataProviderRelease(provider);
        CFRelease(data);
    }
}

unsafe fn msg_cstr(obj: *mut c_void, sel: *mut c_void, s: &str) -> *mut c_void {
    let c = CString::new(s).unwrap();
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const i8) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, c.as_ptr()) }
}

pub fn window_id() -> Option<u64> {
    let id = WINDOW_ID.load(Ordering::Acquire);
    if id == 0 { None } else { Some(id) }
}

struct UiJob {
    f: unsafe extern "C" fn(*mut c_void),
    data: *mut c_void,
    done: std::sync::Arc<(Mutex<bool>, Condvar)>,
}

// The pointer is a gfxstream cookie handed back to the callback on the UI thread.
unsafe impl Send for UiJob {}

static UI_QUEUE: Mutex<Vec<UiJob>> = Mutex::new(Vec::new());

/// gfxstream asks the host to run a present on the thread that owns the window.
/// The library's default of this is a no-op, which drops the frame.
pub fn run_on_ui_thread(f: unsafe extern "C" fn(*mut c_void), data: *mut c_void, wait: bool) {
    if unsafe { libc::pthread_main_np() } != 0 {
        unsafe { f(data) };
        return;
    }
    let done = std::sync::Arc::new((Mutex::new(false), Condvar::new()));
    UI_QUEUE.lock().unwrap_or_else(|p| p.into_inner()).push(UiJob { f, data, done: done.clone() });
    if wait {
        let (lock, cv) = &*done;
        let mut flag = lock.lock().unwrap_or_else(|p| p.into_inner());
        while !*flag {
            flag = cv.wait(flag).unwrap_or_else(|p| p.into_inner());
        }
    }
}

fn drain_ui() {
    let jobs = std::mem::take(&mut *UI_QUEUE.lock().unwrap_or_else(|p| p.into_inner()));
    for job in jobs {
        unsafe { (job.f)(job.data) };
        let (lock, cv) = &*job.done;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
    }
}

fn pump_once(wait_s: f64) {
    drain_ui();
    show_frame();
    let app = APP.load(Ordering::Acquire);
    if app.is_null() {
        std::thread::sleep(Duration::from_secs_f64(wait_s));
        return;
    }
    unsafe {
        let until = msg_f64_id(cls("NSDate"), sel("dateWithTimeIntervalSinceNow:"), wait_s);
        let mode = NSDefaultRunLoopMode;
        let event = msg_next_event(app, sel("nextEventMatchingMask:untilDate:inMode:dequeue:"), u64::MAX, until, mode, 1);
        if !event.is_null() {
            msg_id(app, sel("sendEvent:"), event);
            msg_void(app, sel("updateWindows"));
        }
    }
    drain_ui();
}

pub fn pump_until(done: &std::sync::atomic::AtomicBool) {
    while !done.load(Ordering::Acquire) {
        pump_once(0.008);
    }
}

pub fn pump_for(secs: f64) {
    let start = Instant::now();
    let total = Duration::from_secs_f64(secs);
    while start.elapsed() < total {
        let left = total.saturating_sub(start.elapsed()).as_secs_f64().min(0.05);
        pump_once(left.max(0.001));
    }
}
