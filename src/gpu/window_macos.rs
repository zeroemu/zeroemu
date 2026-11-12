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

unsafe fn msg_point(obj: *mut c_void, sel: *mut c_void) -> NSPoint {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> NSPoint = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
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

/// ZEROEMU_BACKGROUND=1: open the window without taking the keyboard or coming
/// forward, for tests run while someone uses the Mac.
pub fn background() -> bool {
    std::env::var_os("ZEROEMU_BACKGROUND").is_some_and(|v| !v.is_empty() && v != "0")
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
        let title = msg_cstr(cls("NSString"), sel("stringWithUTF8String:"), "zeroemu");
        msg_id(window, sel("setTitle:"), title);
        msg_bool(window, sel("setReleasedWhenClosed:"), 0); // this stays pointed at it
        msg_void(window, sel("center"));
        if background() {
            // Behind everything, and the app never asks to be active: the user's
            // keyboard and mouse stay where they were.
            msg_id(window, sel("orderBack:"), std::ptr::null_mut());
        } else {
            msg_id(window, sel("makeKeyAndOrderFront:"), std::ptr::null_mut());
            msg_bool(app, sel("activateIgnoringOtherApps:"), 1);
        }
        msg_void(app, sel("finishLaunching"));
        // A device keeps running when its window is covered or minimized, as a phone's
        // apps do with its screen off: no App Nap, which throttled a covered zeroemu's
        // threads and timers until frames took ten times as long. The Mac may still sleep.
        const USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP: u64 = 0x00ef_ffff;
        let info = msg0(cls("NSProcessInfo"), sel("processInfo"));
        let reason = msg_cstr(cls("NSString"), sel("stringWithUTF8String:"), "zeroemu runs an Android device");
        let begin: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let activity = begin(info, sel("beginActivityWithOptions:reason:"), USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP, reason);
        if !activity.is_null() {
            msg0(activity, sel("retain")); // held for the process's life
        }
        // createSubWindow messages this pointer with frame / contentRectForFrameRect:
        // / contentView / makeKeyAndOrderFront:, which are NSWindow methods, then
        // inserts its own EmuGLView into the content view.
        if msg0(window, sel("contentView")).is_null() {
            return Err("NSWindow contentView is null".into());
        }
        let number = msg_i64_ret(window, sel("windowNumber"));
        SHOWN_SIZE.store((fb_w as u64) << 32 | fb_h as u64, Ordering::Relaxed);
        WINDOW.store(window, Ordering::Release);
        if number > 0 {
            WINDOW_ID.store(number as u64, Ordering::Release);
        }
        let px_w = (win_w * dpr).round().max(1.0);
        let px_h = (win_h * dpr).round().max(1.0);
        eprintln!("zeroemu: window {win_w:.0}x{win_h:.0} points ({px_w:.0}x{px_h:.0} px, dpr {dpr}) for {fb_w}x{fb_h} (id {number})");
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
    static kCGColorSpaceSRGB: *const c_void;
    fn CGColorSpaceCreateWithName(name: *const c_void) -> *mut c_void;
    fn CGColorSpaceRelease(cs: *mut c_void);
    fn CGDataProviderCreateWithCFData(data: *mut c_void) -> *mut c_void;
    fn CGDataProviderRelease(p: *mut c_void);
    fn CGImageCreate(w: usize, h: usize, bpc: usize, bpp: usize, bpr: usize, cs: *mut c_void, info: u32, provider: *mut c_void, decode: *const f64, interpolate: bool, intent: i32) -> *mut c_void;
    fn CGImageRelease(img: *mut c_void);
    fn CGColorCreateGenericGray(gray: f64, alpha: f64) -> *mut c_void;
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
    // Debugging: ZEROEMU_SAVE_FRAMES=<dir> keeps every 8th frame shown (60 at
    // most) as raw pixels, named by time since the first.
    if let Ok(dir) = std::env::var("ZEROEMU_SAVE_FRAMES") {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let t = T0.get_or_init(Instant::now).elapsed().as_millis();
        if n.is_multiple_of(8) && n < 480 {
            let _ = std::fs::write(format!("{dir}/f{n:04}_{t:06}ms_{w}x{h}_{stride}_{fourcc:x}.raw"), pixels);
        }
    }
    SHOWN_SIZE.store((w as u64) << 32 | h as u64, Ordering::Relaxed);
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

/// The newest frame as top-down B,G,R,A rows, and its size.
pub fn shown_frame() -> Option<(u32, u32, Vec<u8>)> {
    let slot = FRAME.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(f) = slot.as_ref() {
        return Some((f.w, f.h, bgra(f.w, f.h, f.stride, f.fourcc, &f.data)));
    }
    drop(slot);
    let (w, h, fourcc, data) = RENDERER.get()?.1()?;
    Some((w, h, bgra(w, h, w * 4, fourcc, &data)))
}

fn bgra(w: u32, h: u32, stride: u32, fourcc: u32, data: &[u8]) -> Vec<u8> {
    const BGRA: [u32; 2] = [0x3432_5241, 0x3432_5258];
    let mut out = Vec::with_capacity(w as usize * h as usize * 4);
    for row in data.chunks_exact(stride as usize).take(h as usize) {
        for p in row.chunks_exact(4).take(w as usize) {
            out.extend_from_slice(&if BGRA.contains(&fourcc) { [p[0], p[1], p[2], 255] } else { [p[2], p[1], p[0], 255] });
        }
    }
    out
}

/// Where the renderer draws in the window: a rectangle of the content view in
/// points, from its top left, at `dpr` pixels per point.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Placement {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub dpr: f32,
}

/// Puts the renderer's view at a placement (UI thread).
pub type Attach = Box<dyn Fn(*mut c_void, Placement) + Send + Sync>;
/// The frame on show, read back: width, height, DRM fourcc, rows of width * 4 bytes.
pub type FrameSource = Box<dyn Fn() -> Option<(u32, u32, u32, Vec<u8>)> + Send + Sync>;

/// The renderer drawing into the window itself, when it does.
static RENDERER: std::sync::OnceLock<(Attach, FrameSource)> = std::sync::OnceLock::new();
/// Where it was last put.
static PLACED: Mutex<Option<Placement>> = Mutex::new(None);
/// The renderer is drawing frames into the window, not leaving them to be read back.
static DRAWING: AtomicBool = AtomicBool::new(false);

/// Whether the renderer draws into the window (it may fail to, and frames are then
/// read back and shown at the event loop's next turn).
pub fn set_drawing(on: bool) {
    DRAWING.store(on, Ordering::Relaxed);
}

/// The renderer draws frames into the window from now on, in a view `attach` puts
/// where the frame belongs and puts again whenever that changes (UI thread).
pub fn attach_renderer(attach: Attach, source: FrameSource) {
    if RENDERER.set((attach, source)).is_ok() {
        unsafe {
            // Black around the frame when the window's shape isn't the display's.
            let window = WINDOW.load(Ordering::Acquire);
            if !window.is_null() {
                let view = msg0(window, sel("contentView"));
                msg_bool(view, sel("setWantsLayer:"), 1);
                let layer = msg0(view, sel("layer"));
                let black = CGColorCreateGenericGray(0.0, 1.0);
                if !layer.is_null() && !black.is_null() {
                    msg_id(layer, sel("setBackgroundColor:"), black);
                }
                if !black.is_null() {
                    CFRelease(black);
                }
            }
        }
        relayout();
    }
}

/// Resizes the window's content area, from any thread.
pub fn resize(w: f64, h: f64) {
    extern "C" fn on_main(context: *mut c_void) {
        let size = unsafe { Box::from_raw(context as *mut NSSize) };
        let window = WINDOW.load(Ordering::Acquire);
        if !window.is_null() {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void, NSSize) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
            unsafe { f(window, sel("setContentSize:"), *size) };
            relayout();
        }
    }
    let size = Box::new(NSSize { width: w.max(100.0), height: h.max(100.0) });
    unsafe { dispatch_async_f(&raw const _dispatch_main_q, Box::into_raw(size) as *mut c_void, on_main) };
}

/// The frame's size, for fitting it to the window and placing the pointer on it.
pub fn set_shown_size(w: u32, h: u32) {
    SHOWN_SIZE.store((w as u64) << 32 | h as u64, Ordering::Relaxed);
}

/// Moves the renderer's view to where the frame now belongs, if that changed:
/// the window was resized or went to a screen of another density (UI thread).
fn relayout() {
    let Some((attach, _)) = RENDERER.get() else { return };
    let window = WINDOW.load(Ordering::Acquire);
    if window.is_null() {
        return;
    }
    let (bounds, dpr) = unsafe {
        let view = msg0(window, sel("contentView"));
        if view.is_null() {
            return;
        }
        (msg_rect(view, sel("bounds")), msg_f64_ret(window, sel("backingScaleFactor")))
    };
    let r = shown_rect(bounds);
    let (w, h) = (r.w.floor().max(1.0), r.h.floor().max(1.0));
    let p = Placement {
        x: ((bounds.size.width - w) / 2.0).round() as i32,
        y: ((bounds.size.height - h) / 2.0).round() as i32,
        w: w as i32,
        h: h as i32,
        dpr: dpr.max(1.0) as f32,
    };
    {
        let mut placed = PLACED.lock().unwrap_or_else(|e| e.into_inner());
        if *placed == Some(p) {
            return;
        }
        *placed = Some(p);
    }
    attach(window, p);
    // Creating the renderer's view (the first time, or after it failed) orders the
    // window front and makes it key.
    if background() {
        unsafe { msg_id(window, sel("orderBack:"), std::ptr::null_mut()) };
    }
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
        // Android composes in sRGB; device RGB would skip the display's
        // color matching and shift every color.
        let cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
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

#[link(name = "System")]
unsafe extern "C" {
    static _dispatch_main_q: c_void;
    fn dispatch_async_f(queue: *const c_void, context: *mut c_void, work: extern "C" fn(*mut c_void));
}

/// Runs a job from the main dispatch queue, which the UI thread's run loop serves
/// while it waits for events and while AppKit tracks a resize.
extern "C" fn run_ui_job(context: *mut c_void) {
    let job = unsafe { Box::from_raw(context as *mut UiJob) };
    // While AppKit tracks a resize, the pump doesn't run but these do: the frame
    // follows the window's edge as it moves.
    relayout();
    let span = crate::kernel::trace::span("ui: renderer job");
    unsafe { (job.f)(job.data) };
    drop(span);
    let (lock, cv) = &*job.done;
    *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
    cv.notify_all();
}

/// gfxstream asks the host to run a present on the thread that owns the window.
/// The library's default of this is a no-op, which drops the frame. Jobs go to the
/// main dispatch queue, so they run as soon as the UI thread is free, not at its
/// next turn of pumping events.
pub fn run_on_ui_thread(f: unsafe extern "C" fn(*mut c_void), data: *mut c_void, wait: bool) {
    if unsafe { libc::pthread_main_np() } != 0 {
        unsafe { f(data) };
        return;
    }
    let done = std::sync::Arc::new((Mutex::new(false), Condvar::new()));
    let job = Box::new(UiJob { f, data, done: done.clone() });
    unsafe { dispatch_async_f(&raw const _dispatch_main_q, Box::into_raw(job) as *mut c_void, run_ui_job) };
    if wait {
        let (lock, cv) = &*done;
        let mut flag = lock.lock().unwrap_or_else(|p| p.into_inner());
        while !*flag {
            flag = cv.wait(flag).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// A touch is in progress: it began in the content area, and drags and the release
/// belong to it wherever they happen.
static TOUCHING: AtomicBool = AtomicBool::new(false);
/// NSEventModifierFlags seen last, to tell a modifier's press from its release.
/// Whether the window was on screen, when last looked at.
static WAS_VISIBLE: AtomicBool = AtomicBool::new(false);
static ON_CLOSED: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

pub fn on_closed(f: Box<dyn Fn() + Send + Sync>) {
    let _ = ON_CLOSED.set(f);
}

/// Whether the window had the keyboard, when last looked at.
static WAS_KEY: AtomicBool = AtomicBool::new(false);
/// The frame's size, for mapping the pointer onto the frame.
static SHOWN_SIZE: AtomicU64 = AtomicU64::new(0);

/// Android's keys for a Mac's virtual key codes (kVK_*). Escape is BACK and F1 HOME,
/// as there is no other way to reach them; F2 is the recent apps list.
fn linux_key(mac: u16) -> Option<u16> {
    Some(match mac {
        0x00 => 30,  // A
        0x01 => 31,  // S
        0x02 => 32,  // D
        0x03 => 33,  // F
        0x04 => 35,  // H
        0x05 => 34,  // G
        0x06 => 44,  // Z
        0x07 => 45,  // X
        0x08 => 46,  // C
        0x09 => 47,  // V
        0x0b => 48,  // B
        0x0c => 16,  // Q
        0x0d => 17,  // W
        0x0e => 18,  // E
        0x0f => 19,  // R
        0x10 => 21,  // Y
        0x11 => 20,  // T
        0x12 => 2,   // 1
        0x13 => 3,   // 2
        0x14 => 4,   // 3
        0x15 => 5,   // 4
        0x16 => 7,   // 6
        0x17 => 6,   // 5
        0x18 => 13,  // =
        0x19 => 10,  // 9
        0x1a => 8,   // 7
        0x1b => 12,  // -
        0x1c => 9,   // 8
        0x1d => 11,  // 0
        0x1e => 27,  // ]
        0x1f => 24,  // O
        0x20 => 22,  // U
        0x21 => 26,  // [
        0x22 => 23,  // I
        0x23 => 25,  // P
        0x24 => 28,  // Return
        0x25 => 38,  // L
        0x26 => 36,  // J
        0x27 => 40,  // '
        0x28 => 37,  // K
        0x29 => 39,  // ;
        0x2a => 43,  // backslash
        0x2b => 51,  // ,
        0x2c => 53,  // /
        0x2d => 49,  // N
        0x2e => 50,  // M
        0x2f => 52,  // .
        0x30 => 15,  // Tab
        0x31 => 57,  // Space
        0x32 => 399, // `, which qwerty2.kl has here
        0x33 => 14,  // Delete (backspace)
        0x35 => 158, // Escape: BACK
        0x37 => 125, // Command: META
        0x38 => 42,  // Shift
        0x39 => 58,  // Caps Lock
        0x3a => 56,  // Option: ALT
        0x3b => 29,  // Control
        0x3c => 54,  // right Shift
        0x3d => 100, // right Option
        0x3e => 97,  // right Control
        0x75 => 111, // Forward Delete
        0x73 => 452, // Home and End, as qwerty2.kl has them: for its layout, 102 is
        0x77 => 453, // the home screen and 107 hangs up, which puts Android to sleep.
        0x74 => 104, // Page Up
        0x79 => 109, // Page Down
        0x7a => 102, // F1: HOME, as qwerty2.kl has it
        0x78 => 580, // F2: APP_SWITCH
        0x7b => 105, // Left
        0x7c => 106, // Right
        0x7d => 108, // Down
        0x7e => 103, // Up
        _ => return None,
    })
}

/// Sends a mouse or key event in our window to the guest. True if it was consumed:
/// keys sent on would beep, having no responder.
unsafe fn forward_input(event: *mut c_void) -> bool {
    use crate::kernel::evdev::{self, Touch};
    const LEFT_DOWN: i64 = 1;
    const LEFT_UP: i64 = 2;
    const LEFT_DRAGGED: i64 = 6;
    const KEY_DOWN: i64 = 10;
    const KEY_UP: i64 = 11;
    const FLAGS_CHANGED: i64 = 12;
    const SCROLL_WHEEL: i64 = 22;
    /// Each modifier's device-dependent bit: says which of a left and right pair moved.
    const fn modifier_bit(key: i64) -> Option<u64> {
        Some(match key {
            0x37 => 0x8,    // Command
            0x38 => 0x2,    // Shift
            0x3a => 0x20,   // Option
            0x3b => 0x1,    // Control
            0x3c => 0x4,    // right Shift
            0x3d => 0x40,   // right Option
            0x3e => 0x2000, // right Control
            _ => return None,
        })
    }
    const CAPS_LOCK: i64 = 0x39;
    let window = WINDOW.load(Ordering::Acquire);
    unsafe {
        if window.is_null() || msg0(event, sel("window")) != window {
            return false;
        }
        match msg_i64_ret(event, sel("type")) {
            ty @ (LEFT_DOWN | LEFT_UP | LEFT_DRAGGED) => {
                let at = msg_point(event, sel("locationInWindow"));
                let shown = shown_rect(msg_rect(msg0(window, sel("contentView")), sel("bounds")));
                let (x, y) = shown.place(at);
                let inside = (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y);
                match ty {
                    LEFT_DOWN if inside => {
                        evdev::scroll_cancel(); // the slot's a finger's at a time
                        TOUCHING.store(true, Ordering::Relaxed);
                        evdev::touch(Touch::Down, x, y);
                    }
                    LEFT_DRAGGED if TOUCHING.load(Ordering::Relaxed) => evdev::touch(Touch::Move, x, y),
                    LEFT_UP if TOUCHING.swap(false, Ordering::Relaxed) => evdev::touch(Touch::Up, x, y),
                    _ => {}
                }
                false // the window still handles its title bar and resizing
            }
            SCROLL_WHEEL => {
                // NSEventPhase. A mouse wheel has none; a trackpad's fingers do, then
                // momentum, which Android works out for itself when they lift.
                const BEGAN: i64 = 1;
                const CHANGED: i64 = 4;
                const ENDED: i64 = 8;
                const CANCELLED: i64 = 16;
                /// How far one line of a mouse wheel goes, across the display.
                const LINE: f64 = 0.03;
                let (phase, momentum) = (msg_i64_ret(event, sel("phase")), msg_i64_ret(event, sel("momentumPhase")));
                let phase = match phase {
                    0 if momentum == 0 => evdev::Scroll::Wheel,
                    BEGAN => evdev::Scroll::Begin,
                    CHANGED => evdev::Scroll::Change,
                    ENDED | CANCELLED => {
                        // Wherever the pointer has got to by now.
                        evdev::scroll(evdev::Scroll::End, 0.0, 0.0, 0.0, 0.0);
                        return true;
                    }
                    _ => return true,
                };
                let at = msg_point(event, sel("locationInWindow"));
                let shown = shown_rect(msg_rect(msg0(window, sel("contentView")), sel("bounds")));
                let (x, y) = shown.place(at);
                let (dx, dy) = (msg_f64_ret(event, sel("scrollingDeltaX")), msg_f64_ret(event, sel("scrollingDeltaY")));
                let (dx, dy) = if msg_i64_ret(event, sel("hasPreciseScrollingDeltas")) & 1 != 0 {
                    (dx / shown.w, dy / shown.h)
                } else {
                    (dx * LINE, dy * LINE)
                };
                if !TOUCHING.load(Ordering::Relaxed) && (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y) {
                    evdev::scroll(phase, x, y, dx, dy);
                }
                true
            }
            ty @ (KEY_DOWN | KEY_UP) => {
                // Android repeats held keys itself.
                let repeat = ty == KEY_DOWN && msg_i64_ret(event, sel("isARepeat")) & 1 != 0;
                if !repeat && let Some(code) = linux_key(msg_i64_ret(event, sel("keyCode")) as u16) {
                    evdev::key(code, ty == KEY_DOWN);
                }
                true
            }
            FLAGS_CHANGED => {
                let flags = msg_i64_ret(event, sel("modifierFlags")) as u64;
                let key = msg_i64_ret(event, sel("keyCode"));
                if key == CAPS_LOCK {
                    // The Mac reports the lock, not the key, and Android toggles on
                    // release: a press and release for each change keeps them together.
                    evdev::key(58, true);
                    evdev::key(58, false);
                } else if let (Some(bit), Some(code)) = (modifier_bit(key), linux_key(key as u16)) {
                    evdev::key(code, flags & bit != 0);
                }
                true
            }
            _ => false,
        }
    }
}

/// Where the frame is in the window's content view: it keeps its shape (resizeAspect),
/// whatever the window's.
struct ShownRect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl ShownRect {
    /// A point in the view as a fraction of the frame, from its top left.
    fn place(&self, at: NSPoint) -> (f64, f64) {
        ((at.x - self.x) / self.w, 1.0 - (at.y - self.y) / self.h)
    }
}

fn shown_rect(bounds: NSRect) -> ShownRect {
    let (bw, bh) = (bounds.size.width, bounds.size.height);
    let size = SHOWN_SIZE.load(Ordering::Relaxed);
    let (fw, fh) = ((size >> 32) as f64, (size & 0xffff_ffff) as f64);
    if fw == 0.0 || fh == 0.0 {
        return ShownRect { x: 0.0, y: 0.0, w: bw, h: bh };
    }
    let scale = (bw / fw).min(bh / fh);
    let (w, h) = (fw * scale, fh * scale);
    ShownRect { x: (bw - w) / 2.0, y: (bh - h) / 2.0, w, h }
}

/// What the window can no longer be told about: releases that went elsewhere, when
/// another app took the keyboard or AppKit took the mouse (its resize loop, say).
fn check_lost_input() {
    use crate::kernel::evdev::{self, Touch};
    let window = WINDOW.load(Ordering::Acquire);
    if window.is_null() {
        return;
    }
    unsafe {
        // Off screen, and not because it was minimized or the app hidden: closed.
        let visible = msg_i64_ret(window, sel("isVisible")) & 1 != 0;
        if WAS_VISIBLE.swap(visible, Ordering::Relaxed)
            && !visible
            && msg_i64_ret(window, sel("isMiniaturized")) & 1 == 0
            && msg_i64_ret(APP.load(Ordering::Acquire), sel("isHidden")) & 1 == 0
            && let Some(f) = ON_CLOSED.get()
        {
            f();
        }
        let is_key = msg_i64_ret(window, sel("isKeyWindow")) & 1 != 0;
        if WAS_KEY.swap(is_key, Ordering::Relaxed) && !is_key {
            evdev::release_keys();
            evdev::scroll_cancel();
        }
        if TOUCHING.load(Ordering::Relaxed) && msg_i64_ret(cls("NSEvent"), sel("pressedMouseButtons")) & 1 == 0 {
            TOUCHING.store(false, Ordering::Relaxed);
            evdev::touch(Touch::Up, 0.0, 0.0);
        }
    }
}

/// Whether any of the window is on screen, as AppKit last said (UI thread writes).
static ON_SCREEN: AtomicBool = AtomicBool::new(true);

/// Whether any of the window can be seen: not covered, minimized or on another Space.
pub fn on_screen() -> bool {
    ON_SCREEN.load(Ordering::Relaxed)
}

fn pump_once(wait_s: f64) {
    show_frame();
    relayout();
    let window = WINDOW.load(Ordering::Acquire);
    if !window.is_null() {
        const NS_WINDOW_OCCLUSION_STATE_VISIBLE: i64 = 1 << 1;
        let state = unsafe { msg_i64_ret(window, sel("occlusionState")) };
        ON_SCREEN.store(state & NS_WINDOW_OCCLUSION_STATE_VISIBLE != 0, Ordering::Relaxed);
    }
    crate::kernel::evdev::scroll_idle(Duration::from_millis(100));
    check_lost_input();
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
            if !forward_input(event) {
                msg_id(app, sel("sendEvent:"), event);
            }
            msg_void(app, sel("updateWindows"));
        }
    }
}

pub fn pump_until(done: &std::sync::atomic::AtomicBool) {
    while !done.load(Ordering::Acquire) {
        // Events end the wait at once. Frames read back are shown at the next turn, so
        // that has to come soon; when the renderer draws them, only the window's own
        // checks (a resize, a lost mouse release, the end of a scroll) need a turn.
        pump_once(if DRAWING.load(Ordering::Relaxed) { 0.05 } else { 0.008 });
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
