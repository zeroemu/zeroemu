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

pub mod list;

static APP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// The window's title: the device's name, for the Window menu and Mission Control.
static TITLE: Mutex<Option<String>> = Mutex::new(None);

pub fn set_title(name: &str) {
    *TITLE.lock().unwrap() = Some(name.to_string());
}

/// finishLaunching, once: the list of devices may have called it before the window.
unsafe fn finish_launching(app: *mut c_void) {
    static DONE: AtomicBool = AtomicBool::new(false);
    if !DONE.swap(true, Ordering::AcqRel) {
        unsafe { msg_void(app, sel("finishLaunching")) };
    }
}
static WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static WINDOW_ID: AtomicU64 = AtomicU64::new(0);

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const i8) -> *mut c_void;
    fn sel_registerName(name: *const i8) -> *mut c_void;
    fn objc_msgSend();
    fn objc_allocateClassPair(superclass: *mut c_void, name: *const i8, extra: usize) -> *mut c_void;
    fn class_addMethod(class: *mut c_void, name: *mut c_void, imp: *const c_void, types: *const i8) -> bool;
    fn objc_registerClassPair(class: *mut c_void);
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

/// Runs `f` in an autorelease pool. The main thread has none of its own, as nothing
/// here runs NSApplication's run loop: objects AppKit hands back autoreleased, like
/// the NSDate each turn of `pump_once` makes, would otherwise never be freed.
fn with_pool<R>(f: impl FnOnce() -> R) -> R {
    let pool = unsafe { objc_autoreleasePoolPush() };
    let r = f();
    unsafe { objc_autoreleasePoolPop(pool) };
    r
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    static NSDefaultRunLoopMode: *mut c_void;
    static NSToolbarFlexibleSpaceItemIdentifier: *mut c_void;
    fn NSBeep();
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

unsafe fn msg_id_ret(obj: *mut c_void, sel: *mut c_void, a: *mut c_void) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_id_id_ret(obj: *mut c_void, sel: *mut c_void, a: *mut c_void, b: *mut c_void) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a, b) }
}

unsafe fn msg_id_bool_ret(obj: *mut c_void, sel: *mut c_void, a: *mut c_void) -> bool {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_i64_id_ret(obj: *mut c_void, sel: *mut c_void, a: i64) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, i64) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_id_i64_ret(obj: *mut c_void, sel: *mut c_void, a: *mut c_void) -> i64 {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i64 = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_rect_rect(obj: *mut c_void, sel: *mut c_void, r: NSRect) -> NSRect {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, NSRect) -> NSRect = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, r) }
}

unsafe fn msg_size(obj: *mut c_void, sel: *mut c_void, s: NSSize) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, NSSize) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, s) }
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

/// How big the first window's content is, in points, for a device screen of `display`
/// on a Mac screen with `room` points to spare (width, height) at `dpr` pixels a
/// point: the device's shape, as large as fits, but with no more than one of the Mac
/// screen's pixels to each of the device's, as more only blurs the picture. Except
/// that one of Android's dp is never shown smaller than a point, the unit Mac apps
/// are drawn in, as Android's text gets hard to read below that: for a device of low
/// density on a Retina screen, that wins over sharpness, but never over fitting.
fn first_size(display: super::Display, room: (f64, f64), dpr: f64) -> (f64, f64) {
    let (w, h) = (display.width as f64, display.height as f64);
    let fits = (room.0 / w).min(room.1 / h);
    let sharp = 1.0 / dpr.max(1.0);
    // Points to a pixel when a dp (dpi / 160 pixels) is a point.
    let readable = 160.0 / display.dpi.max(1) as f64;
    let scale = fits.min(sharp.max(readable));
    ((w * scale).floor().max(1.0), (h * scale).floor().max(1.0))
}

/// Opens the window for a device screen of `display`, fitted to the Mac's.
pub fn open(display: super::Display) -> Result<(), String> {
    let (fb_w, fb_h) = (display.width, display.height);
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
        set_app_icon(app);
        APP.store(app, Ordering::Release);

        let screen = msg0(cls("NSScreen"), sel("mainScreen"));
        let vis = if screen.is_null() {
            NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: fb_w as f64, height: fb_h as f64 } }
        } else {
            msg_rect(screen, sel("visibleFrame"))
        };
        let mut dpr = if screen.is_null() { 1.0 } else { msg_f64_ret(screen, sel("backingScaleFactor")) };
        if dpr < 1.0 {
            dpr = 1.0;
        }
        let first = NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: fb_w as f64 / 4.0, height: fb_h as f64 / 4.0 } };
        // titled | closable | miniaturizable | resizable, buffered, don't defer.
        let window = msg_init_window(msg0(cls("NSWindow"), sel("alloc")), sel("initWithContentRect:styleMask:backing:defer:"), first, 15, 2, 0);
        if window.is_null() {
            return Err("NSWindow init failed".into());
        }
        let title = TITLE.lock().unwrap().clone().unwrap_or_else(|| "zeroemu".into());
        msg_id(window, sel("setTitle:"), ns_str(&title));
        msg_bool(window, sel("setReleasedWhenClosed:"), 0); // this stays pointed at it
        // No tab bar or its menu items: the window is the device.
        msg_bool(cls("NSWindow"), sel("setAllowsAutomaticWindowTabbing:"), 0);
        add_toolbar(window);
        // Fitted to the screen with the title bar and toolbar, which take whatever
        // height they take: measured, as adding the toolbar doesn't keep the content's.
        let chrome = msg_rect(window, sel("frame")).size.height - msg_rect(msg0(window, sel("contentView")), sel("bounds")).size.height;
        let room = ((vis.size.width - 48.0).max(320.0), (vis.size.height - chrome - 16.0).max(320.0));
        let (win_w, win_h) = first_size(display, room, dpr);
        msg_size(window, sel("setContentSize:"), NSSize { width: win_w, height: win_h });
        msg_void(window, sel("center"));
        set_up_menus(app);
        if background() {
            // Behind everything, and the app never asks to be active: the user's
            // keyboard and mouse stay where they were.
            msg_id(window, sel("orderBack:"), std::ptr::null_mut());
        } else {
            msg_id(window, sel("makeKeyAndOrderFront:"), std::ptr::null_mut());
            msg_bool(app, sel("activateIgnoringOtherApps:"), 1);
        }
        finish_launching(app);
        // A device keeps running when its window is covered or minimized, as a phone's
        // apps do with its screen off: no App Nap, which throttled a covered zeroemu's
        // threads and timers until frames took about eight times as long. The Mac may
        // still sleep.
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
        if crate::kernel::verbose() {
            eprintln!("zeroemu: window {win_w:.0}x{win_h:.0} points (dpr {dpr}) for a {fb_w}x{fb_h} screen at {} dpi (id {number})", display.dpi);
        }
        Ok(())
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
/// points, from its top left, at `dpr` pixels per point, with the panel turned
/// `turns` quarter turns counterclockwise to fill it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Placement {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub dpr: f32,
    pub turns: u8,
}

impl Placement {
    /// gfxstream's setupSubWindow rotation: degrees clockwise, exactly 0, 90, 180 or
    /// 270. Its drawing picks a vertex table by zRot / 90, and any other value gets
    /// the default table (texture_draw.cpp).
    pub fn z_rotation(&self) -> f32 {
        [0.0, 270.0, 180.0, 90.0][(self.turns % 4) as usize]
    }
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
        turns: super::controls::turns(),
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
    // A turned device shows its panel turned, the pixels moved here.
    let turns = super::controls::turns();
    let turned = (turns != 0).then(|| super::controls::rotate_pixels(f.w, f.h, &bgra(f.w, f.h, f.stride, f.fourcc, &f.data), turns));
    let (w, h, stride, info, bytes) = match &turned {
        Some((w, h, px)) => (*w, *h, w * 4, (2 << 12) | 6, px.as_slice()),
        // 32Little|NoneSkipFirst, or NoneSkipLast
        None => (f.w, f.h, f.stride, if BGRA.contains(&f.fourcc) { (2 << 12) | 6 } else { 5 }, f.data.as_slice()),
    };
    unsafe {
        let data = CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize);
        let provider = CGDataProviderCreateWithCFData(data);
        // Android composes in sRGB; device RGB would skip the display's
        // color matching and shift every color.
        let cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        let img = CGImageCreate(w as usize, h as usize, 8, 32, stride as usize, cs, info, provider, std::ptr::null(), false, 0);
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
    with_pool(|| unsafe { (job.f)(job.data) });
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
    // Quit chosen before the device could be told: it is now.
    if QUIT.load(Ordering::Acquire)
        && let Some(f) = ON_CLOSED.get()
    {
        f();
    }
}

/// Quit was chosen.
static QUIT: AtomicBool = AtomicBool::new(false);

/// Whether the device stopped because Quit was chosen, rather than its window closed.
pub fn quit_chosen() -> bool {
    QUIT.load(Ordering::Acquire)
}

/// Quit stops the device as closing its window does, so that /data is saved, rather
/// than exiting from inside AppKit. The window goes at once; zeroemu exits once the
/// device has stopped and its data is saved.
fn quit() {
    QUIT.store(true, Ordering::Release);
    if let Some(f) = ON_CLOSED.get() {
        f();
    }
    let window = WINDOW.load(Ordering::Acquire);
    if !window.is_null() {
        unsafe { msg_id(window, sel("orderOut:"), std::ptr::null_mut()) };
    }
}

/// Whether the window had the keyboard, when last looked at.
static WAS_KEY: AtomicBool = AtomicBool::new(false);
/// The frame's size, for mapping the pointer onto the frame.
static SHOWN_SIZE: AtomicU64 = AtomicU64::new(0);

/// Android's keys for a Mac's virtual key codes (kVK_*). Escape is BACK, F1 HOME and
/// F2 the recent apps list, as the toolbar and the Device menu have them too.
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
                let (dx, dy) = super::controls::delta_to_panel(shown.turns, dx, dy);
                if !TOUCHING.load(Ordering::Relaxed) && (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y) {
                    evdev::scroll(phase, x, y, dx, dy);
                }
                true
            }
            ty @ (KEY_DOWN | KEY_UP) => {
                // Android repeats held keys itself.
                let repeat = ty == KEY_DOWN && msg_i64_ret(event, sel("isARepeat")) & 1 != 0;
                let mac = msg_i64_ret(event, sel("keyCode")) as u16;
                // With Command held, a key is the menu bar's if one of its items has it
                // as a shortcut; that key's release is then the menu's too. Everything
                // else goes on to Android as before.
                const COMMAND: i64 = 1 << 20;
                if ty == KEY_DOWN && msg_i64_ret(event, sel("modifierFlags")) & COMMAND != 0 {
                    // A held key's repeats go to nobody: Android repeats keys itself, and
                    // a key held from before Command was pressed must not become a shortcut.
                    if repeat {
                        return true;
                    }
                    let menu = msg0(APP.load(Ordering::Acquire), sel("mainMenu"));
                    if !menu.is_null() && msg_id_bool_ret(menu, sel("performKeyEquivalent:"), event) {
                        claimed(mac, Some(true));
                        return true;
                    }
                }
                if ty == KEY_UP && claimed(mac, Some(false)) {
                    return true;
                }
                if ty == KEY_DOWN && !repeat {
                    // Pressed again, so released since: a claim left on it (its release
                    // went where this window didn't see it) no longer holds.
                    claimed(mac, Some(false));
                }
                if !repeat && let Some(code) = linux_key(mac) {
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
/// whatever the window's, turned as the device is.
struct ShownRect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    turns: u8,
}

impl ShownRect {
    /// A point in the view as a fraction of the panel, from its top left.
    fn place(&self, at: NSPoint) -> (f64, f64) {
        super::controls::to_panel(self.turns, (at.x - self.x) / self.w, 1.0 - (at.y - self.y) / self.h)
    }
}

/// The frame's own size, the panel's: (width, height).
fn panel_size() -> (u32, u32) {
    let size = SHOWN_SIZE.load(Ordering::Relaxed);
    ((size >> 32) as u32, size as u32)
}

fn shown_rect(bounds: NSRect) -> ShownRect {
    let (bw, bh) = (bounds.size.width, bounds.size.height);
    let turns = super::controls::turns();
    let (fw, fh) = super::controls::shown_size(panel_size(), turns);
    let (fw, fh) = (fw as f64, fh as f64);
    if fw == 0.0 || fh == 0.0 {
        return ShownRect { x: 0.0, y: 0.0, w: bw, h: bh, turns };
    }
    let scale = (bw / fw).min(bh / fh);
    let (w, h) = (fw * scale, fh * scale);
    ShownRect { x: (bw - w) / 2.0, y: (bh - h) / 2.0, w, h, turns }
}

static CLAIMED: Mutex<u128> = Mutex::new(0);

/// Mac key codes whose press the menu bar took, so that their releases go nowhere
/// either. `Some(true)` adds `mac`, `Some(false)` takes it out, `None` only looks;
/// each says whether it was there.
fn claimed(mac: u16, change: Option<bool>) -> bool {
    if mac >= 128 {
        return false;
    }
    let mut set = CLAIMED.lock().unwrap_or_else(|p| p.into_inner());
    let bit = 1u128 << mac;
    let was = *set & bit != 0;
    match change {
        Some(true) => *set |= bit,
        Some(false) => *set &= !bit,
        None => {}
    }
    was
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
            // Their releases went to whichever window has the keyboard now. Left here,
            // a later plain press of one of those keys would lose its release.
            *CLAIMED.lock().unwrap_or_else(|p| p.into_inner()) = 0;
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
    with_pool(|| pump_once_in_pool(wait_s));
}

fn pump_once_in_pool(wait_s: f64) {
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

// ---- The toolbar and the menu bar ----

use super::controls::{Action, Key, Shortcut};

/// The one object that every toolbar item and zeroemu's own menu items send their
/// action to, that the toolbar asks for its items, and that the application asks
/// before it quits. AppKit holds it weakly in all three roles, so it is never let go.
static CONTROLS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Tags of the menu's own commands, after the device's (`Action::tag`).
const TAG_HELP: i64 = 100;
const TAG_GAPS: i64 = 101;
const TAG_ABOUT: i64 = 102;
const TAG_LIST: i64 = 103;

/// The toolbar's items at first, in order; Customize Toolbar offers these and `MORE`.
const TOOLBAR: [Action; 6] = [Action::Back, Action::Home, Action::Recents, Action::Screenshot, Action::RotateRight, Action::Power];
const MORE: [Action; 9] = [
    Action::VolumeDown,
    Action::VolumeUp,
    Action::Mute,
    Action::Notifications,
    Action::Settings,
    Action::Lock,
    Action::PowerMenu,
    Action::RotateLeft,
    Action::AndroidScreenshot,
];

unsafe fn ns_str(s: &str) -> *mut c_void {
    unsafe { msg_cstr(cls("NSString"), sel("stringWithUTF8String:"), s) }
}

unsafe fn rust_str(ns: *mut c_void) -> String {
    if ns.is_null() {
        return String::new();
    }
    let p = unsafe { msg0(ns, sel("UTF8String")) } as *const std::ffi::c_char;
    if p.is_null() { String::new() } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

unsafe fn ns_array(items: &[*mut c_void]) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const *mut c_void, u64) -> *mut c_void = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(cls("NSArray"), sel("arrayWithObjects:count:"), items.as_ptr(), items.len() as u64) }
}

/// The class and its one instance, made the first time they're wanted (UI thread).
fn controls_object() -> *mut c_void {
    let have = CONTROLS.load(Ordering::Acquire);
    if !have.is_null() {
        return have;
    }
    unsafe {
        let name = CString::new("ZeroemuControls").unwrap();
        let class = objc_allocateClassPair(cls("NSObject"), name.as_ptr(), 0);
        if class.is_null() {
            return std::ptr::null_mut();
        }
        // Type encodings as the runtime has them for these selectors' protocols.
        let methods: [(&str, *const c_void, &str); 5] = [
            ("deviceAction:", device_action as *const c_void, "v24@0:8@16"),
            ("toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:", toolbar_item as *const c_void, "@36@0:8@16@24B32"),
            ("toolbarDefaultItemIdentifiers:", toolbar_default as *const c_void, "@24@0:8@16"),
            ("toolbarAllowedItemIdentifiers:", toolbar_allowed as *const c_void, "@24@0:8@16"),
            ("applicationShouldTerminate:", should_terminate as *const c_void, "Q24@0:8@16"),
        ];
        for (selector, imp, types) in methods {
            let types = CString::new(types).unwrap();
            class_addMethod(class, sel(selector), imp, types.as_ptr());
        }
        objc_registerClassPair(class);
        let obj = msg0(msg0(class, sel("alloc")), sel("init"));
        CONTROLS.store(obj, Ordering::Release);
        obj
    }
}

/// A toolbar item or one of zeroemu's menu items was chosen.
extern "C" fn device_action(_this: *mut c_void, _cmd: *mut c_void, sender: *mut c_void) {
    let tag = unsafe { msg_i64_ret(sender, sel("tag")) };
    match tag {
        TAG_HELP => open_url("https://github.com/zeroemu/zeroemu#readme"),
        TAG_GAPS => open_url("https://github.com/zeroemu/zeroemu/blob/main/docs/KNOWN-GAPS.md"),
        TAG_ABOUT => about(),
        TAG_LIST => show_list(),
        _ => {
            if let Some(a) = Action::from_tag(tag) {
                super::controls::perform(a);
            }
        }
    }
}

extern "C" fn toolbar_item(_this: *mut c_void, _cmd: *mut c_void, _toolbar: *mut c_void, ident: *mut c_void, _will_insert: bool) -> *mut c_void {
    let Some(a) = Action::from_name(&unsafe { rust_str(ident) }) else { return std::ptr::null_mut() };
    unsafe {
        let item = msg_id_ret(msg0(cls("NSToolbarItem"), sel("alloc")), sel("initWithItemIdentifier:"), ident);
        msg_id(item, sel("setLabel:"), ns_str(a.label()));
        msg_id(item, sel("setPaletteLabel:"), ns_str(a.title()));
        msg_id(item, sel("setToolTip:"), ns_str(a.tooltip()));
        let image = toolbar_symbol(a.symbol(), a.title());
        if !image.is_null() {
            msg_id(item, sel("setImage:"), image);
        }
        msg_id(item, sel("setTarget:"), controls_object());
        msg_id(item, sel("setAction:"), sel("deviceAction:"));
        msg_i64(item, sel("setTag:"), a.tag());
        msg_bool(item, sel("setBordered:"), 1);
        if matches!(a, Action::Back | Action::Home | Action::Recents) {
            // At the leading edge, beside the window's buttons, as a browser's are.
            msg_bool(item, sel("setNavigational:"), 1);
        }
        // What stays when the window is too narrow for every item; the rest go to the
        // toolbar's own overflow menu.
        if matches!(a, Action::Back | Action::Home | Action::Recents | Action::Power) {
            msg_i64(item, sel("setVisibilityPriority:"), 1000);
        }
        // Not ours to keep: the toolbar retains what it gets (the selector isn't one
        // that hands over ownership).
        msg0(item, sel("autorelease"))
    }
}

/// An SF Symbol for a toolbar item, at 15 points rather than the toolbar's own size,
/// which nearly fills the compact toolbar's 24-point buttons: this leaves the icon
/// room around it.
unsafe fn toolbar_symbol(name: &str, description: &str) -> *mut c_void {
    unsafe { symbol(name, description, 15.0) }
}

/// An SF Symbol at `points`, of regular weight.
unsafe fn symbol(name: &str, description: &str, points: f64) -> *mut c_void {
    unsafe {
        let image = msg_id_id_ret(cls("NSImage"), sel("imageWithSystemSymbolName:accessibilityDescription:"), ns_str(name), ns_str(description));
        if image.is_null() {
            return image;
        }
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, f64, f64) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
        // NSFontWeightRegular is 0.
        let config = f(cls("NSImageSymbolConfiguration"), sel("configurationWithPointSize:weight:"), points, 0.0);
        let sized = if config.is_null() { std::ptr::null_mut() } else { msg_id_ret(image, sel("imageWithSymbolConfiguration:"), config) };
        if sized.is_null() { image } else { sized }
    }
}

extern "C" fn toolbar_default(_this: *mut c_void, _cmd: *mut c_void, _toolbar: *mut c_void) -> *mut c_void {
    unsafe {
        let mut ids: Vec<*mut c_void> = TOOLBAR[..3].iter().map(|a| ns_str(a.name())).collect();
        ids.push(NSToolbarFlexibleSpaceItemIdentifier);
        ids.extend(TOOLBAR[3..].iter().map(|a| ns_str(a.name())));
        ns_array(&ids)
    }
}

extern "C" fn toolbar_allowed(_this: *mut c_void, _cmd: *mut c_void, _toolbar: *mut c_void) -> *mut c_void {
    unsafe {
        let mut ids: Vec<*mut c_void> = TOOLBAR.iter().chain(MORE.iter()).map(|a| ns_str(a.name())).collect();
        ids.push(NSToolbarFlexibleSpaceItemIdentifier);
        ns_array(&ids)
    }
}

/// Quit from the menu, the Dock or a logout: the device stops and saves, then zeroemu
/// exits by itself. NSTerminateCancel, as AppKit would otherwise exit() at once, or,
/// asked to wait (NSTerminateLater), hold the main thread in a loop of its own.
extern "C" fn should_terminate(_this: *mut c_void, _cmd: *mut c_void, _app: *mut c_void) -> u64 {
    quit();
    0
}

/// File > Show Device List: the list another zeroemu shows already, brought forward
/// (chosen again, it doesn't open a second), or the list in a zeroemu of its own.
fn show_list() {
    match crate::app::list_shown_by() {
        Some(Some(pid)) => activate_pid(pid),
        // Just opened, and coming forward by itself.
        Some(None) => {}
        None => {
            if let Err(e) = crate::app::open_list() {
                eprintln!("zeroemu: the list of devices didn't open: {e}");
                unsafe { NSBeep() };
            }
        }
    }
}

/// Brings forward the zeroemu with this process id, all its windows.
pub(super) fn activate_pid(pid: u32) {
    with_pool(|| unsafe {
        let other = msg_i64_id_ret(cls("NSRunningApplication"), sel("runningApplicationWithProcessIdentifier:"), pid as i64);
        if !other.is_null() {
            msg_i64(other, sel("activateWithOptions:"), 1); // NSApplicationActivateAllWindows
        }
    });
}

fn open_url(url: &str) {
    unsafe {
        let u = msg_id_ret(cls("NSURL"), sel("URLWithString:"), ns_str(url));
        if !u.is_null() {
            msg_id_bool_ret(msg0(cls("NSWorkspace"), sel("sharedWorkspace")), sel("openURL:"), u);
        }
    }
}

fn about() {
    unsafe {
        // There is no Info.plist to take these from.
        let keys = [ns_str("ApplicationName"), ns_str("ApplicationVersion"), ns_str("Version")];
        let values = [ns_str("zeroemu"), ns_str(env!("CARGO_PKG_VERSION")), ns_str("")];
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const *mut c_void, *const *mut c_void, u64) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let options = f(cls("NSDictionary"), sel("dictionaryWithObjects:forKeys:count:"), values.as_ptr(), keys.as_ptr(), 3);
        msg_id(APP.load(Ordering::Acquire), sel("orderFrontStandardAboutPanelWithOptions:"), options);
    }
}

/// An alert for zeroemu.app, which has no terminal to say why it stops: `title`, then
/// `text`, with Quit, and Show Log when there is a log. True when Show Log was chosen.
/// Main thread, before or after the window.
pub fn alert(title: &str, text: &str, has_log: bool) -> bool {
    with_pool(|| unsafe {
        let app = msg0(cls("NSApplication"), sel("sharedApplication"));
        if app.is_null() {
            return false;
        }
        msg_i64(app, sel("setActivationPolicy:"), 0);
        set_app_icon(app);
        msg_bool(app, sel("activateIgnoringOtherApps:"), 1);
        let alert = list::new_alert();
        msg_id(alert, sel("setMessageText:"), ns_str(title));
        msg_id(alert, sel("setInformativeText:"), ns_str(text));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Quit"));
        if has_log {
            msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Show Log"));
        }
        // NSAlertFirstButtonReturn is 1000, the second 1001.
        msg_i64_ret(alert, sel("runModal")) == 1001
    })
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(alloc: *const c_void, bytes: *const u8, len: isize, encoding: u32, external: u8) -> *const c_void;
    fn CFUserNotificationDisplayAlert(
        timeout: f64,
        flags: usize,
        icon: *const c_void,
        sound: *const c_void,
        localization: *const c_void,
        header: *const c_void,
        message: *const c_void,
        default_button: *const c_void,
        alternate_button: *const c_void,
        other_button: *const c_void,
        response: *mut usize,
    ) -> i32;
}

/// `alert` for any thread, as a panic's is: AppKit's alerts are the main thread's, and
/// CFUserNotification's are shown by another process. Blocks until a button is chosen.
pub fn alert_any_thread(title: &str, text: &str, has_log: bool) -> bool {
    const UTF8: u32 = 0x0800_0100;
    unsafe {
        let cf = |s: &str| CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as isize, UTF8, 0);
        let (title, text, quit) = (cf(title), cf(text), cf("Quit"));
        let show = if has_log { cf("Show Log") } else { std::ptr::null() };
        let mut response = 0usize;
        let null = std::ptr::null();
        let r = CFUserNotificationDisplayAlert(0.0, 0, null, null, null, title, text, quit, show, null, &mut response);
        for s in [title, text, quit, show] {
            if !s.is_null() {
                CFRelease(s);
            }
        }
        // kCFUserNotificationAlternateResponse, in the low bits.
        r == 0 && response & 3 == 1
    }
}

/// Opens a file in the app the Mac opens it with, Console for a log; from any thread.
pub fn open_file(path: &std::path::Path) {
    let _ = std::process::Command::new("/usr/bin/open").arg(path).status();
}

/// zeroemu's icon, as the Dock shows it, also when it runs from a terminal rather than
/// as zeroemu.app (whose bundle has the same icon).
unsafe fn set_app_icon(app: *mut c_void) {
    static ICON: &[u8] = include_bytes!("../../packaging/macos/zeroemu.icns");
    unsafe {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const u8, u64) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
        let data = f(cls("NSData"), sel("dataWithBytes:length:"), ICON.as_ptr(), ICON.len() as u64);
        let image = if data.is_null() { std::ptr::null_mut() } else { msg_id_ret(msg0(cls("NSImage"), sel("alloc")), sel("initWithData:"), data) };
        if !image.is_null() {
            msg_id(app, sel("setApplicationIconImage:"), image);
        }
    }
}

/// The toolbar, before the window is shown and sized (UI thread).
unsafe fn add_toolbar(window: *mut c_void) {
    unsafe {
        let toolbar = msg_id_ret(msg0(cls("NSToolbar"), sel("alloc")), sel("initWithIdentifier:"), ns_str("zeroemu.device"));
        if toolbar.is_null() {
            return;
        }
        msg_id(toolbar, sel("setDelegate:"), controls_object());
        msg_i64(toolbar, sel("setDisplayMode:"), 2); // icons only
        msg_bool(toolbar, sel("setAllowsUserCustomization:"), 1);
        msg_bool(toolbar, sel("setAutosavesConfiguration:"), 1);
        // In the title bar, compact, to leave the phone's screen as much height as there
        // is; the title is the window menu's, as the screen says what the window is.
        msg_i64(window, sel("setToolbarStyle:"), 4);
        msg_i64(window, sel("setTitleVisibility:"), 1);
        msg_id(window, sel("setToolbar:"), toolbar);
    }
}

/// A menu item. An empty `key` is no shortcut; `target` null sends the action up the
/// responder chain, to the window or the application.
unsafe fn menu_item(title: &str, action: &str, key: &str, mods: u64, tag: i64, target: *mut c_void) -> *mut c_void {
    unsafe {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let item = f(msg0(cls("NSMenuItem"), sel("alloc")), sel("initWithTitle:action:keyEquivalent:"), ns_str(title), sel(action), ns_str(key));
        if !key.is_empty() {
            msg_i64(item, sel("setKeyEquivalentModifierMask:"), mods as i64);
        }
        if tag != 0 {
            msg_i64(item, sel("setTag:"), tag);
        }
        if !target.is_null() {
            msg_id(item, sel("setTarget:"), target);
        }
        item
    }
}

const COMMAND_MASK: u64 = 1 << 20;
const OPTION_MASK: u64 = 1 << 19;
const CONTROL_MASK: u64 = 1 << 18;

/// The key equivalent AppKit wants for a shortcut: an uppercase letter is the one
/// with Shift, and the arrows are the private-use characters NSEvent gives them
/// (NSUpArrowFunctionKey and on).
fn key_equivalent(s: Shortcut) -> String {
    match s.key {
        Key::Char(c) if s.shift => c.to_ascii_uppercase().to_string(),
        Key::Char(c) => c.to_string(),
        Key::Up => '\u{F700}'.to_string(),
        Key::Down => '\u{F701}'.to_string(),
        Key::Left => '\u{F702}'.to_string(),
        Key::Right => '\u{F703}'.to_string(),
    }
}

unsafe fn action_item(a: Action) -> *mut c_void {
    let key = a.shortcut().map(key_equivalent).unwrap_or_default();
    unsafe { menu_item(a.title(), "deviceAction:", &key, COMMAND_MASK, a.tag(), controls_object()) }
}

/// A menu of `items` (null for a separator), and the menu bar item that opens it.
unsafe fn submenu(bar: *mut c_void, title: &str, items: &[*mut c_void]) -> *mut c_void {
    unsafe {
        let menu = msg_id_ret(msg0(cls("NSMenu"), sel("alloc")), sel("initWithTitle:"), ns_str(title));
        for &item in items {
            let item = if item.is_null() { msg0(cls("NSMenuItem"), sel("separatorItem")) } else { item };
            msg_id(menu, sel("addItem:"), item);
        }
        let top = msg0(msg0(cls("NSMenuItem"), sel("alloc")), sel("init"));
        msg_id(top, sel("setSubmenu:"), menu);
        msg_id(bar, sel("addItem:"), top);
        menu
    }
}

/// The menu bar, and Quit's handling (UI thread, before finishLaunching).
unsafe fn set_up_menus(app: *mut c_void) {
    let none = std::ptr::null_mut();
    unsafe {
        let me = controls_object();
        if me.is_null() {
            return;
        }
        msg_id(app, sel("setDelegate:"), me);
        let bar = msg0(msg0(cls("NSMenu"), sel("alloc")), sel("init"));
        // The first menu is the application's, named by macOS after the process.
        submenu(bar, "zeroemu", &[
            menu_item("About zeroemu", "deviceAction:", "", 0, TAG_ABOUT, me),
            none,
            menu_item("Hide zeroemu", "hide:", "h", COMMAND_MASK, 0, none),
            menu_item("Hide Others", "hideOtherApplications:", "h", COMMAND_MASK | OPTION_MASK, 0, none),
            menu_item("Show All", "unhideAllApplications:", "", 0, 0, none),
            none,
            menu_item("Quit zeroemu", "terminate:", "q", COMMAND_MASK, 0, none),
        ]);
        // zeroemu.app's list of devices, in a zeroemu of its own, to start another.
        if crate::app::bundle().is_some() {
            submenu(bar, "File", &[menu_item("Show Device List", "deviceAction:", "D", COMMAND_MASK, TAG_LIST, me), none, action_item(Action::Screenshot)]);
        } else {
            submenu(bar, "File", &[action_item(Action::Screenshot)]);
        }
        submenu(bar, "View", &[
            menu_item("Show Toolbar", "toggleToolbarShown:", "t", COMMAND_MASK | OPTION_MASK, 0, none),
            menu_item("Customize Toolbar…", "runToolbarCustomizationPalette:", "", 0, 0, none),
            none,
            menu_item("Enter Full Screen", "toggleFullScreen:", "f", COMMAND_MASK | CONTROL_MASK, 0, none),
        ]);
        use Action::*;
        let groups: [&[Action]; 6] = [
            &[Back, Home, Recents],
            &[Notifications, Settings],
            &[VolumeUp, VolumeDown, Mute],
            &[Power, Lock, PowerMenu],
            &[RotateLeft, RotateRight],
            &[AndroidScreenshot],
        ];
        let mut device = Vec::new();
        for (i, group) in groups.iter().enumerate() {
            if i > 0 {
                device.push(none);
            }
            device.extend(group.iter().map(|&a| action_item(a)));
        }
        submenu(bar, "Device", &device);
        let window = submenu(bar, "Window", &[
            menu_item("Minimize", "performMiniaturize:", "m", COMMAND_MASK, 0, none),
            menu_item("Zoom", "performZoom:", "", 0, 0, none),
            none,
            menu_item("Bring All to Front", "arrangeInFront:", "", 0, 0, none),
        ]);
        let help = submenu(bar, "Help", &[
            menu_item("zeroemu Help", "deviceAction:", "", 0, TAG_HELP, me),
            menu_item("Known Gaps", "deviceAction:", "", 0, TAG_GAPS, me),
        ]);
        msg_id(app, sel("setMainMenu:"), bar);
        msg_id(app, sel("setWindowsMenu:"), window);
        msg_id(app, sel("setHelpMenu:"), help);
    }
}

/// The device was turned: the window shows the panel the new way (any thread).
pub fn turned() {
    extern "C" fn on_main(_: *mut c_void) {
        use crate::kernel::evdev::{self, Touch};
        // A finger down when the phone turns would land somewhere else.
        if TOUCHING.swap(false, Ordering::Relaxed) {
            evdev::touch(Touch::Up, 0.0, 0.0);
        }
        evdev::scroll_cancel();
        let window = WINDOW.load(Ordering::Acquire);
        if window.is_null() {
            return;
        }
        unsafe { reshape(window) };
        FRAME_NEW.store(true, Ordering::Release);
        relayout();
    }
    unsafe { dispatch_async_f(&raw const _dispatch_main_q, std::ptr::null_mut(), on_main) };
}

/// Gives the window the turned panel's shape, at the same scale, about the same
/// middle, and on its screen. A window already that shape, or full screen, stays.
/// The shape is the panel's own turned, so a tablet's window, wide to begin with,
/// goes tall on its side.
unsafe fn reshape(window: *mut c_void) {
    const FULL_SCREEN: i64 = 1 << 14;
    unsafe {
        if msg_i64_ret(window, sel("styleMask")) & FULL_SCREEN != 0 {
            return;
        }
        let frame = msg_rect(window, sel("frame"));
        let content = msg_rect_rect(window, sel("contentRectForFrameRect:"), frame);
        let (cw, ch) = (content.size.width, content.size.height);
        let shown = super::controls::shown_size(panel_size(), super::controls::turns());
        if !super::controls::other_way_round((cw, ch), shown) {
            return;
        }
        let chrome = frame.size.height - ch;
        // A minimized window has no screen: the main screen, then, or none at all.
        let mut screen = msg0(window, sel("screen"));
        if screen.is_null() {
            screen = msg0(cls("NSScreen"), sel("mainScreen"));
        }
        let vis = (!screen.is_null()).then(|| msg_rect(screen, sel("visibleFrame")));
        let scale = vis.map_or(1.0, |v| ((v.size.width - 16.0) / ch).min((v.size.height - chrome - 16.0) / cw).min(1.0));
        let (w, h) = ((ch * scale).floor(), (cw * scale).floor());
        let mut r = msg_rect_rect(window, sel("frameRectForContentRect:"), NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: w, height: h } });
        r.origin.x = frame.origin.x + (frame.size.width - r.size.width) / 2.0;
        r.origin.y = frame.origin.y + (frame.size.height - r.size.height) / 2.0;
        if let Some(v) = vis {
            r.origin.x = r.origin.x.min(v.origin.x + v.size.width - r.size.width).max(v.origin.x);
            r.origin.y = r.origin.y.min(v.origin.y + v.size.height - r.size.height).max(v.origin.y);
        }
        let set: unsafe extern "C" fn(*mut c_void, *mut c_void, NSRect, i8) = std::mem::transmute(objc_msgSend as *const ());
        set(window, sel("setFrame:display:"), r, 1);
    }
}

#[link(name = "ImageIO", kind = "framework")]
unsafe extern "C" {
    fn CGImageDestinationCreateWithURL(url: *const c_void, kind: *const c_void, count: usize, options: *const c_void) -> *mut c_void;
    fn CGImageDestinationAddImage(dest: *mut c_void, image: *mut c_void, properties: *const c_void);
    fn CGImageDestinationFinalize(dest: *mut c_void) -> bool;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(alloc: *const c_void, path: *const u8, len: isize, is_dir: bool) -> *mut c_void;
    fn CFStringCreateWithCString(alloc: *const c_void, s: *const std::ffi::c_char, encoding: u32) -> *mut c_void;
    fn CFStringGetCString(s: *const c_void, buf: *mut std::ffi::c_char, size: isize, encoding: u32) -> bool;
    fn CFStringGetTypeID() -> usize;
    fn CFGetTypeID(obj: *const c_void) -> usize;
    fn CFPreferencesCopyAppValue(key: *const c_void, app: *const c_void) -> *const c_void;
}

const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

fn cf_str(s: &str) -> *mut c_void {
    let c = CString::new(s).unwrap_or_default();
    unsafe { CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), UTF8) }
}

/// Top-down rows of B,G,R,A pixels as a PNG file, in sRGB as Android drew them.
pub fn write_png(path: &std::path::Path, w: u32, h: u32, bgra: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    unsafe {
        let data = CFDataCreate(std::ptr::null(), bgra.as_ptr(), bgra.len() as isize);
        let provider = CGDataProviderCreateWithCFData(data);
        let cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        let img = CGImageCreate(w as usize, h as usize, 8, 32, w as usize * 4, cs, (2 << 12) | 6, provider, std::ptr::null(), false, 0);
        let url = CFURLCreateFromFileSystemRepresentation(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize, false);
        let kind = cf_str("public.png");
        let dest = if img.is_null() || url.is_null() { std::ptr::null_mut() } else { CGImageDestinationCreateWithURL(url, kind, 1, std::ptr::null()) };
        let ok = !dest.is_null() && {
            CGImageDestinationAddImage(dest, img, std::ptr::null());
            CGImageDestinationFinalize(dest)
        };
        for obj in [dest, kind, url] {
            if !obj.is_null() {
                CFRelease(obj);
            }
        }
        if !img.is_null() {
            CGImageRelease(img);
        }
        CGColorSpaceRelease(cs);
        CGDataProviderRelease(provider);
        CFRelease(data);
        if ok { Ok(()) } else { Err(std::io::Error::other("ImageIO couldn't write a PNG")) }
    }
}

/// Where the Mac saves its own screenshots: what Screenshot's Options set
/// (com.apple.screencapture's `location`), or the Desktop.
pub fn screenshot_folder() -> std::path::PathBuf {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    let chosen = unsafe {
        let (key, app) = (cf_str("location"), cf_str("com.apple.screencapture"));
        let value = CFPreferencesCopyAppValue(key, app);
        CFRelease(key);
        CFRelease(app);
        let mut buf = [0 as std::ffi::c_char; 4096];
        let text = (!value.is_null() && CFGetTypeID(value) == CFStringGetTypeID() && CFStringGetCString(value, buf.as_mut_ptr(), buf.len() as isize, UTF8))
            .then(|| std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned());
        if !value.is_null() {
            CFRelease(value);
        }
        text
    };
    let chosen = chosen.map(|p| match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => std::path::PathBuf::from(p),
    });
    chosen.filter(|p| p.is_dir()).unwrap_or_else(|| home.join("Desktop"))
}

/// The sound the Mac makes for its own screenshots, if it has it where it did.
pub fn shutter_sound() {
    /// Loaded once, and played again each time.
    static SOUND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    on_ui_thread(Box::new(|| unsafe {
        const FILE: &str = "/System/Library/Components/CoreAudio.component/Contents/SharedSupport/SystemSounds/system/Screen Capture.aif";
        let mut sound = SOUND.load(Ordering::Acquire);
        if sound.is_null() {
            if !std::path::Path::new(FILE).exists() {
                return;
            }
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i8) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
            sound = f(msg0(cls("NSSound"), sel("alloc")), sel("initWithContentsOfFile:byReference:"), ns_str(FILE), 1);
            if sound.is_null() {
                return;
            }
            SOUND.store(sound, Ordering::Release);
        }
        msg0(sound, sel("stop"));
        msg0(sound, sel("play"));
    }));
}

// ---- The test FIFO's ways in (src/kernel/evdev.rs), each run on the UI thread ----

fn on_ui_thread(job: Box<dyn FnOnce() + Send>) {
    extern "C" fn run(context: *mut c_void) {
        let job = unsafe { Box::from_raw(context as *mut Box<dyn FnOnce() + Send>) };
        with_pool(job);
    }
    unsafe { dispatch_async_f(&raw const _dispatch_main_q, Box::into_raw(Box::new(job)) as *mut c_void, run) };
}

/// `menu Top/Item`: chooses a menu item as a click would, by its menu's and its titles.
pub fn choose_menu_item(path: &str) {
    let path = path.to_string();
    on_ui_thread(Box::new(move || unsafe {
        let mut parts = path.split('/');
        let (Some(top), Some(title)) = (parts.next(), parts.next()) else {
            eprintln!("zeroemu: menu wants Menu/Item, not {path:?}");
            return;
        };
        let bar = msg0(APP.load(Ordering::Acquire), sel("mainMenu"));
        let n = if bar.is_null() { 0 } else { msg_i64_ret(bar, sel("numberOfItems")) };
        for i in 0..n {
            let menu = msg0(msg_i64_id_ret(bar, sel("itemAtIndex:"), i), sel("submenu"));
            if menu.is_null() || rust_str(msg0(menu, sel("title"))) != top {
                continue;
            }
            let at = msg_id_i64_ret(menu, sel("indexOfItemWithTitle:"), ns_str(title));
            if at >= 0 {
                msg_i64(menu, sel("performActionForItemAtIndex:"), at);
                return;
            }
        }
        eprintln!("zeroemu: no menu item {path:?}");
    }));
}

/// `toolbar NAME`: clicks a toolbar item, found by its identifier (`Action::name`).
pub fn click_toolbar_item(name: &str) {
    let name = name.to_string();
    on_ui_thread(Box::new(move || unsafe {
        let window = WINDOW.load(Ordering::Acquire);
        let toolbar = if window.is_null() { std::ptr::null_mut() } else { msg0(window, sel("toolbar")) };
        let items = if toolbar.is_null() { std::ptr::null_mut() } else { msg0(toolbar, sel("items")) };
        let n = if items.is_null() { 0 } else { msg_i64_ret(items, sel("count")) };
        for i in 0..n {
            let item = msg_i64_id_ret(items, sel("objectAtIndex:"), i);
            if rust_str(msg0(item, sel("itemIdentifier"))) == name {
                let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void) -> bool = std::mem::transmute(objc_msgSend as *const ());
                f(APP.load(Ordering::Acquire), sel("sendAction:to:from:"), msg0(item, sel("action")), msg0(item, sel("target")), item);
                return;
            }
        }
        eprintln!("zeroemu: no toolbar item {name:?}");
    }));
}

/// `click U V`: a click on the shown picture, U and V from 0 to 1 from its top left as
/// the user sees it, posted to the window so that it takes a real click's route,
/// turned back onto the panel as the device is turned.
pub fn post_click(u: f64, v: f64) {
    on_ui_thread(Box::new(move || unsafe {
        let window = WINDOW.load(Ordering::Acquire);
        if window.is_null() {
            return;
        }
        let shown = shown_rect(msg_rect(msg0(window, sel("contentView")), sel("bounds")));
        // Window coordinates go up from the bottom; the content view starts at its origin.
        let at = NSPoint { x: shown.x + u * shown.w, y: shown.y + (1.0 - v) * shown.h };
        let number = msg_i64_ret(window, sel("windowNumber"));
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, NSPoint, u64, f64, i64, *mut c_void, i64, i64, f32) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let post: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, bool) = std::mem::transmute(objc_msgSend as *const ());
        for ty in [1u64, 2] {
            // NSEventTypeLeftMouseDown, NSEventTypeLeftMouseUp
            let event = f(cls("NSEvent"), sel("mouseEventWithType:location:modifierFlags:timestamp:windowNumber:context:eventNumber:clickCount:pressure:"),
                ty, at, 0, 0.0, number, std::ptr::null_mut(), 0, 1, 1.0);
            if !event.is_null() {
                post(APP.load(Ordering::Acquire), sel("postEvent:atStart:"), event, false);
            }
        }
    }));
}

/// `keyeq MODS KEYCODE CHARS`: a key press and release with modifiers, posted to the
/// window as if typed, so that it takes the route a real one does (forward_input).
/// MODS joins cmd, shift, alt and ctrl with `+`; CHARS is the key's character, or
/// up, down, left or right.
pub fn post_key(mods: &str, keycode: u16, chars: &str) {
    let flags = mods.split('+').fold(0u64, |f, m| {
        f | match m {
            "cmd" => COMMAND_MASK,
            "alt" => OPTION_MASK,
            "ctrl" => CONTROL_MASK,
            "shift" => 1 << 17,
            _ => 0,
        }
    });
    let chars = match chars {
        "up" => '\u{F700}'.to_string(),
        "down" => '\u{F701}'.to_string(),
        "left" => '\u{F702}'.to_string(),
        "right" => '\u{F703}'.to_string(),
        c => c.to_string(),
    };
    on_ui_thread(Box::new(move || unsafe {
        let window = WINDOW.load(Ordering::Acquire);
        if window.is_null() {
            return;
        }
        let number = msg_i64_ret(window, sel("windowNumber"));
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, NSPoint, u64, f64, i64, *mut c_void, *mut c_void, *mut c_void, bool, u16) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let post: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, bool) = std::mem::transmute(objc_msgSend as *const ());
        for ty in [10u64, 11] {
            // NSEventTypeKeyDown, NSEventTypeKeyUp
            let s = ns_str(&chars);
            let event = f(cls("NSEvent"), sel("keyEventWithType:location:modifierFlags:timestamp:windowNumber:context:characters:charactersIgnoringModifiers:isARepeat:keyCode:"),
                ty, NSPoint { x: 0.0, y: 0.0 }, flags, 0.0, number, std::ptr::null_mut(), s, s, false, keycode);
            if !event.is_null() {
                post(APP.load(Ordering::Acquire), sel("postEvent:atStart:"), event, false);
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::first_size;
    use crate::gpu::Display;

    /// The first window: the device's shape fitted to the screen, never more than one
    /// screen pixel to a device pixel, unless a dp would then be under a point.
    #[test]
    fn first_window_fits_and_stays_sharp() {
        let phone = Display::DEFAULT;
        let small = Display { width: 720, height: 1280, dpi: 320 };
        let tablet = Display { width: 2560, height: 1600, dpi: 320 };
        // A laptop's Retina screen: the phone fits its height, as before.
        assert_eq!(first_size(phone, (1422.0, 888.0), 2.0), (399.0, 888.0));
        // A big Retina screen: a device pixel to a screen pixel, not more.
        assert_eq!(first_size(phone, (2512.0, 1370.0), 2.0), (540.0, 1200.0));
        assert_eq!(first_size(small, (2512.0, 1370.0), 2.0), (360.0, 640.0));
        assert_eq!(first_size(tablet, (1422.0, 888.0), 2.0), (1280.0, 800.0));
        // A screen at one pixel a point.
        assert_eq!(first_size(small, (1872.0, 1350.0), 1.0), (720.0, 1280.0));
        // A tablet on a small screen fits it, keeping its shape.
        let (w, h) = first_size(tablet, (1232.0, 732.0), 1.0);
        assert_eq!(h, 732.0);
        assert!((w / h - 1.6).abs() < 0.01);
        // At 160 dpi, a dp is a pixel: shown at a pixel a point, though that's two
        // screen pixels to each on a Retina screen, so as to be readable.
        let low = Display { width: 720, height: 1280, dpi: 160 };
        assert_eq!(first_size(low, (2512.0, 1370.0), 2.0), (720.0, 1280.0));
        // But still within the screen.
        assert_eq!(first_size(low, (1422.0, 888.0), 2.0), (499.0, 888.0));
    }
}
