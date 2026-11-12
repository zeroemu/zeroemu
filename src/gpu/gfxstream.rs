//! gfxstream, loaded from the Android emulator install and driven through its
//! `stream_renderer_*` C API. The renderer is a process-wide singleton; the
//! window it draws into has to be created on the main thread (AppKit), but
//! the virtio-gpu entry points are what crosvm calls from a device thread and
//! are safe to call from the guest's vCPU threads. `stream_renderer_init` and
//! `gfxstream_backend_setup_window` run on the thread that owns the window.

use super::window::{self, NativeWindow};
use super::{Blob, Box3, Fence, GpuBackend, Iov, Resource3d, ResourceInfo, Transfer};
use std::ffi::{CStr, CString, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

// This build's get_cap_set wrapper discards max_ver and only writes max_size
// (VirtioGpuFrontend::getCapset). create_blob's wrapper ignores its iov and
// always returns 0. resource_detach_iov only reads the handle.
// Confirmed against libgfxstream_backend.dylib (emulator 37.1.11) and the
// upstream header: the wrappers shift x0.. into the C++ method and drop the
// rest.

const PARAM_USER_DATA: u64 = 1;
const PARAM_RENDERER_FLAGS: u64 = 2;
const PARAM_RENDERER_FEATURES: u64 = 11;
const PARAM_FENCE_CALLBACK: u64 = 3;
const PARAM_WIN0_WIDTH: u64 = 4;
const PARAM_WIN0_HEIGHT: u64 = 5;
const PARAM_DEBUG_CALLBACK: u64 = 6;

// USE_GLES | USE_VK. The EGL bit (1<<0) segfaults in this macOS build.
const RENDERER_FLAGS: u64 = (1 << 4) | (1 << 5);

const DEBUG_ERROR: u32 = 1;

static LOG_MAX: AtomicU32 = AtomicU32::new(DEBUG_ERROR);

#[repr(C)]
struct Param {
    key: u64,
    value: u64,
}

#[repr(C)]
struct CFence {
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
}

#[repr(C)]
struct CDebug {
    debug_type: u32,
    message: *const i8,
}

#[repr(C)]
struct CResCreate {
    handle: u32,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    last_level: u32,
    nr_samples: u32,
    flags: u32,
}

#[repr(C)]
struct CBox {
    x: u32,
    y: u32,
    z: u32,
    w: u32,
    h: u32,
    d: u32,
}

#[repr(C)]
struct CCommand {
    ctx_id: u32,
    cmd_size: u32,
    cmd: *mut u8,
    num_in_fences: u32,
    in_fences: *const u64,
}

#[repr(C)]
struct CBlob {
    blob_mem: u32,
    blob_flags: u32,
    blob_id: u64,
    size: u64,
}

#[repr(C)]
struct CHandle {
    os_handle: i64,
    handle_type: u32,
}

/// `stream_renderer_resource_info` from virtio-gpu-gfxstream-renderer-unstable.h.
#[repr(C)]
struct CInfo {
    handle: u32,
    virgl_format: u32,
    width: u32,
    height: u32,
    depth: u32,
    flags: u32,
    tex_id: u32,
    stride: u32,
    drm_fourcc: i32,
}

#[repr(C)]
struct Iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

const _: () = assert!(std::mem::offset_of!(CFence, fence_id) == 8);
const _: () = assert!(std::mem::offset_of!(CFence, ctx_id) == 16);
const _: () = assert!(std::mem::offset_of!(CFence, ring_idx) == 20);
const _: () = assert!(std::mem::offset_of!(CCommand, cmd) == 8);
const _: () = assert!(std::mem::offset_of!(CCommand, num_in_fences) == 16);
const _: () = assert!(std::mem::offset_of!(CCommand, in_fences) == 24);
const _: () = assert!(std::mem::size_of::<CInfo>() == 36);
const _: () = assert!(std::mem::offset_of!(CBlob, blob_id) == 8);

type FnInit = unsafe extern "C" fn(*mut Param, u64) -> i32;
type FnGetCap = unsafe extern "C" fn(u32, *mut u32, *mut u32);
type FnFill = unsafe extern "C" fn(u32, u32, *mut c_void);
type FnCtxCreate = unsafe extern "C" fn(u32, u32, *const i8, u32) -> i32;
type FnCtxDestroy = unsafe extern "C" fn(u32);
type FnSubmit = unsafe extern "C" fn(*mut CCommand) -> i32;
type FnCreateFence = unsafe extern "C" fn(*const CFence) -> i32;
type FnResCreate = unsafe extern "C" fn(*const CResCreate, *const Iovec, u32) -> i32;
type FnResUnref = unsafe extern "C" fn(u32);
type FnAttachIov = unsafe extern "C" fn(i32, *const Iovec, i32) -> i32;
type FnDetachIov = unsafe extern "C" fn(i32);
type FnCtxRes = unsafe extern "C" fn(i32, i32);
type FnXfer = unsafe extern "C" fn(u32, u32, u32, u32, u32, *const CBox, u64, *const Iovec, i32) -> i32;
type FnGetInfo = unsafe extern "C" fn(i32, *mut CInfo) -> i32;
type FnFlush = unsafe extern "C" fn(u32);
type FnCreateBlob = unsafe extern "C" fn(u32, u32, *const CBlob, *const Iovec, u32, *const CHandle) -> i32;
type FnMap = unsafe extern "C" fn(u32, *mut *mut c_void, *mut u64) -> i32;
type FnUnmap = unsafe extern "C" fn(u32) -> i32;
type FnMapInfo = unsafe extern "C" fn(u32, *mut u32) -> i32;
/// FrameBuffer::getFB(): the renderer's display, or null before init.
type FnGetFb = unsafe extern "C" fn() -> *mut c_void;
/// FrameBuffer::setupSubWindow(this, window, x, y, w, h, fb_w, fb_h, dpr, rotation,
/// delete_existing, hide): what gfxstream_backend_setup_window ends in, there with a
/// pixel ratio fixed at 1. True when the subwindow is up.
type FnSetupSubWindow = unsafe extern "C" fn(*mut c_void, *mut c_void, i32, i32, i32, i32, i32, i32, f32, f32, bool, bool) -> bool;
type FnTeardown = unsafe extern "C" fn();

struct Api {
    init: FnInit,
    get_cap_set: FnGetCap,
    fill_caps: FnFill,
    context_create: FnCtxCreate,
    context_destroy: FnCtxDestroy,
    submit_cmd: FnSubmit,
    create_fence: FnCreateFence,
    resource_create: FnResCreate,
    resource_unref: FnResUnref,
    attach_iov: FnAttachIov,
    detach_iov: FnDetachIov,
    ctx_attach: FnCtxRes,
    ctx_detach: FnCtxRes,
    transfer_read: FnXfer,
    transfer_write: FnXfer,
    get_info: FnGetInfo,
    flush: FnFlush,
    create_blob: FnCreateBlob,
    resource_map: FnMap,
    resource_unmap: FnUnmap,
    map_info: FnMapInfo,
    /// FrameBuffer::getFB and setupSubWindow, C++ methods this build exports.
    subwindow: Option<(FnGetFb, FnSetupSubWindow)>,
    teardown: FnTeardown,
}

/// The renderer's one thread, like a VMM's virtio-gpu worker. The renderer
/// makes its GL contexts current on whichever thread calls it, and ANGLE
/// crashes when a context moves between threads. Calls must not come from
/// the many host threads that run guest threads.
struct Worker {
    tx: Mutex<mpsc::Sender<Job>>,
    id: std::thread::ThreadId,
}

type Job = Box<dyn FnOnce() + Send>;

impl Worker {
    fn spawn() -> Worker {
        let (tx, rx) = mpsc::channel::<Job>();
        let t = std::thread::Builder::new()
            .name("virtio-gpu".into())
            .spawn(move || {
                // Everything on screen waits for this thread, and the renderer's own
                // threads start out as urgent as whoever creates them: here.
                crate::hv::set_thread_urgency(crate::hv::Urgency::Display);
                for job in rx {
                    job();
                }
            })
            .expect("spawn the virtio-gpu thread");
        Worker { tx: Mutex::new(tx), id: t.thread().id() }
    }

    /// Runs `f` on the worker and waits for it.
    fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        if std::thread::current().id() == self.id {
            return f();
        }
        let mut out = None;
        let slot = &mut out;
        let (done, wait) = mpsc::channel::<()>();
        // The job owns the sender: the caller may return (and its frame go)
        // while send() is still running on the worker.
        let job: Box<dyn FnOnce() + '_> = Box::new(move || {
            *slot = Some(f());
            let _ = done.send(());
        });
        // SAFETY: this returns only after the job has run (or was dropped
        // unrun), so what it borrows outlives it.
        let job: Job = unsafe { std::mem::transmute::<Box<dyn FnOnce() + '_>, Job>(job) };
        if self.tx.lock().unwrap_or_else(|p| p.into_inner()).send(job).is_ok() {
            let _ = wait.recv();
        }
        out.expect("the virtio-gpu thread stopped")
    }
}

/// What zeroemu knows of a pipe resource.
#[derive(Clone, Copy, Default)]
struct Pipe {
    /// Its first write, the guest's connect, has been made.
    connected: bool,
    /// The context it was attached to last, whose pipe the renderer uses for it.
    ctx: u32,
    /// It has been attached to more than one context.
    shared: bool,
}

struct FenceSlot {
    handler: Option<Arc<dyn Fn(Fence) + Send + Sync>>,
    pending: Vec<Fence>,
}

pub struct Gfxstream {
    api: Api,
    worker: Worker,
    live: Mutex<bool>,
    /// The renderer's user-data cookie: it holds a reference of its own, never given
    /// back, as the renderer's threads can outlive this (see Drop).
    fences: Arc<Mutex<FenceSlot>>,
    /// The last scanout read back for the window.
    frame: Mutex<Vec<u8>>,
    /// The renderer draws scanouts into the window itself, rather than zeroemu
    /// reading them back to show.
    direct: AtomicBool,
    /// The resource last shown.
    scanout: AtomicU32,
    /// Resources that are a context's pipe to its render thread: the guest's GLES
    /// stream (emulation EGL sends it over the pipe, not ASG). Their transfers touch
    /// no GL state and a read waits for the render thread's reply, so they run on the
    /// calling thread, not the worker every other context waits on.
    pipes: Mutex<std::collections::HashMap<u32, Pipe>>,
    /// One pipe transfer at a time per context: gfxstream's pipe state has no lock.
    pipe_ctx: Mutex<std::collections::HashMap<u32, Arc<Mutex<()>>>>,
    /// The renderer's resource and context maps have no lock of their own. Calls
    /// that insert or erase entries hold this exclusively, on the worker; pipe
    /// transfers, which only look entries up, share it.
    maps: std::sync::RwLock<()>,
    /// The renderer's subwindow is (or was) up: teardown must remove it first.
    subwindow: AtomicBool,
    // Kept mapped for the process lifetime. dlclose races the renderer's threads.
    _lib: *mut c_void,
}

unsafe impl Send for Gfxstream {}
unsafe impl Sync for Gfxstream {}

#[cfg(target_os = "macos")]
#[repr(C)]
struct WindowOps {
    is_ui: unsafe extern "C" fn() -> i32,
    run_on_ui: unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void), *mut c_void, i32),
    paint: unsafe extern "C" fn(u32, u32) -> i32,
    is_folded: unsafe extern "C" fn() -> i32,
    get_folded: unsafe extern "C" fn(*mut i32, *mut i32, *mut i32, *mut i32),
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn window_is_ui() -> i32 {
    unsafe { libc::pthread_main_np() }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn window_run_on_ui(f: unsafe extern "C" fn(*mut c_void), data: *mut c_void, wait: i32) {
    window::run_on_ui_thread(f, data, wait != 0);
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn window_paint(_display: u32, _color_buffer: u32) -> i32 {
    0
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn window_is_folded() -> i32 {
    0
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn window_get_folded(x: *mut i32, y: *mut i32, w: *mut i32, h: *mut i32) {
    if !x.is_null() {
        unsafe { *x = 0 };
    }
    if !y.is_null() {
        unsafe { *y = 0 };
    }
    if !w.is_null() {
        unsafe { *w = 0 };
    }
    if !h.is_null() {
        unsafe { *h = 0 };
    }
}

#[cfg(target_os = "macos")]
static WINDOW_OPS: WindowOps = WindowOps {
    is_ui: window_is_ui,
    run_on_ui: window_run_on_ui,
    paint: window_paint,
    is_folded: window_is_folded,
    get_folded: window_get_folded,
};

#[cfg(target_os = "macos")]
fn install_window_ops(lib: *mut c_void) {
    let name = CString::new("_ZN9gfxstream4host31set_gfxstream_window_operationsERK20gfxstream_window_ops").unwrap();
    let p = unsafe { libc::dlsym(lib, name.as_ptr()) };
    if p.is_null() {
        eprintln!("zeroemu: set_gfxstream_window_operations missing");
        return;
    }
    let set: unsafe extern "C" fn(*const WindowOps) = unsafe { std::mem::transmute(p) };
    unsafe { set(&WINDOW_OPS) };
}

/// ZEROEMU_GPU_LOG, else the renderer's errors: when the window stays black, they
/// are the only clue.
fn log_max_from_env() -> u32 {
    match std::env::var("ZEROEMU_GPU_LOG").ok().as_deref() {
        None => DEBUG_ERROR,
        Some("0" | "S" | "silent") => 0,
        Some("1" | "E" | "error") => 1,
        Some("2" | "W" | "warn") => 2,
        Some("3" | "I" | "info") => 3,
        Some("4" | "D" | "debug" | "V") => 4,
        Some(_) => DEBUG_ERROR,
    }
}

extern "C" fn on_debug(_user: *mut c_void, dbg: *const CDebug) {
    if dbg.is_null() {
        return;
    }
    let d = unsafe { &*dbg };
    if d.debug_type == 0 || d.debug_type > LOG_MAX.load(Ordering::Relaxed) || d.message.is_null() {
        return;
    }
    let msg = unsafe { CStr::from_ptr(d.message) }.to_string_lossy();
    if d.debug_type == DEBUG_ERROR && !explicit_log() && EVERY_BOOT.iter().any(|m| msg.contains(m)) {
        return;
    }
    eprintln!("gfxstream: {msg}");
}

/// Errors the renderer reports at every boot that works, which say nothing wrong:
/// the guest's driver asking for capability sets this renderer doesn't have, and
/// resources let go after the context that held them. They print only when
/// ZEROEMU_GPU_LOG asks for the renderer's log.
const EVERY_BOOT: &[&str] = &["Incorrect capability set specified", "failed to detach resource"];

fn explicit_log() -> bool {
    static SET: OnceLock<bool> = OnceLock::new();
    *SET.get_or_init(|| std::env::var_os("ZEROEMU_GPU_LOG").is_some())
}

/// ZEROEMU_GPU_STATS=1: every five seconds, how many frames went to the window and
/// what showing them cost the composer: reading each back, or handing it to the
/// renderer to draw (`frame` is None). A frame's budget is 16 ms.
fn flush_stats(took: Duration, frame: Option<&[u8]>) {
    struct Window {
        since: Instant,
        frames: u32,
        black: u32,
        total: Duration,
        worst: Duration,
    }
    static ON: OnceLock<bool> = OnceLock::new();
    static STATS: Mutex<Option<Window>> = Mutex::new(None);
    if !*ON.get_or_init(|| std::env::var_os("ZEROEMU_GPU_STATS").is_some()) {
        return;
    }
    let mut g = STATS.lock().unwrap_or_else(|p| p.into_inner());
    let w = g.get_or_insert_with(|| Window { since: Instant::now(), frames: 0, black: 0, total: Duration::ZERO, worst: Duration::ZERO });
    w.frames += 1;
    // A sample is plenty, as a frame is either wholly black or it isn't. Alpha aside.
    if frame.is_some_and(|f| f.chunks_exact(4).step_by(1009).all(|p| p[..3] == [0, 0, 0] || p[1..] == [0, 0, 0])) {
        w.black += 1;
    }
    w.total += took;
    w.worst = w.worst.max(took);
    let elapsed = w.since.elapsed();
    if elapsed >= Duration::from_secs(5) {
        eprintln!(
            "zeroemu: display {:.1} fps, {} black, {} avg {:.1} ms, worst {:.1} ms, window {}; {}",
            w.frames as f64 / elapsed.as_secs_f64(),
            w.black,
            if frame.is_some() { "readback" } else { "post" },
            w.total.as_secs_f64() * 1000.0 / w.frames as f64,
            w.worst.as_secs_f64() * 1000.0,
            if window::on_screen() { "on screen" } else { "covered" },
            crate::kernel::wakeup_stats(elapsed)
        );
        *g = None;
    }
}

extern "C" fn on_fence(user: *mut c_void, fence: *const CFence) {
    if user.is_null() || fence.is_null() {
        return;
    }
    let fences = unsafe { &*(user as *const Mutex<FenceSlot>) };
    let f = unsafe { &*fence };
    let fence = Fence { flags: f.flags, fence_id: f.fence_id, ctx_id: f.ctx_id, ring_idx: f.ring_idx };
    let handler = {
        let mut slot = fences.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(h) = slot.handler.clone() {
            h
        } else {
            slot.pending.push(fence);
            return;
        }
    };
    let _ = catch_unwind(AssertUnwindSafe(|| handler(fence)));
}

fn ck(r: i32) -> Result<(), i64> {
    if r == 0 { Ok(()) } else { Err(r.unsigned_abs() as i64) }
}

fn iov_buf(iov: &Iov) -> Vec<Iovec> {
    iov.iter().map(|&(p, n)| Iovec { iov_base: p as *mut c_void, iov_len: n }).collect()
}

fn c_box(b: &Box3) -> CBox {
    CBox { x: b.x, y: b.y, z: b.z, w: b.w, h: b.h, d: b.d }
}

pub fn open(width: u32, height: u32) -> Result<Arc<dyn GpuBackend>, String> {
    // Before the window: a missing renderer is an error with no window to show.
    let path = backend_path()?;
    let win = window::open(width, height)?;
    let lib = load_backend(&path)?;
    let api = load_api(lib)?;
    let gfx = Arc::new(Gfxstream {
        api,
        worker: Worker::spawn(),
        live: Mutex::new(false),
        fences: Arc::new(Mutex::new(FenceSlot { handler: None, pending: Vec::new() })),
        frame: Mutex::new(Vec::new()),
        direct: AtomicBool::new(false),
        scanout: AtomicU32::new(0),
        pipes: Mutex::new(std::collections::HashMap::new()),
        pipe_ctx: Mutex::new(std::collections::HashMap::new()),
        maps: std::sync::RwLock::new(()),
        subwindow: AtomicBool::new(false),
        _lib: lib,
    });
    gfx.start(width, height, &win)?;
    Ok(gfx)
}

impl Gfxstream {
    fn start(self: &Arc<Self>, fb_w: u32, fb_h: u32, win: &NativeWindow) -> Result<(), String> {
        LOG_MAX.store(log_max_from_env(), Ordering::Relaxed);
        // This build's internal shaders are `#version 300 es` when it thinks the
        // host is GLES, and desktop GL rejects those, so the window stays black.
        // The emulator's ANGLE libs (found by the dlopen hook) are a GLES 3 host.
        #[cfg(target_os = "macos")]
        if std::env::var_os("ANDROID_EGL_ON_EGL").is_none()
            && SEARCH_DIRS.get().is_some_and(|dirs| {
                dirs.iter().any(|d| d.join("libEGL.dylib").is_file() && d.join("libGLESv2.dylib").is_file())
            })
        {
            unsafe { std::env::set_var("ANDROID_EGL_ON_EGL", "1") };
        }
        // ANGLE's default here is its OpenGL backend, which shares one CGL
        // context across threads: guest draws then randomly miss frames. Its
        // Metal backend keeps each context to itself.
        #[cfg(target_os = "macos")]
        if std::env::var_os("ANGLE_DEFAULT_PLATFORM").is_none() {
            unsafe { std::env::set_var("ANGLE_DEFAULT_PLATFORM", "metal") };
        }
        // The guest's gralloc is minigbm, as in the Android Emulator's
        // virtio-gpu mode; ZEROEMU_GPU_FEATURES overrides ("Name:enabled,...").
        let features = std::ffi::CString::new(std::env::var("ZEROEMU_GPU_FEATURES").unwrap_or_else(|_| "Minigbm:enabled".into())).unwrap_or_default();
        let user = Arc::into_raw(self.fences.clone()) as usize as u64;
        let mut params = [
            Param { key: PARAM_USER_DATA, value: user },
            Param { key: PARAM_RENDERER_FLAGS, value: RENDERER_FLAGS },
            Param { key: PARAM_FENCE_CALLBACK, value: on_fence as *const () as usize as u64 },
            // Guest display size is the view's pixel backing. The NSView frame
            // below is in points, so the same image fills the window.
            Param { key: PARAM_WIN0_WIDTH, value: win.px_width as u64 },
            Param { key: PARAM_WIN0_HEIGHT, value: win.px_height as u64 },
            Param { key: PARAM_DEBUG_CALLBACK, value: on_debug as *const () as usize as u64 },
            Param { key: PARAM_RENDERER_FEATURES, value: features.as_ptr() as usize as u64 },
        ];
        let r = self.worker.run(|| unsafe { (self.api.init)(params.as_mut_ptr(), params.len() as u64) });
        if r != 0 {
            return Err(format!("stream_renderer_init returned {r}"));
        }
        *self.live.lock().unwrap_or_else(|p| p.into_inner()) = true;
        #[cfg(target_os = "macos")]
        install_window_ops(self._lib);
        #[cfg(target_os = "macos")]
        self.attach_window();
        let _ = (win, fb_w, fb_h);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Gfxstream {
    /// Has the renderer draw each scanout straight into the window, as the Android
    /// Emulator does, instead of zeroemu reading it back. gfxstream's own
    /// setup_window entry point fixes the pixel ratio at 1, which showed a magnified
    /// corner on Retina screens; the method it ends in takes the real ratio.
    /// ZEROEMU_READBACK=1 keeps the old way.
    fn attach_window(self: &Arc<Self>) {
        let Some((get_fb, setup)) = self.api.subwindow else { return };
        if std::env::var_os("ZEROEMU_READBACK").is_some() {
            return;
        }
        let me = Arc::downgrade(self);
        let attach = move |win: *mut c_void, p: window::Placement| {
            // The UI thread. The rectangle is the view's from its top left, in points;
            // the frame fills it, at p.dpr pixels per point. Not once the renderer is
            // going away.
            let Some(g) = me.upgrade() else { return };
            let fb = unsafe { get_fb() };
            if !fb.is_null() {
                g.subwindow.store(true, Ordering::Release);
            }
            let up = !fb.is_null() && unsafe { setup(fb, win, p.x, p.y, p.w, p.h, p.w, p.h, p.dpr, 0.0, false, false) };
            g.direct.store(up, Ordering::Release);
            window::set_drawing(up);
            if !up {
                eprintln!("zeroemu: the renderer can't draw into the window ({p:?}); reading frames back");
            }
        };
        let me = Arc::downgrade(self);
        let source = move || {
            let g = me.upgrade()?;
            let handle = g.scanout.load(Ordering::Acquire);
            let info = g.resource_info(handle)?;
            let (w, h, px) = g.read_pixels(handle)?;
            Some((w, h, info.drm_fourcc, px))
        };
        window::attach_renderer(Box::new(attach), Box::new(source));
    }
}

impl Drop for Gfxstream {
    fn drop(&mut self) {
        let live = {
            let mut g = self.live.lock().unwrap_or_else(|p| p.into_inner());
            let was = *g;
            *g = false;
            was
        };
        // Once it has drawn into the window, the renderer can't be torn down: its
        // teardown destroys the post worker that posts queued on the UI thread still
        // point at, and removes the subwindow off the UI thread. This only happens as
        // zeroemu exits, which frees everything anyway.
        if live && !self.subwindow.load(Ordering::Acquire) {
            self.exclusive(|| unsafe { (self.api.teardown)() });
        }
    }
}

impl GpuBackend for Gfxstream {
    fn capset_info(&self, id: u32) -> Option<(u32, u32)> {
        let mut ver = 0u32;
        let mut size = 0u32;
        self.worker.run(|| unsafe { (self.api.get_cap_set)(id, &mut ver, &mut size) });
        if size == 0 { None } else { Some((ver, size)) }
    }

    fn capset(&self, id: u32, version: u32) -> Vec<u8> {
        let Some((_, size)) = self.capset_info(id) else { return Vec::new() };
        let mut buf = vec![0u8; size as usize];
        self.worker.run(|| unsafe { (self.api.fill_caps)(id, version, buf.as_mut_ptr() as *mut c_void) });
        buf
    }

    fn context_create(&self, ctx_id: u32, name: &str, context_init: u32) -> Result<(), i64> {
        let c = CString::new(name).map_err(|_| 22i64)?;
        ck(self.exclusive(|| unsafe { (self.api.context_create)(ctx_id, c.as_bytes().len() as u32, c.as_ptr(), context_init) }))
    }

    fn context_destroy(&self, ctx_id: u32) {
        self.exclusive(|| unsafe { (self.api.context_destroy)(ctx_id) });
        self.pipe_ctx.lock().unwrap_or_else(|p| p.into_inner()).remove(&ctx_id);
    }

    fn submit(&self, ctx_id: u32, cmds: &[u8], in_fences: &[u64]) -> Result<(), i64> {
        let mut cmd = CCommand {
            ctx_id,
            cmd_size: cmds.len() as u32,
            cmd: cmds.as_ptr() as *mut u8,
            num_in_fences: in_fences.len() as u32,
            in_fences: if in_fences.is_empty() { std::ptr::null() } else { in_fences.as_ptr() },
        };
        ck(self.worker.run(|| unsafe { (self.api.submit_cmd)(&mut cmd) }))
    }

    fn create_fence(&self, fence: Fence) -> Result<(), i64> {
        let c = CFence { flags: fence.flags, fence_id: fence.fence_id, ctx_id: fence.ctx_id, ring_idx: fence.ring_idx };
        ck(self.worker.run(|| unsafe { (self.api.create_fence)(&c) }))
    }

    fn resource_create(&self, args: &Resource3d, iov: Iov) -> Result<(), i64> {
        let c = CResCreate {
            handle: args.handle,
            target: args.target,
            format: args.format,
            bind: args.bind,
            width: args.width,
            height: args.height,
            depth: args.depth,
            array_size: args.array_size,
            last_level: args.last_level,
            nr_samples: args.nr_samples,
            flags: args.flags,
        };
        let buf = iov_buf(&iov);
        let ptr = if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() };
        ck(self.exclusive(|| unsafe { (self.api.resource_create)(&c, ptr, buf.len() as u32) }))?;
        // As the renderer tells them apart (GetResourceType).
        const PIPE_BUFFER: u32 = 0;
        const VIRGL_BIND_CUSTOM: u32 = 1 << 17;
        if args.target == PIPE_BUFFER && args.bind == VIRGL_BIND_CUSTOM {
            self.pipes.lock().unwrap_or_else(|p| p.into_inner()).insert(args.handle, Pipe::default());
        }
        Ok(())
    }

    fn resource_create_blob(&self, ctx_id: u32, handle: u32, blob: &Blob, iov: Iov) -> Result<(), i64> {
        let c = CBlob { blob_mem: blob.blob_mem, blob_flags: blob.blob_flags, blob_id: blob.blob_id, size: blob.size };
        let buf = iov_buf(&iov);
        let ptr = if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() };
        ck(self.exclusive(|| unsafe { (self.api.create_blob)(ctx_id, handle, &c, ptr, buf.len() as u32, std::ptr::null()) }))
    }

    fn resource_unref(&self, handle: u32) {
        self.pipes.lock().unwrap_or_else(|p| p.into_inner()).remove(&handle);
        self.exclusive(|| unsafe { (self.api.resource_unref)(handle) });
    }

    fn attach_iov(&self, handle: u32, iov: Iov) -> Result<(), i64> {
        let buf = iov_buf(&iov);
        let ptr = if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() };
        ck(self.for_resource(handle, || unsafe { (self.api.attach_iov)(handle as i32, ptr, buf.len() as i32) }))
    }

    fn detach_iov(&self, handle: u32) {
        self.for_resource(handle, || unsafe { (self.api.detach_iov)(handle as i32) });
    }

    fn ctx_attach_resource(&self, ctx_id: u32, handle: u32) {
        self.for_resource(handle, || unsafe { (self.api.ctx_attach)(ctx_id as i32, handle as i32) });
        // The renderer moves a pipe resource onto the pipe of the context it was
        // attached to last.
        if let Some(p) = self.pipes.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&handle) {
            p.shared |= p.ctx != 0 && p.ctx != ctx_id;
            p.ctx = ctx_id;
        }
    }

    fn ctx_detach_resource(&self, ctx_id: u32, handle: u32) {
        self.for_resource(handle, || unsafe { (self.api.ctx_detach)(ctx_id as i32, handle as i32) });
        if let Some(p) = self.pipes.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&handle)
            && p.ctx == ctx_id
        {
            p.ctx = 0;
        }
    }

    fn transfer_write(&self, handle: u32, t: &Transfer) -> Result<(), i64> {
        self.xfer(self.api.transfer_write, handle, t, true)
    }

    fn transfer_read(&self, handle: u32, t: &Transfer) -> Result<(), i64> {
        self.xfer(self.api.transfer_read, handle, t, false)
    }

    fn resource_info(&self, handle: u32) -> Option<ResourceInfo> {
        let mut info = CInfo {
            handle: 0,
            virgl_format: 0,
            width: 0,
            height: 0,
            depth: 0,
            flags: 0,
            tex_id: 0,
            stride: 0,
            drm_fourcc: 0,
        };
        let r = self.worker.run(|| unsafe { (self.api.get_info)(handle as i32, &mut info) });
        if r != 0 {
            return None;
        }
        Some(ResourceInfo {
            virgl_format: info.virgl_format,
            width: info.width,
            height: info.height,
            depth: info.depth,
            flags: info.flags,
            stride: info.stride,
            drm_fourcc: info.drm_fourcc as u32,
        })
    }

    fn resource_map(&self, handle: u32) -> Result<(*mut u8, u64), i64> {
        let mut ptr = std::ptr::null_mut();
        let mut size = 0u64;
        ck(self.for_resource(handle, || unsafe { (self.api.resource_map)(handle, &mut ptr, &mut size) }))?;
        Ok((ptr as *mut u8, size))
    }

    fn resource_unmap(&self, handle: u32) {
        self.for_resource(handle, || unsafe { (self.api.resource_unmap)(handle) });
    }

    fn map_info(&self, handle: u32) -> Option<u32> {
        let mut info = 0u32;
        let r = self.worker.run(|| unsafe { (self.api.map_info)(handle, &mut info) });
        if r == 0 { Some(info) } else { None }
    }

    /// Shows a scanout: the renderer draws it into the window, or, when it can't,
    /// it's read back into host memory for the window to draw on the UI thread.
    fn flush(&self, handle: u32) {
        if self.direct.load(Ordering::Acquire) {
            // The renderer posts it to the window from the UI thread, and finishes the
            // flush's task on its global timeline when it has: the composer's present
            // fence then signals when the frame is up.
            self.scanout.store(handle, Ordering::Release);
            let _span = crate::kernel::trace::span("gpu flush (post)");
            let started = Instant::now();
            let size = self.worker.run(|| unsafe {
                let mut info = CInfo { handle: 0, virgl_format: 0, width: 0, height: 0, depth: 0, flags: 0, tex_id: 0, stride: 0, drm_fourcc: 0 };
                let size = ((self.api.get_info)(handle as i32, &mut info) == 0).then_some((info.width, info.height));
                (self.api.flush)(handle);
                size
            });
            if let Some((w, h)) = size {
                window::set_shown_size(w, h);
            }
            flush_stats(started.elapsed(), None);
            return;
        }
        if self.pipes.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&handle) {
            return; // a pipe, not a picture
        }
        let Some(info) = self.resource_info(handle) else { return };
        let (w, h) = (info.width, info.height);
        if w == 0 || h == 0 || w > 8192 || h > 8192 {
            return;
        }
        let stride = w * 4;
        let mut buf = self.frame.lock().unwrap_or_else(|p| p.into_inner());
        buf.resize(stride as usize * h as usize, 0);
        let iov = Iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() };
        let b = CBox { x: 0, y: 0, z: 0, w, h, d: 1 };
        let started = Instant::now();
        if self.worker.run(|| unsafe { (self.api.transfer_read)(handle, 0, 0, stride, 0, &b, 0, &iov, 1) }) == 0 {
            window::present(w, h, stride, info.drm_fourcc, &buf);
        }
        flush_stats(started.elapsed(), Some(&buf));
    }

    fn read_pixels(&self, handle: u32) -> Option<(u32, u32, Vec<u8>)> {
        if self.pipes.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&handle) {
            return None;
        }
        let info = self.resource_info(handle)?;
        let (w, h) = (info.width, info.height);
        if w == 0 || h == 0 || w > 8192 || h > 8192 {
            return None;
        }
        let mut buf = vec![0u8; w as usize * h as usize * 4];
        let iov = Iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() };
        let b = CBox { x: 0, y: 0, z: 0, w, h, d: 1 };
        (self.worker.run(|| unsafe { (self.api.transfer_read)(handle, 0, 0, w * 4, 0, &b, 0, &iov, 1) }) == 0).then_some((w, h, buf))
    }

    fn set_fence_handler(&self, handler: Arc<dyn Fn(Fence) + Send + Sync>) {
        let pending = {
            let mut slot = self.fences.lock().unwrap_or_else(|p| p.into_inner());
            slot.handler = Some(handler.clone());
            std::mem::take(&mut slot.pending)
        };
        for f in pending {
            let _ = catch_unwind(AssertUnwindSafe(|| handler(f)));
        }
    }
}

impl Gfxstream {
    fn xfer(&self, f: FnXfer, handle: u32, t: &Transfer, write: bool) -> Result<(), i64> {
        // Null iov: the renderer uses the iovec attached to the resource.
        let b = c_box(&t.bx);
        let call = || unsafe { f(handle, t.ctx_id, t.level, t.stride, t.layer_stride, &b, t.offset, std::ptr::null(), 0) };
        static SERIAL: OnceLock<bool> = OnceLock::new();
        let serial = *SERIAL.get_or_init(|| std::env::var_os("ZEROEMU_GPU_SERIAL").is_some());
        let pipe = if serial { None } else { self.pipes.lock().unwrap_or_else(|p| p.into_inner()).get(&handle).copied() };
        match pipe {
            None => ck(self.worker.run(call)),
            // Connected, and on the pipe of the one context it has been attached to: on the
            // calling thread, one transfer at a time on that pipe.
            Some(p) if p.connected && !p.shared && p.ctx != 0 && p.ctx == t.ctx_id => {
                let one = self.pipe_ctx.lock().unwrap_or_else(|p| p.into_inner()).entry(p.ctx).or_default().clone();
                let _one = one.lock().unwrap_or_else(|p| p.into_inner());
                let _shared = self.maps.read().unwrap_or_else(|p| p.into_inner());
                ck(call())
            }
            // The first write is the guest's connect, which makes the renderer create the
            // pipe's render channel. And a pipe attached to more than one context, or used
            // from another, may share its pipe with any of them. With nothing else running.
            Some(p) => {
                let r = ck(self.exclusive(call));
                if !p.connected && write && r.is_ok()
                    && let Some(p) = self.pipes.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&handle)
                {
                    p.connected = true;
                }
                r
            }
        }
    }

    /// A call about one resource that changes no map: on the worker, and with no
    /// pipe transfer running if the resource is a pipe.
    fn for_resource<R>(&self, handle: u32, f: impl FnOnce() -> R) -> R {
        if self.pipes.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&handle) {
            self.exclusive(f)
        } else {
            self.worker.run(f)
        }
    }

    /// Runs a call that inserts or erases entries in the renderer's maps: on the
    /// worker, with no pipe transfer looking at them.
    fn exclusive<R>(&self, f: impl FnOnce() -> R) -> R {
        self.worker.run(|| {
            let _only = self.maps.write().unwrap_or_else(|p| p.into_inner());
            f()
        })
    }
}

/// The renderer library: ZEROEMU_GFXSTREAM, else the SDK's Android Emulator's.
fn backend_path() -> Result<std::path::PathBuf, String> {
    crate::sdk::require_renderer().map(|r| r.path).map_err(|p| p.to_string())
}

fn cast_sym<T>(p: *mut c_void, name: &str) -> Result<T, String> {
    if p.is_null() {
        return Err(format!("gfxstream: missing {name}"));
    }
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
    Ok(unsafe { std::mem::transmute_copy(&p) })
}

fn load_api(lib: *mut c_void) -> Result<Api, String> {
    Ok(Api {
        init: lookup(lib, "stream_renderer_init")?,
        get_cap_set: lookup(lib, "stream_renderer_get_cap_set")?,
        fill_caps: lookup(lib, "stream_renderer_fill_caps")?,
        context_create: lookup(lib, "stream_renderer_context_create")?,
        context_destroy: lookup(lib, "stream_renderer_context_destroy")?,
        submit_cmd: lookup(lib, "stream_renderer_submit_cmd")?,
        create_fence: lookup(lib, "stream_renderer_create_fence")?,
        resource_create: lookup(lib, "stream_renderer_resource_create")?,
        resource_unref: lookup(lib, "stream_renderer_resource_unref")?,
        attach_iov: lookup(lib, "stream_renderer_resource_attach_iov")?,
        detach_iov: lookup(lib, "stream_renderer_resource_detach_iov")?,
        ctx_attach: lookup(lib, "stream_renderer_ctx_attach_resource")?,
        ctx_detach: lookup(lib, "stream_renderer_ctx_detach_resource")?,
        transfer_read: lookup(lib, "stream_renderer_transfer_read_iov")?,
        transfer_write: lookup(lib, "stream_renderer_transfer_write_iov")?,
        get_info: lookup(lib, "stream_renderer_resource_get_info")?,
        flush: lookup(lib, "stream_renderer_flush")?,
        create_blob: lookup(lib, "stream_renderer_create_blob")?,
        resource_map: lookup(lib, "stream_renderer_resource_map")?,
        resource_unmap: lookup(lib, "stream_renderer_resource_unmap")?,
        map_info: lookup(lib, "stream_renderer_resource_map_info")?,
        subwindow: lookup(lib, "_ZN9gfxstream4host11FrameBuffer5getFBEv")
            .and_then(|get| Ok((get, lookup(lib, "_ZN9gfxstream4host11FrameBuffer14setupSubWindowEPviiiiiiffbb")?)))
            .ok(),
        teardown: lookup(lib, "stream_renderer_teardown")?,
    })
}

#[cfg(unix)]
fn lookup<T>(lib: *mut c_void, name: &str) -> Result<T, String> {
    let c = CString::new(name).unwrap();
    let p = unsafe { libc::dlsym(lib, c.as_ptr()) };
    cast_sym(p, name)
}

#[cfg(unix)]
fn load_backend(path: &std::path::Path) -> Result<*mut c_void, String> {
    let dir = path.parent().ok_or_else(|| format!("gfxstream: {} has no directory", path.display()))?;
    #[cfg(target_os = "macos")]
    install_library_search(dir);
    // Absolute dlopen does not search @rpath. A library already in the process
    // satisfies a later @rpath/libX.dylib dependency, so walk the dlerror chain
    // and preload each missing sibling before retrying.
    let mut stack = vec![path.to_path_buf()];
    let mut seen = Vec::new();
    let mut opened = Vec::new();
    let mut spins = 0;
    while let Some(cur) = stack.last().cloned() {
        spins += 1;
        if spins > 64 {
            return Err("gfxstream: dependency cycle while loading".into());
        }
        match dlopen_abs(&cur) {
            Ok(h) => {
                opened.push(h);
                stack.pop();
            }
            Err(msg) => {
                let Some(name) = missing_rpath(&msg) else {
                    return Err(format!("dlopen {}: {msg}", cur.display()));
                };
                let dep = dir.join(&name);
                if seen.iter().any(|p: &std::path::PathBuf| p == &dep) || !dep.exists() {
                    return Err(format!("dlopen {}: {msg}", cur.display()));
                }
                seen.push(dep.clone());
                stack.push(dep);
            }
        }
    }
    #[cfg(target_os = "macos")]
    rebind_imported_dlopen();
    opened.last().copied().ok_or_else(|| "gfxstream: dlopen produced no handle".into())
}

#[cfg(unix)]
fn dlopen_abs(path: &std::path::Path) -> Result<*mut c_void, String> {
    let c = CString::new(path.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
    let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
    if h.is_null() {
        let err = unsafe { CStr::from_ptr(libc::dlerror()) }.to_string_lossy().into_owned();
        Err(err)
    } else {
        Ok(h)
    }
}

#[cfg(unix)]
fn missing_rpath(msg: &str) -> Option<String> {
    let rest = msg.split("@rpath/").nth(1)?;
    let name = rest.split_whitespace().next().unwrap_or("").trim_matches(|c| c == '\'' || c == '"');
    if name.is_empty() { None } else { Some(name.to_string()) }
}

#[cfg(windows)]
fn lookup<T>(lib: *mut c_void, name: &str) -> Result<T, String> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    let c = CString::new(name).unwrap();
    let fp = unsafe { GetProcAddress(lib, c.as_ptr() as *const u8) };
    let p = fp.map(|f| f as usize as *mut c_void).unwrap_or(std::ptr::null_mut());
    cast_sym(p, name)
}

#[cfg(windows)]
fn load_backend(path: &std::path::Path) -> Result<*mut c_void, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::LibraryLoader::{LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let h = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    if h.is_null() {
        Err(format!("LoadLibraryExW {}: error {}", path.display(), unsafe { GetLastError() }))
    } else {
        Ok(h)
    }
}

// gfxstream dlopens libshadertranslator.dylib, libEGL.dylib and libGLESv2.dylib
// by bare filename. dyld does not search DYLD_LIBRARY_PATH for an ad-hoc signed
// executable, so redirect those names into the emulator's lib64 (and its
// gles_angle/ and vulkan/ subdirectories) before the real dlopen.
#[cfg(target_os = "macos")]
fn install_library_search(dir: &std::path::Path) {
    let mut dirs = vec![dir.to_path_buf()];
    for sub in ["gles_angle", "vulkan"] {
        let p = dir.join(sub);
        if p.is_dir() {
            dirs.push(p);
        }
    }
    if std::env::var_os("VK_ICD_FILENAMES").is_none() {
        let icd = dir.join("vulkan/MoltenVK_icd.json");
        if icd.is_file() {
            unsafe { std::env::set_var("VK_ICD_FILENAMES", &icd) };
        }
    }
    let _ = SEARCH_DIRS.set(dirs);
    if REAL_DLOPEN.load(Ordering::Relaxed).is_null() {
        let name = CString::new("dlopen").unwrap();
        REAL_DLOPEN.store(unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) }, Ordering::Relaxed);
    }
}

#[cfg(target_os = "macos")]
static SEARCH_DIRS: std::sync::OnceLock<Vec<std::path::PathBuf>> = std::sync::OnceLock::new();

#[cfg(target_os = "macos")]
static REAL_DLOPEN: std::sync::atomic::AtomicPtr<c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

// dyld ignores __interpose in the main executable, so rewrite each loaded
// image's imported _dlopen slot. stream_renderer_init then resolves
// libshadertranslator / libEGL / libGLESv2 from the emulator tree.
#[cfg(target_os = "macos")]
fn rebind_imported_dlopen() {
    unsafe {
        let n = _dyld_image_count();
        for i in 1..n {
            rebind_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn hooked_dlopen(path: *const libc::c_char, mode: libc::c_int) -> *mut c_void {
    let real = real_dlopen();
    if !path.is_null() {
        let raw = unsafe { CStr::from_ptr(path) }.to_bytes();
        let bare = raw.strip_prefix(b"./").unwrap_or(raw);
        if !bare.contains(&b'/')
            && let Some(dirs) = SEARCH_DIRS.get()
            && let Ok(name) = std::str::from_utf8(bare)
        {
            for d in dirs {
                let cand = d.join(name);
                if !cand.is_file() {
                    continue;
                }
                let Ok(c) = CString::new(cand.to_string_lossy().as_bytes()) else { continue };
                let h = unsafe { real(c.as_ptr(), mode) };
                if !h.is_null() {
                    rebind_imported_dlopen();
                    return h;
                }
            }
        }
    }
    unsafe { real(path, mode) }
}

#[cfg(target_os = "macos")]
fn real_dlopen() -> unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> *mut c_void {
    let p = REAL_DLOPEN.load(Ordering::Relaxed);
    if p.is_null() {
        libc::dlopen
    } else {
        let f: unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> *mut c_void = unsafe { std::mem::transmute(p) };
        f
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader64;
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachHeader64 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[cfg(target_os = "macos")]
fn rebind_image(header: *const MachHeader64, slide: isize) -> u32 {
    if header.is_null() || unsafe { (*header).magic } != 0xfeedfacf {
        return 0;
    }
    let ncmds = unsafe { (*header).ncmds };
    let mut cmd = unsafe { header.add(1) as *const u8 };
    let mut symoff = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut strsize = 0u32;
    let mut indirectoff = 0u32;
    let mut linkedit_vmaddr = 0u64;
    let mut linkedit_fileoff = 0u64;
    let mut have_linkedit = false;
    let mut sections: Vec<(u64, u64, u32)> = Vec::new();
    unsafe {
        for _ in 0..ncmds {
            let cmd_id = (cmd as *const u32).read_unaligned();
            let cmdsize = (cmd.add(4) as *const u32).read_unaligned();
            if cmdsize < 8 {
                return 0;
            }
            if cmd_id == 0x2 && cmdsize >= 24 {
                symoff = (cmd.add(8) as *const u32).read_unaligned();
                nsyms = (cmd.add(12) as *const u32).read_unaligned();
                stroff = (cmd.add(16) as *const u32).read_unaligned();
                strsize = (cmd.add(20) as *const u32).read_unaligned();
            } else if cmd_id == 0xb && cmdsize >= 64 {
                indirectoff = (cmd.add(56) as *const u32).read_unaligned();
            } else if cmd_id == 0x19 && cmdsize >= 72 {
                let name = std::slice::from_raw_parts(cmd.add(8), 16);
                let vmaddr = (cmd.add(24) as *const u64).read_unaligned();
                let fileoff = (cmd.add(40) as *const u64).read_unaligned();
                let nsects = (cmd.add(64) as *const u32).read_unaligned();
                if name.starts_with(b"__LINKEDIT") {
                    linkedit_vmaddr = vmaddr;
                    linkedit_fileoff = fileoff;
                    have_linkedit = true;
                }
                let mut sect = cmd.add(72);
                for _ in 0..nsects {
                    if sect.add(80) > cmd.add(cmdsize as usize) {
                        break;
                    }
                    let flags = (sect.add(64) as *const u32).read_unaligned();
                    let kind = flags & 0xff;
                    if kind == 0x6 || kind == 0x7 {
                        let addr = (sect.add(32) as *const u64).read_unaligned();
                        let size = (sect.add(40) as *const u64).read_unaligned();
                        let reserved1 = (sect.add(68) as *const u32).read_unaligned();
                        sections.push((addr, size, reserved1));
                    }
                    sect = sect.add(80);
                }
            }
            cmd = cmd.add(cmdsize as usize);
        }
    }
    if !have_linkedit || nsyms == 0 || strsize == 0 {
        return 0;
    }
    let base = (slide as u64).wrapping_add(linkedit_vmaddr).wrapping_sub(linkedit_fileoff);
    let strtab = base.wrapping_add(stroff as u64) as *const u8;
    let syms = base.wrapping_add(symoff as u64) as *const u8;
    let indirect = base.wrapping_add(indirectoff as u64) as *const u32;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
    let mut patched = 0u32;
    for (addr, size, reserved1) in sections {
        let count = (size / 8) as u32;
        for i in 0..count {
            let sym_index = unsafe { indirect.add((reserved1 + i) as usize).read() };
            if sym_index & 0x80000000 != 0 || sym_index & 0x40000000 != 0 || sym_index >= nsyms {
                continue;
            }
            // nlist_64: n_strx at offset 0.
            let strx = unsafe { (syms.add(sym_index as usize * 16) as *const u32).read() };
            if strx >= strsize || strsize - strx < 8 {
                continue;
            }
            let symname = unsafe { std::slice::from_raw_parts(strtab.add(strx as usize), 8) };
            if symname != b"_dlopen\0" {
                continue;
            }
            let hook = hooked_dlopen as *const () as *mut c_void;
            let slot = (slide as usize).wrapping_add(addr as usize).wrapping_add(i as usize * 8) as *mut *mut c_void;
            unsafe {
                let page_start = (slot as usize) & !(page - 1);
                libc::mprotect(page_start as *mut c_void, page, libc::PROT_READ | libc::PROT_WRITE);
                if *slot != hook {
                    *slot = hook;
                    patched += 1;
                }
            }
        }
    }
    patched
}
