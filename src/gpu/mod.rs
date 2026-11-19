//! The GPU behind zeroemu's virtio-gpu device: an interface the kernel's
//! DRM driver (src/kernel/drm) calls, implemented on the host by Google's
//! gfxstream renderer, the one the Android Emulator itself uses, loaded from
//! the installed emulator (libgfxstream_backend.dylib / gfxstream_backend.dll).
//!
//! The methods mirror gfxstream's `stream_renderer_*` C API (the virtio-gpu
//! backend interface crosvm and QEMU call) one to one, so the kernel side
//! speaks virtio-gpu semantics and stays independent of the host OS.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod controls;
pub(crate) mod fake;
mod gfxstream;
#[cfg(target_os = "macos")]
mod window_macos;
#[cfg(windows)]
mod window_windows;
#[cfg(target_os = "macos")]
use window_macos as window;
#[cfg(windows)]
use window_windows as window;

/// Writes the frame the window is showing to a BMP file, for tests: what Android
/// sent, with no window system in between.
#[cfg(any(target_os = "macos", windows))]
pub fn save_shown_frame(path: &str) -> std::io::Result<()> {
    let Some((w, h, pixels)) = window::shown_frame() else {
        return Err(std::io::Error::other("no frame yet"));
    };
    let size = pixels.len() as u32;
    let mut bmp = Vec::with_capacity(54 + pixels.len());
    bmp.extend_from_slice(b"BM");
    for v in [54 + size, 0, 54, 40, w] {
        bmp.extend_from_slice(&v.to_le_bytes());
    }
    bmp.extend_from_slice(&h.to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
    bmp.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    for v in [0, size, 2835, 2835, 0, 0u32] {
        bmp.extend_from_slice(&v.to_le_bytes());
    }
    // BMP rows go from the bottom up.
    for row in pixels.chunks_exact(w as usize * 4).rev() {
        bmp.extend_from_slice(row);
    }
    std::fs::write(path, bmp)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn save_shown_frame(_path: &str) -> std::io::Result<()> {
    Err(std::io::Error::other("no window on this host"))
}

/// Resizes the window's content to `w` x `h` points, as a user dragging its edge
/// would (for tests: ZEROEMU_INPUT_FIFO's `resize`).
pub fn resize_window(w: f64, h: f64) {
    #[cfg(target_os = "macos")]
    window::resize(w, h);
    #[cfg(not(target_os = "macos"))]
    let _ = (w, h);
}

/// `f` runs when the user closes the window or quits. It is called on the UI thread,
/// or on the caller's if the user quit before this was called.
pub fn on_window_closed(f: Box<dyn Fn() + Send + Sync>) {
    #[cfg(target_os = "macos")]
    window::on_closed(f);
    #[cfg(not(target_os = "macos"))]
    drop(f);
}

/// zeroemu.app couldn't run Android, or Android stopped: says why in an alert, as there
/// is no terminal to, and offers to show the log. Main thread. Not for tests run behind
/// someone's work (ZEROEMU_BACKGROUND).
pub fn alert_failure(title: &str, why: &str, log: Option<&std::path::Path>) {
    #[cfg(target_os = "macos")]
    if !window::background() && window::alert(title, why, log.is_some()) && let Some(log) = log {
        window::open_file(log);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (title, why, log);
}

/// zeroemu.app panicked, on whatever thread: says so before it exits, as it would
/// otherwise just vanish. The first panic's thread shows the alert; another's waits
/// for that one to exit.
pub fn alert_crash(log: Option<&std::path::Path>) {
    #[cfg(target_os = "macos")]
    {
        static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if window::background() {
            return;
        }
        if SHOWN.swap(true, std::sync::atomic::Ordering::SeqCst) {
            loop {
                std::thread::park();
            }
        }
        let text = "A bug in zeroemu stopped it, and /data wasn't saved: what changed since this boot started is lost. \
                    The log says where the bug is; a report at github.com/zeroemu/zeroemu/issues with it helps.";
        if window::alert_any_thread("zeroemu stopped", text, log.is_some()) && let Some(log) = log {
            window::open_file(log);
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = log;
}

/// The device was turned (controls::turns): the window shows it so.
fn turned() {
    #[cfg(target_os = "macos")]
    window::turned();
}

/// Saves the screen, turned upright for a device turned `turns` times, as a PNG where
/// the Mac keeps screenshots. Returns where.
#[cfg(target_os = "macos")]
fn save_screenshot(turns: u8) -> std::io::Result<std::path::PathBuf> {
    let Some((w, h, pixels)) = window::shown_frame() else {
        return Err(std::io::Error::other("there's nothing on the screen yet"));
    };
    let (w, h, pixels) = controls::rotate_pixels(w, h, &pixels, turns);
    // ZEROEMU_SCREENSHOTS=<dir>: somewhere else, for tests.
    let folder = std::env::var_os("ZEROEMU_SCREENSHOTS").map(std::path::PathBuf::from).unwrap_or_else(window::screenshot_folder);
    // As the Mac names its own, so they sort among them: "... 2026-11-19 at 10.15.32".
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    unsafe { libc::localtime_r(&now, &mut t) };
    let stamp = format!("{}-{:02}-{:02} at {:02}.{:02}.{:02}", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    // One at a time from naming to renaming: two in the same second get two names.
    static SAVING: Mutex<()> = Mutex::new(());
    let _one = SAVING.lock().unwrap_or_else(|p| p.into_inner());
    let mut path = folder.join(format!("zeroemu Screenshot {stamp}.png"));
    for n in 2.. {
        if !path.exists() {
            break;
        }
        path = folder.join(format!("zeroemu Screenshot {stamp} ({n}).png"));
    }
    // Under another name until it's whole, so nothing picks up half a file.
    let partial = folder.join(format!(".{}.partial", path.file_name().unwrap().to_string_lossy()));
    let saved = window::write_png(&partial, w, h, &pixels).and_then(|()| std::fs::rename(&partial, &path));
    if saved.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    saved?;
    // Not for tests run behind someone's work (ZEROEMU_BACKGROUND).
    if !window::background() {
        window::shutter_sound();
    }
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
fn save_screenshot(_turns: u8) -> std::io::Result<std::path::PathBuf> {
    Err(std::io::Error::other("screenshots need the macOS window"))
}

/// A test FIFO line for the device controls (ZEROEMU_INPUT_FIFO, src/kernel/evdev.rs):
/// `action NAME` does what a toolbar item or Device menu item does
/// (controls::Action::name); `menu Menu/Item` chooses a menu item by its titles;
/// `toolbar NAME` clicks a toolbar item; `keyeq MODS KEYCODE CHARS` types a key with
/// modifiers into the window, for its shortcut; `click U V` clicks the shown picture.
pub fn control_line(line: &str) {
    let line = line.trim();
    let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();
    match word {
        "action" => match controls::Action::from_name(rest) {
            Some(a) => controls::perform(a),
            None => eprintln!("zeroemu: no action {rest:?}"),
        },
        #[cfg(target_os = "macos")]
        "menu" => window::choose_menu_item(rest),
        #[cfg(target_os = "macos")]
        "toolbar" => window::click_toolbar_item(rest),
        #[cfg(target_os = "macos")]
        "click" => {
            let mut w = rest.split_whitespace().map(|n| n.parse::<f64>());
            match (w.next(), w.next()) {
                (Some(Ok(u)), Some(Ok(v))) => window::post_click(u, v),
                _ => eprintln!("zeroemu: click wants U V, not {rest:?}"),
            }
        }
        #[cfg(target_os = "macos")]
        "keyeq" => {
            let mut w = rest.split_whitespace();
            match (w.next(), w.next().and_then(|k| k.parse().ok()), w.next()) {
                (Some(mods), Some(code), Some(chars)) => window::post_key(mods, code, chars),
                _ => eprintln!("zeroemu: keyeq wants MODS KEYCODE CHARS, not {rest:?}"),
            }
        }
        _ => eprintln!("zeroemu: {word} needs the macOS window"),
    }
}

/// virtio-gpu capability set ids.
pub const CAPSET_VIRGL: u32 = 1;
pub const CAPSET_VIRGL2: u32 = 2;
pub const CAPSET_GFXSTREAM_VULKAN: u32 = 3;
pub const CAPSET_GFXSTREAM_GLES: u32 = 8;
pub const CAPSET_GFXSTREAM_COMPOSER: u32 = 9;

/// virtio-gpu blob memory types and flags.
pub const BLOB_MEM_GUEST: u32 = 1;
pub const BLOB_MEM_HOST3D: u32 = 2;
pub const BLOB_MEM_HOST3D_GUEST: u32 = 3;
pub const BLOB_FLAG_USE_MAPPABLE: u32 = 1;
pub const BLOB_FLAG_USE_SHAREABLE: u32 = 2;
pub const BLOB_FLAG_USE_CROSS_DEVICE: u32 = 4;

/// `struct stream_renderer_resource_create_args` (virtio_gpu_resource_create_3d).
#[derive(Clone, Copy, Debug, Default)]
pub struct Resource3d {
    pub handle: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub nr_samples: u32,
    pub flags: u32,
}

/// `struct stream_renderer_box`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Box3 {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

/// A transfer between a resource and its guest backing (`transfer_*_iov`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Transfer {
    pub ctx_id: u32,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
    pub bx: Box3,
    pub offset: u64,
}

/// `struct stream_renderer_create_blob`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blob {
    pub blob_mem: u32,
    pub blob_flags: u32,
    pub blob_id: u64,
    pub size: u64,
}

/// `struct stream_renderer_resource_info`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResourceInfo {
    pub virgl_format: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub flags: u32,
    pub stride: u32,
    pub drm_fourcc: u32,
}

/// A fence the renderer signals once the commands before it complete
/// (`struct stream_renderer_fence`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fence {
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
}

/// Host memory the guest sees as a resource's backing: guest RAM pages,
/// given as host addresses (stable for the resource's lifetime).
pub type Iov = Vec<(*mut u8, usize)>;

/// Errors are Linux errnos, as everywhere in the kernel.
pub trait GpuBackend: Send + Sync {
    /// (max_version, size) of a capability set, None if unsupported.
    fn capset_info(&self, id: u32) -> Option<(u32, u32)>;
    fn capset(&self, id: u32, version: u32) -> Vec<u8>;

    fn context_create(&self, ctx_id: u32, name: &str, context_init: u32) -> Result<(), i64>;
    fn context_destroy(&self, ctx_id: u32);
    /// One execbuffer's command stream; `in_fences` are fence ids the
    /// commands wait for.
    fn submit(&self, ctx_id: u32, cmds: &[u8], in_fences: &[u64]) -> Result<(), i64>;
    fn create_fence(&self, fence: Fence) -> Result<(), i64>;

    /// Creates a resource backed by `iov` and, unless `ctx_id` is 0, attaches it to that
    /// context, in one call: the kernel does both for every buffer it creates.
    fn resource_create(&self, args: &Resource3d, iov: Iov, ctx_id: u32) -> Result<(), i64>;
    /// Submits `cmd` to the context first when there is one (gfxstream's guest describes
    /// the blob it is about to create that way), then creates the blob, backs it with
    /// `iov`, and attaches it to the context unless `ctx_id` is 0.
    fn resource_create_blob(&self, ctx_id: u32, handle: u32, blob: &Blob, iov: Iov, cmd: &[u8]) -> Result<(), i64>;
    /// Frees a resource, unmapping its host memory first when it was mapped (`unmap`)
    /// and detaching its guest backing when it has one (`detach`).
    fn resource_unref(&self, handle: u32, unmap: bool, detach: bool);
    fn attach_iov(&self, handle: u32, iov: Iov) -> Result<(), i64>;
    fn detach_iov(&self, handle: u32);
    fn ctx_attach_resource(&self, ctx_id: u32, handle: u32);
    fn ctx_detach_resource(&self, ctx_id: u32, handle: u32);
    fn transfer_write(&self, handle: u32, t: &Transfer) -> Result<(), i64>;
    fn transfer_read(&self, handle: u32, t: &Transfer) -> Result<(), i64>;
    fn resource_info(&self, handle: u32) -> Option<ResourceInfo>;

    /// Host memory of a mappable blob: (address, size). The kernel maps it
    /// into the guest; it stays valid until `resource_unmap`.
    fn resource_map(&self, handle: u32) -> Result<(*mut u8, u64), i64>;
    fn resource_unmap(&self, handle: u32);
    /// VIRTIO_GPU_MAP_CACHE_* for a mapped blob.
    fn map_info(&self, handle: u32) -> Option<u32>;

    /// Shows a resource on the display (a scanout update or page flip).
    fn flush(&self, handle: u32);
    /// Debugging: a resource's current pixels as the host renderer sees them.
    fn read_pixels(&self, _handle: u32) -> Option<(u32, u32, Vec<u8>)> {
        None
    }
    /// Where completed fences go; set once, before any submission.
    fn set_fence_handler(&self, handler: Arc<dyn Fn(Fence) + Send + Sync>);
}

/// Load gfxstream and show a window of `width` x `height` guest pixels.
/// Must run on the main thread.
pub fn open(width: u32, height: u32) -> Result<Arc<dyn GpuBackend>, String> {
    gfxstream::open(width, height)
}

/// In-memory backend (`ZEROEMU_GPU=fake`): no renderer, no window.
pub fn fake() -> Arc<dyn GpuBackend> {
    fake::Fake::new()
}

/// Block the main thread in the native event loop until `done` is set.
pub fn pump_until(done: &AtomicBool) {
    window::pump_until(done);
}

pub fn pump_for(secs: f64) {
    window::pump_for(secs);
}

const FB_W: u32 = 1080;
const FB_H: u32 = 2400;
const PIPE_TEXTURE_2D: u32 = 2;
const VIRGL_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const BIND_RENDER_TARGET: u32 = 1 << 1;
const BIND_SCANOUT: u32 = 1 << 18;

/// Opens the renderer and window, uploads a colored 1080x2400 scanout, and
/// holds it on screen. Exit status is 0 when that path succeeds.
pub fn selftest() -> Result<i32, String> {
    let gpu = open(FB_W, FB_H)?;
    let main_tok = thread_token();
    let cb_tok = Arc::new(AtomicU64::new(0));
    let cb = cb_tok.clone();
    gpu.set_fence_handler(Arc::new(move |f| {
        cb.store(thread_token(), Ordering::Relaxed);
        eprintln!("zeroemu: fence {} ctx {} flags {:#x} ring {}", f.fence_id, f.ctx_id, f.flags, f.ring_idx);
    }));
    // The guest calls these from a vCPU thread. The present is bounced onto
    // this thread through the window ops, so pump while the worker runs.
    let slot: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));
    let slot2 = slot.clone();
    let gpu2 = gpu.clone();
    let drawn = Arc::new(AtomicBool::new(false));
    let drawn2 = drawn.clone();
    std::thread::spawn(move || {
        let worker = thread_token();
        let r = exercise(&*gpu2).map(|s| format!("worker-thread {worker}\n{s}"));
        *slot2.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
        drawn2.store(true, Ordering::Release);
    });
    let start = Instant::now();
    while !drawn.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(30) {
        pump_for(0.05);
    }
    pump_for(3.0);
    screenshot();
    let report = slot.lock().unwrap_or_else(|p| p.into_inner()).take().unwrap_or_else(|| Err("gpu selftest thread failed".into()))?;
    eprintln!("zeroemu: main-thread {main_tok}");
    eprintln!("zeroemu: fence-callback-thread {}", cb_tok.load(Ordering::Relaxed));
    eprintln!("{report}");
    Ok(0)
}

fn thread_token() -> u64 {
    thread_local! {
        static TOKEN: u64 = {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            NEXT.fetch_add(1, Ordering::Relaxed)
        };
    }
    TOKEN.with(|t| *t)
}

fn exercise(gpu: &dyn GpuBackend) -> Result<String, String> {
    let mut lines = Vec::new();
    for id in [CAPSET_GFXSTREAM_VULKAN, CAPSET_GFXSTREAM_GLES, CAPSET_GFXSTREAM_COMPOSER] {
        match gpu.capset_info(id) {
            Some((ver, size)) => {
                let caps = gpu.capset(id, ver);
                let align = caps.get(12..16).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
                lines.push(format!("capset {id}: version {ver} size {size} blob_align {align}"));
            }
            None => lines.push(format!("capset {id}: unsupported")),
        }
    }
    let mut pixels = vec![0u8; (FB_W as usize) * (FB_H as usize) * 4];
    fill_pattern(&mut pixels, FB_W, FB_H);
    let iov: Iov = vec![(pixels.as_mut_ptr(), pixels.len())];
    let args = Resource3d {
        handle: 1,
        target: PIPE_TEXTURE_2D,
        format: VIRGL_FORMAT_B8G8R8A8_UNORM,
        bind: BIND_RENDER_TARGET | BIND_SCANOUT,
        width: FB_W,
        height: FB_H,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: 0,
    };
    gpu.resource_create(&args, iov, 0).map_err(|e| format!("resource_create errno {e}"))?;
    if let Some(info) = gpu.resource_info(1) {
        lines.push(format!(
            "resource info format {} {}x{} stride {} fourcc {:#x}",
            info.virgl_format, info.width, info.height, info.stride, info.drm_fourcc
        ));
    }
    let transfer = Transfer {
        ctx_id: 0,
        level: 0,
        stride: FB_W * 4,
        layer_stride: 0,
        bx: Box3 { x: 0, y: 0, z: 0, w: FB_W, h: FB_H, d: 1 },
        offset: 0,
    };
    gpu.transfer_write(1, &transfer).map_err(|e| format!("transfer_write errno {e}"))?;
    gpu.flush(1);
    // A global-ring fence. The callback's thread is the renderer's, not ours,
    // unless the ring is empty and the timeline completes inline.
    gpu.create_fence(Fence { flags: 0, fence_id: 1, ctx_id: 0, ring_idx: 0 }).map_err(|e| format!("create_fence errno {e}"))?;
    lines.push(probe_blob(gpu));
    Ok(lines.join("\n"))
}

fn probe_blob(gpu: &dyn GpuBackend) -> String {
    if let Err(e) = gpu.context_create(1, "zeroemu", 0) {
        return format!("blob: context_create errno {e}");
    }
    let blob = Blob { blob_mem: BLOB_MEM_HOST3D, blob_flags: BLOB_FLAG_USE_MAPPABLE, blob_id: 0, size: 65536 };
    if let Err(e) = gpu.resource_create_blob(1, 2, &blob, Vec::new(), &[]) {
        return format!("blob: create errno {e}");
    }
    match gpu.resource_map(2) {
        Ok((ptr, size)) => {
            let addr = ptr as usize;
            format!(
                "blob map {ptr:?} size {size} align4k {} align16k {}",
                addr & (4096 - 1) == 0,
                addr & (16384 - 1) == 0
            )
        }
        Err(e) => format!("blob: map errno {e}"),
    }
}

/// BGRA bands: red, green, blue, white, with a yellow strip down the left.
fn fill_pattern(pixels: &mut [u8], w: u32, h: u32) {
    for y in 0..h {
        let band = y * 4 / h;
        let (b, g, r) = match band {
            0 => (0u8, 0, 255),
            1 => (0, 255, 0),
            2 => (255, 0, 0),
            _ => (255, 255, 255),
        };
        for x in 0..w {
            let (b, g, r) = if x < 80 { (0u8, 255, 255) } else { (b, g, r) };
            let i = ((y * w + x) * 4) as usize;
            pixels[i] = b;
            pixels[i + 1] = g;
            pixels[i + 2] = r;
            pixels[i + 3] = 255;
        }
    }
}

fn screenshot() {
    #[cfg(target_os = "macos")]
    {
        let Some(id) = window::window_id() else {
            eprintln!("zeroemu: no window id for screencapture");
            return;
        };
        let path = "/tmp/zeroemu-gpu-selftest.png";
        match std::process::Command::new("screencapture").args(["-l", &id.to_string(), "-o", "-x", path]).status() {
            Ok(s) if s.success() => eprintln!("zeroemu: wrote {path}"),
            Ok(s) => eprintln!("zeroemu: screencapture exited {s}"),
            Err(e) => eprintln!("zeroemu: screencapture: {e}"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("zeroemu: screencapture is macOS-only");
    }
}
