//! The GPU behind droidrt's virtio-gpu device: an interface the kernel's
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

mod gfxstream;
#[cfg(target_os = "macos")]
mod window_macos;
#[cfg(windows)]
mod window_windows;
#[cfg(target_os = "macos")]
use window_macos as window;
#[cfg(windows)]
use window_windows as window;

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

    fn resource_create(&self, args: &Resource3d, iov: Iov) -> Result<(), i64>;
    fn resource_create_blob(&self, ctx_id: u32, handle: u32, blob: &Blob, iov: Iov) -> Result<(), i64>;
    fn resource_unref(&self, handle: u32);
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
    /// Where completed fences go; set once, before any submission.
    fn set_fence_handler(&self, handler: Arc<dyn Fn(Fence) + Send + Sync>);
}

/// Load gfxstream and show a window of `width` x `height` guest pixels.
/// Must run on the main thread.
pub fn open(width: u32, height: u32) -> Result<Arc<dyn GpuBackend>, String> {
    gfxstream::open(width, height)
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
        eprintln!("droidrt: fence {} ctx {} flags {:#x} ring {}", f.fence_id, f.ctx_id, f.flags, f.ring_idx);
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
    eprintln!("droidrt: main-thread {main_tok}");
    eprintln!("droidrt: fence-callback-thread {}", cb_tok.load(Ordering::Relaxed));
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
    gpu.resource_create(&args, iov).map_err(|e| format!("resource_create errno {e}"))?;
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
    if let Err(e) = gpu.context_create(1, "droidrt", 0) {
        return format!("blob: context_create errno {e}");
    }
    let blob = Blob { blob_mem: BLOB_MEM_HOST3D, blob_flags: BLOB_FLAG_USE_MAPPABLE, blob_id: 0, size: 65536 };
    if let Err(e) = gpu.resource_create_blob(1, 2, &blob, Vec::new()) {
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
            eprintln!("droidrt: no window id for screencapture");
            return;
        };
        let path = "/tmp/droidrt-gpu-selftest.png";
        match std::process::Command::new("screencapture").args(["-l", &id.to_string(), "-o", "-x", path]).status() {
            Ok(s) if s.success() => eprintln!("droidrt: wrote {path}"),
            Ok(s) => eprintln!("droidrt: screencapture exited {s}"),
            Err(e) => eprintln!("droidrt: screencapture: {e}"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("droidrt: screencapture is macOS-only");
    }
}
