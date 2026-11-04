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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

// This build's get_cap_set wrapper discards max_ver and only writes max_size
// (VirtioGpuFrontend::getCapset). create_blob's wrapper ignores its iov and
// always returns 0. resource_detach_iov only reads the handle.
// Confirmed against libgfxstream_backend.dylib (emulator 37.1.11) and the
// upstream header: the wrappers shift x0.. into the C++ method and drop the
// rest.

const PARAM_USER_DATA: u64 = 1;
const PARAM_RENDERER_FLAGS: u64 = 2;
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
type FnSetup = unsafe extern "C" fn(*mut c_void, i32, i32, i32, i32, i32, i32);
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
    setup_window: FnSetup,
    teardown: FnTeardown,
}

struct FenceSlot {
    handler: Option<Arc<dyn Fn(Fence) + Send + Sync>>,
    pending: Vec<Fence>,
}

pub struct Gfxstream {
    api: Api,
    live: Mutex<bool>,
    fences: Mutex<FenceSlot>,
    // Kept mapped for the process lifetime. dlclose races the renderer's threads.
    _lib: *mut c_void,
}

unsafe impl Send for Gfxstream {}
unsafe impl Sync for Gfxstream {}

fn log_max_from_env() -> u32 {
    match std::env::var("DROIDRT_GPU_LOG").ok().as_deref() {
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
    eprintln!("gfxstream: {msg}");
}

extern "C" fn on_fence(user: *mut c_void, fence: *const CFence) {
    if user.is_null() || fence.is_null() {
        return;
    }
    let g = unsafe { &*(user as *const Gfxstream) };
    let f = unsafe { &*fence };
    let fence = Fence { flags: f.flags, fence_id: f.fence_id, ctx_id: f.ctx_id, ring_idx: f.ring_idx };
    let handler = {
        let mut slot = g.fences.lock().unwrap_or_else(|p| p.into_inner());
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
    let win = window::open(width, height)?;
    let lib = load_backend(&backend_path()?)?;
    let api = load_api(lib)?;
    let gfx = Arc::new(Gfxstream {
        api,
        live: Mutex::new(false),
        fences: Mutex::new(FenceSlot { handler: None, pending: Vec::new() }),
        _lib: lib,
    });
    gfx.start(width, height, &win)?;
    Ok(gfx)
}

impl Gfxstream {
    fn start(self: &Arc<Self>, fb_w: u32, fb_h: u32, win: &NativeWindow) -> Result<(), String> {
        LOG_MAX.store(log_max_from_env(), Ordering::Relaxed);
        let user = Arc::as_ptr(self) as usize as u64;
        let mut params = [
            Param { key: PARAM_USER_DATA, value: user },
            Param { key: PARAM_RENDERER_FLAGS, value: RENDERER_FLAGS },
            Param { key: PARAM_FENCE_CALLBACK, value: on_fence as *const () as usize as u64 },
            Param { key: PARAM_WIN0_WIDTH, value: fb_w as u64 },
            Param { key: PARAM_WIN0_HEIGHT, value: fb_h as u64 },
            Param { key: PARAM_DEBUG_CALLBACK, value: on_debug as *const () as usize as u64 },
        ];
        let r = unsafe { (self.api.init)(params.as_mut_ptr(), params.len() as u64) };
        if r != 0 {
            return Err(format!("stream_renderer_init returned {r}"));
        }
        *self.live.lock().unwrap_or_else(|p| p.into_inner()) = true;
        // native handle is an NSView* on macOS and an HWND on Windows.
        unsafe {
            (self.api.setup_window)(win.handle, 0, 0, win.width, win.height, fb_w as i32, fb_h as i32);
        }
        Ok(())
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
        if live {
            unsafe { (self.api.teardown)() };
        }
    }
}

impl GpuBackend for Gfxstream {
    fn capset_info(&self, id: u32) -> Option<(u32, u32)> {
        let mut ver = 0u32;
        let mut size = 0u32;
        unsafe { (self.api.get_cap_set)(id, &mut ver, &mut size) };
        if size == 0 { None } else { Some((ver, size)) }
    }

    fn capset(&self, id: u32, version: u32) -> Vec<u8> {
        let Some((_, size)) = self.capset_info(id) else { return Vec::new() };
        let mut buf = vec![0u8; size as usize];
        unsafe { (self.api.fill_caps)(id, version, buf.as_mut_ptr() as *mut c_void) };
        buf
    }

    fn context_create(&self, ctx_id: u32, name: &str, context_init: u32) -> Result<(), i64> {
        let c = CString::new(name).map_err(|_| 22i64)?;
        ck(unsafe { (self.api.context_create)(ctx_id, c.as_bytes().len() as u32, c.as_ptr(), context_init) })
    }

    fn context_destroy(&self, ctx_id: u32) {
        unsafe { (self.api.context_destroy)(ctx_id) };
    }

    fn submit(&self, ctx_id: u32, cmds: &[u8], in_fences: &[u64]) -> Result<(), i64> {
        let mut cmd = CCommand {
            ctx_id,
            cmd_size: cmds.len() as u32,
            cmd: cmds.as_ptr() as *mut u8,
            num_in_fences: in_fences.len() as u32,
            in_fences: if in_fences.is_empty() { std::ptr::null() } else { in_fences.as_ptr() },
        };
        ck(unsafe { (self.api.submit_cmd)(&mut cmd) })
    }

    fn create_fence(&self, fence: Fence) -> Result<(), i64> {
        let c = CFence { flags: fence.flags, fence_id: fence.fence_id, ctx_id: fence.ctx_id, ring_idx: fence.ring_idx };
        ck(unsafe { (self.api.create_fence)(&c) })
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
        ck(unsafe { (self.api.resource_create)(&c, ptr, buf.len() as u32) })
    }

    fn resource_create_blob(&self, ctx_id: u32, handle: u32, blob: &Blob, iov: Iov) -> Result<(), i64> {
        let c = CBlob { blob_mem: blob.blob_mem, blob_flags: blob.blob_flags, blob_id: blob.blob_id, size: blob.size };
        let buf = iov_buf(&iov);
        let ptr = if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() };
        ck(unsafe { (self.api.create_blob)(ctx_id, handle, &c, ptr, buf.len() as u32, std::ptr::null()) })
    }

    fn resource_unref(&self, handle: u32) {
        unsafe { (self.api.resource_unref)(handle) };
    }

    fn attach_iov(&self, handle: u32, iov: Iov) -> Result<(), i64> {
        let buf = iov_buf(&iov);
        let ptr = if buf.is_empty() { std::ptr::null() } else { buf.as_ptr() };
        ck(unsafe { (self.api.attach_iov)(handle as i32, ptr, buf.len() as i32) })
    }

    fn detach_iov(&self, handle: u32) {
        unsafe { (self.api.detach_iov)(handle as i32) };
    }

    fn ctx_attach_resource(&self, ctx_id: u32, handle: u32) {
        unsafe { (self.api.ctx_attach)(ctx_id as i32, handle as i32) };
    }

    fn ctx_detach_resource(&self, ctx_id: u32, handle: u32) {
        unsafe { (self.api.ctx_detach)(ctx_id as i32, handle as i32) };
    }

    fn transfer_write(&self, handle: u32, t: &Transfer) -> Result<(), i64> {
        self.xfer(self.api.transfer_write, handle, t)
    }

    fn transfer_read(&self, handle: u32, t: &Transfer) -> Result<(), i64> {
        self.xfer(self.api.transfer_read, handle, t)
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
        let r = unsafe { (self.api.get_info)(handle as i32, &mut info) };
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
        ck(unsafe { (self.api.resource_map)(handle, &mut ptr, &mut size) })?;
        Ok((ptr as *mut u8, size))
    }

    fn resource_unmap(&self, handle: u32) {
        unsafe { (self.api.resource_unmap)(handle) };
    }

    fn map_info(&self, handle: u32) -> Option<u32> {
        let mut info = 0u32;
        let r = unsafe { (self.api.map_info)(handle, &mut info) };
        if r == 0 { Some(info) } else { None }
    }

    fn flush(&self, handle: u32) {
        unsafe { (self.api.flush)(handle) };
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
    fn xfer(&self, f: FnXfer, handle: u32, t: &Transfer) -> Result<(), i64> {
        // Null iov: the renderer uses the iovec attached to the resource.
        let b = c_box(&t.bx);
        ck(unsafe { f(handle, t.ctx_id, t.level, t.stride, t.layer_stride, &b, t.offset, std::ptr::null(), 0) })
    }
}

fn backend_path() -> Result<std::path::PathBuf, String> {
    if let Ok(p) = std::env::var("DROIDRT_GFXSTREAM") {
        return Ok(std::path::PathBuf::from(p));
    }
    let name = if cfg!(windows) { "gfxstream_backend.dll" } else { "libgfxstream_backend.dylib" };
    if let Some(root) = std::env::var("ANDROID_SDK_ROOT").ok().or_else(|| std::env::var("ANDROID_HOME").ok()) {
        return Ok(std::path::PathBuf::from(root).join("emulator").join("lib64").join(name));
    }
    default_sdk(name)
}

#[cfg(target_os = "macos")]
fn default_sdk(name: &str) -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is unset".to_string())?;
    Ok(std::path::PathBuf::from(home).join("Library/Android/sdk/emulator/lib64").join(name))
}

#[cfg(windows)]
fn default_sdk(name: &str) -> Result<std::path::PathBuf, String> {
    let local = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is unset".to_string())?;
    Ok(std::path::PathBuf::from(local).join("Android/Sdk/emulator/lib64").join(name))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn default_sdk(_name: &str) -> Result<std::path::PathBuf, String> {
    Err("gfxstream: no emulator library path".into())
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
        setup_window: lookup(lib, "gfxstream_backend_setup_window")?,
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
