//! The GPU behind droidrt's virtio-gpu device: an interface the kernel's
//! DRM driver (src/kernel/drm) calls, implemented on the host by Google's
//! gfxstream renderer, the one the Android Emulator itself uses, loaded from
//! the installed emulator (libgfxstream_backend.dylib / gfxstream_backend.dll).
//!
//! The methods mirror gfxstream's `stream_renderer_*` C API (the virtio-gpu
//! backend interface crosvm and QEMU call) one to one, so the kernel side
//! speaks virtio-gpu semantics and stays independent of the host OS.

use std::sync::Arc;

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
