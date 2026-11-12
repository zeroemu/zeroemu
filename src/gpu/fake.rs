//! A virtio-gpu backend with no renderer. `ZEROEMU_GPU=fake` (and the drm
//! unit tests) use it so guest ioctl tests run headless. Host blobs are
//! ordinary 16 KiB-aligned allocations; fences complete inline.

use super::{Blob, Fence, GpuBackend, Iov, Resource3d, ResourceInfo, Transfer, BLOB_FLAG_USE_MAPPABLE, BLOB_MEM_GUEST, BLOB_MEM_HOST3D, BLOB_MEM_HOST3D_GUEST, CAPSET_GFXSTREAM_COMPOSER, CAPSET_GFXSTREAM_GLES, CAPSET_GFXSTREAM_VULKAN, CAPSET_VIRGL, CAPSET_VIRGL2};
use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct HostBuf {
    ptr: *mut u8,
    layout: Layout,
}

// The allocation outlives every resource_map pointer handed to the kernel.
unsafe impl Send for HostBuf {}
unsafe impl Sync for HostBuf {}

impl Drop for HostBuf {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

struct Res {
    info: ResourceInfo,
    host: Option<HostBuf>,
    size: u64,
}

struct State {
    res: HashMap<u32, Res>,
    ctx: HashMap<u32, u32>,
    handler: Option<Arc<dyn Fn(Fence) + Send + Sync>>,
    pub flushed: Vec<u32>,
}

pub struct Fake {
    st: Mutex<State>,
}

impl Fake {
    pub fn new() -> Arc<Fake> {
        Arc::new(Fake {
            st: Mutex::new(State { res: HashMap::new(), ctx: HashMap::new(), handler: None, flushed: Vec::new() }),
        })
    }

    #[cfg(test)]
    pub fn flushed(&self) -> Vec<u32> {
        self.st.lock().unwrap().flushed.clone()
    }
}

fn host_buf(size: u64) -> Result<HostBuf, i64> {
    let align = 16 << 10;
    let bytes = size.max(1).div_ceil(align) * align;
    let layout = Layout::from_size_align(bytes as usize, align as usize).map_err(|_| 12i64)?;
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return Err(12);
    }
    unsafe { ptr.write_bytes(0, bytes as usize) };
    Ok(HostBuf { ptr, layout })
}

impl GpuBackend for Fake {
    fn capset_info(&self, id: u32) -> Option<(u32, u32)> {
        match id {
            CAPSET_VIRGL | CAPSET_VIRGL2 => Some((1, 64)),
            CAPSET_GFXSTREAM_VULKAN => Some((1, 112)),
            CAPSET_GFXSTREAM_GLES | CAPSET_GFXSTREAM_COMPOSER => Some((1, 16)),
            _ => None,
        }
    }

    fn capset(&self, id: u32, _version: u32) -> Vec<u8> {
        let Some((_, n)) = self.capset_info(id) else { return Vec::new() };
        let mut v = vec![0u8; n as usize];
        // gfxstream puts blobAlignment at bytes 12..16 of the GLES/composer capsets.
        if matches!(id, CAPSET_GFXSTREAM_GLES | CAPSET_GFXSTREAM_COMPOSER) {
            v[12..16].copy_from_slice(&16384u32.to_le_bytes());
        }
        v
    }

    fn context_create(&self, ctx_id: u32, _name: &str, context_init: u32) -> Result<(), i64> {
        self.st.lock().unwrap().ctx.insert(ctx_id, context_init);
        Ok(())
    }

    fn context_destroy(&self, ctx_id: u32) {
        self.st.lock().unwrap().ctx.remove(&ctx_id);
    }

    fn submit(&self, ctx_id: u32, _cmds: &[u8], _in_fences: &[u64]) -> Result<(), i64> {
        if !self.st.lock().unwrap().ctx.contains_key(&ctx_id) {
            return Err(22);
        }
        Ok(())
    }

    fn create_fence(&self, fence: Fence) -> Result<(), i64> {
        let handler = self.st.lock().unwrap().handler.clone();
        if let Some(h) = handler {
            h(fence);
        }
        Ok(())
    }

    fn resource_create(&self, args: &Resource3d, _iov: Iov) -> Result<(), i64> {
        let size = (args.width as u64) * (args.height.max(1) as u64) * 4 * (args.depth.max(1) as u64) * (args.array_size.max(1) as u64);
        let info = ResourceInfo { virgl_format: args.format, width: args.width, height: args.height, depth: args.depth.max(1), flags: args.flags, stride: args.width.saturating_mul(4), drm_fourcc: 0 };
        self.st.lock().unwrap().res.insert(args.handle, Res { info, host: None, size });
        Ok(())
    }

    fn resource_create_blob(&self, _ctx_id: u32, handle: u32, blob: &Blob, _iov: Iov) -> Result<(), i64> {
        if !matches!(blob.blob_mem, BLOB_MEM_GUEST | BLOB_MEM_HOST3D | BLOB_MEM_HOST3D_GUEST) || blob.size == 0 {
            return Err(22);
        }
        let host = if blob.blob_mem != BLOB_MEM_GUEST && blob.blob_flags & BLOB_FLAG_USE_MAPPABLE != 0 { Some(host_buf(blob.size)?) } else { None };
        let info = ResourceInfo { width: 0, height: 0, depth: 1, stride: 0, ..ResourceInfo::default() };
        self.st.lock().unwrap().res.insert(handle, Res { info, host, size: blob.size });
        Ok(())
    }

    fn resource_unref(&self, handle: u32) {
        self.st.lock().unwrap().res.remove(&handle);
    }

    fn attach_iov(&self, handle: u32, _iov: Iov) -> Result<(), i64> {
        if self.st.lock().unwrap().res.contains_key(&handle) { Ok(()) } else { Err(22) }
    }

    fn detach_iov(&self, _handle: u32) {}

    fn ctx_attach_resource(&self, _ctx_id: u32, _handle: u32) {}

    fn ctx_detach_resource(&self, _ctx_id: u32, _handle: u32) {}

    fn transfer_write(&self, handle: u32, _t: &Transfer) -> Result<(), i64> {
        if self.st.lock().unwrap().res.contains_key(&handle) { Ok(()) } else { Err(22) }
    }

    fn transfer_read(&self, handle: u32, t: &Transfer) -> Result<(), i64> {
        self.transfer_write(handle, t)
    }

    fn resource_info(&self, handle: u32) -> Option<ResourceInfo> {
        self.st.lock().unwrap().res.get(&handle).map(|r| r.info)
    }

    fn resource_map(&self, handle: u32) -> Result<(*mut u8, u64), i64> {
        let st = self.st.lock().unwrap();
        match st.res.get(&handle).and_then(|r| r.host.as_ref().map(|h| (h.ptr, r.size))) {
            Some(m) => Ok(m),
            None => Err(22),
        }
    }

    fn resource_unmap(&self, _handle: u32) {}

    fn map_info(&self, handle: u32) -> Option<u32> {
        self.st.lock().unwrap().res.contains_key(&handle).then_some(0)
    }

    fn flush(&self, handle: u32) {
        self.st.lock().unwrap().flushed.push(handle);
    }

    fn set_fence_handler(&self, handler: Arc<dyn Fn(Fence) + Send + Sync>) {
        self.st.lock().unwrap().handler = Some(handler);
    }
}
