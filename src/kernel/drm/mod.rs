//! virtio-gpu as a Linux DRM device: /dev/dri/card0 and renderD128, the
//! virtgpu ioctls minigbm and gfxstream's guest issue, dma-buf and sync_file
//! fds, and a single 1080x2400 KMS pipeline for composer3-ranchu. The host
//! renderer sits behind `GpuBackend`; nothing here calls a host API.

use super::block::{self, makedev};
use super::wait::EVENTS;
use super::{ERESTARTSYS, POLL, Thread};
use crate::errno::*;
use crate::gpu::{self, Blob, Box3, Fence, GpuBackend, Resource3d, Transfer};
use crate::mm::{Backing, DevMem};
use crate::phys::{self, PhysMem};
use crate::vfs::FileSystem;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

const DRM_MAJOR: u32 = 226;
const FB_W: u32 = 1080;
const FB_H: u32 = 2400;

const ID_CONN: u32 = 1;
const ID_ENC: u32 = 2;
const ID_CRTC: u32 = 3;
const ID_PLANE: u32 = 4;
const P_TYPE: u32 = 20;
const P_FB_ID: u32 = 21;
const P_CRTC_ID: u32 = 22;
const P_CRTC_X: u32 = 23;
const P_CRTC_Y: u32 = 24;
const P_CRTC_W: u32 = 25;
const P_CRTC_H: u32 = 26;
const P_SRC_X: u32 = 27;
const P_SRC_Y: u32 = 28;
const P_SRC_W: u32 = 29;
const P_SRC_H: u32 = 30;
const P_IN_FENCE: u32 = 31;
const P_ACTIVE: u32 = 32;
const P_MODE_ID: u32 = 33;
const P_OUT_FENCE: u32 = 34;
const P_DPMS: u32 = 35;
const P_LINK: u32 = 36;

const PROP_ATOMIC: u32 = 0x8000_0000;
const PROP_RANGE: u32 = 1 << 1;
const PROP_IMMUTABLE: u32 = 1 << 2;
const PROP_ENUM: u32 = 1 << 3;
const PROP_BLOB: u32 = 1 << 4;
const PROP_OBJECT: u32 = 1 << 6;
const PROP_SIGNED: u32 = 2 << 6;

const OBJ_CRTC: u32 = 0xcccc_cccc;
#[allow(dead_code)]
const OBJ_CONNECTOR: u32 = 0xc0c0_c0c0;
#[allow(dead_code)]
const OBJ_ENCODER: u32 = 0xe0e0_e0e0;
const OBJ_FB: u32 = 0xfbfb_fbfb;
#[allow(dead_code)]
const OBJ_PLANE: u32 = 0xeeee_eeee;

const VIRTGPU_EVENT_FENCE: u32 = 0x8000_0000;
const DRM_EVENT_FLIP: u32 = 0x02;
const PAGE_FLIP_EVENT: u32 = 0x01;
const ATOMIC_TEST: u32 = 0x0100;
const ATOMIC_NONBLOCK: u32 = 0x0200;
const ATOMIC_ALLOW_MODESET: u32 = 0x0400;
const EXEC_FENCE_IN: u32 = 0x01;
const EXEC_FENCE_OUT: u32 = 0x02;
const EXEC_RING: u32 = 0x04;
const O_CLOEXEC_FLAG: u32 = 0x80000;

/// What an ioctl may do to the caller's memory and file table.
pub trait Io {
    fn read_mem(&mut self, addr: u64, n: usize) -> Result<Vec<u8>, i64>;
    fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<(), i64>;
    fn add_sync(&mut self, sync: SyncFile, cloexec: bool) -> Result<i64, i64>;
    fn add_dma(&mut self, dma: DmaBuf, cloexec: bool) -> Result<i64, i64>;
    fn sync_of(&mut self, fd: i64) -> Result<SyncFile, i64>;
    fn dma_of(&mut self, fd: i64) -> Result<DmaBuf, i64>;
    fn comm(&self) -> String;
    fn wait_until(&mut self, pred: &mut dyn FnMut() -> bool) -> Result<(), i64>;
}

pub fn is_node(rdev: u64) -> bool {
    block::major(rdev) == DRM_MAJOR && matches!(block::minor(rdev), 0 | 128)
}

pub fn card_rdev() -> u64 {
    makedev(DRM_MAJOR, 0)
}

pub fn render_rdev() -> u64 {
    makedev(DRM_MAJOR, 128)
}

fn ru32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn ru64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn wu32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wu64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn ioc_nr(cmd: u64) -> u32 {
    (cmd & 0xff) as u32
}
fn ioc_size(cmd: u64) -> usize {
    ((cmd >> 16) & 0x3fff) as usize
}
fn ioc_type(cmd: u64) -> u32 {
    ((cmd >> 8) & 0xff) as u32
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn modeinfo() -> [u8; 68] {
    let mut m = [0u8; 68];
    wu32(&mut m, 0, FB_W.saturating_mul(FB_H) / 1000 * 60);
    for (i, v) in [FB_W, FB_W, FB_W, FB_W, 0].iter().enumerate() {
        m[4 + i * 2..6 + i * 2].copy_from_slice(&(*v as u16).to_le_bytes());
    }
    for (i, v) in [FB_H, FB_H, FB_H, FB_H, 0].iter().enumerate() {
        m[14 + i * 2..16 + i * 2].copy_from_slice(&(*v as u16).to_le_bytes());
    }
    wu32(&mut m, 24, 60);
    wu32(&mut m, 28, 1 | 4); // PHSYNC | PVSYNC
    wu32(&mut m, 32, (1 << 3) | (1 << 6)); // PREFERRED | DRIVER
    // name[32] starts at byte 36. The mode string is shorter than the field.
    let name = b"1080x2400";
    m[36..36 + name.len()].copy_from_slice(name);
    m
}

struct Evq {
    q: Mutex<VecDeque<Vec<u8>>>,
}

impl Evq {
    fn push(&self, ev: Vec<u8>) {
        self.q.lock().unwrap().push_back(ev);
        EVENTS.bump();
    }

    fn take(&self, max: usize) -> Result<Option<Vec<u8>>, i64> {
        let mut q = self.q.lock().unwrap();
        if q.is_empty() {
            return Ok(None);
        }
        if q.front().unwrap().len() > max {
            return Err(EINVAL);
        }
        let mut out = Vec::new();
        while q.front().is_some_and(|e| out.len() + e.len() <= max) {
            out.extend_from_slice(&q.pop_front().unwrap());
        }
        Ok(Some(out))
    }

    fn ready(&self) -> bool {
        !self.q.lock().unwrap().is_empty()
    }
}

pub struct SyncPoint {
    signaled: AtomicBool,
    ns: AtomicU64,
    /// Renderer fence id, or 0 when this point is not a virtio-gpu fence.
    fence: u64,
}

impl SyncPoint {
    fn new(fence: u64) -> Arc<SyncPoint> {
        Arc::new(SyncPoint { signaled: AtomicBool::new(false), ns: AtomicU64::new(0), fence })
    }

    fn signal(&self) {
        if self.signaled.swap(true, Ordering::AcqRel) {
            return;
        }
        self.ns.store(now_ns(), Ordering::Relaxed);
        EVENTS.bump();
    }

    fn ready(&self) -> bool {
        self.signaled.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct SyncFile {
    points: Vec<Arc<SyncPoint>>,
}

impl SyncFile {
    fn ready(&self) -> bool {
        self.points.iter().all(|p| p.ready())
    }

    pub fn poll(&self) -> u16 {
        if self.ready() { 1 } else { 0 } // POLLIN once every point has signaled
    }
}

struct Resource {
    id: u32,
    size: u64,
    #[allow(dead_code)]
    stride: u32,
    blob_mem: u32,
    guest: Option<Arc<crate::mm::SharedObject>>,
    mapped: Mutex<Weak<DevMem>>,
    mapped_once: AtomicBool,
    gpu: Arc<dyn GpuBackend>,
    phys: Arc<PhysMem>,
}

impl Drop for Resource {
    fn drop(&mut self) {
        // Pages (and any GPA map) are still alive: field drops run after this,
        // and a VMA may still hold the shared object. Unmap the renderer
        // view before the resource itself goes.
        if self.mapped_once.load(Ordering::Acquire) {
            self.gpu.resource_unmap(self.id);
        }
        if self.guest.is_some() {
            self.gpu.detach_iov(self.id);
        }
        self.gpu.resource_unref(self.id);
    }
}

impl Resource {
    fn host_mem(self: &Arc<Self>) -> Result<Arc<DevMem>, i64> {
        if let Some(m) = self.mapped.lock().unwrap().upgrade() {
            return Ok(m);
        }
        let (ptr, reported) = self.gpu.resource_map(self.id)?;
        self.mapped_once.store(true, Ordering::Release);
        let gpa = match self.phys.map_external(ptr, reported) {
            Ok(g) => g,
            Err(e) => return Err(e),
        };
        let len = reported.div_ceil(phys::DEV_ALIGN) * phys::DEV_ALIGN;
        let keep = self.clone();
        let phys = self.phys.clone();
        let mem = DevMem::new(gpa, len, move || {
            phys.unmap_external(gpa);
            drop(keep);
        });
        let mut slot = self.mapped.lock().unwrap();
        if let Some(existing) = slot.upgrade() {
            // Another mmap won. Dropping `mem` unmaps only our GPA.
            drop(mem);
            return Ok(existing);
        }
        *slot = Arc::downgrade(&mem);
        Ok(mem)
    }

    fn backing(self: &Arc<Self>, delta: u64, len: u64) -> Result<Backing, i64> {
        let end = delta.checked_add(len).ok_or(EINVAL)?;
        if self.size == 0 || end > self.size.div_ceil(phys::PAGE) * phys::PAGE {
            return Err(EINVAL);
        }
        if self.blob_mem == gpu::BLOB_MEM_HOST3D || self.blob_mem == gpu::BLOB_MEM_HOST3D_GUEST {
            let mem = self.host_mem()?;
            return Ok(Backing::Dev { mem, offset: delta });
        }
        let obj = self.guest.clone().ok_or(ENODEV)?;
        Ok(Backing::Shared { obj, offset: delta })
    }
}

struct Gem {
    res: Arc<Resource>,
    mmap_off: u64,
}

#[derive(Clone)]
pub struct DmaBuf {
    gem: Arc<Gem>,
}

impl DmaBuf {
    pub fn mmap(&self, offset: u64, len: u64) -> Result<Backing, i64> {
        self.gem.res.backing(offset, len)
    }

    pub fn size(&self) -> u64 {
        self.gem.res.size
    }
}

struct Fb {
    res: Arc<Resource>,
    #[allow(dead_code)]
    width: u32,
    #[allow(dead_code)]
    height: u32,
}

struct FenceRec {
    point: Arc<SyncPoint>,
    ctx: u32,
    ring: u8,
}

struct Watch {
    ev: Weak<Evq>,
    mask: u32,
}

struct Kms {
    fbs: HashMap<u32, Fb>,
    blobs: HashMap<u32, Vec<u8>>,
    next_fb: u32,
    next_blob: u32,
    fb: u32,
    crtc_active: bool,
    seq: u32,
}

struct Inner {
    next_res: u32,
    next_ctx: u32,
    next_fence: u64,
    resources: HashMap<u32, Arc<Resource>>,
    fences: HashMap<u64, FenceRec>,
    ctxs: HashMap<u32, Watch>,
    kms: Kms,
}

pub struct Device {
    gpu: Arc<dyn GpuBackend>,
    phys: Arc<PhysMem>,
    /// Bit i set when capset i exists. Cached: probing virgl on this renderer logs an error.
    capsets: u64,
    inner: Mutex<Inner>,
}

impl Device {
    pub fn new(gpu: Arc<dyn GpuBackend>, phys: Arc<PhysMem>) -> Arc<Device> {
        let dev = Arc::new(Device {
            gpu: gpu.clone(),
            phys,
            capsets: capset_mask(gpu.as_ref()),
            inner: Mutex::new(Inner {
                next_res: 0,
                next_ctx: 0,
                next_fence: 0,
                resources: HashMap::new(),
                fences: HashMap::new(),
                ctxs: HashMap::new(),
                kms: Kms { fbs: HashMap::new(), blobs: HashMap::new(), next_fb: 1000, next_blob: 2000, fb: 0, crtc_active: false, seq: 0 },
            }),
        });
        let weak = Arc::downgrade(&dev);
        gpu.set_fence_handler(Arc::new(move |f| {
            if let Some(d) = weak.upgrade() {
                d.on_fence(f);
            }
        }));
        dev
    }

    pub fn publish(&self, dev: &dyn FileSystem, sys: &dyn FileSystem) {
        let root = dev.root().unwrap_or(1);
        let dri = mkdir_p(dev, "dri");
        let _ = dev.create(dri, "card0", 0o020666, card_rdev());
        let _ = dev.create(dri, "renderD128", 0o020666, render_rdev());
        let _ = root;
        put_file(sys, "class/drm/card0/dev", "226:0\n");
        put_file(sys, "class/drm/card0/uevent", "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n");
        put_file(sys, "class/drm/card0/device/uevent", "DRIVER=virtio_gpu\nMODALIAS=virtio:d00000010v00001AF4\n");
        put_file(sys, "class/drm/renderD128/dev", "226:128\n");
        put_file(sys, "class/drm/renderD128/uevent", "MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n");
        put_file(sys, "class/drm/renderD128/device/uevent", "DRIVER=virtio_gpu\nMODALIAS=virtio:d00000010v00001AF4\n");
        put_file(sys, "bus/virtio/drivers/virtio_gpu/uevent", "DRIVER=virtio_gpu\n");
        link_new(sys, "class/drm/card0/device", "driver", "../../../../bus/virtio/drivers/virtio_gpu");
        link_new(sys, "class/drm/renderD128/device", "driver", "../../../../bus/virtio/drivers/virtio_gpu");
        link_new(sys, "dev/char", "226:0", "../../class/drm/card0");
        link_new(sys, "dev/char", "226:128", "../../class/drm/renderD128");
    }

    pub fn open(self: &Arc<Self>, rdev: u64) -> Open {
        Open {
            dev: self.clone(),
            card: block::minor(rdev) == 0,
            st: Mutex::new(OpenSt { ctx: 0, capset: 0, poll_mask: 0, atomic_cap: false }),
            gems: Mutex::new(Gems { next: 1, off: phys::PAGE, map: HashMap::new() }),
            events: Arc::new(Evq { q: Mutex::new(VecDeque::new()) }),
            name: if block::minor(rdev) == 0 { "/dev/dri/card0" } else { "/dev/dri/renderD128" },
        }
    }

    fn on_fence(&self, f: Fence) {
        let rec = self.inner.lock().unwrap().fences.remove(&f.fence_id);
        let Some(rec) = rec else { return };
        rec.point.signal();
        let watch = self.inner.lock().unwrap().ctxs.get(&rec.ctx).map(|w| (w.ev.clone(), w.mask));
        if let Some((ev, mask)) = watch
            && mask & (1 << rec.ring.min(31)) != 0
            && let Some(ev) = ev.upgrade()
        {
            let mut b = vec![0u8; 16];
            wu32(&mut b, 0, VIRTGPU_EVENT_FENCE);
            wu32(&mut b, 4, 16);
            wu64(&mut b, 8, f.fence_id);
            ev.push(b);
        }
    }

    fn alloc_res(&self) -> u32 {
        let mut g = self.inner.lock().unwrap();
        g.next_res = g.next_res.wrapping_add(1).max(1);
        g.next_res
    }

    fn alloc_fence(&self) -> u64 {
        let mut g = self.inner.lock().unwrap();
        g.next_fence = g.next_fence.wrapping_add(1).max(1);
        g.next_fence
    }

    fn track_res(&self, res: Arc<Resource>) {
        self.inner.lock().unwrap().resources.insert(res.id, res);
    }
}

struct Gems {
    next: u32,
    off: u64,
    map: HashMap<u32, Arc<Gem>>,
}

impl Gems {
    fn alloc_off(&mut self, size: u64) -> u64 {
        let off = self.off;
        self.off = off + size.div_ceil(phys::PAGE) * phys::PAGE;
        off
    }

    fn insert(&mut self, res: Arc<Resource>) -> (u32, Arc<Gem>) {
        let handle = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        let gem = Arc::new(Gem { mmap_off: self.alloc_off(res.size), res });
        self.map.insert(handle, gem.clone());
        (handle, gem)
    }
}

struct OpenSt {
    ctx: u32,
    capset: u32,
    poll_mask: u32,
    atomic_cap: bool,
}

pub struct Open {
    dev: Arc<Device>,
    card: bool,
    st: Mutex<OpenSt>,
    gems: Mutex<Gems>,
    events: Arc<Evq>,
    name: &'static str,
}

impl Drop for Open {
    fn drop(&mut self) {
        let ctx = self.st.lock().unwrap().ctx;
        if ctx != 0 {
            self.dev.inner.lock().unwrap().ctxs.remove(&ctx);
            self.dev.gpu.context_destroy(ctx);
        }
    }
}

impl Open {
    pub fn path(&self) -> &'static str {
        self.name
    }

    pub fn rdev(&self) -> u64 {
        if self.card { card_rdev() } else { render_rdev() }
    }

    pub fn poll_bits(&self) -> u16 {
        // POLLIN when a fence or flip event is queued; the node is always writable.
        (if self.events.ready() { 1 } else { 0 }) | 4
    }

    pub fn read_events(&self, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        loop {
            let seen = EVENTS.current();
            if let Some(b) = self.events.take(max)? {
                return Ok(b);
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }

    pub fn mmap(&self, offset: u64, len: u64) -> Result<Backing, i64> {
        let gems = self.gems.lock().unwrap();
        let gem = gems
            .map
            .values()
            .find(|g| offset >= g.mmap_off && offset - g.mmap_off < g.res.size.div_ceil(phys::PAGE) * phys::PAGE)
            .cloned()
            .ok_or(EINVAL)?;
        let delta = offset - gem.mmap_off;
        drop(gems);
        gem.res.backing(delta, len)
    }

    fn gem(&self, handle: u32) -> Result<Arc<Gem>, i64> {
        self.gems.lock().unwrap().map.get(&handle).cloned().ok_or(ENOENT)
    }
}

pub fn ioctl(o: &Open, cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let r = dispatch(o, cmd, arg, io);
    let shown = match &r {
        Ok(v) => v.to_string(),
        Err(e) => format!("-{e}"),
    };
    eprintln!("[drm] {} {} = {shown}", io.comm(), ioctl_name(cmd));
    r
}

fn ioctl_name(cmd: u64) -> String {
    let (t, n) = (ioc_type(cmd), ioc_nr(cmd));
    if t == b'd' as u32 {
        let name = match n {
            0x00 => "VERSION",
            0x01 => "GET_UNIQUE",
            0x02 => "GET_MAGIC",
            0x07 => "SET_VERSION",
            0x09 => "GEM_CLOSE",
            0x0a => "GEM_FLINK",
            0x0b => "GEM_OPEN",
            0x0c => "GET_CAP",
            0x0d => "SET_CLIENT_CAP",
            0x11 => "AUTH_MAGIC",
            0x1e => "SET_MASTER",
            0x1f => "DROP_MASTER",
            0x2d => "PRIME_HANDLE_TO_FD",
            0x2e => "PRIME_FD_TO_HANDLE",
            0x3a => "WAIT_VBLANK",
            0x3b => "CRTC_GET_SEQUENCE",
            0x41 => "VIRTGPU_MAP",
            0x42 => "VIRTGPU_EXECBUFFER",
            0x43 => "VIRTGPU_GETPARAM",
            0x44 => "VIRTGPU_RESOURCE_CREATE",
            0x45 => "VIRTGPU_RESOURCE_INFO",
            0x46 => "VIRTGPU_TRANSFER_FROM_HOST",
            0x47 => "VIRTGPU_TRANSFER_TO_HOST",
            0x48 => "VIRTGPU_WAIT",
            0x49 => "VIRTGPU_GET_CAPS",
            0x4a => "VIRTGPU_RESOURCE_CREATE_BLOB",
            0x4b => "VIRTGPU_CONTEXT_INIT",
            0xa0 => "MODE_GETRESOURCES",
            0xa1 => "MODE_GETCRTC",
            0xa2 => "MODE_SETCRTC",
            0xa6 => "MODE_GETENCODER",
            0xa7 => "MODE_GETCONNECTOR",
            0xaa => "MODE_GETPROPERTY",
            0xac => "MODE_GETPROPBLOB",
            0xaf => "MODE_RMFB",
            0xb0 => "MODE_PAGE_FLIP",
            0xb2 => "MODE_CREATE_DUMB",
            0xb3 => "MODE_MAP_DUMB",
            0xb4 => "MODE_DESTROY_DUMB",
            0xb5 => "MODE_GETPLANERESOURCES",
            0xb6 => "MODE_GETPLANE",
            0xb8 => "MODE_ADDFB2",
            0xb9 => "MODE_OBJ_GETPROPERTIES",
            0xbc => "MODE_ATOMIC",
            0xbd => "MODE_CREATEPROPBLOB",
            0xbe => "MODE_DESTROYPROPBLOB",
            _ => return format!("DRM_{n:#x}"),
        };
        return name.into();
    }
    format!("ioctl({t:#x},{n:#x})")
}

fn dispatch(o: &Open, cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    if ioc_type(cmd) != b'd' as u32 {
        return Err(ENOTTY);
    }
    match ioc_nr(cmd) {
        0x00 => version(arg, io),
        0x01 => unique(arg, io),
        0x02 => magic(arg, io),
        0x07 | 0x1e | 0x1f | 0x11 => Ok(0), // SET_VERSION, master, AUTH_MAGIC
        0x09 => gem_close(o, arg, io),
        0x0c => get_cap(arg, io),
        0x0d => set_client_cap(o, arg, io),
        0x2d => prime_handle_to_fd(o, arg, io),
        0x2e => prime_fd_to_handle(o, arg, io),
        0x3a => wait_vblank(o, arg, io),
        0x3b => crtc_sequence(o, arg, io),
        0x41 => virt_map(o, arg, io),
        0x42 => virt_exec(o, arg, io),
        0x43 => virt_getparam(o, arg, io),
        0x44 => virt_res_create(o, arg, io),
        0x45 => virt_res_info(o, arg, io),
        0x46 | 0x47 => virt_transfer(o, cmd, arg, io),
        0x48 => virt_wait(o, arg, io),
        0x49 => virt_get_caps(o, arg, io),
        0x4a => virt_create_blob(o, arg, io),
        0x4b => virt_context_init(o, arg, io),
        0xa0 => mode_resources(o, arg, io),
        0xa1 => mode_getcrtc(o, arg, io),
        0xa2 => mode_setcrtc(o, arg, io),
        0xa6 => mode_encoder(o, arg, io),
        0xa7 => mode_connector(o, arg, io),
        0xaa => mode_property(o, arg, io),
        0xac => mode_blob_get(o, arg, io),
        0xaf => mode_rmfb(o, arg, io),
        0xb0 => mode_page_flip(o, arg, io),
        0xb2 => mode_create_dumb(o, arg, io),
        0xb3 => mode_map_dumb(o, arg, io),
        0xb4 => gem_close(o, arg, io),
        0xb5 => mode_plane_res(o, arg, io),
        0xb6 => mode_plane(o, arg, io),
        0xb8 => mode_addfb2(o, arg, io),
        0xb9 => mode_obj_props(o, arg, io),
        0xbc => mode_atomic(o, arg, io),
        0xbd => mode_blob_create(o, arg, io),
        0xbe => mode_blob_destroy(o, arg, io),
        _ => Err(ENOTTY),
    }
}

fn load(io: &mut dyn Io, arg: u64, cmd: u64, min: usize) -> Result<Vec<u8>, i64> {
    // Callers pass either a full ioctl command or just its number. A bare
    // number has a zero size field. A shorter guest struct (an older uapi)
    // is zero-extended so fields it doesn't have stay 0.
    let sized = ioc_size(cmd);
    if sized == 0 {
        return io.read_mem(arg, min);
    }
    let mut b = io.read_mem(arg, sized.min(4096))?;
    if b.len() < min {
        b.resize(min, 0);
    }
    Ok(b)
}

fn store(io: &mut dyn Io, arg: u64, buf: &[u8]) -> Result<(), i64> {
    io.write_mem(arg, buf)
}

fn version(arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    // LP64 drm_version: 3xi32, pad4, then (len, ptr) three times. 64 bytes.
    let mut b = io.read_mem(arg, 64)?;
    wu32(&mut b, 0, 0);
    wu32(&mut b, 4, 1);
    wu32(&mut b, 8, 0);
    copy_str(io, &mut b, 16, "virtio_gpu")?;
    copy_str(io, &mut b, 32, "0")?;
    copy_str(io, &mut b, 48, "droidrt virtio GPU")?;
    store(io, arg, &b)?;
    Ok(0)
}

fn copy_str(io: &mut dyn Io, b: &mut [u8], len_at: usize, text: &str) -> Result<(), i64> {
    let want = ru64(b, len_at) as usize;
    let ptr = ru64(b, len_at + 8);
    let n = text.len().min(want);
    if ptr != 0 && n > 0 {
        io.write_mem(ptr, &text.as_bytes()[..n])?;
    }
    wu64(b, len_at, text.len() as u64);
    Ok(())
}

fn unique(arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 16)?;
    copy_str(io, &mut b, 0, "virtio_gpu")?;
    store(io, arg, &b)?;
    Ok(0)
}

fn magic(arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 4)?;
    wu32(&mut b, 0, 1);
    store(io, arg, &b)?;
    Ok(0)
}

fn get_cap(arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 16)?;
    let cap = ru64(&b, 0);
    let value = match cap {
        0x1 => 1,                               // DUMB_BUFFER
        0x2 => 1,                               // VBLANK_HIGH_CRTC
        0x3 => 32,                              // DUMB_PREFERRED_DEPTH
        0x4 => 0,                               // DUMB_PREFER_SHADOW
        0x5 => 3,                               // PRIME import|export
        0x6 => 1,                               // TIMESTAMP_MONOTONIC
        0x10 => 1,                              // ADDFB2_MODIFIERS
        0x12 => 1,                              // CRTC_IN_VBLANK_EVENT
        0x13 | 0x14 => 0,                       // SYNCOBJ / TIMELINE: not provided
        _ => return Err(EINVAL),
    };
    wu64(&mut b, 8, value);
    store(io, arg, &b)?;
    Ok(0)
}

fn set_client_cap(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = io.read_mem(arg, 16)?;
    match ru64(&b, 0) {
        2 => {} // UNIVERSAL_PLANES: the one primary plane is always there
        3 => o.st.lock().unwrap().atomic_cap = ru64(&b, 8) != 0,
        1 | 4 | 5 => {}
        _ => return Err(EINVAL),
    }
    Ok(0)
}

fn gem_close(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = io.read_mem(arg, 4)?;
    o.gems.lock().unwrap().map.remove(&ru32(&b, 0));
    Ok(0)
}

fn prime_handle_to_fd(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 12)?;
    let gem = o.gem(ru32(&b, 0))?;
    let fd = io.add_dma(DmaBuf { gem }, ru32(&b, 4) & O_CLOEXEC_FLAG != 0)?;
    wu32(&mut b, 8, fd as u32);
    store(io, arg, &b)?;
    Ok(0)
}

fn prime_fd_to_handle(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 12)?;
    let dma = io.dma_of(ru32(&b, 8) as i32 as i64)?;
    let ctx = o.st.lock().unwrap().ctx;
    if ctx != 0 {
        o.dev.gpu.ctx_attach_resource(ctx, dma.gem.res.id);
    }
    let (handle, _) = o.gems.lock().unwrap().insert(dma.gem.res.clone());
    wu32(&mut b, 0, handle);
    store(io, arg, &b)?;
    Ok(0)
}

fn capset_mask(gpu: &dyn GpuBackend) -> u64 {
    let mut m = 0u64;
    for id in [gpu::CAPSET_VIRGL, gpu::CAPSET_VIRGL2, gpu::CAPSET_GFXSTREAM_VULKAN, gpu::CAPSET_GFXSTREAM_GLES, gpu::CAPSET_GFXSTREAM_COMPOSER] {
        if id < 64 && gpu.capset_info(id).is_some() {
            m |= 1u64 << id;
        }
    }
    m
}

fn virt_getparam(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = io.read_mem(arg, 16)?;
    let param = ru64(&b, 0);
    let ptr = ru64(&b, 8);
    let mask = o.dev.capsets;
    let value = match param {
        1 => u64::from(mask & (1 << 1 | 1 << 3 | 1 << 8) != 0), // 3D_FEATURES
        2 | 3 | 4 | 5 | 6 => 1,                                 // capset fix, blob, host visible, cross device, context init
        7 => mask,                                              // SUPPORTED_CAPSET_IDs
        _ => return Err(EINVAL),
    };
    if ptr != 0 {
        io.write_mem(ptr, &value.to_le_bytes())?;
    }
    Ok(0)
}

fn virt_get_caps(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = load(io, arg, 0x49, 24)?;
    let id = ru32(&b, 0);
    let ver = ru32(&b, 4);
    let addr = ru64(&b, 8);
    let size = ru32(&b, 16) as usize;
    if o.dev.capsets & (1u64 << id.min(63)) == 0 {
        return Err(EINVAL);
    }
    let caps = o.dev.gpu.capset(id, ver);
    let n = size.min(caps.len());
    if addr != 0 && n > 0 {
        io.write_mem(addr, &caps[..n])?;
    }
    Ok(0)
}

fn virt_context_init(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    if o.st.lock().unwrap().ctx != 0 {
        return Err(EEXIST);
    }
    let b = io.read_mem(arg, 16)?;
    let n = ru32(&b, 0) as usize;
    let ptr = ru64(&b, 8);
    if n > 16 {
        return Err(EINVAL);
    }
    let raw = if n == 0 { Vec::new() } else { io.read_mem(ptr, n * 16)? };
    let mut capset = 0u32;
    let mut rings = 0u32;
    let mut mask = 0u32;
    let mut name = "droidrt".to_string();
    for i in 0..n {
        let param = ru64(&raw, i * 16);
        let value = ru64(&raw, i * 16 + 8);
        match param {
            1 => capset = value as u32, // CAPSET_ID
            2 => rings = value as u32,
            3 => mask = value as u32,
            4 => {
                // DEBUG_NAME is a guest pointer.
                if value != 0 {
                    let bytes = io.read_mem(value, 64).unwrap_or_default();
                    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
                    if end > 0 {
                        name = String::from_utf8_lossy(&bytes[..end]).into_owned();
                    }
                }
            }
            _ => return Err(EINVAL),
        }
    }
    if capset != 0 && o.dev.capsets & (1u64 << capset.min(63)) == 0 {
        return Err(EINVAL);
    }
    if rings > 64 {
        return Err(EINVAL);
    }
    let mut g = o.dev.inner.lock().unwrap();
    g.next_ctx = g.next_ctx.wrapping_add(1).max(1);
    let ctx = g.next_ctx;
    drop(g);
    o.dev.gpu.context_create(ctx, &name, capset)?;
    {
        let mut st = o.st.lock().unwrap();
        st.ctx = ctx;
        st.capset = capset;
        st.poll_mask = mask;
    }
    o.dev.inner.lock().unwrap().ctxs.insert(ctx, Watch { ev: Arc::downgrade(&o.events), mask });
    let _ = rings;
    Ok(0)
}

fn guest_backing(phys: &Arc<PhysMem>, size: u64) -> Result<(Arc<crate::mm::SharedObject>, gpu::Iov), i64> {
    let obj = crate::mm::SharedObject::new(phys.clone());
    let pages = size.div_ceil(phys::PAGE) as usize;
    let mut iov = Vec::with_capacity(pages);
    for i in 0..pages {
        let gpa = obj.frame(i)?;
        let n = (phys::PAGE as usize).min(size as usize - i * phys::PAGE as usize);
        iov.push((phys.host(gpa), n));
    }
    Ok((obj, iov))
}

fn new_res(dev: &Device, id: u32, size: u64, stride: u32, blob_mem: u32, guest: Option<Arc<crate::mm::SharedObject>>) -> Arc<Resource> {
    Arc::new(Resource {
        id,
        size,
        stride,
        blob_mem,
        guest,
        mapped: Mutex::new(Weak::new()),
        mapped_once: AtomicBool::new(false),
        gpu: dev.gpu.clone(),
        phys: dev.phys.clone(),
    })
}

fn virt_res_create(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = load(io, arg, 0x44, 56)?;
    let width = ru32(&b, 12);
    let height = ru32(&b, 16);
    let depth = ru32(&b, 20).max(1);
    let array = ru32(&b, 24).max(1);
    let stride = width.saturating_mul(4);
    let size = (stride as u64) * (height as u64) * (depth as u64) * (array as u64);
    if size == 0 || size > (1 << 32) {
        return Err(EINVAL);
    }
    let (guest, iov) = guest_backing(&o.dev.phys, size)?;
    let id = o.dev.alloc_res();
    let args = Resource3d {
        handle: id,
        target: ru32(&b, 0),
        format: ru32(&b, 4),
        bind: ru32(&b, 8),
        width,
        height,
        depth,
        array_size: array,
        last_level: ru32(&b, 28),
        nr_samples: ru32(&b, 32),
        flags: ru32(&b, 36),
    };
    if let Err(e) = o.dev.gpu.resource_create(&args, iov) {
        return Err(e);
    }
    // Opening a handle attaches the object to the file's context (drm_gem_handle_create).
    let ctx = o.st.lock().unwrap().ctx;
    if ctx != 0 {
        o.dev.gpu.ctx_attach_resource(ctx, id);
    }
    let res = new_res(&o.dev, id, size, stride, 0, Some(guest));
    o.dev.track_res(res.clone());
    let (handle, _) = o.gems.lock().unwrap().insert(res);
    wu32(&mut b, 40, handle);
    wu32(&mut b, 44, id);
    wu32(&mut b, 48, size as u32);
    wu32(&mut b, 52, stride);
    store(io, arg, &b)?;
    Ok(0)
}

fn virt_create_blob(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = load(io, arg, 0x4a, 48)?;
    let mem = ru32(&b, 0);
    let flags = ru32(&b, 4);
    let size = ru64(&b, 16);
    let cmd_size = ru32(&b, 28) as usize;
    let cmd_ptr = ru64(&b, 32);
    let blob_id = ru64(&b, 40);
    if size == 0 || size > (1 << 32) || !matches!(mem, gpu::BLOB_MEM_GUEST | gpu::BLOB_MEM_HOST3D | gpu::BLOB_MEM_HOST3D_GUEST) {
        return Err(EINVAL);
    }
    let (guest, iov) = if mem == gpu::BLOB_MEM_HOST3D {
        (None, Vec::new())
    } else {
        let (g, iov) = guest_backing(&o.dev.phys, size)?;
        (Some(g), iov)
    };
    let ctx = o.st.lock().unwrap().ctx;
    if cmd_size > 0 {
        if ctx == 0 {
            return Err(EINVAL);
        }
        let cmd = io.read_mem(cmd_ptr, cmd_size.min(16 << 20))?;
        o.dev.gpu.submit(ctx, &cmd, &[])?;
    }
    let id = o.dev.alloc_res();
    let blob = Blob { blob_mem: mem, blob_flags: flags, blob_id, size };
    // This gfxstream build's create_blob wrapper ignores the iov, so a guest
    // blob is attached again explicitly. Host blobs have no guest pages.
    if let Err(e) =     o.dev.gpu.resource_create_blob(ctx, id, &blob, iov.clone()) {
        return Err(e);
    }
    if !iov.is_empty() && let Err(e) = o.dev.gpu.attach_iov(id, iov) {
        o.dev.gpu.resource_unref(id);
        return Err(e);
    }
    let res = new_res(&o.dev, id, size, 0, mem, guest);
    o.dev.track_res(res.clone());
    if ctx != 0 {
        o.dev.gpu.ctx_attach_resource(ctx, id);
    }
    let (handle, _) = o.gems.lock().unwrap().insert(res);
    wu32(&mut b, 8, handle);
    wu32(&mut b, 12, id);
    store(io, arg, &b)?;
    Ok(0)
}

fn virt_map(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = load(io, arg, 0x41, 16)?;
    let gem = o.gem(ru32(&b, 8))?;
    wu64(&mut b, 0, gem.mmap_off);
    store(io, arg, &b)?;
    Ok(0)
}

fn virt_res_info(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = load(io, arg, 0x45, 16)?;
    let gem = o.gem(ru32(&b, 0))?;
    wu32(&mut b, 4, gem.res.id);
    wu32(&mut b, 8, gem.res.size as u32);
    wu32(&mut b, 12, gem.res.blob_mem);
    store(io, arg, &b)?;
    Ok(0)
}

fn virt_transfer(o: &Open, cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = load(io, arg, cmd, 44)?;
    let gem = o.gem(ru32(&b, 0))?;
    let t = Transfer {
        ctx_id: o.st.lock().unwrap().ctx,
        level: ru32(&b, 28),
        stride: ru32(&b, 36),
        layer_stride: ru32(&b, 40),
        bx: Box3 { x: ru32(&b, 4), y: ru32(&b, 8), z: ru32(&b, 12), w: ru32(&b, 16), h: ru32(&b, 20), d: ru32(&b, 24) },
        offset: ru32(&b, 32) as u64,
    };
    let xfer = if ioc_nr(cmd) == 0x46 { o.dev.gpu.transfer_read(gem.res.id, &t) } else { o.dev.gpu.transfer_write(gem.res.id, &t) };
    if let Err(e) = xfer {
        eprintln!(
            "[drm] transfer res {} ctx {} box {}x{}x{} at {},{},{} level {} stride {} off {} ioctl {} bytes",
            gem.res.id, t.ctx_id, t.bx.w, t.bx.h, t.bx.d, t.bx.x, t.bx.y, t.bx.z, t.level, t.stride, t.offset, ioc_size(cmd)
        );
        return Err(e);
    }
    Ok(0)
}

fn virt_wait(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let b = load(io, arg, 0x48, 8)?;
    o.gem(ru32(&b, 0))?;
    Ok(0) // transfers complete before they return
}

fn virt_exec(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let ctx = o.st.lock().unwrap().ctx;
    if ctx == 0 {
        return Err(EINVAL);
    }
    let mut b = load(io, arg, 0x42, 32)?;
    let flags = ru32(&b, 0);
    let size = ru32(&b, 4) as usize;
    let cmd_ptr = ru64(&b, 8);
    let bos = ru64(&b, 16);
    let nbo = ru32(&b, 24) as usize;
    let fence_fd = ru32(&b, 28) as i32;
    let ring = if flags & EXEC_RING != 0 && b.len() >= 36 { ru32(&b, 32) as u8 } else { 0 };
    if size > (16 << 20) || nbo > 4096 {
        return Err(EINVAL);
    }
    let cmd = if size == 0 { Vec::new() } else { io.read_mem(cmd_ptr, size)? };
    let mut in_fences = Vec::new();
    if flags & EXEC_FENCE_IN != 0 {
        let sync = io.sync_of(fence_fd as i64)?;
        for p in &sync.points {
            if p.fence == 0 && !p.ready() {
                let pp = p.clone();
                io.wait_until(&mut || pp.ready())?;
            } else if p.fence != 0 {
                in_fences.push(p.fence);
            }
        }
    }
    if nbo > 0 {
        let raw = io.read_mem(bos, nbo * 4)?;
        for i in 0..nbo {
            let gem = o.gem(ru32(&raw, i * 4))?;
            o.dev.gpu.ctx_attach_resource(ctx, gem.res.id);
        }
    }
    o.dev.gpu.submit(ctx, &cmd, &in_fences)?;
    if flags & EXEC_FENCE_OUT != 0 {
        let fd = make_fence(&o.dev, ctx, ring, io, true)?;
        wu32(&mut b, 28, fd as u32);
        store(io, arg, &b)?;
    }
    Ok(0)
}

fn make_fence(dev: &Device, ctx: u32, ring: u8, io: &mut dyn Io, cloexec: bool) -> Result<i64, i64> {
    let id = dev.alloc_fence();
    let point = SyncPoint::new(id);
    dev.inner.lock().unwrap().fences.insert(id, FenceRec { point: point.clone(), ctx, ring });
    if let Err(e) = dev.gpu.create_fence(Fence { flags: 0, fence_id: id, ctx_id: ctx, ring_idx: ring }) {
        dev.inner.lock().unwrap().fences.remove(&id);
        point.signal();
        let _ = e;
    }
    io.add_sync(SyncFile { points: vec![point] }, cloexec)
}

fn card(o: &Open) -> Result<(), i64> {
    if o.card { Ok(()) } else { Err(EINVAL) }
}

fn mode_resources(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xa0, 64)?;
    let fbs: Vec<u32> = o.dev.inner.lock().unwrap().kms.fbs.keys().copied().collect();
    write_ids(io, ru64(&b, 0), ru32(&b, 32), &fbs)?;
    write_ids(io, ru64(&b, 8), ru32(&b, 36), &[ID_CRTC])?;
    write_ids(io, ru64(&b, 16), ru32(&b, 40), &[ID_CONN])?;
    write_ids(io, ru64(&b, 24), ru32(&b, 44), &[ID_ENC])?;
    wu32(&mut b, 32, fbs.len() as u32);
    wu32(&mut b, 36, 1);
    wu32(&mut b, 40, 1);
    wu32(&mut b, 44, 1);
    wu32(&mut b, 48, 0);
    wu32(&mut b, 52, 16384);
    wu32(&mut b, 56, 0);
    wu32(&mut b, 60, 16384);
    store(io, arg, &b)?;
    Ok(0)
}

fn write_ids(io: &mut dyn Io, ptr: u64, count: u32, ids: &[u32]) -> Result<(), i64> {
    if ptr == 0 || count < ids.len() as u32 {
        return Ok(());
    }
    let mut raw = Vec::with_capacity(ids.len() * 4);
    for id in ids {
        raw.extend_from_slice(&id.to_le_bytes());
    }
    io.write_mem(ptr, &raw)
}

fn mode_getcrtc(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xa1, 104)?;
    let k = &o.dev.inner.lock().unwrap().kms;
    wu32(&mut b, 12, ID_CRTC);
    wu32(&mut b, 16, k.fb);
    wu32(&mut b, 32, u32::from(k.crtc_active));
    if k.crtc_active {
        b[36..36 + 68].copy_from_slice(&modeinfo());
    }
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_setcrtc(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let b = load(io, arg, 0xa2, 104)?;
    let fb = ru32(&b, 16);
    let valid = ru32(&b, 32) != 0;
    present(o, if valid { fb } else { 0 }, 0, false)?;
    Ok(0)
}

fn mode_encoder(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xa6, 20)?;
    wu32(&mut b, 0, ID_ENC);
    wu32(&mut b, 4, 5); // VIRTUAL
    wu32(&mut b, 8, ID_CRTC);
    wu32(&mut b, 12, 1); // possible_crtcs bit 0
    wu32(&mut b, 16, 0);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_connector(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xa7, 80)?;
    let mode = modeinfo();
    write_bytes(io, ru64(&b, 8), ru32(&b, 32), &mode, 1)?;
    let props = [P_CRTC_ID, P_DPMS, P_LINK];
    let values = [ID_CRTC as u64, 0, 0];
    write_ids(io, ru64(&b, 16), ru32(&b, 36), &props)?;
    write_u64s(io, ru64(&b, 24), ru32(&b, 36), &values)?;
    write_ids(io, ru64(&b, 0), ru32(&b, 40), &[ID_ENC])?;
    wu32(&mut b, 32, 1);
    wu32(&mut b, 36, props.len() as u32);
    wu32(&mut b, 40, 1);
    wu32(&mut b, 44, ID_ENC);
    wu32(&mut b, 48, ID_CONN);
    wu32(&mut b, 52, 15); // VIRTUAL
    wu32(&mut b, 56, 1);
    wu32(&mut b, 60, 1); // CONNECTED
    wu32(&mut b, 64, 68);
    wu32(&mut b, 68, 151);
    store(io, arg, &b)?;
    Ok(0)
}

fn write_bytes(io: &mut dyn Io, ptr: u64, count: u32, one: &[u8], n: u32) -> Result<(), i64> {
    if ptr == 0 || count < n {
        return Ok(());
    }
    io.write_mem(ptr, one)
}

fn write_u64s(io: &mut dyn Io, ptr: u64, count: u32, vals: &[u64]) -> Result<(), i64> {
    if ptr == 0 || count < vals.len() as u32 {
        return Ok(());
    }
    let mut raw = Vec::with_capacity(vals.len() * 8);
    for v in vals {
        raw.extend_from_slice(&v.to_le_bytes());
    }
    io.write_mem(ptr, &raw)
}

struct PropInfo {
    name: &'static str,
    flags: u32,
    values: &'static [u64],
    enums: &'static [(u64, &'static str)],
}

fn prop_info(id: u32) -> Option<PropInfo> {
    const R: &[u64] = &[0, u64::MAX];
    const SIGNED: &[u64] = &[(-1i64) as u64, i32::MAX as u64];
    Some(match id {
        P_TYPE => PropInfo { name: "type", flags: PROP_ENUM | PROP_IMMUTABLE, values: &[], enums: &[(1, "Primary")] },
        P_FB_ID => PropInfo { name: "FB_ID", flags: PROP_ATOMIC | PROP_OBJECT, values: &[OBJ_FB as u64], enums: &[] },
        P_CRTC_ID => PropInfo { name: "CRTC_ID", flags: PROP_ATOMIC | PROP_OBJECT, values: &[OBJ_CRTC as u64], enums: &[] },
        P_CRTC_X => PropInfo { name: "CRTC_X", flags: PROP_ATOMIC | PROP_SIGNED, values: SIGNED, enums: &[] },
        P_CRTC_Y => PropInfo { name: "CRTC_Y", flags: PROP_ATOMIC | PROP_SIGNED, values: SIGNED, enums: &[] },
        P_CRTC_W => PropInfo { name: "CRTC_W", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_CRTC_H => PropInfo { name: "CRTC_H", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_SRC_X => PropInfo { name: "SRC_X", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_SRC_Y => PropInfo { name: "SRC_Y", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_SRC_W => PropInfo { name: "SRC_W", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_SRC_H => PropInfo { name: "SRC_H", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_IN_FENCE => PropInfo { name: "IN_FENCE_FD", flags: PROP_ATOMIC | PROP_SIGNED, values: SIGNED, enums: &[] },
        P_ACTIVE => PropInfo { name: "ACTIVE", flags: PROP_ATOMIC | PROP_RANGE, values: &[0, 1], enums: &[] },
        P_MODE_ID => PropInfo { name: "MODE_ID", flags: PROP_ATOMIC | PROP_BLOB, values: &[], enums: &[] },
        P_OUT_FENCE => PropInfo { name: "OUT_FENCE_PTR", flags: PROP_ATOMIC | PROP_RANGE, values: R, enums: &[] },
        P_DPMS => PropInfo { name: "DPMS", flags: PROP_ENUM, values: &[], enums: &[(0, "On"), (3, "Off")] },
        P_LINK => PropInfo { name: "link-status", flags: PROP_ENUM, values: &[], enums: &[(0, "Good"), (1, "Bad")] },
        _ => return None,
    })
}

fn mode_property(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xaa, 64)?;
    let info = prop_info(ru32(&b, 16)).ok_or(ENOENT)?;
    wu32(&mut b, 20, info.flags);
    b[24..24 + info.name.len()].copy_from_slice(info.name.as_bytes());
    write_u64s(io, ru64(&b, 0), ru32(&b, 56), info.values)?;
    if !info.enums.is_empty() && ru64(&b, 8) != 0 && ru32(&b, 60) >= info.enums.len() as u32 {
        let mut raw = vec![0u8; info.enums.len() * 40];
        for (i, (val, name)) in info.enums.iter().enumerate() {
            wu64(&mut raw, i * 40, *val);
            raw[i * 40 + 8..i * 40 + 8 + name.len()].copy_from_slice(name.as_bytes());
        }
        io.write_mem(ru64(&b, 8), &raw)?;
    }
    wu32(&mut b, 56, info.values.len() as u32);
    wu32(&mut b, 60, info.enums.len() as u32);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_plane_res(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb5, 16)?;
    write_ids(io, ru64(&b, 0), ru32(&b, 8), &[ID_PLANE])?;
    wu32(&mut b, 8, 1);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_plane(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb6, 32)?;
    let formats = [0x3432_5241u32, 0x3432_4258u32, 0x3432_5242u32, 0x3432_4252u32]; // AR24 XR24 AB24 XB24
    let fb = o.dev.inner.lock().unwrap().kms.fb;
    wu32(&mut b, 0, ID_PLANE);
    wu32(&mut b, 4, ID_CRTC);
    wu32(&mut b, 8, fb);
    wu32(&mut b, 12, 1);
    write_ids(io, ru64(&b, 24), ru32(&b, 20), &formats)?;
    wu32(&mut b, 20, formats.len() as u32);
    store(io, arg, &b)?;
    Ok(0)
}

fn obj_props(id: u32) -> Option<(&'static [u32], Vec<u64>)> {
    match id {
        ID_CONN => Some((&[P_CRTC_ID, P_DPMS, P_LINK], vec![ID_CRTC as u64, 0, 0])),
        ID_CRTC => Some((&[P_ACTIVE, P_MODE_ID, P_OUT_FENCE], vec![1, 0, 0])),
        ID_PLANE => Some((
            &[P_TYPE, P_FB_ID, P_CRTC_ID, P_CRTC_X, P_CRTC_Y, P_CRTC_W, P_CRTC_H, P_SRC_X, P_SRC_Y, P_SRC_W, P_SRC_H, P_IN_FENCE],
            vec![1, 0, ID_CRTC as u64, 0, 0, FB_W as u64, FB_H as u64, 0, 0, (FB_W as u64) << 16, (FB_H as u64) << 16, u64::MAX],
        )),
        _ => None,
    }
}

fn mode_obj_props(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb9, 32)?;
    let id = ru32(&b, 20);
    let (props, mut values) = obj_props(id).ok_or(ENOENT)?;
    if id == ID_PLANE || id == ID_CRTC {
        let fb = o.dev.inner.lock().unwrap().kms.fb as u64;
        if id == ID_PLANE {
            values[1] = fb;
        }
    }
    write_ids(io, ru64(&b, 0), ru32(&b, 16), props)?;
    write_u64s(io, ru64(&b, 8), ru32(&b, 16), &values)?;
    wu32(&mut b, 16, props.len() as u32);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_blob_create(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xbd, 16)?;
    let ptr = ru64(&b, 0);
    let len = ru32(&b, 8) as usize;
    if len > (1 << 20) {
        return Err(EINVAL);
    }
    let data = if len == 0 { Vec::new() } else { io.read_mem(ptr, len)? };
    let mut k = o.dev.inner.lock().unwrap();
    k.kms.next_blob += 1;
    let id = k.kms.next_blob;
    k.kms.blobs.insert(id, data);
    drop(k);
    wu32(&mut b, 12, id);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_blob_get(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xac, 20)?;
    // drm_mode_get_blob: blob_id u32, length u32, data ptr. 16 bytes, callers pass >= 16.
    let id = ru32(&b, 0);
    let data = o.dev.inner.lock().unwrap().kms.blobs.get(&id).cloned().ok_or(ENOENT)?;
    if b.len() >= 16 {
        write_bytes(io, ru64(&b, 8), ru32(&b, 4), &data, 1)?;
        wu32(&mut b, 4, data.len() as u32);
    }
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_blob_destroy(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let b = io.read_mem(arg, 4)?;
    o.dev.inner.lock().unwrap().kms.blobs.remove(&ru32(&b, 0));
    Ok(0)
}

fn mode_addfb2(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb8, 104)?;
    let handle = ru32(&b, 20); // handles[0], after 5xu32
    let gem = o.gem(handle)?;
    let mut k = o.dev.inner.lock().unwrap();
    k.kms.next_fb += 1;
    let id = k.kms.next_fb;
    k.kms.fbs.insert(id, Fb { res: gem.res.clone(), width: ru32(&b, 4), height: ru32(&b, 8) });
    drop(k);
    wu32(&mut b, 0, id);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_rmfb(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let b = io.read_mem(arg, 4)?;
    let id = ru32(&b, 0);
    let mut k = o.dev.inner.lock().unwrap();
    if k.kms.fbs.remove(&id).is_none() {
        return Err(ENOENT);
    }
    if k.kms.fb == id {
        k.kms.fb = 0;
    }
    Ok(0)
}

fn present(o: &Open, fb: u32, user: u64, event: bool) -> Result<(), i64> {
    let mut k = o.dev.inner.lock().unwrap();
    if fb != 0 && !k.kms.fbs.contains_key(&fb) {
        return Err(ENOENT);
    }
    let res = fb.checked_sub(0).and_then(|_| k.kms.fbs.get(&fb)).map(|f| f.res.id);
    k.kms.fb = fb;
    k.kms.crtc_active = fb != 0;
    k.kms.seq = k.kms.seq.wrapping_add(1);
    let seq = k.kms.seq;
    drop(k);
    if let Some(id) = res {
        o.dev.gpu.flush(id);
    }
    if event {
        let mut ev = vec![0u8; 32];
        wu32(&mut ev, 0, DRM_EVENT_FLIP);
        wu32(&mut ev, 4, 32);
        wu64(&mut ev, 8, user);
        let ns = now_ns();
        wu32(&mut ev, 16, (ns / 1_000_000_000) as u32);
        wu32(&mut ev, 20, ((ns / 1000) % 1_000_000) as u32);
        wu32(&mut ev, 24, seq);
        wu32(&mut ev, 28, ID_CRTC);
        o.events.push(ev);
    }
    Ok(())
}

fn mode_page_flip(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let b = load(io, arg, 0xb0, 24)?;
    present(o, ru32(&b, 4), ru64(&b, 16), ru32(&b, 8) & PAGE_FLIP_EVENT != 0)?;
    Ok(0)
}

fn mode_create_dumb(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb2, 32)?;
    let height = ru32(&b, 0);
    let width = ru32(&b, 4);
    let bpp = ru32(&b, 8);
    if width == 0 || height == 0 || bpp == 0 || bpp > 64 {
        return Err(EINVAL);
    }
    let stride = width.saturating_mul(bpp.div_ceil(8));
    let size = (stride as u64).saturating_mul(height as u64);
    if size == 0 || size > (1 << 32) {
        return Err(EINVAL);
    }
    let (guest, iov) = guest_backing(&o.dev.phys, size)?;
    let id = o.dev.alloc_res();
    let args = Resource3d {
        handle: id,
        target: 2,
        format: 1,
        bind: (1 << 1) | (1 << 18),
        width,
        height,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: 0,
    };
    if let Err(e) = o.dev.gpu.resource_create(&args, iov) {
        return Err(e);
    }
    let res = new_res(&o.dev, id, size, stride, 0, Some(guest));
    o.dev.track_res(res.clone());
    let (handle, _) = o.gems.lock().unwrap().insert(res);
    wu32(&mut b, 16, handle);
    wu32(&mut b, 20, stride);
    wu64(&mut b, 24, size);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_map_dumb(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0xb3, 16)?;
    let gem = o.gem(ru32(&b, 0))?;
    wu64(&mut b, 8, gem.mmap_off);
    store(io, arg, &b)?;
    Ok(0)
}

fn mode_atomic(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    if !o.st.lock().unwrap().atomic_cap {
        return Err(EINVAL);
    }
    let b = load(io, arg, 0xbc, 56)?;
    let flags = ru32(&b, 0);
    let nobj = ru32(&b, 4) as usize;
    if flags & !(PAGE_FLIP_EVENT | ATOMIC_TEST | ATOMIC_NONBLOCK | ATOMIC_ALLOW_MODESET | 0x02 | 0x04 | 0x08) != 0 || nobj > 64 {
        return Err(EINVAL);
    }
    let counts = read_u32s(io, ru64(&b, 16), nobj)?;
    let total: usize = counts.iter().map(|&c| c as usize).sum();
    if total > 4096 {
        return Err(EINVAL);
    }
    let props = read_u32s(io, ru64(&b, 24), total)?;
    let values = read_u64s(io, ru64(&b, 32), total)?;
    let mut cursor = 0usize;
    let mut fb = None;
    let mut out_ptr = 0u64;
    let mut in_fd = -1i32;
    for i in 0..nobj {
        let n = counts[i] as usize;
        for (&p, &v) in props[cursor..cursor + n].iter().zip(&values[cursor..cursor + n]) {
            match p {
                P_FB_ID => fb = Some(v as u32),
                P_OUT_FENCE => out_ptr = v,
                P_IN_FENCE => in_fd = v as i32,
                P_ACTIVE => {}
                _ => {}
            }
        }
        cursor += n;
    }
    if in_fd >= 0 {
        let sync = io.sync_of(in_fd as i64)?;
        for p in sync.points {
            if !p.ready() {
                let pp = p.clone();
                io.wait_until(&mut || pp.ready())?;
            }
        }
    }
    if flags & ATOMIC_TEST == 0 {
        if let Some(id) = fb {
            present(o, id, ru64(&b, 48), flags & PAGE_FLIP_EVENT != 0)?;
        } else if flags & PAGE_FLIP_EVENT != 0 {
            present(o, o.dev.inner.lock().unwrap().kms.fb, ru64(&b, 48), true)?;
        }
        if out_ptr != 0 {
            let fd = make_fence(&o.dev, 0, 0, io, true)?;
            io.write_mem(out_ptr, &(fd as i32).to_le_bytes())?;
        }
    }
    Ok(0)
}

fn read_u32s(io: &mut dyn Io, ptr: u64, n: usize) -> Result<Vec<u32>, i64> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let raw = io.read_mem(ptr, n * 4)?;
    Ok((0..n).map(|i| ru32(&raw, i * 4)).collect())
}

fn read_u64s(io: &mut dyn Io, ptr: u64, n: usize) -> Result<Vec<u64>, i64> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let raw = io.read_mem(ptr, n * 8)?;
    Ok((0..n).map(|i| ru64(&raw, i * 8)).collect())
}

fn wait_vblank(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    // union drm_wait_vblank: request type at 0, sequence at 4, signal at 8, then reply sec/usec.
    let mut b = load(io, arg, 0x3a, 24)?;
    let seq = {
        let mut k = o.dev.inner.lock().unwrap();
        k.kms.seq = k.kms.seq.wrapping_add(1);
        k.kms.seq
    };
    wu32(&mut b, 4, seq);
    let ns = now_ns();
    wu32(&mut b, 12, (ns / 1_000_000_000) as u32); // reply starts after the request's 8 bytes? 
    // The union is { request, reply }. reply: { type, sequence, tval_sec, tval_usec }.
    wu32(&mut b, 8, (ns / 1_000_000_000) as u32);
    if b.len() >= 16 {
        wu32(&mut b, 12, ((ns / 1000) % 1_000_000) as u32);
    }
    store(io, arg, &b)?;
    Ok(0)
}

fn crtc_sequence(o: &Open, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    card(o)?;
    let mut b = load(io, arg, 0x3b, 24)?;
    let seq = o.dev.inner.lock().unwrap().kms.seq as u64;
    wu64(&mut b, 8, seq);
    if b.len() >= 24 {
        wu64(&mut b, 16, now_ns());
    }
    store(io, arg, &b)?;
    Ok(0)
}

pub fn sync_ioctl(s: &SyncFile, cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    if ioc_type(cmd) != b'>' as u32 {
        return Err(ENOTTY);
    }
    match ioc_nr(cmd) {
        3 => sync_merge(s, arg, io),
        4 => sync_info(s, arg, io),
        _ => Err(ENOTTY),
    }
}

fn sync_merge(s: &SyncFile, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 48)?;
    let fd2 = ru32(&b, 32) as i32;
    let other = io.sync_of(fd2 as i64)?;
    let mut points = s.points.clone();
    points.extend(other.points);
    let fd = io.add_sync(SyncFile { points }, true)?;
    wu32(&mut b, 36, fd as u32);
    store(io, arg, &b)?;
    Ok(0)
}

fn sync_info(s: &SyncFile, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    let mut b = io.read_mem(arg, 56)?;
    let status: i32 = if s.ready() { 1 } else { 0 };
    wu32(&mut b, 32, status as u32);
    let n = s.points.len() as u32;
    let ptr = ru64(&b, 48);
    if ptr != 0 && ru32(&b, 40) >= n {
        let mut raw = vec![0u8; s.points.len() * 80];
        for (i, p) in s.points.iter().enumerate() {
            let base = i * 80;
            raw[base..base + 4].copy_from_slice(b"fence");
            raw[base + 32..base + 32 + 8].copy_from_slice(b"virtio_g");
            let st: i32 = if p.ready() { 1 } else { 0 };
            wu32(&mut raw, base + 64, st as u32);
            wu64(&mut raw, base + 72, p.ns.load(Ordering::Relaxed));
        }
        io.write_mem(ptr, &raw)?;
    }
    wu32(&mut b, 40, n);
    store(io, arg, &b)?;
    Ok(0)
}

pub fn dma_ioctl(cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
    // DMA_BUF_IOCTL_SYNC: accept and return. Guest and host memory are coherent.
    if ioc_type(cmd) == b'b' as u32 && ioc_nr(cmd) == 0 {
        if arg != 0 && ioc_size(cmd) > 0 {
            let _ = io.read_mem(arg, ioc_size(cmd).min(16))?;
        }
        return Ok(0);
    }
    Err(ENOTTY)
}

fn mkdir_p(fs: &dyn FileSystem, path: &str) -> u64 {
    let mut d = fs.root().unwrap_or(1);
    for part in path.split('/').filter(|p| !p.is_empty()) {
        d = match fs.lookup(d, part).ok().flatten() {
            Some(i) => i,
            None => fs.mkdir(d, part, 0o755).unwrap_or(d),
        };
    }
    d
}

fn put_file(fs: &dyn FileSystem, path: &str, content: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let d = mkdir_p(fs, dir);
    let ino = match fs.lookup(d, name).ok().flatten() {
        Some(i) => i,
        None => match fs.create(d, name, 0o100644, 0) {
            Ok(i) => i,
            Err(_) => return,
        },
    };
    if let Some(f) = fs.mem_file(ino) {
        f.truncate(0);
        let _ = f.write_at(0, content.as_bytes());
    }
}

fn link_new(fs: &dyn FileSystem, dir: &str, name: &str, target: &str) {
    let d = mkdir_p(fs, dir);
    if fs.lookup(d, name).ok().flatten().is_none() {
        let _ = fs.symlink(d, name, target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::{CpuState, Hypervisor, KernelPage, PageTableRoot, Vcpu};

    struct NoHv;
    impl Hypervisor for NoHv {
        fn map_ram(&self, _: *mut u8, _: u64, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn unmap_ram(&self, _: u64, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn kernel_pages(&self, _: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage> {
            Vec::new()
        }
        fn create_vcpu(&self, _: PageTableRoot, _: &CpuState) -> Result<Box<dyn Vcpu>, String> {
            Err("no vcpu".into())
        }
        fn max_vcpus(&self) -> usize {
            0
        }
    }

    struct Mem {
        buf: Vec<u8>,
        syncs: Vec<SyncFile>,
        dmas: Vec<DmaBuf>,
    }

    impl Io for Mem {
        fn read_mem(&mut self, addr: u64, n: usize) -> Result<Vec<u8>, i64> {
            self.buf.get(addr as usize..addr as usize + n).map(|s| s.to_vec()).ok_or(EFAULT)
        }
        fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<(), i64> {
            self.buf.get_mut(addr as usize..addr as usize + data.len()).ok_or(EFAULT)?.copy_from_slice(data);
            Ok(())
        }
        fn add_sync(&mut self, sync: SyncFile, _: bool) -> Result<i64, i64> {
            self.syncs.push(sync);
            Ok(self.syncs.len() as i64)
        }
        fn add_dma(&mut self, dma: DmaBuf, _: bool) -> Result<i64, i64> {
            self.dmas.push(dma);
            Ok(100 + self.dmas.len() as i64)
        }
        fn sync_of(&mut self, fd: i64) -> Result<SyncFile, i64> {
            self.syncs.get(fd as usize - 1).cloned().ok_or(EBADF)
        }
        fn dma_of(&mut self, fd: i64) -> Result<DmaBuf, i64> {
            self.dmas.get((fd - 100) as usize - 1).cloned().ok_or(EBADF)
        }
        fn comm(&self) -> String {
            "test".into()
        }
        fn wait_until(&mut self, pred: &mut dyn FnMut() -> bool) -> Result<(), i64> {
            if pred() { Ok(()) } else { Err(ETIMEDOUT) }
        }
    }

    fn ioc(dir: u32, nr: u32, size: u32) -> u64 {
        ((dir as u64) << 30) | ((size as u64) << 16) | ((b'd' as u64) << 8) | nr as u64
    }

    #[test]
    fn virtgpu_blob_map_prime_and_flip() {
        let phys = PhysMem::new(Arc::new(NoHv));
        let fake = gpu::fake::Fake::new();
        let dev = Device::new(fake.clone(), phys.clone());
        let render = dev.open(render_rdev());
        let card = dev.open(card_rdev());
        card.st.lock().unwrap().atomic_cap = true;
        let mut m = Mem { buf: vec![0u8; 1 << 16], syncs: Vec::new(), dmas: Vec::new() };

        // VERSION: name pointer at 0x100, len slot large.
        wu64(&mut m.buf, 16, 64);
        wu64(&mut m.buf, 24, 0x100);
        ioctl(&render, ioc(3, 0x00, 64), 0, &mut m).unwrap();
        assert_eq!(&m.buf[0x100..0x100 + 10], b"virtio_gpu");

        // GETPARAM supported capsets (param 7) written to 0x200.
        wu64(&mut m.buf, 0, 7);
        wu64(&mut m.buf, 8, 0x200);
        ioctl(&render, ioc(3, 0x43, 16), 0, &mut m).unwrap();
        let mask = u64::from_le_bytes(m.buf[0x200..0x208].try_into().unwrap());
        assert_ne!(mask & (1 << 8), 0, "gfxstream GLES capset");
        assert_ne!(mask & (1 << 9), 0, "composer capset");

        // CONTEXT_INIT capset 8.
        wu64(&mut m.buf, 0x300, 1);
        wu64(&mut m.buf, 0x308, 8);
        wu32(&mut m.buf, 0, 1);
        wu64(&mut m.buf, 8, 0x300);
        ioctl(&render, ioc(3, 0x4b, 16), 0, &mut m).unwrap();
        assert_eq!(render.st.lock().unwrap().capset, 8);

        // Guest blob, 4096 bytes.
        m.buf[..48].fill(0);
        wu32(&mut m.buf, 0, gpu::BLOB_MEM_GUEST);
        wu32(&mut m.buf, 4, gpu::BLOB_FLAG_USE_MAPPABLE);
        wu64(&mut m.buf, 16, 4096);
        ioctl(&render, ioc(3, 0x4a, 48), 0, &mut m).unwrap();
        let guest_handle = ru32(&m.buf, 8);
        wu32(&mut m.buf, 8, guest_handle);
        ioctl(&render, ioc(3, 0x41, 16), 0, &mut m).unwrap();
        let off = ru64(&m.buf, 0);
        let backing = render.mmap(off, 4096).unwrap();
        let Backing::Shared { obj, .. } = &backing else { panic!("guest blob is shared ram") };
        obj.write(0, b"guest-pixel").unwrap();
        let mut got = [0u8; 11];
        obj.read(0, &mut got);
        assert_eq!(&got, b"guest-pixel");

        // Host blob, mapped above RAM and visible through phys.host.
        m.buf[..48].fill(0);
        wu32(&mut m.buf, 0, gpu::BLOB_MEM_HOST3D);
        wu32(&mut m.buf, 4, gpu::BLOB_FLAG_USE_MAPPABLE);
        wu64(&mut m.buf, 16, 16384);
        ioctl(&render, ioc(3, 0x4a, 48), 0, &mut m).unwrap();
        let host_handle = ru32(&m.buf, 8);
        wu32(&mut m.buf, 8, host_handle);
        ioctl(&render, ioc(3, 0x41, 16), 0, &mut m).unwrap();
        let hoff = ru64(&m.buf, 0);
        let hb = render.mmap(hoff, 16384).unwrap();
        let Backing::Dev { mem, .. } = &hb else { panic!("host blob is device memory") };
        assert!(mem.gpa >= phys::PHYS_MAX);
        assert_eq!(mem.gpa & (phys::DEV_ALIGN - 1), 0);
        unsafe { phys.host(mem.gpa).write_bytes(0x5a, 16) };
        assert_eq!(unsafe { *phys.host(mem.gpa) }, 0x5a);

        // PRIME export and import onto the card node.
        m.buf[..12].fill(0);
        wu32(&mut m.buf, 0, host_handle);
        ioctl(&render, ioc(3, 0x2d, 12), 0, &mut m).unwrap();
        let dma_fd = ru32(&m.buf, 8) as i64;
        assert!(m.dma_of(dma_fd).is_ok());
        wu32(&mut m.buf, 8, dma_fd as u32);
        ioctl(&card, ioc(3, 0x2e, 12), 0, &mut m).unwrap();
        let imported = ru32(&m.buf, 0);
        assert!(imported >= 1);

        // Execbuffer fence-out is signaled (fake completes fences inline).
        m.buf[..40].fill(0);
        wu32(&mut m.buf, 0, EXEC_FENCE_OUT);
        ioctl(&render, ioc(3, 0x42, 40), 0, &mut m).unwrap();
        let sfd = ru32(&m.buf, 28) as i64;
        let sync = m.sync_of(sfd).unwrap();
        assert!(sync.ready());

        // Dumb buffer + ADDFB2 + atomic commit presents it.
        m.buf[..32].fill(0);
        wu32(&mut m.buf, 0, 4);
        wu32(&mut m.buf, 4, 4);
        wu32(&mut m.buf, 8, 32);
        ioctl(&card, ioc(3, 0xb2, 32), 0, &mut m).unwrap();
        let dumb = ru32(&m.buf, 16);
        m.buf[..104].fill(0);
        wu32(&mut m.buf, 4, 4);
        wu32(&mut m.buf, 8, 4);
        wu32(&mut m.buf, 20, dumb);
        ioctl(&card, ioc(3, 0xb8, 104), 0, &mut m).unwrap();
        let fb = ru32(&m.buf, 0);
        // one object, one prop FB_ID.
        wu32(&mut m.buf, 0x400, ID_PLANE);
        wu32(&mut m.buf, 0x410, 1);
        wu32(&mut m.buf, 0x420, P_FB_ID);
        wu64(&mut m.buf, 0x430, fb as u64);
        m.buf[..56].fill(0);
        wu32(&mut m.buf, 4, 1);
        wu64(&mut m.buf, 8, 0x400);
        wu64(&mut m.buf, 16, 0x410);
        wu64(&mut m.buf, 24, 0x420);
        wu64(&mut m.buf, 32, 0x430);
        wu32(&mut m.buf, 0, ATOMIC_ALLOW_MODESET);
        ioctl(&card, ioc(3, 0xbc, 56), 0, &mut m).unwrap();
        assert!(fake.flushed().contains(&card.gem(dumb).unwrap().res.id));
    }
}
