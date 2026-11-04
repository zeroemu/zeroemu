//! Guest physical memory: one large host reservation, committed and handed to
//! the hypervisor in chunks as frames are needed, carved into 4 KiB frames.
//! Untouched memory costs nothing on either host.

use crate::errno::ENOMEM;
use crate::hv::Hypervisor;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

pub const PAGE: u64 = 4096;
/// Guest RAM ceiling: fits the default 36-bit IPA space of Apple Silicon.
pub const PHYS_MAX: u64 = 32 << 30;
/// IPA width this HVF configuration advertises (TCR_EL1.IPS). Device memory
/// (GPU blobs) is mapped above `PHYS_MAX` and must stay inside it.
pub const IPA_BITS: u32 = 36;
/// Hypervisor.framework maps only 16 KiB-aligned host, GPA and size.
pub const DEV_ALIGN: u64 = 16 << 10;
const CHUNK: u64 = 64 << 20;

pub struct PhysMem {
    base: NonNull<u8>,
    hv: Arc<dyn Hypervisor>,
    alloc: Mutex<Alloc>,
    /// Host mappings installed above `PHYS_MAX` (not frames of `base`).
    ext: Mutex<Ext>,
}

struct Alloc {
    /// Guest-physical end of the memory mapped into the VM so far.
    mapped: u64,
    /// Next never-used frame (fresh frames are already zero).
    bump: u64,
    /// Freed frames, zeroed again when reused.
    free: Vec<u64>,
}

struct Ext {
    /// Next GPA to try, 16 KiB aligned, at or above `PHYS_MAX`.
    bump: u64,
    free: Vec<(u64, u64)>,
    live: Vec<ExtRange>,
}

struct ExtRange {
    gpa: u64,
    size: u64,
    host: usize,
}

// The reservation is plain memory shared by all guest threads; frame
// ownership is tracked by the address spaces.
unsafe impl Send for PhysMem {}
unsafe impl Sync for PhysMem {}

impl PhysMem {
    pub fn new(hv: Arc<dyn Hypervisor>) -> Arc<PhysMem> {
        Arc::new(PhysMem {
            base: os::reserve(PHYS_MAX as usize),
            hv,
            // Frame 0 is never handed out, so 0 can mean "no frame".
            alloc: Mutex::new(Alloc { mapped: 0, bump: PAGE, free: Vec::new() }),
            ext: Mutex::new(Ext { bump: PHYS_MAX, free: Vec::new(), live: Vec::new() }),
        })
    }

    /// Maps already-allocated host memory into the IPA space above RAM.
    /// `host` and `size` are rounded up to `DEV_ALIGN` (HVF's requirement);
    /// the returned GPA is aligned the same way. The range stays mapped until
    /// `unmap_external`.
    pub fn map_external(&self, host: *mut u8, size: u64) -> Result<u64, i64> {
        if host.is_null() || (host as u64) & (DEV_ALIGN - 1) != 0 || size == 0 {
            return Err(crate::errno::EINVAL);
        }
        let size = size.div_ceil(DEV_ALIGN) * DEV_ALIGN;
        let mut ext = self.ext.lock().unwrap();
        let gpa = if let Some(i) = ext.free.iter().position(|&(_, n)| n == size) {
            ext.free.swap_remove(i).0
        } else {
            let gpa = ext.bump;
            let end = gpa.checked_add(size).ok_or(crate::errno::ENOMEM)?;
            if end > 1u64 << IPA_BITS {
                return Err(crate::errno::ENOMEM);
            }
            ext.bump = end;
            gpa
        };
        if let Err(e) = self.hv.map_ram(host, gpa, size) {
            ext.free.push((gpa, size));
            eprintln!("[droidrt] device memory: {e}");
            return Err(crate::errno::ENOMEM);
        }
        ext.live.push(ExtRange { gpa, size, host: host as usize });
        Ok(gpa)
    }

    pub fn unmap_external(&self, gpa: u64) {
        let mut ext = self.ext.lock().unwrap();
        let Some(i) = ext.live.iter().position(|r| r.gpa == gpa) else { return };
        let range = ext.live.swap_remove(i);
        if let Err(e) = self.hv.unmap_ram(range.gpa, range.size) {
            eprintln!("[droidrt] device memory unmap: {e}");
        }
        ext.free.push((range.gpa, range.size));
    }

    /// A zeroed frame.
    pub fn alloc(&self) -> Result<u64, i64> {
        let mut a = self.alloc.lock().unwrap();
        if let Some(gpa) = a.free.pop() {
            drop(a);
            unsafe { self.host(gpa).write_bytes(0, PAGE as usize) };
            return Ok(gpa);
        }
        if a.bump + PAGE > a.mapped {
            if a.mapped + CHUNK > PHYS_MAX {
                return Err(ENOMEM);
            }
            let host = unsafe { self.base.as_ptr().add(a.mapped as usize) };
            os::commit(host, CHUNK as usize);
            if let Err(e) = self.hv.map_ram(host, a.mapped, CHUNK) {
                eprintln!("[droidrt] guest RAM: {e}");
                return Err(ENOMEM);
            }
            a.mapped += CHUNK;
        }
        let gpa = a.bump;
        a.bump += PAGE;
        Ok(gpa)
    }

    pub fn free(&self, gpa: u64) {
        debug_assert!(gpa != 0 && gpa.is_multiple_of(PAGE));
        self.alloc.lock().unwrap().free.push(gpa);
    }

    /// Host address of guest-physical `gpa` (a RAM frame, or a device mapping).
    pub fn host(&self, gpa: u64) -> *mut u8 {
        if gpa < PHYS_MAX {
            return unsafe { self.base.as_ptr().add(gpa as usize) };
        }
        let ext = self.ext.lock().unwrap();
        let range = ext.live.iter().find(|r| (r.gpa..r.gpa + r.size).contains(&gpa)).expect("device gpa");
        unsafe { (range.host as *mut u8).add((gpa - range.gpa) as usize) }
    }

    pub fn read_u64(&self, gpa: u64) -> u64 {
        unsafe { (self.host(gpa) as *const u64).read() }
    }

    pub fn write_u64(&self, gpa: u64, v: u64) {
        unsafe { (self.host(gpa) as *mut u64).write(v) }
    }

    /// Frames in use (for diagnostics).
    pub fn frames_in_use(&self) -> u64 {
        let a = self.alloc.lock().unwrap();
        a.bump / PAGE - 1 - a.free.len() as u64
    }
}

pub fn random_bytes(buf: &mut [u8]) {
    os::random(buf)
}

#[cfg(unix)]
mod os {
    use std::ptr::{self, NonNull};

    pub fn reserve(size: usize) -> NonNull<u8> {
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert!(p != libc::MAP_FAILED, "failed to reserve guest memory");
        NonNull::new(p.cast()).unwrap()
    }

    /// Anonymous private memory is committed by first touch.
    pub fn commit(_p: *mut u8, _size: usize) {}

    pub fn random(buf: &mut [u8]) {
        for chunk in buf.chunks_mut(256) {
            unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        }
    }
}

#[cfg(windows)]
mod os {
    use std::ptr::{self, NonNull};
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc};

    pub fn reserve(size: usize) -> NonNull<u8> {
        let p = unsafe { VirtualAlloc(ptr::null(), size, MEM_RESERVE, PAGE_NOACCESS) };
        NonNull::new(p.cast()).expect("failed to reserve guest memory")
    }

    /// Commit charge is taken only for chunks actually in use.
    pub fn commit(p: *mut u8, size: usize) {
        let r = unsafe { VirtualAlloc(p.cast(), size, MEM_COMMIT, PAGE_READWRITE) };
        assert!(!r.is_null(), "failed to commit guest memory");
    }

    pub fn random(buf: &mut [u8]) {
        unsafe {
            BCryptGenRandom(ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
    }
}
