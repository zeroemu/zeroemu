//! Guest physical memory, shared by every hypervisor backend.
//!
//! Guest VA == IPA/GPA (identity mapped by each backend's page tables):
//!
//!   0x0000_0000 .. 0x0020_0000   unmapped (catches NULL derefs)
//!   0x0020_0000 .. MMAP_BASE     ELF images + brk heap
//!   MMAP_BASE   .. STACK_TOP     anonymous mmap region, then the main stack
//!   KERNEL_BASE .. MEM_SIZE      backend-private: page tables, trap stubs

use std::ptr::NonNull;

/// Guest physical memory. Host pages are committed lazily, so untouched memory
/// is free; bionic's allocator alone reserves ~8.25 GiB of address space.
/// The Windows backend's page tables (a single page directory) and its
/// committed allocation keep it at 1 GiB until demand paging replaces the
/// identity map.
#[cfg(all(target_os = "macos", not(test)))]
pub const MEM_SIZE: u64 = 16 << 30;
#[cfg(not(all(target_os = "macos", not(test))))]
pub const MEM_SIZE: u64 = 1 << 30;
pub const BLOCK: u64 = 2 << 20;
pub const KERNEL_BASE: u64 = MEM_SIZE - 32 * BLOCK;
pub const MMAP_BASE: u64 = 0x2000_0000;
pub const STACK_TOP: u64 = KERNEL_BASE - BLOCK;
pub const STACK_SIZE: u64 = 8 << 20;

pub struct GuestMem {
    base: NonNull<u8>,
}

impl GuestMem {
    pub fn new() -> Self {
        GuestMem {
            base: os::reserve(MEM_SIZE as usize),
        }
    }

    pub fn host_ptr(&self) -> *mut u8 {
        self.base.as_ptr()
    }

    pub fn contains(&self, addr: u64, len: u64) -> bool {
        untag(addr).checked_add(len).is_some_and(|end| end <= KERNEL_BASE)
    }

    /// Host view of a guest (user) range; `None` becomes -EFAULT for the guest.
    #[allow(clippy::mut_from_ref)]
    pub fn slice(&self, addr: u64, len: u64) -> Option<&mut [u8]> {
        let addr = untag(addr);
        if !self.contains(addr, len) {
            return None;
        }
        Some(unsafe {
            std::slice::from_raw_parts_mut(self.host_ptr().add(addr as usize), len as usize)
        })
    }

    /// memmove within guest memory (ranges may overlap).
    pub fn copy_within(&self, src: u64, dst: u64, len: u64) -> bool {
        let (src, dst) = (untag(src), untag(dst));
        if !self.contains(src, len) || !self.contains(dst, len) {
            return false;
        }
        unsafe {
            std::ptr::copy(self.host_ptr().add(src as usize), self.host_ptr().add(dst as usize), len as usize)
        };
        true
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        match self.slice(addr, data.len() as u64) {
            Some(dst) => {
                dst.copy_from_slice(data);
                true
            }
            None => false,
        }
    }

    pub fn write_u64(&self, addr: u64, v: u64) -> bool {
        self.write(addr, &v.to_le_bytes())
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        self.slice(addr, 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }

    /// Reads a NUL-terminated guest string (at most 4 KiB, like PATH_MAX).
    pub fn read_cstr(&self, addr: u64) -> Option<String> {
        let mut out = Vec::new();
        for a in addr..addr + 4096 {
            match *self.slice(a, 1)?.first()? {
                0 => return Some(String::from_utf8_lossy(&out).into_owned()),
                b => out.push(b),
            }
        }
        None
    }

    /// Backend-only access to the reserved kernel area.
    pub fn kwrite<T: Copy>(&self, addr: u64, v: T) {
        assert!(addr >= KERNEL_BASE && addr + size_of::<T>() as u64 <= MEM_SIZE);
        unsafe { (self.host_ptr().add(addr as usize) as *mut T).write_unaligned(v) }
    }
}

impl Drop for GuestMem {
    fn drop(&mut self) {
        os::release(self.base, MEM_SIZE as usize);
    }
}

/// Strips an arm64 pointer tag (top byte). Android tags heap pointers and
/// passes them to syscalls under the tagged-address ABI; x86_64 has no tags.
pub fn untag(addr: u64) -> u64 {
    if cfg!(target_arch = "aarch64") { addr & 0x00ff_ffff_ffff_ffff } else { addr }
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
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert!(p != libc::MAP_FAILED, "failed to reserve guest memory");
        NonNull::new(p.cast()).unwrap()
    }

    pub fn release(p: NonNull<u8>, size: usize) {
        unsafe { libc::munmap(p.as_ptr().cast(), size) };
    }

    pub fn random(buf: &mut [u8]) {
        unsafe { libc::getentropy(buf.as_mut_ptr().cast(), buf.len()) };
    }
}

#[cfg(windows)]
mod os {
    use std::ptr::{self, NonNull};
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    };

    pub fn reserve(size: usize) -> NonNull<u8> {
        // Committed pages are zero-filled and only backed by RAM once touched.
        let p =
            unsafe { VirtualAlloc(ptr::null(), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        NonNull::new(p.cast()).expect("failed to reserve guest memory")
    }

    pub fn release(p: NonNull<u8>, _size: usize) {
        unsafe { VirtualFree(p.as_ptr().cast(), 0, MEM_RELEASE) };
    }

    pub fn random(buf: &mut [u8]) {
        unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
    }
}
