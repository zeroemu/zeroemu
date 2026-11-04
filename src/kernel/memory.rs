//! Memory syscalls: thin wrappers over the process's `AddressSpace`.

use super::{Kernel, Thread};
use crate::errno::*;
use crate::mm::{Backing, Placement, SharedObject};
use crate::phys::PAGE;

const MAP_SHARED: u64 = 0x01;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
/// PROT_GROWSDOWN / PROT_GROWSUP / arm64 PROT_BTI and PROT_MTE.
const PROT_IGNORED: u32 = 0x0100_0000 | 0x0200_0000 | 0x10 | 0x20;

impl Kernel {
    pub(super) fn sys_brk(&self, t: &Thread, want: u64) -> i64 {
        t.proc.mm().set_brk(want) as i64
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sys_mmap(&self, t: &Thread, addr: u64, len: u64, prot: u32, flags: u64, fd: i64, offset: u64) -> i64 {
        if len == 0 || !offset.is_multiple_of(PAGE) {
            return -EINVAL;
        }
        let place = if flags & MAP_FIXED_NOREPLACE != 0 {
            Placement::NoReplace(addr)
        } else if flags & MAP_FIXED != 0 {
            Placement::Fixed(addr)
        } else {
            Placement::Hint(addr)
        };
        // A binder fd's receive area: read-only to the process, filled by the driver.
        if flags & MAP_ANONYMOUS == 0
            && let Ok(f) = t.proc.files.lock().unwrap().get(fd)
            && let Some(b) = super::binder::mmap_area(&f)
        {
            if prot & 2 != 0 {
                return -EPERM;
            }
            let len = len.min(4 << 20);
            let mut mm = t.proc.mm();
            let a = match mm.map(place, len, 1, Backing::Anon) {
                Ok(a) => a,
                Err(e) => return -e,
            };
            mm.set_name(a, len, "/dev/binderfs/binder");
            drop(mm);
            return match super::binder::set_area(b, a, len) {
                Ok(()) => a as i64,
                Err(e) => -e,
            };
        }
        if flags & MAP_ANONYMOUS == 0
            && let Ok(f) = t.proc.files.lock().unwrap().get(fd)
        {
            let mapped = match &f.kind {
                super::files::Kind::Drm(d) => Some(d.mmap(offset, len)),
                super::files::Kind::DmaBuf(b) => Some(b.mmap(offset, len)),
                super::files::Kind::Ashmem(a) => Some(a.mmap(&self.phys, offset, len, prot, flags & MAP_SHARED != 0)),
                _ => None,
            };
            if let Some(mapped) = mapped {
                let backing = match mapped {
                    Ok(b) => b,
                    Err(e) => return -e,
                };
                let name = super::files::file_name(&f);
                let mut mm = t.proc.mm();
                return match mm.map(place, len, prot & !PROT_IGNORED, backing) {
                    Ok(a) => {
                        mm.set_name(a, len, &name);
                        a as i64
                    }
                    Err(e) => -e,
                };
            }
        }
        let shared = flags & MAP_SHARED != 0;
        let backing = if flags & MAP_ANONYMOUS != 0 {
            if shared { Backing::Shared { obj: SharedObject::new(self.phys.clone()), offset: 0 } } else { Backing::Anon }
        } else {
            match self.fd_shared_object(t, fd) {
                Ok(Some(obj)) if shared => Backing::Shared { obj, offset },
                Err(e) => return -e,
                // Private mappings, and read-only image files, get a copy.
                _ => match self.fd_file_data(t, fd) {
                    Ok(data) => Backing::File { data, offset },
                    Err(e) => return -e,
                },
            }
        };
        let name = if flags & MAP_ANONYMOUS == 0 { self.fd_name(t, fd) } else { None };
        let mut mm = t.proc.mm();
        match mm.map(place, len, prot & !PROT_IGNORED, backing) {
            Ok(a) => {
                if let Some(n) = name {
                    mm.set_name(a, len, &n);
                }
                a as i64
            }
            Err(e) => -e,
        }
    }

    pub(super) fn sys_munmap(&self, t: &Thread, addr: u64, len: u64) -> i64 {
        match t.proc.mm().unmap(crate::arch::untag(addr), len) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    }

    pub(super) fn sys_mprotect(&self, t: &Thread, addr: u64, len: u64, prot: u32) -> i64 {
        match t.proc.mm().protect(crate::arch::untag(addr), len, prot & !PROT_IGNORED) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    }

    pub(super) fn sys_mremap(&self, t: &Thread, old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) -> i64 {
        if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED) != 0 || (flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0) {
            return -EINVAL;
        }
        let fixed = (flags & MREMAP_FIXED != 0).then_some(new_addr);
        match t.proc.mm().remap(crate::arch::untag(old), old_len, new_len, flags & MREMAP_MAYMOVE != 0, fixed) {
            Ok(a) => a as i64,
            Err(e) => -e,
        }
    }

    pub(super) fn sys_madvise(&self, t: &Thread, addr: u64, len: u64, advice: u64) -> i64 {
        if matches!(advice, MADV_DONTNEED | MADV_FREE) {
            // Private mappings read back as zeros (or the file) afterwards.
            if let Err(e) = t.proc.mm().discard(crate::arch::untag(addr), len) {
                return -e;
            }
        }
        0
    }
}
