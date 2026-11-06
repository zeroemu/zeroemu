//! Memory syscalls: thin wrappers over the process's `AddressSpace`.

use super::{Kernel, Thread};
use crate::errno::*;
use crate::mm::{Backing, Placement, SharedObject, OnFork};
use crate::phys::PAGE;

const MAP_SHARED: u64 = 0x01;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_DONTFORK: u64 = 10;
const MADV_DOFORK: u64 = 11;
const MADV_WIPEONFORK: u64 = 18;
const MADV_KEEPONFORK: u64 = 19;
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
        // Bound first: a temporary fd table guard would live through the block,
        // and set_area takes the binder lock.
        let file = if flags & MAP_ANONYMOUS == 0 { t.files().get(fd).ok() } else { None };
        if let Some(f) = &file
            && let Some(b) = super::binder::mmap_area(f)
        {
            if prot & 2 != 0 {
                return -EPERM;
            }
            let len = len.min(super::binder::MAX_AREA);
            let mut mm = t.proc.mm();
            let a = match mm.map(place, len, 1, Backing::Anon) {
                Ok(a) => a,
                Err(e) => return -e,
            };
            mm.set_name(a, len, "/dev/binderfs/binder");
            // VM_DONTCOPY on Linux: a child has no business with these buffers.
            let _ = mm.set_on_fork(a, len, OnFork::Drop);
            drop(mm);
            return match super::binder::set_area(b, a, len) {
                Ok(()) => a as i64,
                Err(e) => -e,
            };
        }
        if flags & MAP_ANONYMOUS == 0
            && let Ok(f) = t.files().get(fd)
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
                // Private mappings, and read-only image files, share pages until written.
                _ => match self.fd_page_source(t, fd) {
                    Ok(src) => Backing::File { src, offset },
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
        const MREMAP_DONTUNMAP: u64 = 4;
        let may_move = flags & MREMAP_MAYMOVE != 0;
        if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 || (flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 && !may_move) {
            return -EINVAL;
        }
        let fixed = (flags & MREMAP_FIXED != 0).then_some(new_addr);
        match t.proc.mm().remap(crate::arch::untag(old), old_len, new_len, may_move, fixed, flags & MREMAP_DONTUNMAP != 0) {
            Ok(a) => a as i64,
            Err(e) => -e,
        }
    }

    /// Nothing to write back: writable files are memory, and shared mappings
    /// of them are that memory. dex2oat fails its compile if this fails.
    pub(super) fn sys_msync(&self, t: &Thread, addr: u64, len: u64, flags: u64) -> i64 {
        const MS_ASYNC: u64 = 1;
        const MS_INVALIDATE: u64 = 2;
        const MS_SYNC: u64 = 4;
        let start = crate::arch::untag(addr);
        if !start.is_multiple_of(PAGE) || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC {
            return -EINVAL;
        }
        let end = start.saturating_add(len.next_multiple_of(PAGE));
        if t.proc.mm().covered(start, end) { 0 } else { -ENOMEM }
    }

    /// mlock, munlock, mlock2: guest memory is never swapped, so only the range
    /// is checked. Nothing is faulted in, as PinnerService pins whole APKs.
    pub(super) fn sys_mlock(&self, t: &Thread, addr: u64, len: u64, flags: u64) -> i64 {
        const MLOCK_ONFAULT: u64 = 1;
        if flags & !MLOCK_ONFAULT != 0 {
            return -EINVAL;
        }
        let va = crate::arch::untag(addr);
        let start = va & !(PAGE - 1);
        let end = va.saturating_add(len).next_multiple_of(PAGE);
        if t.proc.mm().covered(start, end) { 0 } else { -ENOMEM }
    }

    pub(super) fn sys_mlockall(&self, flags: u64) -> i64 {
        const MCL_CURRENT: u64 = 1;
        const MCL_FUTURE: u64 = 2;
        const MCL_ONFAULT: u64 = 4;
        if flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 || flags == 0 || flags == MCL_ONFAULT {
            return -EINVAL;
        }
        0
    }

    pub(super) fn sys_mincore(&self, t: &Thread, addr: u64, len: u64, vec: u64) -> i64 {
        let start = crate::arch::untag(addr);
        if !start.is_multiple_of(PAGE) {
            return -EINVAL;
        }
        let end = start.saturating_add(len.next_multiple_of(PAGE));
        let mut mm = t.proc.mm();
        if !mm.covered(start, end) {
            return -ENOMEM;
        }
        let bytes = mm.residency(start, end);
        match mm.write(vec, &bytes) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    }

    pub(super) fn sys_madvise(&self, t: &Thread, addr: u64, len: u64, advice: u64) -> i64 {
        let on_fork = match advice {
            MADV_DONTFORK => Some(OnFork::Drop),
            MADV_WIPEONFORK => Some(OnFork::Wipe),
            MADV_DOFORK | MADV_KEEPONFORK => Some(OnFork::Copy),
            _ => None,
        };
        if let Some(on_fork) = on_fork {
            return match t.proc.mm().set_on_fork(crate::arch::untag(addr), len, on_fork) {
                Ok(()) => 0,
                Err(e) => -e,
            };
        }
        if matches!(advice, MADV_DONTNEED | MADV_FREE) {
            // Private mappings read back as zeros (or the file) afterwards.
            if let Err(e) = t.proc.mm().discard(crate::arch::untag(addr), len) {
                return -e;
            }
        }
        0
    }
}
