//! Memory syscalls: thin wrappers over the process's `AddressSpace`.

use super::{Kernel, Thread};
use crate::errno::*;
use crate::mm::{Backing, Placement};
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
        let backing = if flags & MAP_ANONYMOUS != 0 {
            if flags & MAP_SHARED != 0 && self.strace {
                // Treated as private until shared frames exist (ashmem, M3).
                eprintln!("[droidrt] note: MAP_SHARED|MAP_ANONYMOUS treated as private");
            }
            Backing::Anon
        } else {
            match self.fd_file_data(t, fd) {
                Ok(data) => Backing::File { data, offset },
                Err(e) => return -e,
            }
        };
        match t.proc.mm().map(place, len, prot & !PROT_IGNORED, backing) {
            Ok(a) => a as i64,
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
