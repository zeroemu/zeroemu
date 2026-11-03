//! Page-table entry formats. Both architectures use 4 KiB pages and 512-entry
//! tables; arm64 walks 3 levels (39-bit VA, like Android's GKI kernels) and
//! x86_64 walks 4 (48-bit VA).
//!
//! Layout shared by both: user space below `USER_TOP`; the top GiB of the
//! lower 512 GiB is the kernel window holding backend trap stubs.

use crate::arch::Arch;

pub const USER_TOP: u64 = 0x7f_c000_0000;
pub const KERNEL_WINDOW: u64 = USER_TOP;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

pub fn levels() -> usize {
    match Arch::HOST {
        Arch::Aarch64 => 3,
        Arch::X86_64 => 4,
    }
}

/// Table index of `va` at `level` (0 = top).
pub fn index(va: u64, level: usize) -> usize {
    let shift = 12 + 9 * (levels() - 1 - level);
    ((va >> shift) & 511) as usize
}

/// Level whose entries each cover 1 GiB (where the kernel window attaches).
pub fn gib_level() -> usize {
    levels() - 3
}

pub fn is_valid(e: u64) -> bool {
    e & 1 != 0
}

pub fn addr(e: u64) -> u64 {
    e & ADDR_MASK
}

pub fn table(gpa: u64) -> u64 {
    match Arch::HOST {
        Arch::Aarch64 => gpa | 0b11,
        // Present | writable | user: leaf entries decide the real permissions.
        Arch::X86_64 => gpa | 0x7,
    }
}

/// A user page with `prot`. PROT_NONE pages stay mapped but kernel-only, so
/// their contents survive until mprotect makes them accessible again.
pub fn user_page(gpa: u64, prot: u32) -> u64 {
    let user = prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0;
    let write = prot & PROT_WRITE != 0;
    let exec = prot & PROT_EXEC != 0;
    match Arch::HOST {
        Arch::Aarch64 => {
            const PAGE: u64 = 0b11;
            const SH_INNER: u64 = 0b11 << 8;
            const AF: u64 = 1 << 10;
            const NG: u64 = 1 << 11; // tagged with the ASID
            const PXN: u64 = 1 << 53;
            const UXN: u64 = 1 << 54;
            let ap = match (user, write) {
                (false, _) => 0b00,    // EL1 only
                (true, true) => 0b01,  // EL0+EL1 read/write
                (true, false) => 0b11, // EL0+EL1 read-only
            } << 6;
            let uxn = if user && exec { 0 } else { UXN };
            gpa | PAGE | SH_INNER | AF | NG | PXN | uxn | ap
        }
        Arch::X86_64 => {
            const P: u64 = 1;
            const RW: u64 = 2;
            const US: u64 = 4;
            const A: u64 = 0x20;
            const D: u64 = 0x40;
            const NX: u64 = 1 << 63;
            let mut e = gpa | P | A | D;
            if user {
                e |= US;
            }
            if write {
                e |= RW;
            }
            if !exec {
                e |= NX;
            }
            e
        }
    }
}

/// Whether an existing user entry already permits the access (if so, a fault
/// on it came from a stale TLB entry).
pub fn permits(e: u64, write: bool, exec: bool) -> bool {
    if !is_valid(e) {
        return false;
    }
    match Arch::HOST {
        Arch::Aarch64 => {
            let ap = (e >> 6) & 3;
            let user = ap & 1 != 0;
            let writable = ap == 0b01;
            let uexec = e & (1 << 54) == 0;
            user && (!write || writable) && (!exec || uexec)
        }
        Arch::X86_64 => {
            let user = e & 4 != 0;
            let writable = e & 2 != 0;
            let nx = e & (1 << 63) != 0;
            user && (!write || writable) && (!exec || !nx)
        }
    }
}

/// A kernel-window page: privileged-only, global (never ASID-tagged).
pub fn kernel_page(gpa: u64, exec: bool) -> u64 {
    match Arch::HOST {
        Arch::Aarch64 => {
            const PAGE: u64 = 0b11;
            const SH_INNER: u64 = 0b11 << 8;
            const AF: u64 = 1 << 10;
            const PXN: u64 = 1 << 53;
            const UXN: u64 = 1 << 54;
            gpa | PAGE | SH_INNER | AF | UXN | if exec { 0 } else { PXN }
        }
        Arch::X86_64 => gpa | 0x1 | 0x20 | 0x40 | if exec { 0 } else { 0x2 | 1 << 63 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_cover_the_va() {
        let va = 0x12_3456_7000u64;
        let rebuilt: u64 = (0..levels()).map(|l| (index(va, l) as u64) << (12 + 9 * (levels() - 1 - l))).sum();
        assert_eq!(rebuilt, va);
        assert_eq!(index(KERNEL_WINDOW, gib_level()), 511);
    }

    #[test]
    fn user_permissions_round_trip() {
        let rw = user_page(0x5000, PROT_READ | PROT_WRITE);
        assert!(permits(rw, true, false) && !permits(rw, false, true));
        let rx = user_page(0x5000, PROT_READ | PROT_EXEC);
        assert!(permits(rx, false, true) && !permits(rx, true, false));
        let none = user_page(0x5000, 0);
        assert!(is_valid(none) && !permits(none, false, false));
        assert_eq!(addr(rw), 0x5000);
    }
}
