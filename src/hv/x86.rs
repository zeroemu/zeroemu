//! x86_64 tables shared by the Windows backend and the host-side unit tests.
//!
//! Long mode, identity-mapped with 2 MiB pages. The encodings are the on-wire
//! descriptor and page-table values; nothing here talks to a hypervisor.

#![cfg_attr(not(all(windows, target_arch = "x86_64")), allow(dead_code))]

use crate::mem::{BLOCK, KERNEL_BASE, MEM_SIZE};

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_LARGE: u64 = 1 << 7;
pub const PTE_NX: u64 = 1 << 63;

pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_PG: u64 = 1 << 31;
/// PE MP ET NE WP PG. EM and TS stay clear so ring 3 can use the FPU.
pub const CR0_LONG: u64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_PG;

pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_FSGSBASE: u64 = 1 << 16;
pub const CR4_OSXSAVE: u64 = 1 << 18;
/// Long mode plus the bits ring 3 needs for SSE. OSXSAVE is added only when
/// XCR0 is programmed, and FSGSBASE only when the processor feature is present.
pub const CR4_GUEST: u64 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;

/// `WHV_X64_PROCESSOR_FEATURES.RdWrFsGsSupport` (CPUID FSGSBASE). This is not
/// `CR4_FSGSBASE`; the capability bit and the CR4 bit are different positions.
pub const PROCESSOR_FEATURE_FSGSBASE: u64 = 1 << 22;

pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;
/// LME LMA NXE, with SCE clear so `syscall` is a #UD we can intercept.
pub const EFER_LONG: u64 = EFER_LME | EFER_LMA | EFER_NXE;
const _: () = assert!(EFER_LONG & EFER_SCE == 0);

pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_AVX: u64 = 1 << 2;

/// `WHV_PROCESSOR_XSAVE_FEATURES` bits whose state XCR0 below actually enables.
/// AVX-512 and AMX need further XCR0 bits; advertising them makes WHP reject
/// the virtual processor.
const XSAVE_XSAVE: u64 = 1 << 0;
const XSAVE_XSAVEOPT: u64 = 1 << 1;
const XSAVE_AVX: u64 = 1 << 2;
const XSAVE_AVX2: u64 = 1 << 3;
const XSAVE_FMA: u64 = 1 << 4;
const XSAVE_PROPERTY_MASK: u64 = XSAVE_XSAVE | XSAVE_XSAVEOPT | XSAVE_AVX | XSAVE_AVX2 | XSAVE_FMA;

/// Linux userspace x87 control word: all six exceptions masked, 64-bit precision.
pub const FCW_LINUX: u16 = 0x037F;
/// Linux / architectural MXCSR: SIMD exceptions masked, round-to-nearest.
pub const MXCSR_LINUX: u32 = 0x1F80;
/// MXCSR_MASK reported to the guest. Every exception-mask bit is writable.
pub const MXCSR_MASK: u32 = 0xFFFF;

/// Architectural PAT reset value: entry 0 is write-back.
pub const PAT_RESET: u64 = 0x0007_0406_0007_0406;
/// Reserved bit 1, plus IF. IOPL stays 0.
pub const RFLAGS_USER: u64 = 0x202;

pub const SEL_KCODE: u16 = 0x08;
pub const SEL_KDATA: u16 = 0x10;
pub const SEL_UDATA: u16 = 0x1B;
pub const SEL_UCODE: u16 = 0x23;
pub const SEL_TSS: u16 = 0x28;

pub const PML4: u64 = KERNEL_BASE;
pub const PDPT: u64 = KERNEL_BASE + 0x1000;
pub const PD: u64 = KERNEL_BASE + 0x2000;
pub const GDT_BASE: u64 = KERNEL_BASE + 0x3000;
pub const IDT_BASE: u64 = KERNEL_BASE + 0x4000;
pub const TSS_BASE: u64 = KERNEL_BASE + 0x5000;
pub const STUB: u64 = KERNEL_BASE + 0x6000;
/// Ring-0 stack for the `hlt` stubs. Grows down, still inside the first kernel page.
pub const RSP0: u64 = KERNEL_BASE + 0x8000;

pub const GDT_ENTRIES: u64 = 7;
pub const GDT_LIMIT: u16 = (GDT_ENTRIES * 8 - 1) as u16;
pub const IDT_LIMIT: u16 = 256 * 16 - 1;
pub const TSS_LIMIT: u32 = 103;
/// Present, 64-bit busy TSS (type 0xB). A loaded TR is busy.
pub const TSS_ACCESS: u8 = 0x8B;

pub const HLT: u8 = 0xF4;
pub const SYSCALL: [u8; 2] = [0x0F, 0x05];

const TABLE_FLAGS: u64 = PTE_PRESENT | PTE_WRITE | PTE_USER | PTE_ACCESSED;
const LEAF_FLAGS: u64 = PTE_PRESENT | PTE_WRITE | PTE_ACCESSED | PTE_DIRTY | PTE_LARGE;

/// Vectors intercepted before they reach the IDT.
///
/// Matches `WHV_EXCEPTION_TYPE`, including `#CP` (21). Bit 2 (NMI), 9, 15 and
/// 20 stay clear: they are not in that enum.
pub fn exception_exit_bitmap() -> u64 {
    const VECTORS: [u8; 18] = [
        0, 1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 21,
    ];
    let mut bits = 0u64;
    for vector in VECTORS {
        bits |= 1u64 << vector;
    }
    bits
}

/// CR4 value for a ring-3 long-mode guest. `fsgsbase` and `osxsave` are
/// independent: OSXSAVE requires a programmed XCR0, FSGSBASE requires the
/// processor feature.
pub fn cr4_guest(fsgsbase: bool, osxsave: bool) -> u64 {
    let mut cr4 = CR4_GUEST;
    if fsgsbase {
        cr4 |= CR4_FSGSBASE;
    }
    if osxsave {
        cr4 |= CR4_OSXSAVE;
    }
    cr4
}

/// Subset of a `WHvCapabilityCodeProcessorXsaveFeatures` mask to install as
/// `WHvPartitionPropertyCodeProcessorXsaveFeatures`. `None` when XSAVE itself
/// is absent, so the guest stays on FXSAVE.
pub fn xsave_property(features: u64) -> Option<u64> {
    if features & XSAVE_XSAVE == 0 {
        return None;
    }
    Some(features & XSAVE_PROPERTY_MASK)
}

/// XCR0 consistent with `xsave_property`: x87 and SSE always, AVX only when
/// that feature bit survived the mask. Bit 0 is mandatory.
pub fn xcr0_from_xsave(property: u64) -> u64 {
    let mut xcr0 = XCR0_X87 | XCR0_SSE;
    if property & XSAVE_AVX != 0 {
        xcr0 |= XCR0_AVX;
    }
    xcr0
}

/// `Some(rip)` when `len` bytes at `rip` lie entirely inside a guest of
/// `mem_size` bytes. Overflow and a range that runs off the end are `None`.
pub fn checked_range(mem_size: u64, rip: u64, len: u64) -> Option<u64> {
    let end = rip.checked_add(len)?;
    if end > mem_size { None } else { Some(rip) }
}

pub fn is_syscall(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == SYSCALL[0] && bytes[1] == SYSCALL[1]
}

/// Next-level table pointer. U/S is set so a user leaf under it stays reachable.
pub fn table_entry(next: u64) -> u64 {
    next | TABLE_FLAGS
}

/// Identity 2 MiB translation for page-directory index `index`.
pub fn pde_for_block(index: u64) -> u64 {
    let pa = index * BLOCK;
    if !(BLOCK..MEM_SIZE).contains(&pa) {
        return 0;
    }
    if pa >= KERNEL_BASE {
        // The stub shares the first kernel 2 MiB with the tables, so that
        // page stays executable. Every later kernel page is NX.
        let nx = if pa == KERNEL_BASE { 0 } else { PTE_NX };
        return pa | LEAF_FLAGS | nx;
    }
    pa | LEAF_FLAGS | PTE_USER
}

/// 8-byte code/data descriptor. `flags` is the high nibble (G D/B L AVL).
pub fn segment_descriptor(limit: u32, base: u64, access: u8, flags: u8) -> u64 {
    let limit_low = (limit & 0xFFFF) as u64;
    let limit_high = ((limit >> 16) & 0xF) as u64;
    let base_low = base & 0xFFFF;
    let base_mid = (base >> 16) & 0xFF;
    let base_high = (base >> 24) & 0xFF;
    limit_low
        | (base_low << 16)
        | (base_mid << 32)
        | ((access as u64) << 40)
        | (limit_high << 48)
        | ((flags as u64) << 52)
        | (base_high << 56)
}

/// Flat 64-bit code. DPL 0 is `0x00AF9A000000FFFF` (L=1, G=1, execute/read).
pub fn code64_descriptor(dpl: u8) -> u64 {
    segment_descriptor(0xF_FFFF, 0, 0x9A | (dpl << 5), 0xA)
}

/// Flat data, D/B=1 so a 32-bit stack pop still works if something drops out of long mode.
pub fn data_descriptor(dpl: u8) -> u64 {
    segment_descriptor(0xF_FFFF, 0, 0x92 | (dpl << 5), 0xC)
}

/// 16-byte system descriptor. The second qword is base\[63:32\].
pub fn system_descriptor(base: u64, limit: u32, access: u8) -> [u64; 2] {
    [
        segment_descriptor(limit, base & 0xFFFF_FFFF, access, 0),
        base >> 32,
    ]
}

/// Interrupt gate, IST 0, DPL 0, present. Selector is the ring-0 code segment.
pub fn interrupt_gate(target: u64, selector: u16) -> [u64; 2] {
    let low = (target & 0xFFFF)
        | ((selector as u64) << 16)
        | (0x8Eu64 << 40)
        | (((target >> 16) & 0xFFFF) << 48);
    [low, target >> 32]
}

/// Loaded code-segment attributes. Type is 0xB (accessed); the WHP long-mode
/// sample uses `0xA09B` for DPL 0. The GDT itself stores the not-yet-accessed form.
pub fn code_attributes(dpl: u16) -> u16 {
    0xA09B | (dpl << 5)
}

/// Loaded data-segment attributes: type 0x3, D/B, G. DPL 0 is `0xC093`.
pub fn data_attributes(dpl: u16) -> u16 {
    0xC093 | (dpl << 5)
}

pub fn tss_attributes() -> u16 {
    0x008B
}

pub fn tss_bytes(rsp0: u64) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes[4..12].copy_from_slice(&rsp0.to_le_bytes());
    // I/O map sits just past the structure, so there is no bitmap.
    bytes[0x66..0x68].copy_from_slice(&104u16.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_code_descriptor_matches_the_canonical_value() {
        assert_eq!(code64_descriptor(0), 0x00AF_9A00_0000_FFFF);
        assert_eq!(code64_descriptor(3), 0x00AF_FA00_0000_FFFF);
    }

    #[test]
    fn flat_data_descriptors() {
        assert_eq!(data_descriptor(0), 0x00CF_9200_0000_FFFF);
        assert_eq!(data_descriptor(3), 0x00CF_F200_0000_FFFF);
    }

    #[test]
    fn loaded_segment_attributes() {
        assert_eq!(code_attributes(0), 0xA09B);
        assert_eq!(code_attributes(3), 0xA0FB);
        assert_eq!(data_attributes(0), 0xC093);
        assert_eq!(data_attributes(3), 0xC0F3);
        assert_eq!(tss_attributes(), 0x008B);
    }

    #[test]
    fn tss_descriptor_splits_the_base() {
        assert_eq!(
            system_descriptor(0x1000, 0x67, 0x8B),
            [0x0000_8B00_1000_0067, 0]
        );
        let high = 0x0000_0001_2345_6780;
        let desc = system_descriptor(high, TSS_LIMIT, TSS_ACCESS);
        assert_eq!(desc[1], 0x1);
        assert_eq!(desc[0] & 0xFF, 0x67);
        assert_eq!((desc[0] >> 16) & 0xFFFF, 0x6780);
        assert_eq!((desc[0] >> 40) & 0xFF, 0x8B);
    }

    #[test]
    fn interrupt_gate_points_at_the_stub_selector() {
        assert_eq!(
            interrupt_gate(0x1000, SEL_KCODE),
            [0x0000_8E00_0008_1000, 0]
        );
        let gate = interrupt_gate(STUB, SEL_KCODE);
        assert_eq!(gate[0] & 0xFFFF, STUB & 0xFFFF);
        assert_eq!((gate[0] >> 16) & 0xFFFF, SEL_KCODE as u64);
        assert_eq!((gate[0] >> 40) & 0xFF, 0x8E);
        assert_eq!(gate[1], STUB >> 32);
    }

    #[test]
    fn long_mode_controls_leave_syscall_disabled() {
        assert_eq!(EFER_LONG, 0xD00);
        assert_eq!(EFER_LONG & EFER_SCE, 0);
        // PG PE WP NE MP ET. EM (bit 2) stays clear so the FPU is usable.
        assert_eq!(CR0_LONG, 0x8001_0033);
        assert_eq!(CR0_LONG & (1 << 2), 0);
        assert_eq!(CR4_GUEST, CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT);
        assert_eq!(cr4_guest(false, false), CR4_GUEST);
        assert_eq!(cr4_guest(true, false) & CR4_FSGSBASE, CR4_FSGSBASE);
        assert_eq!(cr4_guest(false, true) & CR4_OSXSAVE, CR4_OSXSAVE);
        assert_eq!(cr4_guest(false, false) & (CR4_FSGSBASE | CR4_OSXSAVE), 0);
        assert_eq!(PROCESSOR_FEATURE_FSGSBASE, 1 << 22);
        assert_ne!(PROCESSOR_FEATURE_FSGSBASE, CR4_FSGSBASE);
    }

    #[test]
    fn xsave_property_matches_the_xcr0_we_program() {
        assert_eq!(xsave_property(0), None);
        // AVX without XSAVE is not a usable feature mask.
        assert_eq!(xsave_property(1 << 2), None);
        let sse = xsave_property(1 << 0).unwrap();
        assert_eq!(sse, 1 << 0);
        assert_eq!(xcr0_from_xsave(sse), XCR0_X87 | XCR0_SSE);

        // Capability bits past FMA (AVX-512 at bit 6, AMX-TILE at bit 27) must
        // not be copied into the partition property.
        let host = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 6) | (1 << 27);
        let enabled = xsave_property(host).unwrap();
        assert_eq!(enabled & ((1 << 6) | (1 << 27)), 0);
        assert_eq!(enabled & (1 << 2), 1 << 2);
        let xcr0 = xcr0_from_xsave(enabled);
        assert_eq!(xcr0 & XCR0_X87, XCR0_X87);
        assert_eq!(xcr0, XCR0_X87 | XCR0_SSE | XCR0_AVX);
    }

    #[test]
    fn linux_fpu_masks_exceptions() {
        assert_eq!(FCW_LINUX & 0x3F, 0x3F);
        assert_eq!(MXCSR_LINUX & 0x1F80, 0x1F80);
        assert_eq!(MXCSR_MASK & 0x1F80, 0x1F80);
    }

    #[test]
    fn syscall_fetch_is_bounds_checked() {
        assert_eq!(checked_range(MEM_SIZE, 0, 2), Some(0));
        assert_eq!(checked_range(MEM_SIZE, MEM_SIZE - 2, 2), Some(MEM_SIZE - 2));
        assert_eq!(checked_range(MEM_SIZE, MEM_SIZE - 1, 2), None);
        assert_eq!(checked_range(MEM_SIZE, MEM_SIZE, 2), None);
        assert_eq!(checked_range(MEM_SIZE, u64::MAX, 2), None);
        assert_eq!(checked_range(MEM_SIZE, u64::MAX - 1, 2), None);
    }

    #[test]
    fn page_tables_split_user_kernel_and_the_null_page() {
        assert_eq!(pde_for_block(0), 0);
        let user = pde_for_block(1);
        assert_eq!(user & 0xFF, 0xE7);
        assert_eq!(user & !0xFFF, BLOCK);
        assert_eq!(user & PTE_NX, 0);

        let kernel = KERNEL_BASE / BLOCK;
        let exec = pde_for_block(kernel);
        assert_eq!(exec & PTE_USER, 0);
        assert_eq!(exec & PTE_NX, 0);
        assert_eq!(exec & !0xFFF, KERNEL_BASE);
        assert_ne!(exec & PTE_PRESENT, 0);

        let nx = pde_for_block(kernel + 1);
        assert_eq!(nx & PTE_USER, 0);
        assert_ne!(nx & PTE_NX, 0);
        assert_eq!(nx & !PTE_NX & !0xFFF, KERNEL_BASE + BLOCK);

        let table = table_entry(PD);
        assert_eq!(
            table & (PTE_PRESENT | PTE_WRITE | PTE_USER),
            PTE_PRESENT | PTE_WRITE | PTE_USER
        );
        assert_eq!(table & (PTE_LARGE | PTE_NX), 0);
        assert_eq!(table & !0xFFF, PD);
    }

    #[test]
    fn every_block_is_identity_mapped_once() {
        let mut present = 0;
        for i in 0..(MEM_SIZE / BLOCK) {
            let pte = pde_for_block(i);
            let pa = i * BLOCK;
            if pa < BLOCK {
                assert_eq!(pte, 0);
                continue;
            }
            present += 1;
            assert_eq!(pte & PTE_NX & !PTE_NX, 0);
            assert_eq!(pte & !PTE_NX & !0xFFF, pa);
            if pa >= KERNEL_BASE {
                assert_eq!(pte & PTE_USER, 0);
            } else {
                assert_ne!(pte & PTE_USER, 0);
                assert_eq!(pte & PTE_NX, 0);
            }
        }
        assert_eq!(present, MEM_SIZE / BLOCK - 1);
    }

    #[test]
    fn kernel_window_holds_the_stub_and_the_ring0_stack() {
        for addr in [PML4, PDPT, PD, GDT_BASE, IDT_BASE, TSS_BASE, STUB, RSP0] {
            assert!(addr >= KERNEL_BASE && addr < MEM_SIZE, "{addr:#x}");
            assert_eq!(addr & 0xF, 0);
        }
        assert!(STUB - KERNEL_BASE < BLOCK);
        assert!(RSP0 - KERNEL_BASE < BLOCK);
        assert!(RSP0 > STUB);
        assert_eq!(GDT_LIMIT, 55);
        assert!(is_syscall(&[0x0F, 0x05, 0x90]));
        assert!(!is_syscall(&[0x0F, 0x0B]));
        assert!(!is_syscall(&[0x0F]));
        let bitmap = exception_exit_bitmap();
        for vector in [0u8, 3, 6, 13, 14] {
            assert_ne!(bitmap & (1u64 << vector), 0);
        }
        assert_eq!(bitmap & (1 << 2), 0);
        assert_ne!(bitmap & (1 << 21), 0);
        for reserved in [9u8, 15, 20] {
            assert_eq!(bitmap & (1u64 << reserved), 0, "vector {reserved}");
        }
        let tss = tss_bytes(RSP0);
        assert_eq!(u64::from_le_bytes(tss[4..12].try_into().unwrap()), RSP0);
        assert_eq!(u16::from_le_bytes(tss[0x66..0x68].try_into().unwrap()), 104);
    }
}
