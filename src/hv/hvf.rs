//! macOS backend: Hypervisor.framework on Apple Silicon.
//!
//! The guest runs at EL0 under page tables built by `mm`. EL1 holds only the
//! kernel window: a vector table whose every entry exits to us with `hvc`, and
//! TLB-flush trampolines. The entry for exceptions from EL0 tells an svc from
//! anything else and follows its hvc with an `eret`, so that a syscall's exit reads
//! no EL1 register and the vCPU goes back to EL0 by itself when it next runs. After
//! page-table changes it goes back through a trampoline instead, which invalidates the
//! address space's translations (`tlbi aside1is`) or one page's (`tlbi vale1is`),
//! broadcast to every vCPU, and `eret`s to EL0.

use super::hvf_sys::*;
use super::{Aarch64State, CpuState, Exit, Hypervisor, KernelPage, Kick, PageTableRoot, SyscallRegs, TlbFlush, Vcpu};
use crate::paging::KERNEL_WINDOW;
use std::ptr;
use std::sync::Arc;

const VECTORS: u64 = KERNEL_WINDOW;
/// Flushes the current address space (its ASID, from TTBR0_EL1).
const TLB_FLUSH: u64 = KERNEL_WINDOW + 0x800;
/// Flushes one page: the `tlbi` operand (ASID and page number) is in SP_EL1,
/// which nothing else at EL1 uses.
const TLB_FLUSH_PAGE: u64 = KERNEL_WINDOW + 0x840;
/// TLB_FLUSH for the kernel's own use: comes back with `hvc` instead of going
/// on to EL0.
const TLB_FLUSH_NOW: u64 = KERNEL_WINDOW + 0x880;
const TLB_FLUSH_END: u64 = KERNEL_WINDOW + 0x8c0;
/// Past the entries of the vector table, whose only EL1 code is `hvc`.
const VECTORS_END: u64 = KERNEL_WINDOW + 0x800;

/// Vector index for "synchronous exception from lower EL, AArch64", and the
/// immediate of its hvc for anything but an svc.
const VEC_LOWER_SYNC: u64 = 8;
/// That vector's hvc immediate for an svc: its exception class.
const HVC_SYSCALL: u64 = EC_SVC64;
/// That vector's two `eret`s, one after each hvc. A vCPU stopped at one goes back
/// to EL0 at ELR_EL1, with SPSR_EL1, when it next runs.
const STUB_ERETS: [u64; 2] = [VECTORS + VEC_LOWER_SYNC * 0x80 + 7 * 4, VECTORS + VEC_LOWER_SYNC * 0x80 + 9 * 4];

const EC_INSTR_ABORT_LOWER: u64 = 0x20;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;
const ESR_WNR: u64 = 1 << 6;
/// The abort came from a cache maintenance instruction (DC CVAU, IC IVAU...),
/// which reports WnR = 1; Linux counts it as a read (is_write_abort), so
/// cleaning the cache over read-only code works.
const ESR_CM: u64 = 1 << 8;
/// A data abort's fault status code: translation, access flag and permission faults
/// (levels 0 to 3 of each) are what a page table can answer, and alignment isn't.
const ESR_DFSC: u64 = 0x3f;
const DFSC_PAGING: std::ops::RangeInclusive<u64> = 0b000100..=0b001111;
const DFSC_ALIGNMENT: u64 = 0b100001;

const CPSR_EL1H_MASKED: u64 = 0x3c5;
const CPSR_MODE_MASK: u64 = 0xf;

/// ZEROEMU_WATCHDOG=<secs>, read once: every kick's exit and every new vCPU look.
fn watchdog() -> Option<u64> {
    static SECS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *SECS.get_or_init(|| std::env::var("ZEROEMU_WATCHDOG").ok().and_then(|s| s.parse().ok()))
}

pub struct Hvf;

impl Hvf {
    /// The process's VM. Hypervisor.framework allows one per process.
    pub fn new() -> Result<Self, crate::Problem> {
        let ret = vm_create();
        if ret != HV_SUCCESS {
            return Err(no_vm(ret));
        }
        Ok(Hvf)
    }

    /// Creates a VM and destroys it again: whether this process may have one.
    pub fn probe() -> Result<(), crate::Problem> {
        let ret = vm_create();
        if ret != HV_SUCCESS {
            return Err(no_vm(ret));
        }
        unsafe { hv_vm_destroy() };
        Ok(())
    }
}

/// hv_vm_create, with every signal blocked while it runs. It starts
/// Hypervisor.framework's virtual-clock thread
/// (com.apple.virtualization.thread.virtual-clock), which keeps the signal mask of
/// the thread that called it. Were SIGINT, SIGTERM or SIGHUP open there, macOS
/// could hand Ctrl-C or a kill to that thread, whose default action ends zeroemu
/// before the thread that saves /data sees the signal. Blocked there, they go to
/// zeroemu's own threads, whatever order main sets their masks in.
fn vm_create() -> hv_return_t {
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        let ret = hv_vm_create(ptr::null_mut());
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut());
        ret
    }
}

/// Why hv_vm_create refused, and what to do about it.
fn no_vm(ret: hv_return_t) -> crate::Problem {
    match ret {
        HV_DENIED => {
            let exe = std::env::current_exe().map(|p| crate::sdk::shell_quote(&p.to_string_lossy())).unwrap_or_else(|_| "zeroemu".into());
            crate::Problem::new(
                "this binary isn't signed with the hypervisor entitlement (com.apple.security.hypervisor), so macOS won't let it create a VM",
                [
                    format!("codesign -s - -f --entitlements entitlements.plist {exe}"),
                    "(entitlements.plist is in the release archive and in the repository)".into(),
                ],
            )
        }
        HV_UNSUPPORTED => crate::Problem::new(
            "hardware virtualization isn't available here, as inside a VM or on a CI runner (hv_vm_create: HV_UNSUPPORTED)",
            ["run zeroemu on a Mac with Apple Silicon, outside any VM"],
        ),
        _ => crate::Problem::new(
            format!("hardware virtualization isn't available (hv_vm_create returned {ret:#x}), as happens inside a VM or on a CI runner"),
            ["run zeroemu on a Mac with Apple Silicon, outside any VM"],
        ),
    }
}

impl Hypervisor for Hvf {
    fn map_ram(&self, host: *mut u8, gpa: u64, size: u64) -> Result<(), String> {
        let ret = unsafe { hv_vm_map(host.cast(), gpa, size as usize, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC) };
        if ret != HV_SUCCESS {
            return Err(format!("hv_vm_map({gpa:#x}, {size:#x}) failed ({ret:#x})"));
        }
        Ok(())
    }

    fn unmap_ram(&self, gpa: u64, size: u64) -> Result<(), String> {
        let ret = unsafe { hv_vm_unmap(gpa, size as usize) };
        if ret != HV_SUCCESS {
            return Err(format!("hv_vm_unmap({gpa:#x}, {size:#x}) failed ({ret:#x})"));
        }
        Ok(())
    }

    fn kernel_pages(&self, alloc: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage> {
        let (gpa, host) = alloc();
        let put = |off: u64, insn: u32| unsafe { (host.add(off as usize) as *mut u32).write(insn) };
        const HVC: u32 = 0xd400_0002; // hvc #0; the immediate goes in bits 20:5
        const ERET: u32 = 0xd69f_03e0;
        // EL1 code uses x0 alone, kept meanwhile in TPIDR_EL1 (which EL0 can't
        // reach), where back_to_el0 finds it if a kick lands in a trampoline.
        const SAVE_X0: u32 = 0xd518_d080; // msr tpidr_el1, x0
        const RESTORE_X0: u32 = 0xd538_d080; // mrs x0, tpidr_el1
        for n in 0..16u32 {
            put(n as u64 * 0x80, HVC | n << 5); // hvc #n
        }
        // An exception from EL0. Reading an EL1 register after an exit, or writing
        // PC and CPSR, costs about 20 ns each (measured on an M1 Pro, against about
        // 0.9 us for the exit itself), and a syscall's exit needs none of them if the
        // svc is sorted out here and its eret done here.
        let lower_sync = [
            SAVE_X0,
            0xd538_5200, // mrs x0, esr_el1
            0xd35a_fc00, // lsr x0, x0, #26 (the exception class)
            0xf100_541f, // cmp x0, #0x15 (svc)
            RESTORE_X0,
            0x5400_0061, // b.ne +3
            HVC | (HVC_SYSCALL as u32) << 5,
            ERET,
            HVC | (VEC_LOWER_SYNC as u32) << 5,
            ERET,
        ];
        for (i, insn) in lower_sync.iter().enumerate() {
            put(VEC_LOWER_SYNC * 0x80 + i as u64 * 4, *insn);
        }
        // Only the address space's own translations: every caller flushes for
        // changes to its own page tables, and the kernel window's entries are
        // global and never change. arm64 Linux's flush_tlb_mm and flush_tlb_page
        // (arch/arm64/include/asm/tlbflush.h) do the same.
        let asid = [
            SAVE_X0,
            0xd538_2000, // mrs x0, ttbr0_el1
            0x9250_3c00, // and x0, x0, #0xffff000000000000 (the ASID)
            0xd503_3a9f, // dsb ishst
            0xd508_8340, // tlbi aside1is, x0
            0xd503_3b9f, // dsb ish
            0xd503_3fdf, // isb
            RESTORE_X0,
        ];
        let page = [
            SAVE_X0,
            0x9100_03e0, // mov x0, sp (SP_EL1)
            0xd503_3a9f, // dsb ishst
            0xd508_83a0, // tlbi vale1is, x0
            0xd503_3b9f, // dsb ish
            0xd503_3fdf, // isb
            RESTORE_X0,
        ];
        let code: [(u64, &[u32]); 3] = [
            (TLB_FLUSH, &[&asid[..], &[ERET]].concat()),
            (TLB_FLUSH_PAGE, &[&page[..], &[ERET]].concat()),
            (TLB_FLUSH_NOW, &[&asid[..], &[HVC | 16 << 5]].concat()),
        ];
        for (at, insns) in code {
            for (i, insn) in insns.iter().enumerate() {
                put(at - KERNEL_WINDOW + i as u64 * 4, *insn);
            }
        }
        vec![KernelPage { va: KERNEL_WINDOW, gpa, exec: true }]
    }

    fn create_vcpu(&self, root: PageTableRoot, state: &CpuState) -> Result<Box<dyn Vcpu>, String> {
        let mut id = 0;
        let mut exit = ptr::null();
        let ret = unsafe { hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(format!("hv_vcpu_create failed ({ret:#x})"));
        }
        // No flush on the way in: what a TLB may still hold for its address space is
        // the run loop's business (TlbGen), which makes a new address space flush
        // before anything runs in it.
        let mut v = HvfVcpu { id, exit, flush_pending: None, asid: 0 };
        if let Some(secs) = watchdog() {
            // Debug aid: force an exit after `secs` so a guest stuck without
            // trapping (e.g. an EL1 exception loop) gets its state dumped.
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                unsafe { hv_vcpus_exit(&id, 1) };
            });
        }

        // MAIR: attr0 = normal write-back, attr1 = device-nGnRnE.
        v.set_sys(HV_SYS_REG_MAIR_EL1, 0x00ff);
        // T0SZ=25 (39-bit VA), cacheable inner-shareable walks, 4K granule,
        // TTBR1 walks disabled, 36-bit IPA, 16-bit ASIDs, and TBI0
        // (top-byte-ignore), which Linux always enables for EL0: Android tags
        // heap pointers.
        let tcr = 25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (1 << 32) | (1 << 36) | (1 << 37);
        v.set_sys(HV_SYS_REG_TCR_EL1, tcr);
        v.set_sys(HV_SYS_REG_VBAR_EL1, VECTORS);
        v.set_sys(HV_SYS_REG_CPACR_EL1, 3 << 20); // FP/SIMD at EL0
        // EL0 may read the virtual counter and frequency (bionic's clock
        // fast path).
        v.set_sys(HV_SYS_REG_CNTKCTL_EL1, 1 << 1);
        let sctlr_res1 = (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23) | (1 << 28) | (1 << 29);
        let sctlr = sctlr_res1
            | (1 << 0)   // M: MMU on
            | (1 << 2)   // C: data cache
            | (1 << 12)  // I: instruction cache
            | (1 << 14)  // DZE: EL0 may use DC ZVA
            | (1 << 15)  // UCT: EL0 may read CTR_EL0
            | (1 << 16)  // nTWI
            | (1 << 18)  // nTWE
            | (1 << 26); // UCI: EL0 cache maintenance
        v.set_sys(HV_SYS_REG_SCTLR_EL1, sctlr);
        v.set_page_tables(root);
        v.set_state(state);
        Ok(Box::new(v))
    }

    fn max_vcpus(&self) -> usize {
        let mut n = 0u32;
        unsafe { hv_vm_get_max_vcpu_count(&mut n) };
        if n == 0 { 64 } else { n as usize }
    }
}

struct HvfVcpu {
    id: hv_vcpu_t,
    exit: *const hv_vcpu_exit_t,
    /// Enter through a TLB-flush trampoline on the next run: AddressSpace or
    /// Now for TLB_FLUSH, Page for TLB_FLUSH_PAGE with this `tlbi` operand.
    flush_pending: Option<(TlbFlush, u64)>,
    /// Its address space's id, as in TTBR0_EL1.
    asid: u16,
}

/// Where a kick's exit found the vCPU.
enum Kicked {
    /// At EL0, or at a stub's eret: as good as EL0.
    El0,
    /// In a vector, before its hvc.
    BeforeHvc,
    /// In a TLB-flush trampoline.
    Trampoline,
}

struct HvfKick(hv_vcpu_t);

impl Kick for HvfKick {
    fn kick(&self) {
        unsafe { hv_vcpus_exit(&self.0, 1) };
    }
}

impl HvfVcpu {
    fn reg(&self, r: u32) -> u64 {
        let mut v = 0;
        check("hv_vcpu_get_reg", unsafe { hv_vcpu_get_reg(self.id, r, &mut v) });
        v
    }
    fn set_reg(&self, r: u32, v: u64) {
        check("hv_vcpu_set_reg", unsafe { hv_vcpu_set_reg(self.id, r, v) });
    }
    fn sys(&self, r: u16) -> u64 {
        let mut v = 0;
        check("hv_vcpu_get_sys_reg", unsafe { hv_vcpu_get_sys_reg(self.id, r, &mut v) });
        v
    }
    fn set_sys(&self, r: u16, v: u64) {
        check("hv_vcpu_set_sys_reg", unsafe { hv_vcpu_set_sys_reg(self.id, r, v) });
    }

    /// Where a kick's exit found the vCPU.
    fn kicked_at(&self) -> Kicked {
        if self.reg(HV_REG_CPSR) & CPSR_MODE_MASK == 0 {
            return Kicked::El0;
        }
        match self.reg(HV_REG_PC) {
            pc if STUB_ERETS.contains(&pc) => Kicked::El0,
            pc if pc < VECTORS_END => Kicked::BeforeHvc,
            _ => Kicked::Trampoline,
        }
    }

    /// The kick caught the vCPU inside a TLB-flush trampoline: rewind to the EL0
    /// resume point and redo the flush next time.
    fn back_to_el0(&mut self) {
        let pc = self.reg(HV_REG_PC);
        // Past its first instruction, the guest's x0 is in TPIDR_EL1.
        if (TLB_FLUSH..TLB_FLUSH_END).contains(&pc) && ![TLB_FLUSH, TLB_FLUSH_PAGE].contains(&pc) {
            self.set_reg(HV_REG_X0, self.sys(HV_SYS_REG_TPIDR_EL1));
        }
        self.set_reg(HV_REG_PC, self.sys(HV_SYS_REG_ELR_EL1));
        self.set_reg(HV_REG_CPSR, self.sys(HV_SYS_REG_SPSR_EL1));
        self.flush_tlb();
    }
}

impl Vcpu for HvfVcpu {
    fn run(&mut self) -> Exit {
        loop {
            if let Some((why, operand)) = self.flush_pending.take() {
                why.count();
                // Stopped at a stub's eret, ELR_EL1 and SPSR_EL1 already say where to
                // go back to in EL0, as the trampoline's own eret wants. A vCPU at EL0
                // (new, or given new registers) has them set here, which costs more:
                // Hypervisor.framework loads EL1 registers written from the host on
                // the next entry.
                if self.reg(HV_REG_CPSR) & CPSR_MODE_MASK == 0 {
                    self.set_sys(HV_SYS_REG_ELR_EL1, self.reg(HV_REG_PC));
                    self.set_sys(HV_SYS_REG_SPSR_EL1, self.reg(HV_REG_CPSR));
                    self.set_reg(HV_REG_CPSR, CPSR_EL1H_MASKED);
                }
                let at = match why {
                    TlbFlush::Page => {
                        self.set_sys(HV_SYS_REG_SP_EL1, operand);
                        TLB_FLUSH_PAGE
                    }
                    _ => TLB_FLUSH,
                };
                self.set_reg(HV_REG_PC, at);
            }
            check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) });
            let exit = unsafe { *self.exit };
            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {}
                HV_EXIT_REASON_CANCELED if watchdog().is_some() => {
                    return Exit::Fault {
                        pc: self.reg(HV_REG_PC),
                        addr: self.sys(HV_SYS_REG_FAR_EL1),
                        detail: format!(
                            "watchdog: CPSR={:#x} ESR_EL1={:#x} ELR_EL1={:#x} SPSR_EL1={:#x} TTBR0={:#x}",
                            self.reg(HV_REG_CPSR),
                            self.sys(HV_SYS_REG_ESR_EL1),
                            self.sys(HV_SYS_REG_ELR_EL1),
                            self.sys(HV_SYS_REG_SPSR_EL1),
                            self.sys(HV_SYS_REG_TTBR0_EL1),
                        ),
                    };
                }
                HV_EXIT_REASON_CANCELED => match self.kicked_at() {
                    // A kick can land after the guest took an exception and before the
                    // vector's hvc ran. ELR holds the instruction after an svc: going
                    // back to EL0 from here would drop the syscall, and the guest would
                    // see its first argument as the result. Let the hvc happen; the
                    // thread looks at its signals on the way back in anyway.
                    Kicked::BeforeHvc => continue,
                    // At EL0, or at a stub's eret on the way there: whatever the kick
                    // was for (a signal, giving the vCPU up) is looked at before the
                    // guest runs on.
                    Kicked::El0 => return Exit::Interrupted,
                    Kicked::Trampoline => {
                        self.back_to_el0();
                        return Exit::Interrupted;
                    }
                },
                HV_EXIT_REASON_VTIMER_ACTIVATED => continue,
                other => {
                    return Exit::Fault { pc: self.reg(HV_REG_PC), addr: 0, detail: format!("unexpected exit reason {other}") };
                }
            }

            let syndrome = exit.exception.syndrome;
            if syndrome >> 26 != EC_HVC64 {
                return Exit::Fault {
                    pc: self.reg(HV_REG_PC),
                    addr: exit.exception.virtual_address,
                    detail: format!("exception to EL2, ESR_EL2={syndrome:#x}"),
                };
            }

            let vector = syndrome & 0xffff;
            if vector == HVC_SYSCALL {
                return Exit::Syscall;
            }
            let esr = self.sys(HV_SYS_REG_ESR_EL1);
            let elr = self.sys(HV_SYS_REG_ELR_EL1);
            if vector != VEC_LOWER_SYNC {
                return Exit::Fault {
                    pc: elr,
                    addr: self.sys(HV_SYS_REG_FAR_EL1),
                    detail: format!("vector {vector} taken, ESR_EL1={esr:#x}"),
                };
            }

            // The stub's eret goes back to EL0 where the guest left off: for aborts,
            // that re-executes the faulting instruction.
            let addr = || crate::arch::untag(self.sys(HV_SYS_REG_FAR_EL1));
            return match esr >> 26 {
                EC_DATA_ABORT_LOWER if DFSC_PAGING.contains(&(esr & ESR_DFSC)) => Exit::PageFault { pc: elr, addr: addr(), write: esr & ESR_WNR != 0 && esr & ESR_CM == 0, exec: false },
                EC_DATA_ABORT_LOWER if esr & ESR_DFSC == DFSC_ALIGNMENT => Exit::Alignment { pc: elr, addr: addr() },
                EC_INSTR_ABORT_LOWER => Exit::PageFault { pc: elr, addr: addr(), write: false, exec: true },
                ec => Exit::Fault { pc: elr, addr: addr(), detail: format!("ESR_EL1={esr:#x} (EC {ec:#x})") },
            };
        }
    }

    fn syscall_regs(&self) -> SyscallRegs {
        let mut args = [0; 6];
        for (i, a) in args.iter_mut().enumerate() {
            *a = self.reg(HV_REG_X0 + i as u32);
        }
        SyscallRegs { nr: self.reg(HV_REG_X0 + 8), args }
    }

    fn set_syscall_return(&mut self, value: u64) {
        self.set_reg(HV_REG_X0, value);
    }

    fn state(&self) -> CpuState {
        let mut s = Aarch64State::default();
        for (i, x) in s.x.iter_mut().enumerate() {
            *x = self.reg(HV_REG_X0 + i as u32);
        }
        s.sp = self.sys(HV_SYS_REG_SP_EL0);
        // At EL1 the vCPU is stopped at a stub's eret (as after every exit but a
        // kick at EL0), and the guest's PC and PSTATE are where the eret takes them from.
        let cpsr = self.reg(HV_REG_CPSR);
        (s.pc, s.pstate) = if cpsr & CPSR_MODE_MASK != 0 { (self.sys(HV_SYS_REG_ELR_EL1), self.sys(HV_SYS_REG_SPSR_EL1)) } else { (self.reg(HV_REG_PC), cpsr) };
        s.tpidr = self.sys(HV_SYS_REG_TPIDR_EL0);
        s.fpcr = self.reg(HV_REG_FPCR);
        s.fpsr = self.reg(HV_REG_FPSR);
        for (i, q) in s.v.iter_mut().enumerate() {
            check("hv_vcpu_get_simd_fp_reg", unsafe { hv_vcpu_get_simd_fp_reg(self.id, HV_SIMD_FP_REG_Q0 + i as u32, q) });
        }
        CpuState::Aarch64(Box::new(s))
    }

    fn set_state(&mut self, state: &CpuState) {
        let CpuState::Aarch64(s) = state else { panic!("x86_64 state on an arm64 vCPU") };
        for (i, &x) in s.x.iter().enumerate() {
            self.set_reg(HV_REG_X0 + i as u32, x);
        }
        self.set_sys(HV_SYS_REG_SP_EL0, s.sp);
        // Straight to EL0, past any stub's eret.
        self.set_reg(HV_REG_PC, s.pc);
        // Only user-mode flags; the mode field must say EL0t.
        self.set_reg(HV_REG_CPSR, s.pstate & !CPSR_MODE_MASK & 0xf000_0000);
        self.set_sys(HV_SYS_REG_TPIDR_EL0, s.tpidr);
        self.set_reg(HV_REG_FPCR, s.fpcr);
        self.set_reg(HV_REG_FPSR, s.fpsr);
        for (i, &q) in s.v.iter().enumerate() {
            check("hv_vcpu_set_simd_fp_reg", set_simd_fp_reg(self.id, HV_SIMD_FP_REG_Q0 + i as u32, q));
        }
    }

    fn set_page_tables(&mut self, root: PageTableRoot) {
        // No flush: a new address space, or an ASID used before, starts behind on
        // its flushes (mm::TlbGen).
        self.set_sys(HV_SYS_REG_TTBR0_EL1, root.root | (root.asid as u64) << 48);
        self.asid = root.asid;
    }

    fn flush_tlb_now(&mut self) {
        TlbFlush::Now.count();
        let (pc, cpsr) = (self.reg(HV_REG_PC), self.reg(HV_REG_CPSR));
        self.set_reg(HV_REG_PC, TLB_FLUSH_NOW);
        self.set_reg(HV_REG_CPSR, CPSR_EL1H_MASKED);
        // Anything but the hvc is a kick or timer, and just continues the stub:
        // the thread looks at its signals before it next enters the guest.
        loop {
            check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) });
            if unsafe { (*self.exit).reason } == HV_EXIT_REASON_EXCEPTION {
                break;
            }
        }
        self.set_reg(HV_REG_PC, pc);
        self.set_reg(HV_REG_CPSR, cpsr);
    }

    fn flush_tlb(&mut self) {
        self.flush_pending = Some((TlbFlush::AddressSpace, 0));
    }

    fn flush_tlb_page(&mut self, va: u64) {
        // The operand of tlbi vale1is: ASID in bits 63:48, VA[55:12] in 43:0.
        let operand = (self.asid as u64) << 48 | (va >> 12) & ((1 << 44) - 1);
        self.flush_pending = match self.flush_pending {
            None => Some((TlbFlush::Page, operand)),
            Some((TlbFlush::Page, o)) if o == operand => Some((TlbFlush::Page, o)),
            Some(_) => Some((TlbFlush::AddressSpace, 0)),
        };
    }

    fn kicker(&self) -> Arc<dyn Kick> {
        Arc::new(HvfKick(self.id))
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        unsafe { hv_vcpu_destroy(self.id) };
    }
}
