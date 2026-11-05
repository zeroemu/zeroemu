//! macOS backend: Hypervisor.framework on Apple Silicon.
//!
//! The guest runs at EL0 under page tables built by `mm`. EL1 holds only the
//! kernel window: a vector table whose every entry is `hvc #n`, so any
//! exception from user code exits straight to us, and a TLB-flush trampoline.
//! We resume the guest by restoring PC/CPSR from ELR_EL1/SPSR_EL1 ourselves,
//! or, after page-table changes, by entering the trampoline, which runs
//! `tlbi vmalle1is` (broadcast to every vCPU) and `eret`s to EL0.

use super::hvf_sys::*;
use super::{Aarch64State, CpuState, Exit, Hypervisor, KernelPage, Kick, PageTableRoot, SyscallRegs, Vcpu};
use crate::paging::KERNEL_WINDOW;
use std::ptr;
use std::sync::Arc;

const VECTORS: u64 = KERNEL_WINDOW;
const TLB_FLUSH: u64 = KERNEL_WINDOW + 0x800;
/// The same flush for the kernel's own use: comes back with `hvc` instead of
/// going on to EL0.
const TLB_FLUSH_NOW: u64 = KERNEL_WINDOW + 0x820;
/// Past the entries of the vector table, whose only EL1 code is `hvc`.
const VECTORS_END: u64 = KERNEL_WINDOW + 0x800;

/// Vector index for "synchronous exception from lower EL, AArch64".
const VEC_LOWER_SYNC: u64 = 8;

const EC_INSTR_ABORT_LOWER: u64 = 0x20;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;
const ESR_WNR: u64 = 1 << 6;
/// The abort came from a cache maintenance instruction (DC CVAU, IC IVAU...),
/// which reports WnR = 1; Linux counts it as a read (is_write_abort), so
/// cleaning the cache over read-only code works.
const ESR_CM: u64 = 1 << 8;

const CPSR_EL1H_MASKED: u64 = 0x3c5;
const CPSR_MODE_MASK: u64 = 0xf;

pub struct Hvf;

impl Hvf {
    pub fn new() -> Result<Self, String> {
        let ret = unsafe { hv_vm_create(ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(format!(
                "hv_vm_create failed ({ret:#x}); is the binary signed with the \
                 com.apple.security.hypervisor entitlement?"
            ));
        }
        Ok(Hvf)
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
        for n in 0..16u32 {
            put(n as u64 * 0x80, 0xd400_0002 | (n << 5)); // hvc #n
        }
        let flush = [
            0xd503_3a9f, // dsb ishst
            0xd508_831f, // tlbi vmalle1is
            0xd503_3b9f, // dsb ish
            0xd503_3fdf, // isb
            0xd69f_03e0, // eret
        ];
        for (i, insn) in flush.iter().enumerate() {
            put(TLB_FLUSH - KERNEL_WINDOW + i as u64 * 4, *insn);
        }
        for (i, insn) in flush[..4].iter().chain(&[0xd400_0002 | (16 << 5)]).enumerate() {
            put(TLB_FLUSH_NOW - KERNEL_WINDOW + i as u64 * 4, *insn);
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
        let mut v = HvfVcpu { id, exit, flush_pending: true };
        if let Some(secs) = std::env::var("DROIDRT_WATCHDOG").ok().and_then(|s| s.parse::<u64>().ok()) {
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
    /// Enter through the TLB-flush trampoline on the next run.
    flush_pending: bool,
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

    /// If an exit (a kick) caught the vCPU inside the EL1 trampoline, rewind
    /// to the EL0 resume point and redo the flush next time.
    fn back_to_el0(&mut self) {
        if self.reg(HV_REG_CPSR) & CPSR_MODE_MASK != 0 {
            self.set_reg(HV_REG_PC, self.sys(HV_SYS_REG_ELR_EL1));
            self.set_reg(HV_REG_CPSR, self.sys(HV_SYS_REG_SPSR_EL1));
            self.flush_pending = true;
        }
    }
}

impl Vcpu for HvfVcpu {
    fn run(&mut self) -> Exit {
        loop {
            if self.flush_pending {
                self.set_sys(HV_SYS_REG_ELR_EL1, self.reg(HV_REG_PC));
                self.set_sys(HV_SYS_REG_SPSR_EL1, self.reg(HV_REG_CPSR));
                self.set_reg(HV_REG_PC, TLB_FLUSH);
                self.set_reg(HV_REG_CPSR, CPSR_EL1H_MASKED);
                self.flush_pending = false;
            }
            check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) });
            let exit = unsafe { *self.exit };
            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {}
                HV_EXIT_REASON_CANCELED if std::env::var_os("DROIDRT_WATCHDOG").is_some() => {
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
                // A kick can land after the guest took an exception and before the
                // vector's hvc ran. ELR holds the instruction after an svc: going
                // back to EL0 from here would drop the syscall, and the guest would
                // see its first argument as the result. Let the hvc happen; the
                // thread looks at its signals on the way back in anyway.
                HV_EXIT_REASON_CANCELED if self.reg(HV_REG_CPSR) & CPSR_MODE_MASK != 0 && self.reg(HV_REG_PC) < VECTORS_END => continue,
                HV_EXIT_REASON_CANCELED => {
                    self.back_to_el0();
                    return Exit::Interrupted;
                }
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
            let esr = self.sys(HV_SYS_REG_ESR_EL1);
            let elr = self.sys(HV_SYS_REG_ELR_EL1);
            if vector != VEC_LOWER_SYNC {
                return Exit::Fault {
                    pc: elr,
                    addr: self.sys(HV_SYS_REG_FAR_EL1),
                    detail: format!("vector {vector} taken, ESR_EL1={esr:#x}"),
                };
            }

            // Return to EL0 where the guest left off (for aborts, that
            // re-executes the faulting instruction).
            self.set_reg(HV_REG_PC, elr);
            self.set_reg(HV_REG_CPSR, self.sys(HV_SYS_REG_SPSR_EL1));

            let addr = || crate::arch::untag(self.sys(HV_SYS_REG_FAR_EL1));
            return match esr >> 26 {
                EC_SVC64 => Exit::Syscall,
                EC_DATA_ABORT_LOWER => Exit::PageFault { pc: elr, addr: addr(), write: esr & ESR_WNR != 0 && esr & ESR_CM == 0, exec: false },
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
        s.pc = self.reg(HV_REG_PC);
        s.pstate = self.reg(HV_REG_CPSR);
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
        self.set_sys(HV_SYS_REG_TTBR0_EL1, root.root | (root.asid as u64) << 48);
        self.flush_pending = true;
    }

    fn flush_tlb_now(&mut self) {
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
        self.flush_pending = true;
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
