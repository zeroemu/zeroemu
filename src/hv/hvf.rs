//! macOS backend: Hypervisor.framework on Apple Silicon.
//!
//! The guest runs at EL0. EL1 holds only a vector table whose every entry is
//! `hvc #n`, so any exception from user code exits straight to us; we then
//! resume the guest by restoring PC/CPSR from ELR_EL1/SPSR_EL1 ourselves.

use super::hvf_sys::*;
use super::{Exit, Hypervisor, SyscallRegs, Vcpu};
use crate::mem::{BLOCK, GuestMem, KERNEL_BASE, MEM_SIZE};
use std::ptr;

const PT_L1: u64 = KERNEL_BASE;
/// One L2 table (512 x 2 MiB blocks) per GiB of guest memory, up to 64 GiB.
const PT_L2: u64 = KERNEL_BASE + 0x1000;
const VECTORS: u64 = KERNEL_BASE + 0x80000;
const EL1_STACK: u64 = KERNEL_BASE + 0x90000;
const _: () = assert!(MEM_SIZE >> 30 <= 64, "page tables would overlap the vectors");

/// Vector index for "synchronous exception from lower EL, AArch64".
const VEC_LOWER_SYNC: u64 = 8;

const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;

pub struct Hvf;

impl Hvf {
    pub fn new(mem: &GuestMem) -> Result<Self, String> {
        let ret = unsafe { hv_vm_create(ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(format!(
                "hv_vm_create failed ({ret:#x}); is the binary signed with the \
                 com.apple.security.hypervisor entitlement?"
            ));
        }
        check("hv_vm_map", unsafe {
            hv_vm_map(
                mem.host_ptr().cast(),
                0,
                MEM_SIZE as usize,
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )
        });
        build_page_tables(mem);
        build_vectors(mem);
        Ok(Hvf)
    }
}

fn build_page_tables(mem: &GuestMem) {
    const VALID_BLOCK: u64 = 0b01;
    const VALID_TABLE: u64 = 0b11;
    const ATTR_NORMAL: u64 = 0 << 2; // MAIR index 0
    const AP_EL0_RW: u64 = 0b01 << 6;
    const SH_INNER: u64 = 0b11 << 8;
    const AF: u64 = 1 << 10;
    const UXN: u64 = 1 << 54;

    for gib in 0..(MEM_SIZE >> 30) {
        mem.kwrite(PT_L1 + gib * 8, (PT_L2 + gib * 0x1000) | VALID_TABLE);
    }
    // Block 0 stays invalid so the first 2 MiB faults. The L2 tables are
    // contiguous, so block i's descriptor lives at PT_L2 + i * 8.
    for i in 1..(MEM_SIZE / BLOCK) {
        let pa = i * BLOCK;
        let common = pa | VALID_BLOCK | ATTR_NORMAL | SH_INNER | AF;
        let desc = if pa >= KERNEL_BASE {
            common | UXN
        } else {
            common | AP_EL0_RW
        };
        mem.kwrite(PT_L2 + i * 8, desc);
    }
}

fn build_vectors(mem: &GuestMem) {
    for n in 0..16u32 {
        mem.kwrite(VECTORS + n as u64 * 0x80, 0xd400_0002u32 | (n << 5)); // hvc #n
    }
}

impl Hypervisor for Hvf {
    fn create_vcpu(&self, entry: u64, stack: u64) -> Result<Box<dyn Vcpu>, String> {
        let mut id = 0;
        let mut exit = ptr::null();
        let ret = unsafe { hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(format!("hv_vcpu_create failed ({ret:#x})"));
        }
        let v = HvfVcpu { id, exit };
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
        // TTBR1 walks disabled, 36-bit IPA, and TBI0 (top-byte-ignore), which
        // Linux always enables for EL0: Android tags heap pointers.
        let tcr = 25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (1 << 32) | (1 << 37);
        v.set_sys(HV_SYS_REG_TCR_EL1, tcr);
        v.set_sys(HV_SYS_REG_TTBR0_EL1, PT_L1);
        v.set_sys(HV_SYS_REG_VBAR_EL1, VECTORS);
        v.set_sys(HV_SYS_REG_CPACR_EL1, 3 << 20); // FP/SIMD at EL0
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
        v.set_sys(HV_SYS_REG_SP_EL1, EL1_STACK);

        v.set_sys(HV_SYS_REG_SP_EL0, stack);
        v.set_reg(HV_REG_PC, entry);
        v.set_reg(HV_REG_CPSR, 0); // EL0t
        Ok(Box::new(v))
    }
}

struct HvfVcpu {
    id: hv_vcpu_t,
    exit: *const hv_vcpu_exit_t,
}

impl HvfVcpu {
    fn reg(&self, r: u32) -> u64 {
        let mut v = 0;
        check("hv_vcpu_get_reg", unsafe {
            hv_vcpu_get_reg(self.id, r, &mut v)
        });
        v
    }
    fn set_reg(&self, r: u32, v: u64) {
        check("hv_vcpu_set_reg", unsafe { hv_vcpu_set_reg(self.id, r, v) });
    }
    fn sys(&self, r: u16) -> u64 {
        let mut v = 0;
        check("hv_vcpu_get_sys_reg", unsafe {
            hv_vcpu_get_sys_reg(self.id, r, &mut v)
        });
        v
    }
    fn set_sys(&self, r: u16, v: u64) {
        check("hv_vcpu_set_sys_reg", unsafe {
            hv_vcpu_set_sys_reg(self.id, r, v)
        });
    }
}

impl Vcpu for HvfVcpu {
    fn run(&mut self) -> Exit {
        loop {
            check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) });
            let exit = unsafe { *self.exit };
            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {}
                HV_EXIT_REASON_CANCELED if std::env::var_os("DROIDRT_WATCHDOG").is_some() => {
                    return Exit::Fault {
                        pc: self.reg(HV_REG_PC),
                        addr: self.sys(HV_SYS_REG_FAR_EL1),
                        detail: format!(
                            "watchdog: CPSR={:#x} ESR_EL1={:#x} ELR_EL1={:#x} SPSR_EL1={:#x} VBAR={:#x}",
                            self.reg(HV_REG_CPSR),
                            self.sys(HV_SYS_REG_ESR_EL1),
                            self.sys(HV_SYS_REG_ELR_EL1),
                            self.sys(HV_SYS_REG_SPSR_EL1),
                            self.sys(HV_SYS_REG_VBAR_EL1),
                        ),
                    };
                }
                HV_EXIT_REASON_CANCELED | HV_EXIT_REASON_VTIMER_ACTIVATED => continue,
                other => {
                    return Exit::Fault {
                        pc: self.reg(HV_REG_PC),
                        addr: 0,
                        detail: format!("unexpected exit reason {other}"),
                    };
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

            // Return to EL0 where the guest left off.
            self.set_reg(HV_REG_PC, elr);
            self.set_reg(HV_REG_CPSR, self.sys(HV_SYS_REG_SPSR_EL1));

            if esr >> 26 == EC_SVC64 {
                return Exit::Syscall;
            }
            return Exit::Fault {
                pc: elr,
                addr: self.sys(HV_SYS_REG_FAR_EL1),
                detail: format!("ESR_EL1={esr:#x} (EC {:#x})", esr >> 26),
            };
        }
    }

    fn syscall_regs(&self) -> SyscallRegs {
        let mut args = [0; 6];
        for (i, a) in args.iter_mut().enumerate() {
            *a = self.reg(HV_REG_X0 + i as u32);
        }
        SyscallRegs {
            nr: self.reg(HV_REG_X0 + 8),
            args,
        }
    }

    fn set_syscall_return(&mut self, value: u64) {
        self.set_reg(HV_REG_X0, value);
    }

    fn set_tls(&mut self, value: u64) {
        self.set_sys(HV_SYS_REG_TPIDR_EL0, value);
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        unsafe { hv_vcpu_destroy(self.id) };
    }
}
