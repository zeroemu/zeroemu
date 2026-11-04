//! Hypervisor backends. Each one runs guest *user* code with no guest kernel
//! and hands control back to us whenever the guest makes a syscall, faults on a
//! page, or is interrupted. Page tables, processes, and everything
//! Linux-specific live above this line, in `mm` and `kernel`.

#[cfg(target_os = "macos")]
mod hvf;
#[cfg(target_os = "macos")]
mod hvf_sys;
#[cfg(windows)]
mod whp;
#[cfg(any(windows, test))]
mod x86;

use crate::arch::Arch;
use std::sync::Arc;

#[derive(Debug)]
// The arm64 Windows build has no vCPU, so nothing constructs these variants there.
#[cfg_attr(all(windows, target_arch = "aarch64"), allow(dead_code))]
pub enum Exit {
    /// The guest executed its syscall instruction. Arguments: `syscall_regs`.
    Syscall,
    /// A user access the page tables did not allow (not present, or protected).
    /// Resuming re-executes the faulting instruction.
    PageFault {
        pc: u64,
        addr: u64,
        write: bool,
        exec: bool,
    },
    /// Anything else the guest cannot continue from (undefined instruction…).
    Fault { pc: u64, addr: u64, detail: String },
    /// `Kick::kick` was called from another thread.
    Interrupted,
}

/// Syscall-visible register state, in arch-neutral form.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallRegs {
    pub nr: u64,
    pub args: [u64; 6],
}

/// Complete user-mode register state of one guest thread: what fork copies,
/// clone starts from, and signal delivery saves.
#[derive(Clone, Debug)]
pub enum CpuState {
    Aarch64(Box<Aarch64State>),
    X86_64(Box<X86_64State>),
}

#[derive(Clone, Debug, Default)]
pub struct Aarch64State {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub tpidr: u64,
    pub v: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

/// Read by the Windows backend (being ported to this interface).
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct X86_64State {
    /// rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8–r15.
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    /// FXSAVE/XSAVE image, backend-defined.
    pub fpu: Vec<u8>,
}

impl CpuState {
    /// A fresh user thread about to start at `entry` with stack `sp`.
    pub fn new_user(entry: u64, sp: u64) -> CpuState {
        match Arch::HOST {
            Arch::Aarch64 => CpuState::Aarch64(Box::new(Aarch64State {
                sp,
                pc: entry,
                ..Default::default()
            })),
            Arch::X86_64 => {
                let mut s = X86_64State {
                    rip: entry,
                    rflags: 0x202,
                    ..Default::default()
                };
                s.gpr[4] = sp;
                CpuState::X86_64(Box::new(s))
            }
        }
    }

    pub fn set_sp(&mut self, sp: u64) {
        match self {
            CpuState::Aarch64(s) => s.sp = sp,
            CpuState::X86_64(s) => s.gpr[4] = sp,
        }
    }

    /// The syscall return register (x0 / rax).
    pub fn set_return(&mut self, v: u64) {
        match self {
            CpuState::Aarch64(s) => s.x[0] = v,
            CpuState::X86_64(s) => s.gpr[0] = v,
        }
    }

    /// The syscall number and arguments, as `Vcpu::syscall_regs` reads them.
    pub fn syscall_regs(&self) -> SyscallRegs {
        match self {
            CpuState::Aarch64(s) => SyscallRegs { nr: s.x[8], args: [s.x[0], s.x[1], s.x[2], s.x[3], s.x[4], s.x[5]] },
            // rax; rdi, rsi, rdx, r10, r8, r9
            CpuState::X86_64(s) => SyscallRegs { nr: s.gpr[0], args: [s.gpr[7], s.gpr[6], s.gpr[2], s.gpr[10], s.gpr[8], s.gpr[9]] },
        }
    }

    pub fn set_tls(&mut self, tls: u64) {
        match self {
            CpuState::Aarch64(s) => s.tpidr = tls,
            CpuState::X86_64(s) => s.fs_base = tls,
        }
    }
}

/// Which page tables a vCPU translates through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTableRoot {
    /// Guest-physical address of the top-level table.
    pub root: u64,
    /// Address-space id (TLB tag), unique among live address spaces.
    pub asid: u16,
}

/// A page the backend needs mapped at the same address in every address
/// space, readable/executable only from the guest's privileged level.
#[derive(Clone, Copy, Debug)]
pub struct KernelPage {
    pub va: u64,
    pub gpa: u64,
    pub exec: bool,
}

/// Interrupts a running vCPU from another host thread.
pub trait Kick: Send + Sync {
    fn kick(&self);
}

pub trait Vcpu {
    /// Runs the guest until it needs the kernel.
    fn run(&mut self) -> Exit;
    fn syscall_regs(&self) -> SyscallRegs;
    fn set_syscall_return(&mut self, value: u64);
    fn state(&self) -> CpuState;
    fn set_state(&mut self, state: &CpuState);
    fn set_page_tables(&mut self, root: PageTableRoot);
    /// Invalidates cached translations for every vCPU of the VM before this
    /// one next enters the guest (after unmapping or downgrading pages).
    fn flush_tlb(&mut self);
    fn kicker(&self) -> Arc<dyn Kick>;
}

pub trait Hypervisor: Send + Sync {
    /// Makes `size` bytes of host memory visible to the guest at `gpa`.
    fn map_ram(&self, host: *mut u8, gpa: u64, size: u64) -> Result<(), String>;
    /// Removes a mapping installed by `map_ram`. The guest must not still
    /// have translations for `gpa` (the caller flushes TLBs first).
    fn unmap_ram(&self, gpa: u64, size: u64) -> Result<(), String>;
    /// Pages to map in every address space, given frames to place them in.
    /// Called once, before any vCPU exists.
    fn kernel_pages(&self, alloc: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage>;
    /// Creates a vCPU owned by the calling host thread (HVF requires that the
    /// creating thread is the only one that runs it).
    fn create_vcpu(&self, root: PageTableRoot, state: &CpuState) -> Result<Box<dyn Vcpu>, String>;
    /// Upper bound on simultaneously existing vCPUs.
    fn max_vcpus(&self) -> usize;
}

pub fn create() -> Result<Arc<dyn Hypervisor>, String> {
    #[cfg(target_os = "macos")]
    return hvf::Hvf::new().map(|h| Arc::new(h) as Arc<dyn Hypervisor>);
    #[cfg(windows)]
    return whp::Whp::new().map(|h| Arc::new(h) as Arc<dyn Hypervisor>);
    #[cfg(not(any(target_os = "macos", windows)))]
    Err("no hypervisor backend for this OS yet (KVM is planned)".into())
}
