//! Hypervisor backends. Each one runs guest *user* code with no guest kernel
//! and hands control back to us whenever the guest makes a syscall or faults.
//! Everything Linux-specific lives above this line, in `kernel`.

use crate::mem::GuestMem;

#[cfg(target_os = "macos")]
mod hvf;
#[cfg(target_os = "macos")]
mod hvf_sys;
#[cfg(windows)]
mod whp;
#[cfg(any(windows, test))]
mod x86;

#[derive(Debug)]
pub enum Exit {
    /// The guest executed its syscall instruction. Arguments are in `Regs`.
    Syscall,
    /// The guest touched memory it may not, or hit an undefined instruction.
    Fault { pc: u64, addr: u64, detail: String },
}

/// Syscall-visible register state, in arch-neutral form.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallRegs {
    pub nr: u64,
    pub args: [u64; 6],
}

pub trait Vcpu {
    fn run(&mut self) -> Exit;
    fn syscall_regs(&self) -> SyscallRegs;
    fn set_syscall_return(&mut self, value: u64);
    fn set_tls(&mut self, value: u64);
}

pub trait Hypervisor {
    fn create_vcpu(&self, entry: u64, stack: u64) -> Result<Box<dyn Vcpu>, String>;
}

pub fn create(mem: &GuestMem) -> Result<Box<dyn Hypervisor>, String> {
    #[cfg(target_os = "macos")]
    return hvf::Hvf::new(mem).map(|h| Box::new(h) as Box<dyn Hypervisor>);
    #[cfg(windows)]
    return whp::Whp::new(mem).map(|h| Box::new(h) as Box<dyn Hypervisor>);
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = mem;
        Err("no hypervisor backend for this OS yet (KVM is planned)".into())
    }
}
