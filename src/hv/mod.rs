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
    /// An access the page tables allow and the CPU still refused: a misaligned one
    /// where alignment is required (an exclusive or atomic access). Resuming would
    /// fault again, for ever.
    Alignment { pc: u64, addr: u64 },
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
    /// Invalidates cached translations for every vCPU of the VM before returning.
    fn flush_tlb_now(&mut self);
    /// Makes sure there is a vCPU behind this object; false if the thread is dying.
    fn ready(&mut self) -> bool {
        true
    }
    fn kicker(&self) -> Arc<dyn Kick>;
}

/// How urgently the host should run the calling thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Urgency {
    /// Late work shows: compositing, drawing, input, audio.
    Display,
    /// What the user is looking at.
    Foreground,
    Normal,
    /// Work nobody is waiting for.
    Background,
}

/// Tells the host's scheduler how urgent the calling thread is. Only ever about the
/// thread itself: that is all macOS's QoS allows.
pub fn set_thread_urgency(u: Urgency) {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }
        let class = match u {
            Urgency::Display => 0x21,    // QOS_CLASS_USER_INTERACTIVE
            Urgency::Foreground => 0x19, // QOS_CLASS_USER_INITIATED
            Urgency::Normal => 0x15,     // QOS_CLASS_DEFAULT
            // UTILITY, not BACKGROUND: that is confined to the efficiency cores and
            // can wait so long that a kernel lock this thread holds stalls the rest.
            Urgency::Background => 0x11,
        };
        unsafe { pthread_set_qos_class_self_np(class, 0) };
    }
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn GetCurrentThread() -> *mut std::ffi::c_void;
            fn SetThreadPriority(thread: *mut std::ffi::c_void, priority: i32) -> i32;
        }
        let priority = match u {
            Urgency::Display => 2,    // THREAD_PRIORITY_HIGHEST
            Urgency::Foreground => 1, // THREAD_PRIORITY_ABOVE_NORMAL
            Urgency::Normal => 0,
            Urgency::Background => -1, // THREAD_PRIORITY_BELOW_NORMAL
        };
        unsafe { SetThreadPriority(GetCurrentThread(), priority) };
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = u;
}

/// A host thread whose CPU time any thread can read. Each guest thread runs on a host
/// thread of its own, so this is that guest thread's CPU time: its code in the VM and
/// zeroemu's work on its behalf.
pub struct HostThread {
    #[cfg(target_os = "macos")]
    port: u32,
    #[cfg(windows)]
    handle: usize,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_mach_thread_np(thread: libc::pthread_t) -> u32;
    fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetCurrentThread() -> usize;
    fn GetCurrentProcess() -> usize;
    fn DuplicateHandle(src_process: usize, src: usize, dst_process: usize, dst: *mut usize, access: u32, inherit: i32, options: u32) -> i32;
    fn CloseHandle(h: usize) -> i32;
    fn GetThreadTimes(thread: usize, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn GetProcessTimes(process: usize, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
}

impl HostThread {
    /// The calling thread. Valid for reading while that thread lives.
    pub fn current() -> HostThread {
        #[cfg(target_os = "macos")]
        {
            HostThread { port: unsafe { pthread_mach_thread_np(libc::pthread_self()) } }
        }
        #[cfg(windows)]
        {
            const DUPLICATE_SAME_ACCESS: u32 = 2;
            let mut handle = 0;
            unsafe { DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &mut handle, 0, 0, DUPLICATE_SAME_ACCESS) };
            HostThread { handle }
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            HostThread {}
        }
    }

    /// CPU time used so far, user and system together.
    pub fn cpu_time(&self) -> std::time::Duration {
        #[cfg(target_os = "macos")]
        {
            // struct thread_basic_info: user_time and system_time (seconds,
            // microseconds), then six more integers.
            const THREAD_BASIC_INFO: i32 = 3;
            let mut info = [0i32; 10];
            let mut count = info.len() as u32;
            if unsafe { thread_info(self.port, THREAD_BASIC_INFO, info.as_mut_ptr(), &mut count) } != 0 {
                return std::time::Duration::ZERO;
            }
            let us = (info[0] as u64 + info[2] as u64) * 1_000_000 + info[1] as u64 + info[3] as u64;
            std::time::Duration::from_micros(us)
        }
        #[cfg(windows)]
        {
            let (mut c, mut e, mut k, mut u) = (0, 0, 0, 0);
            if unsafe { GetThreadTimes(self.handle, &mut c, &mut e, &mut k, &mut u) } == 0 {
                return std::time::Duration::ZERO;
            }
            std::time::Duration::from_nanos((k + u) * 100)
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            std::time::Duration::ZERO
        }
    }
}

#[cfg(windows)]
impl Drop for HostThread {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

/// The calling thread's CPU time.
pub fn thread_cpu_time() -> std::time::Duration {
    #[cfg(unix)]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }
    #[cfg(windows)]
    {
        HostThread::current().cpu_time()
    }
}

/// CPU time of zeroemu as a whole: every guest thread and zeroemu's own, gone ones too.
pub fn process_cpu_time() -> std::time::Duration {
    #[cfg(unix)]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let tv = |t: libc::timeval| std::time::Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
        tv(ru.ru_utime) + tv(ru.ru_stime)
    }
    #[cfg(windows)]
    {
        let (mut c, mut e, mut k, mut u) = (0, 0, 0, 0);
        unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
        std::time::Duration::from_nanos((k + u) * 100)
    }
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

/// A hypervisor that is never asked for anything, for tests of what only needs memory.
#[cfg(test)]
pub struct NoHv;
#[cfg(test)]
impl crate::hv::Hypervisor for NoHv {
    fn map_ram(&self, _: *mut u8, _: u64, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn unmap_ram(&self, _: u64, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn kernel_pages(&self, _: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<crate::hv::KernelPage> {
        Vec::new()
    }
    fn create_vcpu(&self, _: crate::hv::PageTableRoot, _: &crate::hv::CpuState) -> Result<Box<dyn crate::hv::Vcpu>, String> {
        Err("no vCPUs in tests".into())
    }
    fn max_vcpus(&self) -> usize {
        0
    }
}
