//! Signals: dispositions, pending sets, delivery through Linux-compatible
//! signal frames, and rt_sigreturn. Frames are built for arm64 (the layout of
//! arch/arm64/kernel/signal.c); x86_64 frames are not written yet.

use super::{Kernel, POLL, Process, Ret, Thread};
use crate::errno::*;
use crate::hv::{CpuState, SyscallRegs, Vcpu};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub const SIGILL: u32 = 4;
pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGCHLD: u32 = 17;
pub const SIGSTOP: u32 = 19;
pub const SS_ONSTACK: i32 = 1;

/// A user page holding `rt_sigreturn`, mapped in every address space just
/// below the top of user space; handlers return there unless SA_RESTORER
/// gives another address (arm64 bionic relies on the kernel's).
pub const SIGRETURN_TRAMPOLINE: u64 = crate::paging::USER_TOP - crate::phys::PAGE;

pub fn trampoline_page() -> Arc<[u8]> {
    let mut page = vec![0u8; crate::phys::PAGE as usize];
    let code: &[u8] = match crate::arch::Arch::HOST {
        // mov x8, #139 (__NR_rt_sigreturn); svc #0
        crate::arch::Arch::Aarch64 => &[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4],
        // mov eax, 15 (__NR_rt_sigreturn); syscall
        crate::arch::Arch::X86_64 => &[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05],
    };
    page[..code.len()].copy_from_slice(code);
    page.into()
}
pub const SS_DISABLE: i32 = 2;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

const fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

#[derive(Clone, Copy, Default, Debug)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

#[derive(Clone)]
pub struct Actions([SigAction; 65]);

impl Default for Actions {
    fn default() -> Self {
        Actions([SigAction::default(); 65])
    }
}

impl Actions {
    pub fn get(&self, sig: u32) -> SigAction {
        self.0[sig as usize]
    }
    /// execve keeps ignored signals ignored and resets handlers to default.
    pub fn reset_on_exec(&mut self) {
        for a in self.0.iter_mut() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum Default_ {
    Ignore,
    Terminate,
    Core,
}

fn default_action(sig: u32) -> Default_ {
    match sig {
        // SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGWINCH:
        // stopping is not modelled, so stop signals are ignored.
        17..=23 | 28 => Default_::Ignore,
        3..=8 | 11 | 24 | 25 | 31 => Default_::Core,
        _ => Default_::Terminate,
    }
}

/// A 128-byte `siginfo_t`.
#[derive(Clone, Copy)]
pub struct SigInfo(pub [u8; 128]);

impl SigInfo {
    fn base(sig: u32, code: i32) -> SigInfo {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
        b[8..12].copy_from_slice(&code.to_le_bytes());
        SigInfo(b)
    }
    /// Sent by kill/tgkill (SI_USER) from `pid`, uid 0.
    pub fn user(sig: u32, pid: i32) -> SigInfo {
        let mut s = SigInfo::base(sig, 0);
        s.0[16..20].copy_from_slice(&pid.to_le_bytes());
        s
    }
    /// SIGCHLD: `code` is CLD_EXITED (1) or CLD_KILLED (2).
    pub fn child(code: i32, pid: i32, status: i32) -> SigInfo {
        let mut s = SigInfo::base(SIGCHLD, code);
        s.0[16..20].copy_from_slice(&pid.to_le_bytes());
        s.0[24..28].copy_from_slice(&status.to_le_bytes());
        s
    }
    /// A synchronous fault at `addr` (e.g. SEGV_MAPERR = 1).
    pub fn fault(sig: u32, code: i32, addr: u64) -> SigInfo {
        let mut s = SigInfo::base(sig, code);
        s.0[16..24].copy_from_slice(&addr.to_le_bytes());
        s
    }
    fn addr(&self) -> u64 {
        u64::from_le_bytes(self.0[16..24].try_into().unwrap())
    }
}

fn sig_name(sig: u32) -> String {
    const NAMES: [&str; 32] = [
        "", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV",
        "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN",
        "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
    ];
    NAMES.get(sig as usize).map_or_else(|| format!("signal {sig}"), |s| s.to_string())
}

impl Thread {
    pub(super) fn has_deliverable_signal(&self) -> bool {
        let mask = self.mask.load(Ordering::Relaxed) & !UNBLOCKABLE;
        let deliverable = |p: &std::collections::HashMap<u32, SigInfo>| p.keys().any(|&s| bit(s) & mask == 0);
        deliverable(&self.pending.lock().unwrap()) || deliverable(&self.proc.pending.lock().unwrap())
    }

    fn take_signal(&self) -> Option<(u32, SigInfo)> {
        let mask = self.mask.load(Ordering::Relaxed) & !UNBLOCKABLE;
        for pending in [&self.pending, &self.proc.pending] {
            let mut p = pending.lock().unwrap();
            if let Some(&sig) = p.keys().filter(|&&s| bit(s) & mask == 0).min() {
                return p.remove(&sig).map(|i| (sig, i));
            }
        }
        None
    }
}

impl Kernel {
    fn discarded(&self, proc: &Process, sig: u32) -> bool {
        let act = proc.sig.lock().unwrap().get(sig);
        sig != SIGKILL && (act.handler == SIG_IGN || (act.handler == SIG_DFL && default_action(sig) == Default_::Ignore))
    }

    pub(super) fn send_process_signal(&self, proc: &Arc<Process>, sig: u32, info: SigInfo) {
        if proc.status.lock().unwrap().is_some() || self.discarded(proc, sig) {
            return;
        }
        if sig == SIGKILL {
            self.exit_group(proc, SIGKILL as i32, None);
            return;
        }
        proc.pending.lock().unwrap().insert(sig, info);
        // Wake a thread that can take it.
        let threads = proc.threads.lock().unwrap();
        if let Some(th) = threads.iter().find(|t| t.mask.load(Ordering::Relaxed) & bit(sig) == 0) {
            th.kick();
        }
    }

    pub(super) fn send_thread_signal(&self, th: &Arc<Thread>, sig: u32, info: SigInfo) {
        if self.discarded(&th.proc, sig) {
            return;
        }
        if sig == SIGKILL {
            self.exit_group(&th.proc, SIGKILL as i32, None);
            return;
        }
        th.pending.lock().unwrap().insert(sig, info);
        th.kick();
    }

    /// A fault the thread caused: delivered to its handler, or fatal.
    pub(super) fn force_signal(&self, t: &Arc<Thread>, sig: u32, info: SigInfo, pc: u64) {
        let act = t.proc.sig.lock().unwrap().get(sig);
        let blocked = t.mask.load(Ordering::Relaxed) & bit(sig) != 0;
        if act.handler == SIG_DFL || act.handler == SIG_IGN || blocked {
            eprintln!(
                "[droidrt] pid {} tid {} ({}): {} at pc={pc:#x} addr={:#x}",
                t.proc.pid,
                t.tid,
                t.proc.exe.lock().unwrap(),
                sig_name(sig),
                info.addr()
            );
            self.exit_group(&t.proc, sig as i32 | 0x80, None);
            return;
        }
        t.pending.lock().unwrap().insert(sig, info);
    }

    /// Runs before re-entering the guest. `restart` is a syscall that returned
    /// ERESTARTSYS: restarted unless a handler without SA_RESTART runs.
    pub(super) fn deliver_signals(&self, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, mut restart: Option<SyscallRegs>) {
        while let Some((sig, info)) = t.take_signal() {
            let act = t.proc.sig.lock().unwrap().get(sig);
            if act.handler == SIG_IGN {
                continue;
            }
            if act.handler == SIG_DFL {
                match default_action(sig) {
                    Default_::Ignore => continue,
                    d => {
                        if d == Default_::Core || self.strace {
                            eprintln!("[droidrt] pid {} ({}) killed by {}", t.proc.pid, t.proc.exe.lock().unwrap(), sig_name(sig));
                        }
                        let core = if d == Default_::Core { 0x80 } else { 0 };
                        self.exit_group(&t.proc, sig as i32 | core, None);
                        t.dying.store(true, Ordering::Release);
                        return;
                    }
                }
            }
            let mut state = vcpu.state();
            if let Some(regs) = restart.take() {
                if act.flags & SA_RESTART != 0 {
                    rewind(&mut state, &regs);
                } else {
                    state.set_return(-EINTR as u64);
                }
            }
            let old_mask = t.saved_mask.lock().unwrap().take().unwrap_or(t.mask.load(Ordering::Relaxed));
            match self.setup_frame(t, &mut state, sig, &info, &act, old_mask) {
                Ok(()) => {
                    vcpu.set_state(&state);
                    let mut mask = old_mask | act.mask;
                    if act.flags & SA_NODEFER == 0 {
                        mask |= bit(sig);
                    }
                    t.mask.store(mask & !UNBLOCKABLE, Ordering::Relaxed);
                    if act.flags & SA_RESETHAND != 0 {
                        t.proc.sig.lock().unwrap().0[sig as usize] = SigAction::default();
                    }
                }
                Err(e) => {
                    eprintln!("[droidrt] pid {}: cannot deliver {} (errno {e}); killing it", t.proc.pid, sig_name(sig));
                    self.exit_group(&t.proc, SIGSEGV as i32 | 0x80, None);
                    t.dying.store(true, Ordering::Release);
                    return;
                }
            }
        }
        if let Some(regs) = restart {
            // Interrupted but no handler ran: restart transparently.
            let mut state = vcpu.state();
            rewind(&mut state, &regs);
            vcpu.set_state(&state);
        }
        if let Some(m) = t.saved_mask.lock().unwrap().take() {
            t.mask.store(m, Ordering::Relaxed); // sigsuspend woke without a handler
        }
    }

    pub(super) fn sys_rt_sigaction(&self, t: &Thread, sig: u32, act: u64, old: u64) -> i64 {
        if sig == 0 || sig > 64 || (act != 0 && (sig == SIGKILL || sig == SIGSTOP)) {
            return -EINVAL;
        }
        let mut mm = t.proc.mm();
        let mut actions = t.proc.sig.lock().unwrap();
        if old != 0 {
            let a = actions.get(sig);
            let mut b = [0u8; 32];
            for (i, v) in [a.handler, a.flags, a.restorer, a.mask].iter().enumerate() {
                b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            if let Err(e) = mm.write(old, &b) {
                return -e;
            }
        }
        if act != 0 {
            let b = match mm.read_vec(act, 32) {
                Ok(b) => b,
                Err(e) => return -e,
            };
            let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
            actions.0[sig as usize] = SigAction { handler: w(0), flags: w(1), restorer: w(2), mask: w(3) & !UNBLOCKABLE };
            let ignore = w(0) == SIG_IGN || (w(0) == SIG_DFL && default_action(sig) == Default_::Ignore);
            drop(actions);
            drop(mm);
            if ignore {
                // Setting a signal to be ignored discards it if pending.
                t.proc.pending.lock().unwrap().remove(&sig);
                for th in t.proc.threads.lock().unwrap().iter() {
                    th.pending.lock().unwrap().remove(&sig);
                }
            }
            if sig == SIGCHLD && (w(0) == SIG_IGN || w(1) & SA_NOCLDWAIT != 0) && self.strace {
                eprintln!("[droidrt] note: SIGCHLD auto-reaping is not implemented");
            }
        }
        0
    }

    pub(super) fn sys_rt_sigprocmask(&self, t: &Thread, how: u64, set: u64, old: u64) -> i64 {
        let cur = t.mask.load(Ordering::Relaxed);
        let mut mm = t.proc.mm();
        if old != 0
            && let Err(e) = mm.write_u64(old, cur) {
                return -e;
            }
        if set == 0 {
            return 0;
        }
        let s = match mm.read_u64(set) {
            Ok(s) => s,
            Err(e) => return -e,
        };
        let new = match how {
            0 => cur | s,  // SIG_BLOCK
            1 => cur & !s, // SIG_UNBLOCK
            2 => s,        // SIG_SETMASK
            _ => return -EINVAL,
        };
        t.mask.store(new & !UNBLOCKABLE, Ordering::Relaxed);
        0
    }

    pub(super) fn sys_rt_sigsuspend(&self, t: &Thread, set: u64) -> i64 {
        let mask = match t.proc.mm().read_u64(set) {
            Ok(m) => m,
            Err(e) => return -e,
        };
        let old = t.mask.swap(mask & !UNBLOCKABLE, Ordering::Relaxed);
        *t.saved_mask.lock().unwrap() = Some(old);
        while !t.interrupted() {
            std::thread::sleep(POLL.min(std::time::Duration::from_millis(2)));
        }
        -EINTR
    }

    pub(super) fn sys_sigaltstack(&self, t: &Thread, ss: u64, old: u64) -> i64 {
        let mut mm = t.proc.mm();
        let mut alt = t.altstack.lock().unwrap();
        if old != 0 {
            let mut b = [0u8; 24];
            b[0..8].copy_from_slice(&alt.0.to_le_bytes());
            b[8..12].copy_from_slice(&alt.2.to_le_bytes());
            b[16..24].copy_from_slice(&alt.1.to_le_bytes());
            if let Err(e) = mm.write(old, &b) {
                return -e;
            }
        }
        if ss != 0 {
            let b = match mm.read_vec(ss, 24) {
                Ok(b) => b,
                Err(e) => return -e,
            };
            let sp = u64::from_le_bytes(b[0..8].try_into().unwrap());
            let flags = i32::from_le_bytes(b[8..12].try_into().unwrap());
            let size = u64::from_le_bytes(b[16..24].try_into().unwrap());
            *alt = if flags & SS_DISABLE != 0 { (0, 0, SS_DISABLE) } else { (sp, size, 0) };
        }
        0
    }

    // ---- arm64 frames ----

    fn setup_frame(&self, t: &Thread, state: &mut CpuState, sig: u32, info: &SigInfo, act: &SigAction, mask: u64) -> Result<(), i64> {
        let CpuState::Aarch64(s) = state else {
            return Err(EOPNOTSUPP); // x86_64 frames: not written yet
        };
        let (alt_sp, alt_size, alt_flags) = *t.altstack.lock().unwrap();
        let on_alt = alt_flags != SS_DISABLE && s.sp > alt_sp && s.sp <= alt_sp + alt_size;
        let top = if act.flags & SA_ONSTACK != 0 && alt_flags != SS_DISABLE && !on_alt { alt_sp + alt_size } else { s.sp };

        let frame = (top - FRAME_SIZE - 16) & !15;
        let mut b = vec![0u8; (FRAME_SIZE + 16) as usize];
        let mut put = |off: u64, v: &[u8]| b[off as usize..off as usize + v.len()].copy_from_slice(v);
        put(0, &info.0);
        // ucontext: uc_flags, uc_link, uc_stack, uc_sigmask.
        put(UC + 16, &alt_sp.to_le_bytes());
        put(UC + 24, &(if on_alt { SS_ONSTACK } else { alt_flags }).to_le_bytes());
        put(UC + 32, &alt_size.to_le_bytes());
        put(UC + 40, &mask.to_le_bytes());
        // sigcontext.
        put(MC, &(if matches!(sig, 4 | 7 | 8 | 11) { info.addr() } else { 0 }).to_le_bytes());
        for (i, x) in s.x.iter().enumerate() {
            put(MC + 8 + i as u64 * 8, &x.to_le_bytes());
        }
        put(MC + 256, &s.sp.to_le_bytes());
        put(MC + 264, &s.pc.to_le_bytes());
        put(MC + 272, &s.pstate.to_le_bytes());
        // fpsimd_context, then the zero terminator (already zero).
        put(FPSIMD, &FPSIMD_MAGIC.to_le_bytes());
        put(FPSIMD + 4, &FPSIMD_SIZE.to_le_bytes());
        put(FPSIMD + 8, &(s.fpsr as u32).to_le_bytes());
        put(FPSIMD + 12, &(s.fpcr as u32).to_le_bytes());
        for (i, v) in s.v.iter().enumerate() {
            put(FPSIMD + 16 + i as u64 * 16, &v.to_le_bytes());
        }
        // Frame record for unwinders.
        put(FRAME_SIZE, &s.x[29].to_le_bytes());
        put(FRAME_SIZE + 8, &s.x[30].to_le_bytes());
        t.proc.mm().write(frame, &b)?;

        s.x[0] = sig as u64;
        s.x[1] = frame;
        s.x[2] = frame + UC;
        s.x[29] = frame + FRAME_SIZE;
        s.x[30] = if act.restorer != 0 { act.restorer } else { SIGRETURN_TRAMPOLINE };
        s.sp = frame;
        s.pc = act.handler;
        Ok(())
    }

    pub(super) fn sys_rt_sigreturn(&self, t: &Thread, vcpu: &mut dyn Vcpu) -> Ret {
        let mut state = vcpu.state();
        let CpuState::Aarch64(s) = &mut state else {
            return Ret::Value(-ENOSYS);
        };
        let frame = s.sp;
        let b = match t.proc.mm().read_vec(frame, FRAME_SIZE as usize) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("[droidrt] pid {}: bad signal frame at {frame:#x}", t.proc.pid);
                self.exit_group(&t.proc, SIGSEGV as i32 | 0x80, None);
                return Ret::ExitThread;
            }
        };
        let r = |off: u64| u64::from_le_bytes(b[off as usize..off as usize + 8].try_into().unwrap());
        for i in 0..31 {
            s.x[i] = r(MC + 8 + i as u64 * 8);
        }
        s.sp = r(MC + 256);
        s.pc = r(MC + 264);
        s.pstate = r(MC + 272);
        if u32::from_le_bytes(b[FPSIMD as usize..FPSIMD as usize + 4].try_into().unwrap()) == FPSIMD_MAGIC {
            s.fpsr = u32::from_le_bytes(b[FPSIMD as usize + 8..FPSIMD as usize + 12].try_into().unwrap()) as u64;
            s.fpcr = u32::from_le_bytes(b[FPSIMD as usize + 12..FPSIMD as usize + 16].try_into().unwrap()) as u64;
            for i in 0..32 {
                let o = (FPSIMD + 16 + i * 16) as usize;
                s.v[i as usize] = u128::from_le_bytes(b[o..o + 16].try_into().unwrap());
            }
        }
        t.mask.store(r(UC + 40) & !UNBLOCKABLE, Ordering::Relaxed);
        vcpu.set_state(&state);
        Ret::NoReturn
    }
}

/// Offsets in arm64's `struct rt_sigframe { siginfo; ucontext }`.
const UC: u64 = 128;
const MC: u64 = UC + 176;
const FPSIMD: u64 = MC + 288;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: u32 = 528;
const FRAME_SIZE: u64 = UC + 4560;

/// Re-arms an interrupted syscall: back up over the trap instruction and
/// restore the register the return value overwrote.
fn rewind(state: &mut CpuState, regs: &SyscallRegs) {
    match state {
        CpuState::Aarch64(s) => {
            s.pc -= 4;
            s.x[0] = regs.args[0];
        }
        CpuState::X86_64(s) => {
            s.rip -= 2;
            s.gpr[0] = regs.nr;
        }
    }
}
