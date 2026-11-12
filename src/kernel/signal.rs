//! Signals: dispositions, pending sets, delivery through Linux-compatible
//! signal frames, and rt_sigreturn. arm64 frames follow
//! arch/arm64/kernel/signal.c. x86_64 frames follow
//! arch/x86/kernel/signal_64.c and uapi `struct sigcontext_64`: `pretcode`,
//! `ucontext` (sigcontext + 8-byte `uc_sigmask`), `siginfo`, and a
//! 64-byte-aligned FXSAVE/XSAVE image above the frame.

use super::{Kernel, Process, Ret, Thread};
use crate::errno::*;
use crate::hv::{CpuState, SyscallRegs, Vcpu};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub const SIGILL: u32 = 4;
pub const SIGKILL: u32 = 9;
pub const SIGBUS: u32 = 7;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
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
const SA_RESTORER: u64 = 0x0400_0000;
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
    /// (SIGCHLD is SIG_IGN, SA_NOCLDWAIT is set): either way children are
    /// reaped as they exit instead of becoming zombies.
    pub fn child_ignore(&self) -> (bool, bool) {
        let a = self.get(SIGCHLD);
        (a.handler == SIG_IGN, a.flags & SA_NOCLDWAIT != 0)
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
    /// Sent by kill/tgkill (SI_USER) from `pid`, uid 0 unless `with_uid`.
    pub fn user(sig: u32, pid: i32) -> SigInfo {
        let mut s = SigInfo::base(sig, 0);
        s.0[16..20].copy_from_slice(&pid.to_le_bytes());
        s
    }
    /// A timer's expiry: si_tid, si_overrun, si_value.
    pub fn timer(sig: u32, code: i32, id: i32, overrun: i32, value: u64) -> SigInfo {
        let mut s = SigInfo::base(sig, code);
        s.0[16..20].copy_from_slice(&id.to_le_bytes());
        s.0[20..24].copy_from_slice(&overrun.to_le_bytes());
        s.0[24..32].copy_from_slice(&value.to_le_bytes());
        s
    }
    /// Whether this is the expiry of POSIX timer `id`.
    pub fn is_timer(&self, id: i32) -> bool {
        self.0[8..12] == (-2i32).to_le_bytes() && self.0[16..20] == id.to_le_bytes()
    }
    /// Sent by tgkill or tkill rather than kill: bionic's timer threads tell
    /// their shutdown from an expiry by this.
    pub fn tkill(mut self) -> SigInfo {
        self.0[8..12].copy_from_slice(&(-6i32).to_le_bytes());
        self
    }
    /// Sets si_uid (the sender's, or for SIGCHLD the child's, real uid).
    pub fn with_uid(mut self, uid: u32) -> SigInfo {
        self.0[20..24].copy_from_slice(&uid.to_le_bytes());
        self
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
        "",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    NAMES
        .get(sig as usize)
        .map_or_else(|| format!("signal {sig}"), |s| s.to_string())
}

/// Whether `act` makes `sig` a no-op (for init, any default action is).
fn ignored(act: &SigAction, sig: u32, init: bool) -> bool {
    sig != SIGKILL && (act.handler == SIG_IGN || (act.handler == SIG_DFL && (init || default_action(sig) == Default_::Ignore)))
}

impl Thread {
    pub(super) fn has_deliverable_signal(&self) -> bool {
        let mask = self.mask.load(Ordering::Relaxed) & !UNBLOCKABLE;
        let unmasked = |p: &std::collections::HashMap<u32, SigInfo>| {
            p.keys().copied().filter(|&s| bit(s) & mask == 0).collect::<Vec<_>>()
        };
        let mut sigs = unmasked(&self.pending.lock().unwrap());
        sigs.extend(unmasked(&self.proc.pending.lock().unwrap()));
        if sigs.is_empty() {
            return false;
        }
        // One queued while blocked may be ignored now: it interrupts nothing
        // (deliver_signals drops it). The root process is always pid 1.
        let actions = self.proc.sig.lock().unwrap();
        sigs.into_iter().any(|s| !ignored(&actions.get(s), s, self.proc.pid == 1))
    }

    /// The lowest pending signal in `set` (this thread's first), dequeued.
    fn take_from(&self, set: u64) -> Option<(u32, SigInfo)> {
        for pending in [&self.pending, &self.proc.pending] {
            let mut p = pending.lock().unwrap();
            if let Some(&sig) = p.keys().filter(|&&s| bit(s) & set != 0).min() {
                return p.remove(&sig).map(|i| (sig, i));
            }
        }
        None
    }

    fn take_signal(&self) -> Option<(u32, SigInfo)> {
        // Synchronous signals first, as Linux's next_signal does: a fault's frame
        // must be the one the guest runs, with the faulting PC in it.
        const SYNCHRONOUS: [u32; 6] = [SIGSEGV, SIGBUS, SIGILL, 5 /* SIGTRAP */, 8 /* SIGFPE */, 31 /* SIGSYS */];
        let mask = self.mask.load(Ordering::Relaxed) & !UNBLOCKABLE;
        for pending in [&self.pending, &self.proc.pending] {
            let mut p = pending.lock().unwrap();
            let ready = |s: &&u32| bit(**s) & mask == 0;
            let sig = p.keys().filter(ready).find(|s| SYNCHRONOUS.contains(s)).or_else(|| p.keys().filter(ready).min()).copied();
            if let Some(sig) = sig {
                return p.remove(&sig).map(|i| (sig, i));
            }
        }
        None
    }
}

impl Kernel {
    /// sig_ignored: whether sending `sig` is a no-op. A blocked signal is
    /// always queued (its disposition may change, or signalfd reads it).
    /// The root process is pid 1: like Linux's init (SIGNAL_UNKILLABLE) it
    /// gets only signals it handles, never SIGKILL; faults still kill it.
    fn discarded(&self, proc: &Process, sig: u32, blocked: bool) -> bool {
        let init = self.is_init(proc);
        if init && (sig == SIGKILL || sig == SIGSTOP) {
            return true;
        }
        if blocked {
            return false;
        }
        let act = proc.sig.lock().unwrap().get(sig);
        ignored(&act, sig, init)
    }

    fn is_init(&self, proc: &Process) -> bool {
        proc.pid == self.root_pid.load(Ordering::Relaxed)
    }

    pub(super) fn send_process_signal(&self, proc: &Arc<Process>, sig: u32, info: SigInfo) {
        let blocked = proc.threads.lock().unwrap().iter().any(|t| t.mask.load(Ordering::Relaxed) & bit(sig) != 0);
        if proc.status.lock().unwrap().is_some() || self.discarded(proc, sig, blocked) {
            return;
        }
        if sig == SIGKILL {
            self.exit_group(proc, SIGKILL as i32, None);
            return;
        }
        proc.pending.lock().unwrap().insert(sig, info);
        if blocked {
            super::wait::EVENTS.bump_key(Arc::as_ptr(proc) as usize); // a signalfd reader may be polling for it
        }
        // Wake a thread that can take it.
        let threads = proc.threads.lock().unwrap();
        for th in threads.iter().filter(|th| th.sigwait_set.load(Ordering::SeqCst) & bit(sig) != 0) {
            th.wake_sleeper();
        }
        if let Some(th) = threads
            .iter()
            .find(|t| t.mask.load(Ordering::Relaxed) & bit(sig) == 0)
        {
            th.kick();
        }
    }

    pub(super) fn send_thread_signal(&self, th: &Arc<Thread>, sig: u32, info: SigInfo) {
        if self.discarded(&th.proc, sig, th.mask.load(Ordering::Relaxed) & bit(sig) != 0) {
            return;
        }
        if sig == SIGKILL {
            self.exit_group(&th.proc, SIGKILL as i32, None);
            return;
        }
        let blocked = th.mask.load(Ordering::Relaxed) & bit(sig) != 0;
        th.pending.lock().unwrap().insert(sig, info);
        if blocked {
            super::wait::EVENTS.bump_key(Arc::as_ptr(&th.proc) as usize); // a signalfd reader may be polling for it
        }
        th.kick();
    }

    /// A fault the thread caused: delivered to its handler, or fatal.
    /// Whether a fault raising `sig` runs a handler rather than killing.
    pub(super) fn signal_caught(&self, t: &Thread, sig: u32) -> bool {
        let act = t.proc.sig.lock().unwrap().get(sig);
        act.handler != SIG_DFL && act.handler != SIG_IGN && t.mask.load(Ordering::Relaxed) & bit(sig) == 0
    }

    pub(super) fn force_signal(&self, t: &Arc<Thread>, sig: u32, info: SigInfo, pc: u64) {
        let act = t.proc.sig.lock().unwrap().get(sig);
        let blocked = t.mask.load(Ordering::Relaxed) & bit(sig) != 0;
        if act.handler == SIG_DFL || act.handler == SIG_IGN || blocked {
            eprintln!(
                "[zeroemu] pid {} tid {} ({}): {} at pc={pc:#x} addr={:#x}",
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
    pub(super) fn deliver_signals(
        &self,
        t: &Arc<Thread>,
        vcpu: &mut dyn Vcpu,
        mut restart: Option<SyscallRegs>,
    ) {
        while let Some((sig, info)) = t.take_signal() {
            let act = t.proc.sig.lock().unwrap().get(sig);
            if act.handler == SIG_IGN {
                continue;
            }
            if act.handler == SIG_DFL {
                match default_action(sig) {
                    Default_::Ignore => continue,
                    _ if self.is_init(&t.proc) => continue, // queued while blocked
                    d => {
                        if d == Default_::Core || self.strace {
                            super::binder::dump_rings(t.proc.pid);
                            eprintln!(
                                "[zeroemu] pid {} ({}) killed by {}",
                                t.proc.pid,
                                t.proc.exe.lock().unwrap(),
                                sig_name(sig)
                            );
                            self.report_last_fault(t);
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
            let old_mask = t
                .saved_mask
                .lock()
                .unwrap()
                .take()
                .unwrap_or(t.mask.load(Ordering::Relaxed));
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
                    eprintln!(
                        "[zeroemu] pid {}: cannot deliver {} (errno {e}); killing it",
                        t.proc.pid,
                        sig_name(sig)
                    );
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
            actions.0[sig as usize] = SigAction {
                handler: w(0),
                flags: w(1),
                restorer: w(2),
                mask: w(3) & !UNBLOCKABLE,
            };
            let ignore =
                w(0) == SIG_IGN || (w(0) == SIG_DFL && default_action(sig) == Default_::Ignore);
            drop(actions);
            drop(mm);
            if ignore {
                // Setting a signal to be ignored discards it if pending.
                t.proc.pending.lock().unwrap().remove(&sig);
                for th in t.proc.threads.lock().unwrap().iter() {
                    th.pending.lock().unwrap().remove(&sig);
                }
            }
        }
        0
    }

    pub(super) fn sys_rt_sigprocmask(&self, t: &Thread, how: u64, set: u64, old: u64) -> i64 {
        let cur = t.mask.load(Ordering::Relaxed);
        let mut mm = t.proc.mm();
        if old != 0
            && let Err(e) = mm.write_u64(old, cur)
        {
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
            super::vcpus::blocking();
            t.nap(super::IDLE);
        }
        -EINTR
    }

    /// sigwaitinfo / sigtimedwait: takes a signal of `set` (normally blocked)
    /// without running its handler. ART's Signal Catcher sits in this.
    pub(super) fn sys_rt_sigtimedwait(&self, t: &Thread, set: u64, info: u64, timeout: u64) -> i64 {
        let (want, deadline) = {
            let mut mm = t.proc.mm();
            let want = match mm.read_u64(set) {
                Ok(m) => m & !UNBLOCKABLE,
                Err(e) => return -e,
            };
            let deadline = if timeout == 0 {
                None
            } else {
                match (mm.read_u64(timeout), mm.read_u64(timeout + 8)) {
                    (Ok(s), Ok(ns)) => match super::wait::guest_timespec(s, ns) {
                        Ok(d) => Some(super::wait::instant_after(d)),
                        Err(e) => return -e,
                    },
                    (Err(e), _) | (_, Err(e)) => return -e,
                }
            };
            (want, deadline)
        };
        // Published before looking, so a signal sent after the look finds us.
        t.sigwait_set.store(want, Ordering::SeqCst);
        let result = loop {
            if let Some((sig, si)) = t.take_from(want) {
                if info != 0
                    && let Err(e) = t.proc.mm().write(info, &si.0)
                {
                    break -e;
                }
                break sig as i64;
            }
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                break -EAGAIN;
            }
            if t.interrupted() {
                break -EINTR; // a signal outside the set, to be handled
            }
            let nap = deadline.map_or(super::IDLE, |d| d.saturating_duration_since(std::time::Instant::now()).min(super::IDLE));
            super::vcpus::blocking();
            t.nap(nap);
        };
        t.sigwait_set.store(0, Ordering::SeqCst);
        result
    }

    /// The signals pending for the thread or its process.
    pub(super) fn sys_rt_sigpending(&self, t: &Thread, set: u64) -> i64 {
        let bits = [&t.pending, &t.proc.pending].iter().flat_map(|p| p.lock().unwrap().keys().copied().collect::<Vec<u32>>()).fold(0u64, |acc, s| acc | bit(s));
        match t.proc.mm().write_u64(set, bits) {
            Ok(()) => 0,
            Err(e) => -e,
        }
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
            *alt = if flags & SS_DISABLE != 0 {
                (0, 0, SS_DISABLE)
            } else {
                (sp, size, 0)
            };
        }
        0
    }

    // ---- arm64 frames ----

    fn setup_frame(
        &self,
        t: &Thread,
        state: &mut CpuState,
        sig: u32,
        info: &SigInfo,
        act: &SigAction,
        mask: u64,
    ) -> Result<(), i64> {
        if let CpuState::X86_64(_) = state {
            return self.setup_frame_x64(t, state, sig, info, act, mask);
        }
        let CpuState::Aarch64(s) = state else {
            unreachable!();
        };
        let (alt_sp, alt_size, alt_flags) = *t.altstack.lock().unwrap();
        let on_alt = alt_flags != SS_DISABLE && s.sp > alt_sp && s.sp <= alt_sp + alt_size;
        let top = if act.flags & SA_ONSTACK != 0 && alt_flags != SS_DISABLE && !on_alt {
            alt_sp + alt_size
        } else {
            s.sp
        };

        let frame = (top - FRAME_SIZE - 16) & !15;
        let mut b = vec![0u8; (FRAME_SIZE + 16) as usize];
        let mut put =
            |off: u64, v: &[u8]| b[off as usize..off as usize + v.len()].copy_from_slice(v);
        put(0, &info.0);
        // ucontext: uc_flags, uc_link, uc_stack, uc_sigmask.
        put(UC + 16, &alt_sp.to_le_bytes());
        put(
            UC + 24,
            &(if on_alt { SS_ONSTACK } else { alt_flags }).to_le_bytes(),
        );
        put(UC + 32, &alt_size.to_le_bytes());
        put(UC + 40, &mask.to_le_bytes());
        // sigcontext.
        put(
            MC,
            &(if matches!(sig, 4 | 7 | 8 | 11) {
                info.addr()
            } else {
                0
            })
            .to_le_bytes(),
        );
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
        // Only if it says so, as Linux: bionic passes the caller's sa_restorer through as
        // it found it, and a caller that never set the field left whatever was there.
        s.x[30] = if act.flags & SA_RESTORER != 0 && act.restorer != 0 {
            act.restorer
        } else {
            SIGRETURN_TRAMPOLINE
        };
        s.sp = frame;
        s.pc = act.handler;
        Ok(())
    }

    pub(super) fn sys_rt_sigreturn(&self, t: &Thread, vcpu: &mut dyn Vcpu) -> Ret {
        let mut state = vcpu.state();
        let CpuState::Aarch64(s) = &mut state else {
            return self.rt_sigreturn_x64(t, vcpu, &mut state);
        };
        let frame = s.sp;
        let b = match t.proc.mm().read_vec(frame, FRAME_SIZE as usize) {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "[zeroemu] pid {}: bad signal frame at {frame:#x}",
                    t.proc.pid
                );
                self.exit_group(&t.proc, SIGSEGV as i32 | 0x80, None);
                return Ret::ExitThread;
            }
        };
        let r =
            |off: u64| u64::from_le_bytes(b[off as usize..off as usize + 8].try_into().unwrap());
        for i in 0..31 {
            s.x[i] = r(MC + 8 + i as u64 * 8);
        }
        s.sp = r(MC + 256);
        s.pc = r(MC + 264);
        s.pstate = r(MC + 272);
        if u32::from_le_bytes(b[FPSIMD as usize..FPSIMD as usize + 4].try_into().unwrap())
            == FPSIMD_MAGIC
        {
            s.fpsr = u32::from_le_bytes(
                b[FPSIMD as usize + 8..FPSIMD as usize + 12]
                    .try_into()
                    .unwrap(),
            ) as u64;
            s.fpcr = u32::from_le_bytes(
                b[FPSIMD as usize + 12..FPSIMD as usize + 16]
                    .try_into()
                    .unwrap(),
            ) as u64;
            for i in 0..32 {
                let o = (FPSIMD + 16 + i * 16) as usize;
                s.v[i as usize] = u128::from_le_bytes(b[o..o + 16].try_into().unwrap());
            }
        }
        t.mask.store(r(UC + 40) & !UNBLOCKABLE, Ordering::Relaxed);
        vcpu.set_state(&state);
        Ret::NoReturn
    }

    /// Linux x86_64 `rt_sigframe` (arch/x86/kernel/signal_64.c). The handler is
    /// entered with RSP pointing at `pretcode` (so `ret` jumps to the restorer)
    /// and `(RSP + 8)` 16-byte aligned. `fpu` is copied to a 64-byte-aligned
    /// FXSAVE/XSAVE image above the frame; `sigcontext.fpstate` points at it.
    fn setup_frame_x64(
        &self,
        t: &Thread,
        state: &mut CpuState,
        sig: u32,
        info: &SigInfo,
        act: &SigAction,
        mask: u64,
    ) -> Result<(), i64> {
        let CpuState::X86_64(s) = state else {
            unreachable!()
        };
        let (alt_sp, alt_size, alt_flags) = *t.altstack.lock().unwrap();
        let sp0 = s.gpr[4];
        let on_alt = alt_flags != SS_DISABLE && sp0 > alt_sp && sp0 <= alt_sp + alt_size;
        let mut sp = sp0.saturating_sub(128); // SysV red zone
        if act.flags & SA_ONSTACK != 0 && alt_flags != SS_DISABLE && !on_alt {
            sp = alt_sp.saturating_add(alt_size);
        }
        let fpu = x64_fpstate(&s.fpu);
        let (frame, fp_addr) = x64_frame_layout(sp, fpu.len() as u64);
        if frame.saturating_add(X64_FRAME_SIZE) > fp_addr {
            return Err(EFAULT);
        }
        let mut b = vec![0u8; (fp_addr + fpu.len() as u64 - frame) as usize];
        let put = |b: &mut [u8], off: u64, v: &[u8]| {
            let o = off as usize;
            b[o..o + v.len()].copy_from_slice(v);
        };
        let restorer = if act.restorer != 0 {
            act.restorer
        } else {
            SIGRETURN_TRAMPOLINE
        };
        put(&mut b, 0, &restorer.to_le_bytes());
        let uc_flags = UC_SIGCONTEXT_SS
            | UC_STRICT_RESTORE_SS
            | if fpu.len() > 512 { UC_FP_XSTATE } else { 0 };
        put(&mut b, X64_UC, &uc_flags.to_le_bytes());
        put(&mut b, X64_UC + 16, &alt_sp.to_le_bytes());
        put(
            &mut b,
            X64_UC + 24,
            &(if on_alt { SS_ONSTACK } else { alt_flags }).to_le_bytes(),
        );
        put(&mut b, X64_UC + 32, &alt_size.to_le_bytes());
        store_x64_gprs(&mut b, X64_SC, &s.gpr);
        put(&mut b, X64_SC + 128, &s.rip.to_le_bytes());
        put(&mut b, X64_SC + 136, &s.rflags.to_le_bytes());
        put(&mut b, X64_SC + 144, &X64_USER_CS.to_le_bytes());
        put(&mut b, X64_SC + 150, &X64_USER_SS.to_le_bytes());
        put(&mut b, X64_SC + 168, &mask.to_le_bytes());
        let cr2 = if matches!(sig, 4 | 7 | 8 | 11) {
            info.addr()
        } else {
            0
        };
        put(&mut b, X64_SC + 176, &cr2.to_le_bytes());
        put(&mut b, X64_SC + 184, &fp_addr.to_le_bytes());
        put(&mut b, X64_SIGMASK, &mask.to_le_bytes());
        put(&mut b, X64_INFO, &info.0);
        let fp_off = (fp_addr - frame) as usize;
        b[fp_off..fp_off + fpu.len()].copy_from_slice(&fpu);
        t.proc.mm().write(frame, &b)?;

        s.gpr[7] = sig as u64; // rdi
        s.gpr[6] = frame + X64_INFO; // rsi = siginfo
        s.gpr[2] = frame + X64_UC; // rdx = ucontext
        s.gpr[0] = 0; // rax, as Linux does for an unprototyped handler
        s.gpr[4] = frame;
        s.rip = act.handler;
        Ok(())
    }

    /// `rt_sigreturn`: the restorer's `ret` already popped `pretcode`, so the
    /// frame starts at `RSP - 8` (arch/x86/kernel/signal_64.c).
    fn rt_sigreturn_x64(&self, t: &Thread, vcpu: &mut dyn Vcpu, state: &mut CpuState) -> Ret {
        let CpuState::X86_64(s) = state else {
            unreachable!()
        };
        let frame = s.gpr[4].wrapping_sub(8);
        let b = match t.proc.mm().read_vec(frame, X64_FRAME_SIZE as usize) {
            Ok(b) => b,
            Err(_) => return self.bad_sigframe(t, frame),
        };
        let r =
            |off: u64| u64::from_le_bytes(b[off as usize..off as usize + 8].try_into().unwrap());
        load_x64_gprs(&b, X64_SC, &mut s.gpr);
        s.rip = r(X64_SC + 128);
        // Same mask as Linux `FIX_EFLAGS`: condition codes, DF, TF, RF, AC.
        // IF and the reserved bit stay as they were (CPL 3 cannot clear IF).
        s.rflags = (s.rflags & !X64_FIX_EFLAGS) | (r(X64_SC + 136) & X64_FIX_EFLAGS) | 2;
        let fp = r(X64_SC + 184);
        if fp != 0 {
            let mut mm = t.proc.mm();
            match read_x64_fpstate(&mut mm, fp) {
                Ok(image) => s.fpu = image,
                Err(_) => return self.bad_sigframe(t, frame),
            }
        }
        t.mask
            .store(r(X64_SIGMASK) & !UNBLOCKABLE, Ordering::Relaxed);
        vcpu.set_state(state);
        Ret::NoReturn
    }

    fn bad_sigframe(&self, t: &Thread, frame: u64) -> Ret {
        eprintln!(
            "[zeroemu] pid {}: bad signal frame at {frame:#x}",
            t.proc.pid
        );
        self.exit_group(&t.proc, SIGSEGV as i32 | 0x80, None);
        Ret::ExitThread
    }
}

/// Offsets in arm64's `struct rt_sigframe { siginfo; ucontext }`.
const UC: u64 = 128;
const MC: u64 = UC + 176;
const FPSIMD: u64 = MC + 288;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: u32 = 528;
const FRAME_SIZE: u64 = UC + 4560;

/// Offsets in Linux's x86_64 `struct rt_sigframe` (pretcode, ucontext, siginfo).
/// `ucontext` is 304 bytes: flags, link, 24-byte `stack_t`, 256-byte
/// `sigcontext`, 8-byte kernel `sigset_t`. User CS/SS are zeroemu's GDT slots
/// (`hv::x86::SEL_UCODE` / `SEL_UDATA`), not Linux's 0x33/0x2b.
const X64_UC: u64 = 8;
const X64_SC: u64 = 48;
const X64_SIGMASK: u64 = 304;
const X64_INFO: u64 = 312;
const X64_FRAME_SIZE: u64 = 440;
const X64_USER_CS: u16 = 0x23;
const X64_USER_SS: u16 = 0x1b;
const UC_FP_XSTATE: u64 = 1;
const UC_SIGCONTEXT_SS: u64 = 2;
const UC_STRICT_RESTORE_SS: u64 = 4;
/// `FP_XSTATE_MAGIC1` (`_fpx_sw_bytes` at FXSAVE offset 464).
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// AC|OF|DF|TF|SF|ZF|AF|PF|CF|RF.
const X64_FIX_EFLAGS: u64 = (1 << 18)
    | (1 << 11)
    | (1 << 10)
    | (1 << 8)
    | (1 << 7)
    | (1 << 6)
    | (1 << 4)
    | (1 << 2)
    | 1
    | (1 << 16);
// Both frame ABIs are implemented, so nothing returns this anymore. Keeping
// the reference leaves the errno available without a dead-code warning.
const _: i64 = EOPNOTSUPP;
/// sigcontext GPR order: r8–r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp.
const X64_GPR_ORDER: [usize; 16] = [8, 9, 10, 11, 12, 13, 14, 15, 7, 6, 5, 3, 2, 0, 1, 4];

fn store_x64_gprs(b: &mut [u8], base: u64, gpr: &[u64; 16]) {
    for (i, &src) in X64_GPR_ORDER.iter().enumerate() {
        let off = (base + i as u64 * 8) as usize;
        b[off..off + 8].copy_from_slice(&gpr[src].to_le_bytes());
    }
}

fn load_x64_gprs(b: &[u8], base: u64, gpr: &mut [u64; 16]) {
    for (i, &dst) in X64_GPR_ORDER.iter().enumerate() {
        let off = (base + i as u64 * 8) as usize;
        gpr[dst] = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
    }
}

/// `get_sigframe`: FXSAVE/XSAVE at a 64-byte boundary, then
/// `round_down(fp - frame_size, 16) - 8` so the handler's entry RSP is 8 mod 16.
fn x64_frame_layout(sp: u64, fp_len: u64) -> (u64, u64) {
    let fp_addr = sp.saturating_sub(fp_len) & !63;
    let frame = (fp_addr.saturating_sub(X64_FRAME_SIZE) & !15).saturating_sub(8);
    (frame, fp_addr)
}

/// FXSAVE (512 bytes) or the backend XSAVE image, with Linux's software
/// reserved header stamped when the image carries state past the legacy region.
fn x64_fpstate(fpu: &[u8]) -> Vec<u8> {
    let mut image = if fpu.len() >= 512 {
        fpu.to_vec()
    } else {
        let mut image = vec![0u8; 512];
        image[..fpu.len()].copy_from_slice(fpu);
        if fpu.is_empty() {
            image[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
            image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
            image[28..32].copy_from_slice(&0xffffu32.to_le_bytes());
        }
        image
    };
    if image.len() > 512 {
        image[464..468].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        let xstate = image.len() as u32;
        image[468..472].copy_from_slice(&xstate.saturating_add(4).to_le_bytes());
        if image.len() >= 520 {
            let xfeatures = image[512..520].to_vec();
            image[472..480].copy_from_slice(&xfeatures);
        }
        image[480..484].copy_from_slice(&xstate.to_le_bytes());
    }
    image
}

fn read_x64_fpstate(mm: &mut crate::mm::AddressSpace, fp: u64) -> Result<Vec<u8>, i64> {
    let head = mm.read_vec(fp, 512)?;
    if u32::from_le_bytes(head[464..468].try_into().unwrap()) != FP_XSTATE_MAGIC1 {
        return Ok(head);
    }
    let n = u32::from_le_bytes(head[480..484].try_into().unwrap()) as usize;
    if !(512..=8192).contains(&n) {
        return Err(EFAULT);
    }
    if n == 512 {
        Ok(head)
    } else {
        mm.read_vec(fp, n)
    }
}

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

#[cfg(test)]
mod x64_frame_tests {
    use super::*;

    #[test]
    fn x64_frame_matches_the_linux_layout() {
        // pretcode + 304-byte ucontext + 128-byte siginfo.
        assert_eq!(X64_FRAME_SIZE, 8 + 304 + 128);
        assert_eq!(X64_SC, 48);
        assert_eq!(X64_SIGMASK, 304);
        assert_eq!(X64_INFO, 312);
        // fpstate pointer is 184 bytes into sigcontext.
        assert_eq!(X64_SC + 184, 232);
        let (frame, fp) = x64_frame_layout(0x7f00_0000, 512);
        assert_eq!(frame & 15, 8, "handler entry RSP is 8 mod 16");
        assert_eq!(fp & 63, 0);
        assert!(frame + X64_FRAME_SIZE <= fp);
        let (frame, fp) = x64_frame_layout(0x7f00_0000, 832);
        assert_eq!(frame & 15, 8);
        assert_eq!(fp & 63, 0);
        assert!(frame + X64_FRAME_SIZE <= fp);
    }

    #[test]
    fn x64_sigcontext_gprs_round_trip() {
        let mut gpr = [0u64; 16];
        for (i, g) in gpr.iter_mut().enumerate() {
            *g = 0x1000 + i as u64;
        }
        let mut b = vec![0u8; X64_FRAME_SIZE as usize];
        store_x64_gprs(&mut b, X64_SC, &gpr);
        let mut out = [0u64; 16];
        load_x64_gprs(&b, X64_SC, &mut out);
        assert_eq!(gpr, out);
        // rdi is the 9th sigcontext slot (after r8–r15).
        assert_eq!(
            u64::from_le_bytes(
                b[X64_SC as usize + 64..X64_SC as usize + 72]
                    .try_into()
                    .unwrap()
            ),
            gpr[7]
        );
        assert_eq!(
            u64::from_le_bytes(
                b[X64_SC as usize + 120..X64_SC as usize + 128]
                    .try_into()
                    .unwrap()
            ),
            gpr[4]
        );
    }

    #[test]
    fn x64_fpstate_stamps_the_xsave_header() {
        let legacy = x64_fpstate(&[]);
        assert_eq!(legacy.len(), 512);
        assert_eq!(u16::from_le_bytes(legacy[0..2].try_into().unwrap()), 0x037f);
        assert_eq!(u32::from_le_bytes(legacy[464..468].try_into().unwrap()), 0);
        let mut xsave = vec![0u8; 832];
        xsave[512..520].copy_from_slice(&0x7u64.to_le_bytes());
        let stamped = x64_fpstate(&xsave);
        assert_eq!(
            u32::from_le_bytes(stamped[464..468].try_into().unwrap()),
            FP_XSTATE_MAGIC1
        );
        assert_eq!(
            u32::from_le_bytes(stamped[480..484].try_into().unwrap()),
            832
        );
        assert_eq!(
            u64::from_le_bytes(stamped[472..480].try_into().unwrap()),
            0x7
        );
    }
}
