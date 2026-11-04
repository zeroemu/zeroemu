//! Process lifecycle: clone (threads and fork), execve, wait4/waitid, kill,
//! process groups and sessions, and reparenting when a parent exits.

use super::creds::Creds;
use super::signal::{SIGCHLD, SIGCONT, SigInfo};
use super::{ERESTARTSYS, Kernel, POLL, Process, Ret, Thread, int};
use crate::arch::Sysno;
use crate::elf;
use crate::errno::*;
use crate::hv::{CpuState, Vcpu};
use crate::mm::AddressSpace;
use crate::vfs::{S_IFMT, S_IFREG};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const CLONE_VM: u64 = 0x100;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const WNOHANG: u64 = 1;
const WSTOPPED: u64 = 2;
const WEXITED: u64 = 4;
const WCONTINUED: u64 = 8;
const WNOWAIT: u64 = 0x0100_0000;
/// __WNOTHREAD | __WALL | __WCLONE
const WAIT_LINUX: u64 = 0xe000_0000;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;

/// Which children a wait call is for.
#[derive(Clone, Copy)]
enum Which {
    Any,
    Pid(i32),
    Pgid(i32),
}

/// (pid, wait status, real uid) of an exited child.
type Exited = (i32, i32, u32);

/// A wait status as SIGCHLD/waitid report it: (si_code, si_status).
fn child_code(status: i32) -> (i32, i32) {
    match status {
        s if s & 0x7f == 0 => (CLD_EXITED, (s >> 8) & 0xff),
        s if s & 0x80 != 0 => (CLD_DUMPED, s & 0x7f),
        s => (CLD_KILLED, s & 0x7f),
    }
}

impl Kernel {
    pub(super) fn sys_clone(self: &Arc<Self>, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, a: [u64; 6]) -> Ret {
        let (flags, sp, ptid, ctid, tls) = self.arch.clone_args(a);
        let mut state = vcpu.state();
        state.set_return(0);
        if sp != 0 {
            state.set_sp(sp);
        }
        if flags & CLONE_SETTLS != 0 {
            state.set_tls(tls);
        }
        let tid = self.next_id.fetch_add(1, Ordering::Relaxed);
        let r = if flags & CLONE_THREAD != 0 {
            self.clone_thread(t, flags, tid, ptid, ctid, state)
        } else {
            self.fork(t, flags, tid, ptid, ctid, state)
        };
        Ret::Value(match r {
            Ok(()) => tid as i64,
            Err(e) => -e,
        })
    }

    fn clone_thread(self: &Arc<Self>, t: &Arc<Thread>, flags: u64, tid: i32, ptid: u64, ctid: u64, state: CpuState) -> Result<(), i64> {
        if flags & CLONE_VM == 0 || flags & CLONE_SIGHAND == 0 {
            return Err(EINVAL);
        }
        let th = Thread::new(tid, t.proc.clone(), t.mask.load(Ordering::Relaxed));
        *th.attrs.lock().unwrap() = t.attrs.lock().unwrap().fork();
        th.sec.inherit(&t.sec);
        {
            let mut mm = t.proc.mm();
            if flags & CLONE_PARENT_SETTID != 0 {
                mm.write_u32(ptid, tid as u32)?;
            }
            if flags & CLONE_CHILD_SETTID != 0 {
                mm.write_u32(ctid, tid as u32)?;
            }
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            th.clear_child_tid.store(ctid, Ordering::Relaxed);
        }
        t.proc.threads.lock().unwrap().push(th.clone());
        self.spawn(th, state).inspect_err(|_| {
            t.proc.threads.lock().unwrap().retain(|x| x.tid != tid);
        })
    }

    /// fork, vfork and posix_spawn. CLONE_VM without CLONE_THREAD (vfork) gets
    /// a copy too: equivalent for children that only exec or exit.
    fn fork(self: &Arc<Self>, t: &Arc<Thread>, flags: u64, pid: i32, ptid: u64, ctid: u64, state: CpuState) -> Result<(), i64> {
        let parent = &t.proc;
        let mut mm = parent.mm().fork(&self.kwin, self.alloc_asid())?;
        if flags & CLONE_PARENT_SETTID != 0 {
            parent.mm().write_u32(ptid, pid as u32)?;
        }
        if flags & CLONE_CHILD_SETTID != 0 {
            mm.write_u32(ctid, pid as u32)?;
        }
        let child = Arc::new(Process {
            pid,
            ppid: AtomicI32::new(parent.pid),
            mm: Mutex::new(Some(mm)),
            files: Mutex::new(parent.files.lock().unwrap().clone()),
            cwd: Mutex::new(parent.cwd.lock().unwrap().clone()),
            exe: Mutex::new(parent.exe.lock().unwrap().clone()),
            cmdline: Mutex::new(parent.cmdline.lock().unwrap().clone()),
            sig: Mutex::new(parent.sig.lock().unwrap().clone()),
            threads: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            child_cv: Condvar::new(),
            status: Mutex::new(None),
            exiting: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            knobs: Mutex::new(parent.knobs.lock().unwrap().clone()),
            creds: Mutex::new(parent.creds.lock().unwrap().clone()),
            attrs: Mutex::new(parent.attrs.lock().unwrap().fork(t.tid)),
            sec: parent.sec.clone(),
        });
        let th = Thread::new(pid, child.clone(), t.mask.load(Ordering::Relaxed));
        th.sec.inherit(&t.sec);
        *th.altstack.lock().unwrap() = *t.altstack.lock().unwrap();
        *th.attrs.lock().unwrap() = t.attrs.lock().unwrap().fork();
        if flags & CLONE_CHILD_CLEARTID != 0 {
            th.clear_child_tid.store(ctid, Ordering::Relaxed);
        }
        child.threads.lock().unwrap().push(th.clone());
        self.procs.lock().unwrap().insert(pid, child.clone());
        parent.children.lock().unwrap().push(pid);
        if let Err(e) = self.spawn(th, state) {
            parent.children.lock().unwrap().retain(|&c| c != pid);
            self.procs.lock().unwrap().remove(&pid);
            return Err(e);
        }
        Ok(())
    }

    pub(super) fn sys_execve(self: &Arc<Self>, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, path: u64, argv: u64, envp: u64) -> Ret {
        let read = || -> Result<(String, Vec<String>, Vec<String>), i64> {
            let mut mm = t.proc.mm();
            Ok((mm.read_cstr(path)?, read_strv(&mut mm, argv)?, read_strv(&mut mm, envp)?))
        };
        let (path, argv, envp) = match read() {
            Ok(x) => x,
            Err(e) => return Ret::Value(-e),
        };
        let cwd = t.proc.cwd.lock().unwrap().clone();
        let mut mm = match self.new_address_space() {
            Ok(m) => m,
            Err(e) => return Ret::Value(-e),
        };
        let cmdline = super::cmdline_bytes(&argv);
        let comm_path = path.clone();
        let (state, exe) = match self.load_program(&mut mm, &cwd, &path, argv, &envp) {
            Ok(x) => x,
            Err(e) => return Ret::Value(-e),
        };

        // Point of no return: other threads go first, so nothing still runs on
        // the old page tables when they are freed.
        self.exit_group_others(t);
        t.proc.files.lock().unwrap().close_on_exec();
        t.proc.sig.lock().unwrap().reset_on_exec();
        *t.altstack.lock().unwrap() = (0, 0, super::signal::SS_DISABLE);
        *t.proc.exe.lock().unwrap() = exe;
        *t.proc.cmdline.lock().unwrap() = cmdline;
        self.exec_attrs(t, &comm_path);
        if let Some(vfs) = self.vfs.as_deref() {
            self.selinux.exec(t, vfs, &cwd, &path);
        }
        vcpu.set_page_tables(mm.root);
        vcpu.set_state(&state);
        let old = t.proc.mm.lock().unwrap().replace(mm);
        drop(old);
        Ret::NoReturn
    }

    /// Kills the other threads of `t`'s process and waits until they are gone.
    fn exit_group_others(&self, t: &Arc<Thread>) {
        for th in t.proc.threads.lock().unwrap().iter() {
            if th.tid != t.tid {
                th.dying.store(true, Ordering::Release);
                th.kick();
            }
        }
        while t.proc.threads.lock().unwrap().len() > 1 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Loads `path` (an ELF or a `#!` script) into `mm` and builds its stack.
    /// Returns the initial register state and the executable's path.
    pub fn load_program(&self, mm: &mut AddressSpace, cwd: &str, path: &str, mut argv: Vec<String>, envp: &[String]) -> Result<(CpuState, String), i64> {
        let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
        let mut path = path.to_string();
        for _ in 0..4 {
            let node = vfs.resolve(cwd, &path, true)?;
            if vfs.stat(&node)?.mode & S_IFMT != S_IFREG {
                return Err(EACCES);
            }
            let data = vfs.read_all(&node)?;
            if data.starts_with(b"#!") {
                let line = data[2..].split(|&b| b == b'\n').next().unwrap_or(&[]);
                let line = String::from_utf8_lossy(line);
                let mut parts = line.trim().splitn(2, [' ', '\t']);
                let interp = parts.next().filter(|s| !s.is_empty()).ok_or(ENOEXEC)?.to_string();
                let mut new_argv = vec![interp.clone()];
                if let Some(arg) = parts.next().map(str::trim).filter(|s| !s.is_empty()) {
                    new_argv.push(arg.to_string());
                }
                new_argv.push(node.path.clone());
                new_argv.extend(argv.into_iter().skip(1));
                argv = new_argv;
                path = interp;
                continue;
            }
            let main = elf::load(mm, &data, &node.path, false).map_err(|e| {
                eprintln!("[droidrt] exec: {e}");
                ENOEXEC
            })?;
            let mut interp_range = None;
            let (entry, base) = match &main.interp {
                Some(interp) => {
                    let inode = vfs.resolve("/", interp, true)?;
                    let idata = vfs.read_all(&inode)?;
                    let li = elf::load(mm, &idata, interp, true).map_err(|e| {
                        eprintln!("[droidrt] exec: {e}");
                        ENOEXEC
                    })?;
                    interp_range = Some((li.lo, li.end, inode.path.clone()));
                    (li.entry, li.bias)
                }
                None => (main.entry, 0),
            };
            mm.set_brk_start(main.end);
            let sp = elf::build_stack(mm, &main, base, &argv, envp)?;
            mm.set_name(main.lo, main.end - main.lo, &node.path);
            if let Some((lo, end, name)) = interp_range {
                mm.set_name(lo, end - lo, &name);
            }
            return Ok((CpuState::new_user(entry, sp), node.path));
        }
        Err(ELOOP)
    }

    pub(super) fn sys_wait4(&self, t: &Thread, pid: i32, status: u64, options: u64, rusage: u64) -> i64 {
        if options & !(WNOHANG | WSTOPPED | WCONTINUED | WAIT_LINUX) != 0 {
            return -EINVAL;
        }
        let which = match pid {
            i32::MIN => return -ESRCH,
            -1 => Which::Any,
            0 => Which::Pgid(t.proc.attrs.lock().unwrap().pgid),
            p if p < 0 => Which::Pgid(-p),
            p => Which::Pid(p),
        };
        match self.wait_child(t, which, options | WEXITED) {
            Ok(Some((pid, st, _))) => {
                let mut mm = t.proc.mm();
                if (status != 0 && mm.write_u32(status, st as u32).is_err()) || (rusage != 0 && mm.write(rusage, &[0; 144]).is_err()) {
                    return -EFAULT;
                }
                pid as i64
            }
            Ok(None) => 0,
            Err(e) => -e,
        }
    }

    pub(super) fn sys_waitid(&self, t: &Thread, idtype: u64, id: i32, infop: u64, options: u64, rusage: u64) -> i64 {
        const P_ALL: u64 = 0;
        const P_PID: u64 = 1;
        const P_PGID: u64 = 2;
        const P_PIDFD: u64 = 3;
        if options & !(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | WAIT_LINUX) != 0 || options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
            return -EINVAL;
        }
        let which = match idtype {
            P_ALL => Which::Any,
            P_PID if id > 0 => Which::Pid(id),
            P_PGID if id == 0 => Which::Pgid(t.proc.attrs.lock().unwrap().pgid),
            P_PGID if id > 0 => Which::Pgid(id),
            P_PIDFD if id >= 0 => return -EBADF, // no pidfds
            _ => return -EINVAL,
        };
        let found = match self.wait_child(t, which, options) {
            Ok(f) => f,
            Err(e) => return -e,
        };
        // si_signo, si_errno, si_code, si_pid, si_uid, si_status; all zero if nothing exited.
        let mut info = [0u8; 28];
        if let Some((pid, st, uid)) = found {
            let (code, value) = child_code(st);
            info[0..4].copy_from_slice(&(SIGCHLD as i32).to_le_bytes());
            info[8..12].copy_from_slice(&code.to_le_bytes());
            info[16..20].copy_from_slice(&pid.to_le_bytes());
            info[20..24].copy_from_slice(&uid.to_le_bytes());
            info[24..28].copy_from_slice(&value.to_le_bytes());
            if rusage != 0 && t.proc.mm().write(rusage, &[0; 144]).is_err() {
                return -EFAULT;
            }
        }
        if infop != 0 && t.proc.mm().write(infop, &info).is_err() {
            return -EFAULT;
        }
        0
    }

    /// Finds an exited child matching `which` and, unless WNOWAIT, reaps it.
    /// `None`: WNOHANG and nothing has exited yet. Stopped and continued
    /// children are not modelled, so only WEXITED ever reports anything.
    fn wait_child(&self, t: &Thread, which: Which, options: u64) -> Result<Option<Exited>, i64> {
        let proc = &t.proc;
        let mut children = proc.children.lock().unwrap();
        loop {
            let candidates: Vec<Arc<Process>> = children
                .iter()
                .filter_map(|&c| self.process(c))
                .filter(|c| match which {
                    Which::Any => true,
                    Which::Pid(p) => c.pid == p,
                    Which::Pgid(g) => c.attrs.lock().unwrap().pgid == g,
                })
                .collect();
            if candidates.is_empty() {
                return Err(ECHILD);
            }
            for c in candidates.iter().filter(|_| options & WEXITED != 0) {
                let Some(st) = *c.status.lock().unwrap() else { continue };
                if options & WNOWAIT == 0 {
                    children.retain(|&x| x != c.pid);
                    self.procs.lock().unwrap().remove(&c.pid);
                }
                return Ok(Some((c.pid, st, c.creds.lock().unwrap().uid)));
            }
            if options & WNOHANG != 0 {
                return Ok(None);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            children = proc.child_cv.wait_timeout(children, POLL).unwrap().0;
        }
    }

    /// do_notify_parent: wakes waiters and sends SIGCHLD. A parent that
    /// ignores SIGCHLD (SIG_IGN or SA_NOCLDWAIT) has the child reaped at once.
    pub(super) fn notify_parent(&self, parent: &Arc<Process>, child: &Process, status: i32) {
        let (ignored, nocldwait) = parent.sig.lock().unwrap().child_ignore();
        let adopted = child.attrs.lock().unwrap().adopted;
        if ignored || nocldwait {
            parent.children.lock().unwrap().retain(|&c| c != child.pid);
            self.procs.lock().unwrap().remove(&child.pid);
        } else if adopted && parent.pid == self.root_pid.load(Ordering::Relaxed) {
            self.trim_adopted_zombies(parent);
        }
        {
            let _children = parent.children.lock().unwrap();
            parent.child_cv.notify_all();
        }
        if !ignored {
            let (code, value) = child_code(status);
            let uid = child.creds.lock().unwrap().uid;
            self.send_process_signal(parent, SIGCHLD, SigInfo::child(code, child.pid, value).with_uid(uid));
        }
    }

    /// forget_original_parent: an exiting process's children go to the
    /// nearest live PR_SET_CHILD_SUBREAPER ancestor, else to the root
    /// process (pid 1). The new parent hears about those already dead; the
    /// others get their parent-death signal.
    pub(super) fn reparent_children(&self, proc: &Arc<Process>) {
        let orphans: Vec<Arc<Process>> = std::mem::take(&mut *proc.children.lock().unwrap()).into_iter().filter_map(|c| self.process(c)).collect();
        let Some(reaper) = (!orphans.is_empty()).then(|| self.find_reaper(proc)).flatten() else { return };
        for c in &orphans {
            c.ppid.store(reaper.pid, Ordering::Relaxed);
            let mut a = c.attrs.lock().unwrap();
            (a.parent_tid, a.adopted) = (reaper.pid, true);
        }
        reaper.children.lock().unwrap().extend(orphans.iter().map(|c| c.pid));
        for c in &orphans {
            let status = *c.status.lock().unwrap();
            match status {
                Some(st) => self.notify_parent(&reaper, c, st),
                None => self.send_pdeathsig(c, proc),
            }
        }
        let _children = reaper.children.lock().unwrap();
        reaper.child_cv.notify_all();
    }

    /// The root may be a program that never waits for anything (droidrt runs
    /// arbitrary ones as pid 1): orphans it adopted and never reaped are
    /// released, oldest first, once there are more than ADOPTED_ZOMBIES.
    fn trim_adopted_zombies(&self, root: &Process) {
        const ADOPTED_ZOMBIES: usize = 256;
        let mut children = root.children.lock().unwrap();
        let zombies: Vec<i32> = children
            .iter()
            .filter_map(|&c| self.process(c))
            .filter(|c| c.status.lock().unwrap().is_some() && c.attrs.lock().unwrap().adopted)
            .map(|c| c.pid)
            .collect();
        for pid in zombies.iter().take(zombies.len().saturating_sub(ADOPTED_ZOMBIES)) {
            children.retain(|c| c != pid);
            self.procs.lock().unwrap().remove(pid);
        }
    }

    fn find_reaper(&self, proc: &Process) -> Option<Arc<Process>> {
        let root = self.root_pid.load(Ordering::Relaxed);
        let alive = |p: &Process| p.pid != proc.pid && p.status.lock().unwrap().is_none();
        let mut at = proc.ppid.load(Ordering::Relaxed);
        for _ in 0..4096 {
            let Some(a) = self.process(at).filter(|_| at != root) else { break };
            if alive(&a) && a.attrs.lock().unwrap().subreaper {
                return Some(a);
            }
            at = a.ppid.load(Ordering::Relaxed);
        }
        self.process(root).filter(|r| alive(r))
    }

    /// A thread exited while its process lives on: processes it forked get
    /// their parent-death signal and another thread becomes their parent.
    pub(super) fn parent_thread_gone(&self, t: &Thread) {
        let Some(heir) = t.proc.threads.lock().unwrap().first().map(|th| th.tid) else { return };
        let children: Vec<Arc<Process>> = t.proc.children.lock().unwrap().iter().filter_map(|&c| self.process(c)).collect();
        for c in children {
            let mine = {
                let mut a = c.attrs.lock().unwrap();
                let mine = a.parent_tid == t.tid;
                if mine {
                    a.parent_tid = heir;
                }
                mine
            };
            if mine {
                self.send_pdeathsig(&c, &t.proc);
            }
        }
    }

    fn send_pdeathsig(&self, child: &Arc<Process>, parent: &Process) {
        let uid = parent.creds.lock().unwrap().uid;
        let threads = child.threads.lock().unwrap().clone();
        for th in threads {
            let sig = th.attrs.lock().unwrap().pdeathsig;
            if sig != 0 {
                self.send_process_signal(child, sig, SigInfo::user(sig, parent.pid).with_uid(uid));
            }
        }
    }

    /// setpgid, getpgid, getpgrp, getsid, setsid.
    pub(super) fn pgrp_syscall(&self, no: Sysno, t: &Thread, a: [u64; 6]) -> Result<i64, i64> {
        let me = t.proc.pid;
        let lookup = |pid: i32| if pid == 0 { Some(t.proc.clone()) } else { self.process(pid).or_else(|| self.live_process(pid)) };
        let (pid, arg) = (int(a[0]) as i32, int(a[1]) as i32);
        match no {
            Sysno::getpgid | Sysno::getpgrp => Ok(lookup(if no == Sysno::getpgrp { 0 } else { pid }).ok_or(ESRCH)?.attrs.lock().unwrap().pgid as i64),
            Sysno::getsid => Ok(lookup(pid).ok_or(ESRCH)?.attrs.lock().unwrap().sid as i64),
            Sysno::setsid => {
                let procs = self.procs.lock().unwrap();
                let leader = t.proc.attrs.lock().unwrap().leader;
                // Fails if a process group with our id exists (ours, if we lead one).
                if leader || procs.values().any(|p| p.attrs.lock().unwrap().pgid == me) {
                    return Err(EPERM);
                }
                let mut attrs = t.proc.attrs.lock().unwrap();
                (attrs.sid, attrs.pgid, attrs.leader) = (me, me, true);
                Ok(me as i64)
            }
            _ => {
                let pid = if pid == 0 { me } else { pid };
                let pgid = if arg == 0 { pid } else { arg };
                if pgid < 0 {
                    return Err(EINVAL);
                }
                let procs = self.procs.lock().unwrap();
                let p = procs.get(&pid).ok_or(ESRCH)?;
                let my_sid = t.proc.attrs.lock().unwrap().sid;
                let (sid, leader, execed) = {
                    let pa = p.attrs.lock().unwrap();
                    (pa.sid, pa.leader, pa.execed)
                };
                if pid != me {
                    if p.ppid.load(Ordering::Relaxed) != me {
                        return Err(ESRCH);
                    }
                    if sid != my_sid {
                        return Err(EPERM);
                    }
                    if execed {
                        return Err(EACCES);
                    }
                }
                let group_ok = pgid == pid || procs.values().any(|g| {
                    let ga = g.attrs.lock().unwrap();
                    ga.pgid == pgid && ga.sid == my_sid
                });
                if leader || !group_ok {
                    return Err(EPERM);
                }
                p.attrs.lock().unwrap().pgid = pgid;
                Ok(0)
            }
        }
    }

    /// kill(2): a process, the caller's group (0), a group (-pgid), or every
    /// process but init and the caller (-1). Zombies accept signals silently.
    pub(super) fn sys_kill(&self, pid: i32, sig: u32, sender: &Thread) -> i64 {
        if sig > 64 {
            return -EINVAL;
        }
        let me = sender.proc.pid;
        let root = self.root_pid.load(Ordering::Relaxed);
        let own_group = sender.proc.attrs.lock().unwrap().pgid;
        let all = || -> Vec<Arc<Process>> { self.procs.lock().unwrap().values().cloned().collect() };
        let in_group = |g: i32| -> Vec<Arc<Process>> { all().into_iter().filter(|p| p.attrs.lock().unwrap().pgid == g).collect() };
        let targets: Vec<Arc<Process>> = match pid {
            p if p > 0 => self.process(p).or_else(|| self.live_process(p)).into_iter().collect(),
            0 => in_group(own_group),
            -1 => all().into_iter().filter(|p| p.pid != root && p.pid != me).collect(),
            i32::MIN => Vec::new(),
            p => in_group(-p),
        };
        if targets.is_empty() {
            return -ESRCH;
        }
        let creds = self.creds(sender);
        let (mut sent, mut err) = (false, -ESRCH);
        for p in targets {
            if !self.may_signal(sender, &creds, &p, sig) {
                err = -EPERM;
                continue;
            }
            sent = true;
            if sig != 0 {
                self.send_process_signal(&p, sig, SigInfo::user(sig, me).with_uid(creds.uid));
            }
        }
        // kill(-1) succeeds once there was anyone to try, like Linux.
        if sent || pid == -1 { 0 } else { err }
    }

    pub(super) fn sys_tgkill(&self, tgid: i32, tid: i32, sig: u32, sender: &Thread) -> i64 {
        if sig > 64 || tid <= 0 {
            return -EINVAL;
        }
        let Some(th) = self.task(tid).filter(|th| tgid <= 0 || th.proc.pid == tgid) else { return -ESRCH };
        let creds = self.creds(sender);
        if !self.may_signal(sender, &creds, &th.proc, sig) {
            return -EPERM;
        }
        if sig != 0 {
            self.send_thread_signal(&th, sig, SigInfo::user(sig, sender.proc.pid).with_uid(creds.uid));
        }
        0
    }

    /// check_kill_permission: our own process, matching uids, CAP_KILL, or
    /// SIGCONT within our session.
    fn may_signal(&self, sender: &Thread, creds: &Creds, target: &Process, sig: u32) -> bool {
        if std::ptr::eq(&*sender.proc, target) {
            return true;
        }
        let theirs = target.creds.lock().unwrap().clone();
        if creds.may_kill(&theirs) {
            return true;
        }
        let sid = target.attrs.lock().unwrap().sid;
        sig == SIGCONT && sid == sender.proc.attrs.lock().unwrap().sid
    }
}

fn read_strv(mm: &mut AddressSpace, mut p: u64) -> Result<Vec<String>, i64> {
    let mut out = Vec::new();
    if p == 0 {
        return Ok(out);
    }
    loop {
        let s = mm.read_u64(p)?;
        if s == 0 {
            return Ok(out);
        }
        if out.len() >= 65536 {
            return Err(E2BIG);
        }
        out.push(mm.read_cstr(s)?);
        p += 8;
    }
}
