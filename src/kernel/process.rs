//! Process lifecycle: clone (threads and fork), execve, wait4, kill.

use super::signal::SigInfo;
use super::{ERESTARTSYS, Kernel, POLL, Process, Ret, Thread};
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
        });
        let th = Thread::new(pid, child.clone(), t.mask.load(Ordering::Relaxed));
        *th.altstack.lock().unwrap() = *t.altstack.lock().unwrap();
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

    pub(super) fn sys_wait4(&self, t: &Thread, pid: i32, status: u64, options: u64) -> i64 {
        let proc = &t.proc;
        let mut children = proc.children.lock().unwrap();
        loop {
            let candidates: Vec<i32> = children.iter().copied().filter(|&c| pid <= 0 || c == pid).collect();
            if candidates.is_empty() {
                return -ECHILD;
            }
            for c in candidates {
                let Some(child) = self.process(c) else { continue };
                let Some(st) = *child.status.lock().unwrap() else { continue };
                children.retain(|&x| x != c);
                self.procs.lock().unwrap().remove(&c);
                drop(children);
                if status != 0 && proc.mm().write_u32(status, st as u32).is_err() {
                    return -EFAULT;
                }
                return c as i64;
            }
            if options & WNOHANG != 0 {
                return 0;
            }
            if t.interrupted() {
                return -ERESTARTSYS;
            }
            children = proc.child_cv.wait_timeout(children, POLL).unwrap().0;
        }
    }

    pub(super) fn sys_kill(&self, pid: i32, sig: u32, sender: &Thread) -> i64 {
        if sig > 64 {
            return -EINVAL;
        }
        let targets: Vec<Arc<Process>> = match pid {
            p if p > 0 => self.process(p).into_iter().collect(),
            0 => vec![sender.proc.clone()],
            -1 => self.procs.lock().unwrap().values().filter(|p| p.pid != sender.proc.pid).cloned().collect(),
            p => self.process(-p).into_iter().collect(), // process groups: one process per group
        };
        let targets: Vec<_> = targets.into_iter().filter(|p| p.status.lock().unwrap().is_none()).collect();
        if targets.is_empty() {
            return -ESRCH;
        }
        if sig != 0 {
            for p in targets {
                self.send_process_signal(&p, sig, SigInfo::user(sig, sender.proc.pid));
            }
        }
        0
    }

    pub(super) fn sys_tgkill(&self, tgid: i32, tid: i32, sig: u32, sender: &Thread) -> i64 {
        if sig > 64 || tid <= 0 {
            return -EINVAL;
        }
        let procs: Vec<Arc<Process>> = if tgid > 0 { self.process(tgid).into_iter().collect() } else { self.procs.lock().unwrap().values().cloned().collect() };
        for p in procs {
            let th = p.threads.lock().unwrap().iter().find(|x| x.tid == tid).cloned();
            if let Some(th) = th {
                if sig != 0 {
                    self.send_thread_signal(&th, sig, SigInfo::user(sig, sender.proc.pid));
                }
                return 0;
            }
        }
        -ESRCH
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
