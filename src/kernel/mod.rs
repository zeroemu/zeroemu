//! The Linux personality: processes, threads, files, memory, futexes and
//! signals, implemented on top of the host OS. Nothing here may depend on
//! POSIX; host specifics go through Rust's std, `phys`, `vfs`, and `hv`, so the
//! same code serves macOS and Windows.
//!
//! Every guest thread runs on its own host thread, which owns that thread's
//! vCPU (Hypervisor.framework binds a vCPU to its creating thread). Blocking
//! syscalls simply block that host thread.

mod binder;
mod block;
mod epoll;
mod files;
mod futex;
mod logd;
mod memory;
mod misc;
mod process;
mod procfs;
mod properties;
mod selinux;
mod signal;
mod specialfd;
mod unix;
mod wait;

use crate::arch::{Arch, Sysno};
use crate::errno::*;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, SyscallRegs, Vcpu};
use crate::mm::{AddressSpace, Backing, KernelWindow, Placement};
use crate::paging::{PROT_EXEC, PROT_READ};
use crate::phys::PAGE;
use crate::phys::PhysMem;
use crate::vfs::Vfs;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub use files::FdTable;
use signal::{Actions, SigInfo};

/// Returned by a blocking syscall interrupted by a signal: restarted
/// transparently unless a handler without SA_RESTART runs (Linux's ERESTARTSYS).
const ERESTARTSYS: i64 = 512;

/// How often blocked threads re-check for signals and process exit.
const POLL: Duration = Duration::from_millis(20);

/// A C `int` syscall argument (fds, dirfds, pids): only the low 32 bits are
/// defined, so AT_FDCWD arrives as 0xffffff9c.
fn int(v: u64) -> i64 {
    v as u32 as i32 as i64
}

pub enum Ret {
    Value(i64),
    /// The syscall replaced the register state itself (execve, rt_sigreturn).
    NoReturn,
    /// The calling thread is gone (exit, exit_group).
    ExitThread,
}

pub struct Kernel {
    pub arch: Arch,
    pub vfs: Option<Arc<Vfs>>,
    pub hv: Arc<dyn Hypervisor>,
    pub phys: Arc<PhysMem>,
    pub kwin: KernelWindow,
    pub strace: bool,
    pub boot: Instant,
    procs: Mutex<HashMap<i32, Arc<Process>>>,
    next_id: AtomicI32,
    next_asid: AtomicU32,
    live_vcpus: AtomicUsize,
    futex: futex::Futexes,
    root_pid: AtomicI32,
    pub props: Arc<properties::Properties>,
    /// Loop and device-mapper devices.
    blocks: Arc<block::Blocks>,
    /// SELinux state and selinuxfs.
    selinux: Arc<selinux::Selinux>,
    /// Kernel-side socket services (kept alive here; looked up by name).
    _services: Vec<Arc<unix::Socket>>,
    /// The root process's wait status once it exits; droidrt then exits.
    exit: (Mutex<Option<i32>>, Condvar),
}

fn cmdline_bytes(argv: &[String]) -> Vec<u8> {
    argv.iter().flat_map(|a| a.bytes().chain([0])).collect()
}

/// init's property service, answered inside the kernel.
struct PropertyService {
    kernel: std::sync::Weak<Kernel>,
}

impl unix::Service for PropertyService {
    fn handle(&self, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        let k = self.kernel.upgrade()?;
        properties::handle_request(&k.props, &k.futex, buf)
    }
}

/// The writable filesystems a device has after first-stage init, empty
/// apart from the basics (init itself is not run yet). Returns /dev.
fn mount_tmpfs(vfs: &mut Vfs, phys: &Arc<PhysMem>) -> Arc<crate::tmpfs::Tmpfs> {
    use crate::tmpfs::Tmpfs;
    use crate::vfs::FileSystem;
    let dev = Tmpfs::new(phys.clone(), 0o755);
    let dev_handle = dev.clone();
    for (name, rdev) in [("null", 0x103), ("zero", 0x105), ("random", 0x108), ("urandom", 0x109), ("kmsg", 0x10b)] {
        dev.create(1, name, 0o020666, rdev).expect("tmpfs /dev");
    }
    for (name, rdev) in binder::DEVICES {
        dev.create(1, name, 0o020666, rdev).expect("tmpfs /dev");
    }
    dev.mkdir_p("socket", 0o755);
    dev.mkdir_p("pts", 0o755);
    vfs.mount("/dev", dev);
    let data = Tmpfs::new(phys.clone(), 0o771);
    data.mkdir_p("local/tmp", 0o771);
    data.mkdir_p("system", 0o775);
    vfs.mount("/data", data);
    vfs.mount("/tmp", Tmpfs::new(phys.clone(), 0o1777));
    vfs.mount("/mnt", Tmpfs::new(phys.clone(), 0o755));
    vfs.mount("/cache", Tmpfs::new(phys.clone(), 0o770));
    // sysfs: what bionic's sysconf and friends read. No /sys/fs/selinux, so
    // libselinux sees SELinux as disabled.
    let sys = Tmpfs::with_type(phys.clone(), 0o755, "sysfs");
    let n = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
    for f in ["online", "possible", "present"] {
        sys.write_file(&format!("devices/system/cpu/{f}"), 0o444, &format!("0-{}\n", n - 1));
    }
    sys.write_file("devices/system/cpu/kernel_max", 0o444, "63\n");
    for d in ["fs", "kernel", "class", "bus", "block", "dev/char", "dev/block", "module"] {
        sys.mkdir_p(d, 0o755);
    }
    vfs.mount("/sys", sys);
    dev_handle
}

pub struct Process {
    pub pid: i32,
    pub ppid: AtomicI32,
    mm: Mutex<Option<AddressSpace>>,
    pub files: Mutex<FdTable>,
    pub cwd: Mutex<String>,
    pub exe: Mutex<String>,
    /// argv, NUL-separated, for /proc/<pid>/cmdline.
    pub cmdline: Mutex<Vec<u8>>,
    sig: Mutex<Actions>,
    threads: Mutex<Vec<Arc<Thread>>>,
    children: Mutex<Vec<i32>>,
    child_cv: Condvar,
    /// Wait status once the process is a zombie.
    status: Mutex<Option<i32>>,
    /// Set by exit_group / a fatal signal: the status the process will report.
    exiting: Mutex<Option<i32>>,
    /// Process-directed pending signals.
    pending: Mutex<HashMap<u32, SigInfo>>,
    pub sec: selinux::ProcSec,
}

pub struct Thread {
    pub tid: i32,
    pub proc: Arc<Process>,
    clear_child_tid: AtomicU64,
    mask: AtomicU64,
    /// Mask to restore after a sigsuspend once its handler returns.
    saved_mask: Mutex<Option<u64>>,
    pending: Mutex<HashMap<u32, SigInfo>>,
    altstack: Mutex<(u64, u64, i32)>,
    kick: Mutex<Option<Arc<dyn Kick>>>,
    dying: AtomicBool,
    pub sec: selinux::ThreadSec,
}

/// Locked access to a live process's address space.
pub struct Mm<'a>(MutexGuard<'a, Option<AddressSpace>>);

impl Deref for Mm<'_> {
    type Target = AddressSpace;
    fn deref(&self) -> &AddressSpace {
        self.0.as_ref().expect("address space of an exited process")
    }
}
impl DerefMut for Mm<'_> {
    fn deref_mut(&mut self) -> &mut AddressSpace {
        self.0.as_mut().expect("address space of an exited process")
    }
}

impl Process {
    pub fn mm(&self) -> Mm<'_> {
        Mm(self.mm.lock().unwrap())
    }
}

impl Thread {
    fn new(tid: i32, proc: Arc<Process>, mask: u64) -> Arc<Thread> {
        Arc::new(Thread {
            tid,
            proc,
            clear_child_tid: AtomicU64::new(0),
            mask: AtomicU64::new(mask),
            saved_mask: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            altstack: Mutex::new((0, 0, signal::SS_DISABLE)),
            kick: Mutex::new(None),
            dying: AtomicBool::new(false),
            sec: Default::default(),
        })
    }

    /// Whether a blocking wait should give up now (signal or exit).
    fn interrupted(&self) -> bool {
        self.dying.load(Ordering::Acquire) || self.has_deliverable_signal()
    }

    fn kick(&self) {
        if let Some(k) = self.kick.lock().unwrap().as_ref() {
            k.kick();
        }
    }
}

impl Kernel {
    /// `boot`: Android's init runs as pid 1 and provides properties and
    /// daemons itself; otherwise the kernel stands in for what init would
    /// have set up (the property area and service, logd).
    pub fn new(hv: Arc<dyn Hypervisor>, vfs: Option<Vfs>, strace: bool, boot: bool) -> Result<Arc<Kernel>, String> {
        let phys = PhysMem::new(hv.clone());
        let pages = hv.kernel_pages(&mut || {
            let gpa = phys.alloc().expect("no memory for the kernel window");
            (gpa, phys.host(gpa))
        });
        let kwin = KernelWindow::new(&phys, &pages).map_err(|e| format!("kernel window: errno {e}"))?;
        // Without an image the root itself is a tmpfs (for freestanding guests).
        let mut v = vfs.unwrap_or_else(|| {
            let mut v = Vfs::default();
            v.mount("/", crate::tmpfs::Tmpfs::new(phys.clone(), 0o755));
            v
        });
        let dev = mount_tmpfs(&mut v, &phys);
        let sys = v.resolve("/", "/sys", true).map(|n| v.fs_arc(&n)).map_err(|e| format!("/sys: errno {e}"))?;
        let blocks = block::Blocks::new(dev.clone(), sys);
        // Properties, as init would set them up: defaults from build.prop,
        // shared read-only with every process at /dev/__properties__.
        let props = properties::Properties::new(phys.clone());
        if !boot {
            props.load_defaults(&v);
            props.set(None, "logd.ready", "true"); // logd is answered in the kernel (logd.rs)
            dev.add_file("__properties__", 0o444, props.file.clone());
        }
        // /proc reads kernel state, so the kernel is built around it.
        Ok(Arc::new_cyclic(|me| {
            v.mount("/proc", procfs::ProcFs::new(me.clone()));
            let selinux = selinux::Selinux::new(me.clone(), phys.clone(), boot);
            v.mount("/sys/fs/selinux", selinux.clone());
            let svc: Arc<dyn unix::Service> = Arc::new(PropertyService { kernel: me.clone() });
            let mut services = Vec::new();
            if !boot {
                services.push(unix::listen_service("/dev/socket/property_service", unix::SOCK_STREAM, svc.clone()));
                services.push(unix::listen_service("/dev/socket/property_service_for_system", unix::SOCK_STREAM, svc));
            }
            // Also in boot mode, until init starts the real logd, which
            // replaces these (init unlinks a socket's path before binding it).
            services.extend(logd::start());
            Kernel {
            arch: Arch::HOST,
            vfs: Some(Arc::new(v)),
            hv,
            phys,
            kwin,
            strace,
            boot: Instant::now(),
            procs: Mutex::new(HashMap::new()),
            next_id: AtomicI32::new(1),
            next_asid: AtomicU32::new(1),
            live_vcpus: AtomicUsize::new(0),
            futex: futex::Futexes::default(),
            root_pid: AtomicI32::new(0),
            props,
            blocks,
            selinux,
            _services: services,
            exit: (Mutex::new(None), Condvar::new()),
            }
        }))
    }

    fn alloc_asid(&self) -> u16 {
        // 16-bit ASIDs; on wrap-around, vCPUs flush when they switch roots.
        (self.next_asid.fetch_add(1, Ordering::Relaxed) % 0xffff + 1) as u16
    }

    pub fn new_address_space(&self) -> Result<AddressSpace, i64> {
        let mut mm = AddressSpace::new(self.phys.clone(), &self.kwin, self.alloc_asid())?;
        // Where signal handlers return to (Linux puts this in the vDSO).
        mm.map(Placement::Fixed(signal::SIGRETURN_TRAMPOLINE), PAGE, PROT_READ | PROT_EXEC, Backing::File { data: signal::trampoline_page(), offset: 0 })?;
        mm.set_name(signal::SIGRETURN_TRAMPOLINE, PAGE, "[sigpage]");
        Ok(mm)
    }

    fn process(&self, pid: i32) -> Option<Arc<Process>> {
        self.procs.lock().unwrap().get(&pid).cloned()
    }

    /// Starts the first process: `mm` already holds the program and its stack.
    pub fn start(self: &Arc<Self>, mm: AddressSpace, exe: String, argv: &[String], state: CpuState) -> Result<(), String> {
        let pid = self.next_id.fetch_add(1, Ordering::Relaxed);
        let proc = Arc::new(Process {
            pid,
            ppid: AtomicI32::new(0),
            mm: Mutex::new(Some(mm)),
            files: Mutex::new(FdTable::stdio()),
            cwd: Mutex::new("/".into()),
            exe: Mutex::new(exe),
            cmdline: Mutex::new(cmdline_bytes(argv)),
            sig: Mutex::new(Actions::default()),
            threads: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            child_cv: Condvar::new(),
            status: Mutex::new(None),
            exiting: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            sec: selinux::ProcSec::new(self.selinux.initial),
        });
        self.root_pid.store(pid, Ordering::Relaxed);
        self.procs.lock().unwrap().insert(pid, proc.clone());
        let thread = Thread::new(pid, proc.clone(), 0);
        proc.threads.lock().unwrap().push(thread.clone());
        self.spawn(thread, state).map_err(|e| format!("cannot start the first thread: errno {e}"))
    }

    /// Blocks until the root process exits; returns its wait status.
    pub fn wait_root(&self) -> i32 {
        let (lock, cv) = &self.exit;
        let mut status = lock.lock().unwrap();
        while status.is_none() {
            status = cv.wait(status).unwrap();
        }
        status.unwrap()
    }

    /// Runs `thread` on a new host thread with its own vCPU.
    fn spawn(self: &Arc<Self>, thread: Arc<Thread>, state: CpuState) -> Result<(), i64> {
        if self.live_vcpus.fetch_add(1, Ordering::AcqRel) >= self.hv.max_vcpus() {
            self.live_vcpus.fetch_sub(1, Ordering::AcqRel);
            eprintln!("[droidrt] thread limit: the hypervisor allows {} vCPUs", self.hv.max_vcpus());
            return Err(EAGAIN);
        }
        let k = self.clone();
        let t = thread.clone();
        std::thread::Builder::new()
            .name(format!("guest-{}", thread.tid))
            .stack_size(1 << 20)
            .spawn(move || {
                k.thread_main(&t, state);
                k.live_vcpus.fetch_sub(1, Ordering::AcqRel);
            })
            .map(|_| ())
            .map_err(|_| {
                self.live_vcpus.fetch_sub(1, Ordering::AcqRel);
                EAGAIN
            })
    }

    fn thread_main(self: &Arc<Self>, t: &Arc<Thread>, state: CpuState) {
        let root = t.proc.mm().root;
        let mut vcpu = match self.hv.create_vcpu(root, &state) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[droidrt] tid {}: {e}", t.tid);
                self.thread_exit(t, 127 << 8);
                return;
            }
        };
        *t.kick.lock().unwrap() = Some(vcpu.kicker());
        let mut stale = crate::mm::Stale::default();
        let mut restart: Option<SyscallRegs> = None;
        let mut exit_code = 0;

        loop {
            if t.dying.load(Ordering::Acquire) {
                break;
            }
            self.deliver_signals(t, vcpu.as_mut(), restart.take());
            if t.dying.load(Ordering::Acquire) {
                break;
            }
            let exit = vcpu.run();
            // The flush requested last time ran on entry; now frames are safe to reuse.
            stale.release(&self.phys);
            match exit {
                Exit::Syscall => {
                    let regs = vcpu.syscall_regs();
                    match self.syscall(t, vcpu.as_mut(), &regs) {
                        Ret::Value(v) if v == -ERESTARTSYS => restart = Some(regs),
                        Ret::Value(v) => vcpu.set_syscall_return(v as u64),
                        Ret::NoReturn => {}
                        Ret::ExitThread => {
                            exit_code = (regs.args[0] as i32 & 0xff) << 8;
                            break;
                        }
                    }
                }
                Exit::PageFault { pc, addr, write, exec } => {
                    if t.proc.mm().fault(addr, write, exec).is_err() {
                        self.crash_report(t, vcpu.as_ref(), "SIGSEGV", pc, addr, write);
                        self.force_signal(t, signal::SIGSEGV, SigInfo::fault(signal::SIGSEGV, 1, addr), pc);
                    }
                }
                Exit::Fault { pc, addr, detail } => {
                    eprintln!("[droidrt] tid {}: guest fault at pc={pc:#x} addr={addr:#x}: {detail}", t.tid);
                    self.force_signal(t, signal::SIGILL, SigInfo::fault(signal::SIGILL, 1, pc), pc);
                }
                Exit::Interrupted => {}
            }
            let mut mm = t.proc.mm();
            if mm.tlb_dirty {
                mm.tlb_dirty = false;
                stale = mm.take_stale();
                vcpu.flush_tlb();
            }
        }
        *t.kick.lock().unwrap() = None;
        drop(vcpu); // destroyed on the thread that owns it
        stale.release(&self.phys);
        self.thread_exit(t, exit_code);
    }

    fn syscall(self: &Arc<Self>, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, regs: &SyscallRegs) -> Ret {
        let sysno = self.arch.sysno(regs.nr);
        let a = regs.args;
        let ret = match sysno {
            None => Ret::Value(-ENOSYS),
            Some(no) => self.dispatch(no, t, vcpu, a),
        };
        if self.strace {
            let name = sysno.map_or_else(|| format!("syscall_{}", regs.nr), |s| format!("{s:?}"));
            let path = match sysno {
                Some(Sysno::openat | Sysno::newfstatat | Sysno::readlinkat | Sysno::faccessat | Sysno::faccessat2 | Sysno::statx | Sysno::execve) => {
                    let at = if sysno == Some(Sysno::execve) { a[0] } else { a[1] };
                    t.proc.mm.lock().unwrap().as_mut().and_then(|mm| mm.read_cstr(at).ok()).map(|p| format!(" \"{p}\"")).unwrap_or_default()
                }
                _ => String::new(),
            };
            let shown = match &ret {
                Ret::Value(v) => v.to_string(),
                Ret::NoReturn => "<new state>".into(),
                Ret::ExitThread => "<exit>".into(),
            };
            eprintln!("[strace] {} {name}({:#x}, {:#x}, {:#x}, {:#x}){path} = {shown}", t.tid, a[0], a[1], a[2], a[3]);
        } else if matches!(ret, Ret::Value(v) if v == -ENOSYS) {
            eprintln!("[droidrt] unimplemented syscall {} ({sysno:?}, {:?})", regs.nr, self.arch);
        }
        ret
    }

    fn dispatch(self: &Arc<Self>, no: Sysno, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, a: [u64; 6]) -> Ret {
        use Sysno::*;
        let v = match no {
            // processes and threads
            clone => return self.sys_clone(t, vcpu, a),
            fork => return self.sys_clone(t, vcpu, [signal::SIGCHLD as u64, 0, 0, 0, 0, 0]),
            vfork => return self.sys_clone(t, vcpu, [0x4100 | signal::SIGCHLD as u64, 0, 0, 0, 0, 0]),
            pipe => match self.file_syscall(pipe2, t, [a[0], 0, 0, 0, 0, 0]) {
                Ok(v) => v,
                Err(e) => -e,
            },
            execve => return self.sys_execve(t, vcpu, a[0], a[1], a[2]),
            exit => return Ret::ExitThread,
            exit_group => {
                self.exit_group(&t.proc, (a[0] as i32 & 0xff) << 8, Some(t.tid));
                return Ret::ExitThread;
            }
            wait4 => self.sys_wait4(t, int(a[0]) as i32, a[1], a[2]),
            kill => self.sys_kill(int(a[0]) as i32, a[1] as u32, t),
            tgkill => self.sys_tgkill(int(a[0]) as i32, int(a[1]) as i32, a[2] as u32, t),
            tkill => self.sys_tgkill(-1, int(a[0]) as i32, a[1] as u32, t),
            rt_tgsigqueueinfo => self.sys_tgkill(int(a[0]) as i32, int(a[1]) as i32, a[2] as u32, t),
            rt_sigqueueinfo => self.sys_kill(int(a[0]) as i32, a[1] as u32, t),
            getpid => t.proc.pid as i64,
            gettid => t.tid as i64,
            getppid => t.proc.ppid.load(Ordering::Relaxed) as i64,
            set_tid_address => {
                t.clear_child_tid.store(a[0], Ordering::Relaxed);
                t.tid as i64
            }
            getpgid | getsid => t.proc.pid as i64,
            setpgid | setsid => 0,

            // signals
            rt_sigaction => self.sys_rt_sigaction(t, a[0] as u32, a[1], a[2]),
            rt_sigprocmask => self.sys_rt_sigprocmask(t, a[0], a[1], a[2]),
            rt_sigsuspend => self.sys_rt_sigsuspend(t, a[0]),
            rt_sigreturn => return self.sys_rt_sigreturn(t, vcpu),
            sigaltstack => self.sys_sigaltstack(t, a[0], a[1]),

            // memory
            brk => self.sys_brk(t, a[0]),
            mmap => self.sys_mmap(t, a[0], a[1], a[2] as u32, a[3], int(a[4]), a[5]),
            munmap => self.sys_munmap(t, a[0], a[1]),
            mprotect => self.sys_mprotect(t, a[0], a[1], a[2] as u32),
            mremap => self.sys_mremap(t, a[0], a[1], a[2], a[3], a[4]),
            madvise => self.sys_madvise(t, a[0], a[1], a[2]),

            // futexes
            futex => self.sys_futex(t, a[0], a[1] as u32, a[2] as u32, a[3], a[4], a[5] as u32),
            set_robust_list => 0,

            // sockets
            n if unix::handles(n) => match self.socket_syscall(n, t, a) {
                Ok(v) => v,
                Err(e) => -e,
            },

            // files
            n if files::handles(n) => match self.file_syscall(n, t, a) {
                Ok(v) => v,
                Err(e) => -e,
            },

            // everything else
            n => match self.misc_syscall(n, t, vcpu, a) {
                Ok(v) => v,
                Err(e) => -e,
            },
        };
        Ret::Value(v)
    }

    /// A crash report: where it faulted and a frame-pointer backtrace, with
    /// addresses as library+offset (there is no tombstoned to write one).
    fn crash_report(&self, t: &Thread, vcpu: &dyn Vcpu, what: &str, pc: u64, addr: u64, write: bool) {
        let mut mm = t.proc.mm();
        eprintln!(
            "[droidrt] pid {} tid {} ({}): {what} {} {addr:#x} at {}",
            t.proc.pid,
            t.tid,
            t.proc.exe.lock().unwrap(),
            if write { "writing" } else { "reading" },
            mm.symbolize(pc)
        );
        if let CpuState::Aarch64(s) = vcpu.state() {
            eprintln!("[droidrt]   lr {}", mm.symbolize(s.x[30]));
            let mut fp = s.x[29];
            for i in 0..16 {
                let (Ok(next), Ok(ret)) = (mm.read_u64(fp), mm.read_u64(fp + 8)) else { break };
                if ret == 0 {
                    break;
                }
                eprintln!("[droidrt]   #{i:02} {}", mm.symbolize(ret));
                if next <= fp {
                    break;
                }
                fp = next;
            }
        }
    }

    /// Called on the exiting thread's host thread after its vCPU is gone.
    fn thread_exit(self: &Arc<Self>, t: &Arc<Thread>, code: i32) {
        let proc = &t.proc;
        let ctid = t.clear_child_tid.swap(0, Ordering::Relaxed);
        if ctid != 0 && proc.mm.lock().unwrap().as_mut().is_some_and(|mm| mm.write_u32(ctid, 0).is_ok()) {
            let key = self.futex_key(t, ctid, false);
            self.futex.wake(key, 1, u32::MAX);
        }
        let last = {
            let mut threads = proc.threads.lock().unwrap();
            threads.retain(|x| x.tid != t.tid);
            threads.is_empty()
        };
        if last {
            let status = proc.exiting.lock().unwrap().unwrap_or(code);
            self.process_exit(proc, status);
        }
    }

    /// Ends every thread of `proc`; `except` is the caller, which exits itself.
    fn exit_group(&self, proc: &Arc<Process>, status: i32, except: Option<i32>) {
        {
            let mut ex = proc.exiting.lock().unwrap();
            if ex.is_none() {
                *ex = Some(status);
            }
        }
        for th in proc.threads.lock().unwrap().iter() {
            if Some(th.tid) != except {
                th.dying.store(true, Ordering::Release);
                th.kick();
            }
        }
    }

    fn process_exit(self: &Arc<Self>, proc: &Arc<Process>, status: i32) {
        // Closing files first lets pipe readers see EOF.
        drop(std::mem::replace(&mut *proc.files.lock().unwrap(), FdTable::empty()));
        drop(proc.mm.lock().unwrap().take());
        *proc.status.lock().unwrap() = Some(status);

        let root = self.root_pid.load(Ordering::Relaxed);
        let orphans = std::mem::take(&mut *proc.children.lock().unwrap());
        if let Some(r) = self.process(root).filter(|r| r.pid != proc.pid) {
            for c in &orphans {
                if let Some(child) = self.process(*c) {
                    child.ppid.store(root, Ordering::Relaxed);
                }
            }
            r.children.lock().unwrap().extend(orphans);
            r.child_cv.notify_all();
        }

        if proc.pid == root {
            let (lock, cv) = &self.exit;
            *lock.lock().unwrap() = Some(status);
            cv.notify_all();
            return;
        }
        let parent = self.process(proc.ppid.load(Ordering::Relaxed));
        if let Some(parent) = parent {
            {
                let _children = parent.children.lock().unwrap();
                parent.child_cv.notify_all();
            }
            let (code, value) = if status & 0x7f == 0 { (1, (status >> 8) & 0xff) } else { (2, status & 0x7f) };
            self.send_process_signal(&parent, signal::SIGCHLD, SigInfo::child(code, proc.pid, value));
        }
    }
}
