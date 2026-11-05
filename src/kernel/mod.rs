//! The Linux personality: processes, threads, files, memory, futexes and
//! signals, implemented on top of the host OS. Nothing here may depend on
//! POSIX; host specifics go through Rust's std, `phys`, `vfs`, and `hv`, so the
//! same code serves macOS and Windows.
//!
//! Every guest thread runs on its own host thread, which owns that thread's
//! vCPU (Hypervisor.framework binds a vCPU to its creating thread). Blocking
//! syscalls simply block that host thread.

mod ashmem;
mod binder;
mod block;
mod bpf;
mod cgroup;
mod control;
mod creds;
mod drm;
pub mod adb;
pub mod evdev;
mod hostio;
mod uffd;
mod epoll;
mod files;
mod futex;
mod inet;
mod inotify;
mod locks;
mod logd;
mod net;
mod power;
mod memory;
mod misc;
mod mount;
mod netlink;
mod process;
mod procfs;
mod properties;
mod pty;
mod sched;
mod selinux;
mod signal;
mod specialfd;
mod sysctl;
mod timers;
mod unix;
mod vcpus;
mod vsock;
mod wait;
mod xattr;

use crate::arch::{Arch, Sysno};
use crate::errno::*;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, SyscallRegs, Urgency, Vcpu};
use crate::mm::{AddressSpace, Backing, KernelWindow, Placement};
use crate::paging::{PROT_EXEC, PROT_READ};
use crate::phys::PAGE;
use crate::phys::PhysMem;
use crate::vfs::Vfs;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

pub use files::FdTable;
use signal::{Actions, SigInfo};

/// Returned by a blocking syscall interrupted by a signal: restarted
/// transparently unless a handler without SA_RESTART runs (Linux's ERESTARTSYS).
pub(super) const ERESTARTSYS: i64 = 512;

/// How often blocked threads re-check for signals and process exit.
/// Hardware the image declares and droidrt has no driver behind. SystemConfig
/// applies these last, whichever file declared the feature.
/// Properties for a booted device. The emulator's answer to a busy host: Watchdog and
/// ANR timeouts scale by the multiplier. SurfaceFlinger composes layers with a blur
/// itself rather than through the composer HAL, and those frames come out black on this
/// GPU path; blurs also cost a lot. Compiling SurfaceFlinger's shader cache took 14 s
/// of every boot, holding up SystemUI and so the boot animation, for layers that
/// nearly always go through the composer HAL instead.
const BOOT_PROPS: &str = "ro.hw_timeout_multiplier=5\nro.surface_flinger.supports_background_blur=0\nservice.sf.prime_shader_cache=0\nservice.adb.listen_addrs=vsock:5555\n";
const NO_BLUETOOTH: &str = "<config>\n  <unavailable-feature name=\"android.hardware.bluetooth\" />\n  <unavailable-feature name=\"android.hardware.bluetooth_le\" />\n</config>\n";

pub(super) const POLL: Duration = Duration::from_millis(200);
/// For sleeps every wakeup reaches directly (Thread::sleep): only a kick lost
/// in the instant before the sleep starts ever waits this long.
pub(super) const IDLE: Duration = Duration::from_secs(2);
/// Guest threads at once (each is a host thread; vCPUs are shared).
const MAX_THREADS: usize = 16384;

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
    timers: Arc<timers::TimerQueue>,
    procs: Mutex<HashMap<i32, Arc<Process>>>,
    next_id: AtomicI32,
    /// Serializes allocation; set once ids have wrapped around.
    id_wrapped: Mutex<bool>,
    next_asid: AtomicU32,
    /// Host threads running guest threads.
    live_threads: AtomicUsize,
    persist: Option<Persist>,
    /// The vCPUs guest threads share.
    vcpus: Arc<vcpus::Pool>,
    futex: futex::Futexes,
    root_pid: AtomicI32,
    pub props: Arc<properties::Properties>,
    /// Loop and device-mapper devices.
    blocks: Arc<block::Blocks>,
    /// /proc/sys values.
    sysctl: sysctl::Sysctl,
    /// SELinux state and selinuxfs.
    selinux: Arc<selinux::Selinux>,
    /// Kernel-side socket services (kept alive here; looked up by name).
    _services: Vec<Arc<unix::Socket>>,
    /// virtio-gpu, when a renderer (or the fake backend) was handed in.
    /// None on a headless boot: no /dev/dri nodes.
    drm: Option<Arc<drm::Device>>,
    #[allow(dead_code)]
    gpu: Option<Arc<dyn crate::gpu::GpuBackend>>,
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
/// Additions to a booted image, for development: files pushed into the
/// device (like adb push) and a shell command init runs once SurfaceFlinger
/// is up, its output on the terminal.
#[derive(Default)]
pub struct BootExtras {
    /// (guest path in a writable filesystem such as /data, contents)
    pub push: Vec<(String, Vec<u8>)>,
    pub run: Option<String>,
    /// Where /data is kept between boots, if it is.
    pub data: Option<DataImage>,
}

pub struct DataImage {
    pub path: std::path::PathBuf,
    /// Start empty, whatever the file holds.
    pub wipe: bool,
}

/// What a device keeps between boots: its /data and /metadata, in one host file.
/// These live in memory. The file is read at boot and written at exit, and written
/// whole, then renamed over the old one, so a failure leaves the last good one.
struct Persist {
    path: std::path::PathBuf,
    trees: Vec<(&'static str, Arc<crate::tmpfs::Tmpfs>)>,
}

impl Persist {
    const MAGIC: &'static [u8] = b"droidrt data 1\n";

    fn load(&self) -> std::io::Result<u64> {
        use std::io::Read;
        let file = std::fs::File::open(&self.path)?;
        let size = file.metadata()?.len();
        let mut r = std::io::BufReader::with_capacity(1 << 20, file);
        let mut magic = vec![0; Self::MAGIC.len()];
        r.read_exact(&mut magic)?;
        if magic != Self::MAGIC {
            return Err(std::io::Error::other("not a droidrt data file"));
        }
        let mut read = Vec::new();
        for (_, tree) in &self.trees {
            read.push(tree.read_saved(&mut r)?);
        }
        for ((_, tree), saved) in self.trees.iter().zip(read) {
            tree.install(saved);
        }
        Ok(size)
    }

    fn save(&self) -> std::io::Result<u64> {
        use std::io::Write;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let new = self.path.with_extension("new");
        let file = std::fs::File::create(&new)?;
        let mut w = std::io::BufWriter::with_capacity(1 << 20, file);
        w.write_all(Self::MAGIC)?;
        let mut contents = 0;
        for (_, tree) in &self.trees {
            contents += tree.save(&mut w)?;
        }
        w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&new, &self.path)?;
        Ok(contents)
    }
}

fn apply_extras(v: &Vfs, dev: &crate::tmpfs::Tmpfs, extras: &BootExtras) -> Result<(), String> {
    let put = |path: &str, data: &[u8]| -> Result<(), String> {
        let fail = |e: i64| format!("--push {path}: errno {e}");
        let (parent, name) = path.rsplit_once('/').filter(|(_, n)| !n.is_empty()).ok_or(format!("--push {path}: not a file path"))?;
        let mut dir = v.resolve("/", "/", true).map_err(fail)?;
        for part in parent.split('/').filter(|p| !p.is_empty()) {
            if v.resolve(&dir.path, part, true).is_err() {
                v.mkdir(&dir, part, 0o755).map_err(fail)?;
            }
            dir = v.resolve(&dir.path, part, true).map_err(fail)?;
        }
        let node = match v.resolve(&dir.path, name, true) {
            Ok(n) => n,
            Err(_) => v.create(&dir, name, crate::vfs::S_IFREG | 0o755, 0).map_err(fail)?,
        };
        let file = v.mem_file(&node).ok_or(format!("--push {path}: not on a writable filesystem"))?;
        file.truncate(0);
        file.write_at(0, data).map(|_| ()).map_err(fail)
    };
    for (path, data) in &extras.push {
        put(path, data)?;
    }
    let Some(cmd) = &extras.run else { return Ok(()) };
    // Its output goes to /dev/kmsg, which droidrt prints.
    put("/data/local/tmp/.droidrt-run.sh", format!("exec >/dev/kmsg 2>&1\n{cmd}\n").as_bytes())?;
    let rc = v.resolve("/", "/system/etc/init/hw/init.rc", true).map_err(|e| format!("init.rc: errno {e}"))?;
    let mut text = String::from_utf8_lossy(&v.read_all(&rc).map_err(|e| format!("init.rc: errno {e}"))?).into_owned();
    text += "\n# Added by droidrt --run.\nservice droidrt_run /system/bin/sh /data/local/tmp/.droidrt-run.sh\n    user root\n    group root\n    seclabel u:r:shell:s0\n    stdio_to_kmsg\n    oneshot\n    disabled\n\non property:init.svc.surfaceflinger=running\n    start droidrt_run\n";
    dev.write_file(".droidrt/init.rc", 0o644, &text);
    let src = v.resolve("/", "/dev/.droidrt/init.rc", true).map_err(|e| format!("init.rc copy: errno {e}"))?;
    v.bind(&src, &rc, false).map_err(|e| format!("init.rc bind: errno {e}"))
}

/// What first-stage init leaves for the second stage beyond the partitions
/// droidrt already mounted: a writable /metadata, and an fstab describing the
/// mounts that exist (bound over the vendor's, which names virtio disks
/// droidrt has no reason to emulate), so `mount_all` has nothing to wait for.
fn first_stage_mounts(v: &Vfs, metadata: &Arc<crate::tmpfs::Tmpfs>, dev: &crate::tmpfs::Tmpfs, partitions: &[String]) {
    if let Ok(node) = v.resolve("/", "/metadata", true) {
        let sb = v.new_super(metadata.clone(), "tmpfs", None, 0, "mode=0755");
        let _ = v.mount_at(&node, sb, 0);
    }
    // The host's adb key, as /adb_keys: outside /data, so it doesn't expire or depend on
    // what a saved /data holds. This overlays the image's link to its own (empty) file.
    dev.write_file(".droidrt/adb_keys", 0o644, "");
    if let (Ok(src), Ok(target)) = (v.resolve("/", "/dev/.droidrt/adb_keys", true), v.resolve("/", "/adb_keys", false)) {
        let _ = v.bind(&src, &target, false);
        if let Some(file) = v.mem_file(&src) {
            adb::set_key_file(file);
        }
    }
    let Ok(hw_fstab) = v.resolve("/", "/vendor/etc/fstab.ranchu", true) else { return };
    let mut fstab = String::from("# Written by droidrt, which plays first-stage init.\n");
    for (name, mountpoint) in crate::android::PARTITIONS {
        if partitions.iter().any(|p| p == name) {
            fstab += &format!("{name} {mountpoint} erofs ro wait,logical,first_stage_mount\n");
        }
    }
    fstab += "tmpfs /metadata tmpfs nosuid,nodev,noatime,mode=0755 first_stage_mount\n";
    dev.write_file(".droidrt/fstab.ranchu", 0o644, &fstab);
    if let Ok(src) = v.resolve("/", "/dev/.droidrt/fstab.ranchu", true) {
        let _ = v.bind(&src, &hw_fstab, false);
    }
}

/// Adds BOOT_PROPS to the ODM partition's build.prop, which init reads after the
/// vendor's so they override it. The image is read-only, so a copy of that (small)
/// directory goes over it. /odm/etc is a link to here.
fn add_boot_props(v: &mut Vfs, phys: &Arc<PhysMem>) {
    const DIR: &str = "/vendor/odm/etc";
    fn copy(v: &Vfs, to: &crate::tmpfs::Tmpfs, from: &str, rel: &str) -> Result<(), i64> {
        let dir = v.resolve("/", from, true)?;
        for e in v.readdir(&dir)? {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let (path, rel) = (format!("{from}/{}", e.name), format!("{rel}{}", e.name));
            let node = v.resolve("/", &path, false)?;
            let st = v.stat(&node)?;
            if st.mode & crate::vfs::S_IFMT == crate::vfs::S_IFDIR {
                to.mkdir_p(&rel, st.mode & 0o7777);
                copy(v, to, &path, &format!("{rel}/"))?;
            } else {
                let content = v.read_all(&node)?;
                let mut text = String::from_utf8_lossy(&content).into_owned();
                if rel == "build.prop" {
                    text.push_str(BOOT_PROPS);
                }
                to.write_file(&rel, st.mode & 0o7777, &text);
            }
        }
        Ok(())
    }
    let etc = crate::tmpfs::Tmpfs::new(phys.clone(), 0o755);
    match copy(v, &etc, DIR, "") {
        Ok(()) => v.mount(DIR, etc),
        Err(e) => eprintln!("droidrt: {DIR}: errno {e}: boot properties not set"),
    }
}

fn mount_tmpfs(vfs: &mut Vfs, phys: &Arc<PhysMem>) -> (Arc<crate::tmpfs::Tmpfs>, Arc<crate::tmpfs::Tmpfs>) {
    use crate::tmpfs::Tmpfs;
    use crate::vfs::FileSystem;
    let dev = Tmpfs::new(phys.clone(), 0o755);
    let dev_handle = dev.clone();
    for (name, rdev) in [("null", 0x103), ("zero", 0x105), ("random", 0x108), ("urandom", 0x109), ("kmsg", 0x10b), ("ptmx", 0x502)] {
        dev.create(1, name, 0o020666, rdev).expect("tmpfs /dev");
    }
    for (name, rdev) in binder::DEVICES {
        dev.create(1, name, 0o020666, rdev).expect("tmpfs /dev");
    }
    dev.mkdir_p("socket", 0o755);
    dev.mkdir_p("pts", 0o755);
    let input = dev.mkdir_p("input", 0o755);
    for (name, rdev) in evdev::nodes() {
        dev.create(input, name, 0o020666, rdev).expect("tmpfs /dev");
    }
    vfs.mount("/dev", dev);
    let pts = Tmpfs::with_type(phys.clone(), 0o755, "devpts");
    pts.create(1, "ptmx", 0o020000, 0x502).expect("devpts");
    vfs.mount("/dev/pts", pts);
    let data = Tmpfs::new(phys.clone(), 0o771);
    data.mkdir_p("local/tmp", 0o771);
    data.mkdir_p("system", 0o775);
    vfs.mount("/data", data.clone());
    vfs.mount("/tmp", Tmpfs::new(phys.clone(), 0o1777));
    vfs.mount("/mnt", Tmpfs::new(phys.clone(), 0o755));
    vfs.mount("/cache", Tmpfs::new(phys.clone(), 0o770));
    // sysfs: what bionic's sysconf and friends read. (selinuxfs is mounted
    // over /sys/fs/selinux once the kernel exists: it reads the policy lazily.)
    let sys = Tmpfs::with_type(phys.clone(), 0o755, "sysfs");
    let n = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
    for f in ["online", "possible", "present"] {
        sys.write_file(&format!("devices/system/cpu/{f}"), 0o444, &format!("0-{}\n", n - 1));
    }
    sys.write_file("devices/system/cpu/kernel_max", 0o444, "63\n");
    for d in ["fs/cgroup", "fs/bpf", "fs/pstore", "fs/fuse/connections", "kernel/tracing", "kernel/debug", "kernel/config", "class", "bus", "block", "dev/char", "dev/block", "module"] {
        sys.mkdir_p(d, 0o755);
    }
    vfs.mount("/sys", sys);
    (dev_handle, data)
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
    timers: Mutex<timers::ProcTimers>,
    mm_taker: AtomicI32,
    files_taker: AtomicI32,
    knobs: Mutex<procfs::Knobs>,
    pub creds: Mutex<creds::Creds>,
    /// Process group, session, limits, and other process-wide control state.
    pub attrs: Mutex<control::ProcAttrs>,
    /// SELinux context (and the one before the last execve).
    pub sec: selinux::ProcSec,
    /// Its mount namespace (vfs.rs).
    pub mnt_ns: AtomicU32,
    /// umask(2): permission bits new files, directories and sockets lack.
    pub umask: AtomicU32,
}

pub struct Thread {
    pub tid: i32,
    pub proc: Arc<Process>,
    last_fault: Mutex<Option<FaultRegs>>,
    /// The condvar this thread sleeps on, for a kick to wake it.
    sleeping_on: Mutex<Option<SleepOn>>,
    /// The signals an rt_sigtimedwait is waiting for: they are blocked, so
    /// sending one kicks nobody else's way.
    sigwait_set: AtomicU64,
    nap_lock: Mutex<()>,
    nap_cv: Condvar,
    clear_child_tid: AtomicU64,
    mask: AtomicU64,
    /// Mask to restore after a sigsuspend once its handler returns.
    saved_mask: Mutex<Option<u64>>,
    pending: Mutex<HashMap<u32, SigInfo>>,
    altstack: Mutex<(u64, u64, i32)>,
    kick: Mutex<Option<Arc<dyn Kick>>>,
    dying: AtomicBool,
    /// comm, prctl state, scheduling attributes.
    pub attrs: Mutex<control::ThreadAttrs>,
    /// Where it sleeps in wait::EVENTS, once it runs.
    event_slot: AtomicUsize,
    /// sched::CpuGroup, kept here for its readers on every guest entry.
    cpu_group: AtomicU8,
    /// hv::Urgency as computed from the attributes and the group.
    urgency: AtomicU8,
    /// SELinux exec/fscreate/keycreate/sockcreate contexts.
    pub sec: selinux::ThreadSec,
    /// The syscall in progress, for thread dumps.
    in_syscall: Mutex<Option<SyscallSnap>>,
    /// A descriptor table of its own: cloned without CLONE_FILES. Bionic's
    /// crash handler makes such a thread and closes everything in it.
    own_files: Option<Arc<Mutex<FdTable>>>,
}

/// Where a thread entered the kernel: what a thread dump prints for it. The
/// registers for its backtrace are read only under DROIDRT_DUMP (they cost a
/// trip to the hypervisor on every syscall).
struct SyscallSnap {
    nr: u64,
    args: [u64; 6],
    pc: u64,
    lr: u64,
    fp: u64,
    since: Instant,
}

/// DROIDRT_DUMP=<secs>: every that many seconds, print every guest thread,
/// the syscall it is in, and its backtrace (for diagnosing hangs). SIGUSR1
/// prints one dump any time, without backtraces unless this is set.
#[cfg(unix)]
fn dump_signal() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        set
    }
}

/// Wakeups since last asked, for DROIDRT_GPU_STATS.
pub fn wakeup_stats(over: Duration) -> String {
    static LAST: Mutex<(u64, u64)> = Mutex::new((0, 0));
    let (plain, keyed) = (wait::BUMPS_PLAIN.load(Ordering::Relaxed), wait::BUMPS_KEYED.load(Ordering::Relaxed));
    let mut last = LAST.lock().unwrap();
    let secs = over.as_secs_f64().max(0.001);
    let s = format!("bumps {:.0}/s plain, {:.0}/s keyed", (plain - last.0) as f64 / secs, (keyed - last.1) as f64 / secs);
    *last = (plain, keyed);
    s
}

/// SIGINT and SIGTERM, when a device has something to save before it goes.
#[cfg(unix)]
fn exit_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        set
    }
}

/// Holds SIGINT and SIGTERM for `start`'s thread. As `reserve_dump_signal`.
pub fn reserve_exit_signals() {
    #[cfg(unix)]
    unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &exit_signals(), std::ptr::null_mut());
    }
}

/// Holds SIGUSR1 for the dump thread's sigwait. Call before any thread
/// starts: threads inherit the mask, and one that took the signal itself
/// would die of it.
pub fn reserve_dump_signal() {
    #[cfg(unix)]
    unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &dump_signal(), std::ptr::null_mut());
    }
}

/// DROIDRT_FAULTLOG=1 reports every fault that raises a signal, handled or not.
fn fault_log(addr: u64) -> bool {
    static WANT: std::sync::OnceLock<Option<Option<u64>>> = std::sync::OnceLock::new();
    let want = WANT.get_or_init(|| {
        let v = std::env::var("DROIDRT_FAULTLOG").ok()?;
        Some(v.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()))
    });
    want.is_some_and(|only| only.is_none_or(|a| a == addr))
}

/// DROIDRT_STRACE=<name> traces only processes whose executable path
/// contains it; 1 (or --strace) traces everything.
fn strace_wanted(t: &Thread) -> bool {
    static ONLY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    match ONLY.get_or_init(|| std::env::var("DROIDRT_STRACE").ok().filter(|v| v != "1" && !v.is_empty())) {
        None => true,
        Some(name) => t.proc.exe.try_lock().is_ok_and(|e| e.contains(name.as_str())),
    }
}

fn dump_after() -> Option<u64> {
    static AFTER: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *AFTER.get_or_init(|| std::env::var("DROIDRT_DUMP").ok().and_then(|v| v.parse().ok()))
}

thread_local! {
    // The guest thread this host thread runs; 0 for droidrt's own threads.
    static GUEST_TID: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

/// For the thread dump: who last took a lock. If the lock stays taken, that is
/// who holds it.
fn guest_tid() -> i32 {
    GUEST_TID.with(|t| t.get())
}

#[derive(Clone, Copy)]
struct FaultRegs {
    pc: u64,
    lr: u64,
    fp: u64,
    addr: u64,
    write: bool,
}

struct SleepOn(*const Condvar);
// The pointer is only used under Thread::sleeping_on, and the sleeper clears
// it under that lock before the condvar can go away.
unsafe impl Send for SleepOn {}

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
        let guard = self.mm.lock().unwrap();
        self.mm_taker.store(guest_tid(), Ordering::Relaxed);
        Mm(guard)
    }
}

/// DROIDRT_SCHED_TRACE=1: every change in what the host is told about a thread.
fn sched_tracing() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("DROIDRT_SCHED_TRACE").is_some())
}

impl Thread {
    fn new(tid: i32, proc: Arc<Process>, mask: u64, own_files: Option<Arc<Mutex<FdTable>>>) -> Arc<Thread> {
        Arc::new(Thread {
            last_fault: Mutex::new(None),
            sleeping_on: Mutex::new(None),
            sigwait_set: AtomicU64::new(0),
            nap_lock: Mutex::new(()),
            nap_cv: Condvar::new(),
            own_files,
            tid,
            proc,
            clear_child_tid: AtomicU64::new(0),
            mask: AtomicU64::new(mask),
            saved_mask: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            altstack: Mutex::new((0, 0, signal::SS_DISABLE)),
            kick: Mutex::new(None),
            dying: AtomicBool::new(false),
            attrs: Mutex::new(control::ThreadAttrs::default()),
            event_slot: AtomicUsize::new(usize::MAX),
            cpu_group: AtomicU8::new(sched::CpuGroup::Other as u8),
            urgency: AtomicU8::new(Urgency::Normal as u8),
            sec: Default::default(),
            in_syscall: Mutex::new(None),
        })
    }

    /// What the host should make of this thread (see sched::urgency).
    pub(super) fn urgency(&self) -> Urgency {
        match self.urgency.load(Ordering::Relaxed) {
            0 => Urgency::Display,
            1 => Urgency::Foreground,
            3 => Urgency::Background,
            _ => Urgency::Normal,
        }
    }

    /// `attrs` is this thread's, held by the caller.
    pub(super) fn update_urgency(&self, attrs: &control::ThreadAttrs) {
        let group = sched::CpuGroup::from_u8(self.cpu_group.load(Ordering::Relaxed));
        let u = sched::urgency(attrs.sched.policy, attrs.sched.nice, group);
        let was = self.urgency.swap(u as u8, Ordering::Relaxed);
        if was == u as u8 {
            return;
        }
        if sched_tracing() {
            eprintln!("[sched] {} tid {}: {u:?} (nice {}, policy {}, {group:?})", attrs.comm, self.tid, attrs.sched.nice, attrs.sched.policy);
        }
        // It may be queuing for a background place it no longer needs.
        if was == Urgency::Background as u8 {
            self.wake_sleeper();
        }
    }

    /// What binder does to a thread for the length of a call.
    pub(super) fn set_nice(&self, nice: i32) {
        let mut attrs = self.attrs.lock().unwrap();
        if attrs.sched.nice != nice {
            attrs.sched.nice = nice;
            self.update_urgency(&attrs);
        }
    }

    pub(super) fn nice(&self) -> i32 {
        self.attrs.lock().unwrap().sched.nice
    }

    pub(super) fn set_cpu_group(&self, group: sched::CpuGroup) {
        self.cpu_group.store(group as u8, Ordering::Relaxed);
        self.update_urgency(&self.attrs.lock().unwrap());
    }

    /// A new thread is where its creator is, and as urgent.
    fn inherit_sched(&self, from: &Thread) {
        self.cpu_group.store(from.cpu_group.load(Ordering::Relaxed), Ordering::Relaxed);
        self.update_urgency(&self.attrs.lock().unwrap());
    }

    /// Whether a blocking wait should give up now (signal or exit).
    /// The descriptor table this thread's syscalls use.
    pub(super) fn files(&self) -> std::sync::MutexGuard<'_, FdTable> {
        let guard = match &self.own_files {
            Some(f) => f.lock().unwrap(),
            None => self.proc.files.lock().unwrap(),
        };
        self.proc.files_taker.store(self.tid, Ordering::Relaxed);
        guard
    }

    pub(super) fn interrupted(&self) -> bool {
        self.dying.load(Ordering::Acquire) || self.has_deliverable_signal()
    }

    /// Stops the thread's vCPU if it is in the guest.
    fn kick_vcpu(&self) {
        if let Some(k) = self.kick.lock().unwrap().as_ref() {
            k.kick();
        }
    }

    /// Makes the thread look at its signals and whether it is dying, wherever
    /// it is: in the guest, or asleep in a syscall.
    fn kick(&self) {
        self.kick_vcpu();
        self.wake_sleeper();
        // Poll, epoll and the like sleep there.
        let slot = self.event_slot.load(Ordering::Relaxed);
        if slot != usize::MAX {
            wait::EVENTS.wake_slot(slot);
        }
    }

    fn wake_sleeper(&self) {
        if let Some(cv) = &*self.sleeping_on.lock().unwrap() {
            unsafe { (*cv.0).notify_all() };
        }
    }

    /// Sleeps on `cv` until it is notified, the thread is kicked, or `timeout`
    /// passes. Anything that can end the sleep must notify `cv`.
    fn sleep<'a, T>(&self, cv: &Condvar, g: MutexGuard<'a, T>, timeout: Duration) -> MutexGuard<'a, T> {
        *self.sleeping_on.lock().unwrap() = Some(SleepOn(cv));
        let g = if self.interrupted() { g } else { cv.wait_timeout(g, timeout).unwrap().0 };
        *self.sleeping_on.lock().unwrap() = None;
        g
    }

    /// As `sleep` for a thread that can't do anything about a signal until it gets
    /// where it is going, so only dying ends the wait. A signal still wakes it, but then
    /// it goes back to sleep, as it would not if this looked at signals.
    fn wait_for_turn<'a, T>(&self, cv: &Condvar, g: MutexGuard<'a, T>, timeout: Duration) -> MutexGuard<'a, T> {
        *self.sleeping_on.lock().unwrap() = Some(SleepOn(cv));
        let g = if self.dying.load(Ordering::Acquire) { g } else { cv.wait_timeout(g, timeout).unwrap().0 };
        *self.sleeping_on.lock().unwrap() = None;
        g
    }

    /// Sleeps for `d` unless kicked.
    fn nap(&self, d: Duration) {
        let g = self.nap_lock.lock().unwrap();
        drop(self.sleep(&self.nap_cv, g, d));
    }
}

impl Kernel {
    /// `boot`: Android's init runs as pid 1 and provides properties and
    /// daemons itself; otherwise the kernel stands in for what init would
    /// have set up (the property area and service, logd).
    /// `partitions`: the image's logical partitions, mapped as device-mapper
    /// devices as first-stage init would.
    pub fn new(hv: Arc<dyn Hypervisor>, vfs: Option<Vfs>, partitions: Vec<(String, crate::image::Dev)>, strace: bool, extras: Option<BootExtras>, gpu: Option<Arc<dyn crate::gpu::GpuBackend>>) -> Result<Arc<Kernel>, String> {
        let boot = extras.is_some();
        let phys = PhysMem::new(hv.clone());
        let max_vcpus = hv.max_vcpus();
        let pages = hv.kernel_pages(&mut || {
            let gpa = phys.alloc().expect("no memory for the kernel window");
            (gpa, phys.host(gpa))
        });
        let kwin = KernelWindow::new(&phys, &pages).map_err(|e| format!("kernel window: errno {e}"))?;
        // Without an image the root itself is a tmpfs (for freestanding guests).
        let mut v = vfs.unwrap_or_else(|| {
            let v = Vfs::default();
            v.mount("/", crate::tmpfs::Tmpfs::new(phys.clone(), 0o755));
            v
        });
        let (dev, data) = mount_tmpfs(&mut v, &phys);
        let mut persist = None;
        if boot {
            evdev::start_input_fifo();
            // There is no virtual HCI controller yet. With the feature declared,
            // Android's Bluetooth stack aborts and restarts for as long as it runs.
            let oem = crate::tmpfs::Tmpfs::new(phys.clone(), 0o755);
            oem.write_file("etc/sysconfig/droidrt.xml", 0o644, NO_BLUETOOTH);
            v.mount("/oem", oem);
            add_boot_props(&mut v, &phys);
        }
        let sys = v.resolve("/", "/sys", true).map(|n| v.fs_arc(&n)).map_err(|e| format!("/sys: errno {e}"))?;
        let blocks = block::Blocks::new(dev.clone(), sys.clone());
        let drm = gpu.as_ref().map(|g| drm::Device::new(g.clone(), phys.clone()));
        if let Some(d) = &drm {
            d.publish(dev.as_ref(), sys.as_ref());
        }
        net::publish(sys.clone());
        power::publish(sys.as_ref());
        let sysctl = sysctl::Sysctl::new();
        // libcutils opens /dev/ashmem<boot id> (init names the node so).
        {
            use crate::vfs::FileSystem;
            if let Ok(root) = dev.root() {
                for name in ["ashmem".to_string(), format!("ashmem{}", sysctl.get("kernel/random/boot_id"))] {
                    let _ = dev.create(root, &name, 0o020666, ashmem::rdev());
                }
                // The TUN device, at Android's path and Linux's.
                let _ = dev.create(root, "tun", 0o020660, net::tun_rdev());
                if let Ok(d) = dev.mkdir(root, "net", 0o755) {
                    let _ = dev.create(d, "tun", 0o020660, net::tun_rdev());
                }
            }
        }
        let names: Vec<String> = partitions.iter().map(|(n, _)| n.clone()).collect();
        for (name, dev) in partitions {
            blocks.add_static(&name, dev);
        }
        if let Some(extras) = &extras {
            let metadata = crate::tmpfs::Tmpfs::new(phys.clone(), 0o755);
            first_stage_mounts(&v, &metadata, &dev, &names);
            if let Some(image) = &extras.data {
                let p = Persist { path: image.path.clone(), trees: vec![("data", data.clone()), ("metadata", metadata)] };
                if !image.wipe {
                    let started = Instant::now();
                    match p.load() {
                        Ok(size) => eprintln!("droidrt: {}: read {} MB in {:.1} s", p.path.display(), size >> 20, started.elapsed().as_secs_f64()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => eprintln!("droidrt: {}: {e}; starting with an empty /data", p.path.display()),
                    }
                }
                persist = Some(p);
            }
            apply_extras(&v, &dev, extras)?;
        }
        // Properties, as init would set them up: defaults from build.prop,
        // shared read-only with every process at /dev/__properties__.
        let props = properties::Properties::new(phys.clone());
        if !boot {
            props.load_defaults(&v);
            props.set(None, "logd.ready", "true"); // logd is answered in the kernel (logd.rs)
            // The emulator's answer to a busy host: Watchdog and ANR timeouts scale by this.
            props.set(None, "ro.hw_timeout_multiplier", "5");
            dev.add_file("__properties__", 0o444, props.file.clone());
        }
        xattr::label_mounts(&v);
        // /proc reads kernel state, so the kernel is built around it.
        Ok(Arc::new_cyclic(|me| {
            v.mount("/proc", procfs::ProcFs::new(me.clone()));
            let selinux = selinux::Selinux::new(me.clone(), phys.clone(), boot);
            v.mount("/sys/fs/selinux", selinux.clone());
            let svc: Arc<dyn unix::Service> = Arc::new(PropertyService { kernel: me.clone() });
            // Socket nodes in /dev/socket, with init's modes and owners.
            let mut services = Vec::new();
            if !boot {
                services.push(unix::listen_service(&v, "/dev/socket/property_service", unix::SOCK_STREAM, 0o666, (0, 0), svc.clone()));
                services.push(unix::listen_service(&v, "/dev/socket/property_service_for_system", unix::SOCK_STREAM, 0o660, (0, 1000), svc));
            }
            // Also in boot mode, until init starts the real logd, which
            // replaces these (init unlinks a socket's path before binding it).
            services.extend(logd::start(&v));
            Kernel {
            arch: Arch::HOST,
            vfs: Some(Arc::new(v)),
            hv,
            phys,
            kwin,
            strace,
            boot: {
                let now = Instant::now();
                evdev::set_boot(now);
                now
            },
            timers: timers::TimerQueue::new(me.clone()),
            procs: Mutex::new(HashMap::new()),
            next_id: AtomicI32::new(1),
            id_wrapped: Mutex::new(false),
            next_asid: AtomicU32::new(1),
            live_threads: AtomicUsize::new(0),
            vcpus: vcpus::Pool::new(max_vcpus),
            persist,
            futex: futex::Futexes::default(),
            root_pid: AtomicI32::new(0),
            props,
            blocks,
            sysctl,
            selinux,
            _services: services,
            exit: (Mutex::new(None), Condvar::new()),
            drm,
            gpu,
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

    /// A free pid or tid. Ids wrap at pid_max as on Linux, and never reuse a
    /// live thread, process, group or session id. /proc keeps them in 16 bits.
    fn alloc_id(&self) -> i32 {
        const PID_MAX: i32 = 32768;
        const AFTER_WRAP: i32 = 300;
        let mut wrapped = self.id_wrapped.lock().unwrap();
        loop {
            let mut id = self.next_id.load(Ordering::Relaxed);
            if id >= PID_MAX {
                id = AFTER_WRAP;
                *wrapped = true;
            }
            self.next_id.store(id + 1, Ordering::Relaxed);
            let taken = *wrapped
                && self.procs.lock().unwrap().values().any(|p| {
                    let a = p.attrs.lock().unwrap();
                    p.pid == id || a.pgid == id || a.sid == id || p.threads.lock().unwrap().iter().any(|t| t.tid == id)
                });
            if !taken {
                return id;
            }
        }
    }

    fn process(&self, pid: i32) -> Option<Arc<Process>> {
        self.procs.lock().unwrap().get(&pid).cloned()
    }

    /// Starts the first process: `mm` already holds the program and its stack.
    /// Prints every guest thread: comm, the syscall it is in, backtrace.
    /// Only try_lock: a dump is for when something holds a lock forever.
    fn dump_threads(&self) {
        let procs = (0..50).find_map(|_| match self.procs.try_lock() {
            Ok(p) => Some(p.values().cloned().collect::<Vec<Arc<Process>>>()),
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            }
        });
        let Some(mut procs) = procs else {
            eprintln!("[droidrt] ---- thread dump: the process table stays locked ----");
            return;
        };
        procs.sort_by_key(|p| p.pid);
        eprintln!("[droidrt] ---- thread dump: {} processes ----", procs.len());
        if let Some(tid) = binder::lock_taker() {
            eprintln!("[droidrt] binder lock held by tid {tid}");
        }
        for p in procs {
            if p.mm.try_lock().is_err() {
                eprintln!("[droidrt] {}: address space locked by tid {}", p.pid, p.mm_taker.load(Ordering::Relaxed));
            }
            if p.files.try_lock().is_err() {
                eprintln!("[droidrt] {}: fd table locked by tid {}", p.pid, p.files_taker.load(Ordering::Relaxed));
            }
            if p.creds.try_lock().is_err() {
                eprintln!("[droidrt] {}: creds locked", p.pid);
            }
            let Ok(threads) = p.threads.try_lock().map(|t| t.clone()) else {
                eprintln!("[droidrt] {}: thread list locked", p.pid);
                continue;
            };
            let exe = p.exe.try_lock().map(|e| e.clone()).unwrap_or_else(|_| "?".into());
            for t in threads {
                let comm = t.attrs.try_lock().map(|a| a.comm.clone()).unwrap_or_else(|_| "?".into());
                let Ok(snap) = t.in_syscall.try_lock().map(|s| s.as_ref().map(|s| (s.nr, s.args, s.pc, s.lr, s.fp, s.since.elapsed()))) else {
                    eprintln!("[droidrt] {} {} {comm} ({exe}): entering or leaving a syscall", p.pid, t.tid);
                    continue;
                };
                let Some((nr, a, pc, lr, mut fp, held)) = snap else {
                    eprintln!("[droidrt] {} {} {comm} ({exe}): running", p.pid, t.tid);
                    continue;
                };
                let name = self.arch.sysno(nr).map_or_else(|| format!("syscall_{nr}"), |s| format!("{s:?}"));
                // What the first argument names, when it is a file descriptor.
                let fd = match p.files.try_lock() {
                    Ok(files) => files.get(a[0] as i32 as i64).map(|f| files::file_name(&f)).unwrap_or_default(),
                    Err(_) => String::new(),
                };
                eprintln!("[droidrt] {} {} {comm} ({exe}): {name}({:#x}, {:#x}, {:#x}, {:#x}) for {:.1}s {fd}", p.pid, t.tid, a[0], a[1], a[2], a[3], held.as_secs_f64());
                if pc == 0 {
                    continue; // no registers without DROIDRT_DUMP
                }
                // The address space may be busy; skip rather than wait.
                let Ok(mut guard) = p.mm.try_lock() else { continue };
                let Some(mm) = guard.as_mut() else { continue };
                eprintln!("[droidrt]     at {}", mm.symbolize(pc));
                eprintln!("[droidrt]     lr {}", mm.symbolize(lr));
                for _ in 0..12 {
                    let (Ok(next), Ok(ret)) = (mm.read_u64(fp), mm.read_u64(fp + 8)) else { break };
                    if ret == 0 {
                        break;
                    }
                    eprintln!("[droidrt]     {}", mm.symbolize(ret));
                    if next <= fp {
                        break;
                    }
                    fp = next;
                }
            }
        }
    }

    pub fn start(self: &Arc<Self>, mm: AddressSpace, exe: String, argv: &[String], state: CpuState) -> Result<(), String> {
        if let Some(secs) = dump_after() {
            let k = self.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(secs.max(1)));
                k.dump_threads();
            });
        }
        if self.persist.is_some() {
            let k = self.clone();
            crate::gpu::on_window_closed(Box::new(move || k.request_exit(0)));
            #[cfg(unix)]
            {
                let k = self.clone();
                let _ = std::thread::Builder::new().name("exit-signals".into()).spawn(move || {
                    let mut sig = 0;
                    if unsafe { libc::sigwait(&exit_signals(), &mut sig) } == 0 {
                        k.request_exit(sig);
                    }
                    // Again while saving: this time they mean it.
                    if unsafe { libc::sigwait(&exit_signals(), &mut sig) } == 0 {
                        std::process::exit(128 + sig);
                    }
                });
            }
        }
        #[cfg(unix)]
        {
            let k = self.clone();
            let _ = std::thread::Builder::new().name("dump".into()).spawn(move || loop {
                let mut sig = 0;
                if unsafe { libc::sigwait(&dump_signal(), &mut sig) } == 0 {
                    k.dump_threads();
                }
            });
        }
        let pid = self.alloc_id();
        let proc = Arc::new(Process {
            pid,
            ppid: AtomicI32::new(0),
            mm: Mutex::new(Some(mm)),
            files: Mutex::new(FdTable::stdio()),
            cwd: Mutex::new("/".into()),
            timers: Mutex::default(),
            mm_taker: AtomicI32::new(0),
            files_taker: AtomicI32::new(0),
            exe: Mutex::new(exe),
            cmdline: Mutex::new(cmdline_bytes(argv)),
            sig: Mutex::new(Actions::default()),
            threads: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            child_cv: Condvar::new(),
            status: Mutex::new(None),
            exiting: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            knobs: Mutex::default(),
            creds: Mutex::new(creds::Creds::root()),
            attrs: Mutex::new(control::ProcAttrs::first()),
            sec: self.selinux.initial_sec(),
            mnt_ns: AtomicU32::new(crate::vfs::INIT_NS),
            umask: AtomicU32::new(0o022),
        });
        self.root_pid.store(pid, Ordering::Relaxed);
        self.procs.lock().unwrap().insert(pid, proc.clone());
        let thread = Thread::new(pid, proc.clone(), 0, None);
        thread.attrs.lock().unwrap().comm = control::comm_of(argv.first().map_or("", String::as_str));
        proc.threads.lock().unwrap().push(thread.clone());
        self.spawn(thread, state).map_err(|e| format!("cannot start the first thread: errno {e}"))
    }

    /// Blocks until the root process exits; returns its wait status.
    /// Ends the run as if the root process had exited with `status`.
    pub fn request_exit(&self, status: i32) {
        let (lock, cv) = &self.exit;
        lock.lock().unwrap().get_or_insert(status);
        cv.notify_all();
    }

    /// Keeps what a device keeps, if it does: stops guest code running first, so the
    /// file holds one moment rather than a smear of them.
    pub fn save_data(&self) {
        let Some(p) = &self.persist else { return };
        self.vcpus.freeze();
        let procs: Vec<Arc<Process>> = self.procs.lock().unwrap().values().cloned().collect();
        for proc in procs {
            for th in proc.threads.lock().unwrap().iter() {
                th.kick_vcpu();
            }
        }
        // Long enough for syscalls under way to finish what they are writing. Those
        // that sleep instead aren't writing.
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        match p.save() {
            Ok(contents) => eprintln!("droidrt: {}: saved {} MB in {:.1} s", p.path.display(), contents >> 20, started.elapsed().as_secs_f64()),
            Err(e) => eprintln!("droidrt: {}: not saved: {e}", p.path.display()),
        }
    }

    pub fn wait_root(&self) -> i32 {
        let (lock, cv) = &self.exit;
        let mut status = lock.lock().unwrap();
        while status.is_none() {
            status = cv.wait(status).unwrap();
        }
        status.unwrap()
    }

    /// Runs `thread` on a new host thread (it gets a vCPU when it runs guest code).
    fn spawn(self: &Arc<Self>, thread: Arc<Thread>, state: CpuState) -> Result<(), i64> {
        if self.live_threads.fetch_add(1, Ordering::AcqRel) >= MAX_THREADS {
            self.live_threads.fetch_sub(1, Ordering::AcqRel);
            eprintln!("[droidrt] thread limit ({MAX_THREADS}) reached");
            return Err(EAGAIN);
        }
        let k = self.clone();
        let t = thread.clone();
        std::thread::Builder::new()
            .name(format!("guest-{}", thread.tid))
            .stack_size(1 << 20)
            .spawn(move || {
                k.thread_main(&t, state);
                k.live_threads.fetch_sub(1, Ordering::AcqRel);
            })
            .map(|_| ())
            .map_err(|_| {
                self.live_threads.fetch_sub(1, Ordering::AcqRel);
                EAGAIN
            })
    }

    fn thread_main(self: &Arc<Self>, t: &Arc<Thread>, state: CpuState) {
        GUEST_TID.with(|tid| tid.set(t.tid));
        t.event_slot.store(wait::EVENTS.slot_of_this_thread(), Ordering::Relaxed);
        crate::vfs::set_current_ns(t.proc.mnt_ns.load(Ordering::Relaxed));
        let root = t.proc.mm().root;
        let mut vcpu: Box<dyn Vcpu> = Box::new(vcpus::LazyVcpu::new(self.hv.clone(), self.vcpus.clone(), t.clone(), root, state));
        let mut stale = crate::mm::Stale::default();
        let mut restart: Option<SyscallRegs> = None;
        // The generation a requested TLB flush will cover, until it has run.
        let mut flushing: Option<u64> = None;
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
            // The flush requested last time ran on entry; now frames are safe to
            // reuse. (Interrupted: the vCPU may not have reached the flush yet.)
            if !matches!(exit, Exit::Interrupted)
                && let Some(generation) = flushing.take()
            {
                let mut mm = t.proc.mm();
                mm.flushed_gen = mm.flushed_gen.max(generation);
                drop(mm);
                stale.release(&self.phys);
            }
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
                    let faulted = t.proc.mm().fault(addr, write, exec);
                    if faulted == Err(crate::mm::FAULT_UFFD) {
                        const BUS_ADRERR: i32 = 2;
                        if !self.signal_caught(t, signal::SIGBUS) {
                            self.crash_report(t, vcpu.as_ref(), "SIGBUS", pc, addr, write);
                        }
                        self.force_signal(t, signal::SIGBUS, SigInfo::fault(signal::SIGBUS, BUS_ADRERR, addr), pc);
                    } else if let Err(code) = faulted {
                        if let CpuState::Aarch64(s) = vcpu.state() {
                            *t.last_fault.lock().unwrap() = Some(FaultRegs { pc, lr: s.x[30], fp: s.x[29], addr, write });
                        }
                        // ART takes these all the time (implicit null and suspend
                        // checks) and handles them. Only one that kills is a crash:
                        // a real one comes back here once its handler gives up.
                        if !self.signal_caught(t, signal::SIGSEGV) || fault_log(addr) {
                            self.crash_report(t, vcpu.as_ref(), "SIGSEGV", pc, addr, write);
                        }
                        self.force_signal(t, signal::SIGSEGV, SigInfo::fault(signal::SIGSEGV, code, addr), pc);
                    }
                }
                Exit::Fault { pc, addr, detail } => {
                    eprintln!("[droidrt] tid {}: guest fault at pc={pc:#x} addr={addr:#x}: {detail}", t.tid);
                    if !self.signal_caught(t, signal::SIGILL) {
                        self.crash_report(t, vcpu.as_ref(), "SIGILL", pc, addr, false);
                    }
                    self.force_signal(t, signal::SIGILL, SigInfo::fault(signal::SIGILL, 1, pc), pc);
                }
                Exit::Interrupted => {}
            }
            let mut mm = t.proc.mm();
            if mm.flushed_gen < mm.tlb_gen {
                stale.absorb(mm.take_stale());
                vcpu.flush_tlb();
                flushing = Some(mm.tlb_gen);
            }
        }
        drop(vcpu); // destroyed on the thread that owns it
        // Never flushed for: another thread will, or the address space goes with us.
        t.proc.mm().return_stale(stale);
        self.thread_exit(t, exit_code);
    }

    fn syscall(self: &Arc<Self>, t: &Arc<Thread>, vcpu: &mut dyn Vcpu, regs: &SyscallRegs) -> Ret {
        let sysno = self.arch.sysno(regs.nr);
        let a = regs.args;
        files::CURRENT.with(|c| c.set((t.proc.pid, t.tid, regs.nr)));
        let (pc, lr, fp) = match dump_after().map(|_| vcpu.state()) {
            Some(CpuState::Aarch64(st)) => (st.pc, st.x[30], st.x[29]),
            _ => (0, 0, 0),
        };
        *t.in_syscall.lock().unwrap() = Some(SyscallSnap { nr: regs.nr, args: a, pc, lr, fp, since: Instant::now() });
        let ret = match sysno {
            None => Ret::Value(-ENOSYS),
            Some(no) => self.dispatch(no, t, vcpu, a),
        };
        *t.in_syscall.lock().unwrap() = None;
        if self.strace && strace_wanted(t) {
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
            wait4 => self.sys_wait4(t, int(a[0]) as i32, a[1], a[2], a[3]),
            waitid => self.sys_waitid(t, a[0], int(a[1]) as i32, a[2], a[3], a[4]),
            kill => self.sys_kill(int(a[0]) as i32, a[1] as u32, t),
            tgkill => self.sys_tgkill(int(a[0]) as i32, int(a[1]) as i32, a[2] as u32, t),
            tkill => self.sys_tgkill(-1, int(a[0]) as i32, a[1] as u32, t),
            rt_tgsigqueueinfo => self.sys_sigqueueinfo(t, int(a[0]) as i32, Some(int(a[1]) as i32), a[2] as u32, a[3]).unwrap_or_else(|e| -e),
            rt_sigqueueinfo => self.sys_sigqueueinfo(t, int(a[0]) as i32, None, a[1] as u32, a[2]).unwrap_or_else(|e| -e),
            timer_create | timer_settime | timer_gettime | timer_getoverrun | timer_delete | setitimer | getitimer | alarm => self.timer_syscall(no, t, a).unwrap_or_else(|e| -e),
            getpid => t.proc.pid as i64,
            gettid => t.tid as i64,
            getppid => t.proc.ppid.load(Ordering::Relaxed) as i64,
            set_tid_address => {
                t.clear_child_tid.store(a[0], Ordering::Relaxed);
                t.tid as i64
            }
            // credentials, capabilities, prctl, limits, scheduling, process groups
            n if creds::handles(n) => match self.creds_syscall(n, t, a) {
                Ok(v) => v,
                Err(e) => -e,
            },

            // signals
            rt_sigaction => self.sys_rt_sigaction(t, a[0] as u32, a[1], a[2]),
            rt_sigprocmask => self.sys_rt_sigprocmask(t, a[0], a[1], a[2]),
            rt_sigsuspend => self.sys_rt_sigsuspend(t, a[0]),
            rt_sigtimedwait => self.sys_rt_sigtimedwait(t, a[0], a[1], a[2]),
            rt_sigpending => self.sys_rt_sigpending(t, a[0]),
            rt_sigreturn => return self.sys_rt_sigreturn(t, vcpu),
            sigaltstack => self.sys_sigaltstack(t, a[0], a[1]),

            // memory
            brk => self.sys_brk(t, a[0]),
            mmap => self.sys_mmap(t, a[0], a[1], a[2] as u32, a[3], int(a[4]), a[5]),
            munmap => self.sys_munmap(t, a[0], a[1]),
            mprotect => self.sys_mprotect(t, a[0], a[1], a[2] as u32),
            mremap => self.sys_mremap(t, a[0], a[1], a[2], a[3], a[4]),
            madvise => self.sys_madvise(t, a[0], a[1], a[2]),
            msync => self.sys_msync(t, a[0], a[1], a[2]),
            mlock | munlock | mlock2 => self.sys_mlock(t, a[0], a[1], if no == mlock2 { a[2] } else { 0 }),
            mlockall => self.sys_mlockall(a[0]),
            munlockall => 0,
            mincore => self.sys_mincore(t, a[0], a[1], a[2]),

            bpf => match self.sys_bpf(t, a[0], a[1], a[2]) {
                Ok(v) => v,
                Err(e) => -e,
            },

            // futexes
            futex => self.sys_futex(t, a[0], a[1] as u32, a[2] as u32, a[3], a[4], a[5] as u32),
            set_robust_list => 0,

            // mounts and namespaces
            n if self::mount::handles(n) => match self.mount_syscall(n, t, a) {
                Ok(v) => v,
                Err(e) => -e,
            },

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
            n if xattr::handles(n) => match self.xattr_syscall(n, t, a) {
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
        eprintln!("[droidrt]   in {}", mm.describe(addr));
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

    /// For a process about to die of a signal: where its last fault was. crash_dump
    /// needs ptrace, so this is the only report such a crash gets. Faults are recorded
    /// when they happen, as ART takes and handles them all the time.
    fn report_last_fault(&self, t: &Thread) {
        let Some(f) = t.last_fault.lock().unwrap().take() else { return };
        let mut guard = t.proc.mm.lock().unwrap();
        let Some(mm) = guard.as_mut() else { return };
        eprintln!("[droidrt]   last fault: tid {} {} {:#x} at {}", t.tid, if f.write { "writing" } else { "reading" }, f.addr, mm.symbolize(f.pc));
        eprintln!("[droidrt]   in {}", mm.describe(f.addr));
        eprintln!("[droidrt]   lr {}", mm.symbolize(f.lr));
        let mut fp = f.fp;
        for i in 0..24 {
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

    /// Called on the exiting thread's host thread after its vCPU is gone.
    fn thread_exit(self: &Arc<Self>, t: &Arc<Thread>, code: i32) {
        let proc = &t.proc;
        // A table only this thread had closes with it (pipe readers see EOF).
        if let Some(f) = t.own_files.as_ref().filter(|f| Arc::strong_count(f) == 1) {
            drop(std::mem::replace(&mut *f.lock().unwrap(), FdTable::empty()));
        }
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
        self.parent_thread_gone(t);
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
        // Two statements: the lock must be free before the files go. Closing them
        // can wait on locks whose holders are putting descriptors in this table.
        let files = std::mem::replace(&mut *proc.files.lock().unwrap(), FdTable::empty());
        drop(files);
        locks::LOCKS.release(locks::Owner::Process(proc.pid));
        let old = proc.mm.lock().unwrap().take();
        drop(old);
        // Children move before we become a zombie: whoever reaps us finds them in place.
        self.reparent_children(proc);
        *proc.status.lock().unwrap() = Some(status);
        if proc.pid == self.root_pid.load(Ordering::Relaxed) {
            let (lock, cv) = &self.exit;
            lock.lock().unwrap().get_or_insert(status); // a reboot() may have decided already
            cv.notify_all();
            return;
        }
        if let Some(parent) = self.process(proc.ppid.load(Ordering::Relaxed)) {
            self.notify_parent(&parent, proc, status);
        }
    }
}
