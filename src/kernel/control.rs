//! Process control: prctl, seccomp (filters are accepted and counted, not
//! enforced), resource limits, personality, host and domain names, reboot,
//! and process_vm_readv/writev.

use super::creds::{CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_PTRACE, CAP_SYS_RESOURCE};
use super::{Kernel, Process, Thread};
use crate::arch::{Arch, Sysno};
use crate::errno::*;
use crate::mm::STACK_SIZE;
use std::sync::{Arc, LazyLock, Mutex};

pub const RLIMIT_NOFILE: usize = 7;
pub const RLIMIT_NICE: usize = 13;
pub const RLIMIT_RTPRIO: usize = 14;
const RLIM_NLIMITS: u64 = 16;
const INF: u64 = u64::MAX;
/// fs.nr_open: the largest RLIMIT_NOFILE hard limit.
const NR_OPEN: u64 = 1 << 20;
/// RLIMIT_NPROC / RLIMIT_SIGPENDING: Linux sizes them from memory (max_threads / 2).
const NPROC: u64 = crate::phys::PHYS_MAX / crate::phys::PAGE / 64;
const TIMER_SLACK_NS: u64 = 50_000;
const IOV_MAX: u64 = 1024;
/// How much process_vm_readv/writev copies per step.
const VM_CHUNK: u64 = 64 << 10;

const PR_SPEC_PRCTL: u64 = 1;
const PR_SPEC_ENABLE: u64 = 2;
const PR_SPEC_DISABLE: u64 = 4;
const PR_SPEC_FORCE_DISABLE: u64 = 8;
const PR_SPEC_DISABLE_NOEXEC: u64 = 16;

static UTS: LazyLock<Mutex<(String, String)>> = LazyLock::new(|| Mutex::new(("localhost".into(), "(none)".into())));

/// uname's nodename (sethostname).
pub fn hostname() -> String {
    UTS.lock().unwrap().0.clone()
}

pub fn domainname() -> String {
    UTS.lock().unwrap().1.clone()
}

/// Per-process state beyond credentials.
#[derive(Clone)]
pub struct ProcAttrs {
    pub pgid: i32,
    pub sid: i32,
    /// A session leader (it called setsid).
    pub leader: bool,
    /// Has execve'd since fork: setpgid from its parent then fails.
    pub execed: bool,
    /// The thread that forked us; its exit sends our threads their parent-death signal.
    pub parent_tid: i32,
    /// Reparented to a reaper after our parent exited.
    pub adopted: bool,
    pub subreaper: bool,
    pub dumpable: u32,
    pub limits: [(u64, u64); RLIM_NLIMITS as usize],
    pub personality: u32,
    pub thp_disable: bool,
}

impl ProcAttrs {
    /// The first process. Like Linux's init it is in process group and
    /// session 0, inherited from the idle task, and leads neither.
    pub fn first() -> ProcAttrs {
        let mut limits = [(INF, INF); RLIM_NLIMITS as usize];
        limits[3] = (STACK_SIZE, INF); // RLIMIT_STACK
        limits[4] = (0, INF); // RLIMIT_CORE
        limits[6] = (NPROC, NPROC); // RLIMIT_NPROC
        limits[RLIMIT_NOFILE] = (super::files::NOFILE_DEFAULT as u64, 4096);
        limits[8] = (8 << 20, 8 << 20); // RLIMIT_MEMLOCK
        limits[11] = (NPROC, NPROC); // RLIMIT_SIGPENDING
        limits[12] = (819_200, 819_200); // RLIMIT_MSGQUEUE
        limits[RLIMIT_NICE] = (0, 0);
        limits[RLIMIT_RTPRIO] = (0, 0);
        ProcAttrs { pgid: 0, sid: 0, leader: false, execed: false, parent_tid: 0, adopted: false, subreaper: false, dumpable: 1, limits, personality: 0, thp_disable: false }
    }

    pub fn fork(&self, parent_tid: i32) -> ProcAttrs {
        ProcAttrs { leader: false, execed: false, parent_tid, adopted: false, subreaper: false, ..self.clone() }
    }
}

/// Per-thread state (Linux keeps these in the task).
#[derive(Clone)]
pub struct ThreadAttrs {
    /// TASK_COMM_LEN - 1 bytes at most.
    pub comm: String,
    pub pdeathsig: u32,
    timer_slack: u64,
    default_slack: u64,
    pub no_new_privs: bool,
    pub seccomp: u32,
    pub filters: u32,
    tagged_addr: u64,
    /// PR_SPEC_STORE_BYPASS state, as PR_GET_SPECULATION_CTRL reports it.
    ssb: u64,
    pub sched: super::sched::Sched,
}

impl Default for ThreadAttrs {
    fn default() -> Self {
        ThreadAttrs {
            comm: String::new(),
            pdeathsig: 0,
            timer_slack: TIMER_SLACK_NS,
            default_slack: TIMER_SLACK_NS,
            no_new_privs: false,
            seccomp: 0,
            filters: 0,
            tagged_addr: 0,
            ssb: PR_SPEC_PRCTL | PR_SPEC_ENABLE,
            sched: Default::default(),
        }
    }
}

impl ThreadAttrs {
    /// A new thread or process: the parent-death signal is never inherited.
    pub fn fork(&self) -> ThreadAttrs {
        ThreadAttrs { pdeathsig: 0, default_slack: self.timer_slack, sched: self.sched.fork(), ..self.clone() }
    }
}

/// /proc/<pid>/comm after execve(path).
pub fn comm_of(path: &str) -> String {
    truncate_comm(path.rsplit('/').next().unwrap_or(""))
}

fn truncate_comm(s: &str) -> String {
    let mut n = s.len().min(15);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

impl Kernel {
    pub(super) fn control_syscall(self: &Arc<Self>, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            prctl => self.sys_prctl(t, a),
            seccomp => self.sys_seccomp(t, a[0], a[1], a[2]),
            getrlimit | setrlimit => {
                let new = if no == setrlimit { Some(self.read_rlimit(t, a[1])?) } else { None };
                let old = self.prlimit(t, 0, a[0], new)?;
                if no == getrlimit {
                    self.write_rlimit(t, a[1], old)?;
                }
                Ok(0)
            }
            prlimit64 => {
                let new = if a[2] != 0 { Some(self.read_rlimit(t, a[2])?) } else { None };
                let old = self.prlimit(t, super::int(a[0]) as i32, a[1], new)?;
                if a[3] != 0 {
                    self.write_rlimit(t, a[3], old)?;
                }
                Ok(0)
            }
            personality => {
                const PER_LINUX32: u32 = 8;
                let p = a[0] as u32;
                let mut attrs = t.proc.attrs.lock().unwrap();
                let old = attrs.personality;
                if p != u32::MAX {
                    if p & 0xff == PER_LINUX32 && self.arch == Arch::Aarch64 {
                        return Err(EINVAL); // no AArch32 at EL0
                    }
                    attrs.personality = p;
                }
                Ok(old as i64)
            }
            sethostname | setdomainname => {
                if !self.creds(t).capable(CAP_SYS_ADMIN) {
                    return Err(EPERM);
                }
                let len = super::int(a[1]);
                if !(0..=64).contains(&len) {
                    return Err(EINVAL);
                }
                let raw = t.proc.mm().read_vec(a[0], len as usize)?;
                let name = String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
                let mut uts = UTS.lock().unwrap();
                *if no == sethostname { &mut uts.0 } else { &mut uts.1 } = name;
                Ok(0)
            }
            reboot => self.sys_reboot(t, a[0] as u32, a[1] as u32, a[2] as u32, a[3]),
            process_vm_readv | process_vm_writev => self.process_vm(t, no == process_vm_writev, super::int(a[0]) as i32, (a[1], a[2]), (a[3], a[4]), a[5]),
            _ => Err(ENOSYS),
        }
    }

    /// A process by pid or by the tid of any of its threads, unless it is a zombie.
    pub(super) fn live_process(&self, id: i32) -> Option<Arc<Process>> {
        self.task(id).map(|th| th.proc.clone())
    }

    /// A live thread by tid.
    pub(super) fn task(&self, tid: i32) -> Option<Arc<Thread>> {
        let procs = self.procs.lock().unwrap();
        let find = |p: &Arc<Process>| p.threads.lock().unwrap().iter().find(|th| th.tid == tid).cloned();
        procs.get(&tid).and_then(find).or_else(|| procs.values().find_map(find))
    }

    /// The process `pid` names for prlimit/capget (0 = the caller).
    fn limit_target(&self, t: &Thread, pid: i32) -> Result<Arc<Process>, i64> {
        if pid == 0 || pid == t.proc.pid {
            return Ok(t.proc.clone());
        }
        if pid < 0 {
            return Err(EINVAL);
        }
        self.live_process(pid).ok_or(ESRCH)
    }

    fn sys_prctl(self: &Arc<Self>, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        const PR_SET_PDEATHSIG: u64 = 1;
        const PR_GET_PDEATHSIG: u64 = 2;
        const PR_GET_DUMPABLE: u64 = 3;
        const PR_SET_DUMPABLE: u64 = 4;
        const PR_SET_NAME: u64 = 15;
        const PR_GET_NAME: u64 = 16;
        const PR_GET_SECCOMP: u64 = 21;
        const PR_SET_SECCOMP: u64 = 22;
        const PR_SET_TIMERSLACK: u64 = 29;
        const PR_GET_TIMERSLACK: u64 = 30;
        const PR_SET_MM: u64 = 35;
        const PR_SET_CHILD_SUBREAPER: u64 = 36;
        const PR_GET_CHILD_SUBREAPER: u64 = 37;
        const PR_SET_NO_NEW_PRIVS: u64 = 38;
        const PR_GET_NO_NEW_PRIVS: u64 = 39;
        const PR_GET_TID_ADDRESS: u64 = 40;
        const PR_SET_THP_DISABLE: u64 = 41;
        const PR_GET_THP_DISABLE: u64 = 42;
        const PR_GET_SPECULATION_CTRL: u64 = 52;
        const PR_SET_SPECULATION_CTRL: u64 = 53;
        const PR_SET_TAGGED_ADDR_CTRL: u64 = 55;
        const PR_GET_TAGGED_ADDR_CTRL: u64 = 56;
        const PR_SET_VMA: u64 = 0x5356_4d41;
        let op = a[0] as u32 as u64;
        let rest = |from: usize| a[from..5].iter().any(|&v| v != 0);
        match op {
            7 | 8 | 23 | 24 | 27 | 28 | 47 => self.cap_prctl(t, op, a),
            PR_SET_PDEATHSIG => {
                if a[1] > 64 {
                    return Err(EINVAL);
                }
                t.attrs.lock().unwrap().pdeathsig = a[1] as u32;
                Ok(0)
            }
            PR_GET_PDEATHSIG => {
                let sig = t.attrs.lock().unwrap().pdeathsig;
                t.proc.mm().write_u32(a[1], sig).map(|_| 0)
            }
            PR_GET_DUMPABLE => Ok(t.proc.attrs.lock().unwrap().dumpable as i64),
            PR_SET_DUMPABLE => {
                if a[1] > 1 {
                    return Err(EINVAL);
                }
                t.proc.attrs.lock().unwrap().dumpable = a[1] as u32;
                Ok(0)
            }
            PR_SET_NAME => {
                let mut name = Vec::new();
                let mut mm = t.proc.mm();
                for i in 0..15 {
                    let mut b = [0u8];
                    mm.read(a[1] + i, &mut b)?;
                    if b[0] == 0 {
                        break;
                    }
                    name.push(b[0]);
                }
                drop(mm);
                t.attrs.lock().unwrap().comm = truncate_comm(&String::from_utf8_lossy(&name));
                Ok(0)
            }
            PR_GET_NAME => {
                let mut b = [0u8; 16];
                let comm = t.attrs.lock().unwrap().comm.clone();
                b[..comm.len().min(15)].copy_from_slice(&comm.as_bytes()[..comm.len().min(15)]);
                t.proc.mm().write(a[1], &b).map(|_| 0)
            }
            PR_GET_SECCOMP => Ok(t.attrs.lock().unwrap().seccomp as i64),
            PR_SET_SECCOMP => match a[1] {
                1 => self.sys_seccomp(t, 0, 0, 0),
                2 => self.sys_seccomp(t, 1, 0, a[2]),
                _ => Err(EINVAL),
            },
            PR_SET_TIMERSLACK => {
                let mut ta = t.attrs.lock().unwrap();
                ta.timer_slack = if a[1] == 0 { ta.default_slack } else { a[1] };
                Ok(0)
            }
            PR_GET_TIMERSLACK => Ok(t.attrs.lock().unwrap().timer_slack as i64),
            PR_SET_MM => Err(EPERM),
            PR_SET_CHILD_SUBREAPER => {
                t.proc.attrs.lock().unwrap().subreaper = a[1] != 0;
                Ok(0)
            }
            PR_GET_CHILD_SUBREAPER => {
                let v = t.proc.attrs.lock().unwrap().subreaper as u32;
                t.proc.mm().write_u32(a[1], v).map(|_| 0)
            }
            PR_SET_NO_NEW_PRIVS => {
                if a[1] != 1 || rest(2) {
                    return Err(EINVAL);
                }
                t.attrs.lock().unwrap().no_new_privs = true;
                Ok(0)
            }
            PR_GET_NO_NEW_PRIVS => {
                if rest(1) {
                    return Err(EINVAL);
                }
                Ok(t.attrs.lock().unwrap().no_new_privs as i64)
            }
            PR_GET_TID_ADDRESS => {
                let addr = t.clear_child_tid.load(std::sync::atomic::Ordering::Relaxed);
                t.proc.mm().write_u64(a[1], addr).map(|_| 0)
            }
            PR_SET_THP_DISABLE | PR_GET_THP_DISABLE => {
                if rest(if op == PR_GET_THP_DISABLE { 1 } else { 2 }) {
                    return Err(EINVAL);
                }
                let mut pa = t.proc.attrs.lock().unwrap();
                if op == PR_SET_THP_DISABLE {
                    pa.thp_disable = a[1] != 0;
                }
                Ok(if op == PR_GET_THP_DISABLE { pa.thp_disable as i64 } else { 0 })
            }
            PR_GET_SPECULATION_CTRL | PR_SET_SPECULATION_CTRL => self.speculation_ctrl(t, op == PR_SET_SPECULATION_CTRL, a),
            PR_SET_TAGGED_ADDR_CTRL | PR_GET_TAGGED_ADDR_CTRL => {
                const PR_TAGGED_ADDR_ENABLE: u64 = 1;
                if self.arch != Arch::Aarch64 || rest(2) || (op == PR_GET_TAGGED_ADDR_CTRL && a[1] != 0) {
                    return Err(EINVAL);
                }
                let mut ta = t.attrs.lock().unwrap();
                if op == PR_GET_TAGGED_ADDR_CTRL {
                    return Ok(ta.tagged_addr as i64);
                }
                // No MTE: only the tagged-address ABI itself (TBI) can be enabled.
                if a[1] & !PR_TAGGED_ADDR_ENABLE != 0 {
                    return Err(EINVAL);
                }
                ta.tagged_addr = a[1];
                Ok(0)
            }
            PR_SET_VMA => Ok(0),
            _ => Err(EINVAL),
        }
    }

    fn speculation_ctrl(&self, t: &Thread, set: bool, a: [u64; 6]) -> Result<i64, i64> {
        const PR_SPEC_STORE_BYPASS: u64 = 0;
        if a[3] | a[4] != 0 || (!set && a[2] != 0) {
            return Err(EINVAL);
        }
        match a[1] {
            PR_SPEC_STORE_BYPASS => {}
            1 | 2 if self.arch == Arch::X86_64 => return if set { Err(ENXIO) } else { Ok(0) }, // not affected
            _ => return Err(ENODEV),
        }
        let mut ta = t.attrs.lock().unwrap();
        if !set {
            return Ok(ta.ssb as i64);
        }
        let forced = ta.ssb & PR_SPEC_FORCE_DISABLE != 0;
        ta.ssb = PR_SPEC_PRCTL
            | match a[2] {
                PR_SPEC_ENABLE | PR_SPEC_DISABLE_NOEXEC if forced => return Err(EPERM),
                PR_SPEC_ENABLE | PR_SPEC_DISABLE_NOEXEC => a[2],
                PR_SPEC_DISABLE if forced => PR_SPEC_FORCE_DISABLE,
                PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE => a[2],
                _ => return Err(ERANGE),
            };
        Ok(0)
    }

    /// seccomp(2). Filters are validated and recorded, never run: nothing
    /// in Android depends on them to function (zygote installs one for apps).
    fn sys_seccomp(&self, t: &Thread, op: u64, flags: u64, uargs: u64) -> Result<i64, i64> {
        const SET_MODE_STRICT: u64 = 0;
        const SET_MODE_FILTER: u64 = 1;
        const GET_ACTION_AVAIL: u64 = 2;
        const GET_NOTIF_SIZES: u64 = 3;
        const FLAG_TSYNC: u64 = 1;
        const FLAG_NEW_LISTENER: u64 = 8;
        const FLAGS_ALL: u64 = 0x3f;
        const BPF_MAXINSNS: u64 = 4096;
        match op {
            SET_MODE_STRICT | SET_MODE_FILTER => {
                let mode = op as u32 + 1;
                if op == SET_MODE_STRICT && (flags != 0 || uargs != 0) || flags & !FLAGS_ALL != 0 {
                    return Err(EINVAL);
                }
                if op == SET_MODE_FILTER {
                    let (len, ptr) = {
                        let mut mm = t.proc.mm();
                        let len = mm.read_vec(uargs, 2)?;
                        (u16::from_le_bytes([len[0], len[1]]) as u64, mm.read_u64(uargs + 8)?)
                    };
                    if len == 0 || len > BPF_MAXINSNS {
                        return Err(EINVAL);
                    }
                    t.proc.mm().read_vec(ptr, len as usize * 8)?;
                    let nnp = t.attrs.lock().unwrap().no_new_privs;
                    if !nnp && !self.creds(t).capable(CAP_SYS_ADMIN) {
                        return Err(EACCES);
                    }
                    if flags & FLAG_NEW_LISTENER != 0 {
                        return Err(EINVAL); // no user-space notification fds
                    }
                }
                let cur = t.attrs.lock().unwrap().seccomp;
                if cur != 0 && cur != mode {
                    return Err(EINVAL);
                }
                let threads: Vec<Arc<Thread>> =
                    if flags & FLAG_TSYNC != 0 { t.proc.threads.lock().unwrap().clone() } else { t.proc.threads.lock().unwrap().iter().filter(|x| x.tid == t.tid).cloned().collect() };
                for th in threads {
                    let mut ta = th.attrs.lock().unwrap();
                    ta.seccomp = mode;
                    ta.filters += (op == SET_MODE_FILTER) as u32;
                }
                Ok(0)
            }
            GET_ACTION_AVAIL => {
                if flags != 0 {
                    return Err(EINVAL);
                }
                let action = t.proc.mm().read_u32(uargs)?;
                // KILL_PROCESS, KILL_THREAD, TRAP, ERRNO, USER_NOTIF, TRACE, LOG, ALLOW
                if [0x8000_0000, 0, 0x0003_0000, 0x0005_0000, 0x7fc0_0000, 0x7ff0_0000, 0x7ffc_0000, 0x7fff_0000].contains(&action) { Ok(0) } else { Err(EOPNOTSUPP) }
            }
            GET_NOTIF_SIZES => {
                if flags != 0 {
                    return Err(EINVAL);
                }
                let sizes: Vec<u8> = [80u16, 24, 64].iter().flat_map(|v| v.to_le_bytes()).collect();
                t.proc.mm().write(uargs, &sizes).map(|_| 0)
            }
            _ => Err(EINVAL),
        }
    }

    fn read_rlimit(&self, t: &Thread, at: u64) -> Result<(u64, u64), i64> {
        let mut mm = t.proc.mm();
        Ok((mm.read_u64(at)?, mm.read_u64(at + 8)?))
    }

    fn write_rlimit(&self, t: &Thread, at: u64, (cur, max): (u64, u64)) -> Result<(), i64> {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&cur.to_le_bytes());
        b[8..].copy_from_slice(&max.to_le_bytes());
        t.proc.mm().write(at, &b)
    }

    /// do_prlimit: returns the old limit, installing `new` if given.
    fn prlimit(&self, t: &Thread, pid: i32, res: u64, new: Option<(u64, u64)>) -> Result<(u64, u64), i64> {
        if res >= RLIM_NLIMITS {
            return Err(EINVAL);
        }
        if let Some((cur, max)) = new {
            if cur > max {
                return Err(EINVAL);
            }
            if res as usize == RLIMIT_NOFILE && max > NR_OPEN {
                return Err(EPERM);
            }
        }
        let target = self.limit_target(t, pid)?;
        let me = self.creds(t);
        if !Arc::ptr_eq(&target, &t.proc) {
            let c = target.creds.lock().unwrap().clone();
            let same = [c.uid, c.euid, c.suid].iter().all(|&u| u == me.uid) && [c.gid, c.egid, c.sgid].iter().all(|&g| g == me.gid);
            if !same && !me.capable(CAP_SYS_RESOURCE) {
                return Err(EPERM);
            }
        }
        let mut attrs = target.attrs.lock().unwrap();
        let slot = &mut attrs.limits[res as usize];
        let old = *slot;
        if let Some(lim) = new {
            if lim.1 > old.1 && !me.capable(CAP_SYS_RESOURCE) {
                return Err(EPERM);
            }
            *slot = lim;
            drop(attrs);
            if res as usize == RLIMIT_NOFILE {
                target.files.lock().unwrap().set_limit(lim.0.min(NR_OPEN) as usize);
            }
        }
        Ok(old)
    }

    fn sys_reboot(&self, t: &Thread, magic1: u32, magic2: u32, cmd: u32, arg: u64) -> Result<i64, i64> {
        const CMD_RESTART: u32 = 0x0123_4567;
        const CMD_HALT: u32 = 0xcdef_0123;
        const CMD_CAD_ON: u32 = 0x89ab_cdef;
        const CMD_CAD_OFF: u32 = 0;
        const CMD_POWER_OFF: u32 = 0x4321_fedc;
        const CMD_RESTART2: u32 = 0xa1b2_c3d4;
        const CMD_KEXEC: u32 = 0x4558_4543;
        if !self.creds(t).capable(CAP_SYS_BOOT) {
            return Err(EPERM);
        }
        if magic1 != 0xfee1_dead || ![0x2812_1969, 0x0512_1996, 0x1604_1998, 0x2011_2000].contains(&magic2) {
            return Err(EINVAL);
        }
        let (what, code, reason) = match cmd {
            CMD_CAD_ON | CMD_CAD_OFF => return Ok(0),
            CMD_POWER_OFF | CMD_HALT => ("power off", 0, String::new()),
            CMD_RESTART | CMD_KEXEC => ("reboot", 1, String::new()),
            CMD_RESTART2 => {
                let mut mm = t.proc.mm();
                let mut s = Vec::new();
                for i in 0..255 {
                    let mut b = [0u8];
                    mm.read(arg + i, &mut b).map_err(|_| EFAULT)?;
                    if b[0] == 0 {
                        break;
                    }
                    s.push(b[0]);
                }
                ("reboot", 1, format!(": {}", String::from_utf8_lossy(&s)))
            }
            _ => return Err(EINVAL),
        };
        eprintln!("[droidrt] {what} requested by pid {}{reason}", t.proc.pid);
        {
            let (lock, cv) = &self.exit;
            lock.lock().unwrap().get_or_insert(code << 8);
            cv.notify_all();
        }
        // Like the real thing, reboot does not return: droidrt exits under us.
        loop {
            std::thread::park();
        }
    }

    /// process_vm_readv/writev: copies between our iovecs and another
    /// address space (or our own). A fault ends the transfer early.
    fn process_vm(&self, t: &Thread, write: bool, pid: i32, local: (u64, u64), remote: (u64, u64), flags: u64) -> Result<i64, i64> {
        if flags != 0 || local.1 > IOV_MAX || remote.1 > IOV_MAX {
            return Err(EINVAL);
        }
        let (liov, riov) = {
            let mut mm = t.proc.mm();
            let mut iovs = |(at, n): (u64, u64)| -> Result<Vec<(u64, u64)>, i64> { (0..n).map(|i| Ok((mm.read_u64(at + i * 16)?, mm.read_u64(at + i * 16 + 8)?))).collect() };
            (iovs(local)?, iovs(remote)?)
        };
        let target = self.live_process(pid).ok_or(ESRCH)?;
        if !Arc::ptr_eq(&target, &t.proc) {
            let me = self.creds(t);
            let c = target.creds.lock().unwrap().clone();
            if !me.capable(CAP_SYS_PTRACE) && !(me.same_real_ids(&c) && target.attrs.lock().unwrap().dumpable == 1) {
                return Err(EPERM);
            }
        }
        let mut done = 0u64;
        let (mut li, mut loff) = (0, 0);
        let mut failed = false;
        'outer: for &(raddr, rlen) in &riov {
            let mut roff = 0;
            while roff < rlen {
                while li < liov.len() && loff == liov[li].1 {
                    li += 1;
                    loff = 0;
                }
                let Some(&(laddr, llen)) = liov.get(li) else { break 'outer };
                let n = (rlen - roff).min(llen - loff).min(VM_CHUNK);
                let (from, to) = if write { ((&t.proc, laddr + loff), (&target, raddr + roff)) } else { ((&target, raddr + roff), (&t.proc, laddr + loff)) };
                // Two statements: the two address spaces may be the same one.
                let data = from.0.mm.lock().unwrap().as_mut().ok_or(ESRCH).and_then(|mm| mm.read_vec(from.1, n as usize));
                let ok = data.and_then(|d| to.0.mm.lock().unwrap().as_mut().ok_or(ESRCH).and_then(|mm| mm.write(to.1, &d)));
                if ok.is_err() {
                    failed = true;
                    break 'outer;
                }
                done += n;
                roff += n;
                loff += n;
            }
        }
        if done == 0 && failed { Err(EFAULT) } else { Ok(done as i64) }
    }

    /// execve's effect on identity and per-thread state (no file caps, no set-id bits).
    pub(super) fn exec_attrs(&self, t: &Thread, path: &str) {
        let same = {
            let mut c = t.proc.creds.lock().unwrap();
            c.exec();
            c.euid == c.uid && c.egid == c.gid
        };
        {
            let mut pa = t.proc.attrs.lock().unwrap();
            pa.execed = true;
            pa.dumpable = same as u32;
        }
        let mut ta = t.attrs.lock().unwrap();
        ta.comm = comm_of(path);
        ta.tagged_addr = 0;
        if ta.ssb & PR_SPEC_DISABLE_NOEXEC != 0 {
            ta.ssb = PR_SPEC_PRCTL | PR_SPEC_ENABLE;
        }
    }
}
