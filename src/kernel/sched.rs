//! Scheduling attributes: nice values, policies and real-time priorities,
//! utilization clamps, and I/O priorities. Validated with Linux's rules and
//! stored per thread (Linux keeps them per task), so they read back; the
//! host scheduler is not told.

use super::control::{RLIMIT_NICE, RLIMIT_RTPRIO};
use super::creds::{CAP_SYS_ADMIN, CAP_SYS_NICE, Creds};
use super::{Kernel, Thread};
use crate::arch::Sysno;
use crate::errno::*;
use std::sync::Arc;

const SCHED_OTHER: u32 = 0;
const SCHED_FIFO: u32 = 1;
const SCHED_RR: u32 = 2;
const SCHED_BATCH: u32 = 3;
const SCHED_IDLE: u32 = 5;
const SCHED_DEADLINE: u32 = 6;
const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;
const FLAG_RESET_ON_FORK: u64 = 0x01;
const FLAG_KEEP_POLICY: u64 = 0x08;
const FLAG_KEEP_PARAMS: u64 = 0x10;
const FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
const FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
const FLAGS_ALL: u64 = 0x7f;
const ATTR_SIZE_VER0: u32 = 48;
/// sizeof(struct sched_attr) with utilization clamps (SCHED_ATTR_SIZE_VER1).
const ATTR_SIZE: u32 = 56;
const UCLAMP_MAX: u32 = 1024;
const IOPRIO_CLASS_NONE: u32 = 0;
const IOPRIO_CLASS_RT: u32 = 1;
const IOPRIO_CLASS_BE: u32 = 2;
const IOPRIO_CLASS_IDLE: u32 = 3;

#[derive(Clone, Debug)]
pub struct Sched {
    pub nice: i32,
    pub policy: u32,
    pub prio: u32,
    reset_on_fork: bool,
    util: (u32, u32),
    /// SCHED_DEADLINE runtime, deadline, period (ns).
    dl: (u64, u64, u64),
    ioprio: u32,
}

impl Default for Sched {
    fn default() -> Self {
        Sched { nice: 0, policy: SCHED_OTHER, prio: 0, reset_on_fork: false, util: (0, UCLAMP_MAX), dl: (0, 0, 0), ioprio: 0 }
    }
}

impl Sched {
    /// sched_fork: SCHED_RESET_ON_FORK children start as plain SCHED_OTHER.
    pub fn fork(&self) -> Sched {
        let mut s = self.clone();
        if s.reset_on_fork {
            if rt_or_dl(s.policy) {
                (s.policy, s.prio, s.nice, s.dl) = (SCHED_OTHER, 0, 0, (0, 0, 0));
            }
            s.nice = s.nice.max(0);
            s.reset_on_fork = false;
        }
        s
    }

    /// The "priority" field of /proc/<pid>/stat.
    pub fn proc_priority(&self) -> i32 {
        if rt(self.policy) { -1 - self.prio as i32 } else { 20 + self.nice }
    }
}

fn rt(policy: u32) -> bool {
    policy == SCHED_FIFO || policy == SCHED_RR
}

fn rt_or_dl(policy: u32) -> bool {
    rt(policy) || policy == SCHED_DEADLINE
}

fn fair(policy: u32) -> bool {
    matches!(policy, SCHED_OTHER | SCHED_BATCH | SCHED_IDLE)
}

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        setpriority | getpriority | sched_setscheduler | sched_getscheduler | sched_setparam | sched_getparam | sched_setattr | sched_getattr
            | sched_get_priority_max | sched_get_priority_min | sched_rr_get_interval | ioprio_set | ioprio_get
    )
}

/// What a sched_setattr-style request asks for.
struct Attr {
    policy: Option<u32>,
    flags: u64,
    nice: Option<i32>,
    prio: u32,
    dl: (u64, u64, u64),
    util: (u32, u32),
}

impl Kernel {
    pub(super) fn sched_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        let pid = super::int(a[0]) as i32;
        match no {
            setpriority | getpriority => {
                let targets = self.prio_targets(t, a[0], super::int(a[1]) as i32)?;
                if targets.is_empty() {
                    return Err(ESRCH);
                }
                if no == getpriority {
                    return Ok(targets.iter().map(|th| 20 - th.attrs.lock().unwrap().sched.nice).max().unwrap_or(0) as i64);
                }
                let nice = (super::int(a[2]) as i32).clamp(-20, 19);
                let me = self.creds(t);
                let mut err = None;
                for th in targets {
                    let c = th.proc.creds.lock().unwrap().clone();
                    let nice_limit = th.proc.attrs.lock().unwrap().limits[RLIMIT_NICE].0;
                    let mut ta = th.attrs.lock().unwrap();
                    if me.euid != c.uid && me.euid != c.euid && !me.capable(CAP_SYS_NICE) {
                        err = Some(EPERM);
                    } else if nice < ta.sched.nice && (20 - nice) as u64 > nice_limit && !me.capable(CAP_SYS_NICE) {
                        err = Some(EACCES);
                    } else {
                        ta.sched.nice = nice;
                    }
                }
                err.map_or(Ok(0), Err)
            }
            sched_get_priority_max | sched_get_priority_min => match a[0] as u32 {
                SCHED_FIFO | SCHED_RR => Ok(if no == sched_get_priority_max { 99 } else { 1 }),
                SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
                _ => Err(EINVAL),
            },
            sched_getscheduler => {
                let s = self.sched_target(t, pid)?.attrs.lock().unwrap().sched.clone();
                Ok((s.policy | if s.reset_on_fork { SCHED_RESET_ON_FORK } else { 0 }) as i64)
            }
            sched_getparam => {
                if a[1] == 0 {
                    return Err(EINVAL);
                }
                let prio = self.sched_target(t, pid)?.attrs.lock().unwrap().sched.prio;
                t.proc.mm().write_u32(a[1], prio).map(|_| 0)
            }
            sched_setscheduler | sched_setparam => {
                let policy = if no == sched_setscheduler { Some(super::int(a[1]) as i32) } else { None };
                let param = if no == sched_setscheduler { a[2] } else { a[1] };
                if param == 0 || policy.is_some_and(|p| p < 0) {
                    return Err(EINVAL);
                }
                let th = self.sched_target(t, pid)?;
                let prio = t.proc.mm().read_u32(param)?;
                let policy = policy.map(|p| p as u32);
                let flags = if policy.is_some_and(|p| p & SCHED_RESET_ON_FORK != 0) { FLAG_RESET_ON_FORK } else { 0 };
                let keep_reset = policy.is_none() && th.attrs.lock().unwrap().sched.reset_on_fork;
                let attr = Attr { policy: policy.map(|p| p & !SCHED_RESET_ON_FORK), flags: flags | if keep_reset { FLAG_RESET_ON_FORK } else { 0 }, nice: None, prio, dl: (0, 0, 0), util: (0, 0) };
                self.set_sched(t, &th, attr)
            }
            sched_setattr => {
                if a[1] == 0 || pid < 0 || a[2] != 0 {
                    return Err(EINVAL);
                }
                let raw = self.read_sched_attr(t, a[1])?;
                let w32 = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
                let w64 = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                let (policy, flags) = (w32(4), w64(8));
                if (policy as i32) < 0 {
                    return Err(EINVAL);
                }
                let th = self.sched_target(t, pid)?;
                let nice = (w32(16) as i32).clamp(-20, 19);
                let attr = Attr {
                    policy: if flags & FLAG_KEEP_POLICY != 0 { None } else { Some(policy) },
                    flags,
                    nice: Some(nice),
                    prio: w32(20),
                    dl: (w64(24), w64(32), w64(40)),
                    util: (w32(48), w32(52)),
                };
                self.set_sched(t, &th, attr)
            }
            sched_getattr => {
                let size = a[2] as u32;
                if a[1] == 0 || pid < 0 || !(ATTR_SIZE_VER0..=4096).contains(&size) || a[3] != 0 {
                    return Err(EINVAL);
                }
                let s = self.sched_target(t, pid)?.attrs.lock().unwrap().sched.clone();
                let mut b = vec![0u8; ATTR_SIZE as usize];
                let n = size.min(ATTR_SIZE);
                b[0..4].copy_from_slice(&n.to_le_bytes());
                b[4..8].copy_from_slice(&s.policy.to_le_bytes());
                b[8..16].copy_from_slice(&(if s.reset_on_fork { FLAG_RESET_ON_FORK } else { 0 }).to_le_bytes());
                if fair(s.policy) {
                    b[16..20].copy_from_slice(&s.nice.to_le_bytes());
                }
                b[20..24].copy_from_slice(&s.prio.to_le_bytes());
                if s.policy == SCHED_DEADLINE {
                    b[24..32].copy_from_slice(&s.dl.0.to_le_bytes());
                    b[32..40].copy_from_slice(&s.dl.1.to_le_bytes());
                    b[40..48].copy_from_slice(&s.dl.2.to_le_bytes());
                }
                b[48..52].copy_from_slice(&s.util.0.to_le_bytes());
                b[52..56].copy_from_slice(&s.util.1.to_le_bytes());
                t.proc.mm().write(a[1], &b[..n as usize]).map(|_| 0)
            }
            sched_rr_get_interval => {
                if pid < 0 {
                    return Err(EINVAL);
                }
                let policy = self.sched_target(t, pid)?.attrs.lock().unwrap().sched.policy;
                // RR_TIMESLICE is 100 ms; FIFO has none; fair tasks get a few ms.
                let ns: u64 = match policy {
                    SCHED_RR => 100_000_000,
                    SCHED_FIFO => 0,
                    _ => 4_000_000,
                };
                let mut b = [0u8; 16];
                b[8..].copy_from_slice(&ns.to_le_bytes());
                t.proc.mm().write(a[1], &b).map(|_| 0)
            }
            ioprio_set | ioprio_get => {
                if !(1..=3).contains(&a[0]) {
                    return Err(EINVAL);
                }
                let targets = self.prio_targets(t, a[0] - 1, super::int(a[1]) as i32)?;
                if no == ioprio_set {
                    let ioprio = a[2] as u32;
                    let (class, level) = (ioprio >> 13 & 7, ioprio & 7);
                    let me = self.creds(t);
                    match class {
                        IOPRIO_CLASS_RT if !me.capable(CAP_SYS_ADMIN) && !me.capable(CAP_SYS_NICE) => return Err(EPERM),
                        IOPRIO_CLASS_RT | IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => {}
                        IOPRIO_CLASS_NONE if level == 0 => {}
                        _ => return Err(EINVAL),
                    }
                    if targets.is_empty() {
                        return Err(ESRCH);
                    }
                    for th in targets {
                        let c = th.proc.creds.lock().unwrap().clone();
                        if c.uid != me.euid && c.uid != me.uid && !me.capable(CAP_SYS_NICE) {
                            return Err(EPERM);
                        }
                        th.attrs.lock().unwrap().sched.ioprio = ioprio;
                    }
                    return Ok(0);
                }
                // ioprio_best: the highest priority, "none" counting as best-effort level 4.
                let best = |p: u32| if p >> 13 == IOPRIO_CLASS_NONE { IOPRIO_CLASS_BE << 13 | 4 } else { p };
                let prios: Vec<u32> = targets.iter().map(|th| th.attrs.lock().unwrap().sched.ioprio).collect();
                match prios.as_slice() {
                    [] => Err(ESRCH),
                    [one] => Ok(*one as i64),
                    many => Ok(many.iter().copied().min_by_key(|&p| best(p)).unwrap() as i64),
                }
            }
            _ => Err(ENOSYS),
        }
    }

    /// The thread a sched_* call names (0 = the caller).
    fn sched_target(&self, t: &Arc<Thread>, pid: i32) -> Result<Arc<Thread>, i64> {
        match pid {
            0 => Ok(t.clone()),
            p if p < 0 => Err(EINVAL),
            p => self.task(p).ok_or(ESRCH),
        }
    }

    /// The threads setpriority/ioprio_set address: PRIO_PROCESS (a thread),
    /// PRIO_PGRP (every thread in a process group), PRIO_USER (by real uid).
    fn prio_targets(&self, t: &Arc<Thread>, which: u64, who: i32) -> Result<Vec<Arc<Thread>>, i64> {
        let all = |keep: &dyn Fn(&super::Process) -> bool| -> Vec<Arc<Thread>> {
            let procs: Vec<_> = self.procs.lock().unwrap().values().cloned().collect();
            procs.iter().filter(|p| keep(p)).flat_map(|p| p.threads.lock().unwrap().clone()).collect()
        };
        match which {
            0 => Ok(if who == 0 { vec![t.clone()] } else { self.task(who).into_iter().collect() }),
            1 => {
                let pgid = if who == 0 { t.proc.attrs.lock().unwrap().pgid } else { who };
                Ok(all(&|p| p.attrs.lock().unwrap().pgid == pgid))
            }
            2 => {
                let uid = if who == 0 { self.creds(t).uid } else { who as u32 };
                Ok(all(&|p| p.creds.lock().unwrap().uid == uid))
            }
            _ => Err(EINVAL),
        }
    }

    /// sched_copy_attr: sizes from 48 bytes to a page; unknown trailing bytes must be zero.
    fn read_sched_attr(&self, t: &Thread, at: u64) -> Result<Vec<u8>, i64> {
        let mut mm = t.proc.mm();
        let size = match mm.read_u32(at)? {
            0 => ATTR_SIZE_VER0,
            s => s,
        };
        let too_big = |mm: &mut crate::mm::AddressSpace| mm.write_u32(at, ATTR_SIZE).and(Err(E2BIG));
        if !(ATTR_SIZE_VER0..=4096).contains(&size) {
            return too_big(&mut mm);
        }
        let mut raw = mm.read_vec(at, size as usize)?;
        if raw.len() > ATTR_SIZE as usize && raw[ATTR_SIZE as usize..].iter().any(|&b| b != 0) {
            return too_big(&mut mm);
        }
        let flags = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        if flags & (FLAG_UTIL_CLAMP_MIN | FLAG_UTIL_CLAMP_MAX) != 0 && size < ATTR_SIZE {
            return Err(EINVAL);
        }
        raw.resize(ATTR_SIZE as usize, 0);
        Ok(raw)
    }

    /// __sched_setscheduler with its validity and permission checks.
    fn set_sched(&self, t: &Thread, th: &Thread, attr: Attr) -> Result<i64, i64> {
        if attr.flags & !FLAGS_ALL != 0 {
            return Err(EINVAL);
        }
        let me: Creds = self.creds(t);
        let c = th.proc.creds.lock().unwrap().clone();
        let limits = th.proc.attrs.lock().unwrap().limits;
        let mut ta = th.attrs.lock().unwrap();
        let cur = ta.sched.clone();
        let policy = attr.policy.unwrap_or(cur.policy);
        if !matches!(policy, SCHED_OTHER | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE) {
            return Err(EINVAL);
        }
        let keep_params = attr.flags & FLAG_KEEP_PARAMS != 0;
        let (prio, nice, dl) = if keep_params { (cur.prio, cur.nice, cur.dl) } else { (attr.prio, attr.nice.unwrap_or(cur.nice), attr.dl) };
        if prio > 99 || rt(policy) != (prio != 0) {
            return Err(EINVAL);
        }
        if policy == SCHED_DEADLINE && !keep_params {
            let (runtime, deadline, period) = dl;
            let period = if period == 0 { deadline } else { period };
            if deadline == 0 || runtime < 1024 || (deadline | period) >> 63 != 0 || period < deadline || deadline < runtime {
                return Err(EINVAL);
            }
        }
        let mut util = cur.util;
        for (bit, slot, v) in [(FLAG_UTIL_CLAMP_MIN, 0, attr.util.0), (FLAG_UTIL_CLAMP_MAX, 1, attr.util.1)] {
            if attr.flags & bit != 0 {
                let v = if v == u32::MAX { [0, UCLAMP_MAX][slot] } else { v };
                if v > UCLAMP_MAX {
                    return Err(EINVAL);
                }
                if slot == 0 { util.0 = v } else { util.1 = v }
            }
        }
        if util.0 > util.1 {
            return Err(EINVAL);
        }
        let reset_on_fork = attr.flags & FLAG_RESET_ON_FORK != 0;
        if !me.capable(CAP_SYS_NICE) {
            let nice_ok = |n: i32| (20 - n) as u64 <= limits[RLIMIT_NICE].0;
            let rtprio = limits[RLIMIT_RTPRIO].0;
            let denied = (fair(policy) && nice < cur.nice && !nice_ok(nice))
                || (rt(policy) && ((policy != cur.policy && rtprio == 0) || (prio > cur.prio && prio as u64 > rtprio)))
                || policy == SCHED_DEADLINE
                || (cur.policy == SCHED_IDLE && policy != SCHED_IDLE && !nice_ok(cur.nice))
                || (me.euid != c.euid && me.euid != c.uid)
                || (cur.reset_on_fork && !reset_on_fork);
            if denied {
                return Err(EPERM);
            }
        }
        let s = &mut ta.sched;
        (s.policy, s.prio, s.reset_on_fork, s.util) = (policy, prio, reset_on_fork, util);
        if fair(policy) {
            s.nice = nice;
        }
        if policy == SCHED_DEADLINE {
            s.dl = dl;
        }
        Ok(0)
    }
}
