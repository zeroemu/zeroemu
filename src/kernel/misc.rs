//! Time, system information, affinity, and other small syscalls.

use super::{IDLE, Kernel, Thread};
use crate::arch::{Arch, Sysno};
use crate::errno::*;
use crate::hv::Vcpu;
use crate::phys;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ARCH_SET_FS: u64 = 0x1002;

impl Kernel {
    pub(super) fn misc_syscall(&self, no: Sysno, t: &Thread, vcpu: &mut dyn Vcpu, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            uname => {
                let machine = match self.arch {
                    Arch::Aarch64 => "aarch64",
                    Arch::X86_64 => "x86_64",
                };
                let mut out = [0u8; 65 * 6];
                let (host, domain) = (self.sysctl.get("kernel/hostname"), self.sysctl.get("kernel/domainname"));
                for (i, f) in ["Linux", &host, "6.6.0-zeroemu", "#1 SMP PREEMPT zeroemu", machine, &domain].iter().enumerate() {
                    let n = f.len().min(64);
                    out[i * 65..i * 65 + n].copy_from_slice(&f.as_bytes()[..n]);
                }
                t.proc.mm().write(a[0], &out)?;
                Ok(0)
            }
            clock_gettime => {
                let (s, ns) = match self.cpu_clock(t, a[0] as i32) {
                    Some(d) => {
                        let d = d?;
                        (d.as_secs(), d.subsec_nanos() as u64)
                    }
                    None => self.clock(a[0]),
                };
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&s.to_le_bytes());
                b[8..].copy_from_slice(&ns.to_le_bytes());
                t.proc.mm().write(a[1], &b)?;
                Ok(0)
            }
            clock_getres => {
                if a[1] != 0 {
                    let mut b = [0u8; 16];
                    b[8..].copy_from_slice(&1u64.to_le_bytes());
                    t.proc.mm().write(a[1], &b)?;
                }
                Ok(0)
            }
            gettimeofday => {
                if a[0] != 0 {
                    let (s, ns) = self.clock(0);
                    let mut b = [0u8; 16];
                    b[..8].copy_from_slice(&s.to_le_bytes());
                    b[8..].copy_from_slice(&(ns / 1000).to_le_bytes());
                    t.proc.mm().write(a[0], &b)?;
                }
                Ok(0)
            }
            nanosleep | clock_nanosleep => {
                const TIMER_ABSTIME: u64 = 1;
                let (req, abs, clock, rem) = if no == nanosleep { (a[0], false, 1, a[1]) } else { (a[2], a[1] & TIMER_ABSTIME != 0, a[0], a[3]) };
                let (s, ns) = {
                    let mut mm = t.proc.mm();
                    (mm.read_u64(req)?, mm.read_u64(req + 8)?)
                };
                let d = super::wait::guest_timespec(s, ns)?;
                if no == clock_nanosleep
                    && let Some(now) = self.cpu_clock(t, clock as i32)
                {
                    // A CPU-time clock: a thread's can't be slept on (Linux says EINVAL);
                    // a process's is slept on until it has used that much.
                    let now = now?;
                    if clock == 3 || (clock as i32) < 0 && clock as i32 & 4 != 0 {
                        return Err(EINVAL);
                    }
                    let target = if abs { d } else { now + d };
                    loop {
                        let used = self.cpu_clock(t, clock as i32).unwrap_or(Ok(target))?;
                        if used >= target {
                            return Ok(0);
                        }
                        if t.interrupted() {
                            return Err(EINTR);
                        }
                        super::vcpus::blocking();
                        t.nap((target - used).min(IDLE));
                    }
                }
                let deadline = if abs {
                    let (now_s, now_ns) = self.clock(clock);
                    super::wait::instant_after(d.saturating_sub(Duration::new(now_s, now_ns as u32)))
                } else {
                    super::wait::instant_after(d)
                };
                while Instant::now() < deadline {
                    if t.interrupted() {
                        // What is left of a relative sleep, for the caller to sleep again:
                        // `while (nanosleep(&ts, &ts) == -1 && errno == EINTR)` counts on it.
                        if !abs && rem != 0 {
                            let left = deadline.saturating_duration_since(Instant::now());
                            let mut b = [0u8; 16];
                            b[..8].copy_from_slice(&left.as_secs().to_le_bytes());
                            b[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_le_bytes());
                            t.proc.mm().write(rem, &b)?;
                        }
                        return Err(EINTR);
                    }
                    super::vcpus::blocking();
                    t.nap(deadline.saturating_duration_since(Instant::now()).min(IDLE));
                }
                Ok(0)
            }
            getrandom => {
                let mut buf = vec![0u8; a[1].min(1 << 20) as usize];
                phys::random_bytes(&mut buf);
                t.proc.mm().write(a[0], &buf)?;
                Ok(buf.len() as i64)
            }
            sched_yield | sched_setaffinity => Ok(0),
            sched_getaffinity => {
                // One CPU per vCPU slot would be truthful; report the host's
                // core count so thread pools size themselves sensibly.
                let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
                let mut mask = [0u8; 8];
                for i in 0..cpus {
                    mask[i / 8] |= 1 << (i % 8);
                }
                let len = a[1].min(8) as usize;
                t.proc.mm().write(a[2], &mask[..len])?;
                Ok(len as i64)
            }
            getrusage => {
                const RUSAGE_SELF: i32 = 0;
                const RUSAGE_CHILDREN: i32 = -1;
                const RUSAGE_THREAD: i32 = 1;
                let ns = match a[0] as i32 {
                    RUSAGE_SELF => t.proc.cpu_ns(),
                    RUSAGE_CHILDREN => t.proc.cpu_children.load(std::sync::atomic::Ordering::Relaxed),
                    RUSAGE_THREAD => t.cpu_ns(),
                    _ => return Err(EINVAL),
                };
                let rss_kb = t.proc.mm.lock().unwrap().as_ref().map_or(0, |m| m.usage().1 / 1024);
                t.proc.mm().write(a[1], &rusage(ns, rss_kb)).map(|_| 0)
            }
            sysinfo => {
                let mut b = [0u8; 112];
                b[0..8].copy_from_slice(&self.boot.elapsed().as_secs().to_le_bytes());
                b[32..40].copy_from_slice(&phys::ram().to_le_bytes()); // totalram
                b[40..48].copy_from_slice(&phys::ram().saturating_sub(self.phys.frames_in_use() * phys::PAGE).to_le_bytes());
                b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
                t.proc.mm().write(a[0], &b)?;
                Ok(0)
            }
            arch_prctl => {
                if a[0] != ARCH_SET_FS {
                    return Err(EINVAL);
                }
                let mut st = vcpu.state();
                st.set_tls(a[1]);
                vcpu.set_state(&st);
                Ok(0)
            }
            // Every other thread of the process (or every process) passes a
            // full barrier: each is forced out of the guest, and leaving and
            // re-entering it is context-synchronizing (the SYNC_CORE flavour
            // ART's JIT needs after writing code through its writable view).
            membarrier => {
                const QUERY: u64 = 0;
                const GLOBAL: u64 = 1;
                const GLOBAL_EXPEDITED: u64 = 2;
                const PRIVATE_EXPEDITED: u64 = 8;
                const PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
                const SUPPORTED: u64 = 0x7f; // all but the rseq commands
                match a[0] {
                    QUERY => Ok(SUPPORTED as i64),
                    GLOBAL | GLOBAL_EXPEDITED | PRIVATE_EXPEDITED | PRIVATE_EXPEDITED_SYNC_CORE => {
                        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                        let procs: Vec<std::sync::Arc<super::Process>> = if a[0] & (GLOBAL | GLOBAL_EXPEDITED) != 0 {
                            self.procs.lock().unwrap().values().cloned().collect()
                        } else {
                            vec![t.proc.clone()]
                        };
                        for p in procs {
                            for th in p.threads.lock().unwrap().iter().filter(|th| th.tid != t.tid) {
                                th.kick_vcpu();
                            }
                        }
                        Ok(0)
                    }
                    c if c.is_power_of_two() && c & SUPPORTED != 0 => Ok(0), // the REGISTER_* commands
                    _ => Err(EINVAL),
                }
            }
            // Disk quotas are off (installd then counts by hand); it asks per mount.
            quotactl => Err(ESRCH),
            // The drivers a module would bring are zeroemu's own.
            finit_module | init_module | delete_module => Ok(0),
            // The guest's clock is the host's: nothing to set.
            settimeofday => Ok(0),
            rseq | clone3 => Err(ENOSYS), // bionic falls back cleanly
            _ => Err(ENOSYS),
        }
    }

    /// The CPU-time clocks: CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, and the
    /// ids clock_getcpuclockid and pthread_getcpuclockid make, which are a pid or tid
    /// negated and shifted, with a thread bit and a kind (Linux's CPUCLOCK_*). None:
    /// not one of these.
    pub(super) fn cpu_clock(&self, t: &Thread, id: i32) -> Option<Result<Duration, i64>> {
        let ns = |n: u64| Some(Ok(Duration::from_nanos(n)));
        match id {
            2 => ns(t.proc.cpu_ns()),
            3 => ns(t.cpu_ns()),
            id if id < 0 => {
                if id & 3 == 3 {
                    return Some(Err(EINVAL));
                }
                // 0 is the caller. A thread's clock only for the caller's own threads, as on
                // Linux; a process's by its pid, or the caller's by any of its tids.
                let who = !(id >> 3);
                let found = if id & 4 != 0 {
                    if who == 0 {
                        Some(t.cpu_ns())
                    } else {
                        t.proc.threads.lock().unwrap().iter().find(|th| th.tid == who).map(|th| th.cpu_ns())
                    }
                } else if who == 0 || t.proc.threads.lock().unwrap().iter().any(|th| th.tid == who) {
                    Some(t.proc.cpu_ns())
                } else {
                    self.live_process(who).filter(|p| p.pid == who).map(|p| p.cpu_ns())
                };
                match found {
                    Some(n) => ns(n),
                    None => Some(Err(EINVAL)),
                }
            }
            _ => None,
        }
    }

    fn clock(&self, id: u64) -> (u64, u64) {
        let d = match id {
            0 | 5 | 8 | 11 => SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default(), // REALTIME(_COARSE), REALTIME_ALARM
            _ => self.boot.elapsed(),
        };
        (d.as_secs(), d.subsec_nanos() as u64)
    }
}

/// struct rusage: ru_utime then ru_stime (timevals), then ru_maxrss in KB and the rest.
/// All of the time counts as user time (see /proc/<pid>/stat).
pub(super) fn rusage(cpu_ns: u64, maxrss_kb: u64) -> [u8; 144] {
    let mut b = [0u8; 144];
    b[0..8].copy_from_slice(&(cpu_ns / 1_000_000_000).to_le_bytes());
    b[8..16].copy_from_slice(&(cpu_ns % 1_000_000_000 / 1000).to_le_bytes());
    b[32..40].copy_from_slice(&maxrss_kb.to_le_bytes());
    b
}
