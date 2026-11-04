//! Time, system information, affinity, and other small syscalls.

use super::{Kernel, POLL, Thread};
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
                let (host, domain) = (super::control::hostname(), super::control::domainname());
                for (i, f) in ["Linux", &host, "6.6.0-droidrt", "#1 SMP PREEMPT droidrt", machine, &domain].iter().enumerate() {
                    out[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
                }
                t.proc.mm().write(a[0], &out)?;
                Ok(0)
            }
            clock_gettime => {
                let (s, ns) = self.clock(a[0]);
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
                let (req, abs, clock) = if no == nanosleep { (a[0], false, 1) } else { (a[2], a[1] & TIMER_ABSTIME != 0, a[0]) };
                let (s, ns) = {
                    let mut mm = t.proc.mm();
                    (mm.read_u64(req)?, mm.read_u64(req + 8)?)
                };
                let d = Duration::new(s, ns as u32);
                let deadline = if abs {
                    let (now_s, now_ns) = self.clock(clock);
                    Instant::now() + d.saturating_sub(Duration::new(now_s, now_ns as u32))
                } else {
                    Instant::now() + d
                };
                while Instant::now() < deadline {
                    if t.interrupted() {
                        return Err(EINTR);
                    }
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()).min(POLL));
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
            getrusage => t.proc.mm().write(a[1], &[0u8; 144]).map(|_| 0),
            sysinfo => {
                let mut b = [0u8; 112];
                b[0..8].copy_from_slice(&self.boot.elapsed().as_secs().to_le_bytes());
                b[32..40].copy_from_slice(&phys::PHYS_MAX.to_le_bytes()); // totalram
                b[40..48].copy_from_slice(&(phys::PHYS_MAX - self.phys.frames_in_use() * phys::PAGE).to_le_bytes());
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
            rseq | membarrier | clone3 => Err(ENOSYS), // bionic falls back cleanly
            _ => Err(ENOSYS),
        }
    }

    fn clock(&self, id: u64) -> (u64, u64) {
        let d = match id {
            0 | 5 | 8 => SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default(), // REALTIME(_COARSE), REALTIME_ALARM
            _ => self.boot.elapsed(),
        };
        (d.as_secs(), d.subsec_nanos() as u64)
    }
}
