//! eventfd, timerfd, and signalfd: file descriptors whose contents are a
//! counter, timer expirations, and pending signals.

use super::signal::SigInfo;
use super::wait::EVENTS;
use super::{ERESTARTSYS, POLL, Thread};
use crate::errno::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EFD_SEMAPHORE: u64 = 1;
const COUNTER_MAX: u64 = u64::MAX - 1;

pub struct EventFd {
    count: Mutex<u64>,
    semaphore: bool,
}

impl EventFd {
    pub fn new(initval: u64, flags: u64) -> EventFd {
        EventFd { count: Mutex::new(initval), semaphore: flags & EFD_SEMAPHORE != 0 }
    }

    pub fn ready_in(&self) -> bool {
        *self.count.lock().unwrap() > 0
    }

    pub fn ready_out(&self) -> bool {
        *self.count.lock().unwrap() < COUNTER_MAX
    }

    pub fn read(&self, t: &Thread, nonblock: bool) -> Result<u64, i64> {
        loop {
            let seen = EVENTS.current();
            {
                let mut c = self.count.lock().unwrap();
                if *c > 0 {
                    let v = if self.semaphore { 1 } else { *c };
                    *c -= v;
                    drop(c);
                    EVENTS.bump();
                    return Ok(v);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }

    pub fn write(&self, t: &Thread, v: u64, nonblock: bool) -> Result<(), i64> {
        if v == u64::MAX {
            return Err(EINVAL);
        }
        loop {
            let seen = EVENTS.current();
            {
                let mut c = self.count.lock().unwrap();
                if COUNTER_MAX - *c >= v {
                    *c += v;
                    drop(c);
                    EVENTS.bump();
                    return Ok(());
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }
}

const TFD_TIMER_ABSTIME: u64 = 1;

struct TimerState {
    next: Option<Instant>,
    interval: Duration,
    expirations: u64,
}

pub struct TimerFd {
    clock: u64,
    /// The kernel's boot instant: CLOCK_MONOTONIC zero.
    boot: Instant,
    st: Mutex<TimerState>,
}

fn timespec(b: &[u8]) -> Duration {
    let s = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let ns = u64::from_le_bytes(b[8..16].try_into().unwrap());
    Duration::new(s, ns.min(999_999_999) as u32)
}

fn put_timespec(b: &mut [u8], d: Duration) {
    b[0..8].copy_from_slice(&d.as_secs().to_le_bytes());
    b[8..16].copy_from_slice(&(d.subsec_nanos() as u64).to_le_bytes());
}

impl TimerFd {
    pub fn new(clock: u64, boot: Instant) -> Result<TimerFd, i64> {
        // REALTIME, MONOTONIC, BOOTTIME, REALTIME_ALARM, BOOTTIME_ALARM.
        if !matches!(clock, 0 | 1 | 7 | 8 | 9) {
            return Err(EINVAL);
        }
        Ok(TimerFd { clock, boot, st: Mutex::new(TimerState { next: None, interval: Duration::ZERO, expirations: 0 }) })
    }

    fn tick(st: &mut TimerState) {
        let now = Instant::now();
        let Some(next) = st.next else { return };
        if now < next {
            return;
        }
        if st.interval.is_zero() {
            st.expirations += 1;
            st.next = None;
        } else {
            let n = 1 + ((now - next).as_nanos() / st.interval.as_nanos()) as u64;
            st.expirations += n;
            st.next = Some(next + st.interval * n as u32);
        }
    }

    pub fn ready_in(&self) -> bool {
        let mut st = self.st.lock().unwrap();
        Self::tick(&mut st);
        st.expirations > 0
    }

    /// When this timer next fires (bounds how long a poll may sleep).
    pub fn deadline(&self) -> Option<Instant> {
        self.st.lock().unwrap().next
    }

    /// timerfd_settime: `new` is a 32-byte itimerspec; returns the old one.
    pub fn settime(&self, flags: u64, new: &[u8]) -> [u8; 32] {
        let old = self.gettime();
        let (interval, value) = (timespec(&new[0..16]), timespec(&new[16..32]));
        let mut st = self.st.lock().unwrap();
        st.expirations = 0;
        st.interval = interval;
        st.next = if value.is_zero() {
            None
        } else if flags & TFD_TIMER_ABSTIME != 0 {
            let now = if matches!(self.clock, 0 | 8) {
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
            } else {
                self.boot.elapsed()
            };
            Some(Instant::now() + value.saturating_sub(now))
        } else {
            Some(Instant::now() + value)
        };
        drop(st);
        EVENTS.bump();
        old
    }

    pub fn gettime(&self) -> [u8; 32] {
        let mut st = self.st.lock().unwrap();
        Self::tick(&mut st);
        let mut b = [0u8; 32];
        put_timespec(&mut b[0..16], st.interval);
        if let Some(next) = st.next {
            put_timespec(&mut b[16..32], next.saturating_duration_since(Instant::now()));
        }
        b
    }

    pub fn read(&self, t: &Thread, nonblock: bool) -> Result<u64, i64> {
        loop {
            let seen = EVENTS.current();
            let wait = {
                let mut st = self.st.lock().unwrap();
                Self::tick(&mut st);
                if st.expirations > 0 {
                    return Ok(std::mem::take(&mut st.expirations));
                }
                st.next.map_or(POLL, |n| n.saturating_duration_since(Instant::now()).min(POLL))
            };
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, wait);
        }
    }
}

pub struct SignalFd {
    pub mask: AtomicU64,
}

impl SignalFd {
    fn take(&self, t: &Thread) -> Option<(u32, SigInfo)> {
        let mask = self.mask.load(Ordering::Relaxed);
        for pending in [&t.pending, &t.proc.pending] {
            let mut p = pending.lock().unwrap();
            if let Some(&sig) = p.keys().filter(|&&s| mask & (1 << (s - 1)) != 0).min() {
                return p.remove(&sig).map(|i| (sig, i));
            }
        }
        None
    }

    pub fn ready_in(&self, t: &Thread) -> bool {
        let mask = self.mask.load(Ordering::Relaxed);
        let any = |p: &std::collections::HashMap<u32, SigInfo>| p.keys().any(|&s| mask & (1 << (s - 1)) != 0);
        any(&t.pending.lock().unwrap()) || any(&t.proc.pending.lock().unwrap())
    }

    /// Dequeues pending signals as 128-byte `signalfd_siginfo` records.
    pub fn read(&self, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        if max < 128 {
            return Err(EINVAL);
        }
        loop {
            let seen = EVENTS.current();
            let mut out = Vec::new();
            while out.len() + 128 <= max {
                let Some((sig, info)) = self.take(t) else { break };
                let i = &info.0;
                let mut rec = [0u8; 128];
                rec[0..4].copy_from_slice(&sig.to_le_bytes()); // ssi_signo
                rec[4..12].copy_from_slice(&i[4..12]); // ssi_errno, ssi_code
                rec[12..20].copy_from_slice(&i[16..24]); // ssi_pid, ssi_uid
                rec[40..44].copy_from_slice(&i[24..28]); // ssi_status (SIGCHLD)
                rec[72..80].copy_from_slice(&i[16..24]); // ssi_addr (faults)
                out.extend_from_slice(&rec);
            }
            if !out.is_empty() {
                return Ok(out);
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }
}
