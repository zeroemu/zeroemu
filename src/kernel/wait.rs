//! A kernel-wide change counter. Anything that may make a file readable or
//! writable bumps it; poll/epoll waiters sleep on it and re-check readiness.
//! Waiters read the counter *before* checking, so no wakeup can be lost.

use crate::errno::EINVAL;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How far ahead a deadline can be. Linux stops at 292 years (KTIME_MAX);
/// this is well within what Instant can represent on every host.
pub(super) const CENTURY: Duration = Duration::from_secs(100 * 365 * 86400);

/// A timespec from the guest, or EINVAL as Linux gives for a bad one.
pub(super) fn guest_timespec(sec: u64, nsec: u64) -> Result<Duration, i64> {
    if (sec as i64) < 0 || nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    Ok(Duration::new(sec, nsec as u32))
}

/// The instant `d` from now. Guest values can be huge, and Instant arithmetic
/// panics on overflow.
pub(super) fn instant_after(d: Duration) -> Instant {
    Instant::now() + d.min(CENTURY)
}

pub struct Events {
    generation: Mutex<u64>,
    cv: Condvar,
}

pub static EVENTS: Events = Events { generation: Mutex::new(0), cv: Condvar::new() };

impl Events {
    pub fn bump(&self) {
        *self.generation.lock().unwrap() += 1;
        self.cv.notify_all();
    }

    pub fn current(&self) -> u64 {
        *self.generation.lock().unwrap()
    }

    /// Sleeps until the counter moves past `seen` or `timeout` elapses;
    /// returns whether it was the timeout.
    pub fn wait(&self, seen: u64, timeout: Duration) -> bool {
        super::vcpus::blocking();
        let g = self.generation.lock().unwrap();
        if *g != seen {
            return false;
        }
        self.cv.wait_timeout_while(g, timeout, |g| *g == seen).unwrap().1.timed_out()
    }
}
