//! A kernel-wide change counter. Anything that may make a file readable or
//! writable bumps it; poll/epoll waiters sleep on it and re-check readiness.
//! Waiters read the counter *before* checking, so no wakeup can be lost.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

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

    /// Sleeps until the counter moves past `seen` or `timeout` elapses.
    pub fn wait(&self, seen: u64, timeout: Duration) {
        super::vcpus::blocking();
        let g = self.generation.lock().unwrap();
        if *g == seen {
            let _ = self.cv.wait_timeout_while(g, timeout, |g| *g == seen).unwrap();
        }
    }
}
