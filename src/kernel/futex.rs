//! Futexes, keyed by (process, address). Every futex is treated as private:
//! there is no memory shared between processes yet.
//!
//! Lock order: the waiter table, then the address space (to read the word).

use super::{Kernel, POLL, Thread};
use crate::errno::*;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_PRIVATE_FLAG: u32 = 128;
/// Key "pid" for futexes in shared memory, keyed by guest-physical address.
pub const SHARED: i32 = -1;

struct Waiter {
    woken: Mutex<bool>,
    cv: Condvar,
    bitset: u32,
}

/// (pid, address) -> threads waiting there, in arrival order.
type WaitQueues = HashMap<(i32, u64), Vec<Arc<Waiter>>>;

#[derive(Default)]
pub struct Futexes {
    waiters: Mutex<WaitQueues>,
}

impl Futexes {
    pub fn wake(&self, key: (i32, u64), n: u32, bitset: u32) -> i64 {
        let mut map = self.waiters.lock().unwrap();
        let Some(list) = map.get_mut(&key) else { return 0 };
        let mut woken = 0;
        list.retain(|w| {
            if woken < n && w.bitset & bitset != 0 {
                *w.woken.lock().unwrap() = true;
                w.cv.notify_one();
                woken += 1;
                false
            } else {
                true
            }
        });
        if list.is_empty() {
            map.remove(&key);
        }
        woken as i64
    }

    fn remove(&self, key: (i32, u64), w: &Arc<Waiter>) {
        let mut map = self.waiters.lock().unwrap();
        if let Some(list) = map.get_mut(&key) {
            list.retain(|x| !Arc::ptr_eq(x, w));
            if list.is_empty() {
                map.remove(&key);
            }
        }
    }
}

impl Kernel {
    /// Private futexes are per process; others in shared memory are keyed
    /// by the physical frame so any process mapping it can wake them.
    pub(super) fn futex_key(&self, t: &Thread, addr: u64, private: bool) -> (i32, u64) {
        let addr = crate::arch::untag(addr);
        if !private && let Some(gpa) = t.proc.mm.lock().unwrap().as_ref().and_then(|m| m.shared_frame(addr)) {
            return (SHARED, gpa);
        }
        (t.proc.pid, addr)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sys_futex(&self, t: &Thread, uaddr: u64, op: u32, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
        let addr = crate::arch::untag(uaddr);
        let private = op & FUTEX_PRIVATE_FLAG != 0;
        let key = self.futex_key(t, addr, private);
        match op & FUTEX_CMD_MASK {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let bitset = if op & FUTEX_CMD_MASK == FUTEX_WAIT { u32::MAX } else { val3 };
                if bitset == 0 {
                    return -EINVAL;
                }
                let deadline = if timeout == 0 {
                    None
                } else {
                    let (s, ns) = {
                        let mut mm = t.proc.mm();
                        match (mm.read_u64(timeout), mm.read_u64(timeout + 8)) {
                            (Ok(s), Ok(ns)) => (s, ns),
                            _ => return -EFAULT,
                        }
                    };
                    let d = Duration::new(s, ns as u32);
                    Some(if op & FUTEX_CMD_MASK == FUTEX_WAIT {
                        Instant::now() + d // relative
                    } else if op & FUTEX_CLOCK_REALTIME != 0 {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                        Instant::now() + d.saturating_sub(now)
                    } else {
                        self.boot + d // absolute CLOCK_MONOTONIC
                    })
                };
                self.futex_wait(t, key, addr, val, deadline, bitset)
            }
            FUTEX_WAKE => self.futex.wake(key, val, u32::MAX),
            FUTEX_WAKE_BITSET => self.futex.wake(key, val, val3),
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
                let key2 = self.futex_key(t, uaddr2, private);
                let mut map = self.futex.waiters.lock().unwrap();
                if op & FUTEX_CMD_MASK == FUTEX_CMP_REQUEUE {
                    match t.proc.mm().read_u32(addr) {
                        Ok(cur) if cur == val3 => {}
                        Ok(_) => return -EAGAIN,
                        Err(e) => return -e,
                    }
                }
                let Some(mut list) = map.remove(&key) else { return 0 };
                let wake_n = (val as usize).min(list.len());
                for w in list.drain(..wake_n) {
                    *w.woken.lock().unwrap() = true;
                    w.cv.notify_one();
                }
                let move_n = (timeout as usize).min(list.len()); // val2 travels in the timeout slot
                let moved: Vec<_> = list.drain(..move_n).collect();
                if !list.is_empty() {
                    map.insert(key, list);
                }
                if !moved.is_empty() {
                    map.entry(key2).or_default().extend(moved);
                }
                wake_n as i64
            }
            _ => -ENOSYS,
        }
    }

    fn futex_wait(&self, t: &Thread, key: (i32, u64), addr: u64, val: u32, deadline: Option<Instant>, bitset: u32) -> i64 {
        let w = Arc::new(Waiter { woken: Mutex::new(false), cv: Condvar::new(), bitset });
        {
            let mut map = self.futex.waiters.lock().unwrap();
            match t.proc.mm().read_u32(addr) {
                Ok(cur) if cur == val => {}
                Ok(_) => return -EAGAIN,
                Err(e) => return -e,
            }
            map.entry(key).or_default().push(w.clone());
        }
        let mut woken = w.woken.lock().unwrap();
        loop {
            if *woken {
                return 0;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                drop(woken);
                self.futex.remove(key, &w);
                return if *w.woken.lock().unwrap() { 0 } else { -ETIMEDOUT };
            }
            if t.interrupted() {
                drop(woken);
                self.futex.remove(key, &w);
                return if *w.woken.lock().unwrap() { 0 } else { -EINTR };
            }
            let nap = deadline.map_or(POLL, |d| d.saturating_duration_since(Instant::now()).min(POLL));
            super::vcpus::blocking();
            woken = w.cv.wait_timeout(woken, nap).unwrap().0;
        }
    }
}
