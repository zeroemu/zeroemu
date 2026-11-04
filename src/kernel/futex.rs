//! Futexes, keyed by (process, address). Every futex is treated as private:
//! there is no memory shared between processes yet.
//!
//! Lock order: the waiter table, then the address space (to read the word).

use super::{ERESTARTSYS, Kernel, POLL, Thread};
use crate::errno::*;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_LOCK_PI: u32 = 6;
const FUTEX_UNLOCK_PI: u32 = 7;
const FUTEX_TRYLOCK_PI: u32 = 8;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_LOCK_PI2: u32 = 13;
const FUTEX_PRIVATE_FLAG: u32 = 128;
/// A PI futex word: the owner's tid, plus a bit set while threads wait in
/// the kernel (the owner's unlock then has to come here).
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// Key "pid" for futexes in shared memory, keyed by guest-physical address.
pub const SHARED: i32 = -1;

struct Waiter {
    woken: Mutex<bool>,
    cv: Condvar,
    bitset: u32,
    /// A PI lock waiter's tid: unlock hands it the lock.
    tid: i32,
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
            if woken < n && w.bitset & bitset != 0 && w.tid == 0 {
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
            FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI => {
                let cmd = op & FUTEX_CMD_MASK;
                let deadline = if cmd == FUTEX_TRYLOCK_PI || timeout == 0 {
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
                    // Absolute: LOCK_PI on CLOCK_REALTIME, LOCK_PI2 on
                    // CLOCK_MONOTONIC unless asked otherwise.
                    Some(if cmd == FUTEX_LOCK_PI || op & FUTEX_CLOCK_REALTIME != 0 {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                        Instant::now() + d.saturating_sub(now)
                    } else {
                        self.boot + d
                    })
                };
                self.futex_lock_pi(t, key, addr, cmd == FUTEX_TRYLOCK_PI, deadline)
            }
            FUTEX_UNLOCK_PI => self.futex_unlock_pi(t, key, addr),
            _ => -ENOSYS,
        }
    }

    /// Takes a priority-inheritance lock (without the priority boost: host
    /// threads have no guest priorities to lend). The word holds the owner's
    /// tid; waiters queue here until unlock hands one of them the lock.
    fn futex_lock_pi(&self, t: &Thread, key: (i32, u64), addr: u64, try_only: bool, deadline: Option<Instant>) -> i64 {
        let me = t.tid as u32;
        // Linux: ESRCH when the owning thread does not exist.
        let owner = match t.proc.mm().read_u32(addr) {
            Ok(v) => v & FUTEX_TID_MASK,
            Err(e) => return -e,
        };
        if owner != 0 && owner != me && self.task(owner as i32).is_none() {
            return -ESRCH;
        }
        let w = Arc::new(Waiter { woken: Mutex::new(false), cv: Condvar::new(), bitset: u32::MAX, tid: t.tid });
        {
            let mut map = self.futex.waiters.lock().unwrap();
            let queued = map.get(&key).is_some_and(|l| !l.is_empty());
            let mut taken = false;
            let res = t.proc.mm().update_u32(addr, |cur| {
                let owner = cur & FUTEX_TID_MASK;
                taken = owner == 0;
                if taken {
                    Some(me | (cur & FUTEX_OWNER_DIED) | if queued { FUTEX_WAITERS } else { 0 })
                } else if owner == me || try_only || cur & FUTEX_WAITERS != 0 {
                    None
                } else {
                    Some(cur | FUTEX_WAITERS)
                }
            });
            let cur = match res {
                Ok((cur, _)) => cur,
                Err(e) => return -e,
            };
            if taken {
                return 0;
            }
            if cur & FUTEX_TID_MASK == me {
                return -EDEADLK;
            }
            if try_only {
                return -EAGAIN;
            }
            map.entry(key).or_default().push(w.clone());
        }
        let mut woken = w.woken.lock().unwrap();
        loop {
            if *woken {
                return 0; // the unlocker wrote our tid
            }
            let give_up = if deadline.is_some_and(|d| Instant::now() >= d) {
                Some(-ETIMEDOUT)
            } else if t.interrupted() {
                Some(-ERESTARTSYS)
            } else {
                None
            };
            if let Some(err) = give_up {
                drop(woken);
                self.futex.remove(key, &w);
                return if *w.woken.lock().unwrap() { 0 } else { err };
            }
            let nap = deadline.map_or(POLL, |d| d.saturating_duration_since(Instant::now()).min(POLL));
            super::vcpus::blocking();
            woken = w.cv.wait_timeout(woken, nap).unwrap().0;
        }
    }

    /// Releases a PI lock the caller owns: to the first waiter, or free.
    fn futex_unlock_pi(&self, t: &Thread, key: (i32, u64), addr: u64) -> i64 {
        let me = t.tid as u32;
        let mut map = self.futex.waiters.lock().unwrap();
        let next = map.get_mut(&key).and_then(|l| {
            let i = l.iter().position(|w| w.tid != 0)?;
            Some(l.remove(i))
        });
        let more = map.get(&key).is_some_and(|l| l.iter().any(|w| w.tid != 0));
        if map.get(&key).is_some_and(|l| l.is_empty()) {
            map.remove(&key);
        }
        let new = match &next {
            Some(w) => w.tid as u32 | if more { FUTEX_WAITERS } else { 0 },
            None => 0,
        };
        let res = t.proc.mm().update_u32(addr, |cur| (cur & FUTEX_TID_MASK == me).then_some(new));
        match res {
            Ok((_, true)) => {
                if let Some(w) = next {
                    *w.woken.lock().unwrap() = true;
                    w.cv.notify_one();
                }
                0
            }
            Ok((_, false)) => {
                if let Some(w) = next {
                    map.entry(key).or_default().insert(0, w); // not ours to give
                }
                -EPERM
            }
            Err(e) => -e,
        }
    }

    fn futex_wait(&self, t: &Thread, key: (i32, u64), addr: u64, val: u32, deadline: Option<Instant>, bitset: u32) -> i64 {
        let w = Arc::new(Waiter { woken: Mutex::new(false), cv: Condvar::new(), bitset, tid: 0 });
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
