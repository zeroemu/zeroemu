//! Futexes, keyed by (process, address), or by guest-physical address for those in
//! memory that processes share.
//!
//! Waiters are kept in shards by key, as Linux keeps them in hash buckets
//! (kernel/futex/core.c), so futexes that hash apart never wait for each other.
//!
//! Lock order: a shard (for FUTEX_REQUEUE two, the lower first), then the address
//! space. A wait, the PI calls and FUTEX_CMP_REQUEUE read the word under a shard, so a
//! waiter is on a queue only once its word held its value (futex_wait).

use super::{BACKSTOP, ERESTARTSYS, Kernel, Thread};
use crate::errno::*;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

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
/// Linux's mask (include/uapi/linux/futex.h): any other bit makes an unknown command.
const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
const FUTEX_LOCK_PI2: u32 = 13;
const FUTEX_PRIVATE_FLAG: u32 = 128;
/// A PI futex word: the owner's tid, plus a bit set while threads wait in
/// the kernel (the owner's unlock then has to come here).
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// Key "pid" for futexes in shared memory, keyed by guest-physical address.
pub const SHARED: i32 = -1;

/// A thread's place on the queues (Thread::futex), made with the thread and used for
/// each of its waits, as a thread waits on one futex at a time: a wait allocates nothing.
pub(super) struct Waiter {
    st: Mutex<WaitState>,
    cv: Condvar,
    /// The key it is queued under now: FUTEX_REQUEUE moves waiters, and one that gives
    /// up (a timeout, a signal) must leave the queue it was moved to. Written under the
    /// locks of the shards it moves between.
    key: Mutex<(i32, u64)>,
}

#[derive(Default)]
struct WaitState {
    /// Set, under the lock of its shard, by whoever takes it off its queue to wake it.
    woken: bool,
    /// Its thread sleeps on `cv` now, so a wake or a kick has to tell it.
    asleep: bool,
}

impl Waiter {
    pub(super) fn new() -> Arc<Waiter> {
        Arc::new(Waiter { st: Mutex::default(), cv: Condvar::new(), key: Mutex::new((0, 0)) })
    }

    /// For Thread::kick, once what the thread is to look at is set: wakes it if it
    /// sleeps here. Under the lock it looks and sleeps under, so the kick can't come
    /// between the two and be lost, as one through Thread::sleeping_on can; that is
    /// what lets a futex wait sleep for as long as it waits.
    pub(super) fn kick(&self) {
        if self.st.lock().unwrap().asleep {
            self.cv.notify_one();
        }
    }
}

/// A waiter on one key's queue.
struct Entry {
    key: (i32, u64),
    w: Arc<Waiter>,
    bitset: u32,
    /// A PI lock waiter's tid: unlock hands it the lock. 0 for others.
    tid: i32,
}

const SHARDS: usize = 256;

/// The waiters of the keys that hash here, each key's in arrival order. There are a
/// few, so one list, which keeps its room, where a list per key would be allocated
/// and freed as waits come and go.
#[repr(align(64))]
#[derive(Default)]
struct Shard(Mutex<Vec<Entry>>);

pub struct Futexes {
    shards: [Shard; SHARDS],
}

impl Default for Futexes {
    fn default() -> Futexes {
        Futexes { shards: std::array::from_fn(|_| Shard::default()) }
    }
}

fn shard_of(key: (i32, u64)) -> usize {
    // Words are 4-byte aligned, and an object's few of them close together; multiplying
    // by 2^64/phi spreads the address into the top bits.
    let h = ((key.1 >> 2) ^ (key.0 as u32 as u64) << 40).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (h >> (64 - SHARDS.trailing_zeros())) as usize
}

/// Waiters taken off their queues, to be told once the shard's lock is let go: telling
/// one is a host system call, which other threads should not wait on for the lock.
#[derive(Default)]
struct ToWake {
    asleep: Vec<Arc<Waiter>>,
    n: usize,
}

impl ToWake {
    /// Marks `w` woken, under its shard's lock, so that a waiter giving up meanwhile
    /// finds itself both off the queue and woken. One not asleep yet needs no telling:
    /// it looks before it sleeps.
    fn take(&mut self, w: Arc<Waiter>) {
        let mut st = w.st.lock().unwrap();
        st.woken = true;
        if st.asleep {
            drop(st);
            self.asleep.push(w);
        }
        self.n += 1;
    }

    fn tell(self) -> usize {
        for w in &self.asleep {
            w.cv.notify_one();
        }
        self.n
    }
}

/// Puts a thread's waiter on `key`'s queue, not woken.
fn queue(list: &mut Vec<Entry>, w: &Arc<Waiter>, key: (i32, u64), bitset: u32, tid: i32) {
    w.st.lock().unwrap().woken = false;
    *w.key.lock().unwrap() = key;
    list.push(Entry { key, w: w.clone(), bitset, tid });
}

impl Futexes {
    fn shard(&self, key: (i32, u64)) -> &Mutex<Vec<Entry>> {
        &self.shards[shard_of(key)].0
    }

    pub fn wake(&self, key: (i32, u64), n: u32, bitset: u32) -> i64 {
        let mut wake = ToWake::default();
        {
            let mut list = self.shard(key).lock().unwrap();
            let mut i = 0;
            while i < list.len() && wake.n < n as usize {
                let e = &list[i];
                if e.key == key && e.bitset & bitset != 0 && e.tid == 0 {
                    wake.take(list.remove(i).w);
                } else {
                    i += 1;
                }
            }
        }
        wake.tell() as i64
    }

    /// Takes a waiter that gives up off its queue. False if a wake took it off first:
    /// it was woken, as Linux's futex_unqueue (kernel/futex/core.c) has it, and the
    /// wake was counted for it.
    fn remove(&self, w: &Arc<Waiter>) -> bool {
        loop {
            let key = *w.key.lock().unwrap();
            let mut list = self.shard(key).lock().unwrap();
            if let Some(i) = list.iter().position(|e| Arc::ptr_eq(&e.w, w)) {
                list.remove(i);
                return true;
            }
            if *w.key.lock().unwrap() == key {
                return false;
            }
            // Requeued since its key was read: look where it went.
        }
    }

    /// FUTEX_REQUEUE: wakes up to `wake_n` waiters on `key`, and moves up to `move_n`
    /// of the rest to `key2`, behind those already there; FUTEX_CMP_REQUEUE first checks
    /// the word at `addr` is still `cmp`, under both shards' locks as Linux does
    /// (futex_requeue in kernel/futex/requeue.c). Returns how many it woke and moved,
    /// as Linux's task_count does for both. A PI lock's waiter on `key` stops it with
    /// EINVAL, as on Linux: only FUTEX_UNLOCK_PI may hand it the lock. Those it took
    /// before that stay woken or moved.
    #[allow(clippy::too_many_arguments)]
    fn requeue(&self, t: &Thread, key: (i32, u64), key2: (i32, u64), addr: u64, cmp: Option<u32>, wake_n: usize, move_n: usize) -> i64 {
        let (a, b) = (shard_of(key), shard_of(key2));
        let (lo, hi) = (a.min(b), a.max(b));
        let mut wake = ToWake::default();
        let moved_n;
        let mut pi = false;
        {
            let mut lo_g = self.shards[lo].0.lock().unwrap();
            let mut hi_g = (hi != lo).then(|| self.shards[hi].0.lock().unwrap());
            if let Some(cmp) = cmp {
                let cur = t.proc.mm().read_u32(addr);
                match cur {
                    Ok(cur) if cur == cmp => {}
                    Ok(_) => return -EAGAIN,
                    Err(e) => return -e,
                }
            }
            let (src, dst) = match hi_g.as_mut() {
                None => (&mut *lo_g, None),
                Some(h) if a == lo => (&mut *lo_g, Some(&mut **h)),
                Some(h) => (&mut **h, Some(&mut *lo_g)),
            };
            let mut moved = Vec::new();
            let mut i = 0;
            while i < src.len() && wake.n + moved.len() < wake_n.saturating_add(move_n) {
                if src[i].key != key {
                    i += 1;
                    continue;
                }
                if src[i].tid != 0 {
                    pi = true;
                    break;
                }
                let mut e = src.remove(i);
                if wake.n < wake_n {
                    wake.take(e.w);
                } else {
                    e.key = key2;
                    *e.w.key.lock().unwrap() = key2;
                    moved.push(e);
                }
            }
            moved_n = moved.len();
            dst.unwrap_or(src).extend(moved);
        }
        let n = wake.tell() + moved_n;
        if pi { -EINVAL } else { n as i64 }
    }
}

impl Kernel {
    /// Private futexes are per process; others in shared memory are keyed
    /// by the physical frame so any process mapping it can wake them.
    pub(super) fn futex_key(&self, t: &Thread, addr: u64, private: bool) -> (i32, u64) {
        let addr = crate::arch::untag(addr);
        if !private && let Some(gpa) = t.proc.mm.lock().unwrap().as_mut().and_then(|m| m.shared_frame(addr)) {
            return (SHARED, gpa);
        }
        (t.proc.pid, addr)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sys_futex(&self, t: &Thread, uaddr: u64, op: u32, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
        let addr = crate::arch::untag(uaddr);
        let private = op & FUTEX_PRIVATE_FLAG != 0;
        let cmd = op & FUTEX_CMD_MASK;
        // In Linux's order: the timeout first, for the calls that take one (sys_futex and
        // futex_init_timeout in kernel/futex/syscalls.c). FUTEX_WAIT's is relative,
        // FUTEX_LOCK_PI's an absolute CLOCK_REALTIME time, and the others' absolute, on
        // CLOCK_MONOTONIC unless FUTEX_CLOCK_REALTIME asks otherwise.
        let deadline = if timeout == 0 || !matches!(cmd, FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI) {
            None
        } else {
            let (s, ns) = {
                let mut mm = t.proc.mm();
                match (mm.read_u64(timeout), mm.read_u64(timeout + 8)) {
                    (Ok(s), Ok(ns)) => (s, ns),
                    _ => return -EFAULT,
                }
            };
            let d = match super::wait::guest_timespec(s, ns) {
                Ok(d) => d,
                Err(e) => return -e,
            };
            Some(if cmd == FUTEX_WAIT {
                super::wait::instant_after(d)
            } else if cmd == FUTEX_LOCK_PI || op & FUTEX_CLOCK_REALTIME != 0 {
                super::wait::instant_after(d.saturating_sub(super::clock::realtime()))
            } else {
                self.boot + d.min(super::wait::CENTURY)
            })
        };
        // Then FUTEX_CLOCK_REALTIME, which only the calls whose clock the caller picks
        // take: do_futex refuses it on any other with ENOSYS, before it looks at the word
        // or the queue.
        if op & FUTEX_CLOCK_REALTIME != 0 && !matches!(cmd, FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI | FUTEX_LOCK_PI2) {
            return -ENOSYS;
        }
        // A futex is an aligned word (get_futex_key in kernel/futex/core.c).
        if !addr.is_multiple_of(4) {
            return -EINVAL;
        }
        let key = self.futex_key(t, addr, private);
        match cmd {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let bitset = if cmd == FUTEX_WAIT { u32::MAX } else { val3 };
                if bitset == 0 {
                    return -EINVAL;
                }
                self.futex_wait(t, key, private, addr, val, deadline, bitset)
            }
            // The count is an int, and futex_wake (kernel/futex/waitwake.c) wakes a
            // waiter before it compares: 0 or less wakes one.
            FUTEX_WAKE => self.futex.wake(key, (val as i32).max(1) as u32, u32::MAX),
            FUTEX_WAKE_BITSET if val3 == 0 => -EINVAL,
            FUTEX_WAKE_BITSET => self.futex.wake(key, (val as i32).max(1) as u32, val3),
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
                // Both counts are ints, the second the timeout slot's low 32 bits
                // (kernel/futex/syscalls.c), and a negative one is EINVAL, as is a target
                // that isn't an aligned word (futex_requeue in kernel/futex/requeue.c).
                let (wake_n, move_n) = (val as i32, timeout as u32 as i32);
                if wake_n < 0 || move_n < 0 || !crate::arch::untag(uaddr2).is_multiple_of(4) {
                    return -EINVAL;
                }
                let key2 = self.futex_key(t, uaddr2, private);
                let cmp = (cmd == FUTEX_CMP_REQUEUE).then_some(val3);
                self.futex.requeue(t, key, key2, addr, cmp, wake_n as usize, move_n as usize)
            }
            // FUTEX_TRYLOCK_PI takes no timeout: `deadline` is None for it.
            FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI => self.futex_lock_pi(t, key, addr, cmd == FUTEX_TRYLOCK_PI, deadline),
            FUTEX_UNLOCK_PI => self.futex_unlock_pi(t, key, addr),
            _ => -ENOSYS,
        }
    }

    /// Sleeps until this thread's waiter is woken, the deadline passes (`timed_out`)
    /// or a signal comes (`interrupted`); a waiter that gives up leaves its queue.
    fn futex_sleep(&self, t: &Thread, w: &Arc<Waiter>, deadline: Option<Instant>, timed_out: i64, interrupted: i64) -> i64 {
        let mut fell_back = false;
        loop {
            if w.st.lock().unwrap().woken {
                return 0;
            }
            let give_up = if deadline.is_some_and(|d| Instant::now() >= d) {
                Some(timed_out)
            } else if t.interrupted() {
                Some(interrupted)
            } else {
                None
            };
            if std::mem::take(&mut fell_back) && (give_up.is_some() || t.give_back.load(Ordering::Relaxed)) {
                let what = if give_up.is_some() { "a signal or exit" } else { "an ask for its vCPU" };
                eprintln!("[zeroemu] late wake: tid {} futex: only the fallback timeout noticed {what}", t.tid);
            }
            if let Some(err) = give_up {
                return if self.futex.remove(w) { err } else { 0 };
            }
            // Wakes and kicks both reach it under its lock (Waiter::kick): the limit
            // is only a backstop.
            let nap = deadline.map_or(BACKSTOP, |d| d.saturating_duration_since(Instant::now()).min(BACKSTOP));
            // Before the waiter's lock is taken: giving the vCPU back can take a while,
            // and a waker takes that lock while it holds the shard's.
            super::vcpus::blocking();
            let mut st = w.st.lock().unwrap();
            if !st.woken {
                // Asked for its vCPU since blocking() looked: the ask's kick found it
                // not asleep yet, and Thread::sleep looks only for signals and exits.
                // blocking() gives the vCPU up, the next time round.
                if t.give_back.load(Ordering::Relaxed) {
                    continue;
                }
                st.asleep = true;
                let start = super::files::late_wake_log().then(Instant::now);
                st = t.sleep(&w.cv, st, nap);
                st.asleep = false;
                fell_back = nap == BACKSTOP && start.is_some_and(|s| s.elapsed() >= nap);
            }
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
        let w = &t.futex;
        {
            let mut list = self.futex.shard(key).lock().unwrap();
            let queued = list.iter().any(|e| e.key == key);
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
            queue(&mut list, w, key, u32::MAX, t.tid);
        }
        // Woken: the unlocker wrote our tid.
        self.futex_sleep(t, w, deadline, -ETIMEDOUT, -ERESTARTSYS)
    }

    /// Releases a PI lock the caller owns: to the first waiter, or free.
    fn futex_unlock_pi(&self, t: &Thread, key: (i32, u64), addr: u64) -> i64 {
        let me = t.tid as u32;
        let mut wake = ToWake::default();
        let ret = {
            let mut list = self.futex.shard(key).lock().unwrap();
            let next = list.iter().position(|e| e.key == key && e.tid != 0);
            let new = match next {
                Some(i) => {
                    let more = list[i + 1..].iter().any(|e| e.key == key && e.tid != 0);
                    list[i].tid as u32 | if more { FUTEX_WAITERS } else { 0 }
                }
                None => 0,
            };
            let res = t.proc.mm().update_u32(addr, |cur| (cur & FUTEX_TID_MASK == me).then_some(new));
            match res {
                Ok((_, true)) => {
                    if let Some(i) = next {
                        wake.take(list.remove(i).w);
                    }
                    0
                }
                Ok((_, false)) => -EPERM, // not ours to give
                Err(e) => -e,
            }
        };
        wake.tell();
        ret
    }

    #[allow(clippy::too_many_arguments)]
    fn futex_wait(&self, t: &Thread, mut key: (i32, u64), private: bool, addr: u64, val: u32, deadline: Option<Instant>, bitset: u32) -> i64 {
        let w = &t.futex;
        // Queued only if the word holds `val`, read with the shard locked, as
        // futex_wait_setup (kernel/futex/waitwake.c) reads it with the bucket locked: a
        // wake after the change being waited for finds the waiter, and a wake or a
        // requeue finds only waiters that sleep. A requeue that moved a waiter about to
        // find its word changed would leave a sleeper behind, and lose its wakeup.
        //
        // The read under the shard doesn't fault the page in, as futex_get_value_locked
        // reads with page faults disabled: a page read from a file would hold up every
        // futex in the shard. A page not in yet is faulted in without the shard, as a
        // touch would, and the read starts over, as futex_wait_setup's retry does.
        let mut shard = self.futex.shard(key);
        let mut list = shard.lock().unwrap();
        let (mut waited, mut faulted) = (false, false);
        let cur = loop {
            let mut mm = match t.proc.try_mm() {
                Some(mm) => mm,
                None if !waited => {
                    // A page fault may hold the address space for a while: wait for it
                    // without the shard, then read again under the shard. If someone
                    // took it again meanwhile, the read waits for it there, as
                    // FUTEX_CMP_REQUEUE and the PI calls do.
                    drop(list);
                    drop(t.proc.mm());
                    waited = true;
                    list = shard.lock().unwrap();
                    continue;
                }
                None => t.proc.mm(),
            };
            // A page faulted in and gone again (another thread unmapped it) is read the
            // old way, under the shard, so that this ends.
            let cur = if faulted { Some(mm.read_u32(addr)) } else { mm.peek_u32(addr) };
            if let Some(cur) = cur {
                break cur;
            }
            drop(mm);
            drop(list);
            if self.page_fault(t, addr, false, false).is_err() {
                return -EFAULT;
            }
            faulted = true;
            // A shared futex's key is its page's frame, which may be another one now:
            // worked out again, as that retry gets the key again.
            if !private {
                key = self.futex_key(t, addr, false);
                shard = self.futex.shard(key);
            }
            list = shard.lock().unwrap();
        };
        match cur {
            Ok(cur) if cur == val => queue(&mut list, w, key, bitset, 0),
            Ok(_) => return -EAGAIN,
            Err(e) => return -e,
        }
        drop(list);
        self.futex_sleep(t, w, deadline, -ETIMEDOUT, -EINTR)
    }
}
