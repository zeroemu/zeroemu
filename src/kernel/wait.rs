//! Waiting for files to change. Anything that may make a file readable or writable
//! bumps; poll/epoll waiters sleep and re-check readiness when woken.

use crate::errno::EINVAL;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
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

/// Threads that can be asleep here at once.
const SLOTS: usize = 16384;
/// What keys hash onto. Bucket 0 is for plain `bump`s, which every watcher watches.
const BUCKETS: usize = 4096;
const WORDS: usize = BUCKETS / 64;

/// What a waiting thread watches: a set of buckets that keys hash onto. An event wakes
/// only the threads whose sets have its bucket. Android has a thousand threads or more
/// in epoll, each with a few files, and with 63 buckets every event woke dozens of them
/// for nothing; at idle that cost half a core. With 4096, a collision is rare.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mask([u64; WORDS]);

impl Mask {
    /// Nothing but plain bumps.
    pub const fn plain() -> Mask {
        let mut w = [0; WORDS];
        w[0] = 1;
        Mask(w)
    }

    fn bucket(b: usize) -> Mask {
        let mut w = [0; WORDS];
        w[b / 64] = 1 << (b % 64);
        Mask(w)
    }

    fn buckets(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(w, &bits)| {
            let mut bits = bits;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(w * 64 + b)
            })
        })
    }
}

impl std::ops::BitOr for Mask {
    type Output = Mask;
    fn bitor(mut self, o: Mask) -> Mask {
        self |= o;
        self
    }
}

impl std::ops::BitOrAssign for Mask {
    fn bitor_assign(&mut self, o: Mask) {
        for (a, b) in self.0.iter_mut().zip(o.0) {
            *a |= b;
        }
    }
}

impl std::fmt::Debug for Mask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_list().entries(self.buckets()).finish()
    }
}

struct Slot {
    seq: Mutex<u64>,
    cv: Condvar,
    /// Its thread is asleep in `wait`, for WAKES to count only real wakeups: a slot
    /// keeps the mask it last watched while its thread does other things.
    asleep: std::sync::atomic::AtomicBool,
}

/// One sleeping place per thread, with what its thread is waiting for (a Mask).
///
/// Whoever changes something bumps after the change, and whoever waits watches
/// before checking, so no wakeup can be lost: each is sure to see the other.
pub struct Events {
    /// masks[w][slot]: word w of each slot's mask, so that an event looks at one
    /// contiguous row, a word per thread, as cheaply as before buckets were many.
    masks: [[AtomicU64; SLOTS]; WORDS],
    slots: [Slot; SLOTS],
    /// Slots at or above this have never been used.
    high: AtomicUsize,
    free: Mutex<Vec<usize>>,
    /// How many times each bucket has been announced, for `generation`.
    announced: [AtomicU64; BUCKETS],
}

pub static EVENTS: Events = Events {
    masks: [const { [const { AtomicU64::new(0) }; SLOTS] }; WORDS],
    announced: [const { AtomicU64::new(0) }; BUCKETS],
    slots: [const { Slot { seq: Mutex::new(0), cv: Condvar::new(), asleep: std::sync::atomic::AtomicBool::new(false) } }; SLOTS],
    high: AtomicUsize::new(0),
    free: Mutex::new(Vec::new()),
};

/// This thread's slot, for as long as it lives, and which words of its mask aren't zero.
struct MySlot(usize, std::cell::Cell<u64>);

impl Drop for MySlot {
    fn drop(&mut self) {
        clear_words(self.0, self.1.get());
        EVENTS.free.lock().unwrap().push(self.0);
    }
}

fn clear_words(slot: usize, words: u64) {
    let mut words = words;
    while words != 0 {
        let w = words.trailing_zeros() as usize;
        words &= words - 1;
        EVENTS.masks[w][slot].store(0, Ordering::Relaxed);
    }
}

thread_local! {
    static MY_SLOT: MySlot = MySlot({
        let reused = EVENTS.free.lock().unwrap().pop();
        reused.unwrap_or_else(|| {
            let i = EVENTS.high.fetch_add(1, Ordering::AcqRel);
            assert!(i < SLOTS, "more threads than event slots");
            i
        })
    }, std::cell::Cell::new(0));
}

fn my_slot() -> usize {
    MY_SLOT.with(|s| s.0)
}

fn bucket_of(key: usize) -> usize {
    // Multiplying by 2^64/phi spreads the bits of an address into the top ones.
    let hash = ((key >> 4) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    1 + (hash >> 52) as usize % (BUCKETS - 1)
}

/// The mask for one key, any address that stands for the thing changing.
pub fn key_mask(key: usize) -> Mask {
    Mask::bucket(bucket_of(key))
}

/// Each slot's guest thread, for DROIDRT_WAKE_STATS to say whom a crowd wake reached.
static SLOT_TIDS: [std::sync::atomic::AtomicI32; SLOTS] = [const { std::sync::atomic::AtomicI32::new(0) }; SLOTS];

/// Records which guest thread sleeps in this thread's slot.
pub fn set_slot_tid(tid: i32) {
    SLOT_TIDS[my_slot()].store(tid, Ordering::Relaxed);
}

/// Wakeups sent, for wakeup_stats: how many threads each event woke.
pub static WAKES: AtomicU64 = AtomicU64::new(0);

/// DROIDRT_WAKE_STATS=1: per key, events and threads woken, for wakeup_stats to name the
/// keys that wake the most.
static WAKE_STATS: std::sync::LazyLock<Option<Mutex<std::collections::HashMap<usize, (u64, u64)>>>> =
    std::sync::LazyLock::new(|| std::env::var_os("DROIDRT_WAKE_STATS").map(|_| Mutex::default()));

/// The keys that woke the most threads since last asked: (key, events, woken).
pub fn top_wakers(n: usize) -> Vec<(usize, u64, u64)> {
    let Some(stats) = WAKE_STATS.as_ref() else { return Vec::new() };
    let mut v: Vec<(usize, u64, u64)> = stats.lock().unwrap().drain().map(|(k, (e, w))| (k, e, w)).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2));
    v.truncate(n);
    v
}

impl Events {
    fn wake(&self, i: usize) {
        let slot = &self.slots[i];
        *slot.seq.lock().unwrap() += 1;
        if slot.asleep.load(Ordering::Relaxed) {
            WAKES.fetch_add(1, Ordering::Relaxed);
        }
        slot.cv.notify_one();
    }

    fn wake_bucket(&self, b: usize) -> u64 {
        fence(Ordering::SeqCst);
        let (w, bit) = (b / 64, 1u64 << (b % 64));
        let row = &self.masks[w];
        let mut woken = 0;
        for i in 0..self.high.load(Ordering::Acquire).min(SLOTS) {
            if row[i].load(Ordering::Relaxed) & bit != 0 {
                self.wake(i);
                woken += 1;
            }
        }
        woken
    }

    /// Something changed that nothing keeps a key for: wakes everyone.
    pub fn bump(&self) {
        BUMPS_PLAIN.fetch_add(1, Ordering::Relaxed);
        self.announced[0].fetch_add(1, Ordering::SeqCst);
        let _ = self.wake_bucket(0);
    }

    /// The thing `key` stands for changed.
    pub fn bump_key(&self, key: usize) {
        BUMPS_KEYED.fetch_add(1, Ordering::Relaxed);
        let b = bucket_of(key);
        self.announced[b].fetch_add(1, Ordering::SeqCst);
        let woken = self.wake_bucket(b);
        if let Some(stats) = WAKE_STATS.as_ref() {
            let mut g = stats.lock().unwrap();
            let e = g.entry(key).or_default();
            e.0 += 1;
            e.1 += woken;
            // Where a key that wakes a crowd is announced from, once each.
            static SHOWN: Mutex<Vec<usize>> = Mutex::new(Vec::new());
            if woken > 100 && !SHOWN.lock().unwrap().contains(&key) {
                SHOWN.lock().unwrap().push(key);
                let (w, bit) = (b / 64, 1u64 << (b % 64));
                let tids: Vec<i32> = (0..self.high.load(Ordering::Acquire).min(SLOTS))
                    .filter(|&i| self.masks[w][i].load(Ordering::Relaxed) & bit != 0)
                    .map(|i| SLOT_TIDS[i].load(Ordering::Relaxed))
                    .take(40)
                    .collect();
                eprintln!("droidrt: key {key:#x} woke {woken} threads ({tids:?}), from:\n{}", std::backtrace::Backtrace::force_capture());
            }
        }
    }

    /// A number that moves whenever something a waiter on `mask` would be woken for is
    /// announced, and sometimes when it isn't. A plain bump wakes everyone, so it counts
    /// for everyone.
    pub fn generation(&self, mask: &Mask) -> u64 {
        (*mask | Mask::plain()).buckets().map(|b| self.announced[b].load(Ordering::SeqCst)).fold(0, u64::wrapping_add)
    }

    /// Before checking: this thread is about to care about `mask`. What to pass to `wait`.
    pub fn watch(&self, mask: &Mask) -> u64 {
        // Plain bumps get through to everyone: never an empty mask, which would be no
        // way to wake the thread at all.
        let mask = *mask | Mask::plain();
        MY_SLOT.with(|s| {
            let i = s.0;
            let now = mask.0.iter().enumerate().filter(|(_, w)| **w != 0).fold(0u64, |m, (w, _)| m | 1 << w);
            let mut touch = now | s.1.get();
            while touch != 0 {
                let w = touch.trailing_zeros() as usize;
                touch &= touch - 1;
                self.masks[w][i].store(mask.0[w], Ordering::Relaxed);
            }
            s.1.set(now);
            fence(Ordering::SeqCst);
            *self.slots[i].seq.lock().unwrap()
        })
    }

    /// `watch`, for a wait on `key` alone.
    pub fn watch_key(&self, key: usize) -> u64 {
        self.watch(&key_mask(key))
    }

    /// `watch`, for what only ever gets a plain `bump`.
    pub fn current(&self) -> u64 {
        self.watch(&Mask::plain())
    }

    /// Sleeps until something this thread watches moves past `seen` or `timeout`
    /// elapses; returns whether it was the timeout.
    pub fn wait(&self, seen: u64, timeout: Duration) -> bool {
        super::vcpus::blocking();
        let slot = &self.slots[my_slot()];
        let g = slot.seq.lock().unwrap();
        if *g != seen {
            return false;
        }
        slot.asleep.store(true, Ordering::Relaxed);
        let timed_out = slot.cv.wait_timeout_while(g, timeout, |g| *g == seen).unwrap().1.timed_out();
        slot.asleep.store(false, Ordering::Relaxed);
        timed_out
    }

    /// This thread's own place, for `wake_slot`.
    pub fn slot_of_this_thread(&self) -> usize {
        my_slot()
    }

    /// Wakes one thread: there is something for it in particular.
    pub fn wake_slot(&self, slot: usize) {
        self.wake(slot);
    }
}

pub static BUMPS_PLAIN: AtomicU64 = AtomicU64::new(0);
pub static BUMPS_KEYED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_land_on_their_own_buckets() {
        let a = key_mask(0x1000);
        assert_eq!(a.buckets().count(), 1);
        assert_ne!(a.buckets().next(), Some(0), "a key never lands on what only plain bumps wake");
        let spread: std::collections::HashSet<usize> = (0..4096usize).map(|i| bucket_of(0x7000_0000 + i * 64)).collect();
        assert!(spread.len() > 2000, "addresses spread: {} buckets", spread.len());
        let objects: std::collections::HashSet<usize> = (0..1000usize).map(|i| bucket_of(0x1_0000_0000 + i * 0x2c0)).collect();
        assert!(objects.len() > 800, "heap objects spread: {} buckets", objects.len());
    }

    #[test]
    fn a_keyed_bump_wakes_only_its_watchers_and_a_plain_one_wakes_all() {
        use std::sync::mpsc;
        let (k1, k2) = (0x1000_0040usize, (0..).map(|i| 0x2000_0000 + i * 64).find(|&k| bucket_of(k) != bucket_of(0x1000_0040)).unwrap());
        // Each thread watches its key and reports each wake, or its timeout.
        let watcher = |key: usize| {
            let (tx, rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut seen = EVENTS.watch_key(key);
                ready_tx.send(()).unwrap();
                for _ in 0..2 {
                    let timed_out = EVENTS.wait(seen, Duration::from_secs(5));
                    seen = EVENTS.watch_key(key);
                    tx.send(timed_out).unwrap();
                }
            });
            ready_rx.recv().unwrap();
            rx
        };
        let (a, b) = (watcher(k1), watcher(k2));
        EVENTS.bump_key(k1);
        assert_eq!(a.recv_timeout(Duration::from_secs(5)), Ok(false), "woken by its key");
        assert!(b.recv_timeout(Duration::from_millis(100)).is_err(), "not by another's");
        EVENTS.bump();
        assert_eq!(a.recv_timeout(Duration::from_secs(5)), Ok(false));
        assert_eq!(b.recv_timeout(Duration::from_secs(5)), Ok(false), "a plain bump reaches everyone");
    }

    #[test]
    fn a_bump_between_watching_and_waiting_is_not_lost() {
        let seen = EVENTS.watch_key(0x3000_0000);
        EVENTS.bump_key(0x3000_0000);
        assert!(!EVENTS.wait(seen, Duration::from_secs(30)), "no sleep at all");
    }
}
