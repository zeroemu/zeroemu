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
/// What a watcher of plain `bump`s watches: nothing a key can land on.
const PLAIN: u64 = 1;

struct Slot {
    seq: Mutex<u64>,
    cv: Condvar,
}

/// One sleeping place per thread, with what its thread is waiting for as a mask of
/// 63 bits that keys hash onto. An event wakes only the threads whose masks have its
/// bit: Android has hundreds of threads in epoll, each with a few files, and waking
/// them all for every eventfd write costs more than everything they then do. A hash
/// collision just wakes a thread for nothing.
///
/// Whoever changes something bumps after the change, and whoever waits watches
/// before checking, so no wakeup can be lost: each is sure to see the other.
pub struct Events {
    masks: [AtomicU64; SLOTS],
    slots: [Slot; SLOTS],
    /// Slots at or above this have never been used.
    high: AtomicUsize,
    free: Mutex<Vec<usize>>,
    /// How many times each bit has been announced, for `generation`.
    announced: [AtomicU64; 64],
}

pub static EVENTS: Events = Events {
    masks: [const { AtomicU64::new(0) }; SLOTS],
    announced: [const { AtomicU64::new(0) }; 64],
    slots: [const { Slot { seq: Mutex::new(0), cv: Condvar::new() } }; SLOTS],
    high: AtomicUsize::new(0),
    free: Mutex::new(Vec::new()),
};

/// This thread's slot, for as long as it lives.
struct MySlot(usize);

impl Drop for MySlot {
    fn drop(&mut self) {
        EVENTS.masks[self.0].store(0, Ordering::Relaxed);
        EVENTS.free.lock().unwrap().push(self.0);
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
    });
}

fn my_slot() -> usize {
    MY_SLOT.with(|s| s.0)
}

/// The mask for one key, any address that stands for the thing changing.
pub fn key_bit(key: usize) -> u64 {
    // Multiplying by 2^64/phi spreads the bits of an address into the top ones.
    let hash = ((key >> 4) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    1 << (1 + (hash >> 58) % 63)
}

/// The bit for what only ever gets a plain `bump`.
pub const fn plain_bit() -> u64 {
    PLAIN
}

impl Events {
    fn wake(&self, i: usize) {
        *self.slots[i].seq.lock().unwrap() += 1;
        self.slots[i].cv.notify_one();
    }

    fn wake_bits(&self, bits: u64) {
        fence(Ordering::SeqCst);
        for i in 0..self.high.load(Ordering::Acquire).min(SLOTS) {
            if self.masks[i].load(Ordering::Relaxed) & bits != 0 {
                self.wake(i);
            }
        }
    }

    /// Something changed that nothing keeps a key for: wakes everyone.
    pub fn bump(&self) {
        BUMPS_PLAIN.fetch_add(1, Ordering::Relaxed);
        self.announced[0].fetch_add(1, Ordering::SeqCst);
        self.wake_bits(u64::MAX);
    }

    /// The thing `key` stands for changed.
    pub fn bump_key(&self, key: usize) {
        BUMPS_KEYED.fetch_add(1, Ordering::Relaxed);
        let bit = key_bit(key);
        self.announced[bit.trailing_zeros() as usize].fetch_add(1, Ordering::SeqCst);
        self.wake_bits(bit);
    }

    /// A number that moves whenever something a waiter on `mask` would be woken for is
    /// announced, and sometimes when it isn't. A plain bump wakes everyone, so it counts
    /// for everyone.
    pub fn generation(&self, mask: u64) -> u64 {
        let mask = mask | PLAIN;
        (0..64).filter(|i| mask & 1 << i != 0).map(|i| self.announced[i].load(Ordering::SeqCst)).fold(0, u64::wrapping_add)
    }

    /// Before checking: this thread is about to care about `mask`. What to pass to `wait`.
    pub fn watch(&self, mask: u64) -> u64 {
        let i = my_slot();
        // A key's bit in a mask of its own, for a thread that only needs `bump`s to
        // get through: never zero, which would be no way to wake it at all.
        self.masks[i].store(mask | PLAIN, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        *self.slots[i].seq.lock().unwrap()
    }

    /// `watch`, for a wait on `key` alone.
    pub fn watch_key(&self, key: usize) -> u64 {
        self.watch(key_bit(key))
    }

    /// `watch`, for what only ever gets a plain `bump`.
    pub fn current(&self) -> u64 {
        self.watch(PLAIN)
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
        slot.cv.wait_timeout_while(g, timeout, |g| *g == seen).unwrap().1.timed_out()
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
    fn keys_land_on_their_own_bits() {
        let a = key_bit(0x1000);
        assert_eq!(a.count_ones(), 1);
        assert_ne!(a & PLAIN, PLAIN, "a key never lands on what only plain bumps wake");
        let spread: std::collections::HashSet<u64> = (0..4096usize).map(|i| key_bit(0x7000_0000 + i * 64)).collect();
        assert!(spread.len() > 40, "addresses spread: {} bits", spread.len());
    }

    #[test]
    fn a_keyed_bump_wakes_only_its_watchers_and_a_plain_one_wakes_all() {
        use std::sync::mpsc;
        let (k1, k2) = (0x1000_0040usize, (0..).map(|i| 0x2000_0000 + i * 64).find(|&k| key_bit(k) != key_bit(0x1000_0040)).unwrap());
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
