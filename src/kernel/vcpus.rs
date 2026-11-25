//! More guest threads than vCPUs. A hypervisor allows only so many vCPUs
//! (HVF: 64) and Android runs hundreds of threads, most of them blocked in
//! the kernel (idle binder pools, futex and poll waits). A vCPU belongs to the
//! host thread that made it (HVF's rule), so it cannot be handed to another
//! thread; instead a thread asked for its place saves its registers and
//! destroys its vCPU, and makes a new one when it next runs guest code. While
//! parked, its register state is answered from the copy.
//!
//! Destroying and making a vCPU are costly calls to the hypervisor, so a thread
//! that blocks keeps its vCPU while places are free. A few places are kept free by
//! asking the threads that have slept longest to give theirs back: most sleeps are
//! short, and a thread asleep for a long time is likely to stay asleep. Only when
//! that falls behind, or someone waits for a place, does a thread that blocks give
//! its own up at once: a thread that wakes to find no place has to wait for one.
//!
//! The first thread in line for a vCPU asks the longest sleepers too, and kicks
//! the threads that have run longest, which give their vCPUs up at their next exit,
//! so threads spinning in user code cannot starve the rest. Everyone else in line
//! sleeps until it is first: hundreds of them polling this lock would be a load all
//! of its own.
//!
//! Background threads also need a place in a much smaller pool, the cores a phone
//! would have kept them to. There is nowhere better to hold them back: they
//! wait here at the door of the guest, holding no kernel lock anyone could want.
//! A thread asleep in the kernel uses no core, so it gives that place up when it
//! blocks, and takes one again, or waits in line without its vCPU, when it wakes.
//!
//! When Android is given fewer cores than the host has (kernel::set_cpus), a third
//! set of places, one per core it was given, holds everyone back: macOS has no CPU
//! affinity to keep threads to some of the cores, so letting no more than that many
//! run at once is the only way to leave the Mac the rest. A thread holds a core from
//! its way into the guest until it next blocks in the kernel, as a Linux thread keeps
//! its CPU through its syscalls; it gives it up when it blocks, at sched_yield while
//! others wait, and at the door once others wait and its turn is up. A core given up
//! goes straight to the first in line, so a thread that comes for one meanwhile cannot
//! take it from someone who waited.
//!
//! Display work goes first, as Linux runs real-time threads before the rest: each
//! display thread in line has one thread of other work give its core up at its next
//! door, and the first in line kicks that many out of guest code to get them there.
//! Display work that has held its core for DISPLAY_SLICE while only the rest wait, or
//! yields to them, waits and runs as the rest until it next blocks, so it cannot take
//! its core straight back. Display threads taking turns could still keep the rest out
//! for good, so the first of the rest goes first once it has waited REST_WAIT, and
//! display work makes way for it after its DISPLAY_SLICE; while both lines wait, they
//! take turns, so neither waits for good. The first in line kicks only
//! holders in guest code: one in
//! the kernel comes to the door by itself, and one waiting for a vCPU has none to stop.
//! A thread waiting for a core keeps its vCPU, marked asleep so the whole pool can still
//! ask for it: destroying and making one costs far more than the wait. With as many
//! cores as the host, there is no gate.
//!
//! Every thread takes its places in one order, background, then core, then vCPU, and
//! waits for one only at the door, holding no kernel lock, and never holding a later
//! one that others need: a vCPU it keeps while it waits for a core, the pool can take
//! back. So no two threads can each wait for what the other holds.

use super::Thread;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, PageTableRoot, SyscallRegs, Urgency, Vcpu, set_thread_urgency};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The kernel's pool, for wakeup_stats.
pub static MAIN: std::sync::OnceLock<std::sync::Weak<Pool>> = std::sync::OnceLock::new();

/// vCPUs made, for wakeup_stats: each costs the hypervisor a fresh one.
pub static MADE: AtomicU64 = AtomicU64::new(0);

/// Times a thread waited in line for a place in the whole pool, for wakeup_stats.
pub static WAITED: AtomicU64 = AtomicU64::new(0);

/// A holder asleep in the kernel this long may be asked for its vCPU to keep places free.
/// Shorter sleeps are most of them, and are over before the hypervisor would have
/// destroyed and made a vCPU for them.
const DROWSY: Duration = Duration::from_millis(2);

/// How long a holder runs on, from when it took its place or last woke, once others wait.
const SLICE: Duration = Duration::from_millis(10);

/// How often free places are topped up, at most.
const TOP_UP: Duration = Duration::from_millis(1);

/// How long display work keeps a core while only other work waits for one; then it
/// waits and runs as other work, a slice at a time, until it next blocks. Linux's
/// real-time throttling keeps a share of every second for the rest
/// (sched_rt_runtime_us, kernel/sched/rt.c) so that a real-time thread that spins
/// cannot shut them out; this does as much for a display thread that spins without
/// blocking. One that blocks now and then is display work again each time it wakes.
const DISPLAY_SLICE: Duration = Duration::from_millis(50);
/// How long the first of the rest waits behind display work before it goes first: two
/// display threads that spin would otherwise hand a core to and fro and keep the rest
/// out for good, where Linux's real-time throttling leaves fair threads 5% of each
/// second (sched_rt_runtime_us). Then display work that has held its core for
/// DISPLAY_SLICE makes way for it, so the rest wait for no more than about the two.
const REST_WAIT: Duration = DISPLAY_SLICE;

pub struct Pool {
    max: usize,
    /// Background threads' places, when this is the whole pool.
    background: Option<Arc<Pool>>,
    /// One place per core, when Android is given fewer than the host has and this is
    /// the whole pool.
    cores: Option<Cores>,
    /// No guest code runs from now on.
    frozen: AtomicBool,
    st: Mutex<PoolState>,
    /// Threads waiting for a vCPU (read without the lock on every exit).
    waiting: AtomicUsize,
    used: AtomicUsize,
    /// What Holder::asleep counts from.
    epoch: Instant,
    /// When free places were last topped up, after `epoch` in ns.
    topped_up: AtomicU64,
}

/// A thread holding a place.
struct Holder {
    thread: Arc<Thread>,
    /// When it took the place, or last woke from a sleep it kept the place through, in
    /// ns after the pool's epoch: how long it has run, for a slice. A thread that slept
    /// most of the time since it took the place has not kept anyone out.
    run_since: AtomicU64,
    /// When its thread went to sleep in the kernel (`blocking`), in ns after the
    /// pool's epoch; 0 while it runs.
    asleep: AtomicU64,
}

#[derive(Default)]
struct PoolState {
    next: u64,
    holders: HashMap<u64, Arc<Holder>>,
    /// Waiters, served in order: a thread that just gave its vCPU up must not take it
    /// straight back past the threads it yielded to.
    queue: VecDeque<(u64, Arc<Condvar>)>,
}

impl PoolState {
    fn wake_first(&self) {
        if let Some((_, cv)) = self.queue.front() {
            cv.notify_one();
        }
    }
}

impl Pool {
    /// `max` vCPUs at most, for a guest given `cpus` cores.
    pub fn new(max: usize, cpus: usize) -> Arc<Pool> {
        let host = super::host_cpus();
        let cores = cpus.min(host);
        // Half the cores, at least one: with a device given two or three, at least two
        // would let background work (dex2oat after an install) take them all.
        let background = Pool::sized((cores / 2).max(1), None, None);
        // Not sized to `cpus`: this counts vCPUs, most of them held by threads asleep in
        // the kernel, not cores; so few would have every thread that blocks destroy its
        // vCPU and make another when it wakes (docs/PERFORMANCE.md).
        let pool = Pool::sized(max, Some(background), cores_gate(cpus, host));
        let _ = MAIN.set(Arc::downgrade(&pool));
        pool
    }

    fn sized(max: usize, background: Option<Arc<Pool>>, cores: Option<Cores>) -> Arc<Pool> {
        Arc::new(Pool {
            max: max.max(1),
            background,
            cores,
            frozen: AtomicBool::new(false),
            st: Mutex::default(),
            waiting: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
            epoch: Instant::now(),
            topped_up: AtomicU64::new(0),
        })
    }

    fn add_holder(&self, thread: &Arc<Thread>) -> (u64, Arc<Holder>) {
        let mut st = self.st.lock().unwrap();
        st.next += 1;
        let id = st.next;
        let h = Arc::new(Holder { thread: thread.clone(), run_since: AtomicU64::new(self.now_ns()), asleep: AtomicU64::new(0) });
        st.holders.insert(id, h.clone());
        (id, h)
    }

    /// Now, as Holder::asleep counts it: never 0.
    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64 + 1
    }

    /// Whether `h` has run a slice since it took its place or last woke.
    fn ran_slice(&self, h: &Holder) -> bool {
        self.now_ns().saturating_sub(h.run_since.load(Ordering::Relaxed)) >= SLICE.as_nanos() as u64
    }

    /// Stops guest code: from now on threads wait at the door. Kicking those already
    /// inside is the caller's business. This is the end: nothing thaws them.
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    /// (in use, held by threads asleep in the kernel, the most there can be), for
    /// wakeup_stats.
    pub fn usage(&self) -> (usize, usize, usize) {
        let asleep = self.st.lock().unwrap().holders.values().filter(|h| h.asleep.load(Ordering::Relaxed) != 0).count();
        (self.used.load(Ordering::Relaxed), asleep, self.max)
    }

    /// (cores in use, threads in line for one, cores, times a thread waited for one) when
    /// cores are gated, for wakeup_stats.
    pub fn cores_usage(&self) -> Option<(usize, usize, usize, u64)> {
        self.cores.as_ref().map(Cores::usage)
    }

    /// So few places free that a thread going to sleep should give its own up now: half
    /// of what top_up keeps.
    fn low(&self) -> bool {
        self.max.saturating_sub(self.used.load(Ordering::Relaxed)) <= self.max / 16
    }

    /// Asks up to `n` holders asleep in the kernel for at least `min`, longest asleep
    /// first, to give their places back: woken, each finds nothing to do and gives its
    /// vCPU up as it goes back to sleep (`blocking`). Returns how many it asked: one
    /// found awake by then isn't.
    /// `again`: those already asked count too, and are woken again, in case the last
    /// wakeup came before they slept.
    fn reclaim(&self, st: &PoolState, n: usize, min: Duration, again: bool) -> usize {
        if n == 0 {
            return 0;
        }
        let now = self.now_ns();
        let min = min.as_nanos() as u64;
        let mut sleepers: Vec<(u64, &Holder)> = st
            .holders
            .values()
            .filter_map(|h| {
                let asleep = h.asleep.load(Ordering::Relaxed);
                (asleep != 0 && now.saturating_sub(asleep) >= min && (again || !h.thread.give_back.load(Ordering::Relaxed))).then_some((asleep, &**h))
            })
            .collect();
        sleepers.sort_unstable_by_key(|(asleep, _)| *asleep);
        sleepers.truncate(n);
        let mut asked = 0;
        for (_, h) in &sleepers {
            h.thread.give_back.store(true, Ordering::Relaxed);
            // It may have woken since it was read asleep: `running` clears the ask, but
            // it may have done so before this set it, and then the thread would give
            // its vCPU up at its next sleep for no reason. With the fence in `running`,
            // either this sees it awake and takes the ask back, or `running` clears it.
            fence(Ordering::SeqCst);
            if h.asleep.load(Ordering::Relaxed) == 0 {
                h.thread.give_back.store(false, Ordering::Relaxed);
                continue;
            }
            nudge(&h.thread);
            asked += 1;
        }
        asked
    }

    /// After a place was taken: keeps an eighth of the places free, so a thread that
    /// wakes finds one without waiting, by asking those that have slept longest for
    /// theirs. Otherwise the pool fills with sleepers, which can sleep for ever.
    fn top_up(&self, st: &PoolState) {
        let free = self.max.saturating_sub(self.used.load(Ordering::Relaxed));
        let reserve = self.max / 8;
        if free >= reserve {
            return;
        }
        // Under the pool's lock, so no other thread is here at once.
        let now = self.now_ns();
        if now.saturating_sub(self.topped_up.load(Ordering::Relaxed)) < TOP_UP.as_nanos() as u64 {
            return;
        }
        self.topped_up.store(now, Ordering::Relaxed);
        self.reclaim(st, reserve - free, DROWSY, false);
    }

    /// Takes a place now if one is free and nobody is in line for it.
    fn try_acquire(&self) -> bool {
        let st = self.st.lock().unwrap();
        if self.used.load(Ordering::Relaxed) < self.max && st.queue.is_empty() {
            self.used.fetch_add(1, Ordering::Relaxed);
            self.top_up(&st);
            return true;
        }
        false
    }

    /// Takes a place, waiting for one. False if there is no point any more: the thread
    /// is dying, or `still_wanted` says it no longer needs one.
    fn acquire(&self, t: &Thread, still_wanted: impl Fn() -> bool) -> bool {
        let mut st = self.st.lock().unwrap();
        if t.dying.load(Ordering::Acquire) {
            return false;
        }
        if self.used.load(Ordering::Relaxed) < self.max && st.queue.is_empty() {
            self.used.fetch_add(1, Ordering::Relaxed);
            self.top_up(&st);
            return true;
        }
        st.next += 1;
        let ticket = st.next;
        let cv = Arc::new(Condvar::new());
        st.queue.push_back((ticket, cv.clone()));
        self.waiting.fetch_add(1, Ordering::Relaxed);
        if self.background.is_some() {
            WAITED.fetch_add(1, Ordering::Relaxed);
        }
        let got = loop {
            if t.dying.load(Ordering::Acquire) || !still_wanted() {
                break false;
            }
            let first = st.queue.front().is_some_and(|(x, _)| *x == ticket);
            if first && self.used.load(Ordering::Relaxed) < self.max {
                self.used.fetch_add(1, Ordering::Relaxed);
                self.top_up(&st);
                break true;
            }
            if first {
                // As many holders as there are threads in line: those asleep in the
                // kernel longest, which give their places up as they go back to sleep,
                // and then those that have run longest, once they have had their slice,
                // which give theirs up at the exit this forces.
                let asked = self.reclaim(&st, st.queue.len(), Duration::ZERO, true);
                let mut running: Vec<_> = st.holders.values().filter(|h| h.asleep.load(Ordering::Relaxed) == 0 && self.ran_slice(h)).collect();
                running.sort_by_key(|h| h.run_since.load(Ordering::Relaxed));
                for h in running.iter().take(st.queue.len().saturating_sub(asked)) {
                    h.thread.kick();
                }
            }
            st = t.wait_for_turn(&cv, st, if first { SLICE / 2 } else { super::IDLE });
        };
        st.queue.retain(|(x, _)| *x != ticket);
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        // It is first now, and there may be room for it too.
        st.wake_first();
        got
    }

    fn release(&self) {
        let st = self.st.lock().unwrap();
        self.used.fetch_sub(1, Ordering::Relaxed);
        st.wake_first();
    }
}

/// The cores gate for a guest given `cpus` of the host's `host` cores: none when it has
/// them all, as before there was a choice.
fn cores_gate(cpus: usize, host: usize) -> Option<Cores> {
    (cpus < host).then(|| Cores::new(cpus))
}

/// A thread's urgency changed (Thread::update_urgency): if it waits for a core, it moves
/// to the line it now belongs in.
pub fn urgency_changed(thread: &Thread) {
    if let Some(pool) = MAIN.get().and_then(std::sync::Weak::upgrade)
        && let Some(cores) = &pool.cores
    {
        cores.reclassify(thread as *const Thread);
    }
}

/// Whether a thread that has held its core for `held` makes way for the first in line:
/// gives its core up at its next way into the guest, and gets in line itself.
fn makes_way(holder_display: bool, held: Duration, first_display: bool) -> bool {
    match (holder_display, first_display) {
        // At once, as a real-time thread that wakes preempts a fair one on Linux
        // (wakeup_preempt, kernel/sched/core.c): late display work shows on the screen.
        (false, true) => true,
        // Turns among their like, a slice each, as SCHED_RR's and CFS's.
        (true, true) | (false, false) => held >= SLICE,
        // Then it waits and runs as the rest until it next blocks (Held::spent).
        (true, false) => held >= DISPLAY_SLICE,
    }
}

/// Which holders, as (id, display work, held for), the first in line stops so that they
/// come to the door and make way: those that would, longest held first, `n` at most.
/// Only holders in guest code are given: a kick hurries no other to the door.
fn to_kick(mut holders: Vec<(u64, bool, Duration)>, first_display: bool, n: usize) -> Vec<u64> {
    holders.retain(|&(_, display, held)| makes_way(display, held, first_display));
    holders.sort_unstable_by_key(|&(_, _, held)| std::cmp::Reverse(held));
    holders.into_iter().take(n).map(|(id, ..)| id).collect()
}

/// What the cores gate needs of a thread: a trait so that its tests need no kernel.
trait Runner {
    /// Display work goes first.
    fn is_display(&self) -> bool;
    fn is_dying(&self) -> bool;
    /// Asked by the whole pool for its vCPU (Pool::reclaim).
    fn asked_for_vcpu(&self) -> bool;
    /// In guest code now: only then does stop_in_guest bring it to the door sooner.
    fn in_guest(&self) -> bool;
    /// Stops it if it runs guest code, so that it comes to the door.
    fn stop_in_guest(&self);
    /// Sleeps on `cv` until it is notified, the thread is kicked or nudged, or `timeout`
    /// passes.
    fn wait_turn<'a, T>(&self, cv: &Condvar, g: MutexGuard<'a, T>, timeout: Duration) -> MutexGuard<'a, T>;
}

impl Runner for Thread {
    fn is_display(&self) -> bool {
        self.urgency() == Urgency::Display
    }
    fn is_dying(&self) -> bool {
        self.dying.load(Ordering::Acquire)
    }
    fn asked_for_vcpu(&self) -> bool {
        self.give_back.load(Ordering::Relaxed)
    }
    fn in_guest(&self) -> bool {
        self.in_guest.load(Ordering::Relaxed)
    }
    fn stop_in_guest(&self) {
        // Only the vCPU: a holder that sleeps without giving its core up waits for a
        // vCPU or a kernel lock, which waking it would not hurry.
        self.kick_vcpu();
    }
    fn wait_turn<'a, T>(&self, cv: &Condvar, g: MutexGuard<'a, T>, timeout: Duration) -> MutexGuard<'a, T> {
        // Only dying ends it: a signal can't be handled until the thread runs.
        self.wait_for_turn(cv, g, timeout)
    }
}

/// One place per core Android was given. Unlike the vCPU pools', a thread waiting here
/// may hold a vCPU, which it does not give back for this.
struct Cores<R: Runner = Thread> {
    n: usize,
    st: Mutex<CoresState<R>>,
    /// Threads in line, and how many of them in display work's: read without the lock on
    /// every way into the guest. A thread leaves the count as it is handed a core.
    waiting: AtomicUsize,
    waiting_display: AtomicUsize,
    /// Times a thread waited in line, for wakeup_stats.
    waits: AtomicU64,
}

/// A thread holding a core.
struct Held<R> {
    who: Arc<R>,
    /// Since when, for the first in line to stop those that have held theirs longest.
    since: Instant,
    /// Display work that made way for the rest or yielded to them: it counts as the rest
    /// until it next blocks.
    spent: bool,
}

impl<R: Runner> Held<R> {
    fn display(&self) -> bool {
        !self.spent && self.who.is_display()
    }
}

/// A thread in line for a core.
struct Waiter<R> {
    ticket: u64,
    cv: Arc<Condvar>,
    who: Arc<R>,
    spent: bool,
    /// When it got in line: the rest's first goes first after REST_WAIT.
    since: Instant,
}

struct CoresState<R> {
    next: u64,
    used: usize,
    holders: HashMap<u64, Held<R>>,
    /// Two lines, each served in order: display work's goes first.
    display: VecDeque<Waiter<R>>,
    rest: VecDeque<Waiter<R>>,
    /// Cores handed to threads that were in line, by ticket, as (place id, since): each
    /// finds its own here when it wakes.
    handed: HashMap<u64, (u64, Instant)>,
    /// The rest went first, being due, while display work waited: the next core is
    /// display work's. Under load both lines stay full and the rest's first is always
    /// due, so without turns display work would wait for good in its place.
    rest_went: bool,
    /// REST_WAIT, but for tests, which need it not to pass while they look.
    rest_wait: Duration,
}

impl<R> CoresState<R> {
    /// The first of the rest has waited REST_WAIT behind display work at `now`: it goes
    /// first. Each decision reads the clock once and asks all of these at that `now`,
    /// so who is first and who is due agree.
    fn rest_due(&self, now: Instant) -> bool {
        let display_owed = self.rest_went && !self.display.is_empty();
        !display_owed && self.rest.front().is_some_and(|w| now.saturating_duration_since(w.since) >= self.rest_wait)
    }

    fn first(&self, now: Instant) -> Option<&Waiter<R>> {
        if self.rest_due(now) { self.rest.front() } else { self.display.front().or(self.rest.front()) }
    }

    /// The first in line is display work's.
    fn first_is_display(&self, now: Instant) -> bool {
        !self.rest_due(now) && !self.display.is_empty()
    }

    /// Wakes whoever is first, to stop holders for its turn, and the first of the rest,
    /// to look at when it is due: either may have changed, and one asleep behind the
    /// other would otherwise not know until its sleep ends.
    fn wake_first(&self, now: Instant) {
        if let Some(w) = self.first(now) {
            w.cv.notify_one();
        }
        if let Some(w) = self.rest.front() {
            w.cv.notify_one();
        }
    }

    fn free(&self, n: usize) -> bool {
        self.used < n
    }

    fn hold(&mut self, who: &Arc<R>, spent: bool) -> (u64, Instant) {
        self.next += 1;
        self.used += 1;
        let since = Instant::now();
        self.holders.insert(self.next, Held { who: who.clone(), since, spent });
        (self.next, since)
    }
}

impl<R: Runner> Cores<R> {
    fn new(n: usize) -> Self {
        Self::waiting_rest(n, REST_WAIT)
    }

    /// Tests: the rest come due after `wait` from now on, as if the clock had moved.
    #[cfg(test)]
    fn set_rest_wait(&self, wait: Duration) {
        self.st.lock().unwrap().rest_wait = wait;
    }

    /// A gate whose rest wait `rest_wait` before they go first (REST_WAIT but in tests).
    fn waiting_rest(n: usize, rest_wait: Duration) -> Self {
        Cores {
            n: n.max(1),
            st: Mutex::new(CoresState { next: 0, used: 0, holders: HashMap::new(), display: VecDeque::new(), rest: VecDeque::new(), handed: HashMap::new(), rest_went: false, rest_wait }),
            waiting: AtomicUsize::new(0),
            waiting_display: AtomicUsize::new(0),
            waits: AtomicU64::new(0),
        }
    }

    /// Takes a place now if one is free and nobody is in line for it: its id, and since
    /// when. `spent`: display work that is to count as the rest (Held::spent).
    fn try_take(&self, who: &Arc<R>, spent: bool) -> Option<(u64, Instant)> {
        let mut st = self.st.lock().unwrap();
        (st.free(self.n) && st.first(Instant::now()).is_none()).then(|| st.hold(who, spent))
    }

    /// Takes a place, waiting in line for one: its id and since when, or None if the
    /// thread is dying. `spent`: display work that is to wait and count as the rest.
    /// `vcpu`: it waits keeping its vCPU, which this gives up if the whole pool asks for
    /// it meanwhile, keeping its turn.
    fn take(&self, who: &Arc<R>, spent: bool, mut vcpu: Option<&mut dyn FnMut()>) -> Option<(u64, Instant)> {
        let mut st = self.st.lock().unwrap();
        // Read under the lock: an urgency changed after this moves the waiter
        // (reclassify, which takes the lock); one changed before is seen here.
        let display = !spent && who.is_display();
        if who.is_dying() {
            return None;
        }
        if st.free(self.n) && st.first(Instant::now()).is_none() {
            return Some(st.hold(who, spent));
        }
        st.next += 1;
        let ticket = st.next;
        let cv = Arc::new(Condvar::new());
        let w = Waiter { ticket, cv: cv.clone(), who: who.clone(), spent, since: Instant::now() };
        if display {
            st.display.push_back(w);
            self.waiting_display.fetch_add(1, Ordering::Relaxed);
        } else {
            st.rest.push_back(w);
        }
        self.waiting.fetch_add(1, Ordering::Relaxed);
        self.waits.fetch_add(1, Ordering::Relaxed);
        loop {
            if who.is_dying() {
                match st.handed.remove(&ticket) {
                    // Handed one as it died: on to the next in line.
                    Some((id, _)) => self.give_up(&mut st, id, Instant::now()),
                    None => self.leave_line(&mut st, ticket),
                }
                return None;
            }
            if let Some(got) = st.handed.remove(&ticket) {
                return Some(got);
            }
            if who.asked_for_vcpu()
                && let Some(give_up) = vcpu.take()
            {
                // Not under the lock: destroying a vCPU takes a while.
                drop(st);
                give_up();
                st = self.st.lock().unwrap();
                continue;
            }
            let now = Instant::now();
            let first = st.first(now).is_some_and(|w| w.ticket == ticket);
            if first {
                // Holders that run guest code without exits would never come to the
                // door: stop as many as there are in line of its kind, of those that
                // should make way for it.
                let first_display = st.first_is_display(now);
                let n = if first_display { st.display.len() } else { st.rest.len() };
                let holders = st.holders.iter().filter(|(_, h)| h.who.in_guest()).map(|(id, h)| (*id, h.display(), now.saturating_duration_since(h.since))).collect();
                for id in to_kick(holders, first_display, n) {
                    st.holders[&id].who.stop_in_guest();
                }
            }
            // The first of the rest, behind display work, looks again when it is due to
            // go first, to stop holders for its turn then. Once due, it is woken when it
            // is first (serve's wake_first), so it doesn't wake meanwhile.
            let due = st.rest.front().filter(|w| w.ticket == ticket).and_then(|w| st.rest_wait.checked_sub(now.saturating_duration_since(w.since))).filter(|d| !d.is_zero());
            st = who.wait_turn(&cv, st, if first { SLICE / 2 } else { due.unwrap_or(super::IDLE) });
        }
    }

    /// Takes the thread with `ticket` out of its line, unserved: whichever line it is in
    /// now, as `reclassify` may have moved it.
    fn leave_line(&self, st: &mut CoresState<R>, ticket: u64) {
        if let Some(at) = st.display.iter().position(|w| w.ticket == ticket) {
            st.display.remove(at);
            self.waiting_display.fetch_sub(1, Ordering::Relaxed);
        } else if let Some(at) = st.rest.iter().position(|w| w.ticket == ticket) {
            st.rest.remove(at);
        } else {
            return;
        }
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        // Someone else may be first now, to stop holders for its turn.
        st.wake_first(Instant::now());
    }

    /// `who`'s urgency changed while it may wait in line (sched_setscheduler, setpriority,
    /// a cgroup move by another thread): it moves to the line it now belongs in, at its
    /// place by when it came (its ticket), as Linux requeues a task whose class changes.
    /// Display work that made way for the rest stays with the rest (Held::spent).
    fn reclassify(&self, who: *const R) {
        let mut st = self.st.lock().unwrap();
        let in_display = st.display.iter().position(|w| Arc::as_ptr(&w.who) == who);
        let in_rest = st.rest.iter().position(|w| Arc::as_ptr(&w.who) == who);
        let w = match (in_display, in_rest) {
            (Some(at), _) => {
                if st.display[at].who.is_display() {
                    return;
                }
                self.waiting_display.fetch_sub(1, Ordering::Relaxed);
                st.display.remove(at)
            }
            (None, Some(at)) => {
                let w = &st.rest[at];
                if w.spent || !w.who.is_display() {
                    return;
                }
                self.waiting_display.fetch_add(1, Ordering::Relaxed);
                st.rest.remove(at)
            }
            (None, None) => return,
        };
        let Some(w) = w else { return };
        let to = if in_display.is_some() { &mut st.rest } else { &mut st.display };
        let at = to.iter().position(|x| x.ticket > w.ticket).unwrap_or(to.len());
        to.insert(at, w);
        // Who is first may have changed: it stops holders for its turn.
        st.wake_first(Instant::now());
    }

    /// Hands free places to the first in line, display work's first. Handed rather than
    /// left free for the first to take when it wakes: meanwhile a thread that comes for
    /// one would find it free, and display work would take it, even display work that
    /// had just given it up.
    fn serve(&self, st: &mut CoresState<R>, now: Instant) {
        let mut served = false;
        while st.free(self.n) {
            let due = st.rest_due(now);
            let display = if due { None } else { st.display.pop_front() };
            if display.is_some() {
                self.waiting_display.fetch_sub(1, Ordering::Relaxed);
            }
            // Display work served: the rest may go first again when due. The rest, being
            // due, ahead of display work: display work's turn next.
            st.rest_went = if display.is_some() { false } else { due && !st.display.is_empty() };
            let Some(w) = display.or_else(|| st.rest.pop_front()).or_else(|| {
                // The rest due first, but none left: display work, then.
                let w = st.display.pop_front();
                if w.is_some() {
                    self.waiting_display.fetch_sub(1, Ordering::Relaxed);
                }
                w
            }) else {
                break;
            };
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            let got = st.hold(&w.who, w.spent);
            st.handed.insert(w.ticket, got);
            w.cv.notify_one();
            served = true;
        }
        if served {
            // Someone else is first now, to stop holders for its turn: at once, not when
            // the one served gets round to waking.
            st.wake_first(now);
        }
    }

    /// Gives up place `id`, under the lock: to the first in line, if anyone is.
    fn give_up(&self, st: &mut CoresState<R>, id: u64, now: Instant) {
        if st.holders.remove(&id).is_some() {
            st.used -= 1;
            self.serve(st, now);
        }
    }

    fn release(&self, id: u64) {
        self.give_up(&mut self.st.lock().unwrap(), id, Instant::now());
    }

    /// Whether a holder that has held its core since `since` may have to give it up now,
    /// at the door, for those in line: give_way decides, under the lock. Read on every
    /// way into the guest: the clock only when someone waits.
    fn should_yield(&self, display: bool, since: Instant) -> bool {
        self.waiting.load(Ordering::Relaxed) > 0 && makes_way(display, since.elapsed(), self.waiting_display.load(Ordering::Relaxed) > 0)
    }

    /// At the door, or at sched_yield if `yielding`: gives up place `id`, held since
    /// `since` by display work or not, to the first in line if it should. Then the holder
    /// waits in line itself: Some(true) if as the rest, being display work that gave way
    /// to the rest only (Held::spent). None: it keeps its place.
    /// Decided under the lock, with the core handed over at once: each thread in line is
    /// owed one holder's place, so holders that come to the door after it was served
    /// keep theirs.
    fn give_way(&self, id: u64, display: bool, since: Instant, yielding: bool) -> Option<bool> {
        let maybe = if yielding { self.waiting.load(Ordering::Relaxed) > 0 } else { self.should_yield(display, since) };
        if !maybe {
            return None;
        }
        let mut st = self.st.lock().unwrap();
        // One `now` for the decision and the hand-off, so the core goes to whom it was
        // given up for.
        let now = Instant::now();
        let first_display = st.first_is_display(now);
        if st.first(now).is_none() || !(yielding || makes_way(display, now.saturating_duration_since(since), first_display)) {
            return None;
        }
        self.give_up(&mut st, id, now);
        Some(display && !first_display)
    }

    fn usage(&self) -> (usize, usize, usize, u64) {
        let used = self.st.lock().unwrap().used;
        (used, self.waiting.load(Ordering::Relaxed), self.n, self.waits.load(Ordering::Relaxed))
    }
}

struct Inner {
    vcpu: Option<Box<dyn Vcpu>>,
    /// The registers while parked (stale while a vCPU is live).
    state: CpuState,
    root: PageTableRoot,
    /// Holder id and entry, while live.
    held: Option<(u64, Arc<Holder>)>,
    /// Holder id in the background pool, while it has a place there.
    gated: Option<u64>,
    /// Its place in the cores gate, and when it took it, while it has one.
    core: Option<(u64, Instant)>,
    /// Display work that gave its core up to the rest (Held::spent): it waits and runs as
    /// the rest until it next blocks.
    spent: bool,
    /// What the host was last told about this thread.
    told: Option<Urgency>,
    /// A TLB flush asked for with no vCPU to ask: the next one does it. A new vCPU
    /// doesn't flush otherwise.
    flush_wanted: bool,
    /// A flush asked of the live vCPU that it may not have run yet: if it is
    /// destroyed first, the next one does it.
    flush_asked: bool,
}

/// One guest thread's vCPU, made and destroyed on its own host thread.
struct Slot {
    hv: Arc<dyn Hypervisor>,
    pool: Arc<Pool>,
    thread: Arc<Thread>,
    inner: RefCell<Inner>,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Slot>>> = const { RefCell::new(None) };
}

impl Slot {
    /// Gets what it needs to run guest code, in the order every thread takes them: a
    /// background place if it is background work, a core if they are gated, then its
    /// vCPU. True if it waited for any or made a vCPU, as things may have changed
    /// meanwhile. On an error it holds neither a core nor a background place.
    fn ensure(&self) -> Result<bool, String> {
        // `|`, not `||`: each step runs, in order.
        let got = (|| -> Result<bool, String> { Ok(self.take_gate()? | self.take_core()? | self.make_vcpu()?) })();
        if got.is_err() {
            self.leave_core();
            self.leave_gate();
        }
        got
    }

    /// Makes the vCPU if there is none: true if it did.
    fn make_vcpu(&self) -> Result<bool, String> {
        let mut i = self.inner.borrow_mut();
        if i.vcpu.is_some() {
            return Ok(false);
        }
        if !self.pool.acquire(&self.thread, || true) {
            return Err("dying".into());
        }
        MADE.fetch_add(1, Ordering::Relaxed);
        let mut v = match self.hv.create_vcpu(i.root, &i.state) {
            Ok(v) => v,
            Err(e) => {
                self.pool.release();
                return Err(e);
            }
        };
        if std::mem::take(&mut i.flush_wanted) {
            v.flush_tlb();
            i.flush_asked = true;
        }
        let held = self.pool.add_holder(&self.thread);
        *self.thread.kick.lock().unwrap() = Some(v.kicker());
        i.held = Some(held);
        i.vcpu = Some(v);
        Ok(true)
    }

    /// The pool this thread must also take a place in, as things stand.
    fn gate(&self) -> Option<&Pool> {
        self.pool.background.as_deref().filter(|_| self.thread.urgency() == Urgency::Background)
    }

    /// Takes a place in the background pool if it is background work and has none: at
    /// once if one is free, else in line. True if it waited.
    fn take_gate(&self) -> Result<bool, String> {
        let Some(g) = self.gate() else { return Ok(false) };
        if self.inner.borrow().gated.is_some() {
            return Ok(false);
        }
        let waited = !g.try_acquire();
        if waited {
            // Not in line with a vCPU or a core: places in the whole pool, and cores,
            // would then wait on background work.
            self.park_vcpu();
            self.leave_core();
            // Waiting in line for a background place can outlast being background.
            if !g.acquire(&self.thread, || self.thread.urgency() == Urgency::Background) {
                return if self.thread.dying.load(Ordering::Acquire) { Err("dying".into()) } else { Ok(true) };
            }
        }
        self.inner.borrow_mut().gated = Some(g.add_holder(&self.thread).0);
        Ok(waited)
    }

    /// Takes a core if they are gated and it has none, after giving its own up if its
    /// turn is up. In line, it keeps its vCPU, unless the whole pool is short of them
    /// or asks for it. True if it waited.
    fn take_core(&self) -> Result<bool, String> {
        let Some(c) = &self.pool.cores else { return Ok(false) };
        let (core, spent) = {
            let i = self.inner.borrow();
            (i.core, i.spent)
        };
        match core {
            Some((id, since)) => match c.give_way(id, !spent && self.thread.urgency() == Urgency::Display, since, false) {
                None => return Ok(false),
                // The first in line has its core now: to the back of its own line. Here
                // at the door it holds no kernel lock.
                Some(gave) => {
                    let mut i = self.inner.borrow_mut();
                    i.core = None;
                    i.spent |= gave;
                }
            },
            None => {
                if let Some(got) = c.try_take(&self.thread, spent) {
                    self.inner.borrow_mut().core = Some(got);
                    return Ok(false);
                }
            }
        }
        let spent = self.inner.borrow().spent;
        let kept = self.idle();
        let mut give_up = || self.park_vcpu();
        let Some(got) = c.take(&self.thread, spent, if kept { Some(&mut give_up) } else { None }) else { return Err("dying".into()) };
        self.inner.borrow_mut().core = Some(got);
        // Awake again, if it kept its vCPU: an ask `reclaim` made of it as it got its
        // core no longer stands.
        self.running();
        Ok(true)
    }

    /// Gives up its core, if it has one.
    fn leave_core(&self) {
        let Some((id, _)) = self.inner.borrow_mut().core.take() else { return };
        self.pool.cores.as_ref().unwrap().release(id);
    }

    /// sched_yield: lets one in line for a core go first, as Linux runs another runnable
    /// thread first (do_sched_yield, kernel/sched/syscalls.c). A thread that spins on
    /// sched_yield waiting for one in line would otherwise hold its core a whole slice.
    /// Display work that yields to the rest only waits as the rest: in its own line it
    /// would be served first and take the core straight back.
    fn yield_core(&self) {
        let Some(c) = &self.pool.cores else { return };
        let mut i = self.inner.borrow_mut();
        let Some((id, since)) = i.core else { return };
        if let Some(gave) = c.give_way(id, !i.spent && self.thread.urgency() == Urgency::Display, since, true) {
            i.core = None;
            i.spent |= gave;
        }
    }

    /// Tells the host how urgent this thread is now.
    fn tell_host(&self) -> Urgency {
        let want = self.thread.urgency();
        let mut i = self.inner.borrow_mut();
        if i.told != Some(want) {
            set_thread_urgency(want);
            i.told = Some(want);
        }
        want
    }

    /// The thread's urgency may have changed, or it slept: tells the host, and gives up
    /// a place in the background pool it no longer needs. ensure() takes one it needs.
    fn follow_urgency(&self) {
        if self.tell_host() != Urgency::Background {
            self.leave_gate();
        }
    }

    /// Gives up its place in the background pool, if it has one.
    fn leave_gate(&self) {
        let Some(id) = self.inner.borrow_mut().gated.take() else { return };
        let g = self.pool.background.as_ref().unwrap();
        g.st.lock().unwrap().holders.remove(&id);
        g.release();
    }

    /// Going to sleep in the kernel.
    fn blocking(&self) {
        // Asleep, it uses no core.
        self.leave_gate();
        self.leave_core();
        // Display work that gave way to the rest is display work again when it wakes.
        self.inner.borrow_mut().spent = false;
        self.idle();
    }

    /// About to wait with nothing to run: gives the vCPU back if another thread is
    /// waiting for a place, places are low, or it was asked to; else keeps it, noted
    /// for `reclaim`. True if it kept one.
    fn idle(&self) -> bool {
        let asked = self.thread.give_back.swap(false, Ordering::Relaxed);
        if asked || self.pool.waiting.load(Ordering::Relaxed) > 0 || self.pool.low() {
            self.park_vcpu();
            return false;
        }
        // Kept: noted for `reclaim`, from the first time it blocks in this syscall.
        let i = self.inner.borrow();
        if let Some((_, h)) = &i.held
            && h.asleep.load(Ordering::Relaxed) == 0
        {
            h.asleep.store(self.pool.now_ns(), Ordering::Relaxed);
        }
        i.vcpu.is_some()
    }

    /// About to run guest code: no longer asleep, nor asked to give its vCPU back
    /// because it was, and its slice starts again.
    fn running(&self) {
        if let Some((_, h)) = &self.inner.borrow().held
            && h.asleep.load(Ordering::Relaxed) != 0
        {
            h.asleep.store(0, Ordering::Relaxed);
            h.run_since.store(self.pool.now_ns(), Ordering::Relaxed);
            // Pairs with the one in `reclaim`.
            fence(Ordering::SeqCst);
            self.thread.give_back.store(false, Ordering::Relaxed);
        }
    }

    /// Gives up its vCPU, and its background place with it.
    fn park(&self) {
        self.park_vcpu();
        self.leave_gate();
    }

    /// Gives up its vCPU only: a core or a background place it keeps.
    fn park_vcpu(&self) {
        let mut i = self.inner.borrow_mut();
        let Some(v) = i.vcpu.take() else { return };
        i.state = v.state();
        i.flush_wanted |= std::mem::take(&mut i.flush_asked);
        if let Some((id, _)) = i.held.take() {
            self.pool.st.lock().unwrap().holders.remove(&id);
            // Its place is given back, so any ask is answered. One can come in as it
            // leaves (`reclaim` read it asleep in an earlier sleep of this syscall), but
            // only under the pool's lock, which the removal waited for; none can come
            // now. Left set, it would make the next vCPU's first sleep give it up too.
            self.thread.give_back.store(false, Ordering::Relaxed);
        }
        *self.thread.kick.lock().unwrap() = None;
        drop(v); // destroyed on the thread that owns it
        self.pool.release();
    }

    /// Whether others are waiting for what this thread holds. Not those in line for a
    /// core: it gives that up at the door (`take_core`), keeping its vCPU.
    fn wanted(&self) -> bool {
        let gated = self.inner.borrow().gated.is_some();
        self.pool.waiting.load(Ordering::Relaxed) > 0 || (gated && self.pool.background.as_ref().is_some_and(|g| g.waiting.load(Ordering::Relaxed) > 0))
    }

    /// After an exit: give the vCPU up if others wait for one and it has run a slice.
    fn maybe_yield(&self) {
        if !self.wanted() {
            return;
        }
        let held_long = self.inner.borrow().held.as_ref().is_some_and(|(_, h)| self.pool.ran_slice(h));
        if held_long {
            self.park();
        }
    }
}

/// The guest thread's vCPU handle (implements `Vcpu`; dropped when the thread ends).
pub struct LazyVcpu(Rc<Slot>);

impl LazyVcpu {
    pub fn new(hv: Arc<dyn Hypervisor>, pool: Arc<Pool>, thread: Arc<Thread>, root: PageTableRoot, state: CpuState) -> LazyVcpu {
        let slot = Rc::new(Slot { hv, pool, thread, inner: RefCell::new(Inner { vcpu: None, state, root, held: None, gated: None, core: None, spent: false, told: None, flush_wanted: false, flush_asked: false }) });
        CURRENT.with(|c| *c.borrow_mut() = Some(slot.clone()));
        LazyVcpu(slot)
    }
}

impl Drop for LazyVcpu {
    fn drop(&mut self) {
        self.0.park();
        self.0.leave_core();
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

/// Called by blocking waits, before each sleep: gives up the current thread's core and
/// background place, and hands its vCPU back if another thread is waiting for a place,
/// places are low, or it was asked to.
pub fn blocking() {
    CURRENT.with(|c| {
        if let Some(s) = c.borrow().as_ref() {
            s.blocking();
        }
    });
}

/// sched_yield: lets a thread in line for a core have the current thread's.
pub fn yielding() {
    CURRENT.with(|c| {
        if let Some(s) = c.borrow().as_ref() {
            s.yield_core();
        }
    });
}

/// Wakes a thread asleep in the kernel, without stopping it if it runs guest code
/// (as `Thread::kick` would): it was asked for its vCPU because it slept.
fn nudge(th: &Thread) {
    th.wake_sleeper();
    let slot = th.event_slot.load(Ordering::Relaxed);
    if slot != usize::MAX {
        super::wait::EVENTS.wake_slot(slot);
    }
}

impl Vcpu for LazyVcpu {
    fn run(&mut self) -> Exit {
        if self.0.pool.frozen.load(Ordering::Acquire) {
            // It will never run again: a syscall under way may still want its core.
            self.0.leave_core();
            while self.0.pool.frozen.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.0.follow_urgency();
        match self.0.ensure() {
            Err(e) => return if e == "dying" { Exit::Interrupted } else { Exit::Fault { pc: 0, addr: 0, detail: e } },
            Ok(true) => {
                // It may have waited: for a new urgency to take effect, or for a signal
                // or exit that was sent when there was no vCPU to kick. Any sent from
                // here on find this one.
                self.0.tell_host();
                let t = &self.0.thread;
                if t.interrupted() || self.0.pool.frozen.load(Ordering::Acquire) {
                    return Exit::Interrupted;
                }
            }
            Ok(false) => {}
        }
        self.0.running();
        // Only the cores gate reads it, for whom to kick: with no gate, nothing changes.
        let gated = self.0.pool.cores.is_some();
        let exit = {
            let mut i = self.0.inner.borrow_mut();
            if gated {
                self.0.thread.in_guest.store(true, Ordering::Relaxed);
            }
            let exit = i.vcpu.as_mut().unwrap().run();
            if gated {
                self.0.thread.in_guest.store(false, Ordering::Relaxed);
            }
            // It went in, and through any flush asked for.
            if !matches!(exit, Exit::Interrupted) {
                i.flush_asked = false;
            }
            exit
        };
        self.0.maybe_yield();
        exit
    }

    fn syscall_regs(&self) -> SyscallRegs {
        let i = self.0.inner.borrow();
        match &i.vcpu {
            Some(v) => v.syscall_regs(),
            None => i.state.syscall_regs(),
        }
    }

    fn set_syscall_return(&mut self, value: u64) {
        let mut i = self.0.inner.borrow_mut();
        match &mut i.vcpu {
            Some(v) => v.set_syscall_return(value),
            None => i.state.set_return(value),
        }
    }

    fn state(&self) -> CpuState {
        let i = self.0.inner.borrow();
        match &i.vcpu {
            Some(v) => v.state(),
            None => i.state.clone(),
        }
    }

    fn set_state(&mut self, state: &CpuState) {
        let mut i = self.0.inner.borrow_mut();
        match &mut i.vcpu {
            Some(v) => v.set_state(state),
            None => i.state = state.clone(),
        }
    }

    fn set_page_tables(&mut self, root: PageTableRoot) {
        let mut i = self.0.inner.borrow_mut();
        i.root = root;
        if let Some(v) = &mut i.vcpu {
            v.set_page_tables(root);
        }
    }

    fn flush_tlb(&mut self) {
        let mut i = self.0.inner.borrow_mut();
        match &mut i.vcpu {
            Some(v) => {
                v.flush_tlb();
                i.flush_asked = true;
            }
            None => i.flush_wanted = true,
        }
    }

    fn flush_tlb_page(&mut self, va: u64) {
        let mut i = self.0.inner.borrow_mut();
        match &mut i.vcpu {
            Some(v) => {
                v.flush_tlb_page(va);
                i.flush_asked = true;
            }
            None => i.flush_wanted = true,
        }
    }

    fn flush_tlb_now(&mut self) {
        // ready() came first, but keep to what a parked thread can do: the next
        // vCPU flushes on its first entry, and nothing else here is on the way.
        let mut i = self.0.inner.borrow_mut();
        match &mut i.vcpu {
            Some(v) => v.flush_tlb_now(),
            None => i.flush_wanted = true,
        }
    }

    fn ready(&mut self) -> bool {
        self.0.ensure().is_ok()
    }

    fn kicker(&self) -> Arc<dyn Kick> {
        unreachable!("the slot keeps Thread::kick up to date")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// For tests of the order the lines alone give: the rest never come due while they
    /// look, however slowly the test runs.
    const NEVER_DUE: Duration = Duration::from_secs(3600);

    /// A thread as the cores gate sees it, with no kernel behind it.
    #[derive(Default)]
    struct Fake {
        display: AtomicBool,
        dying: AtomicBool,
        asked: AtomicBool,
        /// Running guest code: a holder spins there unless a test says otherwise.
        in_guest: AtomicBool,
        kicks: AtomicUsize,
    }

    impl Fake {
        fn new(display: bool) -> Arc<Fake> {
            Arc::new(Fake { display: AtomicBool::new(display), in_guest: AtomicBool::new(true), ..Default::default() })
        }

        fn set_display(&self, display: bool) {
            self.display.store(display, Ordering::Relaxed);
        }
    }

    impl Runner for Fake {
        fn is_display(&self) -> bool {
            self.display.load(Ordering::Relaxed)
        }
        fn is_dying(&self) -> bool {
            self.dying.load(Ordering::Relaxed)
        }
        fn asked_for_vcpu(&self) -> bool {
            self.asked.load(Ordering::Relaxed)
        }
        fn in_guest(&self) -> bool {
            self.in_guest.load(Ordering::Relaxed)
        }
        fn stop_in_guest(&self) {
            self.kicks.fetch_add(1, Ordering::Relaxed);
        }
        fn wait_turn<'a, T>(&self, cv: &Condvar, g: MutexGuard<'a, T>, timeout: Duration) -> MutexGuard<'a, T> {
            // Nothing wakes a fake when its flags change, so it looks again soon.
            cv.wait_timeout(g, timeout.min(Duration::from_millis(2))).unwrap().0
        }
    }

    /// Waits for `f` to hold, failing after 10 seconds.
    fn until(f: impl Fn() -> bool) {
        let start = Instant::now();
        while !f() {
            assert!(start.elapsed() < Duration::from_secs(10), "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Puts `who` in line for a core on a thread of its own, once no core is free:
    /// returns when it is in line. The thread ends with the place it gets.
    fn queue(gate: &Arc<Cores<Fake>>, who: &Arc<Fake>, spent: bool) -> std::thread::JoinHandle<Option<(u64, Instant)>> {
        let before = gate.waits.load(Ordering::Relaxed);
        let (g, who) = (gate.clone(), who.clone());
        let j = std::thread::spawn(move || g.take(&who, spent, None));
        until(|| gate.waits.load(Ordering::Relaxed) > before);
        j
    }

    #[test]
    fn cores_are_gated_only_when_fewer_than_the_host_has() {
        assert!(cores_gate(8, 8).is_none());
        assert!(cores_gate(12, 8).is_none());
        assert_eq!(cores_gate(4, 8).map(|c| c.n), Some(4));
        assert_eq!(cores_gate(1, 8).map(|c| c.n), Some(1));
    }

    #[test]
    fn who_makes_way() {
        let ms = Duration::from_millis;
        // For display work: other work at once, display work after a slice.
        assert!(makes_way(false, ms(0), true));
        assert!(!makes_way(true, ms(0), true));
        assert!(makes_way(true, SLICE, true));
        // For other work: other work after a slice, display work after a long one.
        assert!(!makes_way(false, SLICE - ms(1), false));
        assert!(makes_way(false, SLICE, false));
        assert!(!makes_way(true, SLICE, false));
        assert!(makes_way(true, DISPLAY_SLICE, false));
    }

    #[test]
    fn the_first_in_line_stops_those_that_should_make_way_longest_held_first() {
        let ms = Duration::from_millis;
        let holders = vec![(1, false, ms(1)), (2, false, ms(30)), (3, true, ms(5)), (4, false, ms(20)), (5, true, ms(60))];
        assert_eq!(to_kick(holders.clone(), true, 2), [5, 2]);
        assert_eq!(to_kick(holders.clone(), true, 9), [5, 2, 4, 1]);
        assert_eq!(to_kick(holders.clone(), false, 9), [5, 2, 4]);
        assert_eq!(to_kick(holders.clone(), false, 1), [5]);
        assert!(to_kick(holders, false, 0).is_empty());
    }

    #[test]
    fn places_are_counted() {
        let gate = Cores::<Fake>::waiting_rest(2, NEVER_DUE);
        let (a, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let (b, _) = gate.try_take(&Fake::new(false), false).unwrap();
        assert_eq!(gate.try_take(&Fake::new(true), false), None);
        let long_ago = Instant::now() - Duration::from_secs(1);
        assert!(!gate.should_yield(false, long_ago), "nobody waits");
        assert_eq!(gate.give_way(b, false, long_ago, false), None);
        assert_eq!(gate.give_way(b, true, long_ago, true), None);
        gate.release(a);
        assert!(gate.try_take(&Fake::new(false), false).is_some());
        assert_eq!(gate.usage().0, 2);
        // A place given back twice is given back once.
        gate.release(a);
        assert_eq!(gate.usage().0, 2);
    }

    #[test]
    fn display_work_goes_first_and_the_rest_in_turn() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let holder = Fake::new(false);
        let (id, _) = gate.try_take(&holder, false).unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut joins = Vec::new();
        for (name, display) in [("a", false), ("b", false), ("c", true)] {
            let (g, order) = (gate.clone(), order.clone());
            let before = gate.waits.load(Ordering::Relaxed);
            joins.push(std::thread::spawn(move || {
                let (id, _) = g.take(&Fake::new(display), false, None).expect("a place");
                order.lock().unwrap().push(name);
                g.release(id);
            }));
            until(|| gate.waits.load(Ordering::Relaxed) == before + 1);
        }
        // Display work in line: the holder is stopped, and makes way at its door.
        until(|| holder.kicks.load(Ordering::Relaxed) > 0);
        assert!(gate.should_yield(false, Instant::now()));
        assert!(!gate.should_yield(true, Instant::now()));
        assert_eq!(gate.give_way(id, false, Instant::now(), false), Some(false));
        for j in joins {
            j.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), ["c", "a", "b"]);
        assert_eq!((gate.waiting.load(Ordering::Relaxed), gate.waiting_display.load(Ordering::Relaxed)), (0, 0));
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn a_core_given_up_goes_straight_to_the_first_in_line() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (id, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let first = queue(&gate, &Fake::new(false), false);
        gate.release(id);
        // Display work that comes for it before the one in line has woken waits too,
        // though it would go first.
        let late = queue(&gate, &Fake::new(true), false);
        until(|| first.is_finished());
        let (got, _) = first.join().unwrap().expect("the core");
        assert_eq!(gate.waiting_display.load(Ordering::Relaxed), 1, "still in line");
        gate.release(got);
        let (got, _) = late.join().unwrap().expect("the core next");
        gate.release(got);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn display_work_that_made_way_for_the_rest_waits_as_the_rest() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let display = Fake::new(true);
        let (id, _) = gate.try_take(&display, false).unwrap();
        let r = queue(&gate, &Fake::new(false), false);
        // Only the rest wait: display work keeps its core a long slice, then makes way.
        assert_eq!(gate.give_way(id, true, Instant::now(), false), None);
        assert_eq!(gate.give_way(id, true, Instant::now() - DISPLAY_SLICE, false), Some(true));
        until(|| r.is_finished());
        let (got, _) = r.join().unwrap().expect("the core");
        // Spent, it waits in the rest's line, so the holder keeps its core a slice: had
        // it gone first, the holder would make way at once.
        let d = queue(&gate, &display, true);
        assert_eq!(gate.waiting_display.load(Ordering::Relaxed), 0);
        assert!(!gate.should_yield(false, Instant::now()));
        assert_eq!(gate.give_way(got, false, Instant::now(), false), None);
        assert_eq!(gate.give_way(got, false, Instant::now() - SLICE, false), Some(false));
        let (got, _) = d.join().unwrap().expect("the core");
        gate.release(got);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn the_rest_go_first_once_they_have_waited_behind_display_work() {
        // One core, and two display threads that would hand it to and fro.
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (one, two) = (Fake::new(true), Fake::new(true));
        let (id, _) = gate.try_take(&one, false).unwrap();
        let d = queue(&gate, &two, false);
        let r = queue(&gate, &Fake::new(false), false);
        // At first display work goes first: the core goes to the other display thread.
        assert_eq!(gate.give_way(id, true, Instant::now() - SLICE, false), Some(false));
        let (id, _) = d.join().unwrap().expect("the core");
        let d = queue(&gate, &one, false);
        assert!(!r.is_finished());
        // Once the rest have waited REST_WAIT, they go first: display work that has held
        // its core for DISPLAY_SLICE makes way for them, not for the display thread.
        gate.set_rest_wait(Duration::ZERO);
        // Taken "from now on" so that no pause of this test ages it past its slice.
        assert_eq!(gate.give_way(id, true, Instant::now() + Duration::from_secs(60), false), None, "not before its long slice");
        assert_eq!(gate.give_way(id, true, Instant::now() - DISPLAY_SLICE, false), Some(true));
        let (id, _) = r.join().unwrap().expect("the core");
        assert!(!d.is_finished());
        gate.release(id);
        let (id, _) = d.join().unwrap().expect("the core");
        gate.release(id);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn the_rest_due_and_display_work_take_turns_when_both_wait() {
        // One core, the rest always due (they waited REST_WAIT), display work waiting too:
        // the core goes to each in turn, so neither waits for good.
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (mut id, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let r1 = queue(&gate, &Fake::new(false), false);
        let r2 = queue(&gate, &Fake::new(false), false);
        gate.set_rest_wait(Duration::ZERO);
        let d = queue(&gate, &Fake::new(true), false);
        // The rest's first is due: it goes first, ahead of display work.
        gate.release(id);
        (id, _) = r1.join().unwrap().expect("the core");
        assert!(!d.is_finished());
        // Then display work, though the rest's next is due as well.
        gate.release(id);
        (id, _) = d.join().unwrap().expect("the core");
        assert!(!r2.is_finished());
        gate.release(id);
        let (id, _) = r2.join().unwrap().expect("the core");
        gate.release(id);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn a_waiter_whose_urgency_changes_moves_to_its_new_line_in_its_turn() {
        // The rest never come due here: the order is the lines' alone.
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (id, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let early = Fake::new(false);
        let r1 = queue(&gate, &early, false);
        let promoted = Fake::new(false);
        let r2 = queue(&gate, &promoted, false);
        // Made display work while it waits: it goes ahead of the rest.
        promoted.set_display(true);
        gate.reclassify(Arc::as_ptr(&promoted));
        assert_eq!(gate.waiting_display.load(Ordering::Relaxed), 1);
        gate.release(id);
        until(|| r2.is_finished());
        let (id, _) = r2.join().unwrap().expect("the core");
        assert!(!r1.is_finished());
        // And back: a waiter no longer display work goes back among the rest.
        let back = Fake::new(true);
        let r3 = queue(&gate, &back, false);
        back.set_display(false);
        gate.reclassify(Arc::as_ptr(&back));
        assert_eq!(gate.waiting_display.load(Ordering::Relaxed), 0);
        // In order of coming: the earlier waiter first.
        gate.release(id);
        until(|| r1.is_finished());
        let (id, _) = r1.join().unwrap().expect("the core");
        assert!(!r3.is_finished());
        gate.release(id);
        until(|| r3.is_finished());
        let (id, _) = r3.join().unwrap().expect("the core");
        gate.release(id);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn sched_yield_lets_the_first_in_line_go_first() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (id, _) = gate.try_take(&Fake::new(true), false).unwrap();
        let now = Instant::now();
        assert_eq!(gate.give_way(id, true, now, true), None, "nobody waits");
        // Display work that yields to the rest only waits as the rest.
        let r = queue(&gate, &Fake::new(false), false);
        assert_eq!(gate.give_way(id, true, now, true), Some(true));
        let (id, _) = r.join().unwrap().expect("the core");
        // To display work, the rest yields, and display work stays display work.
        let d = queue(&gate, &Fake::new(true), false);
        assert_eq!(gate.give_way(id, false, now, true), Some(false));
        let (id, _) = d.join().unwrap().expect("the core");
        let d = queue(&gate, &Fake::new(true), false);
        assert_eq!(gate.give_way(id, true, now, true), Some(false));
        let (id, _) = d.join().unwrap().expect("the core");
        gate.release(id);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn only_holders_in_guest_code_are_stopped() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(2, NEVER_DUE));
        // Held longest, but in the kernel: it comes to the door by itself.
        let in_kernel = Fake::new(false);
        in_kernel.in_guest.store(false, Ordering::Relaxed);
        let (a, _) = gate.try_take(&in_kernel, false).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let spinning = Fake::new(false);
        let (b, _) = gate.try_take(&spinning, false).unwrap();
        // One kick for one in line: the holder in guest code gets it.
        let w = queue(&gate, &Fake::new(true), false);
        until(|| spinning.kicks.load(Ordering::Relaxed) > 0);
        assert_eq!(in_kernel.kicks.load(Ordering::Relaxed), 0);
        assert_eq!(gate.give_way(b, false, Instant::now(), false), Some(false));
        let (got, _) = w.join().unwrap().expect("the core");
        gate.release(got);
        gate.release(a);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn as_many_holders_make_way_for_display_work_as_wait() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(3, NEVER_DUE));
        let held: Vec<u64> = (0..3).map(|_| gate.try_take(&Fake::new(false), false).unwrap().0).collect();
        let waiters = [queue(&gate, &Fake::new(true), false), queue(&gate, &Fake::new(true), false)];
        let now = Instant::now();
        // Each holder that comes to the door serves one in line: the third finds nobody
        // left and keeps its core.
        assert_eq!(gate.give_way(held[0], false, now, false), Some(false));
        assert_eq!(gate.give_way(held[1], false, now, false), Some(false));
        assert!(!gate.should_yield(false, now));
        assert_eq!(gate.give_way(held[2], false, now, false), None);
        for w in waiters {
            gate.release(w.join().unwrap().expect("a core").0);
        }
        gate.release(held[2]);
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn dying_ends_a_wait() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (id, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let dying = Fake::new(false);
        let d = queue(&gate, &dying, false);
        dying.dying.store(true, Ordering::Relaxed);
        assert_eq!(d.join().unwrap(), None);
        assert_eq!(gate.waiting.load(Ordering::Relaxed), 0);
        gate.release(id);
        assert!(gate.try_take(&Fake::new(false), false).is_some(), "nobody left in line");
    }

    #[test]
    fn an_ask_for_the_vcpu_a_waiter_keeps_costs_it_the_vcpu_but_not_its_turn() {
        let gate = Arc::new(Cores::<Fake>::waiting_rest(1, NEVER_DUE));
        let (id, _) = gate.try_take(&Fake::new(false), false).unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let gave_up = Arc::new(AtomicUsize::new(0));
        let (first, second) = (Fake::new(false), Fake::new(false));
        let mut joins = Vec::new();
        for (name, who, with_vcpu) in [("first", first.clone(), true), ("second", second.clone(), false)] {
            let (g, order, gave_up) = (gate.clone(), order.clone(), gave_up.clone());
            let before = gate.waiting.load(Ordering::Relaxed);
            joins.push(std::thread::spawn(move || {
                let mut give_up = || {
                    gave_up.fetch_add(1, Ordering::Relaxed);
                };
                let (id, _) = g.take(&who, false, if with_vcpu { Some(&mut give_up) } else { None }).expect("a place");
                order.lock().unwrap().push(name);
                g.release(id);
            }));
            until(|| gate.waiting.load(Ordering::Relaxed) == before + 1);
        }
        // Both asked: only the one with a vCPU has one to give up, and does so once.
        first.asked.store(true, Ordering::Relaxed);
        second.asked.store(true, Ordering::Relaxed);
        until(|| gave_up.load(Ordering::Relaxed) == 1);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(gave_up.load(Ordering::Relaxed), 1);
        assert_eq!(gate.waiting.load(Ordering::Relaxed), 2, "both still in line");
        gate.release(id);
        for j in joins {
            j.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), ["first", "second"]);
    }
}
