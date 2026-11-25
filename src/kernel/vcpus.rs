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
//! its CPU through its syscalls; it gives it up when it blocks, at sched_yield, and at
//! the door once others wait and its turn is up. Display work goes first, as Linux
//! runs real-time threads before the rest. A thread waiting for a core keeps its vCPU,
//! marked asleep so the whole pool can still ask for it: destroying and making one
//! costs far more than the wait. With as many cores as the host, there is no gate.
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

/// How long display work keeps a core while only other work waits for one. Linux's
/// real-time throttling keeps a share of every second for the rest
/// (sched_rt_runtime_us, kernel/sched/rt.c) so that a real-time thread that spins
/// cannot shut them out; this does the same for a display thread.
const DISPLAY_SLICE: Duration = Duration::from_millis(50);

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
        let background = Pool::sized((cores / 2).max(2), None, None);
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

/// Whether a thread that has held its core for `held` makes way for the first in line:
/// gives its core up at its next way into the guest, and gets in line itself.
fn makes_way(holder_display: bool, held: Duration, first_display: bool) -> bool {
    match (holder_display, first_display) {
        // At once, as a real-time thread that wakes preempts a fair one on Linux
        // (wakeup_preempt, kernel/sched/core.c): late display work shows on the screen.
        (false, true) => true,
        // Turns among their like, a slice each, as SCHED_RR's and CFS's.
        (true, true) | (false, false) => held >= SLICE,
        (true, false) => held >= DISPLAY_SLICE,
    }
}

/// Which holders, as (id, display work, held for), the first in line stops so that they
/// come to the door and make way: those that would, longest held first, `n` at most.
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
    /// Threads in line, and how many of them are display work: read without the lock on
    /// every way into the guest.
    waiting: AtomicUsize,
    waiting_display: AtomicUsize,
    /// Times a thread waited in line, for wakeup_stats.
    waits: AtomicU64,
}

struct CoresState<R> {
    next: u64,
    used: usize,
    /// Who holds a place, and since when, for the first in line to stop them.
    holders: HashMap<u64, (Arc<R>, Instant)>,
    /// Two lines, each served in order: display work's goes first.
    display: VecDeque<(u64, Arc<Condvar>)>,
    rest: VecDeque<(u64, Arc<Condvar>)>,
}

impl<R> CoresState<R> {
    fn first(&self) -> Option<&(u64, Arc<Condvar>)> {
        self.display.front().or(self.rest.front())
    }

    fn wake_first(&self) {
        if let Some((_, cv)) = self.first() {
            cv.notify_one();
        }
    }

    fn free(&self, n: usize) -> bool {
        self.used < n
    }

    fn hold(&mut self, who: &Arc<R>) -> u64 {
        self.next += 1;
        self.used += 1;
        self.holders.insert(self.next, (who.clone(), Instant::now()));
        self.next
    }
}

impl<R: Runner> Cores<R> {
    fn new(n: usize) -> Self {
        Cores {
            n: n.max(1),
            st: Mutex::new(CoresState { next: 0, used: 0, holders: HashMap::new(), display: VecDeque::new(), rest: VecDeque::new() }),
            waiting: AtomicUsize::new(0),
            waiting_display: AtomicUsize::new(0),
            waits: AtomicU64::new(0),
        }
    }

    /// Takes a place now if one is free and nobody is in line for it.
    fn try_take(&self, who: &Arc<R>) -> Option<u64> {
        let mut st = self.st.lock().unwrap();
        (st.free(self.n) && st.first().is_none()).then(|| st.hold(who))
    }

    /// Takes a place, waiting in line for one: its id, or None if the thread is dying.
    /// `vcpu`: it waits keeping its vCPU, which this gives up if the whole pool asks for
    /// it meanwhile, keeping its turn.
    fn take(&self, who: &Arc<R>, mut vcpu: Option<&mut dyn FnMut()>) -> Option<u64> {
        let display = who.is_display();
        let mut st = self.st.lock().unwrap();
        if who.is_dying() {
            return None;
        }
        if st.free(self.n) && st.first().is_none() {
            return Some(st.hold(who));
        }
        st.next += 1;
        let ticket = st.next;
        let cv = Arc::new(Condvar::new());
        if display {
            st.display.push_back((ticket, cv.clone()));
            self.waiting_display.fetch_add(1, Ordering::Relaxed);
        } else {
            st.rest.push_back((ticket, cv.clone()));
        }
        self.waiting.fetch_add(1, Ordering::Relaxed);
        self.waits.fetch_add(1, Ordering::Relaxed);
        let took = loop {
            if who.is_dying() {
                break None;
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
            let first = st.first().is_some_and(|(x, _)| *x == ticket);
            if first && st.free(self.n) {
                break Some(st.hold(who));
            }
            if first {
                // Holders that run guest code without exits would never come to the
                // door: stop as many as there are in line of its kind, of those that
                // should make way for it. Those in the kernel get there by themselves.
                let first_display = !st.display.is_empty();
                let n = if first_display { st.display.len() } else { st.rest.len() };
                let now = Instant::now();
                let holders = st.holders.iter().map(|(id, (r, since))| (*id, r.is_display(), now.saturating_duration_since(*since))).collect();
                for id in to_kick(holders, first_display, n) {
                    st.holders[&id].0.stop_in_guest();
                }
            }
            st = who.wait_turn(&cv, st, if first { SLICE / 2 } else { super::IDLE });
        };
        if display {
            st.display.retain(|(x, _)| *x != ticket);
            self.waiting_display.fetch_sub(1, Ordering::Relaxed);
        } else {
            st.rest.retain(|(x, _)| *x != ticket);
        }
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        // It is first now, and there may be room for it too.
        st.wake_first();
        took
    }

    fn release(&self, id: u64) {
        let mut st = self.st.lock().unwrap();
        if st.holders.remove(&id).is_some() {
            st.used -= 1;
        }
        st.wake_first();
    }

    /// Whether a holder that has held its core since `since` should give it up now, at
    /// the door, for those in line. Read on every way into the guest: the clock only
    /// when someone waits.
    fn should_yield(&self, display: bool, since: Instant) -> bool {
        self.waiting.load(Ordering::Relaxed) > 0 && makes_way(display, since.elapsed(), self.waiting_display.load(Ordering::Relaxed) > 0)
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
        let since = self.inner.borrow().core.map(|(_, since)| since);
        match since {
            Some(since) if !c.should_yield(self.thread.urgency() == Urgency::Display, since) => return Ok(false),
            // To the back of its line. Here at the door it holds no kernel lock.
            Some(_) => self.leave_core(),
            None => {
                if let Some(id) = c.try_take(&self.thread) {
                    self.inner.borrow_mut().core = Some((id, Instant::now()));
                    return Ok(false);
                }
            }
        }
        let kept = self.idle();
        let mut give_up = || self.park_vcpu();
        let Some(id) = c.take(&self.thread, if kept { Some(&mut give_up) } else { None }) else { return Err("dying".into()) };
        self.inner.borrow_mut().core = Some((id, Instant::now()));
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
    fn yield_core(&self) {
        if self.pool.cores.as_ref().is_some_and(|c| c.waiting.load(Ordering::Relaxed) > 0) {
            self.leave_core();
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
        let slot = Rc::new(Slot { hv, pool, thread, inner: RefCell::new(Inner { vcpu: None, state, root, held: None, gated: None, core: None, told: None, flush_wanted: false, flush_asked: false }) });
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
        let exit = {
            let mut i = self.0.inner.borrow_mut();
            let exit = i.vcpu.as_mut().unwrap().run();
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

    /// A thread as the cores gate sees it, with no kernel behind it.
    #[derive(Default)]
    struct Fake {
        display: bool,
        dying: AtomicBool,
        asked: AtomicBool,
        kicks: AtomicUsize,
    }

    impl Fake {
        fn new(display: bool) -> Arc<Fake> {
            Arc::new(Fake { display, ..Default::default() })
        }
    }

    impl Runner for Fake {
        fn is_display(&self) -> bool {
            self.display
        }
        fn is_dying(&self) -> bool {
            self.dying.load(Ordering::Relaxed)
        }
        fn asked_for_vcpu(&self) -> bool {
            self.asked.load(Ordering::Relaxed)
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
        let gate = Cores::<Fake>::new(2);
        let a = gate.try_take(&Fake::new(false)).unwrap();
        let _b = gate.try_take(&Fake::new(false)).unwrap();
        assert_eq!(gate.try_take(&Fake::new(true)), None);
        assert!(!gate.should_yield(false, Instant::now() - Duration::from_secs(1)), "nobody waits");
        gate.release(a);
        assert!(gate.try_take(&Fake::new(false)).is_some());
        assert_eq!(gate.usage().0, 2);
        // A place given back twice is given back once.
        gate.release(a);
        assert_eq!(gate.usage().0, 2);
    }

    #[test]
    fn display_work_goes_first_and_the_rest_in_turn() {
        let gate = Arc::new(Cores::<Fake>::new(1));
        let holder = Fake::new(false);
        let id = gate.try_take(&holder).unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut joins = Vec::new();
        for (name, display) in [("a", false), ("b", false), ("c", true)] {
            let (g, order) = (gate.clone(), order.clone());
            let before = gate.waiting.load(Ordering::Relaxed);
            joins.push(std::thread::spawn(move || {
                let id = g.take(&Fake::new(display), None).expect("a place");
                order.lock().unwrap().push(name);
                g.release(id);
            }));
            until(|| gate.waiting.load(Ordering::Relaxed) == before + 1);
        }
        // Display work in line: the holder is stopped, and makes way at its door.
        until(|| holder.kicks.load(Ordering::Relaxed) > 0);
        assert!(gate.should_yield(false, Instant::now()));
        assert!(!gate.should_yield(true, Instant::now()));
        gate.release(id);
        for j in joins {
            j.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), ["c", "a", "b"]);
        assert_eq!((gate.waiting.load(Ordering::Relaxed), gate.waiting_display.load(Ordering::Relaxed)), (0, 0));
        assert_eq!(gate.usage().0, 0);
    }

    #[test]
    fn dying_ends_a_wait() {
        let gate = Arc::new(Cores::<Fake>::new(1));
        let id = gate.try_take(&Fake::new(false)).unwrap();
        let dying = Fake::new(false);
        let d = {
            let (g, who) = (gate.clone(), dying.clone());
            std::thread::spawn(move || g.take(&who, None))
        };
        until(|| gate.waiting.load(Ordering::Relaxed) == 1);
        dying.dying.store(true, Ordering::Relaxed);
        assert_eq!(d.join().unwrap(), None);
        assert_eq!(gate.waiting.load(Ordering::Relaxed), 0);
        gate.release(id);
        assert!(gate.try_take(&Fake::new(false)).is_some(), "nobody left in line");
    }

    #[test]
    fn an_ask_for_the_vcpu_a_waiter_keeps_costs_it_the_vcpu_but_not_its_turn() {
        let gate = Arc::new(Cores::<Fake>::new(1));
        let id = gate.try_take(&Fake::new(false)).unwrap();
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
                let id = g.take(&who, if with_vcpu { Some(&mut give_up) } else { None }).expect("a place");
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
