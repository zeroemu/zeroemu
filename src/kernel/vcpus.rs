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

use super::Thread;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, PageTableRoot, SyscallRegs, Urgency, Vcpu, set_thread_urgency};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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

/// How long a holder keeps its vCPU once others wait.
const SLICE: Duration = Duration::from_millis(10);

/// How often free places are topped up, at most.
const TOP_UP: Duration = Duration::from_millis(1);

pub struct Pool {
    max: usize,
    /// Background threads' places, when this is the whole pool.
    background: Option<Arc<Pool>>,
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
    /// When it took the place.
    since: Instant,
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
    pub fn new(max: usize) -> Arc<Pool> {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        let background = Pool::sized((cores / 2).max(2), None);
        let pool = Pool::sized(max, Some(background));
        let _ = MAIN.set(Arc::downgrade(&pool));
        pool
    }

    fn sized(max: usize, background: Option<Arc<Pool>>) -> Arc<Pool> {
        Arc::new(Pool {
            max: max.max(1),
            background,
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
        let h = Arc::new(Holder { thread: thread.clone(), since: Instant::now(), asleep: AtomicU64::new(0) });
        st.holders.insert(id, h.clone());
        (id, h)
    }

    /// Now, as Holder::asleep counts it: never 0.
    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64 + 1
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

    /// So few places free that a thread going to sleep should give its own up now: half
    /// of what top_up keeps.
    fn low(&self) -> bool {
        self.max.saturating_sub(self.used.load(Ordering::Relaxed)) <= self.max / 16
    }

    /// Asks up to `n` holders asleep in the kernel for at least `min`, longest asleep
    /// first, to give their places back: woken, each finds nothing to do and gives its
    /// vCPU up as it goes back to sleep (`blocking`). Returns how many it asked.
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
        for (_, h) in &sleepers {
            h.thread.give_back.store(true, Ordering::Relaxed);
            nudge(&h.thread);
        }
        sleepers.len()
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
                let mut running: Vec<_> = st.holders.values().filter(|h| h.asleep.load(Ordering::Relaxed) == 0 && h.since.elapsed() >= SLICE).collect();
                running.sort_by_key(|h| h.since);
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

struct Inner {
    vcpu: Option<Box<dyn Vcpu>>,
    /// The registers while parked (stale while a vCPU is live).
    state: CpuState,
    root: PageTableRoot,
    /// Holder id and entry, while live.
    held: Option<(u64, Arc<Holder>)>,
    /// Holder id in the background pool, if this vCPU took a place there.
    gated: Option<u64>,
    /// What the host was last told about this thread.
    told: Option<Urgency>,
    /// A TLB flush asked for with no vCPU to ask: the next one does it. A new vCPU
    /// flushing for itself isn't enough, since others hold translations too.
    flush_wanted: bool,
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
    /// Makes the vCPU if there is none: true if it did.
    fn ensure(&self) -> Result<bool, String> {
        let mut i = self.inner.borrow_mut();
        if i.vcpu.is_some() {
            return Ok(false);
        }
        // Waiting in line for a background place can outlast being background.
        let gate = self.gate();
        let gated = gate.is_some_and(|g| g.acquire(&self.thread, || self.thread.urgency() == Urgency::Background));
        if gate.is_some() && !gated && self.thread.dying.load(Ordering::Acquire) {
            return Err("dying".into());
        }
        let gate = gate.filter(|_| gated);
        let release_gate = || {
            if let Some(g) = gate {
                g.release();
            }
        };
        if !self.pool.acquire(&self.thread, || true) {
            release_gate();
            return Err("dying".into());
        }
        MADE.fetch_add(1, Ordering::Relaxed);
        let mut v = match self.hv.create_vcpu(i.root, &i.state) {
            Ok(v) => v,
            Err(e) => {
                self.pool.release();
                release_gate();
                return Err(e);
            }
        };
        if std::mem::take(&mut i.flush_wanted) {
            v.flush_tlb();
        }
        let held = self.pool.add_holder(&self.thread);
        i.gated = gate.map(|g| g.add_holder(&self.thread).0);
        *self.thread.kick.lock().unwrap() = Some(v.kicker());
        i.held = Some(held);
        i.vcpu = Some(v);
        Ok(true)
    }

    /// The pool this thread must also take a place in, as things stand.
    fn gate(&self) -> Option<&Pool> {
        self.pool.background.as_deref().filter(|_| self.thread.urgency() == Urgency::Background)
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

    /// The thread's urgency may have changed, or it slept: tells the host, and brings
    /// its place in the background pool into line.
    fn follow_urgency(&self) {
        let want = self.tell_host();
        let background = want == Urgency::Background;
        if !background {
            self.leave_gate();
            return;
        }
        let mut i = self.inner.borrow_mut();
        if i.vcpu.is_some() && i.gated.is_none() && let Some(g) = self.pool.background.as_deref() {
            if g.try_acquire() {
                i.gated = Some(g.add_holder(&self.thread).0);
            } else {
                // Not waiting in line with a vCPU: places in the whole pool would then
                // wait on background work. ensure() queues for both, in order.
                drop(i);
                self.park();
            }
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
        let asked = self.thread.give_back.swap(false, Ordering::Relaxed);
        if asked || self.pool.waiting.load(Ordering::Relaxed) > 0 || self.pool.low() {
            self.park();
            return;
        }
        // Kept: noted for `reclaim`, from the first time it blocks in this syscall.
        if let Some((_, h)) = &self.inner.borrow().held
            && h.asleep.load(Ordering::Relaxed) == 0
        {
            h.asleep.store(self.pool.now_ns(), Ordering::Relaxed);
        }
    }

    /// About to run guest code: no longer asleep, nor asked to give its vCPU back
    /// because it was.
    fn running(&self) {
        if let Some((_, h)) = &self.inner.borrow().held
            && h.asleep.load(Ordering::Relaxed) != 0
        {
            h.asleep.store(0, Ordering::Relaxed);
            self.thread.give_back.store(false, Ordering::Relaxed);
        }
    }

    fn park(&self) {
        let mut i = self.inner.borrow_mut();
        let Some(v) = i.vcpu.take() else { return };
        i.state = v.state();
        if let Some((id, _)) = i.held.take() {
            self.pool.st.lock().unwrap().holders.remove(&id);
        }
        let gated = i.gated.take();
        if let Some(id) = gated {
            self.pool.background.as_ref().unwrap().st.lock().unwrap().holders.remove(&id);
        }
        *self.thread.kick.lock().unwrap() = None;
        drop(v); // destroyed on the thread that owns it
        self.pool.release();
        if gated.is_some() {
            self.pool.background.as_ref().unwrap().release();
        }
    }

    /// Whether others are waiting for what this thread holds.
    fn wanted(&self) -> bool {
        let gated = self.inner.borrow().gated.is_some();
        self.pool.waiting.load(Ordering::Relaxed) > 0 || (gated && self.pool.background.as_ref().is_some_and(|g| g.waiting.load(Ordering::Relaxed) > 0))
    }

    /// After an exit: give the vCPU up if others have waited a slice for one.
    fn maybe_yield(&self) {
        if !self.wanted() {
            return;
        }
        let held_long = self.inner.borrow().held.as_ref().is_some_and(|(_, h)| h.since.elapsed() >= SLICE);
        if held_long {
            self.park();
        }
    }
}

/// The guest thread's vCPU handle (implements `Vcpu`; dropped when the thread ends).
pub struct LazyVcpu(Rc<Slot>);

impl LazyVcpu {
    pub fn new(hv: Arc<dyn Hypervisor>, pool: Arc<Pool>, thread: Arc<Thread>, root: PageTableRoot, state: CpuState) -> LazyVcpu {
        let slot = Rc::new(Slot { hv, pool, thread, inner: RefCell::new(Inner { vcpu: None, state, root, held: None, gated: None, told: None, flush_wanted: false }) });
        CURRENT.with(|c| *c.borrow_mut() = Some(slot.clone()));
        LazyVcpu(slot)
    }
}

impl Drop for LazyVcpu {
    fn drop(&mut self) {
        self.0.park();
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

/// Called by blocking waits, before each sleep: hands the current thread's vCPU back
/// if another thread is waiting for a place, places are low, or it was asked to.
pub fn blocking() {
    CURRENT.with(|c| {
        if let Some(s) = c.borrow().as_ref() {
            s.blocking();
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
        while self.0.pool.frozen.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(50));
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
        let exit = self.0.inner.borrow_mut().vcpu.as_mut().unwrap().run();
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
            Some(v) => v.flush_tlb(),
            None => i.flush_wanted = true,
        }
    }

    fn flush_tlb_now(&mut self) {
        // ready() came first, but keep to what a parked thread can do: a new
        // vCPU flushes on its first entry, and nothing else here is on the way.
        if let Some(v) = &mut self.0.inner.borrow_mut().vcpu {
            v.flush_tlb_now();
        }
    }

    fn ready(&mut self) -> bool {
        self.0.ensure().is_ok()
    }

    fn kicker(&self) -> Arc<dyn Kick> {
        unreachable!("the slot keeps Thread::kick up to date")
    }
}
