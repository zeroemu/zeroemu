//! More guest threads than vCPUs. A hypervisor allows only so many vCPUs
//! (HVF: 64) and Android runs hundreds of threads, most of them blocked in
//! the kernel (idle binder pools, futex and poll waits). A vCPU belongs to the
//! host thread that made it (HVF's rule), so it cannot be handed to another
//! thread; instead a thread that blocks while the pool runs short saves its
//! registers and destroys its vCPU, and makes a new one when it next runs
//! guest code. While parked, its register state is answered from the copy.
//!
//! The first thread in line for a vCPU kicks those that have held theirs longest,
//! which give them up at their next exit, so threads spinning in user code cannot
//! starve the rest. Everyone else in line sleeps until it is first: hundreds of them
//! polling this lock would be a load all of its own.
//!
//! Background threads also need a place in a much smaller pool, the cores a phone
//! would have kept them to. There is nowhere better to hold them back: they
//! wait here at the door of the guest, holding no kernel lock anyone could want.

use super::Thread;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, PageTableRoot, SyscallRegs, Urgency, Vcpu, set_thread_urgency};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The kernel's pool, for wakeup_stats.
pub static MAIN: std::sync::OnceLock<std::sync::Weak<Pool>> = std::sync::OnceLock::new();

/// vCPUs made, for wakeup_stats: each costs the hypervisor a fresh one.
pub static MADE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A holder asleep in the kernel this long gives its vCPU back when places run short.
const ASLEEP: Duration = Duration::from_secs(1);

/// How long a holder keeps its vCPU once others wait.
const SLICE: Duration = Duration::from_millis(10);

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
}

#[derive(Default)]
struct PoolState {
    next: u64,
    holders: HashMap<u64, (Instant, Arc<Thread>)>,
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
        Arc::new(Pool { max: max.max(1), background, frozen: AtomicBool::new(false), st: Mutex::default(), waiting: AtomicUsize::new(0), used: AtomicUsize::new(0) })
    }

    fn add_holder(&self, thread: &Arc<Thread>) -> u64 {
        let mut st = self.st.lock().unwrap();
        st.next += 1;
        let id = st.next;
        st.holders.insert(id, (Instant::now(), thread.clone()));
        id
    }

    /// Stops guest code: from now on threads wait at the door. Kicking those already
    /// inside is the caller's business. This is the end: nothing thaws them.
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    /// (in use, the most there can be), for wakeup_stats.
    pub fn usage(&self) -> (usize, usize) {
        (self.used.load(Ordering::Relaxed), self.max)
    }

    /// Few enough free vCPUs that blocked threads should give theirs back.
    fn short(&self) -> bool {
        self.waiting.load(Ordering::Relaxed) > 0 || self.used.load(Ordering::Relaxed) * 4 >= self.max * 3
    }

    /// Places run short: wakes holders that have slept in the kernel for a while, which
    /// give theirs back as they go to sleep again. Otherwise those keep their places for
    /// as long as they sleep, which can be for ever, and every thread that blocks for a
    /// moment gives up its own, to make a new vCPU when it wakes: at idle that was 150 a
    /// second, each a costly call to the hypervisor. At most ten times a second.
    fn reclaim_sleepers(&self) {
        static LAST: Mutex<Option<Instant>> = Mutex::new(None);
        {
            let mut last = LAST.lock().unwrap();
            if last.is_some_and(|l| l.elapsed() < Duration::from_millis(100)) {
                return;
            }
            *last = Some(Instant::now());
        }
        let sleepers: Vec<Arc<Thread>> = {
            let st = self.st.lock().unwrap();
            st.holders.values().filter(|(_, th)| th.in_syscall_for().is_some_and(|d| d >= ASLEEP)).map(|(_, th)| th.clone()).collect()
        };
        for th in sleepers {
            th.give_back.store(true, Ordering::Relaxed);
            th.kick();
        }
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
            return true;
        }
        st.next += 1;
        let ticket = st.next;
        let cv = Arc::new(Condvar::new());
        st.queue.push_back((ticket, cv.clone()));
        self.waiting.fetch_add(1, Ordering::Relaxed);
        let got = loop {
            if t.dying.load(Ordering::Acquire) || !still_wanted() {
                break false;
            }
            let first = st.queue.front().is_some_and(|(x, _)| *x == ticket);
            if first && self.used.load(Ordering::Relaxed) < self.max {
                self.used.fetch_add(1, Ordering::Relaxed);
                break true;
            }
            if first {
                // As many of the longest holders as there are threads in line, once
                // they have had their slice. One running guest code gives up its place
                // at the exit this forces, and one asleep in the kernel when it wakes.
                let mut holders: Vec<_> = st.holders.values().filter(|(since, _)| since.elapsed() >= SLICE).collect();
                holders.sort_by_key(|(since, _)| *since);
                for (_, holder) in holders.iter().take(st.queue.len()) {
                    holder.kick();
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
    /// Holder id and when the vCPU was made, while live.
    held: Option<(u64, Instant)>,
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
        let id = self.pool.add_holder(&self.thread);
        i.gated = gate.map(|g| g.add_holder(&self.thread));
        *self.thread.kick.lock().unwrap() = Some(v.kicker());
        i.held = Some((id, Instant::now()));
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

    /// The thread's urgency may have changed: tells the host, and brings its place
    /// in the background pool into line.
    fn follow_urgency(&self) {
        let want = self.tell_host();
        let mut i = self.inner.borrow_mut();
        let background = want == Urgency::Background;
        if background && i.vcpu.is_some() && i.gated.is_none() {
            drop(i);
            self.park(); // ensure() queues for a place
        } else if !background && let Some(id) = i.gated.take() {
            let g = self.pool.background.as_ref().unwrap();
            g.st.lock().unwrap().holders.remove(&id);
            g.release();
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
        let held_long = self.inner.borrow().held.is_some_and(|(_, since)| since.elapsed() >= SLICE);
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

/// Called by blocking waits: hands the current thread's vCPU back when the pool runs short.
pub fn blocking() {
    CURRENT.with(|c| {
        if let Some(s) = c.borrow().as_ref() {
            let gated = s.inner.borrow().gated.is_some();
            let asked = s.thread.give_back.swap(false, Ordering::Relaxed);
            let short = s.pool.short();
            if short || asked || (gated && s.pool.background.as_ref().is_some_and(|g| g.short())) {
                if short {
                    s.pool.reclaim_sleepers();
                }
                s.park();
            }
        }
    });
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
