//! More guest threads than vCPUs. A hypervisor allows only so many vCPUs
//! (HVF: 64) and Android runs hundreds of threads, most of them blocked in
//! the kernel (idle binder pools, futex and poll waits). A vCPU belongs to the
//! host thread that made it (HVF's rule), so it cannot be handed to another
//! thread; instead a thread that blocks while the pool runs short saves its
//! registers and destroys its vCPU, and makes a new one when it next runs
//! guest code. While parked, its register state is answered from the copy.
//!
//! A thread waiting for a vCPU kicks the one that has held its vCPU longest,
//! which gives it up at its next exit, so threads spinning in user code
//! cannot starve the rest.
//!
//! Background threads also need a place in a much smaller pool, the cores a phone
//! would have kept them to. There is nowhere better to hold them back: they
//! wait here at the door of the guest, holding no kernel lock anyone could want.

use super::Thread;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, PageTableRoot, SyscallRegs, Urgency, Vcpu, set_thread_urgency};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a waiter waits before kicking the longest holder, and how long a
/// holder keeps its vCPU once others wait.
const SLICE: Duration = Duration::from_millis(10);

pub struct Pool {
    max: usize,
    /// Background threads' places, when this is the whole pool.
    background: Option<Arc<Pool>>,
    st: Mutex<PoolState>,
    cv: Condvar,
    /// Threads waiting for a vCPU (read without the lock on every exit).
    waiting: AtomicUsize,
    used: AtomicUsize,
}

#[derive(Default)]
struct PoolState {
    next: u64,
    holders: HashMap<u64, (Instant, Arc<dyn Kick>)>,
    /// Waiters' tickets, served in order: a thread that just gave its vCPU
    /// up must not take it straight back past the threads it yielded to.
    queue: VecDeque<u64>,
}

impl Pool {
    pub fn new(max: usize) -> Arc<Pool> {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        let background = Pool::sized((cores / 2).max(2), None);
        Pool::sized(max, Some(background))
    }

    fn sized(max: usize, background: Option<Arc<Pool>>) -> Arc<Pool> {
        Arc::new(Pool { max: max.max(1), background, st: Mutex::default(), cv: Condvar::new(), waiting: AtomicUsize::new(0), used: AtomicUsize::new(0) })
    }

    fn add_holder(&self, kick: Arc<dyn Kick>) -> u64 {
        let mut st = self.st.lock().unwrap();
        st.next += 1;
        let id = st.next;
        st.holders.insert(id, (Instant::now(), kick));
        id
    }

    /// Few enough free vCPUs that blocked threads should give theirs back.
    fn short(&self) -> bool {
        self.waiting.load(Ordering::Relaxed) > 0 || self.used.load(Ordering::Relaxed) * 4 >= self.max * 3
    }

    /// Takes a vCPU slot, waiting for one; None if the thread is dying meanwhile.
    fn acquire(&self, t: &Thread) -> Option<()> {
        let mut st = self.st.lock().unwrap();
        if self.used.load(Ordering::Relaxed) < self.max && st.queue.is_empty() {
            self.used.fetch_add(1, Ordering::Relaxed);
            return Some(());
        }
        st.next += 1;
        let ticket = st.next;
        st.queue.push_back(ticket);
        self.waiting.fetch_add(1, Ordering::Relaxed);
        let mut last_kick = Instant::now();
        let got = loop {
            if self.used.load(Ordering::Relaxed) < self.max && st.queue.front() == Some(&ticket) {
                self.used.fetch_add(1, Ordering::Relaxed);
                break Some(());
            }
            if t.dying.load(Ordering::Acquire) {
                break None;
            }
            if last_kick.elapsed() >= SLICE {
                // Each waiter nudges a different long-running holder.
                let pos = st.queue.iter().position(|&x| x == ticket).unwrap_or(0);
                let mut holders: Vec<_> = st.holders.values().collect();
                holders.sort_by_key(|(since, _)| *since);
                if let Some((_, k)) = holders.get(pos) {
                    k.kick();
                }
                last_kick = Instant::now();
            }
            st = self.cv.wait_timeout(st, SLICE / 2).unwrap().0;
        };
        st.queue.retain(|&x| x != ticket);
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        self.cv.notify_all();
        got
    }

    fn release(&self) {
        let _st = self.st.lock().unwrap();
        self.used.fetch_sub(1, Ordering::Relaxed);
        self.cv.notify_all();
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
    fn ensure(&self) -> Result<(), String> {
        let mut i = self.inner.borrow_mut();
        if i.vcpu.is_some() {
            return Ok(());
        }
        let gate = self.gate();
        if let Some(g) = gate {
            g.acquire(&self.thread).ok_or("dying")?;
        }
        let made = self.pool.acquire(&self.thread).ok_or_else(|| "dying".to_string()).and_then(|()| {
            self.hv.create_vcpu(i.root, &i.state).inspect_err(|_| self.pool.release())
        });
        let v = match made {
            Ok(v) => v,
            Err(e) => {
                if let Some(g) = gate {
                    g.release();
                }
                return Err(e);
            }
        };
        let kick = v.kicker();
        let id = self.pool.add_holder(kick.clone());
        i.gated = gate.map(|g| g.add_holder(kick.clone()));
        *self.thread.kick.lock().unwrap() = Some(kick);
        i.held = Some((id, Instant::now()));
        i.vcpu = Some(v);
        Ok(())
    }

    /// The pool this thread must also take a place in, as things stand.
    fn gate(&self) -> Option<&Pool> {
        self.pool.background.as_deref().filter(|_| self.thread.urgency() == Urgency::Background)
    }

    /// The thread's urgency may have changed: tells the host, and brings its place
    /// in the background pool into line.
    fn follow_urgency(&self) {
        let want = self.thread.urgency();
        let mut i = self.inner.borrow_mut();
        if i.told != Some(want) {
            set_thread_urgency(want);
            i.told = Some(want);
        }
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
        let slot = Rc::new(Slot { hv, pool, thread, inner: RefCell::new(Inner { vcpu: None, state, root, held: None, gated: None, told: None }) });
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
            if s.pool.short() || (gated && s.pool.background.as_ref().is_some_and(|g| g.short())) {
                s.park();
            }
        }
    });
}

impl Vcpu for LazyVcpu {
    fn run(&mut self) -> Exit {
        self.0.follow_urgency();
        if let Err(e) = self.0.ensure() {
            return if e == "dying" { Exit::Interrupted } else { Exit::Fault { pc: 0, addr: 0, detail: e } };
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
        // A new vCPU flushes on its first entry anyway.
        if let Some(v) = &mut self.0.inner.borrow_mut().vcpu {
            v.flush_tlb();
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
