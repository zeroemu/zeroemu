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

use super::Thread;
use crate::hv::{CpuState, Exit, Hypervisor, Kick, PageTableRoot, SyscallRegs, Vcpu};
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
        Arc::new(Pool { max: max.max(1), st: Mutex::default(), cv: Condvar::new(), waiting: AtomicUsize::new(0), used: AtomicUsize::new(0) })
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
        self.pool.acquire(&self.thread).ok_or("dying")?;
        let v = match self.hv.create_vcpu(i.root, &i.state) {
            Ok(v) => v,
            Err(e) => {
                self.pool.release();
                return Err(e);
            }
        };
        let kick = v.kicker();
        let mut st = self.pool.st.lock().unwrap();
        st.next += 1;
        let id = st.next;
        st.holders.insert(id, (Instant::now(), kick.clone()));
        drop(st);
        *self.thread.kick.lock().unwrap() = Some(kick);
        i.held = Some((id, Instant::now()));
        i.vcpu = Some(v);
        Ok(())
    }

    fn park(&self) {
        let mut i = self.inner.borrow_mut();
        let Some(v) = i.vcpu.take() else { return };
        i.state = v.state();
        if let Some((id, _)) = i.held.take() {
            self.pool.st.lock().unwrap().holders.remove(&id);
        }
        *self.thread.kick.lock().unwrap() = None;
        drop(v); // destroyed on the thread that owns it
        self.pool.release();
    }

    /// After an exit: give the vCPU up if others have waited a slice for one.
    fn maybe_yield(&self) {
        if self.pool.waiting.load(Ordering::Relaxed) == 0 {
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
        let slot = Rc::new(Slot { hv, pool, thread, inner: RefCell::new(Inner { vcpu: None, state, root, held: None }) });
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
        if let Some(s) = c.borrow().as_ref()
            && s.pool.short()
        {
            s.park();
        }
    });
}

impl Vcpu for LazyVcpu {
    fn run(&mut self) -> Exit {
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

    fn kicker(&self) -> Arc<dyn Kick> {
        unreachable!("the slot keeps Thread::kick up to date")
    }
}
