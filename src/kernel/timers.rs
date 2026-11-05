//! POSIX timers (timer_create and friends) and interval timers (setitimer).
//! A timerfd counts when somebody looks, but a timer's signal must arrive on
//! its own, so one host thread sleeps until the next deadline.
//!
//! Timers on CPU-time clocks are refused and ITIMER_VIRTUAL and ITIMER_PROF
//! only store their values: droidrt keeps no per-process CPU accounting, and
//! wall time would kill processes, those signals being fatal by default.
//!
//! A pending signal is one entry per number (signal.rs), so a timer that fires
//! while its signal number is still pending counts an overrun instead.

use super::signal::SigInfo;
use super::specialfd::{deadline_for, put_timespec};
use super::wait::EVENTS;
use super::{Kernel, Process, Thread};
use crate::arch::Sysno;
use crate::errno::*;
use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::{Arc, Condvar, Mutex, Once, Weak};
use std::time::{Duration, Instant};

const SI_TIMER: i32 = -2;
const SI_KERNEL: i32 = 0x80;
const SIGALRM: u32 = 14;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

const TIMER_ABSTIME: u64 = 1;
const NANOS: u64 = 1_000_000_000;
const MICROS: u64 = 1_000_000;

const ITIMER_REAL: u64 = 0;
const ITIMER_PROF: u64 = 2;

pub struct Timer {
    id: i32,
    clock: u64,
    proc: Weak<Process>,
    /// SIGEV_THREAD_ID: the thread that gets the signal.
    thread: Option<Weak<Thread>>,
    /// 0 for SIGEV_NONE: the timer runs but says nothing.
    signo: u32,
    value: u64,
    code: i32,
    st: Mutex<State>,
}

#[derive(Default)]
struct State {
    next: Option<Instant>,
    interval: Duration,
    /// Bumped by every change, so queue entries from before it are ignored.
    generation: u64,
    /// Expirations since the last signal went out.
    overrun: i32,
    /// What timer_getoverrun reports: the count as of the last signal.
    overrun_last: i32,
}

impl State {
    fn remaining(&self) -> (Duration, Duration) {
        (self.interval, self.next.map_or(Duration::ZERO, |n| n.saturating_duration_since(Instant::now()).max(Duration::from_nanos(1))))
    }
}

/// A process's timers. fork does not inherit them; exec keeps only ITIMER_REAL.
#[derive(Default)]
pub struct ProcTimers {
    posix: BTreeMap<i32, Arc<Timer>>,
    next_id: i32,
    real: Option<Arc<Timer>>,
    /// ITIMER_VIRTUAL and ITIMER_PROF: (interval, value), never counted down.
    cpu: [(Duration, Duration); 2],
}

struct Due {
    at: Instant,
    generation: u64,
    timer: Weak<Timer>,
}

impl PartialEq for Due {
    fn eq(&self, other: &Due) -> bool {
        self.at == other.at
    }
}
impl Eq for Due {}
impl PartialOrd for Due {
    fn partial_cmp(&self, other: &Due) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl Ord for Due {
    fn cmp(&self, other: &Due) -> CmpOrdering {
        self.at.cmp(&other.at)
    }
}

pub struct TimerQueue {
    kernel: Weak<Kernel>,
    heap: Mutex<BinaryHeap<Reverse<Due>>>,
    wake: Condvar,
    started: Once,
}

impl TimerQueue {
    pub fn new(kernel: Weak<Kernel>) -> Arc<TimerQueue> {
        Arc::new(TimerQueue { kernel, heap: Mutex::default(), wake: Condvar::new(), started: Once::new() })
    }

    fn schedule(self: &Arc<Self>, at: Instant, generation: u64, timer: &Arc<Timer>) {
        self.started.call_once(|| {
            let queue = self.clone();
            let _ = std::thread::Builder::new().name("timers".into()).spawn(move || queue.run());
        });
        self.heap.lock().unwrap().push(Reverse(Due { at, generation, timer: Arc::downgrade(timer) }));
        self.wake.notify_one();
    }

    fn run(&self) {
        let mut heap = self.heap.lock().unwrap();
        loop {
            let now = Instant::now();
            match heap.peek() {
                None => heap = self.wake.wait(heap).unwrap(),
                Some(Reverse(due)) if due.at > now => {
                    let wait = due.at - now;
                    heap = self.wake.wait_timeout(heap, wait).unwrap().0;
                }
                Some(_) => {
                    let Reverse(due) = heap.pop().unwrap();
                    drop(heap);
                    if let (Some(timer), Some(kernel)) = (due.timer.upgrade(), self.kernel.upgrade()) {
                        kernel.fire_timer(&timer, due.generation);
                    }
                    heap = self.heap.lock().unwrap();
                }
            }
        }
    }
}

/// An itimerspec (`scale` 1e9) or itimerval (1e6): interval and value.
fn read_times(b: &[u8], scale: u64) -> Result<(Duration, Duration), i64> {
    let one = |b: &[u8]| -> Result<Duration, i64> {
        let sec = i64::from_le_bytes(b[0..8].try_into().unwrap());
        let frac = i64::from_le_bytes(b[8..16].try_into().unwrap());
        if sec < 0 || frac < 0 || frac as u64 >= scale {
            return Err(EINVAL);
        }
        Ok(Duration::new(sec as u64, (frac as u64 * (NANOS / scale)) as u32))
    };
    Ok((one(&b[0..16])?, one(&b[16..32])?))
}

fn write_itimerval(t: &Thread, at: u64, (interval, value): (Duration, Duration)) -> Result<(), i64> {
    let mut b = [0u8; 32];
    for (slot, d) in [(0, interval), (16, value)] {
        b[slot..slot + 8].copy_from_slice(&d.as_secs().to_le_bytes());
        b[slot + 8..slot + 16].copy_from_slice(&(d.subsec_micros() as u64).to_le_bytes());
    }
    t.proc.mm().write(at, &b)
}

fn write_itimerspec(t: &Thread, at: u64, (interval, value): (Duration, Duration)) -> Result<(), i64> {
    let mut b = [0u8; 32];
    put_timespec(&mut b[0..16], interval);
    put_timespec(&mut b[16..32], value);
    t.proc.mm().write(at, &b)
}

impl Timer {
    /// Where its signal waits while pending.
    fn with_pending<R>(&self, proc: &Process, f: impl FnOnce(&mut HashMap<u32, SigInfo>) -> R) -> Option<R> {
        match &self.thread {
            Some(th) => th.upgrade().map(|th| f(&mut th.pending.lock().unwrap())),
            None => Some(f(&mut proc.pending.lock().unwrap())),
        }
    }

    /// Its expiry signal, if one is still waiting, goes with it.
    fn purge(&self) {
        let mut st = self.st.lock().unwrap();
        st.generation += 1;
        st.next = None;
        drop(st);
        if let Some(proc) = self.proc.upgrade() {
            self.with_pending(&proc, |pending| {
                if pending.get(&self.signo).is_some_and(|info| info.is_timer(self.id)) {
                    pending.remove(&self.signo);
                }
            });
        }
    }
}

impl Kernel {
    fn fire_timer(&self, timer: &Arc<Timer>, generation: u64) {
        let Some(proc) = timer.proc.upgrade() else { return };
        if proc.status.lock().unwrap().is_some() || proc.exiting.lock().unwrap().is_some() {
            return;
        }
        let mut st = timer.st.lock().unwrap();
        if st.generation != generation {
            return;
        }
        if st.interval.is_zero() {
            st.next = None;
        } else {
            let now = Instant::now();
            let due = st.next.unwrap_or(now);
            let missed = (now.saturating_duration_since(due).as_nanos() / st.interval.as_nanos()).min(i32::MAX as u128) as u32;
            let next = due.checked_add(st.interval * (missed + 1)).unwrap_or(now + st.interval);
            st.overrun = st.overrun.saturating_add(missed as i32);
            st.generation += 1;
            st.next = Some(next);
            self.timers.schedule(next, st.generation, timer);
        }
        if timer.signo == 0 {
            return;
        }
        if timer.with_pending(&proc, |pending| pending.contains_key(&timer.signo)).unwrap_or(true) {
            st.overrun = st.overrun.saturating_add(1);
            return;
        }
        st.overrun_last = st.overrun;
        st.overrun = 0;
        let info = SigInfo::timer(timer.signo, timer.code, timer.id, st.overrun_last, timer.value);
        drop(st);
        match &timer.thread {
            Some(th) => {
                if let Some(th) = th.upgrade() {
                    self.send_thread_signal(&th, timer.signo, info);
                }
            }
            None => self.send_process_signal(&proc, timer.signo, info),
        }
        // kick() only stops a running vCPU; this wakes a thread in a blocking call.
        EVENTS.bump();
    }

    /// Sets a timer; returns its old (interval, value).
    fn arm_timer(&self, timer: &Arc<Timer>, interval: Duration, value: Duration, abstime: bool) -> (Duration, Duration) {
        let mut st = timer.st.lock().unwrap();
        let old = st.remaining();
        st.generation += 1;
        st.interval = interval;
        st.overrun = 0;
        st.overrun_last = 0;
        st.next = (!value.is_zero()).then(|| deadline_for(timer.clock, self.boot, value, abstime));
        if let Some(next) = st.next {
            self.timers.schedule(next, st.generation, timer);
        }
        old
    }

    fn real_timer(&self, t: &Thread) -> Arc<Timer> {
        let mut timers = t.proc.timers.lock().unwrap();
        timers
            .real
            .get_or_insert_with(|| {
                Arc::new(Timer {
                    id: 0,
                    clock: 1,
                    proc: Arc::downgrade(&t.proc),
                    thread: None,
                    signo: SIGALRM,
                    value: 0,
                    code: SI_KERNEL,
                    st: Mutex::default(),
                })
            })
            .clone()
    }

    fn posix_timer(&self, t: &Thread, id: i32) -> Result<Arc<Timer>, i64> {
        t.proc.timers.lock().unwrap().posix.get(&id).cloned().ok_or(EINVAL)
    }

    /// exec deletes POSIX timers; their signals would kill the new image.
    pub(super) fn timers_on_exec(&self, proc: &Process) {
        let gone = std::mem::take(&mut proc.timers.lock().unwrap().posix);
        for timer in gone.values() {
            timer.purge();
        }
    }

    pub(super) fn timer_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            timer_create => self.sys_timer_create(t, a[0], a[1], a[2]),
            timer_settime => {
                let timer = self.posix_timer(t, a[0] as i32)?;
                let new = t.proc.mm().read_vec(a[2], 32)?;
                let (interval, value) = read_times(&new, NANOS)?;
                let old = self.arm_timer(&timer, interval, value, a[1] & TIMER_ABSTIME != 0);
                if a[3] != 0 {
                    write_itimerspec(t, a[3], old)?;
                }
                Ok(0)
            }
            timer_gettime => {
                let timer = self.posix_timer(t, a[0] as i32)?;
                let now = timer.st.lock().unwrap().remaining();
                write_itimerspec(t, a[1], now)?;
                Ok(0)
            }
            timer_getoverrun => {
                let timer = self.posix_timer(t, a[0] as i32)?;
                let last = timer.st.lock().unwrap().overrun_last;
                Ok(last as i64)
            }
            timer_delete => {
                let timer = t.proc.timers.lock().unwrap().posix.remove(&(a[0] as i32)).ok_or(EINVAL)?;
                timer.purge();
                Ok(0)
            }
            setitimer => self.sys_setitimer(t, a[0], a[1], a[2]),
            getitimer => {
                if a[0] > ITIMER_PROF {
                    return Err(EINVAL);
                }
                let now = if a[0] == ITIMER_REAL {
                    self.real_timer(t).st.lock().unwrap().remaining()
                } else {
                    t.proc.timers.lock().unwrap().cpu[a[0] as usize - 1]
                };
                write_itimerval(t, a[1], now)?;
                Ok(0)
            }
            alarm => {
                let old = self.arm_timer(&self.real_timer(t), Duration::ZERO, Duration::from_secs(a[0] as u32 as u64), false);
                // Rounded up, so a running alarm never reads as none.
                Ok(old.1.as_secs() as i64 + (old.1.subsec_nanos() != 0) as i64)
            }
            _ => Err(ENOSYS),
        }
    }

    fn sys_timer_create(&self, t: &Arc<Thread>, clock: u64, sevp: u64, idp: u64) -> Result<i64, i64> {
        match clock as i32 {
            0 | 1 | 7..=9 | 11 => {}
            4..=6 => return Err(EOPNOTSUPP),
            _ => return Err(EINVAL),
        }
        let (signo, notify, value, tid) = if sevp == 0 {
            (SIGALRM, SIGEV_SIGNAL, None, 0)
        } else {
            let b = t.proc.mm().read_vec(sevp, 20)?;
            let word = |at: usize| i32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            (word(8) as u32, word(12), Some(u64::from_le_bytes(b[0..8].try_into().unwrap())), word(16))
        };
        let thread = match notify {
            SIGEV_SIGNAL | SIGEV_THREAD | SIGEV_NONE => None,
            SIGEV_THREAD_ID => {
                let threads = t.proc.threads.lock().unwrap();
                Some(Arc::downgrade(threads.iter().find(|th| th.tid == tid).ok_or(EINVAL)?))
            }
            _ => return Err(EINVAL),
        };
        if notify != SIGEV_NONE && !(1..=64).contains(&signo) {
            return Err(EINVAL);
        }
        let mut timers = t.proc.timers.lock().unwrap();
        let id = timers.next_id;
        // Written while the id is still free, so a bad pointer leaves no timer.
        t.proc.mm().write(idp, &id.to_le_bytes())?;
        timers.next_id += 1;
        let timer = Timer {
            id,
            clock,
            proc: Arc::downgrade(&t.proc),
            thread,
            signo: if notify == SIGEV_NONE { 0 } else { signo },
            value: value.unwrap_or(id as u64),
            code: SI_TIMER,
            st: Mutex::default(),
        };
        timers.posix.insert(id, Arc::new(timer));
        Ok(0)
    }

    fn sys_setitimer(&self, t: &Arc<Thread>, which: u64, new: u64, old: u64) -> Result<i64, i64> {
        if which > ITIMER_PROF {
            return Err(EINVAL);
        }
        let times = if new == 0 {
            (Duration::ZERO, Duration::ZERO)
        } else {
            let b = t.proc.mm().read_vec(new, 32)?;
            read_times(&b, MICROS)?
        };
        let before = if which == ITIMER_REAL {
            self.arm_timer(&self.real_timer(t), times.0, times.1, false)
        } else {
            std::mem::replace(&mut t.proc.timers.lock().unwrap().cpu[which as usize - 1], times)
        };
        if old != 0 {
            write_itimerval(t, old, before)?;
        }
        Ok(0)
    }
}
