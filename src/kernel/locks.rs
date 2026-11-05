//! Advisory file locks: POSIX record locks (F_SETLK, owned by the process),
//! open file description locks (F_OFD_SETLK) and flock (whole file), both
//! owned by the open file description. Locks are on the inode, so separate
//! opens of one file contend. Every BPF fd shares one inode, as Linux's anon
//! inode: libbpf_android locks byte <map id> of it to keep a map exclusive.

use super::Thread;
use crate::errno::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, LazyLock, Mutex};

/// What a lock is on: (filesystem, inode), or a stand-in for objects
/// outside the namespace.
pub type Key = (usize, u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    /// POSIX record locks: the process (tgid).
    Process(i32),
    /// OFD and flock locks: the open file description (its address).
    File(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub owner: Owner,
    pub write: bool,
    pub start: u64,
    /// Exclusive; u64::MAX reaches the end of the file however it grows.
    pub end: u64,
    /// Reported by F_GETLK: the locking process, or -1 for an OFD lock.
    pub pid: i32,
}

#[derive(Default)]
struct State {
    ranges: HashMap<Key, Vec<Range>>,
    /// flock: (description, exclusive) per inode.
    whole: HashMap<Key, Vec<(usize, bool)>>,
}

#[derive(Default)]
pub struct Locks {
    st: Mutex<State>,
    /// Signalled whenever a lock goes away, for blocked SETLKW / flock.
    released: Condvar,
    /// Locks held anywhere: closing a file only looks when there are any.
    held: AtomicUsize,
}

pub static LOCKS: LazyLock<Locks> = LazyLock::new(Locks::default);

impl Locks {
    /// A lock of another owner that `want` would conflict with.
    pub fn conflict(&self, key: Key, want: &Range) -> Option<Range> {
        let st = self.st.lock().unwrap();
        st.ranges.get(&key).and_then(|list| list.iter().find(|l| clashes(l, want)).copied())
    }

    /// Takes, changes or (write None) drops `owner`'s lock on [start, end).
    pub fn set(&self, t: &Thread, key: Key, want: Range, unlock: bool, wait: bool) -> Result<(), i64> {
        let mut st = self.st.lock().unwrap();
        loop {
            let list = st.ranges.entry(key).or_default();
            if unlock || !list.iter().any(|l| clashes(l, &want)) {
                // The owner's own locks in the range give way (split at its edges).
                let mut out = Vec::with_capacity(list.len() + 2);
                for l in list.drain(..) {
                    if l.owner != want.owner || l.end <= want.start || l.start >= want.end {
                        out.push(l);
                        continue;
                    }
                    if l.start < want.start {
                        out.push(Range { end: want.start, ..l });
                    }
                    if l.end > want.end {
                        out.push(Range { start: want.end, ..l });
                    }
                }
                if !unlock {
                    out.push(want);
                }
                *list = out;
                if list.is_empty() {
                    st.ranges.remove(&key);
                }
                self.recount(&st);
                self.released.notify_all();
                return Ok(());
            }
            if !wait {
                return Err(EAGAIN);
            }
            st = self.block(t, st)?;
        }
    }

    /// flock(2): LOCK_SH / LOCK_EX / LOCK_UN on the whole file.
    pub fn flock(&self, t: &Thread, key: Key, file: usize, op: Option<bool>, wait: bool) -> Result<(), i64> {
        let mut st = self.st.lock().unwrap();
        loop {
            let list = st.whole.entry(key).or_default();
            list.retain(|(f, _)| *f != file); // converting drops the old lock first, as Linux does
            let Some(exclusive) = op else {
                if list.is_empty() {
                    st.whole.remove(&key);
                }
                self.recount(&st);
                self.released.notify_all();
                return Ok(());
            };
            if !list.iter().any(|(_, ex)| *ex || exclusive) {
                list.push((file, exclusive));
                self.recount(&st);
                return Ok(());
            }
            self.recount(&st);
            self.released.notify_all();
            if !wait {
                return Err(EAGAIN); // EWOULDBLOCK
            }
            st = self.block(t, st)?;
        }
    }

    /// Everything `owner` holds: a description's last close, a process's exit.
    pub fn release(&self, owner: Owner) {
        if self.held.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut st = self.st.lock().unwrap();
        st.ranges.retain(|_, list| {
            list.retain(|l| l.owner != owner);
            !list.is_empty()
        });
        if let Owner::File(f) = owner {
            st.whole.retain(|_, list| {
                list.retain(|(x, _)| *x != f);
                !list.is_empty()
            });
        }
        self.recount(&st);
        self.released.notify_all();
    }

    /// POSIX: closing any fd of a file drops the process's locks on it.
    pub fn release_on(&self, key: Key, pid: i32) {
        if self.held.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut st = self.st.lock().unwrap();
        if let Some(list) = st.ranges.get_mut(&key) {
            list.retain(|l| l.owner != Owner::Process(pid));
            if list.is_empty() {
                st.ranges.remove(&key);
            }
        }
        self.recount(&st);
        self.released.notify_all();
    }

    fn recount(&self, st: &State) {
        let n = st.ranges.values().map(Vec::len).sum::<usize>() + st.whole.values().map(Vec::len).sum::<usize>();
        self.held.store(n, Ordering::Relaxed);
    }

    fn block<'a>(&self, t: &Thread, st: std::sync::MutexGuard<'a, State>) -> Result<std::sync::MutexGuard<'a, State>, i64> {
        if t.interrupted() {
            return Err(super::ERESTARTSYS);
        }
        super::vcpus::blocking();
        Ok(t.sleep(&self.released, st, super::IDLE))
    }
}

fn clashes(held: &Range, want: &Range) -> bool {
    held.owner != want.owner && held.start < want.end && want.start < held.end && (held.write || want.write)
}
