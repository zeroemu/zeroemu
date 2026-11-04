//! inotify: watches on paths, fed by the kernel's own file operations
//! (create, delete, rename, write, attribute changes, closing a written
//! file). A watch is on the canonical path it named; an event on a path
//! reaches the watch on that path (no name) and the watch on its directory
//! (with the name), as Linux reports to an inode and to its parent.

use super::wait::EVENTS;
use super::{ERESTARTSYS, Thread};
use crate::errno::*;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
const IN_DELETE_SELF: u32 = 0x400;
const IN_MOVE_SELF: u32 = 0x800;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
pub const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
const ALL_EVENTS: u32 = 0xfff;
/// /proc/sys/fs/inotify/max_queued_events.
const MAX_QUEUED: usize = 16384;

struct Watch {
    path: String,
    mask: u32,
}

#[derive(Default)]
struct State {
    watches: HashMap<i32, Watch>,
    next_wd: i32,
    queue: VecDeque<Vec<u8>>,
}

#[derive(Default)]
pub struct Inotify {
    st: Mutex<State>,
}

/// Every instance, to deliver to; and how many watches exist anywhere (a
/// file operation looks for watchers only when there are some).
static ALL: LazyLock<Mutex<Vec<Weak<Inotify>>>> = LazyLock::new(Mutex::default);
static WATCHES: AtomicUsize = AtomicUsize::new(0);
static COOKIE: AtomicUsize = AtomicUsize::new(1);

/// One struct inotify_event, the name NUL-padded to 16 bytes as Linux does.
fn event(wd: i32, mask: u32, cookie: u32, name: &str) -> Vec<u8> {
    let len = if name.is_empty() { 0 } else { (name.len() + 1).next_multiple_of(16) };
    let mut e = Vec::with_capacity(16 + len);
    e.extend_from_slice(&wd.to_le_bytes());
    e.extend_from_slice(&mask.to_le_bytes());
    e.extend_from_slice(&cookie.to_le_bytes());
    e.extend_from_slice(&(len as u32).to_le_bytes());
    e.extend_from_slice(name.as_bytes());
    e.resize(16 + len, 0);
    e
}

impl State {
    fn push(&mut self, e: Vec<u8>) {
        if self.queue.len() < MAX_QUEUED {
            // Linux merges an event identical to the last one still queued.
            if self.queue.back() != Some(&e) {
                self.queue.push_back(e);
            }
        } else if self.queue.len() == MAX_QUEUED {
            self.queue.push_back(event(-1, IN_Q_OVERFLOW, 0, ""));
        }
    }

    fn drop_watch(&mut self, wd: i32) {
        if self.watches.remove(&wd).is_some() {
            WATCHES.fetch_sub(1, Ordering::Relaxed);
            self.push(event(wd, IN_IGNORED, 0, ""));
        }
    }
}

impl Inotify {
    pub fn new() -> Arc<Inotify> {
        let i = Arc::new(Inotify::default());
        let mut all = ALL.lock().unwrap();
        all.retain(|w| w.strong_count() > 0);
        all.push(Arc::downgrade(&i));
        i
    }

    /// inotify_add_watch on a resolved path. `is_dir` for IN_ONLYDIR.
    pub fn add_watch(&self, path: &str, is_dir: bool, mask: u32) -> Result<i64, i64> {
        if mask & ALL_EVENTS == 0 {
            return Err(EINVAL);
        }
        if mask & IN_ONLYDIR != 0 && !is_dir {
            return Err(ENOTDIR);
        }
        let mut st = self.st.lock().unwrap();
        let events = mask & (ALL_EVENTS | IN_ONESHOT);
        if let Some((&wd, w)) = st.watches.iter_mut().find(|(_, w)| w.path == path) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(EEXIST);
            }
            w.mask = if mask & IN_MASK_ADD != 0 { w.mask | events } else { events };
            return Ok(wd as i64);
        }
        st.next_wd += 1;
        let wd = st.next_wd;
        st.watches.insert(wd, Watch { path: path.to_string(), mask: events });
        WATCHES.fetch_add(1, Ordering::Relaxed);
        Ok(wd as i64)
    }

    pub fn rm_watch(&self, wd: i32) -> Result<i64, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.watches.contains_key(&wd) {
            return Err(EINVAL);
        }
        st.drop_watch(wd);
        drop(st);
        EVENTS.bump();
        Ok(0)
    }

    pub fn pending(&self) -> usize {
        self.st.lock().unwrap().queue.iter().map(Vec::len).sum()
    }

    /// read(2): whole events only; a buffer too small for the first is EINVAL.
    pub fn read(&self, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        loop {
            let seen = EVENTS.current();
            {
                let mut st = self.st.lock().unwrap();
                if let Some(first) = st.queue.front() {
                    if first.len() > count {
                        return Err(EINVAL);
                    }
                    let mut out = Vec::new();
                    while let Some(e) = st.queue.front() {
                        if out.len() + e.len() > count {
                            break;
                        }
                        out.extend(st.queue.pop_front().unwrap());
                    }
                    return Ok(out);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, super::POLL);
        }
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let n = self.st.get_mut().map(|s| s.watches.len()).unwrap_or(0);
        WATCHES.fetch_sub(n, Ordering::Relaxed);
    }
}

/// A rename's two events share a cookie.
pub fn cookie() -> u32 {
    COOKIE.fetch_add(1, Ordering::Relaxed) as u32
}

/// Something happened to `path` (canonical). Its directory's watchers hear
/// it with the name; its own watchers hear it too, or the _SELF form of a
/// delete or move (after which the watch is gone).
pub fn notify(path: &str, mask: u32, cookie: u32) {
    if WATCHES.load(Ordering::Relaxed) == 0 {
        return;
    }
    let (parent, name) = match path.rsplit_once('/') {
        Some(("", n)) => ("/", n),
        Some((p, n)) => (p, n),
        None => return,
    };
    let base = mask & ALL_EVENTS;
    let instances: Vec<Arc<Inotify>> = ALL.lock().unwrap().iter().filter_map(Weak::upgrade).collect();
    let mut any = false;
    for i in instances {
        let mut st = i.st.lock().unwrap();
        let mut gone = Vec::new();
        let mut out = Vec::new();
        for (&wd, w) in &st.watches {
            if w.path == parent && w.mask & base != 0 {
                out.push(event(wd, mask, cookie, name));
                if w.mask & IN_ONESHOT != 0 {
                    gone.push(wd);
                }
            }
            if w.path == path {
                let own = match base {
                    IN_DELETE => IN_DELETE_SELF,
                    IN_MOVED_FROM => IN_MOVE_SELF,
                    IN_CREATE | IN_MOVED_TO => 0, // a new inode, not the watched one
                    m => m,
                };
                if own != 0 && w.mask & own != 0 {
                    out.push(event(wd, own | (mask & IN_ISDIR), 0, ""));
                }
                if own == IN_DELETE_SELF || (own != 0 && w.mask & IN_ONESHOT != 0) {
                    gone.push(wd);
                }
            }
        }
        any |= !out.is_empty() || !gone.is_empty();
        for e in out {
            st.push(e);
        }
        for wd in gone {
            st.drop_watch(wd);
        }
    }
    if any {
        EVENTS.bump();
    }
}

/// The add_watch flags that ask not to follow a final symlink.
pub fn follow(mask: u32) -> bool {
    mask & IN_DONT_FOLLOW == 0
}

/// "/a/b" + "c".
pub fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}
