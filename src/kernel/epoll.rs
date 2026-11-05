//! epoll: an interest list over open files, waited on through the kernel-wide
//! change counter.
//!
//! An edge-triggered registration is reported only if its file has been announced as
//! changed since the last report, and it's ready. Going by whether readiness rose
//! wouldn't do: what's read to empty and refilled between two waits looks unchanged.
//! Reporting it every time wouldn't either: mio's waker is an eventfd it never reads,
//! so a Tokio runtime would never sleep again. An announcement about some other file
//! that shares its bit makes for a spurious report, which is allowed, as missed ones
//! aren't.

use super::files::{File, Kind, poll_mask, poll_ready};
use super::Thread;
use crate::errno::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

struct Interest {
    file: Weak<File>,
    events: u32,
    data: u64,
    /// EPOLLONESHOT registrations go quiet after one report until MOD.
    fired: bool,
    /// EPOLLET: how far its file's announcements had got at the last report.
    reported: Option<u64>,
}

impl Interest {
    /// For an edge-triggered registration, its file's announcements so far. A timer
    /// comes due with nobody announcing it, so it goes by readiness alone.
    fn generation(&self, f: &File, t: &Thread, depth: u32) -> Option<u64> {
        if self.events & EPOLLET == 0 || matches!(f.kind, Kind::Timer(_)) {
            return None;
        }
        Some(super::wait::EVENTS.generation(poll_mask(f, t, depth)))
    }
}

#[derive(Default)]
pub struct Epoll {
    interest: Mutex<BTreeMap<i32, Interest>>,
}

impl Epoll {
    pub fn ctl(&self, op: u64, fd: i32, file: &Arc<File>, events: u32, data: u64) -> Result<(), i64> {
        let pollable = matches!(&file.kind, Kind::Node(nf) if nf.lock().unwrap().pollable());
        if matches!(file.kind, Kind::Node(_) | Kind::Mem(_)) && !pollable {
            return Err(EPERM); // regular files are always ready; Linux refuses them
        }
        let mut list = self.interest.lock().unwrap();
        // A registration whose file is gone no longer counts.
        if list.get(&fd).is_some_and(|i| i.file.strong_count() == 0) {
            list.remove(&fd);
        }
        match op {
            EPOLL_CTL_ADD => {
                if list.contains_key(&fd) {
                    return Err(EEXIST);
                }
                list.insert(fd, Interest { file: Arc::downgrade(file), events, data, fired: false, reported: None });
            }
            EPOLL_CTL_MOD => {
                let i = list.get_mut(&fd).ok_or(ENOENT)?;
                *i = Interest { file: Arc::downgrade(file), events, data, fired: false, reported: None };
            }
            EPOLL_CTL_DEL => {
                list.remove(&fd).ok_or(ENOENT)?;
            }
            _ => return Err(EINVAL),
        }
        drop(list);
        super::wait::EVENTS.bump_key(self as *const Self as usize);
        Ok(())
    }

    /// Ready registrations as (events, data), at most `max`.
    pub fn collect(&self, t: &Thread, max: usize, depth: u32) -> Vec<(u32, u64)> {
        let mut list = self.interest.lock().unwrap();
        list.retain(|_, i| i.file.strong_count() > 0);
        let mut out = Vec::new();
        for i in list.values_mut() {
            if out.len() >= max {
                break;
            }
            if i.fired {
                continue;
            }
            let Some(f) = i.file.upgrade() else { continue };
            // Before looking: what's announced after this gets looked at next time.
            let generation = i.generation(&f, t, depth + 1);
            if generation.is_some() && generation == i.reported {
                continue;
            }
            let r = poll_ready(&f, t, depth + 1) as u32 & (i.events | EPOLLERR | EPOLLHUP);
            if r != 0 {
                out.push((r, i.data));
                i.reported = generation;
                if i.events & EPOLLONESHOT != 0 {
                    i.fired = true;
                }
            }
        }
        out
    }

    pub fn is_ready(&self, t: &Thread, depth: u32) -> bool {
        if depth > 4 {
            return false; // Linux caps nesting too
        }
        let list = self.interest.lock().unwrap();
        list.values().any(|i| {
            !i.fired
                && i.file.upgrade().is_some_and(|f| {
                    let generation = i.generation(&f, t, depth + 1);
                    (generation.is_none() || generation != i.reported) && poll_ready(&f, t, depth + 1) as u32 & (i.events | EPOLLERR | EPOLLHUP) != 0
                })
        })
    }

    /// What a waiter on this watches: what its files say, and itself for changes
    /// to the list.
    pub fn mask(&self, t: &Thread, depth: u32) -> u64 {
        let own = super::wait::key_bit(self as *const Self as usize);
        if depth > 4 {
            return own;
        }
        let list = self.interest.lock().unwrap();
        list.values().filter_map(|i| i.file.upgrade()).fold(own, |m, f| m | poll_mask(&f, t, depth + 1))
    }

    /// The earliest timerfd expiry among the registrations.
    pub fn deadline(&self) -> Option<Instant> {
        let list = self.interest.lock().unwrap();
        list.values()
            .filter_map(|i| i.file.upgrade())
            .filter_map(|f| match &f.kind {
                Kind::Timer(tf) => tf.deadline(),
                _ => None,
            })
            .min()
    }
}
