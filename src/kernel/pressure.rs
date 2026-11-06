//! Running short of memory, as a kernel handles it. Over the amount the guest
//! believes it has, this takes back what the page cache holds (kswapd's job), and
//! if that isn't enough tells whoever is watching /proc/pressure/memory. That is
//! lmkd, which closes the least important apps, as on a phone; and system_server,
//! which asks apps to trim their caches.

use super::Kernel;
use super::wait::EVENTS;
use crate::phys::{self, PAGE};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_millis(100);

#[derive(Default)]
pub struct Pressure {
    /// What PSI triggers wake on: "some" tasks stalled, and "full", all of them.
    pub some: Arc<AtomicU64>,
    pub full: Arc<AtomicU64>,
    /// Pages looked at to reclaim (vmstat's pgscan_kswapd).
    pub scanned: AtomicU64,
    /// Times memory ran short. This is what lmkd's workingset_refault_file is for us.
    pub short: AtomicU64,
}

/// (min, low, high), in pages, as /proc/zoneinfo gives them. On Linux these are tighter,
/// but there a page cache many times the size of this one stands in front of them.
pub fn watermarks(ram_pages: u64) -> (u64, u64, u64) {
    (ram_pages * 3 / 200, ram_pages / 40, ram_pages / 25)
}

pub fn start(k: &Arc<Kernel>) {
    let k = Arc::downgrade(k);
    let _ = std::thread::Builder::new().name("kswapd".into()).spawn(move || {
        while let Some(k) = k.upgrade() {
            check(&k);
            drop(k);
            std::thread::sleep(INTERVAL);
        }
    });
}

fn check(k: &Kernel) {
    let ram = phys::ram() / PAGE;
    let (min, low, high) = watermarks(ram);
    let free = || ram.saturating_sub(k.phys.frames_in_use());
    let before = free();
    if before >= high {
        return;
    }
    let reclaimed = k.vfs.as_deref().and_then(|v| v.page_cache()).map_or(0, |c| c.reclaim(high - before));
    k.pressure.scanned.fetch_add(reclaimed + 1, Ordering::Relaxed);
    let now = free();
    if now < low {
        // With its BPF memory events available lmkd takes no notice of pgscan_kswapd,
        // and without one of these moving, it takes nothing to be going on.
        k.pressure.short.fetch_add(1, Ordering::Relaxed);
        k.pressure.some.fetch_add(1, Ordering::Relaxed);
        if now < min {
            k.pressure.full.fetch_add(1, Ordering::Relaxed);
        }
        EVENTS.bump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermarks_rise_and_leave_room() {
        let (min, low, high) = watermarks((4 << 30) / PAGE);
        assert!(0 < min && min < low && low < high);
        assert!(high * PAGE < 256 << 20, "high is {} MB", high * PAGE >> 20);
    }
}
