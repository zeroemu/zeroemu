//! The clocks clock_gettime reads that aren't CPU time: CLOCK_MONOTONIC, BOOTTIME and
//! REALTIME, their coarse, raw and alarm forms, and TAI (kernel/time/posix-timers.c).
//! Each is CLOCK_MONOTONIC plus an offset, as in Linux's timekeeping, so that they
//! are computed in one place from a few numbers, which the vDSO (vdso.rs) is handed
//! and computes the same way, to the nanosecond:
//!
//! - CLOCK_MONOTONIC is the host counter's ticks since its zero (hv::clock), in
//!   nanoseconds: what guest code reads from CNTVCT_EL0. It stops while the host
//!   sleeps, as Linux's does while suspended.
//! - CLOCK_BOOTTIME is the same. On Linux it goes on counting during suspend, but
//!   here it never has: it adds nothing to CLOCK_MONOTONIC.
//! - CLOCK_REALTIME is CLOCK_MONOTONIC plus an offset, taken from the host's wall
//!   clock and brought up to date ten times a second (`refresh`). Linux keeps
//!   wall-clock time the same way, as an offset from monotonic time (tk->offs_real
//!   in kernel/time/timekeeping.c).
//!
//! Input event times, GPU fence and flip times and trace times are CLOCK_MONOTONIC
//! too (`monotonic`), and absolute CLOCK_REALTIME deadlines count from `realtime`, so
//! none disagrees with a clock read in the guest.

use crate::hv::clock as counter;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The clock ids answered here, as a bit mask: REALTIME (0), MONOTONIC (1),
/// MONOTONIC_RAW (4), REALTIME_COARSE (5), MONOTONIC_COARSE (6), BOOTTIME (7),
/// REALTIME_ALARM (8), BOOTTIME_ALARM (9) and TAI (11). The others are the CPU-time
/// clocks (2, 3 and negative ids) and ids Linux doesn't have.
pub const SERVED: u32 = 1 << 0 | 1 << 1 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 11;
/// The served ids that are wall-clock time. TAI is too: Linux's TAI offset is 0
/// until something (an NTP daemon) sets it, and nothing here does.
pub const WALL: u32 = 1 << 0 | 1 << 5 | 1 << 8 | 1 << 11;

/// CLOCK_REALTIME less CLOCK_MONOTONIC, in nanoseconds (wrapping).
static REALTIME_OFFSET: AtomicU64 = AtomicU64::new(0);
static FIRST: Once = Once::new();

/// How far the host's wall clock must have moved from what the guest's says before
/// the guest's follows it. macOS's wall clock has microsecond steps, so every reading
/// of the offset differs a little from the last; following each one would step the
/// guest's wall clock back and forth ten times a second. The host's clock drifts
/// away from ours only as fast as it is being slewed.
const STEP: u64 = 20_000;

/// Nanoseconds since CLOCK_MONOTONIC's zero.
pub fn monotonic_ns() -> u64 {
    // The zero first: the first caller in the process fixes it from a counter reading
    // of its own, which a reading taken before it could precede. And a thread that
    // read the counter while another was fixing the zero reads 0, not a wrapped
    // difference centuries long.
    let zero = counter::zero().0;
    counter::to_ns(counter::now().saturating_sub(zero))
}

/// CLOCK_MONOTONIC, as a Duration.
pub fn monotonic() -> Duration {
    Duration::from_nanos(monotonic_ns())
}

/// CLOCK_REALTIME, as the time since 1970.
pub fn realtime() -> Duration {
    Duration::from_nanos(monotonic_ns().wrapping_add(realtime_offset()))
}

/// What CLOCK_REALTIME adds to CLOCK_MONOTONIC.
pub fn realtime_offset() -> u64 {
    FIRST.call_once(|| {
        refresh();
    });
    REALTIME_OFFSET.load(Ordering::Relaxed)
}

/// Brings CLOCK_REALTIME up to date with the host's wall clock. True if it moved.
pub fn refresh() -> bool {
    let before = monotonic_ns();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let after = monotonic_ns();
    let new = wall.wrapping_sub(before + (after - before) / 2);
    let old = REALTIME_OFFSET.load(Ordering::Relaxed);
    if old != 0 && new.abs_diff(old) < STEP {
        return false;
    }
    REALTIME_OFFSET.store(new, Ordering::Relaxed);
    true
}

/// What clock `id` adds to CLOCK_MONOTONIC, or None if it isn't one of these.
pub fn offset(id: u32) -> Option<u64> {
    if id >= 32 || SERVED >> id & 1 == 0 {
        return None;
    }
    Some(if WALL >> id & 1 != 0 { realtime_offset() } else { 0 })
}

/// Clock `id` now, in nanoseconds, or None if it isn't one of these.
pub fn now_ns(id: u32) -> Option<u64> {
    let off = offset(id)?;
    Some(monotonic_ns().wrapping_add(off))
}

impl super::Kernel {
    /// Keeps CLOCK_REALTIME with the host's wall clock, the vDSO's too: called ten
    /// times a second.
    pub(super) fn tick_clocks(&self) {
        if refresh()
            && let Some(v) = &self.vdso
        {
            v.update();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_is_the_host_wall_clock() {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let ours = now_ns(0).unwrap();
        assert!(ours.abs_diff(wall) < 10_000_000, "REALTIME {ours} against the host's {wall}");
        assert_eq!(offset(1), Some(0));
        assert_eq!(offset(7), Some(0));
        assert_eq!(offset(2), None);
        assert_eq!(offset(10), None);
        assert_eq!(offset(40), None);
    }
}
