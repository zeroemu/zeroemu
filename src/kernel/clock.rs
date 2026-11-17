//! The clocks clock_gettime reads that aren't CPU time: CLOCK_MONOTONIC, BOOTTIME and
//! REALTIME, their coarse, raw and alarm forms, and TAI (kernel/time/posix-timers.c).
//! Each is computed from CLOCK_MONOTONIC in one place from a few numbers, which the
//! vDSO (vdso.rs) is handed and computes the same way, to the nanosecond:
//!
//! - CLOCK_MONOTONIC is the host counter's ticks since its zero (hv::clock), in
//!   nanoseconds: what guest code reads from CNTVCT_EL0. It stops while the host
//!   sleeps, as Linux's does while suspended. That takes Hypervisor.framework to keep
//!   the guest's counter at mach_absolute_time() less the vtimer offset across the
//!   host's sleep too, as hv_vcpu.h describes the offset.
//! - CLOCK_BOOTTIME is the same. On Linux it goes on counting during suspend, but
//!   here it never has: it adds nothing to CLOCK_MONOTONIC.
//! - CLOCK_REALTIME is CLOCK_MONOTONIC plus an offset that follows the host's wall
//!   clock (`Line`). Linux keeps wall-clock time as an offset from monotonic time
//!   too (tk->offs_real in kernel/time/timekeeping.c), which only setting the clock
//!   or resuming from suspend moves. NTP's corrections there change how fast both
//!   clocks run (the clocksource's mult), so neither ever goes back. Here
//!   CLOCK_MONOTONIC is the counter, which can't be slowed, so the corrections the
//!   host makes to its own wall clock (timed slews it against mach_absolute_time) go
//!   into the offset as a rate instead: CLOCK_REALTIME gains or loses on
//!   CLOCK_MONOTONIC, at most as fast as NTP slews Linux's clock, until it agrees with
//!   the host's again. Only a gap a slew would take minutes to close, which setting
//!   the host's clock or its sleep makes, is stepped: within a tick of the clock
//!   being set, and as soon as the host wakes. Linux steps it on resume before any
//!   task runs again (timekeeping_resume in kernel/time/timekeeping.c); here a guest
//!   thread that was running when the host went to sleep can read the old time for
//!   the moment before kswapd's tick.
//!
//! Input event times, GPU fence and flip times and trace times are CLOCK_MONOTONIC
//! too (`monotonic`), and absolute CLOCK_REALTIME deadlines count from `realtime`, so
//! none disagrees with a clock read in the guest.

use crate::hv::clock as counter;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Mutex, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The clock ids answered here, as a bit mask: REALTIME (0), MONOTONIC (1),
/// MONOTONIC_RAW (4), REALTIME_COARSE (5), MONOTONIC_COARSE (6), BOOTTIME (7),
/// REALTIME_ALARM (8), BOOTTIME_ALARM (9) and TAI (11). The others are the CPU-time
/// clocks (2, 3 and negative ids) and ids Linux doesn't have.
pub const SERVED: u32 = 1 << 0 | 1 << 1 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 11;
/// The served ids that are wall-clock time. TAI is too: Linux's TAI offset is 0
/// until something (an NTP daemon) sets it, and nothing here does.
pub const WALL: u32 = 1 << 0 | 1 << 5 | 1 << 8 | 1 << 11;

/// CLOCK_REALTIME against CLOCK_MONOTONIC, in nanoseconds: when CLOCK_MONOTONIC reads
/// `base`, CLOCK_REALTIME reads `base + offset` (wrapping), and from there it gains
/// `rate` / 2^32 ns on CLOCK_MONOTONIC for each nanosecond, or loses if `rate` is
/// negative. |rate| is far below 2^32, so CLOCK_REALTIME never runs backward.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Line {
    pub base: u64,
    pub offset: u64,
    pub rate: i64,
}

impl Line {
    /// CLOCK_REALTIME when CLOCK_MONOTONIC reads `mono`. The gain is (mono - base) *
    /// rate as 128 bits, shifted right by 32 (rounded down), as vdso.S computes it.
    pub fn at(&self, mono: u64) -> u64 {
        let gain = ((mono.wrapping_sub(self.base) as i64 as i128 * self.rate as i128) >> 32) as i64;
        mono.wrapping_add(self.offset).wrapping_add(gain as u64)
    }
}

// The line, as readers find it. It changes only while the sequence count is odd, as
// Linux's timekeeper does (tk_core.seq in kernel/time/timekeeping.c).
static SEQ: AtomicU32 = AtomicU32::new(0);
static BASE: AtomicU64 = AtomicU64::new(0);
static OFFSET: AtomicU64 = AtomicU64::new(0);
static RATE: AtomicU64 = AtomicU64::new(0);
static FIRST: Once = Once::new();
/// One writer at a time.
static WRITING: Mutex<()> = Mutex::new(());

/// A gap this wide between CLOCK_REALTIME and the host's wall clock is stepped, not
/// slewed: ntpd's default step threshold (CLOCK_MAX in ntpd/ntp_loopfilter.c). Only
/// setting the host's clock makes one, or the host's sleep, during which
/// CLOCK_MONOTONIC stops and the wall clock doesn't. A slew at MAX_RATE closes a
/// narrower one in at most about four minutes.
const STEP: u64 = 128_000_000;
/// How fast CLOCK_REALTIME may gain or lose on CLOCK_MONOTONIC, as a `Line::rate`:
/// 500 ppm, as fast as NTP may slew Linux's clocks (MAXFREQ in include/linux/timex.h).
const MAX_RATE: i64 = (500 << 32) / 1_000_000;
/// The rate is the gap over this, so that a slew closes it in about a second, at the
/// cost of trailing a host clock that is itself being slewed by its rate times this:
/// 10 us at 10 ppm.
const GAIN_NS: i128 = 1_000_000_000;
/// The narrowest reading of the host's wall clock (`sample`) wider than this is
/// passed over: half of it is how far off it can be.
const WIDEST: u64 = 1_000_000;
/// How long after its own reading of the counter a reader may still apply the line
/// it read before the host changed it: the counter read is done late, or the host's
/// change isn't yet seen on that CPU. Hundreds of nanoseconds at most (`next`).
const MARGIN: u64 = 10_000;

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

/// CLOCK_REALTIME, in nanoseconds since 1970.
pub fn realtime_ns() -> u64 {
    let (line, mono) = read();
    line.at(mono)
}

/// CLOCK_REALTIME, as the time since 1970.
pub fn realtime() -> Duration {
    Duration::from_nanos(realtime_ns())
}

/// CLOCK_REALTIME when CLOCK_MONOTONIC read `mono`, on the line it follows now.
pub fn realtime_at(mono: u64) -> u64 {
    read().0.at(mono)
}

/// CLOCK_REALTIME's line now.
pub fn line() -> Line {
    read().0
}

/// Clock `id` now, in nanoseconds, or None if it isn't one of these.
pub fn now_ns(id: u32) -> Option<u64> {
    if id >= 32 || SERVED >> id & 1 == 0 {
        return None;
    }
    Some(if WALL >> id & 1 != 0 { realtime_ns() } else { monotonic_ns() })
}

/// The line, and CLOCK_MONOTONIC read with it. The counter is read inside the
/// sequence count, as vdso.S reads it, so that a reader the host's change overtakes
/// reads both again. Applied to a later time, the old line could read ahead of the
/// new one, and the clock would go back from one reading to the next.
fn read() -> (Line, u64) {
    first();
    loop {
        let seq = SEQ.load(Ordering::Acquire);
        if seq & 1 == 0 {
            let mono = monotonic_ns();
            let line = stored();
            fence(Ordering::Acquire);
            if SEQ.load(Ordering::Relaxed) == seq {
                return (line, mono);
            }
        }
        std::hint::spin_loop();
    }
}

/// The first line: the host's wall clock as it reads now. Nobody reads it before
/// this returns.
fn first() {
    FIRST.call_once(|| {
        let (_, wall, at) = sample();
        store(Line { base: at, offset: wall.wrapping_sub(at), rate: 0 });
    });
}

fn stored() -> Line {
    Line { base: BASE.load(Ordering::Relaxed), offset: OFFSET.load(Ordering::Relaxed), rate: RATE.load(Ordering::Relaxed) as i64 }
}

fn store(line: Line) {
    BASE.store(line.base, Ordering::Relaxed);
    OFFSET.store(line.offset, Ordering::Relaxed);
    RATE.store(line.rate as u64, Ordering::Relaxed);
}

/// The host's wall clock and CLOCK_MONOTONIC at the same moment: the narrowest of
/// three readings of the wall clock between two of the counter, taken at the middle.
/// A thread preempted between the two would otherwise be off by half the time it
/// spent waiting for a CPU. (width, wall, monotonic).
fn sample() -> (u64, u64, u64) {
    let mut best = (u64::MAX, 0, 0);
    for _ in 0..3 {
        let before = monotonic_ns();
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        let after = monotonic_ns();
        let width = after.saturating_sub(before);
        if width < best.0 {
            best = (width, wall, before + width / 2);
        }
    }
    best
}

/// The line after `old`, for a host wall clock that read `wall` when CLOCK_MONOTONIC
/// read `at`, turning at `now` (CLOCK_MONOTONIC, read once readers can see the line
/// is changing).
fn next(old: Line, wall: u64, at: u64, now: u64) -> Line {
    let gap = wall.wrapping_sub(old.at(at)) as i64;
    if gap.unsigned_abs() >= STEP {
        return Line { base: at, offset: wall.wrapping_sub(at), rate: 0 };
    }
    let rate = (gap as i128 * (1 << 32) / GAIN_NS).clamp(-MAX_RATE as i128, MAX_RATE as i128) as i64;
    // The new line meets the old one where it turns, a nanosecond ahead for the
    // rounding down on each, so a reader of the new line never reads less than a
    // reader of the old one did before. A reader can still apply the old line a
    // little past `now` (MARGIN); past the turn a slower line is behind the old one,
    // so a slower line turns later, where nobody reads the old one.
    let base = if rate < old.rate { now + MARGIN } else { now };
    Line { base, offset: old.at(base).wrapping_add(1).wrapping_sub(base), rate }
}

impl super::Kernel {
    /// Keeps CLOCK_REALTIME with the host's wall clock, the vDSO's too: called ten
    /// times a second, and as soon as the host wakes (pressure.rs).
    pub(super) fn tick_clocks(&self) {
        first();
        let (width, wall, at) = sample();
        if width > WIDEST {
            return;
        }
        let _one = WRITING.lock().unwrap();
        let n = SEQ.load(Ordering::Relaxed);
        SEQ.store(n.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        // The counter reading the line turns at is taken once readers of both copies,
        // this one and the vDSO's, can see it changing.
        let turn = || {
            let line = next(stored(), wall, at, monotonic_ns());
            store(line);
            line
        };
        match &self.vdso {
            Some(v) => v.update(turn),
            None => {
                turn();
            }
        }
        SEQ.store(n.wrapping_add(2), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATE: u64 = 1_700_000_000_000_000_000;

    #[test]
    fn realtime_is_the_host_wall_clock() {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let ours = now_ns(0).unwrap();
        assert!(ours.abs_diff(wall) < 10_000_000, "REALTIME {ours} against the host's {wall}");
        assert!(now_ns(1).unwrap() < 1 << 62);
        assert_eq!(now_ns(2), None);
        assert_eq!(now_ns(10), None);
        assert_eq!(now_ns(40), None);
    }

    /// Whatever the old line and the gap, a reader of the new line never reads less
    /// than a reader of the old one read before it, even one that applied the old
    /// line a little past the turn; and the new line never runs backward.
    #[test]
    fn slewing_never_goes_back() {
        let now = 5_100_000_000;
        for rate in [0, 1, -1, 12_345, -12_345, MAX_RATE, -MAX_RATE] {
            let old = Line { base: 5_000_000_000, offset: DATE, rate };
            for gap in [-100_000_000i64, -20_000, -1, 0, 1, 20_000, 100_000_000] {
                let at = now - 50_000;
                let new = next(old, old.at(at).wrapping_add(gap as u64), at, now);
                assert!(new.rate.abs() <= MAX_RATE);
                for m in (now - 3_000..now + MARGIN / 2).step_by(7) {
                    assert!(new.at(m.max(now)) >= old.at(m), "rate {rate}, gap {gap}, at {m}");
                }
                let mut last = 0;
                for m in (now - 3_000..now + 3_000_000).step_by(13) {
                    assert!(new.at(m) >= last, "rate {rate}, gap {gap}, at {m}");
                    last = new.at(m);
                }
            }
        }
    }

    /// A host clock that is itself being slewed, as timed slews macOS's, is followed
    /// closely, and never by a step back.
    #[test]
    fn follows_a_slewed_host_clock() {
        for ppm in [-400i128, -10, 0, 10, 400] {
            let host = |m: u64| DATE.wrapping_add((m as i128 + m as i128 * ppm / 1_000_000) as u64);
            // Starting 50 us ahead of it.
            let mut line = Line { base: 0, offset: host(0) + 50_000, rate: 0 };
            let mut last = 0;
            for tick in 1..300u64 {
                let at = tick * 100_000_000;
                line = next(line, host(at), at, at + 1_000);
                for m in (at + 1_000..at + 100_000_000).step_by(999_999) {
                    assert!(line.at(m) >= last, "{ppm} ppm, tick {tick}");
                    last = line.at(m);
                }
            }
            let m = 300 * 100_000_000;
            let off = line.at(m) as i128 - host(m) as i128;
            // It trails by the host's rate times GAIN_NS.
            assert!(off.abs() <= ppm.abs() * 1_000 + 2_000, "{ppm} ppm: {off} ns off");
        }
    }

    /// Setting the host's clock, or its sleep, moves CLOCK_REALTIME at once, either way.
    #[test]
    fn a_set_clock_is_stepped() {
        let old = Line { base: 0, offset: DATE, rate: 1_000 };
        let at = 10_000_000_000;
        for gap in [3_600_000_000_000i64, -2_000_000_000, STEP as i64, -(STEP as i64)] {
            let wall = old.at(at).wrapping_add(gap as u64);
            let new = next(old, wall, at, at + 500);
            assert_eq!((new.at(at), new.rate), (wall, 0), "gap {gap}");
        }
    }
}
