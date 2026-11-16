//! The host's counter, which guest code can read too, and CLOCK_MONOTONIC's zero on
//! it. Under Hypervisor.framework a guest's CNTVCT_EL0 is mach_absolute_time() less
//! the vCPU's vtimer offset (hv_vcpu.h), and hvf.rs sets that offset to `zero().0` on
//! every vCPU it makes: guest code then reads the ticks since CLOCK_MONOTONIC's zero,
//! the same on every vCPU, however late it was made. The kernel's CLOCK_MONOTONIC
//! counts from that zero in the same ticks.

use std::sync::OnceLock;
use std::time::Instant;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut [u32; 2]) -> i32;
}

/// Where the counter starts where there is no mach_absolute_time: it counts the
/// nanoseconds since this.
#[cfg(not(target_os = "macos"))]
static ORIGIN: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

/// The counter now, in ticks.
pub fn now() -> u64 {
    #[cfg(target_os = "macos")]
    {
        unsafe { mach_absolute_time() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        ORIGIN.elapsed().as_nanos() as u64
    }
}

/// (numer, denom): a tick is numer / denom nanoseconds. 125 / 3 on Apple Silicon,
/// whose counter runs at 24 MHz.
pub fn timebase() -> (u32, u32) {
    static TB: OnceLock<(u32, u32)> = OnceLock::new();
    *TB.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            let mut tb = [0u32; 2];
            if unsafe { mach_timebase_info(&mut tb) } == 0 && tb[0] != 0 && tb[1] != 0 {
                return (tb[0], tb[1]);
            }
        }
        (1, 1)
    })
}

/// Ticks as nanoseconds, rounded down, computed as (t / denom) * numer +
/// (t % denom) * numer / denom: exact, and without overflow for centuries. The vDSO
/// computes the same, so both agree to the nanosecond.
pub fn to_ns(ticks: u64) -> u64 {
    let (n, d) = timebase();
    let (n, d) = (n as u64, d as u64);
    (ticks / d) * n + (ticks % d) * n / d
}

/// CLOCK_MONOTONIC's zero, fixed by whoever asks first: the counter then, and the
/// Instant from which deadlines (kept as Instants) count.
///
/// The counter's zero is a multiple of denom, so that the nanoseconds since it are
/// exactly macOS's own uptime in nanoseconds, which Instant reads, less a constant:
/// the two never round apart. And it is at least a tick before the Instant, so a
/// deadline `zero().1 + d` falls no earlier than `d` on the counter: a guest woken
/// at it never reads its clock short of the time it asked for.
pub fn zero() -> (u64, Instant) {
    static ZERO: OnceLock<(u64, Instant)> = OnceLock::new();
    *ZERO.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            let d = timebase().1 as u64;
            let t = now().saturating_sub(1);
            (t - t % d, Instant::now())
        }
        // Here the counter is Instant itself, so the zero can be exactly ORIGIN.
        #[cfg(not(target_os = "macos"))]
        {
            (0, *ORIGIN)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_to_ns_is_exact() {
        let (n, d) = timebase();
        for t in [0u64, 1, 2, 3, 23, 24_000_000, 1 << 40, 123_456_789_012_345] {
            assert_eq!(to_ns(t) as u128, t as u128 * n as u128 / d as u128, "{t} ticks");
        }
    }

    #[test]
    fn monotonic_zero_is_before_its_instant() {
        let (t0, at) = zero();
        let elapsed = at.elapsed().as_nanos();
        let since = to_ns(now() - t0);
        // The counter's time since zero, read later, is at least the Instant's.
        assert!(since as u128 >= elapsed);
        assert_eq!(t0 % timebase().1 as u64, 0);
    }
}
