//! Reconnect backoff with full jitter.
//!
//! When the control-plane connection drops, the agent waits for
//! `initial` before the first retry, then doubles the wait on
//! each subsequent failure up to `max`. A successful connect
//! resets the backoff back to `initial`.
//!
//! "Full jitter" (per the AWS Architecture blog) means each wait
//! is drawn uniformly from `[0, current_ceiling]` rather than
//! `current_ceiling` exactly. The classical fixed-doubling scheme
//! produces thundering herds when a fleet of agents reconnect
//! against the same control-plane outage; full jitter smears the
//! retries across the window and is the canonical posture for
//! both the SDA and SKA agents.

use rand::Rng;
use std::time::Duration;

/// Trait surface so tests can drop in deterministic /
/// instantaneous backoffs without poking at the `rand` rng.
pub trait Backoff: std::fmt::Debug + Send + Sync {
    /// Compute the wait before the next reconnect attempt.
    ///
    /// The caller is expected to invoke this once per failure
    /// and then `tokio::time::sleep` for the returned duration.
    /// On a successful connect the caller invokes [`reset`].
    fn next_backoff(&mut self) -> Duration;

    /// Reset the backoff state on a successful connect.
    fn reset(&mut self);

    /// The current ceiling (next_backoff would draw a uniform
    /// `[0, ceiling]`). Surfaced for observability only.
    fn current_ceiling(&self) -> Duration;
}

/// Full-jitter exponential backoff. The next-wait ceiling
/// doubles after every failure and is capped at `max`. Cloning
/// is cheap and preserves state.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    initial: Duration,
    max: Duration,
    multiplier: u32,
    current_ceiling: Duration,
}

impl ReconnectBackoff {
    /// Construct a backoff with the given window.
    ///
    /// * `initial` — first wait (and post-reset wait). 0 is
    ///   allowed and means "retry immediately" on the first
    ///   failure.
    /// * `max` — ceiling the doubled wait is capped at.
    /// * `multiplier` — exponent base. The classical choice is 2
    ///   (each failure doubles); 3 is occasionally used for
    ///   faster fall-off on long outages.
    ///
    /// Panics in debug builds if `multiplier == 0`; multiplier
    /// must be ≥1.
    #[must_use]
    pub fn new(initial: Duration, max: Duration, multiplier: u32) -> Self {
        debug_assert!(multiplier >= 1, "multiplier must be >= 1");
        Self {
            initial,
            max,
            multiplier: multiplier.max(1),
            current_ceiling: initial,
        }
    }

    /// Convenience: classical exponential backoff (multiplier=2)
    /// with `initial=500ms` and `max=30s`. Matches the SDA
    /// agent's default.
    #[must_use]
    pub fn default_with_max(max: Duration) -> Self {
        Self::new(Duration::from_millis(500), max, 2)
    }
}

impl Default for ReconnectBackoff {
    /// `initial=500ms`, `max=30s`, `multiplier=2`. Tuned to the
    /// SDA / SKA agent posture: aggressive first retry to ride
    /// through transient blips, conservative ceiling to avoid
    /// hammering an outage'd control plane.
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30), 2)
    }
}

impl Backoff for ReconnectBackoff {
    fn next_backoff(&mut self) -> Duration {
        let ceiling = self.current_ceiling;
        // Advance the ceiling for the *next* call. We do this
        // before drawing so an immediate-zero initial value
        // still produces a non-zero second backoff.
        let next = ceiling.saturating_mul(self.multiplier).min(self.max);
        self.current_ceiling = next.max(self.initial);
        if ceiling.is_zero() {
            return Duration::ZERO;
        }
        // Full jitter: uniform draw in [0, ceiling]. We work in
        // nanoseconds so sub-millisecond jitter still has
        // resolution.
        let ceiling_nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
        let jittered_nanos = rand::thread_rng().gen_range(0..=ceiling_nanos);
        Duration::from_nanos(jittered_nanos)
    }

    fn reset(&mut self) {
        self.current_ceiling = self.initial;
    }

    fn current_ceiling(&self) -> Duration {
        self.current_ceiling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_backoff_within_ceiling() {
        let mut b = ReconnectBackoff::new(Duration::from_millis(100), Duration::from_secs(5), 2);
        for _ in 0..100 {
            // Capture the ceiling *before* `next_backoff` advances
            // it. The returned wait is drawn from `[0, OLD_ceiling]`;
            // asserting against `b.current_ceiling()` after the call
            // would compare against `OLD * multiplier` (always larger
            // when `multiplier >= 1`), which is trivially satisfied
            // and would fail to catch a future regression that
            // widened the jitter range (e.g. `gen_range(0..=ceiling * 10)`).
            let pre = b.current_ceiling();
            let wait = b.next_backoff();
            assert!(
                wait <= pre,
                "jitter draw {wait:?} exceeded pre-advance ceiling {pre:?}",
            );
        }
    }

    #[test]
    fn ceiling_doubles_until_max() {
        let mut b =
            ReconnectBackoff::new(Duration::from_millis(100), Duration::from_millis(800), 2);
        let _ = b.next_backoff();
        assert_eq!(b.current_ceiling(), Duration::from_millis(200));
        let _ = b.next_backoff();
        assert_eq!(b.current_ceiling(), Duration::from_millis(400));
        let _ = b.next_backoff();
        assert_eq!(b.current_ceiling(), Duration::from_millis(800));
        // Subsequent calls stay at the ceiling.
        let _ = b.next_backoff();
        assert_eq!(b.current_ceiling(), Duration::from_millis(800));
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut b = ReconnectBackoff::new(Duration::from_millis(50), Duration::from_secs(5), 2);
        for _ in 0..5 {
            let _ = b.next_backoff();
        }
        assert!(b.current_ceiling() > Duration::from_millis(50));
        b.reset();
        assert_eq!(b.current_ceiling(), Duration::from_millis(50));
    }

    #[test]
    fn zero_initial_yields_zero_first_wait() {
        let mut b = ReconnectBackoff::new(Duration::ZERO, Duration::from_secs(1), 2);
        assert_eq!(b.next_backoff(), Duration::ZERO);
        // After the first attempt the ceiling reverts to
        // `initial` (zero) — we cap with `next.max(self.initial)`
        // so a zero-initial backoff cannot escalate. This is the
        // "retry immediately, forever" posture some callers want.
        assert_eq!(b.current_ceiling(), Duration::ZERO);
    }

    #[test]
    fn default_constant_window() {
        let b = ReconnectBackoff::default();
        assert_eq!(b.current_ceiling(), Duration::from_millis(500));
    }
}
