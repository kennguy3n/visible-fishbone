//! Per-(tenant, principal) rate limiter.
//!
//! The SWG must protect the verdict providers from a runaway
//! client — a categoriser HTTP call to an external feed costs
//! real money, a misconfigured tenant must not be able to ramp
//! that bill arbitrarily. The limiter is a token-bucket per
//! bucket key with a deterministic clock so the tests don't
//! sleep.
//!
//! Buckets are keyed by `(tenant_id, principal_id)`. Two
//! principals on the same tenant share neither the bucket
//! capacity nor the refill rate. Capacity and refill rate are
//! the same for every bucket — operator policy can later carry a
//! per-principal multiplier but at v0 a single global config is
//! the right default.
//!
//! Concurrency model: an internal [`parking_lot::Mutex`] guards
//! the bucket map. The critical section is one HashMap lookup
//! plus a single arithmetic update, so the lock is held for
//! microseconds. The map is sharded by hash on the key for higher
//! parallelism, but the v0 implementation keeps a single
//! [`std::collections::HashMap`] — the workload is bursty,
//! never long-tail enough that the single-mutex critical
//! section becomes the bottleneck.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Pluggable monotonic clock. The production implementation
/// returns the OS monotonic clock; the test implementation
/// returns a value the test increments by hand so bucket
/// behaviour is fully deterministic.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current monotonic time as a Duration since the
    /// clock's epoch. The exact epoch is unspecified — only
    /// differences are meaningful.
    fn now(&self) -> Duration;
}

/// Production clock backed by the OS monotonic source.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        // `Instant` is monotonic but has no Duration accessor
        // across instances; we convert to a Duration using the
        // wall clock difference from a single process-wide anchor.
        //
        // The anchor MUST be process-global (not thread-local):
        // the rate-limiter buckets are shared across every tokio
        // worker thread via `Arc<Mutex<HashMap>>`, and
        // `bucket.last_refill` is stored as a `Duration` from this
        // anchor's epoch. A `thread_local!` anchor would give each
        // worker its own Instant initialised at a different
        // wall-clock time, so the elapsed-time math
        // (`now.checked_sub(bucket.last_refill)`) would use
        // incompatible epochs across threads — either under-
        // refilling (thread started later → smaller now() →
        // checked_sub falls back to zero, tokens never refill) or
        // over-refilling (thread started earlier → inflated
        // elapsed → extra tokens beyond capacity). `LazyLock`
        // gives us one Instant for the whole process, initialised
        // on the first call from any thread.
        static ANCHOR: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
        ANCHOR.elapsed()
    }
}

/// Deterministic test clock. The test bumps the inner Duration
/// to simulate elapsed time without sleeping.
#[derive(Debug, Default, Clone)]
pub struct TestClock {
    inner: Arc<Mutex<Duration>>,
}

impl TestClock {
    /// Construct a TestClock anchored at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }

    /// Advance the clock by `delta` so tests can drive refill
    /// behaviour without sleeping.
    pub fn advance(&self, delta: Duration) {
        let mut g = self.inner.lock();
        // checked_add only overflows past Ɉ2**63 ns (≈29 yrs).
        // Tests won't run that long, so saturating is safe and
        // preserves the no-panic contract for the production
        // lint policy.
        *g = g.saturating_add(delta);
    }

    /// Set the clock to an absolute Duration. Used to load
    /// canned timelines without computing offsets by hand.
    pub fn set(&self, t: Duration) {
        *self.inner.lock() = t;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        *self.inner.lock()
    }
}

/// One token bucket — capacity, refill rate, last refill time.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Currently available tokens. Floating-point so we can
    /// refill at fractional rates without rounding loss.
    tokens: f64,
    /// Last time we refilled (and reduced the elapsed delta
    /// against the bucket's capacity). Stored as a Duration
    /// from the clock's epoch so the bucket carries no
    /// inherited Instant.
    last_refill: Duration,
}

/// Per-request rate-limit decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Whether the request was permitted.
    pub permitted: bool,
    /// How many seconds the caller should wait before retrying
    /// (Envoy translates this into a Retry-After header on the
    /// 429 response). Zero for permitted requests; positive for
    /// rejected ones.
    pub retry_after_secs: u64,
    /// Bucket key the decision was made against — used by the
    /// telemetry layer to surface the offending tenant/principal
    /// pair without re-deriving it.
    pub bucket_key: String,
}

/// Token-bucket rate limiter. Cheap to clone — the inner state
/// is in an `Arc<Mutex<…>>`.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    clock: Arc<dyn Clock>,
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
}

impl RateLimiter {
    /// Build a new rate limiter with explicit capacity and
    /// refill. `capacity` is the maximum number of tokens a
    /// bucket can hold at once (one token = one request);
    /// `refill_per_sec` is how many tokens are returned per
    /// second of elapsed time.
    ///
    /// Capacity must be > 0; refill_per_sec must be >= 0. The
    /// validator is at construction time so the per-request
    /// path can assume the invariants.
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64, clock: Arc<dyn Clock>) -> Self {
        assert!(capacity > 0.0, "rate limiter capacity must be > 0");
        assert!(
            refill_per_sec >= 0.0,
            "rate limiter refill_per_sec must be >= 0"
        );
        Self {
            capacity,
            refill_per_sec,
            clock,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build a limiter with a SystemClock — convenience for the
    /// production wiring path. Tests should construct with
    /// `new(.., .., Arc::new(TestClock::new()))` instead so the
    /// scheduler is deterministic.
    #[must_use]
    pub fn with_system_clock(capacity: f64, refill_per_sec: f64) -> Self {
        Self::new(capacity, refill_per_sec, Arc::new(SystemClock))
    }

    /// Acquire one token from the (tenant, principal) bucket.
    /// Returns a RateLimitDecision with `permitted = true` on
    /// success and a non-zero retry_after on rejection.
    pub fn acquire(&self, tenant_id: &str, principal_id: &str) -> RateLimitDecision {
        let key = format_key(tenant_id, principal_id);
        let now = self.clock.now();
        let mut buckets = self.buckets.lock();
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        // Refill: add (now - last_refill) * refill_per_sec
        // tokens, clamped to capacity. Saturating subtraction
        // protects against a clock that returns a non-monotonic
        // value (shouldn't happen with a monotonic source but
        // the TestClock could be set backwards).
        let elapsed = now
            .checked_sub(bucket.last_refill)
            .unwrap_or(Duration::ZERO);
        let added = elapsed.as_secs_f64() * self.refill_per_sec;
        bucket.tokens = (bucket.tokens + added).min(self.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitDecision {
                permitted: true,
                retry_after_secs: 0,
                bucket_key: key,
            }
        } else {
            // Compute the wait until the bucket has 1 token.
            // refill_per_sec must be > 0 for a deficit to ever
            // refill; if it's zero, every reject returns the
            // SAFE default of 60s so clients don't busy-loop.
            let deficit = 1.0 - bucket.tokens;
            let wait = if self.refill_per_sec > 0.0 {
                // `deficit` is in [0.0, 1.0) and `refill_per_sec`
                // is positive, so the ratio is non-negative
                // and ≤ 1 / refill_per_sec. The ceil keeps the
                // value an integral count of seconds. We bound
                // the result to [0, 3600] so even a pathological
                // refill rate of 1e-12 tokens/s caps the wait
                // at one hour rather than overflowing the cast.
                let secs_f = (deficit / self.refill_per_sec).ceil().clamp(0.0, 3600.0);
                // The clamp above guarantees [0, 3600] which
                // fits in u64 without truncation or sign loss,
                // so the `as u64` is exact.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let secs_u = secs_f as u64;
                secs_u
            } else {
                60
            };
            RateLimitDecision {
                permitted: false,
                retry_after_secs: wait.max(1),
                bucket_key: key,
            }
        }
    }

    /// Number of buckets currently tracked. Mostly for tests +
    /// telemetry; production callers should treat this as
    /// debug-only.
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }

    /// Drop buckets that have been idle for more than `idle_max`
    /// — bounded memory hygiene for a long-running supervisor.
    /// The manager calls this on a periodic timer.
    pub fn evict_idle(&self, idle_max: Duration) {
        let now = self.clock.now();
        let mut buckets = self.buckets.lock();
        buckets.retain(|_, b| {
            now.checked_sub(b.last_refill)
                .is_some_and(|age| age < idle_max)
        });
    }
}

fn format_key(tenant_id: &str, principal_id: &str) -> String {
    // Pipe-separated so the rare principal id containing a
    // colon does not collide with a tenant_id|principal_id
    // pair on a different tenant.
    format!("{tenant_id}|{principal_id}")
}

/// Wall-clock-stable timestamp formatter used by the telemetry
/// emitter — placed here so the rate limiter does not pull a
/// chrono dependency just for one helper.
#[must_use]
pub fn wall_clock_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn limiter_with_test_clock(cap: f64, refill: f64) -> (RateLimiter, TestClock) {
        let clock = TestClock::new();
        let rl = RateLimiter::new(cap, refill, Arc::new(clock.clone()));
        (rl, clock)
    }

    #[test]
    fn first_request_is_permitted_and_bucket_is_lazily_created() {
        let (rl, _clock) = limiter_with_test_clock(5.0, 1.0);
        assert_eq!(rl.bucket_count(), 0);
        let d = rl.acquire("t1", "p1");
        assert!(d.permitted);
        assert_eq!(d.retry_after_secs, 0);
        assert_eq!(d.bucket_key, "t1|p1");
        assert_eq!(rl.bucket_count(), 1);
    }

    #[test]
    fn capacity_exhausts_after_n_requests_in_same_tick() {
        // Capacity 3 means 3 requests succeed; the 4th must be
        // rate-limited because the clock hasn't advanced.
        let (rl, _clock) = limiter_with_test_clock(3.0, 1.0);
        for i in 0..3 {
            assert!(
                rl.acquire("t1", "p1").permitted,
                "request {i} should permit"
            );
        }
        let d = rl.acquire("t1", "p1");
        assert!(!d.permitted);
        assert!(d.retry_after_secs >= 1, "retry_after should be >= 1");
    }

    #[test]
    fn tokens_refill_with_elapsed_time() {
        let (rl, clock) = limiter_with_test_clock(2.0, 1.0);
        // Drain.
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(!rl.acquire("t1", "p1").permitted);
        // Wait one second — one token comes back.
        clock.advance(Duration::from_secs(1));
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(!rl.acquire("t1", "p1").permitted);
        // Wait long enough to refill to capacity (and try to
        // overflow). Capacity must clamp.
        clock.advance(Duration::from_secs(100));
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(!rl.acquire("t1", "p1").permitted);
    }

    #[test]
    fn different_principals_have_independent_buckets() {
        // Two principals on the same tenant must not share their
        // bucket — exhausting p1 must leave p2 still permitted.
        let (rl, _clock) = limiter_with_test_clock(1.0, 0.0);
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(!rl.acquire("t1", "p1").permitted);
        assert!(rl.acquire("t1", "p2").permitted);
    }

    #[test]
    fn different_tenants_have_independent_buckets() {
        let (rl, _clock) = limiter_with_test_clock(1.0, 0.0);
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(!rl.acquire("t1", "p1").permitted);
        assert!(rl.acquire("t2", "p1").permitted);
    }

    #[test]
    fn retry_after_carries_at_least_one_second() {
        // With a small fractional refill rate, the time-to-one-
        // token can round down to zero seconds; the limiter
        // rounds up so the client never gets a Retry-After of 0
        // (which Envoy interprets as "retry immediately").
        let (rl, _clock) = limiter_with_test_clock(1.0, 0.5);
        assert!(rl.acquire("t1", "p1").permitted);
        let d = rl.acquire("t1", "p1");
        assert!(!d.permitted);
        assert!(d.retry_after_secs >= 1, "got {}", d.retry_after_secs);
    }

    #[test]
    fn zero_refill_uses_60_second_fallback() {
        // Zero refill means the bucket will never recover on
        // its own; the limiter returns a SAFE default so the
        // client doesn't busy-loop.
        let (rl, _clock) = limiter_with_test_clock(1.0, 0.0);
        assert!(rl.acquire("t1", "p1").permitted);
        let d = rl.acquire("t1", "p1");
        assert!(!d.permitted);
        assert_eq!(d.retry_after_secs, 60);
    }

    #[test]
    fn evict_idle_drops_stale_buckets() {
        let (rl, clock) = limiter_with_test_clock(1.0, 1.0);
        assert!(rl.acquire("t1", "p1").permitted);
        assert!(rl.acquire("t1", "p2").permitted);
        assert_eq!(rl.bucket_count(), 2);
        // Move forward past idle threshold; both buckets drop.
        clock.advance(Duration::from_secs(60));
        rl.evict_idle(Duration::from_secs(30));
        assert_eq!(rl.bucket_count(), 0);
        // A fresh acquire repopulates a single bucket.
        assert!(rl.acquire("t1", "p1").permitted);
        assert_eq!(rl.bucket_count(), 1);
    }

    #[test]
    fn non_monotonic_clock_does_not_panic() {
        // A TestClock that's been set backwards must not cause
        // a subtract-overflow on the refill calculation.
        let clock = TestClock::new();
        clock.set(Duration::from_secs(100));
        let rl = RateLimiter::new(2.0, 1.0, Arc::new(clock.clone()));
        assert!(rl.acquire("t1", "p1").permitted);
        clock.set(Duration::from_secs(50));
        // After the backward jump, the limiter saturates
        // elapsed=0 so no extra tokens are credited but no
        // panic either.
        assert!(rl.acquire("t1", "p1").permitted);
    }

    #[test]
    #[should_panic(expected = "capacity")]
    fn zero_capacity_panics_on_construction() {
        // Misconfiguration check — a limiter with zero capacity
        // would reject every request, which is almost certainly
        // not what the operator intended. Surface the bug at
        // construction.
        let _ = RateLimiter::with_system_clock(0.0, 1.0);
    }

    #[test]
    #[should_panic(expected = "refill_per_sec")]
    fn negative_refill_panics_on_construction() {
        let _ = RateLimiter::with_system_clock(1.0, -1.0);
    }

    #[test]
    fn wall_clock_returns_a_recent_unix_timestamp() {
        // Mid-2020 to year 2200 is a wide window; the helper
        // just needs to return something reasonable.
        let t = wall_clock_unix_secs();
        assert!(t > 1_500_000_000, "wall_clock too low: {t}");
        assert!(t < 7_200_000_000, "wall_clock too high: {t}");
    }

    #[test]
    fn system_clock_anchor_is_process_global_not_per_thread() {
        // Regression test for the cross-thread refill bug:
        // `SystemClock::now()` must return values from a single
        // monotonically-increasing epoch shared by every thread.
        // If the anchor were `thread_local!`, a newly-spawned
        // thread would initialise its own Instant later than the
        // process anchor, so its `now()` would return a SMALLER
        // Duration than a thread that had already initialised —
        // and the rate-limiter's `last_refill` math (which stores
        // a Duration from one thread and subtracts a Duration
        // observed on another) would silently under-refill the
        // bucket. The fix is `std::sync::LazyLock<Instant>`; this
        // test pins that.
        let clock = SystemClock;
        // Anchor the process-global Instant on this thread first
        // so subsequent threads can only return larger values.
        let t0 = clock.now();
        // Spin up a few worker threads — each observes the same
        // shared anchor. With a thread-local anchor each thread
        // would start near zero; with the shared anchor each
        // thread sees at least `t0`.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let h = std::thread::spawn(|| SystemClock.now());
            handles.push(h);
        }
        // Give the workers a tiny window so their observed
        // Duration is strictly greater than `t0`.
        std::thread::sleep(Duration::from_millis(10));
        let t_final = clock.now();
        assert!(t_final >= t0, "anchor went backwards on same thread");
        for (i, h) in handles.into_iter().enumerate() {
            let t_worker = h.join().expect("thread join");
            // The worker must see the SAME process anchor — its
            // `now()` cannot be smaller than `t0` (which was
            // observed before the worker spawned).
            assert!(
                t_worker >= t0,
                "worker {i} observed {t_worker:?} < t0 {t0:?} \
                 — the SystemClock anchor is per-thread, which \
                 would cause cross-thread rate-limit refill bugs",
            );
        }
    }
}
