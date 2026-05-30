//! Per-path liveness probe state.
//!
//! A [`PathProbe`] is the most-recent latency / loss /
//! jitter observation the SD-WAN brain has for a given
//! [`crate::PathId`]. The probe carries an
//! epoch-millisecond timestamp so the selector can decide
//! whether the observation is fresh enough to act on (the
//! freshness budget lives on [`crate::SdwanPolicy::probe_max_age_ms`]).
//!
//! The probe **source** is intentionally pluggable —
//! production deploys feed BFD / iperf-style data into a
//! provider that pushes into the runtime. Tests construct
//! a [`StaticProbeProvider`] keyed by `PathId`.
//!
//! ## Invariants
//!
//! 1. **Bounded values.** Loss is a percentage in
//!    `[0.0, 100.0]`; latency and jitter are
//!    milliseconds in `[0.0, ∞)`. The
//!    [`PathProbe::new_checked`] constructor enforces
//!    finiteness + range; the orchestrator additionally
//!    treats `NaN` on any metric as "treat as worst
//!    possible" via [`crate::score::score_path`].
//! 2. **Wall-clock timestamps.** The `observed_at_ms` is
//!    a Unix-epoch millisecond timestamp — the same
//!    clock the request carries
//!    (`SteeringRequest::now_ms`). The selector compares
//!    these directly, so they MUST come from the same
//!    monotonic-but-wall-clocked source.

use crate::path::PathId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Most-recent liveness observation for one underlay path.
///
/// Cheap to clone, cheap to compare, cheap to hash —
/// the orchestrator may hold many of these on the hot
/// path. The fields are public for ergonomic
/// construction in tests / adapters; range-checked
/// construction goes through
/// [`PathProbe::new_checked`].
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathProbe {
    /// Latency in milliseconds. RTT or one-way depending
    /// on the producer; the score function is monotonic
    /// in this value so either is correct, the operator
    /// just needs to stay consistent across paths.
    pub latency_ms: f32,
    /// Packet loss as a percentage, in `[0.0, 100.0]`.
    pub loss_pct: f32,
    /// Inter-packet delay variation in milliseconds, in
    /// `[0.0, ∞)`.
    pub jitter_ms: f32,
    /// Unix epoch milliseconds when this observation was
    /// taken. The selector compares against
    /// [`crate::SteeringRequest::now_ms`] to decide
    /// freshness against the policy's
    /// [`crate::SdwanPolicy::probe_max_age_ms`].
    pub observed_at_ms: u64,
}

impl PathProbe {
    /// Construct without validation. Reserved for adapters
    /// that have already validated their input (e.g. the
    /// BFD ingestor's wire schema enforces ranges) and
    /// for unit tests building intentionally-degenerate
    /// fixtures.
    #[must_use]
    pub const fn new(latency_ms: f32, loss_pct: f32, jitter_ms: f32, observed_at_ms: u64) -> Self {
        Self {
            latency_ms,
            loss_pct,
            jitter_ms,
            observed_at_ms,
        }
    }

    /// Construct with range checks. Returns the descriptive
    /// error string on the first violation so adapters can
    /// surface it on
    /// [`crate::SdwanError::ProviderFailure`].
    ///
    /// # Errors
    ///
    /// - `"latency must be finite and >= 0"` when
    ///   `latency_ms` is `NaN` / negative.
    /// - `"loss must be finite and in [0, 100]"` when
    ///   `loss_pct` is `NaN` / outside the range.
    /// - `"jitter must be finite and >= 0"` when
    ///   `jitter_ms` is `NaN` / negative.
    pub fn new_checked(
        latency_ms: f32,
        loss_pct: f32,
        jitter_ms: f32,
        observed_at_ms: u64,
    ) -> Result<Self, &'static str> {
        if !latency_ms.is_finite() || latency_ms < 0.0 {
            return Err("latency must be finite and >= 0");
        }
        if !loss_pct.is_finite() || !(0.0..=100.0).contains(&loss_pct) {
            return Err("loss must be finite and in [0, 100]");
        }
        if !jitter_ms.is_finite() || jitter_ms < 0.0 {
            return Err("jitter must be finite and >= 0");
        }
        Ok(Self::new(latency_ms, loss_pct, jitter_ms, observed_at_ms))
    }

    /// True iff this probe was observed within
    /// `max_age_ms` of `now_ms`.
    ///
    /// Implementation note: uses [`u64::saturating_sub`]
    /// so a probe with a timestamp slightly *ahead* of
    /// `now_ms` (clock skew between probe collector and
    /// orchestrator) is treated as fresh (age = 0)
    /// rather than wrapping around to ~`u64::MAX`. The
    /// alternative — rejecting future timestamps as
    /// stale — would tip the selector into an
    /// `AllProbesStale` deny on every clock-skew event.
    #[must_use]
    pub fn is_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        let age = now_ms.saturating_sub(self.observed_at_ms);
        age <= max_age_ms
    }
}

/// Read-only source of [`PathProbe`]s keyed by
/// [`PathId`]. Implementations stay cheap on the hot
/// path — the orchestrator calls `get` once per
/// candidate path per request.
pub trait ProbeProvider: Send + Sync + std::fmt::Debug {
    /// Most-recent probe for `path_id`, or `None` if no
    /// probe has been recorded yet. The orchestrator
    /// treats `None` the same as "stale" — the path
    /// never wins selection.
    fn get(&self, path_id: &PathId) -> Option<PathProbe>;
}

/// Trivial in-memory probe table. Production deploys
/// replace this with an `ArcSwap<HashMap<...>>`-backed
/// provider that the BFD ingestor pushes into; tests
/// construct one of these directly.
#[derive(Debug, Default)]
pub struct StaticProbeProvider {
    by_id: HashMap<PathId, PathProbe>,
}

impl StaticProbeProvider {
    /// Construct from an iterator of `(path_id, probe)`.
    /// Duplicate ids are not allowed — the last one
    /// wins.
    pub fn from_probes<I>(probes: I) -> Self
    where
        I: IntoIterator<Item = (PathId, PathProbe)>,
    {
        let mut by_id = HashMap::new();
        for (id, probe) in probes {
            by_id.insert(id, probe);
        }
        Self { by_id }
    }

    /// Empty table. Useful for unit tests that exercise
    /// the "no probes for any candidate" path.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of probes in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True iff there are no probes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl ProbeProvider for StaticProbeProvider {
    fn get(&self, path_id: &PathId) -> Option<PathProbe> {
        self.by_id.get(path_id).copied()
    }
}

/// Reference-counted reference to a probe provider. The
/// orchestrator owns one of these and clones it
/// internally if it ever needs to share with a worker
/// task.
pub type SharedProbeProvider = Arc<dyn ProbeProvider>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn new_checked_rejects_nan_latency() {
        assert!(PathProbe::new_checked(f32::NAN, 1.0, 0.5, 1_000).is_err());
    }

    #[test]
    fn new_checked_rejects_negative_latency() {
        assert!(PathProbe::new_checked(-1.0, 1.0, 0.5, 1_000).is_err());
    }

    #[test]
    fn new_checked_rejects_loss_above_100() {
        // Loss is a percentage — a value above 100 is a
        // wire-schema bug somewhere upstream and must
        // surface as a ProviderFailure, not be silently
        // clamped.
        assert!(PathProbe::new_checked(5.0, 100.1, 0.5, 1_000).is_err());
    }

    #[test]
    fn new_checked_rejects_negative_loss() {
        assert!(PathProbe::new_checked(5.0, -0.5, 0.5, 1_000).is_err());
    }

    #[test]
    fn new_checked_rejects_inf_jitter() {
        assert!(PathProbe::new_checked(5.0, 1.0, f32::INFINITY, 1_000).is_err());
    }

    #[test]
    fn new_checked_accepts_zero_metrics() {
        // A perfectly-clean path is a valid observation.
        let p = PathProbe::new_checked(0.0, 0.0, 0.0, 1_000).unwrap();
        assert_eq!(p.latency_ms, 0.0);
        assert_eq!(p.loss_pct, 0.0);
        assert_eq!(p.jitter_ms, 0.0);
    }

    #[test]
    fn is_fresh_returns_true_within_budget() {
        let p = PathProbe::new(5.0, 0.0, 0.0, 1_000);
        assert!(p.is_fresh(1_500, 1_000));
    }

    #[test]
    fn is_fresh_returns_false_outside_budget() {
        let p = PathProbe::new(5.0, 0.0, 0.0, 1_000);
        assert!(!p.is_fresh(3_001, 2_000));
    }

    #[test]
    fn is_fresh_treats_clock_skew_as_fresh() {
        // Probe timestamp slightly ahead of now_ms (BFD
        // collector and orchestrator on different
        // clocks). saturating_sub keeps age at 0 — the
        // alternative (wrap to u64::MAX) would tip every
        // skewed deploy into AllProbesStale.
        let p = PathProbe::new(5.0, 0.0, 0.0, 2_000);
        assert!(p.is_fresh(1_900, 1_000));
    }

    #[test]
    fn static_provider_returns_none_for_unknown_id() {
        let provider = StaticProbeProvider::empty();
        assert!(provider.get(&PathId::new("mpls")).is_none());
    }

    #[test]
    fn static_provider_returns_stored_probe() {
        let probe = PathProbe::new(5.0, 0.1, 0.5, 1_000);
        let provider = StaticProbeProvider::from_probes([(PathId::new("mpls"), probe)]);
        let got = provider.get(&PathId::new("mpls")).unwrap();
        assert_eq!(got, probe);
    }
}
