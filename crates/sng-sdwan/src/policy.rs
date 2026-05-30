//! SD-WAN policy + atomic-swap holder.
//!
//! [`SdwanPolicy`] is the operator-authored, bundle-
//! adapted configuration the SD-WAN brain runs against.
//! It carries:
//!
//! 1. The score weight vector ([`ScoreWeights`]) — how
//!    much one millisecond of latency is worth relative
//!    to one percent of loss / one millisecond of
//!    jitter.
//! 2. The per-metric SLO floor — a path whose probe
//!    exceeds *any* of `max_latency_ms`, `max_loss_pct`,
//!    `max_jitter_ms` is ineligible regardless of score
//!    (so the policy can express "I'd rather deny than
//!    steer voice onto a 20 % loss link"). The floor
//!    fields are optional — a `None` means the metric
//!    isn't gating.
//! 3. The probe freshness budget
//!    ([`SdwanPolicy::probe_max_age_ms`]) — a path
//!    whose most-recent probe is older than this is
//!    treated as stale (and therefore non-winning).
//!
//! ## Reload semantics
//!
//! [`SdwanPolicyHolder`] mirrors `SwgPolicyHolder` /
//! `ZtnaPolicyHolder`: the live policy lives behind an
//! [`arc_swap::ArcSwap`], reads are wait-free, and the
//! bundle adapter calls [`SdwanPolicyHolder::try_replace`]
//! to validate-then-swap. On validation failure the
//! previously-loaded policy stays active — the data path
//! never sees a half-applied policy.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::SdwanError;

/// Score weight vector. Linear cost coefficients applied
/// in [`crate::score::score_path`]. All weights are
/// constrained to `>= 0` and finite by
/// [`SdwanPolicy::validate`].
///
/// The default is a latency-leaning bias appropriate for
/// the median enterprise mix: latency dominates over
/// jitter, loss is heavily penalised (a 1 %
/// loss is roughly equivalent to 10 ms of latency).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScoreWeights {
    /// Weight on `latency_ms`. Default: `1.0`.
    pub latency: f32,
    /// Weight on `loss_pct`. Default: `10.0` — one
    /// percent of loss costs ten units, comparable to 10
    /// ms of latency.
    pub loss: f32,
    /// Weight on `jitter_ms`. Default: `0.5` — jitter
    /// matters but less than steady-state latency.
    pub jitter: f32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            latency: 1.0,
            loss: 10.0,
            jitter: 0.5,
        }
    }
}

impl ScoreWeights {
    /// True iff every weight is finite and non-negative.
    /// The strict-positivity test belongs on
    /// [`SdwanPolicy::validate`] which inspects the
    /// whole policy.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let finite = self.latency.is_finite() && self.loss.is_finite() && self.jitter.is_finite();
        let non_neg = self.latency >= 0.0 && self.loss >= 0.0 && self.jitter >= 0.0;
        finite && non_neg
    }

    /// Sum of all weights. A policy with sum == 0 is
    /// rejected at validate time — a constant-zero score
    /// would tie every path on every observation.
    #[must_use]
    pub fn sum(&self) -> f32 {
        self.latency + self.loss + self.jitter
    }
}

/// SD-WAN policy snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SdwanPolicy {
    /// Linear score coefficients.
    #[serde(default)]
    pub weights: ScoreWeights,
    /// Maximum latency a path may have and still be
    /// considered. `None` means latency isn't a gating
    /// floor (it still feeds the score).
    #[serde(default)]
    pub max_latency_ms: Option<f32>,
    /// Maximum loss percent a path may have and still be
    /// considered.
    #[serde(default)]
    pub max_loss_pct: Option<f32>,
    /// Maximum jitter a path may have and still be
    /// considered.
    #[serde(default)]
    pub max_jitter_ms: Option<f32>,
    /// Probe freshness budget — a probe older than this
    /// is treated as stale.
    #[serde(default = "default_probe_max_age_ms")]
    pub probe_max_age_ms: u64,
    /// Sticky-flow grace window. The orchestrator records
    /// the last-selected path id keyed by
    /// [`crate::SteeringRequest::flow_key`]; within this
    /// window the brain prefers the previously-selected
    /// path if it is still eligible and fresh, even if a
    /// new candidate now scores marginally better. This
    /// dampens flapping under noisy probe data — the data
    /// path does not have to re-pin TCP sessions onto a
    /// new underlay every probe cycle.
    #[serde(default = "default_sticky_window_ms")]
    pub sticky_window_ms: u64,
}

const fn default_probe_max_age_ms() -> u64 {
    5_000
}
const fn default_sticky_window_ms() -> u64 {
    30_000
}

impl Default for SdwanPolicy {
    fn default() -> Self {
        Self {
            weights: ScoreWeights::default(),
            max_latency_ms: None,
            max_loss_pct: None,
            max_jitter_ms: None,
            probe_max_age_ms: default_probe_max_age_ms(),
            sticky_window_ms: default_sticky_window_ms(),
        }
    }
}

impl SdwanPolicy {
    /// Validate the value domain.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when:
    ///
    /// - Any score weight is `NaN`, infinite, or
    ///   negative.
    /// - The score weights sum to exactly zero (a
    ///   constant-zero score would tie every path on
    ///   every observation, which collapses the
    ///   selector).
    /// - Any of the optional gating floors is `NaN`,
    ///   infinite, or negative.
    /// - `max_loss_pct` is set to a value outside
    ///   `[0.0, 100.0]`.
    /// - `probe_max_age_ms` is zero (every probe would
    ///   be stale; the brain would deny every request).
    pub fn validate(&self) -> Result<(), SdwanError> {
        if !self.weights.is_well_formed() {
            return Err(SdwanError::InvalidPolicy(
                "score weights must be finite and non-negative".into(),
            ));
        }
        if self.weights.sum() == 0.0 {
            return Err(SdwanError::InvalidPolicy(
                "score weights must not sum to zero — every path would tie".into(),
            ));
        }
        if let Some(v) = self.max_latency_ms {
            if !v.is_finite() || v < 0.0 {
                return Err(SdwanError::InvalidPolicy(
                    "max_latency_ms must be finite and >= 0".into(),
                ));
            }
        }
        if let Some(v) = self.max_loss_pct {
            if !v.is_finite() || !(0.0..=100.0).contains(&v) {
                return Err(SdwanError::InvalidPolicy(
                    "max_loss_pct must be finite and in [0, 100]".into(),
                ));
            }
        }
        if let Some(v) = self.max_jitter_ms {
            if !v.is_finite() || v < 0.0 {
                return Err(SdwanError::InvalidPolicy(
                    "max_jitter_ms must be finite and >= 0".into(),
                ));
            }
        }
        if self.probe_max_age_ms == 0 {
            return Err(SdwanError::InvalidPolicy(
                "probe_max_age_ms must be > 0 — every probe would be stale".into(),
            ));
        }
        Ok(())
    }

    /// True iff `latency_ms` is at or below the policy's
    /// latency floor.
    ///
    /// Fail-closed on `NaN`: a NaN metric is always
    /// classified as out-of-floor, regardless of whether
    /// the floor is configured. This matches the broader
    /// brain's contract that NaN-metric paths cannot win
    /// (see also [`crate::score::score_path`] which
    /// collapses to `ScoreBreakdown::worst()` on NaN).
    /// `None` floor with a finite metric → always true.
    #[must_use]
    pub fn within_latency_floor(&self, latency_ms: f32) -> bool {
        if latency_ms.is_nan() {
            return false;
        }
        self.max_latency_ms.is_none_or(|cap| latency_ms <= cap)
    }

    /// True iff `loss_pct` is at or below the policy's
    /// loss floor. Fail-closed on `NaN` — see
    /// [`Self::within_latency_floor`].
    #[must_use]
    pub fn within_loss_floor(&self, loss_pct: f32) -> bool {
        if loss_pct.is_nan() {
            return false;
        }
        self.max_loss_pct.is_none_or(|cap| loss_pct <= cap)
    }

    /// True iff `jitter_ms` is at or below the policy's
    /// jitter floor. Fail-closed on `NaN` — see
    /// [`Self::within_latency_floor`].
    #[must_use]
    pub fn within_jitter_floor(&self, jitter_ms: f32) -> bool {
        if jitter_ms.is_nan() {
            return false;
        }
        self.max_jitter_ms.is_none_or(|cap| jitter_ms <= cap)
    }
}

/// Atomic-swap container for the active
/// [`SdwanPolicy`].
///
/// The active policy lives behind
/// [`arc_swap::ArcSwap`] so the data path reads with one
/// atomic load — no lock, no allocation. The bundle
/// adapter calls [`Self::try_replace`] which validates
/// the candidate and atomically installs it; on
/// validation failure the previously-loaded policy stays
/// active.
#[derive(Debug)]
pub struct SdwanPolicyHolder {
    inner: ArcSwap<SdwanPolicy>,
}

impl SdwanPolicyHolder {
    /// Construct a holder around `policy` *without*
    /// validating it. Reserved for known-good policies —
    /// primarily [`SdwanPolicy::default`] and unit tests.
    /// Bundle adapters should use
    /// [`try_new`](Self::try_new).
    #[must_use]
    pub fn new(policy: SdwanPolicy) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(policy)),
        }
    }

    /// Construct + validate.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when
    /// `policy` fails [`SdwanPolicy::validate`].
    pub fn try_new(policy: SdwanPolicy) -> Result<Self, SdwanError> {
        policy.validate()?;
        Ok(Self::new(policy))
    }

    /// Atomically replace without validation. Reserved
    /// for known-good policies; bundle adapters should
    /// use [`try_replace`](Self::try_replace).
    pub fn replace(&self, policy: SdwanPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Validate and atomically replace.
    ///
    /// On validation failure the previously-loaded
    /// policy is preserved and the data path keeps
    /// running with the last known-good ruleset.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when
    /// `policy` fails [`SdwanPolicy::validate`].
    pub fn try_replace(&self, policy: SdwanPolicy) -> Result<(), SdwanError> {
        policy.validate()?;
        self.replace(policy);
        Ok(())
    }

    /// Cheap clone of the live policy (one `Arc` bump,
    /// no contents clone).
    #[must_use]
    pub fn snapshot(&self) -> Arc<SdwanPolicy> {
        self.inner.load_full()
    }
}

impl Default for SdwanPolicyHolder {
    fn default() -> Self {
        Self::new(SdwanPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_policy_validates() {
        // The default policy must always validate —
        // otherwise the SdwanPolicyHolder::default impl
        // would produce a holder whose contents fail
        // try_replace, which would be surprising for
        // tests / supervisor smoke checks.
        assert!(SdwanPolicy::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_negative_latency_weight() {
        let p = SdwanPolicy {
            weights: ScoreWeights {
                latency: -0.1,
                loss: 10.0,
                jitter: 0.5,
            },
            ..SdwanPolicy::default()
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
    }

    #[test]
    fn validate_rejects_nan_loss_weight() {
        let p = SdwanPolicy {
            weights: ScoreWeights {
                latency: 1.0,
                loss: f32::NAN,
                jitter: 0.5,
            },
            ..SdwanPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_sum_weights() {
        // All weights zero → every path ties; selector
        // becomes useless.
        let p = SdwanPolicy {
            weights: ScoreWeights {
                latency: 0.0,
                loss: 0.0,
                jitter: 0.0,
            },
            ..SdwanPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_probe_age() {
        let p = SdwanPolicy {
            probe_max_age_ms: 0,
            ..SdwanPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_loss_floor_above_100() {
        let p = SdwanPolicy {
            max_loss_pct: Some(150.0),
            ..SdwanPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_negative_latency_floor() {
        let p = SdwanPolicy {
            max_latency_ms: Some(-1.0),
            ..SdwanPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn within_floors_default_accepts_any_finite_value() {
        // No floors set → every (finite) metric is in-budget.
        let p = SdwanPolicy::default();
        assert!(p.within_latency_floor(1_000.0));
        assert!(p.within_loss_floor(95.0));
        assert!(p.within_jitter_floor(500.0));
    }

    #[test]
    fn within_floors_gate_when_set() {
        let p = SdwanPolicy {
            max_latency_ms: Some(50.0),
            max_loss_pct: Some(2.0),
            max_jitter_ms: Some(10.0),
            ..SdwanPolicy::default()
        };
        assert!(p.within_latency_floor(50.0));
        assert!(!p.within_latency_floor(50.1));
        assert!(p.within_loss_floor(2.0));
        assert!(!p.within_loss_floor(2.1));
        assert!(p.within_jitter_floor(10.0));
        assert!(!p.within_jitter_floor(10.1));
    }

    #[test]
    fn within_floors_fail_closed_on_nan_with_or_without_floor() {
        // Defense in depth: a NaN metric value must be
        // classified as out-of-floor *regardless* of
        // whether a floor is configured. Without this,
        // an unconfigured floor would let a NaN-metric
        // path through into the in-budget bucket (the
        // selector then never picks it because score_path
        // collapses to worst(), but the bucket label
        // would be incoherent).
        let no_floors = SdwanPolicy::default();
        assert!(!no_floors.within_latency_floor(f32::NAN));
        assert!(!no_floors.within_loss_floor(f32::NAN));
        assert!(!no_floors.within_jitter_floor(f32::NAN));

        let with_floors = SdwanPolicy {
            max_latency_ms: Some(50.0),
            max_loss_pct: Some(2.0),
            max_jitter_ms: Some(10.0),
            ..SdwanPolicy::default()
        };
        assert!(!with_floors.within_latency_floor(f32::NAN));
        assert!(!with_floors.within_loss_floor(f32::NAN));
        assert!(!with_floors.within_jitter_floor(f32::NAN));
    }

    #[test]
    fn try_replace_rejects_invalid_and_preserves_previous() {
        // The whole point of try_replace: a malformed
        // candidate must NOT clobber the live policy.
        let holder = SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap();
        let before = holder.snapshot();
        let bad = SdwanPolicy {
            probe_max_age_ms: 0,
            ..SdwanPolicy::default()
        };
        assert!(holder.try_replace(bad).is_err());
        let after = holder.snapshot();
        // Same Arc identity → the swap never happened.
        assert!(Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn try_replace_installs_valid_candidate() {
        let holder = SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap();
        let before = holder.snapshot();
        let new = SdwanPolicy {
            probe_max_age_ms: 1_234,
            ..SdwanPolicy::default()
        };
        holder.try_replace(new).unwrap();
        let after = holder.snapshot();
        // Different Arc identity → the swap happened.
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.probe_max_age_ms, 1_234);
    }

    #[test]
    fn snapshot_is_cheap_arc_clone() {
        // Snapshot must not deep-clone the contents.
        // We assert this indirectly by checking that two
        // back-to-back snapshots between which no
        // replace happened share an Arc identity.
        let holder = SdwanPolicyHolder::default();
        let a = holder.snapshot();
        let b = holder.snapshot();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
