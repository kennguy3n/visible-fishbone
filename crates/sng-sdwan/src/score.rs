//! Path scoring — pure, deterministic function from
//! `(probe, weights, bias) → score`.
//!
//! The score is a **cost** — lower is better. The
//! [`crate::service::SdwanService`] picks the path with
//! the lowest [`ScoreBreakdown::total`] among fresh,
//! eligible candidates.
//!
//! ## Cost model
//!
//! ```text
//!   cost(path) =   w_lat * latency_ms
//!                + w_loss * loss_pct
//!                + w_jit  * jitter_ms
//!                + static_bias
//! ```
//!
//! All weights are constrained to be `>= 0` and finite by
//! the policy validator
//! ([`crate::SdwanPolicy::validate`]). The function is
//! linear so the operator can reason about the marginal
//! cost of one millisecond of latency vs. one percent of
//! loss directly.
//!
//! ## NaN handling
//!
//! If a probe metric is `NaN` (a misbehaving collector
//! pushed garbage past the
//! [`crate::probe::PathProbe::new_checked`] gate), the
//! score is defined to be [`f32::INFINITY`]. This makes
//! the path provably non-winning under
//! `partial_cmp(...).unwrap_or(Less)` semantics —
//! identical to "stale probe" behavior, fail-closed.

use crate::policy::ScoreWeights;
use crate::probe::PathProbe;
use serde::{Deserialize, Serialize};

/// Decomposition of one path's cost. Surfaced for
/// dashboards / unit tests so the operator can attribute
/// a selection back to its dominant signal.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// `w_lat * latency_ms`.
    pub latency_component: f32,
    /// `w_loss * loss_pct`.
    pub loss_component: f32,
    /// `w_jit * jitter_ms`.
    pub jitter_component: f32,
    /// Static bias from
    /// [`crate::path::Path::static_bias`].
    pub static_bias: f32,
    /// Sum of the four. This is the value the selector
    /// compares.
    pub total: f32,
}

impl ScoreBreakdown {
    /// Convenience constructor for tests / fixtures.
    /// Production callers go through [`score_path`].
    #[must_use]
    pub const fn new(
        latency_component: f32,
        loss_component: f32,
        jitter_component: f32,
        static_bias: f32,
        total: f32,
    ) -> Self {
        Self {
            latency_component,
            loss_component,
            jitter_component,
            static_bias,
            total,
        }
    }

    /// Provably non-winning score (every metric is
    /// `+inf`). Returned by [`score_path`] when a metric
    /// is `NaN` so the comparison in
    /// [`crate::service::SdwanService::evaluate`] orders
    /// this path after every other finite-scored
    /// candidate.
    #[must_use]
    pub const fn worst() -> Self {
        Self::new(
            f32::INFINITY,
            f32::INFINITY,
            f32::INFINITY,
            f32::INFINITY,
            f32::INFINITY,
        )
    }
}

/// Score one probe under the given weight vector +
/// static bias. Pure, deterministic, allocation-free.
#[must_use]
pub fn score_path(probe: &PathProbe, weights: &ScoreWeights, static_bias: f32) -> ScoreBreakdown {
    // Non-finite on any metric, weight, or bias →
    // fail-closed (worst possible score). The
    // `SdwanPolicy::validate` gate rejects non-finite
    // weights and the probe constructor's `new_checked`
    // rejects NaN metrics, but `score_path` is a free
    // function reachable by any caller — keep the
    // belt-and-braces guard so a misbehaving adapter
    // that bypassed validation cannot mint a NaN total
    // (e.g. `INFINITY * 0.0 = NaN`) and become
    // non-comparable in the selector.
    if !probe.latency_ms.is_finite()
        || !probe.loss_pct.is_finite()
        || !probe.jitter_ms.is_finite()
        || !static_bias.is_finite()
        || !weights.latency.is_finite()
        || !weights.loss.is_finite()
        || !weights.jitter.is_finite()
    {
        return ScoreBreakdown::worst();
    }
    let latency_component = weights.latency * probe.latency_ms;
    let loss_component = weights.loss * probe.loss_pct;
    let jitter_component = weights.jitter * probe.jitter_ms;
    let total = latency_component + loss_component + jitter_component + static_bias;
    // Finite-input overflow guard. The input gate above
    // proves every factor on the right-hand side is
    // finite, but `f * g` where both `f` and `g` are
    // finite can still overflow to ±INFINITY (e.g.
    // `f32::MAX/2 * 3.0`), and `f + g` over an
    // INFINITY component can mint NaN (`INFINITY +
    // -INFINITY`). The selector orders strictly on
    // `total`, so an INFINITY total is functionally
    // never-winning — but it also leaks a non-finite
    // value into the `ScoreBreakdown` that telemetry
    // dashboards consume as a numeric metric. Snap any
    // non-finite total back to `worst()` so the wire
    // shape is strictly `{ all-finite OR all-INFINITY
    // (worst) }` — never a mix. Cheap (`is_finite` is
    // a single bit test) and only fires under
    // misconfigured/adversarial inputs that bypassed
    // `SdwanPolicy::validate`.
    if !total.is_finite()
        || !latency_component.is_finite()
        || !loss_component.is_finite()
        || !jitter_component.is_finite()
    {
        return ScoreBreakdown::worst();
    }
    ScoreBreakdown::new(
        latency_component,
        loss_component,
        jitter_component,
        static_bias,
        total,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn weights(lat: f32, loss: f32, jit: f32) -> ScoreWeights {
        ScoreWeights {
            latency: lat,
            loss,
            jitter: jit,
        }
    }

    #[test]
    fn score_is_weighted_sum_plus_bias() {
        // 1.0 * 10 + 2.0 * 0.5 + 0.5 * 1.0 + (-0.5) = 10 + 1 + 0.5 - 0.5 = 11
        let probe = PathProbe::new(10.0, 0.5, 1.0, 0);
        let w = weights(1.0, 2.0, 0.5);
        let s = score_path(&probe, &w, -0.5);
        assert_eq!(s.latency_component, 10.0);
        assert_eq!(s.loss_component, 1.0);
        assert_eq!(s.jitter_component, 0.5);
        assert_eq!(s.static_bias, -0.5);
        assert_eq!(s.total, 11.0);
    }

    #[test]
    fn zero_weights_collapse_score_to_static_bias() {
        // With zero weights the bias dominates — useful
        // for operators that want to disable the
        // observed-metric channel entirely and steer
        // purely on static preference (e.g. during an
        // emergency pin to MPLS).
        let probe = PathProbe::new(50.0, 5.0, 10.0, 0);
        let w = weights(0.0, 0.0, 0.0);
        let s = score_path(&probe, &w, 1.5);
        assert_eq!(s.total, 1.5);
    }

    #[test]
    fn nan_metric_collapses_to_worst() {
        // Misbehaving adapter pushed NaN past
        // new_checked. The selector must never let this
        // path win — score_path returns `worst()`.
        let probe = PathProbe::new(f32::NAN, 0.0, 0.0, 0);
        let w = weights(1.0, 1.0, 1.0);
        let s = score_path(&probe, &w, 0.0);
        assert!(s.total.is_infinite());
        assert!(s.total > 0.0);
    }

    #[test]
    fn nan_bias_also_collapses_to_worst() {
        // Same fail-closed rule for a NaN static bias.
        let probe = PathProbe::new(5.0, 0.0, 0.0, 0);
        let w = weights(1.0, 1.0, 1.0);
        let s = score_path(&probe, &w, f32::NAN);
        assert!(s.total.is_infinite());
    }

    #[test]
    fn infinite_weight_with_zero_probe_does_not_mint_nan() {
        // Defense-in-depth: `SdwanPolicy::validate()`
        // rejects non-finite weights, but `score_path` is
        // a free function any caller can reach. An
        // INFINITY weight against a 0.0 probe metric
        // mathematically yields NaN (`INFINITY * 0.0`),
        // which would be non-comparable in the selector
        // and could let a garbage path win. The guard
        // must collapse this to `worst()` instead.
        let probe = PathProbe::new(0.0, 0.0, 0.0, 0);
        let w = weights(f32::INFINITY, 1.0, 1.0);
        let s = score_path(&probe, &w, 0.0);
        assert!(
            s.total.is_infinite() && s.total > 0.0,
            "non-finite weight must collapse to worst (+INFINITY), got {}",
            s.total
        );
    }

    #[test]
    fn nan_weight_also_collapses_to_worst() {
        // Same belt-and-braces guard for a NaN weight.
        let probe = PathProbe::new(5.0, 0.5, 1.0, 0);
        let w = weights(f32::NAN, 1.0, 1.0);
        let s = score_path(&probe, &w, 0.0);
        assert!(
            s.total.is_infinite() && s.total > 0.0,
            "NaN weight must collapse to worst, got {}",
            s.total
        );
    }

    /// Adversarial / misconfigured input passes the
    /// finite-input gate but overflows arithmetically to
    /// +INFINITY when multiplied. The post-arithmetic
    /// guard must snap this back to `worst()` so the
    /// `ScoreBreakdown` wire shape is never "some
    /// components finite, total = +INFINITY" (which would
    /// leak into telemetry dashboards as a non-finite
    /// numeric value).
    #[test]
    fn finite_input_overflow_to_infinity_collapses_to_worst() {
        let probe = PathProbe::new(f32::MAX / 2.0, 0.0, 0.0, 0);
        let w = weights(3.0, 1.0, 1.0);
        let s = score_path(&probe, &w, 0.0);
        assert!(
            s.total.is_infinite() && s.total > 0.0,
            "finite-input arithmetic overflow must collapse to worst, got total={}",
            s.total
        );
        // The wire shape is "all components +INFINITY" —
        // never a mix of finite components + infinite total
        // (which would confuse dashboards that bucket on
        // the dominant component).
        assert!(s.latency_component.is_infinite() && s.latency_component > 0.0);
        assert!(s.loss_component.is_infinite() && s.loss_component > 0.0);
        assert!(s.jitter_component.is_infinite() && s.jitter_component > 0.0);
    }

    /// `worst()` already-non-finite paths must still
    /// short-circuit cleanly when summed against a
    /// finite static bias — this is the `INF + finite = INF`
    /// path that the post-arithmetic guard catches as
    /// non-finite total.
    #[test]
    fn overflow_against_negative_bias_does_not_mint_nan() {
        // Without the post-arithmetic guard, an
        // overflowed +INFINITY component + a very
        // negative bias could mathematically produce NaN
        // (`+INFINITY + -INFINITY`). Construct a case
        // where the arithmetic walks that knife-edge and
        // confirm the result still collapses to `worst()`
        // (`+INFINITY`), never NaN.
        let probe = PathProbe::new(f32::MAX, 0.0, 0.0, 0);
        let w = weights(2.0, 1.0, 1.0);
        let s = score_path(&probe, &w, -f32::MAX);
        assert!(s.total.is_infinite() && s.total > 0.0);
        assert!(!s.total.is_nan(), "total must never be NaN");
    }

    #[test]
    fn lower_score_is_better_ordering() {
        // The selector picks the lowest score. Two
        // probes, identical weights, the second one
        // worse on every axis — total must be strictly
        // larger.
        let w = weights(1.0, 2.0, 0.5);
        let s_good = score_path(&PathProbe::new(5.0, 0.1, 0.5, 0), &w, 0.0);
        let s_bad = score_path(&PathProbe::new(50.0, 5.0, 10.0, 0), &w, 0.0);
        assert!(s_good.total < s_bad.total);
    }

    #[test]
    fn breakdown_attributes_dominant_signal() {
        // The dashboards bucket a selection by its
        // dominant cost component. A high-latency path
        // should attribute the total to `latency_component`.
        let probe = PathProbe::new(100.0, 0.1, 1.0, 0);
        let w = weights(1.0, 1.0, 1.0);
        let s = score_path(&probe, &w, 0.0);
        assert!(s.latency_component > s.loss_component);
        assert!(s.latency_component > s.jitter_component);
    }
}
