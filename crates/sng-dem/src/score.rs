//! Optional network-quality sub-signal reusing the SD-WAN scorer.
//!
//! DEM's authoritative experience score (0–100, higher is better) is
//! computed control-plane side over a rolling window. This module
//! provides a *local* per-probe network-quality breakdown by reusing
//! [`sng_sdwan`]'s public [`score_path`] cost model (lower is
//! better), demonstrating the path-selection brain's scorer on a
//! single probe without duplicating its weighting logic. The edge can
//! attach this as a diagnostic hint; it is not the experience score.

use sng_sdwan::{PathProbe, ScoreBreakdown, ScoreWeights, score_path};

use crate::result::ProbeResult;

/// Compute the SD-WAN cost-model breakdown for a single probe.
///
/// Maps the probe onto a [`PathProbe`]: latency is the best available
/// timing (total → TTFB → TCP → DNS), loss is `0` on success and
/// `100` on failure (a failed probe is treated as fully lossy), and
/// jitter is unknown (`0`) for a single sample. Returns `None` when
/// the probe carries no timing at all (e.g. a config failure before
/// any phase ran).
///
/// Latency is narrowed from `f64` ms to the SD-WAN scorer's `f32`;
/// the truncation is immaterial at millisecond resolution over the
/// scorer's range.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn network_score(result: &ProbeResult, weights: &ScoreWeights) -> Option<ScoreBreakdown> {
    let latency_ms = result
        .total_ms
        .or(result.ttfb_ms)
        .or(result.tcp_ms)
        .or(result.dns_ms)?;
    let loss_pct = if result.success { 0.0 } else { 100.0 };
    let probe = PathProbe::new(latency_ms as f32, loss_pct, 0.0, result.observed_at_ms);
    Some(score_path(&probe, weights, 0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::ProbeKind;

    fn result_with_latency(total_ms: Option<f64>, success: bool) -> ProbeResult {
        ProbeResult {
            target_key: "m365".into(),
            target_name: "Microsoft 365".into(),
            probe_kind: ProbeKind::Https,
            success,
            dns_ms: Some(2.0),
            tcp_ms: Some(10.0),
            tls_ms: None,
            ttfb_ms: Some(40.0),
            total_ms,
            http_status: Some(200),
            error_kind: None,
            error_detail: None,
            observed_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn healthy_probe_scores_better_than_failed() {
        let weights = ScoreWeights::default();
        let healthy = network_score(&result_with_latency(Some(50.0), true), &weights).unwrap();
        let failed = network_score(&result_with_latency(Some(50.0), false), &weights).unwrap();
        // Lower cost is better; the lossy (failed) probe must cost more.
        assert!(failed.total > healthy.total);
    }

    #[test]
    fn falls_back_through_timing_chain() {
        let weights = ScoreWeights::default();
        // No total/ttfb/tcp — only DNS timing present.
        let mut r = result_with_latency(None, true);
        r.ttfb_ms = None;
        r.tcp_ms = None;
        assert!(network_score(&r, &weights).is_some());
    }

    #[test]
    fn no_timing_yields_none() {
        let weights = ScoreWeights::default();
        let mut r = result_with_latency(None, false);
        r.dns_ms = None;
        r.tcp_ms = None;
        r.ttfb_ms = None;
        assert!(network_score(&r, &weights).is_none());
    }
}
