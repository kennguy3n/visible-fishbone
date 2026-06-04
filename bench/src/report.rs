//! Benchmark report model: the JSON artifact persisted to
//! `bench/results/`, the human-readable markdown summary, and the
//! run-over-run regression detector the weekly workflow alerts on.
//!
//! Everything here is a pure transform over plain data so the report
//! shape and the regression maths are unit-tested without touching a
//! socket or `/proc`.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors raised while (de)serializing a report.
#[derive(Debug, Error)]
pub enum ReportError {
    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Which benchmark mode produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchMode {
    /// Maximum sustained throughput (pps / Gbps).
    Throughput,
    /// Per-packet latency distribution.
    Latency,
    /// Maximum concurrent active flows before degradation.
    ConcurrentFlows,
}

impl BenchMode {
    /// Stable lowercase label used in filenames and markdown headings.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            BenchMode::Throughput => "throughput",
            BenchMode::Latency => "latency",
            BenchMode::ConcurrentFlows => "concurrent-flows",
        }
    }
}

/// The dimensions a single run was parameterized over — recorded so a
/// report is self-describing and comparisons only ever pit like against
/// like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDimensions {
    /// Wire packet size in bytes (64, 512, 1500, 9000, ...).
    pub packet_size: u32,
    /// Number of policy rules loaded on the edge under test.
    pub policy_rules: u32,
    /// Inspection depth label (`no-inspect`, `url-cat`, `full-tls`).
    pub inspection: String,
}

/// Throughput results for one run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputResult {
    /// Peak packets-per-second observed in any 1s window.
    pub max_pps: f64,
    /// Peak gigabits-per-second observed in any 1s window.
    pub max_gbps: f64,
    /// Mean Gbps across all measurement windows.
    pub mean_gbps: f64,
}

/// Latency percentiles for one run, in nanoseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyResult {
    /// 50th percentile per-packet latency (ns).
    pub p50_ns: u64,
    /// 95th percentile per-packet latency (ns).
    pub p95_ns: u64,
    /// 99th percentile per-packet latency (ns).
    pub p99_ns: u64,
    /// Maximum observed per-packet latency (ns).
    pub max_ns: u64,
    /// Number of samples that exceeded the trackable ceiling.
    pub clamped: u64,
}

/// Concurrent-flow results for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcurrentFlowsResult {
    /// Maximum simultaneously active flows sustained before the
    /// configured degradation threshold (loss / latency) tripped.
    pub max_active_flows: u64,
}

/// Resource utilisation captured at the measured peak.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceResult {
    /// Mean busy-CPU% across sampling windows during the run.
    pub mean_cpu_busy_pct: f64,
    /// Peak resident set size of the harness, in bytes.
    pub peak_rss_bytes: u64,
}

/// A full benchmark report for one `(profile, mode, dimensions)` run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Report schema version; bumped if the shape changes so a stale
    /// `results/` file is never silently compared against a new one.
    pub schema_version: u32,
    /// Profile name (`branch-small`, `branch-medium`, `branch-large`).
    pub profile: String,
    /// Mode that produced this report.
    pub mode: BenchMode,
    /// Run timestamp, Unix epoch seconds.
    pub unix_time_secs: u64,
    /// Optional git commit the run was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// The parameter point this run measured.
    pub dimensions: RunDimensions,
    /// Throughput results (present for throughput mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput: Option<ThroughputResult>,
    /// Latency results (present for latency mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyResult>,
    /// Concurrent-flow results (present for concurrent-flows mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent_flows: Option<ConcurrentFlowsResult>,
    /// Host resource utilisation during the run.
    pub resources: ResourceResult,
    /// Target throughput in Gbps declared by the profile (for context in
    /// the markdown summary; not used by regression detection).
    pub target_gbps: f64,
}

/// Current report schema version.
pub const SCHEMA_VERSION: u32 = 1;

impl BenchmarkReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on serialization failure.
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON (e.g. a previous run pulled from
    /// `bench/results/`).
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on parse failure.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Render a human-readable markdown summary.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = writeln!(
            out,
            "## SNG edge benchmark — {profile} / {mode}",
            profile = self.profile,
            mode = self.mode.label()
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "- packet size: **{}B** · policy rules: **{}** · inspection: **{}**",
            self.dimensions.packet_size, self.dimensions.policy_rules, self.dimensions.inspection
        );
        let _ = writeln!(out, "- run (unix): `{}`", self.unix_time_secs);
        if let Some(sha) = &self.git_sha {
            let _ = writeln!(out, "- commit: `{sha}`");
        }
        let _ = writeln!(out);

        if let Some(t) = &self.throughput {
            let _ = writeln!(out, "### Throughput");
            let _ = writeln!(out, "| metric | value | target |");
            let _ = writeln!(out, "| --- | ---: | ---: |");
            let pass = if t.max_gbps >= self.target_gbps {
                "PASS"
            } else {
                "MISS"
            };
            let _ = writeln!(
                out,
                "| max throughput | {:.3} Gbps | {:.3} Gbps ({pass}) |",
                t.max_gbps, self.target_gbps
            );
            let _ = writeln!(out, "| max pps | {:.0} | |", t.max_pps);
            let _ = writeln!(out, "| mean throughput | {:.3} Gbps | |", t.mean_gbps);
            let _ = writeln!(out);
        }

        if let Some(l) = &self.latency {
            let _ = writeln!(out, "### Latency (per-packet)");
            let _ = writeln!(out, "| percentile | latency |");
            let _ = writeln!(out, "| --- | ---: |");
            let _ = writeln!(out, "| p50 | {} |", fmt_ns(l.p50_ns));
            let _ = writeln!(out, "| p95 | {} |", fmt_ns(l.p95_ns));
            let _ = writeln!(out, "| p99 | {} |", fmt_ns(l.p99_ns));
            let _ = writeln!(out, "| max | {} |", fmt_ns(l.max_ns));
            if l.clamped > 0 {
                let _ = writeln!(
                    out,
                    "\n> {} sample(s) exceeded the trackable ceiling.",
                    l.clamped
                );
            }
            let _ = writeln!(out);
        }

        if let Some(c) = &self.concurrent_flows {
            let _ = writeln!(out, "### Concurrent flows");
            let _ = writeln!(out, "- max active flows: **{}**", c.max_active_flows);
            let _ = writeln!(out);
        }

        let _ = writeln!(out, "### Resources at peak");
        let _ = writeln!(
            out,
            "- mean CPU: **{:.1}%** · peak RSS: **{:.1} MiB**",
            self.resources.mean_cpu_busy_pct,
            self.resources.peak_rss_bytes as f64 / (1024.0 * 1024.0)
        );
        out
    }
}

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.3} µs", ns as f64 / 1_000.0)
    } else {
        format!("{ns} ns")
    }
}

/// Thresholds (as fractions, e.g. `0.10` for 10%) beyond which a
/// metric change is flagged as a regression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegressionThresholds {
    /// Fractional throughput *drop* that counts as a regression.
    pub throughput_drop: f64,
    /// Fractional latency-p99 *increase* that counts as a regression.
    pub latency_increase: f64,
    /// Fractional concurrent-flows *drop* that counts as a regression.
    /// Kept separate from `throughput_drop` so flow-count and bandwidth
    /// sensitivities can be tuned independently.
    pub concurrent_flows_drop: f64,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        // The spec's alert bar: >10% movement in the wrong direction.
        Self {
            throughput_drop: 0.10,
            latency_increase: 0.10,
            concurrent_flows_drop: 0.10,
        }
    }
}

/// A single flagged metric movement.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Regression {
    /// Which metric regressed (`max_gbps`, `p99_ns`, ...).
    pub metric: String,
    /// Value in the previous (baseline) run.
    pub previous: f64,
    /// Value in the current run.
    pub current: f64,
    /// Signed fractional change `(current - previous) / previous`.
    pub change_fraction: f64,
}

/// Result of comparing a current report against a baseline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegressionReport {
    /// Flagged movements; empty means the run is within thresholds.
    pub regressions: Vec<Regression>,
}

impl RegressionReport {
    /// Whether any metric regressed beyond its threshold.
    #[must_use]
    pub fn has_regression(&self) -> bool {
        !self.regressions.is_empty()
    }
}

/// Compare `current` against `baseline` and flag metric movements that
/// exceed `thresholds`.
///
/// Comparison is only meaningful between runs of the same profile, mode,
/// and dimensions; a mismatch returns `Err` so a caller never compares
/// a 64B run against a 9000B run and "discovers" a regression.
///
/// # Errors
/// Returns an error string when the two reports describe different
/// `(profile, mode, dimensions)` points or different schema versions.
pub fn detect_regression(
    baseline: &BenchmarkReport,
    current: &BenchmarkReport,
    thresholds: RegressionThresholds,
) -> Result<RegressionReport, String> {
    if baseline.schema_version != current.schema_version {
        return Err(format!(
            "schema version mismatch: baseline {} vs current {}",
            baseline.schema_version, current.schema_version
        ));
    }
    if baseline.profile != current.profile
        || baseline.mode != current.mode
        || baseline.dimensions != current.dimensions
    {
        return Err("cannot compare runs with different profile/mode/dimensions".to_string());
    }

    let mut regressions = Vec::new();

    if let (Some(base), Some(cur)) = (&baseline.throughput, &current.throughput) {
        // A drop in throughput is bad. change = (cur - base)/base; a
        // change <= -threshold is a regression.
        if let Some(change) = fractional_change(base.max_gbps, cur.max_gbps) {
            if change <= -thresholds.throughput_drop {
                regressions.push(Regression {
                    metric: "max_gbps".to_string(),
                    previous: base.max_gbps,
                    current: cur.max_gbps,
                    change_fraction: change,
                });
            }
        }
    }

    if let (Some(base), Some(cur)) = (&baseline.latency, &current.latency) {
        // An increase in p99 latency is bad.
        if let Some(change) = fractional_change(base.p99_ns as f64, cur.p99_ns as f64) {
            if change >= thresholds.latency_increase {
                regressions.push(Regression {
                    metric: "p99_ns".to_string(),
                    previous: base.p99_ns as f64,
                    current: cur.p99_ns as f64,
                    change_fraction: change,
                });
            }
        }
    }

    if let (Some(base), Some(cur)) = (&baseline.concurrent_flows, &current.concurrent_flows) {
        // A drop in sustainable concurrent flows is bad.
        if let Some(change) =
            fractional_change(base.max_active_flows as f64, cur.max_active_flows as f64)
        {
            if change <= -thresholds.concurrent_flows_drop {
                regressions.push(Regression {
                    metric: "max_active_flows".to_string(),
                    previous: base.max_active_flows as f64,
                    current: cur.max_active_flows as f64,
                    change_fraction: change,
                });
            }
        }
    }

    Ok(RegressionReport { regressions })
}

/// `(current - previous) / previous`, or `None` when `previous` is zero
/// (no defined baseline to compare against).
fn fractional_change(previous: f64, current: f64) -> Option<f64> {
    if previous == 0.0 {
        return None;
    }
    Some((current - previous) / previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(mode: BenchMode) -> BenchmarkReport {
        BenchmarkReport {
            schema_version: SCHEMA_VERSION,
            profile: "branch-medium".to_string(),
            mode,
            unix_time_secs: 1_700_000_000,
            git_sha: Some("abc123".to_string()),
            dimensions: RunDimensions {
                packet_size: 1500,
                policy_rules: 100,
                inspection: "url-cat".to_string(),
            },
            throughput: Some(ThroughputResult {
                max_pps: 800_000.0,
                max_gbps: 5.0,
                mean_gbps: 4.8,
            }),
            latency: Some(LatencyResult {
                p50_ns: 20_000,
                p95_ns: 45_000,
                p99_ns: 80_000,
                max_ns: 250_000,
                clamped: 0,
            }),
            concurrent_flows: Some(ConcurrentFlowsResult {
                max_active_flows: 1_000_000,
            }),
            resources: ResourceResult {
                mean_cpu_busy_pct: 62.5,
                peak_rss_bytes: 256 * 1024 * 1024,
            },
            target_gbps: 5.0,
        }
    }

    #[test]
    fn report_json_round_trips() {
        let r = sample_report(BenchMode::Throughput);
        let json = r.to_json().unwrap();
        let back = BenchmarkReport::from_json(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn markdown_contains_headline_numbers() {
        let md = sample_report(BenchMode::Throughput).to_markdown();
        assert!(md.contains("branch-medium"));
        assert!(md.contains("5.000 Gbps"));
        assert!(md.contains("PASS"));
    }

    #[test]
    fn markdown_marks_throughput_miss_below_target() {
        let mut r = sample_report(BenchMode::Throughput);
        r.throughput.as_mut().unwrap().max_gbps = 3.0;
        let md = r.to_markdown();
        assert!(md.contains("MISS"));
    }

    #[test]
    fn no_regression_when_metrics_hold() {
        let base = sample_report(BenchMode::Throughput);
        let cur = sample_report(BenchMode::Throughput);
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(!rr.has_regression());
    }

    #[test]
    fn throughput_drop_beyond_threshold_is_flagged() {
        let base = sample_report(BenchMode::Throughput);
        let mut cur = sample_report(BenchMode::Throughput);
        // 5.0 -> 4.0 Gbps = 20% drop, beyond the 10% bar.
        cur.throughput.as_mut().unwrap().max_gbps = 4.0;
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(rr.has_regression());
        assert_eq!(rr.regressions[0].metric, "max_gbps");
        assert!((rr.regressions[0].change_fraction + 0.20).abs() < 1e-9);
    }

    #[test]
    fn small_throughput_drop_within_threshold_is_ignored() {
        let base = sample_report(BenchMode::Throughput);
        let mut cur = sample_report(BenchMode::Throughput);
        // 5.0 -> 4.75 = 5% drop, within the 10% bar.
        cur.throughput.as_mut().unwrap().max_gbps = 4.75;
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(!rr.has_regression());
    }

    #[test]
    fn throughput_improvement_is_never_a_regression() {
        let base = sample_report(BenchMode::Throughput);
        let mut cur = sample_report(BenchMode::Throughput);
        cur.throughput.as_mut().unwrap().max_gbps = 6.0;
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(!rr.has_regression());
    }

    #[test]
    fn latency_increase_beyond_threshold_is_flagged() {
        let base = sample_report(BenchMode::Latency);
        let mut cur = sample_report(BenchMode::Latency);
        // p99 80us -> 100us = 25% increase.
        cur.latency.as_mut().unwrap().p99_ns = 100_000;
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(rr.has_regression());
        assert_eq!(rr.regressions[0].metric, "p99_ns");
    }

    #[test]
    fn concurrent_flow_collapse_is_flagged() {
        let base = sample_report(BenchMode::ConcurrentFlows);
        let mut cur = sample_report(BenchMode::ConcurrentFlows);
        cur.concurrent_flows.as_mut().unwrap().max_active_flows = 500_000;
        let rr = detect_regression(&base, &cur, RegressionThresholds::default()).unwrap();
        assert!(rr.has_regression());
        assert_eq!(rr.regressions[0].metric, "max_active_flows");
    }

    #[test]
    fn concurrent_flows_threshold_is_independent_of_throughput() {
        let base = sample_report(BenchMode::ConcurrentFlows);
        let mut cur = sample_report(BenchMode::ConcurrentFlows);
        let base_flows = base.concurrent_flows.as_ref().unwrap().max_active_flows;
        // A 5% flow-count drop: ignored at the default 10% bar, but flagged
        // once the dedicated concurrent-flows threshold is tightened to 1%,
        // independent of `throughput_drop`.
        cur.concurrent_flows.as_mut().unwrap().max_active_flows = (base_flows as f64 * 0.95) as u64;
        assert!(
            !detect_regression(&base, &cur, RegressionThresholds::default())
                .unwrap()
                .has_regression()
        );
        let tight = RegressionThresholds {
            concurrent_flows_drop: 0.01,
            ..RegressionThresholds::default()
        };
        let rr = detect_regression(&base, &cur, tight).unwrap();
        assert!(rr.has_regression());
        assert_eq!(rr.regressions[0].metric, "max_active_flows");
    }

    #[test]
    fn mismatched_dimensions_refuse_comparison() {
        let base = sample_report(BenchMode::Throughput);
        let mut cur = sample_report(BenchMode::Throughput);
        cur.dimensions.packet_size = 64;
        assert!(detect_regression(&base, &cur, RegressionThresholds::default()).is_err());
    }

    #[test]
    fn mismatched_schema_version_refuses_comparison() {
        let base = sample_report(BenchMode::Throughput);
        let mut cur = sample_report(BenchMode::Throughput);
        cur.schema_version = SCHEMA_VERSION + 1;
        assert!(detect_regression(&base, &cur, RegressionThresholds::default()).is_err());
    }
}
