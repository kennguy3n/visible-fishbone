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
    /// Optional same-class competitor comparison (throughput runs only).
    ///
    /// Additive and optional: older `results/` files predating this field
    /// deserialize with `None`, and a report without a comparison
    /// serializes identically to before — so [`SCHEMA_VERSION`] does not
    /// move and committed baselines still compare cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub competitor_comparison: Option<CompetitorComparison>,
}

/// Current report schema version.
///
/// Deliberately *not* bumped for `competitor_comparison`: that field is a
/// purely additive `Option` that round-trips against pre-existing JSON, so
/// bumping would only break [`detect_regression`] against committed
/// `baseline-*.json` files (which carry the old version) for no benefit.
pub const SCHEMA_VERSION: u32 = 1;

/// SNG's measured throughput at one operating point, set against the
/// published figures of same-class competitor appliances.
///
/// Attached to a throughput [`BenchmarkReport`] so a single report is
/// self-describing for an RFP datasheet. Every [`CompetitorRow`] carries
/// its own caveat because the comparison is hardware/ASIC-vs-software and
/// never apples-to-apples (see [`crate::competitor`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompetitorComparison {
    /// SNG measured throughput (Gbps) at this operating point.
    pub sng_measured_gbps: f64,
    /// Competitor feature category compared against (e.g. `"firewall
    /// throughput"`).
    pub feature: String,
    /// One row per same-class competitor appliance.
    pub rows: Vec<CompetitorRow>,
}

/// A single competitor's published number set against SNG's measured one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompetitorRow {
    /// Competitor display name, e.g. `"Fortinet FortiGate 60F"`.
    pub competitor: String,
    /// Competitor's published throughput (Gbps).
    pub published_gbps: f64,
    /// SNG-vs-competitor delta as a percentage:
    /// `(sng - published) / published * 100`.
    pub delta_pct: f64,
    /// One-line verdict, including the apples-to-apples caveat.
    pub verdict: String,
}

impl CompetitorRow {
    /// Build a row, computing the delta and a caveated verdict from the
    /// SNG measured number, the competitor's published number, and the
    /// competitor's own apples-to-apples caveat.
    #[must_use]
    pub fn new(
        competitor: impl Into<String>,
        published_gbps: f64,
        sng_measured_gbps: f64,
        caveat: &str,
    ) -> Self {
        let competitor = competitor.into();
        // published numbers are always > 0 in the catalog; guard anyway so
        // a future zero never produces a NaN/inf delta.
        let delta_pct = if published_gbps > 0.0 {
            (sng_measured_gbps - published_gbps) / published_gbps * 100.0
        } else {
            0.0
        };
        let verdict = format!(
            "SNG {sng_measured_gbps:.2} Gbps (software, VM) vs {competitor} {published_gbps:.2} Gbps published ({delta_pct:+.0}%) — informative, not apples-to-apples: {caveat}",
        );
        Self {
            competitor,
            published_gbps,
            delta_pct,
            verdict,
        }
    }
}

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

    /// Render the standard markdown summary followed by the competitor
    /// comparison table, when one is attached.
    ///
    /// This is the business/RFP-flavoured view of a single report: the
    /// measured numbers plus how they stack up against same-class vendor
    /// appliances, each row carrying its hardware-vs-software caveat. A
    /// report with no comparison renders identically to [`Self::to_markdown`]
    /// (plus a one-line note).
    #[must_use]
    pub fn to_business_markdown(&self) -> String {
        let mut out = self.to_markdown();
        let _ = writeln!(out);
        match &self.competitor_comparison {
            Some(cmp) => {
                let _ = out.write_str(&cmp.to_markdown());
            }
            None => {
                let _ = writeln!(out, "_No competitor comparison attached._");
            }
        }
        out
    }
}

impl CompetitorComparison {
    /// Render the comparison as a markdown table (one row per competitor),
    /// headed by the SNG measured number and the feature category, and
    /// footed by the shared honesty caveat.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = writeln!(out, "### Competitor comparison — {}", self.feature);
        let _ = writeln!(
            out,
            "\nSNG measured: **{:.2} Gbps** (software-only, generic x86 VM).\n",
            self.sng_measured_gbps
        );
        let _ = writeln!(out, "| competitor | published | SNG | delta | verdict |");
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | --- |");
        for r in &self.rows {
            let _ = writeln!(
                out,
                "| {} | {:.2} Gbps | {:.2} Gbps | {:+.0}% | {} |",
                r.competitor, r.published_gbps, self.sng_measured_gbps, r.delta_pct, r.verdict
            );
        }
        if self.rows.is_empty() {
            let _ = writeln!(
                out,
                "| _(no same-class competitor published a figure)_ | | | | |"
            );
        }
        let _ = writeln!(
            out,
            "\n> Vendor figures are for purpose-built hardware/ASIC appliances; SNG is \
             software-only on a generic x86 VM. Treat the comparison as informative, not \
             apples-to-apples."
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

    // A drop in throughput is bad. change = (cur - base)/base; a
    // change <= -threshold is a regression.
    if let (Some(base), Some(cur)) = (&baseline.throughput, &current.throughput)
        && let Some(change) = fractional_change(base.max_gbps, cur.max_gbps)
        && change <= -thresholds.throughput_drop
    {
        regressions.push(Regression {
            metric: "max_gbps".to_string(),
            previous: base.max_gbps,
            current: cur.max_gbps,
            change_fraction: change,
        });
    }

    // An increase in p99 latency is bad.
    if let (Some(base), Some(cur)) = (&baseline.latency, &current.latency)
        && let Some(change) = fractional_change(base.p99_ns as f64, cur.p99_ns as f64)
        && change >= thresholds.latency_increase
    {
        regressions.push(Regression {
            metric: "p99_ns".to_string(),
            previous: base.p99_ns as f64,
            current: cur.p99_ns as f64,
            change_fraction: change,
        });
    }

    // A drop in sustainable concurrent flows is bad.
    if let (Some(base), Some(cur)) = (&baseline.concurrent_flows, &current.concurrent_flows)
        && let Some(change) =
            fractional_change(base.max_active_flows as f64, cur.max_active_flows as f64)
        && change <= -thresholds.concurrent_flows_drop
    {
        regressions.push(Regression {
            metric: "max_active_flows".to_string(),
            previous: base.max_active_flows as f64,
            current: cur.max_active_flows as f64,
            change_fraction: change,
        });
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

/// Schema version for the forwarding-sweep artifact. Bumped independently
/// of [`SCHEMA_VERSION`] so the two report families version separately.
pub const FORWARDING_SCHEMA_VERSION: u32 = 1;

/// One measured `(mode, backend)` point of a forwarding sweep, in the
/// serializable shape persisted to `bench/results/forwarding-*.json` and
/// rendered into `docs/throughput-skus.md`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardingMeasurement {
    /// Inspection-depth label (`raw-l3`, `ngfw-verdict`, ...).
    pub mode: String,
    /// Forwarding-substrate label (`nftables`, `xdp`).
    pub backend: String,
    /// Packets pushed through the pipeline.
    pub packets: u64,
    /// Throughput in packets per second.
    pub pps: f64,
    /// Throughput in Gbps at the profile's representative frame size.
    pub gbps: f64,
    /// Median per-packet service time (ns).
    pub p50_ns: u64,
    /// 99th-percentile per-packet service time (ns).
    pub p99_ns: u64,
    /// Spare decision capacity over the SKU's published target at this
    /// operating point, in `0.0..=1.0`. `1.0 - target_pps / pps`, floored
    /// at zero.
    pub cpu_headroom: f64,
}

impl ForwardingMeasurement {
    /// Mean per-packet service time in nanoseconds derived from `pps`.
    /// This is the hardware-invariant quantity the regression detector
    /// normalises on. `f64::INFINITY` for a zero-throughput point so it
    /// sorts as "infinitely slow" rather than dividing by zero.
    #[must_use]
    pub fn ns_per_packet(&self) -> f64 {
        if self.pps <= 0.0 {
            f64::INFINITY
        } else {
            1e9 / self.pps
        }
    }
}

/// One traffic class's result under the full pipeline on the fast path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardingClassMeasurement {
    /// Traffic-class wire string (`trusted_direct`, `inspect_full`, ...).
    pub class: String,
    /// Packets pushed (all of this class).
    pub packets: u64,
    /// Throughput in packets per second.
    pub pps: f64,
    /// Throughput in Gbps at the profile's representative frame size.
    pub gbps: f64,
    /// Median per-packet service time (ns).
    pub p50_ns: u64,
    /// 99th-percentile per-packet service time (ns).
    pub p99_ns: u64,
}

/// A full forwarding-sweep report for one SKU profile: every
/// `(mode, backend)` point plus the per-traffic-class breakdown. This is
/// the committed-baseline artifact the CI regression gate compares
/// against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardingReport {
    /// Artifact schema version.
    pub schema_version: u32,
    /// SKU profile name the sweep ran against.
    pub profile: String,
    /// Wall-clock time the report was produced (Unix seconds).
    pub unix_time_secs: u64,
    /// Source revision, when known. Additive `Option`: `serde(default)` lets
    /// a baseline that omits the key entirely still deserialize, matching the
    /// `competitor_comparison` convention above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Rule count of the synthetic policy walked.
    pub rule_count: usize,
    /// Representative frame size used for the Gbps figures.
    pub packet_bytes: u32,
    /// Packets pushed per measurement.
    pub sample_packets: usize,
    /// Per-`(mode, backend)` measurements.
    pub measurements: Vec<ForwardingMeasurement>,
    /// Per-traffic-class breakdown (full pipeline, fast path).
    pub per_class: Vec<ForwardingClassMeasurement>,
}

impl ForwardingReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a `serde_json` failure (never expected for this plain
    /// struct).
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    ///
    /// # Errors
    /// Returns [`ReportError::Json`] on malformed input.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Look up a `(mode, backend)` measurement by label.
    #[must_use]
    pub fn get(&self, mode: &str, backend: &str) -> Option<&ForwardingMeasurement> {
        self.measurements
            .iter()
            .find(|m| m.mode == mode && m.backend == backend)
    }

    /// Render this SKU's section of the published throughput document: the
    /// per-mode table on the fast path, the raw-L3 nftables-vs-XDP toggle,
    /// and the per-traffic-class breakdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "### SKU: `{}`", self.profile);
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Synthetic policy: {} rules · representative frame {} B · {} packets/measurement.",
            self.rule_count, self.packet_bytes, self.sample_packets
        );
        let _ = writeln!(out);

        // Per-mode table on the shipping (XDP) data path.
        let _ = writeln!(out, "**Forwarding modes (XDP fast path):**");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |");
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: |");
        for mode in ["raw-l3", "ngfw-verdict", "full-stack", "full-stack-tls"] {
            if let Some(m) = self.get(mode, "xdp") {
                let _ = writeln!(
                    out,
                    "| {} | {:.2} | {:.3} | {} | {} | {:.0}% |",
                    mode,
                    m.pps / 1e6,
                    m.gbps,
                    fmt_ns(m.p50_ns),
                    fmt_ns(m.p99_ns),
                    m.cpu_headroom * 100.0
                );
            }
        }
        let _ = writeln!(out);

        // Raw-L3 backend toggle.
        if let (Some(xdp), Some(nft)) = (self.get("raw-l3", "xdp"), self.get("raw-l3", "nftables"))
        {
            let speedup = if nft.pps > 0.0 {
                xdp.pps / nft.pps
            } else {
                0.0
            };
            let _ = writeln!(out, "**Raw-L3 datapath toggle (nftables vs XDP):**");
            let _ = writeln!(out);
            let _ = writeln!(out, "| Substrate | Mpps | Gbps |");
            let _ = writeln!(out, "| --- | ---: | ---: |");
            let _ = writeln!(
                out,
                "| nftables (slow path) | {:.2} | {:.3} |",
                nft.pps / 1e6,
                nft.gbps
            );
            let _ = writeln!(
                out,
                "| XDP (fast path) | {:.2} | {:.3} |",
                xdp.pps / 1e6,
                xdp.gbps
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "XDP fast-path speedup: **{speedup:.2}×**.");
            let _ = writeln!(out);
        }

        // Per-traffic-class breakdown (full pipeline, fast path).
        if !self.per_class.is_empty() {
            let _ = writeln!(
                out,
                "**Per-traffic-class (full-stack + TLS, XDP fast path):**"
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "| Traffic class | Mpps | Gbps | p50 | p99 |");
            let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
            for c in &self.per_class {
                let _ = writeln!(
                    out,
                    "| {} | {:.2} | {:.3} | {} | {} |",
                    c.class,
                    c.pps / 1e6,
                    c.gbps,
                    fmt_ns(c.p50_ns),
                    fmt_ns(c.p99_ns)
                );
            }
            let _ = writeln!(out);
        }

        out
    }
}

/// Schema version for the multi-queue throughput artifact
/// (`bench/results/multiqueue-*.json`). Independent of [`SCHEMA_VERSION`]
/// and [`FORWARDING_SCHEMA_VERSION`] so the three report families version
/// separately.
pub const MULTIQUEUE_SCHEMA_VERSION: u32 = 1;

/// One measured stream — a single NIC receive (RSS) queue pinned to a
/// worker thread for the duration of a fanout point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiQueueStreamMeasurement {
    /// Stream / queue index, `0..queues`.
    pub queue_index: usize,
    /// Packets this stream pushed through the pipeline.
    pub packets: u64,
    /// This stream's throughput in packets per second, measured while all
    /// queues at this fanout width were running concurrently.
    pub pps: f64,
    /// This stream's throughput in Gbps at the representative frame size.
    pub gbps: f64,
    /// Median per-packet service time (ns) for this stream.
    pub p50_ns: u64,
    /// 99th-percentile per-packet service time (ns) for this stream.
    pub p99_ns: u64,
}

/// Aggregate result at one queue-fanout width (`queues` parallel streams
/// running concurrently). The `queues == 1` point is the single-stream
/// *floor*; the widest point is the multi-queue *ceiling*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiQueueScalePoint {
    /// Number of concurrent streams (NIC RSS queues) at this point.
    pub queues: usize,
    /// Sum of every stream's throughput — the aggregate the box sustains
    /// at this fanout width.
    pub aggregate_pps: f64,
    /// Aggregate throughput in Gbps at the representative frame size.
    pub aggregate_gbps: f64,
    /// Mean per-stream throughput (`aggregate_pps / queues`). Falls as the
    /// fanout exceeds the host's physical cores — the contention the
    /// single-stream number cannot show.
    pub mean_pps_per_queue: f64,
    /// Scaling efficiency: `aggregate_pps / (queues × single_stream_pps)`,
    /// where the single-stream rate is the `queues == 1` aggregate. `1.0`
    /// is ideal linear scaling; below `1.0` is the real, contended ceiling.
    pub scaling_efficiency: f64,
    /// Mean across streams of the per-stream median service time (ns).
    pub p50_ns_mean: u64,
    /// Worst (max) across streams of the per-stream p99 service time (ns).
    pub p99_ns_max: u64,
    /// Per-stream detail for this fanout width.
    pub streams: Vec<MultiQueueStreamMeasurement>,
}

/// A multi-queue / multi-stream wire-throughput report for one SKU: a
/// scaling curve from a single stream up to the widest fanout, recording
/// aggregate throughput and per-stream scaling at each width.
///
/// The point of the artifact is to publish a realistic *line-rate
/// ceiling* (many queues, the way a multi-queue physical NIC and the
/// per-queue XDP fast path actually run) alongside the honestly-caveated
/// single-stream *floor* the blog already quotes. It is still
/// software-on-a-VM, not an ASIC — see [`Self::to_markdown`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiQueueReport {
    /// Artifact schema version.
    pub schema_version: u32,
    /// SKU profile name the sweep ran against.
    pub profile: String,
    /// Wall-clock time the report was produced (Unix seconds).
    pub unix_time_secs: u64,
    /// Source revision, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Forwarding mode (inspection depth) measured (`raw-l3`, ...).
    pub mode: String,
    /// Forwarding substrate measured (`xdp`, `nftables`).
    pub backend: String,
    /// Rule count of the synthetic policy each stream walked.
    pub rule_count: usize,
    /// Representative frame size used for the Gbps figures.
    pub packet_bytes: u32,
    /// Packets each stream pushed per measurement.
    pub packets_per_queue: usize,
    /// `std::thread::available_parallelism()` on the measuring host — the
    /// physical/logical core budget the scaling curve is bounded by.
    pub available_parallelism: usize,
    /// The SKU's published acceptance target in Gbps, for context.
    pub target_gbps: f64,
    /// The scaling curve, in ascending queue-count order.
    pub points: Vec<MultiQueueScalePoint>,
}

impl MultiQueueReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a `serde_json` failure (never expected for this plain
    /// struct).
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    ///
    /// # Errors
    /// Returns [`ReportError::Json`] on malformed input.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// The single-stream floor (`queues == 1`), if measured.
    #[must_use]
    pub fn single_stream(&self) -> Option<&MultiQueueScalePoint> {
        self.points.iter().find(|p| p.queues == 1)
    }

    /// The widest-fanout multi-queue ceiling, if any point was measured.
    #[must_use]
    pub fn ceiling(&self) -> Option<&MultiQueueScalePoint> {
        self.points.iter().max_by_key(|p| p.queues)
    }

    /// Render the markdown summary: the scaling table, the floor→ceiling
    /// headline, and the standing honesty caveat.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "### Multi-queue throughput: `{}`", self.profile);
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Mode `{}` · backend `{}` · {} rules · representative frame {} B · \
             {} packets/stream · host parallelism {}.",
            self.mode,
            self.backend,
            self.rule_count,
            self.packet_bytes,
            self.packets_per_queue,
            self.available_parallelism
        );
        let _ = writeln!(out);

        let _ = writeln!(
            out,
            "| Queues | Aggregate Mpps | Aggregate Gbps | Per-queue Mpps | Scaling eff. | p50 | p99 (max) |"
        );
        let _ = writeln!(out, "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
        for p in &self.points {
            let _ = writeln!(
                out,
                "| {} | {:.2} | {:.3} | {:.2} | {:.0}% | {} | {} |",
                p.queues,
                p.aggregate_pps / 1e6,
                p.aggregate_gbps,
                p.mean_pps_per_queue / 1e6,
                p.scaling_efficiency * 100.0,
                fmt_ns(p.p50_ns_mean),
                fmt_ns(p.p99_ns_max)
            );
        }
        let _ = writeln!(out);

        if let (Some(floor), Some(ceil)) = (self.single_stream(), self.ceiling())
            && ceil.queues > floor.queues
        {
            let lift = if floor.aggregate_gbps > 0.0 {
                ceil.aggregate_gbps / floor.aggregate_gbps
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "Single-stream floor: **{:.3} Gbps** ({} queue). \
                 Multi-queue ceiling: **{:.3} Gbps** ({} queues) — a **{:.2}×** lift.",
                floor.aggregate_gbps, floor.queues, ceil.aggregate_gbps, ceil.queues, lift
            );
            let _ = writeln!(out);
        }

        if self.target_gbps > 0.0 {
            let _ = writeln!(
                out,
                "SKU published acceptance target: **{:.3} Gbps**.",
                self.target_gbps
            );
            let _ = writeln!(out);
        }

        let _ = writeln!(
            out,
            "> **Read this honestly.** This is the in-process forwarding fast path fanned \
             out across {} worker threads on a generic x86 VM — a *software* multi-queue \
             model, not a multi-queue physical NIC and not an ASIC. The single-stream row \
             is the same conservative floor the blog quotes; the wider rows show how the \
             per-queue XDP fast path scales when the box is allowed to use all its cores. \
             Treat the ceiling as an apples-*closer* figure to a vendor's multi-queue \
             line-rate number, still not apples-to-apples.",
            self.available_parallelism
        );

        out
    }
}

/// Schema version for the [`WireScalingReport`] artifact. Bumped
/// independently of the forwarding/throughput schemas because the wire
/// scaling artifact has its own consumers (the `wire-scaling` leg).
pub const WIRE_SCALING_SCHEMA_VERSION: u32 = 1;

/// One measured wire stream — a single `AF_PACKET` transmit socket pinned
/// to a worker thread for the duration of a fanout point. Unlike
/// [`MultiQueueStreamMeasurement`], these frames are actually crafted and
/// pushed at the kernel transmit path (or, in `--dry-run`, crafted and
/// discarded), so the numbers are a *wire* measurement, not an in-process
/// forwarding-decision model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireStreamMeasurement {
    /// Stream / TX-socket index, `0..queues`.
    pub queue_index: usize,
    /// Frames this stream transmitted in its measured window.
    pub packets: u64,
    /// Wire bytes this stream transmitted (sum of per-frame sizes).
    pub bytes: u64,
    /// This stream's transmit rate in packets per second, measured while
    /// every stream at this fanout width was running concurrently.
    pub pps: f64,
    /// This stream's transmit rate in Gbps over the same window.
    pub gbps: f64,
    /// The stream's own measured wall-clock window in milliseconds. Each
    /// stream times itself so a thread that is scheduled late never
    /// inflates another stream's rate.
    pub elapsed_ms: f64,
}

/// Aggregate result at one TX-fanout width (`queues` parallel `AF_PACKET`
/// transmit streams running concurrently). The `queues == 1` point is the
/// single-stream *wire floor* — the ~5.5 Gbps number the blog quotes; the
/// widest point is the multi-queue *wire ceiling*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireScalePoint {
    /// Number of concurrent transmit streams at this point.
    pub queues: usize,
    /// Sum of every stream's transmit rate — the aggregate wire rate the
    /// box sustains at this fanout width.
    pub aggregate_pps: f64,
    /// Aggregate transmit rate in Gbps at this fanout width.
    pub aggregate_gbps: f64,
    /// Mean per-stream transmit rate in Gbps (`aggregate_gbps / queues`).
    /// Falls as the fanout exceeds the host's physical cores — the
    /// contention a single-stream number structurally cannot reveal.
    pub mean_gbps_per_queue: f64,
    /// Scaling efficiency: `aggregate_pps / (queues × single_stream_pps)`,
    /// where the single-stream rate is the `queues == 1` aggregate. `1.0`
    /// is ideal linear scaling; below `1.0` is the real, contended ceiling.
    pub scaling_efficiency: f64,
    /// Per-stream detail for this fanout width.
    pub streams: Vec<WireStreamMeasurement>,
}

/// A multi-queue *wire* transmit scaling report: a curve from a single
/// `AF_PACKET` transmit stream up to the widest fanout, recording the
/// aggregate wire rate and per-stream scaling at each width.
///
/// This is the artifact that retires the "single-stream floor" caveat with
/// a *real wire* number: every frame is crafted and handed to the kernel
/// transmit path across N sockets on N cores, exactly the way a
/// multi-queue NIC fans transmit across TX rings. It remains
/// software-on-a-VM, not an ASIC — [`Self::to_markdown`] carries that
/// caveat. When `transport` is `dry-run` the figures are a craft-rate
/// ceiling (no socket), never to be quoted as a wire number.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireScalingReport {
    /// Artifact schema version.
    pub schema_version: u32,
    /// SKU profile name the sweep ran against.
    pub profile: String,
    /// Wall-clock time the report was produced (Unix seconds).
    pub unix_time_secs: u64,
    /// Source revision, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Transmit transport: `af-packet` for a live wire run, `dry-run` for
    /// the in-process craft-only ceiling. Recorded so a dry-run number is
    /// never silently published as a wire measurement.
    pub transport: String,
    /// Egress interface the live run transmitted on (`lo`, `eth0`, ...).
    pub interface: String,
    /// Representative on-wire frame size in bytes.
    pub frame_bytes: u32,
    /// IP version of the crafted traffic (`v4` / `v6`). Recorded so two
    /// artifacts from the same profile but different IP versions are
    /// self-describing and never conflated by a future compare gate.
    pub ip_version: String,
    /// L4 protocol shape of the crafted traffic (`udp` / `tcp-syn`).
    pub l4: String,
    /// Per-stream measured window in milliseconds.
    pub duration_ms: u64,
    /// `std::thread::available_parallelism()` on the measuring host — the
    /// core budget the scaling curve is bounded by.
    pub available_parallelism: usize,
    /// The SKU's published acceptance target in Gbps, for context.
    pub target_gbps: f64,
    /// The scaling curve, in ascending queue-count order.
    pub points: Vec<WireScalePoint>,
}

impl WireScalingReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a `serde_json` failure (never expected for this plain
    /// struct).
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    ///
    /// # Errors
    /// Returns [`ReportError::Json`] on malformed input.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// The single-stream wire floor (`queues == 1`), if measured.
    #[must_use]
    pub fn single_stream(&self) -> Option<&WireScalePoint> {
        self.points.iter().find(|p| p.queues == 1)
    }

    /// The widest-fanout wire ceiling, if any point was measured.
    #[must_use]
    pub fn ceiling(&self) -> Option<&WireScalePoint> {
        self.points.iter().max_by_key(|p| p.queues)
    }

    /// Render the markdown summary: the scaling table, the floor→ceiling
    /// headline, and the standing honesty caveat.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "### Multi-queue wire throughput: `{}`", self.profile);
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Transport `{}` · interface `{}` · {} {} · frame {} B · {} ms/stream · host parallelism {}.",
            self.transport,
            self.interface,
            self.ip_version,
            self.l4,
            self.frame_bytes,
            self.duration_ms,
            self.available_parallelism
        );
        let _ = writeln!(out);

        let _ = writeln!(
            out,
            "| Streams | Aggregate Mpps | Aggregate Gbps | Per-stream Gbps | Scaling eff. |"
        );
        let _ = writeln!(out, "| ---: | ---: | ---: | ---: | ---: |");
        for p in &self.points {
            let _ = writeln!(
                out,
                "| {} | {:.2} | {:.3} | {:.3} | {:.0}% |",
                p.queues,
                p.aggregate_pps / 1e6,
                p.aggregate_gbps,
                p.mean_gbps_per_queue,
                p.scaling_efficiency * 100.0,
            );
        }
        let _ = writeln!(out);

        if let (Some(floor), Some(ceil)) = (self.single_stream(), self.ceiling())
            && ceil.queues > floor.queues
        {
            let lift = if floor.aggregate_gbps > 0.0 {
                ceil.aggregate_gbps / floor.aggregate_gbps
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "Single-stream wire floor: **{:.3} Gbps** ({} stream). \
                 Multi-queue wire ceiling: **{:.3} Gbps** ({} streams) — a **{:.2}×** lift.",
                floor.aggregate_gbps, floor.queues, ceil.aggregate_gbps, ceil.queues, lift
            );
            let _ = writeln!(out);
        }

        if self.target_gbps > 0.0 {
            let _ = writeln!(
                out,
                "SKU published acceptance target: **{:.3} Gbps**.",
                self.target_gbps
            );
            let _ = writeln!(out);
        }

        let caveat = if self.transport == "dry-run" {
            "> **Read this honestly.** This is a `--dry-run` craft-only ceiling: frames are \
             built and discarded, never handed to a socket, so the figure is the host's \
             packet-*crafting* rate across N cores, not a wire number. Run without \
             `--dry-run` (with `CAP_NET_RAW`) for the real `AF_PACKET` transmit measurement."
        } else {
            "> **Read this honestly.** These frames are really crafted and pushed at the \
             kernel `AF_PACKET` transmit path across N sockets on a generic x86 VM — a real \
             *wire* measurement, but still software-on-x86, not a multi-queue physical NIC \
             and not an ASIC. The single-stream row is the conservative floor the blog \
             quotes; the wider rows show how transmit scales when the box uses all its cores. \
             Treat the ceiling as an apples-*closer* figure to a vendor's multi-queue \
             line-rate number, still not apples-to-apples."
        };
        let _ = writeln!(out, "{caveat}");

        out
    }
}

/// Direction in which a forwarding metric regresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegressDir {
    /// A *rise* beyond the threshold is the regression (cost-like metric:
    /// normalised per-packet cost — bigger is worse).
    Rise,
    /// A *drop* beyond the threshold is the regression (advantage-like
    /// metric: fast-path speedup — smaller is worse).
    Drop,
}

/// One hardware-invariant forwarding metric the gate keys on. Each is a
/// dimensionless ratio that is a pure function of a *single* report, so it
/// can be evaluated independently on the baseline and on every current
/// sample — which is what lets the statistical gate aggregate N samples.
#[derive(Debug, Clone)]
enum FwdMetric {
    /// Per-mode inspection cost normalised to the raw-L3 fast path:
    /// `ns_per_packet(mode, backend) / ns_per_packet(raw-l3, xdp)`. A rise
    /// means a stage (NGFW, IPS, TLS, ...) got disproportionately more
    /// expensive relative to the line-rate fast path.
    RelativeCost { mode: String, backend: String },
    /// Raw-L3 XDP-over-nftables speedup `pps(raw-l3, xdp) /
    /// pps(raw-l3, nftables)`. A drop means the XDP fast path lost ground
    /// against the engine — the one regression a relative-cost check
    /// anchored on the fast path cannot see on its own.
    FastPathAdvantage,
}

impl FwdMetric {
    /// Stable human-readable name surfaced in the regression report.
    fn name(&self) -> String {
        match self {
            FwdMetric::RelativeCost { mode, backend } => format!("{mode}/{backend} relative-cost"),
            FwdMetric::FastPathAdvantage => "raw-l3 xdp-over-nftables speedup".to_string(),
        }
    }

    /// Which direction of movement counts as a regression.
    fn direction(&self) -> RegressDir {
        match self {
            FwdMetric::RelativeCost { .. } => RegressDir::Rise,
            FwdMetric::FastPathAdvantage => RegressDir::Drop,
        }
    }

    /// Evaluate the metric on a single report, given that report's own
    /// `(raw-l3, xdp)` anchor cost in ns/packet. Returns `None` when the
    /// report lacks a measurement the metric needs (so the metric is
    /// skipped rather than fabricated).
    fn eval(&self, r: &ForwardingReport, anchor_ns: f64) -> Option<f64> {
        match self {
            FwdMetric::RelativeCost { mode, backend } => {
                let m = r.get(mode, backend)?;
                let nspp = m.ns_per_packet();
                if nspp.is_finite() {
                    Some(nspp / anchor_ns)
                } else {
                    None
                }
            }
            FwdMetric::FastPathAdvantage => {
                let xdp = r.get(RAW_L3_LABEL, XDP_LABEL)?;
                let nft = r.get(RAW_L3_LABEL, NFTABLES_LABEL)?;
                ratio(xdp.pps, nft.pps)
            }
        }
    }
}

/// The report's `(raw-l3, xdp)` anchor cost in ns/packet, used to
/// normalise every relative-cost metric. Errors when the anchor is absent
/// or has non-positive throughput (which would make the ratios undefined).
fn forwarding_anchor_ns(r: &ForwardingReport) -> Result<f64, String> {
    let m = r
        .get(RAW_L3_LABEL, XDP_LABEL)
        .ok_or_else(|| "report missing (raw-l3, xdp) anchor measurement".to_string())?;
    let nspp = m.ns_per_packet();
    if nspp.is_finite() && nspp > 0.0 {
        Ok(nspp)
    } else {
        Err("(raw-l3, xdp) anchor has non-positive throughput".to_string())
    }
}

/// Enumerate the metrics to gate on, derived from the committed baseline:
/// every `(mode, backend)` point except the anchor (a relative-cost
/// metric), plus the raw-L3 fast-path advantage when the baseline carries
/// both raw-L3 substrates. A point absent from the baseline has no
/// reference value, so it can never be a regression and is not enumerated.
fn forwarding_metrics(baseline: &ForwardingReport) -> Vec<FwdMetric> {
    let mut metrics = Vec::new();
    for m in &baseline.measurements {
        if m.mode == RAW_L3_LABEL && m.backend == XDP_LABEL {
            continue; // the anchor itself
        }
        metrics.push(FwdMetric::RelativeCost {
            mode: m.mode.clone(),
            backend: m.backend.clone(),
        });
    }
    if baseline.get(RAW_L3_LABEL, XDP_LABEL).is_some()
        && baseline.get(RAW_L3_LABEL, NFTABLES_LABEL).is_some()
    {
        metrics.push(FwdMetric::FastPathAdvantage);
    }
    metrics
}

/// Median of `values`, ignoring non-finite entries. `None` for an empty
/// (or all-non-finite) input. The median is robust to the single wild
/// outlier a shared CI runner periodically produces, which is precisely
/// why the gate aggregates with it rather than the mean.
fn median(values: &[f64]) -> Option<f64> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite values are totally ordered"));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        f64::midpoint(v[n / 2 - 1], v[n / 2])
    })
}

/// Corrected (Bessel, `n-1`) sample standard deviation of `values`,
/// ignoring non-finite entries. `0.0` for fewer than two finite samples —
/// a single sample carries no dispersion information, which collapses the
/// noise band to zero and recovers the plain threshold gate.
fn sample_stddev(values: &[f64]) -> f64 {
    let v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    let n = v.len();
    if n < 2 {
        return 0.0;
    }
    let mean = v.iter().sum::<f64>() / n as f64;
    let variance = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    variance.sqrt()
}

/// Per-metric statistical verdict produced by the N-sample forwarding
/// gate. Carries the full picture — baseline, sample median, dispersion,
/// and both gate conditions — so the CLI can explain *why* a metric was or
/// was not flagged instead of emitting a bare pass/fail.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatMetric {
    /// Metric name (`ngfw-verdict/xdp relative-cost`, `raw-l3
    /// xdp-over-nftables speedup`, ...).
    pub metric: String,
    /// Baseline value (the committed reference).
    pub baseline: f64,
    /// Median of the metric across the N current samples.
    pub median: f64,
    /// Corrected sample standard deviation across the N samples — the
    /// measured run-to-run noise that defines the band.
    pub stddev: f64,
    /// Number of finite samples that fed the median/stddev.
    pub samples: usize,
    /// Signed fractional move of the median off the baseline,
    /// `(median - baseline) / baseline`.
    pub change_fraction: f64,
    /// Whether the median moved in the regressing direction by at least
    /// the threshold.
    pub exceeds_threshold: bool,
    /// Whether the absolute median move is larger than the noise band
    /// (`sigma × stddev`) — i.e. too large to be sampling noise.
    pub outside_noise_band: bool,
    /// The final verdict: a regression only when it both exceeds the
    /// threshold *and* sits outside the noise band.
    pub flagged: bool,
}

/// Result of the statistical forwarding gate over N current samples.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatRegressionReport {
    /// Noise-band width applied, in sample standard deviations.
    pub sigma: f64,
    /// Fractional regression threshold applied to the median.
    pub threshold: f64,
    /// Number of current samples aggregated.
    pub sample_count: usize,
    /// Every gated metric with its verdict (flagged or not) for full
    /// transparency.
    pub metrics: Vec<StatMetric>,
}

impl StatRegressionReport {
    /// Whether any metric was flagged as a real regression.
    #[must_use]
    pub fn has_regression(&self) -> bool {
        self.metrics.iter().any(|m| m.flagged)
    }

    /// Iterator over only the flagged (regressing) metrics.
    pub fn flagged(&self) -> impl Iterator<Item = &StatMetric> {
        self.metrics.iter().filter(|m| m.flagged)
    }
}

/// Statistically gate a set of `samples` (N independent re-runs of the
/// forwarding sweep on this host) against a committed `baseline`.
///
/// The gate is **hardware-invariant** — it only ever diffs dimensionless
/// ratios that hold across machines (per-mode normalised cost and the
/// raw-L3 fast-path advantage), never absolute throughput. On top of that
/// it is **statistically robust**, which is what stops a single noisy run
/// on a shared CI runner from failing the build:
///
///   1. Each metric is evaluated on every sample and aggregated with the
///      **median**, which shrugs off the lone wild outlier a shared runner
///      periodically emits.
///   2. A metric is flagged only when the median move (a) exceeds the
///      fractional `threshold` in the regressing direction **and** (b) is
///      larger than the **noise band** `sigma × σ`, where `σ` is the
///      corrected sample standard deviation of the samples themselves. A
///      real per-stage or fast-path regression clears both bars; a dip
///      that lives inside the run-to-run scatter does not.
///
/// With a single sample (`samples.len() == 1`) the standard deviation is
/// zero, the noise band vanishes, and the gate degrades exactly to the
/// legacy threshold-only behaviour — so the interface stays backward
/// compatible.
///
/// # Errors
/// Returns an error string when any sample describes a different schema
/// version or profile than the baseline, when `samples` is empty, or when
/// the baseline or any sample is missing the `(raw-l3, xdp)` anchor the
/// normalisation requires.
pub fn detect_forwarding_regression_stats(
    baseline: &ForwardingReport,
    samples: &[ForwardingReport],
    threshold: f64,
    sigma: f64,
) -> Result<StatRegressionReport, String> {
    if samples.is_empty() {
        return Err("no current samples to compare against the baseline".to_string());
    }
    for s in samples {
        if baseline.schema_version != s.schema_version {
            return Err(format!(
                "forwarding schema version mismatch: baseline {} vs current {}",
                baseline.schema_version, s.schema_version
            ));
        }
        if baseline.profile != s.profile {
            return Err(format!(
                "cannot compare different profiles: baseline {:?} vs current {:?}",
                baseline.profile, s.profile
            ));
        }
    }

    let base_anchor = forwarding_anchor_ns(baseline)?;
    let sample_anchors: Vec<f64> = samples
        .iter()
        .map(forwarding_anchor_ns)
        .collect::<Result<_, _>>()?;

    let mut metrics = Vec::new();
    for metric in forwarding_metrics(baseline) {
        let Some(base_val) = metric.eval(baseline, base_anchor) else {
            continue; // baseline can't form this metric → nothing to gate
        };
        if base_val == 0.0 {
            continue; // no defined reference to take a fractional change from
        }

        // Evaluate the metric on every sample; a sample missing the point
        // simply does not contribute (rather than poisoning the set).
        let sample_vals: Vec<f64> = samples
            .iter()
            .zip(&sample_anchors)
            .filter_map(|(s, &a)| metric.eval(s, a))
            .collect();
        let Some(median_val) = median(&sample_vals) else {
            continue; // no current evidence for this metric
        };
        let stddev = sample_stddev(&sample_vals);

        let change = (median_val - base_val) / base_val;
        let exceeds_threshold = match metric.direction() {
            RegressDir::Rise => change >= threshold,
            RegressDir::Drop => change <= -threshold,
        };
        let noise_band = sigma * stddev;
        let outside_noise_band = (median_val - base_val).abs() > noise_band;

        metrics.push(StatMetric {
            metric: metric.name(),
            baseline: base_val,
            median: median_val,
            stddev,
            samples: sample_vals.len(),
            change_fraction: change,
            exceeds_threshold,
            outside_noise_band,
            flagged: exceeds_threshold && outside_noise_band,
        });
    }

    Ok(StatRegressionReport {
        sigma,
        threshold,
        sample_count: samples.len(),
        metrics,
    })
}

/// Compare a single current forwarding sweep against a committed baseline.
///
/// This is the single-sample special case of
/// [`detect_forwarding_regression_stats`] (one sample, zero-width noise
/// band) preserved for the existing CLI/JSON callers and tests. It is
/// hardware-invariant but **not** noise-robust — prefer the statistical
/// gate with N samples on a shared runner.
///
/// # Errors
/// Returns an error string when the reports describe different schema
/// versions or profiles, or when either is missing the `(raw-l3, xdp)`
/// anchor the normalisation requires.
pub fn detect_forwarding_regression(
    baseline: &ForwardingReport,
    current: &ForwardingReport,
    threshold: f64,
) -> Result<RegressionReport, String> {
    let stats = detect_forwarding_regression_stats(
        baseline,
        std::slice::from_ref(current),
        threshold,
        0.0,
    )?;
    let regressions = stats
        .flagged()
        .map(|m| Regression {
            metric: m.metric.clone(),
            previous: m.baseline,
            current: m.median,
            change_fraction: m.change_fraction,
        })
        .collect();
    Ok(RegressionReport { regressions })
}

/// Statistically gate a set of multi-queue scaling `samples` (N re-runs of
/// the `multi-queue` sweep on this host) against a committed `baseline`.
///
/// Like the forwarding gate, this is **hardware-invariant**: it never
/// diffs absolute Gbps (which tracks the host's core count and clock) but
/// the dimensionless [`MultiQueueScalePoint::scaling_efficiency`] —
/// `aggregate / (queues × single_stream)` — at each fan-out width. That
/// ratio is the portable shape of the scaling curve, so a baseline
/// captured on an 8-vCPU runner still gates a 16-vCPU one: a real loss of
/// scale-out (lock contention, false sharing, an allocator regression in
/// the per-queue harness) drops efficiency on every box, while swapping
/// hardware moves only the absolute numbers the gate ignores.
///
/// The `queues == 1` point is skipped — its efficiency is `1.0` by
/// construction (it *is* the baseline) and carries no signal. Each wider
/// width is gated as a **drop** in efficiency, aggregated by median and
/// tested against a `sigma × σ` noise band exactly as the forwarding gate,
/// so a single noisy run on a shared runner does not fail the build. With
/// one sample the band vanishes and the gate degrades to threshold-only.
///
/// # Errors
/// Returns an error string when `samples` is empty or when any sample
/// describes a different schema version, profile, mode, or backend than
/// the baseline (so a `raw-l3` curve is never compared against a
/// `full-stack` one).
pub fn detect_multiqueue_regression_stats(
    baseline: &MultiQueueReport,
    samples: &[MultiQueueReport],
    threshold: f64,
    sigma: f64,
) -> Result<StatRegressionReport, String> {
    if samples.is_empty() {
        return Err("no current samples to compare against the baseline".to_string());
    }
    for s in samples {
        if baseline.schema_version != s.schema_version {
            return Err(format!(
                "multi-queue schema version mismatch: baseline {} vs current {}",
                baseline.schema_version, s.schema_version
            ));
        }
        if baseline.profile != s.profile || baseline.mode != s.mode || baseline.backend != s.backend
        {
            return Err(format!(
                "cannot compare different sweeps: baseline {}/{}/{} vs current {}/{}/{}",
                baseline.profile, baseline.mode, baseline.backend, s.profile, s.mode, s.backend
            ));
        }
    }

    let mut metrics = Vec::new();
    for point in &baseline.points {
        // queues == 1 is the efficiency baseline (always 1.0) → no signal.
        if point.queues < 2 {
            continue;
        }
        let base_val = point.scaling_efficiency;
        if !base_val.is_finite() || base_val <= 0.0 {
            continue; // no defined reference to take a fractional change from
        }

        // A sample missing this width simply does not contribute, rather
        // than poisoning the set. Non-finite efficiencies are filtered here
        // too — `median`/`sample_stddev` ignore them internally, so keeping
        // them out at collection makes `sample_vals.len()` the true count of
        // finite samples that fed the statistics (matching the documented
        // `StatMetric::samples` contract and the forwarding gate's
        // finite-only collection).
        let sample_vals: Vec<f64> = samples
            .iter()
            .filter_map(|s| s.points.iter().find(|p| p.queues == point.queues))
            .map(|p| p.scaling_efficiency)
            .filter(|e| e.is_finite())
            .collect();
        let Some(median_val) = median(&sample_vals) else {
            continue; // no current evidence for this width
        };
        let stddev = sample_stddev(&sample_vals);

        let change = (median_val - base_val) / base_val;
        // Efficiency is advantage-like: a drop is the regression.
        let exceeds_threshold = change <= -threshold;
        let noise_band = sigma * stddev;
        let outside_noise_band = (median_val - base_val).abs() > noise_band;

        metrics.push(StatMetric {
            metric: format!("q={} scaling-efficiency", point.queues),
            baseline: base_val,
            median: median_val,
            stddev,
            samples: sample_vals.len(),
            change_fraction: change,
            exceeds_threshold,
            outside_noise_band,
            flagged: exceeds_threshold && outside_noise_band,
        });
    }

    Ok(StatRegressionReport {
        sigma,
        threshold,
        sample_count: samples.len(),
        metrics,
    })
}

/// Compare a single current multi-queue sweep against a committed
/// baseline. The single-sample special case of
/// [`detect_multiqueue_regression_stats`] (zero-width noise band),
/// hardware-invariant but not noise-robust — prefer the statistical gate
/// with N samples on a shared runner.
///
/// # Errors
/// Propagates the validation errors of
/// [`detect_multiqueue_regression_stats`].
pub fn detect_multiqueue_regression(
    baseline: &MultiQueueReport,
    current: &MultiQueueReport,
    threshold: f64,
) -> Result<RegressionReport, String> {
    let stats = detect_multiqueue_regression_stats(
        baseline,
        std::slice::from_ref(current),
        threshold,
        0.0,
    )?;
    let regressions = stats
        .flagged()
        .map(|m| Regression {
            metric: m.metric.clone(),
            previous: m.baseline,
            current: m.median,
            change_fraction: m.change_fraction,
        })
        .collect();
    Ok(RegressionReport { regressions })
}

/// Gate one-or-more current *wire* scaling sweeps against a committed
/// baseline on the hardware-invariant per-width transmit scaling
/// efficiency, exactly as [`detect_multiqueue_regression_stats`] gates the
/// in-process forwarding curve.
///
/// Efficiency (`aggregate / (queues × single_stream)`) is dimensionless, so
/// a baseline captured on one box still gates another: a real loss of
/// transmit scale-out (lock contention on the TX path, false sharing in the
/// per-socket harness, an allocator regression) drops efficiency on every
/// host, while swapping hardware moves only the absolute Gbps the gate
/// ignores. The `queues == 1` floor is skipped — its efficiency is `1.0` by
/// construction. Each wider width is gated as a **drop**, aggregated by
/// median and tested against a `sigma × σ` noise band so a single noisy run
/// on a shared runner does not fail the build.
///
/// # Errors
/// Returns an error string when `samples` is empty or when any sample
/// describes a different schema version, profile, transport, IP version, L4
/// shape, or frame size than the baseline — guards that stop a `dry-run`
/// craft ceiling from ever being compared against a live `af-packet` wire
/// curve, or a v4/UDP run against a v6/TCP one.
pub fn detect_wire_scaling_regression_stats(
    baseline: &WireScalingReport,
    samples: &[WireScalingReport],
    threshold: f64,
    sigma: f64,
) -> Result<StatRegressionReport, String> {
    if samples.is_empty() {
        return Err("no current samples to compare against the baseline".to_string());
    }
    for s in samples {
        if baseline.schema_version != s.schema_version {
            return Err(format!(
                "wire-scaling schema version mismatch: baseline {} vs current {}",
                baseline.schema_version, s.schema_version
            ));
        }
        if baseline.profile != s.profile
            || baseline.transport != s.transport
            || baseline.ip_version != s.ip_version
            || baseline.l4 != s.l4
            || baseline.frame_bytes != s.frame_bytes
        {
            return Err(format!(
                "cannot compare different wire sweeps: baseline {}/{}/{}/{}/{}B vs current {}/{}/{}/{}/{}B",
                baseline.profile,
                baseline.transport,
                baseline.ip_version,
                baseline.l4,
                baseline.frame_bytes,
                s.profile,
                s.transport,
                s.ip_version,
                s.l4,
                s.frame_bytes,
            ));
        }
    }

    let mut metrics = Vec::new();
    for point in &baseline.points {
        // queues == 1 is the efficiency baseline (always 1.0) → no signal.
        if point.queues < 2 {
            continue;
        }
        let base_val = point.scaling_efficiency;
        if !base_val.is_finite() || base_val <= 0.0 {
            continue; // no defined reference to take a fractional change from
        }

        let sample_vals: Vec<f64> = samples
            .iter()
            .filter_map(|s| s.points.iter().find(|p| p.queues == point.queues))
            .map(|p| p.scaling_efficiency)
            .filter(|e| e.is_finite())
            .collect();
        let Some(median_val) = median(&sample_vals) else {
            continue; // no current evidence for this width
        };
        let stddev = sample_stddev(&sample_vals);

        let change = (median_val - base_val) / base_val;
        // Efficiency is advantage-like: a drop is the regression.
        let exceeds_threshold = change <= -threshold;
        let noise_band = sigma * stddev;
        let outside_noise_band = (median_val - base_val).abs() > noise_band;

        metrics.push(StatMetric {
            metric: format!("q={} wire-scaling-efficiency", point.queues),
            baseline: base_val,
            median: median_val,
            stddev,
            samples: sample_vals.len(),
            change_fraction: change,
            exceeds_threshold,
            outside_noise_band,
            flagged: exceeds_threshold && outside_noise_band,
        });
    }

    Ok(StatRegressionReport {
        sigma,
        threshold,
        sample_count: samples.len(),
        metrics,
    })
}

/// `numerator / denominator`, or `None` when the denominator is zero.
fn ratio(numerator: f64, denominator: f64) -> Option<f64> {
    if denominator == 0.0 {
        None
    } else {
        Some(numerator / denominator)
    }
}

/// Mode/backend labels the forwarding gate keys on. Kept here (rather than
/// importing the `datapath` enums) so the report model stays a pure data
/// layer; they must match [`crate::datapath::ForwardingMode::label`] and
/// [`crate::datapath::Backend::label`].
const RAW_L3_LABEL: &str = "raw-l3";
const XDP_LABEL: &str = "xdp";
const NFTABLES_LABEL: &str = "nftables";

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
            competitor_comparison: None,
        }
    }

    fn sample_comparison() -> CompetitorComparison {
        CompetitorComparison {
            sng_measured_gbps: 4.8,
            feature: "firewall throughput".to_string(),
            rows: vec![
                CompetitorRow::new("Fortinet FortiGate 60F", 10.0, 4.8, "ASIC appliance"),
                CompetitorRow::new("Palo Alto PA-450", 5.2, 4.8, "hardware appliance"),
            ],
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

    #[test]
    fn competitor_row_computes_signed_delta() {
        // SNG below the published number → negative delta.
        let under = CompetitorRow::new("X", 10.0, 4.8, "c");
        assert!((under.delta_pct + 52.0).abs() < 1e-9);
        // SNG above → positive delta, and the verdict carries the caveat.
        let over = CompetitorRow::new("Y", 4.0, 5.0, "purpose-built ASIC");
        assert!((over.delta_pct - 25.0).abs() < 1e-9);
        assert!(over.verdict.contains("purpose-built ASIC"));
        assert!(over.verdict.contains("not apples-to-apples"));
    }

    #[test]
    fn competitor_row_guards_zero_published() {
        let r = CompetitorRow::new("Z", 0.0, 4.8, "c");
        assert!(r.delta_pct.abs() < 1e-9);
    }

    #[test]
    fn report_with_competitor_comparison_round_trips() {
        let mut r = sample_report(BenchMode::Throughput);
        r.competitor_comparison = Some(sample_comparison());
        let json = r.to_json().unwrap();
        let back = BenchmarkReport::from_json(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn report_without_comparison_omits_the_field_in_json() {
        let r = sample_report(BenchMode::Throughput);
        let json = r.to_json().unwrap();
        assert!(!json.contains("competitor_comparison"));
    }

    #[test]
    fn legacy_json_without_field_deserializes_to_none() {
        // A report serialized before the field existed must still load.
        let r = sample_report(BenchMode::Throughput);
        let mut value: serde_json::Value = serde_json::from_str(&r.to_json().unwrap()).unwrap();
        assert!(
            value
                .as_object_mut()
                .unwrap()
                .remove("competitor_comparison")
                .is_none()
        );
        let back = BenchmarkReport::from_json(&value.to_string()).unwrap();
        assert!(back.competitor_comparison.is_none());
    }

    #[test]
    fn business_markdown_renders_full_comparison_table() {
        let mut r = sample_report(BenchMode::Throughput);
        r.competitor_comparison = Some(sample_comparison());
        let md = r.to_business_markdown();
        assert!(md.contains("Competitor comparison"));
        assert!(md.contains("Fortinet FortiGate 60F"));
        assert!(md.contains("Palo Alto PA-450"));
        assert!(md.contains("-52%"));
        assert!(md.contains("not apples-to-apples"));
    }

    #[test]
    fn business_markdown_notes_absent_comparison() {
        let md = sample_report(BenchMode::Throughput).to_business_markdown();
        assert!(md.contains("No competitor comparison"));
    }

    #[test]
    fn empty_comparison_table_renders_placeholder_row() {
        let cmp = CompetitorComparison {
            sng_measured_gbps: 1.0,
            feature: "NGFW (URL filtering + app-id) throughput".to_string(),
            rows: Vec::new(),
        };
        let md = cmp.to_markdown();
        assert!(md.contains("no same-class competitor"));
    }

    /// A four-point fixture: raw-L3 on both substrates plus the two deeper
    /// XDP modes, with `pps` chosen so the anchor and ratios are tidy.
    fn fwd_report(raw_xdp_pps: f64, raw_nft_pps: f64, full_xdp_pps: f64) -> ForwardingReport {
        let m = |mode: &str, backend: &str, pps: f64| ForwardingMeasurement {
            mode: mode.to_string(),
            backend: backend.to_string(),
            packets: 10_000,
            pps,
            gbps: pps * 1500.0 * 8.0 / 1e9,
            p50_ns: 100,
            p99_ns: 200,
            cpu_headroom: 0.5,
        };
        ForwardingReport {
            schema_version: FORWARDING_SCHEMA_VERSION,
            profile: "micro".to_string(),
            unix_time_secs: 1_700_000_000,
            git_sha: Some("abc123".to_string()),
            rule_count: 128,
            packet_bytes: 1500,
            sample_packets: 10_000,
            measurements: vec![
                m("raw-l3", "xdp", raw_xdp_pps),
                m("raw-l3", "nftables", raw_nft_pps),
                m("full-stack-tls", "xdp", full_xdp_pps),
            ],
            per_class: Vec::new(),
        }
    }

    #[test]
    fn forwarding_identical_reports_have_no_regression() {
        let base = fwd_report(10e6, 2e6, 5e6);
        let cur = fwd_report(10e6, 2e6, 5e6);
        let rr = detect_forwarding_regression(&base, &cur, 0.15).unwrap();
        assert!(!rr.has_regression(), "identical reports must be clean");
    }

    #[test]
    fn forwarding_flags_inflated_inspection_cost() {
        // Baseline: full-stack runs at half the raw-L3 rate (2× cost).
        let base = fwd_report(10e6, 2e6, 5e6);
        // Current: full-stack collapses to a quarter of raw-L3 (4× cost)
        // while the anchor itself is unchanged → normalised cost doubles.
        let cur = fwd_report(10e6, 2e6, 2.5e6);
        let rr = detect_forwarding_regression(&base, &cur, 0.15).unwrap();
        assert!(rr.has_regression());
        assert!(
            rr.regressions
                .iter()
                .any(|r| r.metric.contains("full-stack-tls/xdp")),
            "the inflated full-stack point is flagged: {:?}",
            rr.regressions
        );
    }

    #[test]
    fn forwarding_is_invariant_to_uniform_hardware_slowdown() {
        // A runner that is uniformly 2× slower scales *every* pps by the
        // same factor; no normalised ratio moves, so nothing is flagged.
        let base = fwd_report(10e6, 2e6, 5e6);
        let cur = fwd_report(5e6, 1e6, 2.5e6);
        let rr = detect_forwarding_regression(&base, &cur, 0.15).unwrap();
        assert!(
            !rr.has_regression(),
            "uniform slowdown must not trip the gate: {:?}",
            rr.regressions
        );
    }

    #[test]
    fn forwarding_flags_lost_fast_path_advantage() {
        // Baseline XDP is 5× nftables on raw-L3; current is only 2×, a
        // collapse of the fast-path advantage even though absolute XDP
        // throughput and the deeper-mode ratio are unchanged.
        let base = fwd_report(10e6, 2e6, 5e6);
        let cur = fwd_report(10e6, 5e6, 5e6);
        let rr = detect_forwarding_regression(&base, &cur, 0.15).unwrap();
        assert!(rr.has_regression());
        assert!(
            rr.regressions.iter().any(|r| r.metric.contains("speedup")),
            "the lost speedup is flagged: {:?}",
            rr.regressions
        );
    }

    #[test]
    fn forwarding_rejects_mismatched_profiles() {
        let base = fwd_report(10e6, 2e6, 5e6);
        let mut cur = fwd_report(10e6, 2e6, 5e6);
        cur.profile = "large".to_string();
        assert!(detect_forwarding_regression(&base, &cur, 0.15).is_err());
    }

    #[test]
    fn forwarding_report_json_round_trips() {
        let base = fwd_report(10e6, 2e6, 5e6);
        let json = base.to_json().unwrap();
        let back = ForwardingReport::from_json(&json).unwrap();
        assert_eq!(base, back);
    }

    // --- Statistical (N-sample median + noise-band) gate ------------------

    /// A report whose only relative-cost metric (`full-stack-tls/xdp`)
    /// equals `relcost` exactly, with the raw-L3 anchors held fixed. Since
    /// `relcost = ns_per_packet(full) / ns_per_packet(raw-xdp) =
    /// pps(raw-xdp) / pps(full)`, pinning `raw_xdp_pps` and solving for
    /// `full_xdp_pps` gives a sample with a known metric value, which lets
    /// these tests drive the median/σ logic with exact numbers. The
    /// raw-L3 `xdp/nftables` speedup stays a constant 5× so it never
    /// confounds the relative-cost assertions.
    fn fwd_sample_relcost(relcost: f64) -> ForwardingReport {
        fwd_report(10e6, 2e6, 10e6 / relcost)
    }

    fn relcost_metric(rr: &StatRegressionReport) -> &StatMetric {
        rr.metrics
            .iter()
            .find(|m| m.metric.contains("full-stack-tls/xdp"))
            .expect("full-stack-tls/xdp metric is gated")
    }

    #[test]
    fn median_handles_odd_even_and_ignores_non_finite() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        // A single NaN/inf must not poison the median.
        assert_eq!(median(&[2.0, f64::NAN, 2.0, 2.0, 8.0]), Some(2.0));
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[f64::INFINITY]), None);
    }

    #[test]
    fn sample_stddev_uses_bessel_and_is_zero_below_two() {
        assert!(sample_stddev(&[]).abs() < f64::EPSILON);
        assert!(sample_stddev(&[42.0]).abs() < f64::EPSILON);
        // Corrected (n-1) stddev of {2,4,4,4,5,5,7,9} is 2.13809...
        let s = sample_stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((s - 2.138_089_9).abs() < 1e-6, "got {s}");
    }

    #[test]
    fn stats_flags_a_real_median_regression() {
        // Baseline cost ratio 2.0; every sample sits tightly around 2.5
        // (+25%), so the median clears the 15% threshold and the move
        // dwarfs the tiny noise band.
        let base = fwd_sample_relcost(2.0);
        let samples: Vec<_> = [2.48, 2.49, 2.50, 2.50, 2.50, 2.51, 2.52]
            .iter()
            .map(|&c| fwd_sample_relcost(c))
            .collect();
        let rr = detect_forwarding_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        assert!(rr.has_regression(), "a real, tight +25% shift must flag");
        let m = relcost_metric(&rr);
        assert!(m.flagged);
        assert!(m.exceeds_threshold && m.outside_noise_band);
        assert!((m.median - 2.50).abs() < 1e-9);
        assert_eq!(m.samples, 7);
    }

    #[test]
    fn stats_ignores_a_single_noisy_outlier_via_median() {
        // Six clean runs at the baseline plus one wild 2.5× cost spike.
        // The MEAN (2.43, +21%) would trip a 15% gate; the MEDIAN (2.0)
        // does not — which is the whole point of aggregating with it.
        let base = fwd_sample_relcost(2.0);
        let mut costs = vec![2.0; 6];
        costs.push(5.0);
        let samples: Vec<_> = costs.iter().map(|&c| fwd_sample_relcost(c)).collect();
        let rr = detect_forwarding_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        let m = relcost_metric(&rr);
        assert!(!m.flagged, "a lone outlier must not fail the build: {m:?}");
        assert!((m.median - 2.0).abs() < 1e-9, "median pinned at baseline");
        assert!(!rr.has_regression());
    }

    #[test]
    fn stats_does_not_flag_a_median_move_inside_the_noise_band() {
        // Median lands at 2.35 (+17.5%, past the 15% threshold) but the
        // samples are so scattered that 2σ exceeds the move — so the band
        // absorbs it and nothing is flagged.
        let base = fwd_sample_relcost(2.0);
        let samples: Vec<_> = [2.0, 2.05, 2.35, 2.35, 2.40, 2.80, 2.85]
            .iter()
            .map(|&c| fwd_sample_relcost(c))
            .collect();
        let rr = detect_forwarding_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        let m = relcost_metric(&rr);
        assert!(m.exceeds_threshold, "median did clear the threshold");
        assert!(!m.outside_noise_band, "but it sits inside the 2σ band");
        assert!(!m.flagged);
        assert!(!rr.has_regression());
    }

    #[test]
    fn stats_never_flags_an_improvement() {
        // Cost ratio dropped to 1.5 (cheaper) and the speedup rose; an
        // improvement on every axis must never be reported as a regression.
        let base = fwd_sample_relcost(2.0);
        let samples: Vec<_> = [1.48, 1.49, 1.50, 1.50, 1.51, 1.52, 1.50]
            .iter()
            .map(|&c| fwd_sample_relcost(c))
            .collect();
        let rr = detect_forwarding_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        assert!(!rr.has_regression(), "improvements never flag: {rr:?}");
        let m = relcost_metric(&rr);
        assert!(!m.exceeds_threshold && !m.flagged);
        assert!(m.change_fraction < 0.0, "the median cost actually fell");
    }

    #[test]
    fn stats_single_sample_reduces_to_threshold_gate() {
        // With one sample σ is 0 and the band vanishes, so the gate is the
        // plain threshold check: a real shift flags, a clean run does not.
        let base = fwd_sample_relcost(2.0);

        let regress = detect_forwarding_regression_stats(
            &base,
            std::slice::from_ref(&fwd_sample_relcost(2.5)),
            0.15,
            2.0,
        )
        .unwrap();
        assert!(regress.has_regression());
        assert!(relcost_metric(&regress).stddev.abs() < f64::EPSILON);

        let clean = detect_forwarding_regression_stats(
            &base,
            std::slice::from_ref(&fwd_sample_relcost(2.05)),
            0.15,
            2.0,
        )
        .unwrap();
        assert!(!clean.has_regression(), "a 2.5% move stays clean");
    }

    #[test]
    fn stats_flags_a_real_lost_fast_path_advantage() {
        // Speedup collapses from 5× to ~2× across tight samples — a real
        // fast-path regression the relative-cost axis cannot see.
        let base = fwd_report(10e6, 2e6, 5e6); // speedup 5
        let samples: Vec<_> = [4.9e6, 4.95e6, 5.0e6, 5.0e6, 5.0e6, 5.05e6, 5.1e6]
            .iter()
            .map(|&nft| fwd_report(10e6, nft, 5e6)) // speedup ~2
            .collect();
        let rr = detect_forwarding_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        assert!(rr.has_regression());
        assert!(
            rr.flagged().any(|m| m.metric.contains("speedup")),
            "the lost speedup is flagged: {rr:?}"
        );
    }

    #[test]
    fn stats_rejects_empty_samples_and_mismatches() {
        let base = fwd_sample_relcost(2.0);
        assert!(detect_forwarding_regression_stats(&base, &[], 0.15, 2.0).is_err());

        let mut wrong_profile = fwd_sample_relcost(2.0);
        wrong_profile.profile = "large".to_string();
        assert!(
            detect_forwarding_regression_stats(&base, &[wrong_profile], 0.15, 2.0).is_err(),
            "profile mismatch must error rather than silently compare"
        );

        let mut wrong_schema = fwd_sample_relcost(2.0);
        wrong_schema.schema_version = FORWARDING_SCHEMA_VERSION + 1;
        assert!(detect_forwarding_regression_stats(&base, &[wrong_schema], 0.15, 2.0).is_err());
    }

    /// A multi-queue report whose per-width scaling efficiencies are given
    /// directly, so a test can dial the scaling curve precisely. The
    /// `queues == 1` floor (efficiency `1.0`) is always prepended.
    fn mq_report(efficiencies: &[(usize, f64)]) -> MultiQueueReport {
        let point = |queues: usize, eff: f64| MultiQueueScalePoint {
            queues,
            aggregate_pps: 0.0,
            aggregate_gbps: 0.0,
            mean_pps_per_queue: 0.0,
            scaling_efficiency: eff,
            p50_ns_mean: 0,
            p99_ns_max: 0,
            streams: Vec::new(),
        };
        let mut points = vec![point(1, 1.0)];
        points.extend(efficiencies.iter().map(|&(q, e)| point(q, e)));
        MultiQueueReport {
            schema_version: MULTIQUEUE_SCHEMA_VERSION,
            profile: "micro".to_string(),
            unix_time_secs: 1_700_000_000,
            git_sha: None,
            mode: "raw-l3".to_string(),
            backend: "xdp".to_string(),
            rule_count: 64,
            packet_bytes: 64,
            packets_per_queue: 50_000,
            available_parallelism: 8,
            target_gbps: 5.0,
            points,
        }
    }

    #[test]
    fn multiqueue_gate_flags_efficiency_drop_outside_noise() {
        let base = mq_report(&[(2, 0.95), (4, 0.90), (8, 0.80)]);
        // q=8 collapses from 0.80 to 0.55 (a ~31% drop), the others hold.
        let sample = mq_report(&[(2, 0.95), (4, 0.90), (8, 0.55)]);
        let rr = detect_multiqueue_regression_stats(&base, &[sample], 0.15, 2.0).unwrap();
        assert!(
            rr.has_regression(),
            "a real scaling collapse must flag: {rr:?}"
        );
        assert!(
            rr.flagged().all(|m| m.metric.contains("q=8")),
            "only the q=8 width regressed: {rr:?}"
        );
        // The single-stream floor is never gated (no signal).
        assert!(rr.metrics.iter().all(|m| !m.metric.contains("q=1 ")));
    }

    #[test]
    fn multiqueue_gate_passes_within_threshold() {
        let base = mq_report(&[(2, 0.95), (4, 0.90), (8, 0.80)]);
        // A few percent of scatter, well inside the 15% threshold.
        let sample = mq_report(&[(2, 0.94), (4, 0.88), (8, 0.78)]);
        let rr = detect_multiqueue_regression_stats(&base, &[sample], 0.15, 2.0).unwrap();
        assert!(!rr.has_regression(), "minor scatter must not flag: {rr:?}");
    }

    #[test]
    fn multiqueue_gate_noise_band_absorbs_single_outlier() {
        let base = mq_report(&[(8, 0.80)]);
        // One wild low sample, the rest healthy: the median holds and the
        // dispersion widens the band, so the gate does not fire on noise.
        let samples = [
            mq_report(&[(8, 0.50)]),
            mq_report(&[(8, 0.80)]),
            mq_report(&[(8, 0.81)]),
            mq_report(&[(8, 0.79)]),
            mq_report(&[(8, 0.80)]),
        ];
        let rr = detect_multiqueue_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        assert!(
            !rr.has_regression(),
            "a lone outlier inside the noise band must not fail the build: {rr:?}"
        );
    }

    #[test]
    fn multiqueue_gate_rejects_empty_and_mismatched_sweeps() {
        let base = mq_report(&[(2, 0.9)]);
        assert!(detect_multiqueue_regression_stats(&base, &[], 0.15, 2.0).is_err());

        let mut wrong_mode = mq_report(&[(2, 0.9)]);
        wrong_mode.mode = "full-stack".to_string();
        assert!(
            detect_multiqueue_regression_stats(&base, &[wrong_mode], 0.15, 2.0).is_err(),
            "comparing different inspection depths must error"
        );

        let mut wrong_backend = mq_report(&[(2, 0.9)]);
        wrong_backend.backend = "nftables".to_string();
        assert!(detect_multiqueue_regression_stats(&base, &[wrong_backend], 0.15, 2.0).is_err());

        let mut wrong_schema = mq_report(&[(2, 0.9)]);
        wrong_schema.schema_version = MULTIQUEUE_SCHEMA_VERSION + 1;
        assert!(detect_multiqueue_regression_stats(&base, &[wrong_schema], 0.15, 2.0).is_err());
    }

    #[test]
    fn multiqueue_gate_sample_count_excludes_non_finite() {
        let base = mq_report(&[(8, 0.80)]);
        // Two healthy samples and one with a non-finite efficiency (which
        // the guards in multiqueue.rs prevent in practice, but the gate
        // must not count it): the reported sample count must be the finite
        // pair, not three.
        let samples = [
            mq_report(&[(8, 0.80)]),
            mq_report(&[(8, f64::NAN)]),
            mq_report(&[(8, 0.79)]),
        ];
        let rr = detect_multiqueue_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        let q8 = rr
            .metrics
            .iter()
            .find(|m| m.metric.contains("q=8"))
            .expect("q=8 width is gated");
        assert_eq!(
            q8.samples, 2,
            "non-finite sample must not inflate the count"
        );
        assert!(q8.median.is_finite());
        assert!(!rr.has_regression());
    }

    #[test]
    fn multiqueue_single_sample_wrapper_matches_threshold_only() {
        let base = mq_report(&[(4, 0.90)]);
        let regressed = mq_report(&[(4, 0.60)]);
        let rr = detect_multiqueue_regression(&base, &regressed, 0.15).unwrap();
        assert!(rr.has_regression());
        assert_eq!(rr.regressions.len(), 1);
        assert!(rr.regressions[0].metric.contains("q=4"));
    }

    fn wire_report(transport: &str, points: &[(usize, f64, f64, f64)]) -> WireScalingReport {
        WireScalingReport {
            schema_version: WIRE_SCALING_SCHEMA_VERSION,
            profile: "micro".to_string(),
            unix_time_secs: 0,
            git_sha: None,
            transport: transport.to_string(),
            interface: "lo".to_string(),
            frame_bytes: 1500,
            ip_version: "v4".to_string(),
            l4: "udp".to_string(),
            duration_ms: 1000,
            available_parallelism: 8,
            target_gbps: 0.8,
            points: points
                .iter()
                .map(|&(queues, agg_pps, agg_gbps, eff)| WireScalePoint {
                    queues,
                    aggregate_pps: agg_pps,
                    aggregate_gbps: agg_gbps,
                    mean_gbps_per_queue: agg_gbps / queues as f64,
                    scaling_efficiency: eff,
                    streams: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn wire_scaling_json_roundtrips() {
        let r = wire_report("af-packet", &[(1, 1e5, 0.37, 1.0), (8, 4.5e5, 1.64, 0.56)]);
        let json = r.to_json().unwrap();
        let back = WireScalingReport::from_json(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn wire_scaling_floor_and_ceiling_resolve_by_value() {
        // Out-of-order points: floor/ceiling must key on queue count, not
        // position.
        let r = wire_report("af-packet", &[(8, 4.5e5, 1.64, 0.56), (1, 1e5, 0.37, 1.0)]);
        assert_eq!(r.single_stream().unwrap().queues, 1);
        assert_eq!(r.ceiling().unwrap().queues, 8);
    }

    #[test]
    fn wire_scaling_markdown_headlines_lift_and_keeps_wire_caveat() {
        let md =
            wire_report("af-packet", &[(1, 1e5, 0.40, 1.0), (8, 4.5e5, 1.60, 0.56)]).to_markdown();
        // Floor→ceiling lift is 1.60 / 0.40 = 4.00×.
        assert!(
            md.contains("4.00×"),
            "markdown must headline the lift: {md}"
        );
        assert!(
            md.contains("AF_PACKET"),
            "wire run must keep the wire caveat"
        );
        assert!(
            !md.contains("craft-only"),
            "wire run must not show the dry-run caveat"
        );
        // The run's flow shape is self-describing in the metadata line.
        assert!(
            md.contains("v4 udp"),
            "markdown must record ip version + l4: {md}"
        );
    }

    #[test]
    fn wire_scaling_metadata_roundtrips_ip_version_and_l4() {
        let r = wire_report("af-packet", &[(1, 1e5, 0.37, 1.0)]);
        let back = WireScalingReport::from_json(&r.to_json().unwrap()).unwrap();
        assert_eq!(back.ip_version, "v4");
        assert_eq!(back.l4, "udp");
    }

    #[test]
    fn wire_scaling_markdown_marks_dry_run_as_craft_only() {
        let md = wire_report("dry-run", &[(1, 1e5, 0.40, 1.0), (4, 3e5, 1.19, 0.75)]).to_markdown();
        assert!(
            md.contains("craft-only"),
            "dry-run must flag the craft-only ceiling: {md}"
        );
        assert!(
            !md.contains("really crafted and pushed"),
            "dry-run must not claim a wire number"
        );
    }

    #[test]
    fn wire_scaling_gate_flags_real_efficiency_collapse() {
        // Baseline: efficiency holds at 0.90/0.80 across 2/4 streams.
        let base = wire_report(
            "af-packet",
            &[
                (1, 1e5, 0.37, 1.0),
                (2, 2e5, 0.66, 0.90),
                (4, 3.5e5, 1.18, 0.80),
            ],
        );
        // Current: q=4 collapses 0.80 -> 0.50 (~38% drop); q=2 holds.
        let sample = wire_report(
            "af-packet",
            &[
                (1, 1e5, 0.37, 1.0),
                (2, 2e5, 0.66, 0.90),
                (4, 2.4e5, 0.74, 0.50),
            ],
        );
        let rr = detect_wire_scaling_regression_stats(&base, &[sample], 0.15, 2.0).unwrap();
        assert!(
            rr.has_regression(),
            "a real scaling collapse must flag: {rr:?}"
        );
        let q4 = rr
            .metrics
            .iter()
            .find(|m| m.metric.contains("q=4"))
            .unwrap();
        assert!(q4.flagged, "q=4 must be the flagged width: {q4:?}");
    }

    #[test]
    fn wire_scaling_gate_ignores_minor_scatter() {
        let base = wire_report(
            "af-packet",
            &[
                (1, 1e5, 0.37, 1.0),
                (2, 2e5, 0.66, 0.90),
                (4, 3.5e5, 1.18, 0.80),
            ],
        );
        // A few percent of scatter, well inside the 15% threshold.
        let sample = wire_report(
            "af-packet",
            &[
                (1, 1e5, 0.37, 1.0),
                (2, 2e5, 0.65, 0.88),
                (4, 3.5e5, 1.15, 0.78),
            ],
        );
        let rr = detect_wire_scaling_regression_stats(&base, &[sample], 0.15, 2.0).unwrap();
        assert!(!rr.has_regression(), "minor scatter must not flag: {rr:?}");
    }

    #[test]
    fn wire_scaling_gate_rejects_empty_and_mismatched_sweeps() {
        let base = wire_report("af-packet", &[(1, 1e5, 0.37, 1.0), (2, 2e5, 0.66, 0.90)]);
        assert!(detect_wire_scaling_regression_stats(&base, &[], 0.15, 2.0).is_err());

        // A dry-run craft ceiling must never be gated against a live wire curve.
        let dry = wire_report("dry-run", &[(1, 1e5, 0.37, 1.0), (2, 2e5, 0.66, 0.90)]);
        assert!(
            detect_wire_scaling_regression_stats(&base, &[dry], 0.15, 2.0).is_err(),
            "comparing dry-run vs af-packet must error"
        );

        let mut wrong_ipv = wire_report("af-packet", &[(2, 2e5, 0.66, 0.90)]);
        wrong_ipv.ip_version = "v6".to_string();
        assert!(detect_wire_scaling_regression_stats(&base, &[wrong_ipv], 0.15, 2.0).is_err());

        let mut wrong_l4 = wire_report("af-packet", &[(2, 2e5, 0.66, 0.90)]);
        wrong_l4.l4 = "tcp-syn".to_string();
        assert!(detect_wire_scaling_regression_stats(&base, &[wrong_l4], 0.15, 2.0).is_err());

        let mut wrong_frame = wire_report("af-packet", &[(2, 2e5, 0.66, 0.90)]);
        wrong_frame.frame_bytes = 64;
        assert!(detect_wire_scaling_regression_stats(&base, &[wrong_frame], 0.15, 2.0).is_err());

        let mut wrong_schema = wire_report("af-packet", &[(2, 2e5, 0.66, 0.90)]);
        wrong_schema.schema_version = WIRE_SCALING_SCHEMA_VERSION + 1;
        assert!(detect_wire_scaling_regression_stats(&base, &[wrong_schema], 0.15, 2.0).is_err());
    }

    #[test]
    fn wire_scaling_gate_single_noisy_sample_within_band_does_not_flag() {
        let base = wire_report("af-packet", &[(1, 1e5, 0.37, 1.0), (4, 3.5e5, 1.18, 0.80)]);
        // Several samples scattering around 0.79; median move tiny, σ small.
        let samples = [
            wire_report("af-packet", &[(4, 3.5e5, 1.18, 0.81)]),
            wire_report("af-packet", &[(4, 3.5e5, 1.18, 0.78)]),
            wire_report("af-packet", &[(4, 3.5e5, 1.18, 0.80)]),
        ];
        let rr = detect_wire_scaling_regression_stats(&base, &samples, 0.15, 2.0).unwrap();
        assert!(
            !rr.has_regression(),
            "scatter across samples must not flag: {rr:?}"
        );
    }
}
