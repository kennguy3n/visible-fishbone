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

/// Compare a current forwarding sweep against a committed baseline and
/// flag regressions.
///
/// The gate is **hardware-invariant**: it never compares two absolute
/// throughput numbers (which drift with the runner), only dimensionless
/// ratios that hold across machines:
///
///   1. *Per-mode inspection cost*, normalised to the raw-L3 fast path:
///      `ns_per_packet(mode, backend) / ns_per_packet(raw-l3, xdp)`. A
///      rise beyond `threshold` means a stage (NGFW, IPS, TLS, ...) got
///      disproportionately more expensive — i.e. forwarding throughput at
///      that depth regressed relative to the line-rate fast path.
///   2. *Fast-path advantage*: the raw-L3 XDP-over-nftables speedup
///      `pps(raw-l3, xdp) / pps(raw-l3, nftables)`. A drop beyond
///      `threshold` means the XDP fast path lost ground against the
///      engine — the one regression a relative-cost check anchored on the
///      fast path cannot see on its own.
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
    if baseline.schema_version != current.schema_version {
        return Err(format!(
            "forwarding schema version mismatch: baseline {} vs current {}",
            baseline.schema_version, current.schema_version
        ));
    }
    if baseline.profile != current.profile {
        return Err(format!(
            "cannot compare different profiles: baseline {:?} vs current {:?}",
            baseline.profile, current.profile
        ));
    }

    let anchor = |r: &ForwardingReport| -> Result<f64, String> {
        let m = r
            .get(RAW_L3_LABEL, XDP_LABEL)
            .ok_or_else(|| "report missing (raw-l3, xdp) anchor measurement".to_string())?;
        let nspp = m.ns_per_packet();
        if nspp.is_finite() && nspp > 0.0 {
            Ok(nspp)
        } else {
            Err("(raw-l3, xdp) anchor has non-positive throughput".to_string())
        }
    };
    let base_anchor = anchor(baseline)?;
    let cur_anchor = anchor(current)?;

    let mut regressions = Vec::new();

    // (1) Per-mode normalised inspection cost.
    for cur in &current.measurements {
        if cur.mode == RAW_L3_LABEL && cur.backend == XDP_LABEL {
            continue; // the anchor itself
        }
        let Some(base) = baseline.get(&cur.mode, &cur.backend) else {
            continue; // a point absent from the baseline can't regress
        };
        let base_rel = base.ns_per_packet() / base_anchor;
        let cur_rel = cur.ns_per_packet() / cur_anchor;
        // A *rise* in normalised per-packet cost is the regression.
        if let Some(change) = fractional_change(base_rel, cur_rel)
            && change >= threshold
        {
            regressions.push(Regression {
                metric: format!("{}/{} relative-cost", cur.mode, cur.backend),
                previous: base_rel,
                current: cur_rel,
                change_fraction: change,
            });
        }
    }

    // (2) Raw-L3 fast-path advantage (XDP over nftables).
    if let (Some(base_xdp), Some(base_nft), Some(cur_xdp), Some(cur_nft)) = (
        baseline.get(RAW_L3_LABEL, XDP_LABEL),
        baseline.get(RAW_L3_LABEL, NFTABLES_LABEL),
        current.get(RAW_L3_LABEL, XDP_LABEL),
        current.get(RAW_L3_LABEL, NFTABLES_LABEL),
    ) && let (Some(base_speedup), Some(cur_speedup)) = (
        ratio(base_xdp.pps, base_nft.pps),
        ratio(cur_xdp.pps, cur_nft.pps),
    ) && let Some(change) = fractional_change(base_speedup, cur_speedup)
        && change <= -threshold
    {
        regressions.push(Regression {
            metric: "raw-l3 xdp-over-nftables speedup".to_string(),
            previous: base_speedup,
            current: cur_speedup,
            change_fraction: change,
        });
    }

    Ok(RegressionReport { regressions })
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
}
