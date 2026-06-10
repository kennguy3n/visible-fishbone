//! Aggregation of many per-run [`BenchmarkReport`]s into one consolidated
//! business document — the artifact the `business-report` subcommand
//! emits for an RFP-response datasheet.
//!
//! A [`BusinessReport`] groups reports by edge SKU and renders, per SKU, a
//! throughput matrix (packet size × inspection depth), a latency
//! percentile table, and resource utilisation at each operating point;
//! then a competitor comparison and a cost analysis across SKUs. Like the
//! rest of the harness this is a pure transform over plain data, so the
//! whole document is unit-tested without a socket or `/proc`.
//!
//! Honesty posture: every competitor figure is purpose-built
//! hardware/ASIC; SNG is software-only on a generic x86 VM. The competitor
//! section carries that caveat on every row (see [`crate::competitor`]) and
//! the cost section states its cloud-pricing assumptions rather than
//! inventing appliance list prices.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sng_fw::TrafficClass;

use crate::competitor::{self, InspectionDepth};
use crate::report::{BenchMode, BenchmarkReport, ReportError};

/// Per-edge-SKU profile, loaded from `bench/profiles/*.toml`.
///
/// This is the single source of truth for the profile schema, shared by
/// the live measurement subcommands and the business report (which needs
/// `vcpus`/`ram_gb`/`nic_gbps` for the competitor class match and the cost
/// model — fields the per-run path does not otherwise read).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkuProfile {
    /// Profile name (`branch-small`, `cloud-pop-small`, ...).
    pub name: String,
    /// Reference vCPU count — also the competitor hardware-class key.
    pub vcpus: u32,
    /// Reference RAM in GiB.
    pub ram_gb: u32,
    /// Reference NIC line rate in Gbps.
    pub nic_gbps: f64,
    /// Published acceptance target throughput in Gbps.
    pub target_gbps: f64,
    /// Number of NIC receive queues (RSS rings) the SKU pins. `None`
    /// means "one queue per vCPU" — the default the datapath sweep
    /// assumes. Recorded so a published throughput number names the
    /// fan-out it was measured at and a re-run is reproducible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_queues: Option<u32>,
    /// Reproducible datapath forwarding-benchmark parameters: the
    /// synthetic rule count, representative frame size, and per-loop
    /// sample size this SKU drives. Defaults ([`DatapathParams::default`])
    /// keep the existing profiles valid without a `[datapath]` table.
    #[serde(default)]
    pub datapath: DatapathParams,
    /// The per-traffic-class weighting used to compose the forwarding
    /// sweep's packet stream for this SKU. Defaults to an enterprise-
    /// representative mix ([`TrafficMix::default`]) so the existing
    /// profiles remain valid without a `[traffic_mix]` table.
    #[serde(default)]
    pub traffic_mix: TrafficMix,
}

impl SkuProfile {
    /// NIC receive-queue count the SKU is benchmarked at: the pinned
    /// [`Self::nic_queues`] when set, otherwise one queue per vCPU (the
    /// RSS default a stock multi-queue NIC programs).
    #[must_use]
    pub fn effective_nic_queues(&self) -> u32 {
        self.nic_queues.unwrap_or(self.vcpus).max(1)
    }
}

/// Reproducible parameters for the in-process datapath forwarding
/// benchmark, pinned per SKU so two runs of the same profile drive the
/// identical synthetic workload.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DatapathParams {
    /// Number of L3/L4 policy rules in the synthetic ruleset the
    /// forwarding decision walks.
    pub rule_count: usize,
    /// Representative on-wire frame size in bytes. Converts a measured
    /// packets-per-second figure into the bits-per-second (Gbps) the
    /// published table quotes.
    pub packet_bytes: u32,
    /// Packets evaluated per `(mode, backend)` measurement loop. Larger
    /// SKUs use a larger sample so the per-packet timing is stable.
    pub sample_packets: usize,
}

impl Default for DatapathParams {
    fn default() -> Self {
        // A mid-complexity ruleset, a standard 1500-byte MTU frame, and a
        // sample large enough to time stably on a hosted runner without
        // making the dry-run sweep slow.
        Self {
            rule_count: 256,
            packet_bytes: 1500,
            sample_packets: 200_000,
        }
    }
}

/// Relative weighting of the six steering tiers
/// (`sng_fw::TrafficClass`) in a SKU's representative traffic. Weights
/// are relative — they need not sum to 1.0; the harness normalises them.
/// Every tier is named explicitly so the mix is auditable and a run is
/// reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficMix {
    /// `trusted_direct` — DNS + cert-pinned, no proxy, no decrypt.
    pub trusted_direct: f64,
    /// `trusted_media_bypass` — trusted, telemetry-sampled media.
    pub trusted_media_bypass: f64,
    /// `inspect_lite` — DNS + URL-category, no TLS decrypt.
    pub inspect_lite: f64,
    /// `inspect_full` — full SWG with TLS decrypt, AV, IPS, DLP.
    pub inspect_full: f64,
    /// `tunnel_private` — mTLS overlay to a tenant-private destination.
    pub tunnel_private: f64,
    /// `block` — refused at the earliest enforcement point.
    pub block: f64,
}

impl Default for TrafficMix {
    fn default() -> Self {
        // An enterprise-representative SME mix: most bytes are trusted
        // SaaS / media that ride the fast path, a meaningful slice needs
        // full inspection, a little is ZTNA-tunnelled, and a small tail
        // is blocked outright. Relative weights (sum = 100) for legible
        // TOML.
        Self {
            trusted_direct: 35.0,
            trusted_media_bypass: 20.0,
            inspect_lite: 15.0,
            inspect_full: 22.0,
            tunnel_private: 5.0,
            block: 3.0,
        }
    }
}

impl TrafficMix {
    /// The raw (un-normalised) weight configured for a class. Clamped at
    /// zero so a negative TOML value cannot make a class "subtract" from
    /// the stream.
    #[must_use]
    pub fn weight(&self, class: TrafficClass) -> f64 {
        let w = match class {
            TrafficClass::TrustedDirect => self.trusted_direct,
            TrafficClass::TrustedMediaBypass => self.trusted_media_bypass,
            TrafficClass::InspectLite => self.inspect_lite,
            TrafficClass::InspectFull => self.inspect_full,
            TrafficClass::TunnelPrivate => self.tunnel_private,
            TrafficClass::Block => self.block,
        };
        w.max(0.0)
    }

    /// Sum of every class weight.
    #[must_use]
    pub fn total_weight(&self) -> f64 {
        TrafficClass::all()
            .into_iter()
            .map(|c| self.weight(c))
            .sum()
    }

    /// The mix as normalised fractions in canonical [`TrafficClass::all`]
    /// order, each in `0.0..=1.0` and summing to 1.0. A degenerate
    /// all-zero mix falls back to a uniform split so the harness never
    /// divides by zero or produces an empty stream.
    #[must_use]
    pub fn normalized(&self) -> [(TrafficClass, f64); 6] {
        let total = self.total_weight();
        let classes = TrafficClass::all();
        if total <= 0.0 {
            let uniform = 1.0 / classes.len() as f64;
            return classes.map(|c| (c, uniform));
        }
        classes.map(|c| (c, self.weight(c) / total))
    }
}

/// One SKU's profile paired with every report measured against it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusinessSku {
    /// The SKU profile.
    pub profile: SkuProfile,
    /// All `(mode, dimensions)` reports collected for this SKU.
    pub reports: Vec<BenchmarkReport>,
}

impl BusinessSku {
    /// Pair a profile with its reports.
    #[must_use]
    pub fn new(profile: SkuProfile, reports: Vec<BenchmarkReport>) -> Self {
        Self { profile, reports }
    }

    /// The throughput report at one operating point, if measured.
    fn throughput_at(&self, packet_size: u32, depth: InspectionDepth) -> Option<&BenchmarkReport> {
        self.report_at(BenchMode::Throughput, packet_size, depth)
    }

    fn report_at(
        &self,
        mode: BenchMode,
        packet_size: u32,
        depth: InspectionDepth,
    ) -> Option<&BenchmarkReport> {
        self.reports.iter().find(|r| {
            r.mode == mode
                && r.dimensions.packet_size == packet_size
                && r.dimensions.inspection == depth.label()
        })
    }

    /// Packet sizes present in `mode`'s reports, ascending.
    ///
    /// Scoped to the mode so each rendered table enumerates exactly the
    /// operating points it has data for — the throughput matrix and the
    /// latency table can legitimately cover different sizes.
    fn packet_sizes_for(&self, mode: BenchMode) -> Vec<u32> {
        self.reports
            .iter()
            .filter(|r| r.mode == mode)
            .map(|r| r.dimensions.packet_size)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Inspection depths present in `mode`'s reports, in canonical
    /// (cost-ascending) order.
    fn depths_for(&self, mode: BenchMode) -> Vec<InspectionDepth> {
        InspectionDepth::ALL
            .into_iter()
            .filter(|d| {
                self.reports
                    .iter()
                    .any(|r| r.mode == mode && r.dimensions.inspection == d.label())
            })
            .collect()
    }

    /// Best measured throughput (Gbps) at `depth` across packet sizes.
    fn peak_throughput(&self, depth: InspectionDepth) -> Option<f64> {
        self.reports
            .iter()
            .filter(|r| r.mode == BenchMode::Throughput && r.dimensions.inspection == depth.label())
            .filter_map(|r| r.throughput.as_ref().map(|t| t.max_gbps))
            .fold(None, |acc, g| Some(acc.map_or(g, |m: f64| m.max(g))))
    }
}

/// A consolidated, multi-SKU business report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusinessReport {
    /// Generation time, Unix epoch seconds.
    pub generated_unix_secs: u64,
    /// Git commit the underlying runs were built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// One entry per edge SKU.
    pub skus: Vec<BusinessSku>,
}

/// Representative public-cloud on-demand price per vCPU-hour (USD).
///
/// An assumption, not a quote: roughly an AWS general-purpose (c/m-series)
/// on-demand vCPU in us-east-1. The cost section states this inline.
const VCPU_HOUR_USD: f64 = 0.0416;
/// Hours per 30-day month, for monthly cost projection.
const HOURS_PER_MONTH: f64 = 730.0;

impl BusinessReport {
    /// Assemble from per-SKU groups.
    #[must_use]
    pub fn new(generated_unix_secs: u64, git_sha: Option<String>, skus: Vec<BusinessSku>) -> Self {
        Self {
            generated_unix_secs,
            git_sha,
            skus,
        }
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on serialization failure.
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on parse failure.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Render the full RFP-datasheet markdown document.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::with_capacity(4096);
        let _ = writeln!(out, "# ShieldNet Gateway — edge performance datasheet");
        let _ = writeln!(out);
        let _ = write!(out, "_Generated (unix): `{}`", self.generated_unix_secs);
        if let Some(sha) = &self.git_sha {
            let _ = write!(out, " · commit `{sha}`");
        }
        let _ = writeln!(
            out,
            " · all SNG figures measured by the `sng-bench` harness._"
        );
        let _ = writeln!(out);

        self.write_executive_summary(&mut out);
        self.write_per_sku_detail(&mut out);
        self.write_competitor_comparison(&mut out);
        self.write_cost_analysis(&mut out);
        out
    }

    fn write_executive_summary(&self, out: &mut String) {
        let _ = writeln!(out, "## Executive summary");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| SKU | vCPU | RAM | NIC | target | firewall (no-inspect) | inspected (full-tls) | meets target |"
        );
        let _ = writeln!(
            out,
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |"
        );
        for sku in &self.skus {
            let p = &sku.profile;
            let no_inspect = sku.peak_throughput(InspectionDepth::NoInspect);
            let full_tls = sku.peak_throughput(InspectionDepth::FullTls);
            // "meets target" is measured against the no-inspect peak, which
            // is the figure the profile target is stated for.
            let meets = match no_inspect {
                Some(g) if g >= p.target_gbps => "yes",
                Some(_) => "no",
                None => "—",
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} GB | {:.0} Gbps | {:.2} Gbps | {} | {} | {} |",
                p.name,
                p.vcpus,
                p.ram_gb,
                p.nic_gbps,
                p.target_gbps,
                fmt_gbps(no_inspect),
                fmt_gbps(full_tls),
                meets,
            );
        }
        let _ = writeln!(out);
    }

    fn write_per_sku_detail(&self, out: &mut String) {
        let _ = writeln!(out, "## Per-SKU detail");
        let _ = writeln!(out);
        for sku in &self.skus {
            let p = &sku.profile;
            let _ = writeln!(
                out,
                "### {} ({} vCPU / {} GB, {:.0} Gbps NIC)",
                p.name, p.vcpus, p.ram_gb, p.nic_gbps
            );
            let _ = writeln!(out);
            write_throughput_matrix(out, sku);
            write_latency_table(out, sku);
            write_resource_table(out, sku);
        }
    }

    fn write_competitor_comparison(&self, out: &mut String) {
        let _ = writeln!(out, "## Competitor comparison");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Competitor figures are vendor-published throughput for purpose-built \
             hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The \
             comparison is informative, **not** apples-to-apples. SNG numbers are the \
             measured 1500B peak at each inspection depth."
        );
        let _ = writeln!(out);
        for sku in &self.skus {
            let _ = writeln!(
                out,
                "### {} (vs {}-core class)",
                sku.profile.name, sku.profile.vcpus
            );
            let _ = writeln!(out);
            let appliances = competitor::appliances_for_cores(sku.profile.vcpus);
            if appliances.is_empty() {
                let _ = writeln!(
                    out,
                    "_No competitor appliance is catalogued for the {}-core class._\n",
                    sku.profile.vcpus
                );
                continue;
            }
            // SNG measured at 1500B per depth (datasheet frame size).
            let _ = writeln!(
                out,
                "| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |"
            );
            let _ = writeln!(out, "| --- | ---: | ---: | ---: | --- |");
            let _ = writeln!(
                out,
                "| **SNG {}** (measured) | {} | {} | {} | sng-bench |",
                sku.profile.name,
                fmt_gbps(sng_1500(sku, InspectionDepth::NoInspect)),
                fmt_gbps(sng_1500(sku, InspectionDepth::UrlCat)),
                fmt_gbps(sng_1500(sku, InspectionDepth::FullTls)),
            );
            for a in &appliances {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    a.display_name(),
                    fmt_gbps(a.published_for(InspectionDepth::NoInspect)),
                    fmt_gbps(a.published_for(InspectionDepth::UrlCat)),
                    fmt_gbps(a.published_for(InspectionDepth::FullTls)),
                    a.source,
                );
            }
            let _ = writeln!(out);
            // Per-depth verdicts (with the hardware-vs-software caveat).
            for depth in InspectionDepth::ALL {
                if let Some(measured) = sng_1500(sku, depth) {
                    let cmp = competitor::comparison_for(sku.profile.vcpus, depth, measured);
                    for row in &cmp.rows {
                        let _ = writeln!(out, "- {}", row.verdict);
                    }
                }
            }
            let _ = writeln!(out);
        }
    }

    fn write_cost_analysis(&self, out: &mut String) {
        let _ = writeln!(out, "## Cost analysis");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "SNG cloud opex, assuming **${VCPU_HOUR_USD:.4}/vCPU-hour** (representative \
             public-cloud general-purpose on-demand, us-east-1) over **{HOURS_PER_MONTH:.0} \
             hours/month**. $/Gbps uses the measured peak at each depth. Appliance capex / \
             support TCO is vendor-quote territory and intentionally **not** invented here."
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| SKU | vCPU | est. $/mo | firewall Gbps | $/Gbps (firewall) | full-tls Gbps | $/Gbps (full-tls) |"
        );
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
        for sku in &self.skus {
            let monthly = f64::from(sku.profile.vcpus) * VCPU_HOUR_USD * HOURS_PER_MONTH;
            let no_inspect = sku.peak_throughput(InspectionDepth::NoInspect);
            let full_tls = sku.peak_throughput(InspectionDepth::FullTls);
            let _ = writeln!(
                out,
                "| {} | {} | ${:.0} | {} | {} | {} | {} |",
                sku.profile.name,
                sku.profile.vcpus,
                monthly,
                fmt_gbps(no_inspect),
                fmt_cost_per_gbps(monthly, no_inspect),
                fmt_gbps(full_tls),
                fmt_cost_per_gbps(monthly, full_tls),
            );
        }
        let _ = writeln!(out);
    }
}

/// SNG measured throughput (Gbps) at 1500B for `depth`, the datasheet
/// frame size the competitor figures are quoted at.
fn sng_1500(sku: &BusinessSku, depth: InspectionDepth) -> Option<f64> {
    sku.throughput_at(1500, depth)
        .and_then(|r| r.throughput.as_ref())
        .map(|t| t.max_gbps)
}

/// A datasheet that pairs an in-process **dry-run** sweep with a real
/// **wire** (AF_PACKET, edge in-path) sweep so every throughput figure
/// carries both numbers side by side.
///
/// The dry-run sweep upper-bounds the harness's craft+measure+report
/// pipeline with no NIC in the loop; the wire sweep is the real line-rate
/// an `sng-edge` rig sustains. Keeping both in one artifact lets a reader
/// see the gap between the synthetic ceiling and the measured floor without
/// cross-referencing two documents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DualDatasheet {
    /// In-process (`--dry-run`) sweep.
    pub dry_run: BusinessReport,
    /// Real-wire (AF_PACKET, edge in-path) sweep.
    pub wire: BusinessReport,
}

impl DualDatasheet {
    /// Pair a dry-run report with a wire report.
    #[must_use]
    pub fn new(dry_run: BusinessReport, wire: BusinessReport) -> Self {
        Self { dry_run, wire }
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on serialization failure.
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Propagates a [`ReportError::Json`] on parse failure.
    pub fn from_json(s: &str) -> Result<Self, ReportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Render the full dual-column RFP datasheet markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::with_capacity(8192);
        let _ = writeln!(out, "# ShieldNet Gateway — edge performance datasheet");
        let _ = writeln!(out);
        let _ = write!(
            out,
            "_Generated (unix): `{}`",
            self.wire.generated_unix_secs
        );
        if let Some(sha) = self.wire.git_sha.as_ref().or(self.dry_run.git_sha.as_ref()) {
            let _ = write!(out, " · commit `{sha}`");
        }
        let _ = writeln!(
            out,
            " · all SNG figures measured by the `sng-bench` harness._"
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Every throughput figure is reported in two columns:\n\n\
             - **dry-run** — the in-process craft+measure+report pipeline with no \
             NIC in the loop (the synthetic ceiling; runs on any CI runner).\n\
             - **wire** — real `AF_PACKET` frames transmitted over a veth pair with \
             `sng-edge` enforcing in-path under `CAP_NET_RAW` on the self-hosted \
             `sng-bench-wire` runner (the measured line-rate floor).\n"
        );
        let _ = writeln!(out);

        self.write_dual_executive_summary(&mut out);
        self.write_dual_per_sku_detail(&mut out);
        self.write_dual_competitor_comparison(&mut out);
        self.write_dual_cost_analysis(&mut out);
        out
    }

    /// Wire SKU paired to a dry-run SKU by profile name, if present.
    fn wire_sku(&self, name: &str) -> Option<&BusinessSku> {
        self.wire.skus.iter().find(|s| s.profile.name == name)
    }

    fn write_dual_executive_summary(&self, out: &mut String) {
        let _ = writeln!(out, "## Executive summary");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| SKU | vCPU | RAM | NIC | target | firewall dry-run | firewall wire | inspected dry-run | inspected wire | meets target (wire) |"
        );
        let _ = writeln!(
            out,
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |"
        );
        for sku in &self.dry_run.skus {
            let p = &sku.profile;
            let wire = self.wire_sku(&p.name);
            let dry_fw = sku.peak_throughput(InspectionDepth::NoInspect);
            let dry_tls = sku.peak_throughput(InspectionDepth::FullTls);
            let wire_fw = wire.and_then(|w| w.peak_throughput(InspectionDepth::NoInspect));
            let wire_tls = wire.and_then(|w| w.peak_throughput(InspectionDepth::FullTls));
            // "meets target" is judged on the real wire firewall peak when we
            // have one — the wire number is the figure an operator can rely
            // on — falling back to dry-run only if no wire sweep ran.
            let judged = wire_fw.or(dry_fw);
            let meets = match judged {
                Some(g) if g >= p.target_gbps => "yes",
                Some(_) => "no",
                None => "—",
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} GB | {:.0} Gbps | {:.2} Gbps | {} | {} | {} | {} | {} |",
                p.name,
                p.vcpus,
                p.ram_gb,
                p.nic_gbps,
                p.target_gbps,
                fmt_gbps(dry_fw),
                fmt_gbps(wire_fw),
                fmt_gbps(dry_tls),
                fmt_gbps(wire_tls),
                meets,
            );
        }
        let _ = writeln!(out);
    }

    fn write_dual_per_sku_detail(&self, out: &mut String) {
        let _ = writeln!(out, "## Per-SKU detail");
        let _ = writeln!(out);
        for sku in &self.dry_run.skus {
            let p = &sku.profile;
            let _ = writeln!(
                out,
                "### {} ({} vCPU / {} GB, {:.0} Gbps NIC)",
                p.name, p.vcpus, p.ram_gb, p.nic_gbps
            );
            let _ = writeln!(out);
            write_dual_throughput_matrix(out, sku, self.wire_sku(&p.name));
            // Latency and resource detail come from the dry-run pass: they
            // characterise the harness/datapath cost model and are frame-size
            // driven, independent of whether a NIC is in the loop.
            write_latency_table(out, sku);
            write_resource_table(out, sku);
        }
    }

    fn write_dual_competitor_comparison(&self, out: &mut String) {
        let _ = writeln!(out, "## Competitor comparison");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Competitor figures are vendor-published throughput for purpose-built \
             hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The \
             comparison is informative, **not** apples-to-apples. SNG numbers are the \
             measured 1500B peak at each inspection depth, shown for both the dry-run \
             ceiling and the real-wire floor."
        );
        let _ = writeln!(out);
        for sku in &self.dry_run.skus {
            let _ = writeln!(
                out,
                "### {} (vs {}-core class)",
                sku.profile.name, sku.profile.vcpus
            );
            let _ = writeln!(out);
            let appliances = competitor::appliances_for_cores(sku.profile.vcpus);
            if appliances.is_empty() {
                let _ = writeln!(
                    out,
                    "_No competitor appliance is catalogued for the {}-core class._\n",
                    sku.profile.vcpus
                );
                continue;
            }
            let wire = self.wire_sku(&sku.profile.name);
            let _ = writeln!(
                out,
                "| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |"
            );
            let _ = writeln!(out, "| --- | ---: | ---: | ---: | --- |");
            let _ = writeln!(
                out,
                "| **SNG {}** (dry-run) | {} | {} | {} | sng-bench |",
                sku.profile.name,
                fmt_gbps(sng_1500(sku, InspectionDepth::NoInspect)),
                fmt_gbps(sng_1500(sku, InspectionDepth::UrlCat)),
                fmt_gbps(sng_1500(sku, InspectionDepth::FullTls)),
            );
            if let Some(w) = wire {
                let _ = writeln!(
                    out,
                    "| **SNG {}** (wire) | {} | {} | {} | sng-bench |",
                    sku.profile.name,
                    fmt_gbps(sng_1500(w, InspectionDepth::NoInspect)),
                    fmt_gbps(sng_1500(w, InspectionDepth::UrlCat)),
                    fmt_gbps(sng_1500(w, InspectionDepth::FullTls)),
                );
            }
            for a in &appliances {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    a.display_name(),
                    fmt_gbps(a.published_for(InspectionDepth::NoInspect)),
                    fmt_gbps(a.published_for(InspectionDepth::UrlCat)),
                    fmt_gbps(a.published_for(InspectionDepth::FullTls)),
                    a.source,
                );
            }
            let _ = writeln!(out);
            // Per-depth verdicts use the real-wire number when available
            // (the honest basis for a competitive claim), else dry-run.
            let basis = wire.unwrap_or(sku);
            for depth in InspectionDepth::ALL {
                if let Some(measured) = sng_1500(basis, depth) {
                    let cmp = competitor::comparison_for(sku.profile.vcpus, depth, measured);
                    for row in &cmp.rows {
                        let _ = writeln!(out, "- {}", row.verdict);
                    }
                }
            }
            let _ = writeln!(out);
        }
    }

    fn write_dual_cost_analysis(&self, out: &mut String) {
        let _ = writeln!(out, "## Cost analysis");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "SNG cloud opex, assuming **${VCPU_HOUR_USD:.4}/vCPU-hour** (representative \
             public-cloud general-purpose on-demand, us-east-1) over **{HOURS_PER_MONTH:.0} \
             hours/month**. $/Gbps uses the **real-wire** firewall peak (the number an \
             operator actually provisions against); the dry-run $/Gbps is shown alongside \
             as the synthetic floor on cost. Appliance capex / support TCO is vendor-quote \
             territory and intentionally **not** invented here."
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| SKU | vCPU | est. $/mo | firewall wire Gbps | $/Gbps (wire) | firewall dry-run Gbps | $/Gbps (dry-run) |"
        );
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
        for sku in &self.dry_run.skus {
            let monthly = f64::from(sku.profile.vcpus) * VCPU_HOUR_USD * HOURS_PER_MONTH;
            let dry_fw = sku.peak_throughput(InspectionDepth::NoInspect);
            let wire_fw = self
                .wire_sku(&sku.profile.name)
                .and_then(|w| w.peak_throughput(InspectionDepth::NoInspect));
            let _ = writeln!(
                out,
                "| {} | {} | ${:.0} | {} | {} | {} | {} |",
                sku.profile.name,
                sku.profile.vcpus,
                monthly,
                fmt_gbps(wire_fw),
                fmt_cost_per_gbps(monthly, wire_fw),
                fmt_gbps(dry_fw),
                fmt_cost_per_gbps(monthly, dry_fw),
            );
        }
        let _ = writeln!(out);
    }
}

/// Render a throughput matrix whose cells carry both the dry-run and the
/// wire Gbps for every (packet size × inspection depth) operating point.
fn write_dual_throughput_matrix(out: &mut String, dry: &BusinessSku, wire: Option<&BusinessSku>) {
    // Union the operating points across both passes so a point measured on
    // only one side still gets a row/column (rendered "—" on the other).
    let mut depths: Vec<InspectionDepth> = dry.depths_for(BenchMode::Throughput);
    if let Some(w) = wire {
        for d in w.depths_for(BenchMode::Throughput) {
            if !depths.contains(&d) {
                depths.push(d);
            }
        }
        // Preserve canonical cost-ascending order after the union.
        depths = InspectionDepth::ALL
            .into_iter()
            .filter(|d| depths.contains(d))
            .collect();
    }
    let mut sizes: BTreeSet<u32> = dry.packet_sizes_for(BenchMode::Throughput).into_iter().collect();
    if let Some(w) = wire {
        sizes.extend(w.packet_sizes_for(BenchMode::Throughput));
    }
    let sizes: Vec<u32> = sizes.into_iter().collect();
    if depths.is_empty() || sizes.is_empty() {
        let _ = writeln!(out, "_No throughput runs recorded._\n");
        return;
    }
    let _ = writeln!(
        out,
        "#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)"
    );
    let _ = writeln!(out);
    let mut header = String::from("| packet size |");
    let mut divider = String::from("| --- |");
    for d in &depths {
        let _ = write!(header, " {} dry-run | {} wire |", d.label(), d.label());
        divider.push_str(" ---: | ---: |");
    }
    let _ = writeln!(out, "{header}");
    let _ = writeln!(out, "{divider}");
    for ps in &sizes {
        let _ = write!(out, "| {ps}B |");
        for d in &depths {
            let dry_cell = dry
                .throughput_at(*ps, *d)
                .and_then(|r| r.throughput.as_ref())
                .map(|t| t.max_gbps);
            let wire_cell = wire
                .and_then(|w| w.throughput_at(*ps, *d))
                .and_then(|r| r.throughput.as_ref())
                .map(|t| t.max_gbps);
            let _ = write!(out, " {} | {} |", fmt_gbps(dry_cell), fmt_gbps(wire_cell));
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out);
}

fn write_throughput_matrix(out: &mut String, sku: &BusinessSku) {
    let depths = sku.depths_for(BenchMode::Throughput);
    let sizes = sku.packet_sizes_for(BenchMode::Throughput);
    if depths.is_empty() || sizes.is_empty() {
        let _ = writeln!(out, "_No throughput runs recorded._\n");
        return;
    }
    let _ = writeln!(
        out,
        "#### Throughput matrix — max Gbps (packet size × inspection)"
    );
    let _ = writeln!(out);
    let mut header = String::from("| packet size |");
    let mut divider = String::from("| --- |");
    for d in &depths {
        let _ = write!(header, " {} |", d.label());
        divider.push_str(" ---: |");
    }
    let _ = writeln!(out, "{header}");
    let _ = writeln!(out, "{divider}");
    for ps in &sizes {
        let _ = write!(out, "| {ps}B |");
        for d in &depths {
            let cell = sku
                .throughput_at(*ps, *d)
                .and_then(|r| r.throughput.as_ref())
                .map(|t| t.max_gbps);
            let _ = write!(out, " {} |", fmt_gbps(cell));
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out);
}

fn write_latency_table(out: &mut String, sku: &BusinessSku) {
    let depths = sku.depths_for(BenchMode::Latency);
    let sizes = sku.packet_sizes_for(BenchMode::Latency);
    let mut any = false;
    let mut body = String::new();
    for ps in &sizes {
        for d in &depths {
            if let Some(l) = sku
                .report_at(BenchMode::Latency, *ps, *d)
                .and_then(|r| r.latency.as_ref())
            {
                any = true;
                let _ = writeln!(
                    body,
                    "| {}B | {} | {} | {} | {} | {} |",
                    ps,
                    d.label(),
                    fmt_ns(l.p50_ns),
                    fmt_ns(l.p95_ns),
                    fmt_ns(l.p99_ns),
                    fmt_ns(l.max_ns),
                );
            }
        }
    }
    if !any {
        return;
    }
    let _ = writeln!(out, "#### Latency percentiles (per-packet)");
    let _ = writeln!(out);
    let _ = writeln!(out, "| packet size | inspection | p50 | p95 | p99 | max |");
    let _ = writeln!(out, "| --- | --- | ---: | ---: | ---: | ---: |");
    let _ = out.write_str(&body);
    let _ = writeln!(out);
}

fn write_resource_table(out: &mut String, sku: &BusinessSku) {
    let depths = sku.depths_for(BenchMode::Throughput);
    let sizes = sku.packet_sizes_for(BenchMode::Throughput);
    let mut any = false;
    let mut body = String::new();
    for ps in &sizes {
        for d in &depths {
            if let Some(r) = sku.throughput_at(*ps, *d) {
                any = true;
                let _ = writeln!(
                    body,
                    "| {}B | {} | {:.1}% | {:.1} |",
                    ps,
                    d.label(),
                    r.resources.mean_cpu_busy_pct,
                    r.resources.peak_rss_bytes as f64 / (1024.0 * 1024.0),
                );
            }
        }
    }
    if !any {
        return;
    }
    let _ = writeln!(
        out,
        "#### Resource utilisation at each throughput operating point"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| packet size | inspection | mean CPU | peak RSS (MiB) |"
    );
    let _ = writeln!(out, "| --- | --- | ---: | ---: |");
    let _ = out.write_str(&body);
    let _ = writeln!(out);
}

fn fmt_gbps(g: Option<f64>) -> String {
    g.map_or_else(|| "—".to_string(), |v| format!("{v:.2} Gbps"))
}

fn fmt_cost_per_gbps(monthly: f64, gbps: Option<f64>) -> String {
    match gbps {
        Some(g) if g > 0.0 => format!("${:.0}", monthly / g),
        _ => "—".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{
        LatencyResult, ResourceResult, RunDimensions, SCHEMA_VERSION, ThroughputResult,
    };

    fn profile(name: &str, vcpus: u32) -> SkuProfile {
        SkuProfile {
            name: name.to_string(),
            vcpus,
            ram_gb: 8,
            nic_gbps: 10.0,
            target_gbps: 2.0,
            nic_queues: None,
            datapath: DatapathParams::default(),
            traffic_mix: TrafficMix::default(),
        }
    }

    fn throughput_report(
        profile: &str,
        ps: u32,
        depth: InspectionDepth,
        gbps: f64,
    ) -> BenchmarkReport {
        BenchmarkReport {
            schema_version: SCHEMA_VERSION,
            profile: profile.to_string(),
            mode: BenchMode::Throughput,
            unix_time_secs: 1_700_000_000,
            git_sha: None,
            dimensions: RunDimensions {
                packet_size: ps,
                policy_rules: 100,
                inspection: depth.label().to_string(),
            },
            throughput: Some(ThroughputResult {
                max_pps: 1_000_000.0,
                max_gbps: gbps,
                mean_gbps: gbps * 0.95,
            }),
            latency: None,
            concurrent_flows: None,
            resources: ResourceResult {
                mean_cpu_busy_pct: 50.0,
                peak_rss_bytes: 128 * 1024 * 1024,
            },
            target_gbps: 2.0,
            competitor_comparison: Some(competitor::comparison_for(4, depth, gbps)),
        }
    }

    fn latency_report(profile: &str, ps: u32, depth: InspectionDepth) -> BenchmarkReport {
        let mut r = throughput_report(profile, ps, depth, 1.0);
        r.mode = BenchMode::Latency;
        r.throughput = None;
        r.competitor_comparison = None;
        r.latency = Some(LatencyResult {
            p50_ns: 20_000,
            p95_ns: 40_000,
            p99_ns: 80_000,
            max_ns: 250_000,
            clamped: 0,
        });
        r
    }

    fn sample() -> BusinessReport {
        let prof = profile("cloud-pop-small", 4);
        let reports = vec![
            throughput_report("cloud-pop-small", 1500, InspectionDepth::NoInspect, 4.0),
            throughput_report("cloud-pop-small", 64, InspectionDepth::NoInspect, 2.5),
            throughput_report("cloud-pop-small", 1500, InspectionDepth::FullTls, 1.2),
            latency_report("cloud-pop-small", 1500, InspectionDepth::NoInspect),
        ];
        BusinessReport::new(
            1_700_000_000,
            Some("deadbeef".to_string()),
            vec![BusinessSku::new(prof, reports)],
        )
    }

    #[test]
    fn json_round_trips() {
        let r = sample();
        let back = BusinessReport::from_json(&r.to_json().unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn markdown_has_all_sections() {
        let md = sample().to_markdown();
        assert!(md.contains("# ShieldNet Gateway — edge performance datasheet"));
        assert!(md.contains("## Executive summary"));
        assert!(md.contains("## Per-SKU detail"));
        assert!(md.contains("## Competitor comparison"));
        assert!(md.contains("## Cost analysis"));
    }

    #[test]
    fn throughput_matrix_shows_measured_and_missing_cells() {
        let md = sample().to_markdown();
        // measured 1500B/no-inspect cell present.
        assert!(md.contains("4.00 Gbps"));
        // url-cat column exists only if a url-cat run was recorded; none
        // here, so the matrix shows only the depths present.
        assert!(md.contains("Throughput matrix"));
    }

    #[test]
    fn competitor_section_carries_caveat_and_vendor() {
        let md = sample().to_markdown();
        assert!(md.contains("not apples-to-apples"));
        assert!(md.contains("FortiGate 60F"));
        assert!(md.contains("PA-450"));
        assert!(md.contains("Check Point 3600"));
    }

    #[test]
    fn cost_analysis_projects_dollars_per_gbps() {
        let md = sample().to_markdown();
        assert!(md.contains("Cost analysis"));
        // 4 vCPU * 0.0416 * 730 ≈ $121/mo.
        assert!(md.contains("$121"));
    }

    #[test]
    fn meets_target_uses_no_inspect_peak() {
        // no-inspect peak 4.0 >= target 2.0 → "yes".
        let md = sample().to_markdown();
        let summary_line = md
            .lines()
            .find(|l| l.contains("cloud-pop-small") && l.contains("yes"))
            .expect("summary row with verdict");
        assert!(summary_line.contains("yes"));
    }

    #[test]
    fn peak_throughput_takes_max_across_packet_sizes() {
        let sku = &sample().skus[0];
        // no-inspect measured at 1500B=4.0 and 64B=2.5 → peak 4.0.
        assert_eq!(sku.peak_throughput(InspectionDepth::NoInspect), Some(4.0));
        assert_eq!(sku.peak_throughput(InspectionDepth::UrlCat), None);
    }

    #[test]
    fn latency_table_covers_sizes_with_no_throughput_run() {
        // A latency run at 9000B with no throughput counterpart must still
        // appear: latency rendering is scoped to latency reports, not to
        // the throughput packet sizes.
        let prof = profile("cloud-pop-small", 4);
        let reports = vec![
            throughput_report("cloud-pop-small", 1500, InspectionDepth::NoInspect, 4.0),
            latency_report("cloud-pop-small", 9000, InspectionDepth::NoInspect),
        ];
        let report = BusinessReport::new(1, None, vec![BusinessSku::new(prof, reports)]);
        let md = report.to_markdown();
        let latency_line = md
            .lines()
            .find(|l| l.contains("9000B") && l.contains("no-inspect"))
            .expect("latency row for the 9000B latency-only operating point");
        assert!(latency_line.contains("ns") || latency_line.contains("µs"));
    }

    fn dual_sample() -> DualDatasheet {
        // Dry-run: synthetic ceiling. Wire: lower, real line-rate.
        let dry_prof = profile("small", 4);
        let dry = BusinessReport::new(
            1_700_000_000,
            Some("deadbeef".to_string()),
            vec![BusinessSku::new(
                dry_prof,
                vec![
                    throughput_report("small", 1500, InspectionDepth::NoInspect, 72.0),
                    throughput_report("small", 1500, InspectionDepth::UrlCat, 70.0),
                    throughput_report("small", 1500, InspectionDepth::FullTls, 68.0),
                    latency_report("small", 1500, InspectionDepth::NoInspect),
                ],
            )],
        );
        let wire_prof = profile("small", 4);
        let wire = BusinessReport::new(
            1_700_000_500,
            Some("deadbeef".to_string()),
            vec![BusinessSku::new(
                wire_prof,
                vec![
                    throughput_report("small", 1500, InspectionDepth::NoInspect, 5.4),
                    throughput_report("small", 1500, InspectionDepth::UrlCat, 5.1),
                    throughput_report("small", 1500, InspectionDepth::FullTls, 4.8),
                ],
            )],
        );
        DualDatasheet::new(dry, wire)
    }

    #[test]
    fn dual_datasheet_json_round_trips() {
        let d = dual_sample();
        let back = DualDatasheet::from_json(&d.to_json().unwrap()).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn dual_datasheet_renders_both_columns() {
        let md = dual_sample().to_markdown();
        // Section structure preserved.
        assert!(md.contains("## Executive summary"));
        assert!(md.contains("## Per-SKU detail"));
        assert!(md.contains("## Competitor comparison"));
        assert!(md.contains("## Cost analysis"));
        // Dual-column headers present.
        assert!(md.contains("firewall dry-run"));
        assert!(md.contains("firewall wire"));
        assert!(md.contains("no-inspect dry-run"));
        assert!(md.contains("no-inspect wire"));
        // Both the synthetic and the measured numbers appear.
        assert!(md.contains("72.00 Gbps")); // dry-run no-inspect peak
        assert!(md.contains("5.40 Gbps")); // wire no-inspect peak
        // Competitor section carries an explicit wire row.
        assert!(md.contains("(dry-run)"));
        assert!(md.contains("(wire)"));
    }

    #[test]
    fn dual_meets_target_judged_on_wire() {
        // Wire firewall peak 5.4 >= target 2.0 → "yes" on the wire basis.
        let md = dual_sample().to_markdown();
        let summary_line = md
            .lines()
            .find(|l| l.starts_with("| small |"))
            .expect("summary row for the small SKU");
        assert!(summary_line.contains("yes"));
    }

    #[test]
    fn dual_cost_per_gbps_uses_wire_peak() {
        // $121/mo over the 5.4 Gbps wire peak ≈ $22/Gbps, not the dry-run
        // ceiling. Assert the wire-based $/Gbps is present.
        let md = dual_sample().to_markdown();
        assert!(md.contains("$22"));
    }

    #[test]
    fn dual_handles_missing_wire_sku() {
        // A dry-run SKU with no wire counterpart renders "—" wire cells
        // rather than panicking.
        let dry = sample(); // cloud-pop-small
        let wire = BusinessReport::new(1, None, vec![]);
        let md = DualDatasheet::new(dry, wire).to_markdown();
        assert!(md.contains("cloud-pop-small"));
        assert!(md.contains("—"));
    }
}
