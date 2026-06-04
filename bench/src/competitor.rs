//! Published competitor throughput figures and the mapping from SNG
//! inspection depths onto each vendor's feature categories.
//!
//! Every number here is a *vendor-published* figure for a purpose-built
//! hardware/ASIC appliance. SNG is software-only on a generic x86 VM, so
//! a head-to-head is informative, never apples-to-apples — the
//! [`CompetitorAppliance::caveat`] on each row spells that out and the
//! business report renders it alongside the comparison.
//!
//! The data is intentionally a flat `const` table: it is reference
//! material that changes only when a vendor refreshes a datasheet, so it
//! lives in the binary and is unit-tested for internal consistency rather
//! than loaded at runtime.

/// An SNG inspection depth, paired with the competitor feature category
/// it most closely corresponds to.
///
/// The correspondence is approximate by construction — vendors bin their
/// throughput numbers by marketing feature bundle (firewall / NGFW /
/// threat-prevention), not by the exact processing SNG does at each
/// depth. [`InspectionDepth::competitor_feature`] documents the chosen
/// mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionDepth {
    /// L3/L4 firewall only, no DPI. Compared against vendor *firewall*
    /// throughput.
    NoInspect,
    /// URL categorisation + app-id. Compared against vendor *NGFW /
    /// app-control* throughput.
    UrlCat,
    /// Full TLS inspection + IPS. Compared against vendor
    /// *threat-prevention / IPS* throughput.
    FullTls,
}

impl InspectionDepth {
    /// All depths, in increasing order of inspection cost.
    pub const ALL: [InspectionDepth; 3] = [
        InspectionDepth::NoInspect,
        InspectionDepth::UrlCat,
        InspectionDepth::FullTls,
    ];

    /// Stable label matching [`crate::report::RunDimensions::inspection`]
    /// and the CLI `--inspection` values.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            InspectionDepth::NoInspect => "no-inspect",
            InspectionDepth::UrlCat => "url-cat",
            InspectionDepth::FullTls => "full-tls",
        }
    }

    /// Parse from the report/CLI label; `None` for an unknown string.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "no-inspect" => Some(InspectionDepth::NoInspect),
            "url-cat" => Some(InspectionDepth::UrlCat),
            "full-tls" => Some(InspectionDepth::FullTls),
            _ => None,
        }
    }

    /// The competitor feature category this depth is compared against.
    #[must_use]
    pub fn competitor_feature(self) -> &'static str {
        match self {
            InspectionDepth::NoInspect => "firewall throughput",
            InspectionDepth::UrlCat => "NGFW (URL filtering + app-id) throughput",
            InspectionDepth::FullTls => "threat-prevention / IPS throughput",
        }
    }
}

/// One competitor appliance's published throughput figures.
///
/// Fields are keyed by the SNG inspection depth they map onto rather than
/// by raw vendor label, so [`Self::published_for`] is a direct lookup.
/// `None` means the vendor publishes no figure in that category for this
/// model (e.g. Palo Alto and Check Point do not publish a separate
/// NGFW/app-control number for these SKUs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompetitorAppliance {
    /// Vendor, e.g. `"Fortinet"`.
    pub vendor: &'static str,
    /// Model, e.g. `"FortiGate 60F"`.
    pub model: &'static str,
    /// Reference core count — the hardware class the comparison is bucketed
    /// into, matched against an SNG SKU's `vcpus`.
    pub cores: u32,
    /// Firewall throughput (Gbps), no DPI. Maps to [`InspectionDepth::NoInspect`].
    pub firewall_gbps: Option<f64>,
    /// NGFW / app-control throughput (Gbps). Maps to [`InspectionDepth::UrlCat`].
    pub ngfw_gbps: Option<f64>,
    /// Threat-prevention / IPS throughput (Gbps). Maps to [`InspectionDepth::FullTls`].
    pub ips_gbps: Option<f64>,
    /// Where the figures come from.
    pub source: &'static str,
    /// Why the comparison is not apples-to-apples.
    pub caveat: &'static str,
}

impl CompetitorAppliance {
    /// `"Vendor Model"`, the display name used in comparison tables.
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{} {}", self.vendor, self.model)
    }

    /// The published figure (Gbps) for the feature category that `depth`
    /// maps onto, or `None` if the vendor publishes none.
    #[must_use]
    pub fn published_for(&self, depth: InspectionDepth) -> Option<f64> {
        match depth {
            InspectionDepth::NoInspect => self.firewall_gbps,
            InspectionDepth::UrlCat => self.ngfw_gbps,
            InspectionDepth::FullTls => self.ips_gbps,
        }
    }
}

/// All comparison appliances, grouped by ascending core count.
///
/// ASIC/SoC caveat is per-vendor: Fortinet and Palo Alto front their data
/// path with custom silicon (Fortinet SoC4/NP, Palo Alto single-pass
/// hardware); Check Point's small SKUs are software on a fixed appliance.
/// None of them is a generic VM, which is the whole point SNG is sized
/// against — software-only, any-cloud portability traded for raw silicon
/// throughput.
pub const APPLIANCES: &[CompetitorAppliance] = &[
    CompetitorAppliance {
        vendor: "Fortinet",
        model: "FortiGate 40F",
        cores: 2,
        firewall_gbps: Some(5.0),
        ngfw_gbps: Some(0.6),
        ips_gbps: Some(0.8),
        source: "FortiGate 40F datasheet (firewall / IPS / NGFW throughput, 1518B UDP)",
        caveat: "SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM",
    },
    CompetitorAppliance {
        vendor: "Fortinet",
        model: "FortiGate 60F",
        cores: 4,
        firewall_gbps: Some(10.0),
        ngfw_gbps: Some(1.0),
        ips_gbps: Some(1.4),
        source: "FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP)",
        caveat: "SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM",
    },
    CompetitorAppliance {
        vendor: "Fortinet",
        model: "FortiGate 100F",
        cores: 8,
        firewall_gbps: Some(20.0),
        ngfw_gbps: Some(1.6),
        ips_gbps: Some(2.6),
        source: "FortiGate 100F datasheet (firewall / IPS / NGFW throughput, 1518B UDP)",
        caveat: "NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM",
    },
    CompetitorAppliance {
        vendor: "Palo Alto",
        model: "PA-440",
        cores: 2,
        firewall_gbps: Some(3.1),
        ngfw_gbps: None,
        ips_gbps: Some(0.7),
        source: "PA-400 series datasheet (firewall / threat-prevention throughput)",
        caveat: "single-pass hardware appliance; SNG is software-only on a generic x86 VM",
    },
    CompetitorAppliance {
        vendor: "Palo Alto",
        model: "PA-450",
        cores: 4,
        firewall_gbps: Some(5.2),
        ngfw_gbps: None,
        ips_gbps: Some(1.6),
        source: "PA-400 series datasheet (firewall / threat-prevention throughput)",
        caveat: "single-pass hardware appliance; SNG is software-only on a generic x86 VM",
    },
    CompetitorAppliance {
        vendor: "Check Point",
        model: "3600",
        cores: 4,
        firewall_gbps: Some(3.4),
        ngfw_gbps: None,
        ips_gbps: Some(0.65),
        source: "Check Point 3600 datasheet (firewall / IPS throughput)",
        caveat: "fixed security appliance; SNG is software-only on a generic x86 VM",
    },
];

/// Appliances in the same hardware class as an SNG SKU with `cores`
/// vCPUs, in catalog order.
#[must_use]
pub fn appliances_for_cores(cores: u32) -> Vec<&'static CompetitorAppliance> {
    APPLIANCES.iter().filter(|a| a.cores == cores).collect()
}

/// Build the [`crate::report::CompetitorComparison`] for an SNG SKU of
/// `cores` vCPUs at a given inspection `depth`, given the SNG measured
/// throughput at that point.
///
/// Only same-class competitors that publish a figure in the matching
/// feature category produce a row; vendors with no comparable number are
/// dropped rather than fabricated.
#[must_use]
pub fn comparison_for(
    cores: u32,
    depth: InspectionDepth,
    sng_measured_gbps: f64,
) -> crate::report::CompetitorComparison {
    let rows = appliances_for_cores(cores)
        .into_iter()
        .filter_map(|a| {
            a.published_for(depth).map(|published| {
                crate::report::CompetitorRow::new(
                    a.display_name(),
                    published,
                    sng_measured_gbps,
                    a.caveat,
                )
            })
        })
        .collect();
    crate::report::CompetitorComparison {
        sng_measured_gbps,
        feature: depth.competitor_feature().to_string(),
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_label_round_trips() {
        for depth in InspectionDepth::ALL {
            assert_eq!(InspectionDepth::from_label(depth.label()), Some(depth));
        }
        assert_eq!(InspectionDepth::from_label("bogus"), None);
    }

    #[test]
    fn depth_maps_to_distinct_feature_labels() {
        let features: Vec<_> = InspectionDepth::ALL
            .iter()
            .map(|d| d.competitor_feature())
            .collect();
        // No two depths collapse onto the same competitor category.
        for i in 0..features.len() {
            for j in (i + 1)..features.len() {
                assert_ne!(features[i], features[j]);
            }
        }
    }

    #[test]
    fn published_for_follows_depth_mapping() {
        let fg = APPLIANCES
            .iter()
            .find(|a| a.model == "FortiGate 60F")
            .unwrap();
        assert_eq!(fg.published_for(InspectionDepth::NoInspect), Some(10.0));
        assert_eq!(fg.published_for(InspectionDepth::UrlCat), Some(1.0));
        assert_eq!(fg.published_for(InspectionDepth::FullTls), Some(1.4));
    }

    #[test]
    fn vendors_without_ngfw_figure_report_none() {
        for a in APPLIANCES.iter().filter(|a| a.vendor != "Fortinet") {
            assert_eq!(
                a.published_for(InspectionDepth::UrlCat),
                None,
                "{} unexpectedly publishes an NGFW figure",
                a.display_name()
            );
        }
    }

    #[test]
    fn class_filter_matches_core_count() {
        let four_core = appliances_for_cores(4);
        assert!(!four_core.is_empty());
        assert!(four_core.iter().all(|a| a.cores == 4));
        // The known 4-core field: FortiGate 60F, PA-450, Check Point 3600.
        assert_eq!(four_core.len(), 3);
        assert_eq!(appliances_for_cores(16), Vec::<&CompetitorAppliance>::new());
    }

    #[test]
    fn comparison_drops_vendors_without_a_figure() {
        // url-cat (NGFW) at the 4-core class: only Fortinet publishes one,
        // so PA-450 and Check Point 3600 are dropped, not fabricated.
        let cmp = comparison_for(4, InspectionDepth::UrlCat, 1.2);
        assert_eq!(cmp.rows.len(), 1);
        assert!(cmp.rows[0].competitor.contains("FortiGate 60F"));
        assert!((cmp.rows[0].delta_pct - 20.0).abs() < 1e-9);
        // no-inspect: all three 4-core boxes publish firewall throughput.
        let fw = comparison_for(4, InspectionDepth::NoInspect, 4.0);
        assert_eq!(fw.rows.len(), 3);
        assert_eq!(fw.feature, "firewall throughput");
    }

    #[test]
    fn every_appliance_documents_a_caveat_and_source() {
        for a in APPLIANCES {
            assert!(!a.caveat.is_empty(), "{} missing caveat", a.display_name());
            assert!(!a.source.is_empty(), "{} missing source", a.display_name());
            // Firewall throughput should always exceed the heaviest
            // inspected figure for the same box (sanity on the data).
            if let (Some(fw), Some(ips)) = (a.firewall_gbps, a.ips_gbps) {
                assert!(fw >= ips, "{} firewall < ips", a.display_name());
            }
        }
    }
}
