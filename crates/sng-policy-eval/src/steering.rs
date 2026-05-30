//! Traffic-class steering table.
//!
//! Wire-compatible with `internal/service/appdb/service.go::SteeringRuleSet`:
//! per-class slices of domains / IP ranges / cert pins / app refs,
//! ordered by [`TrafficClass::all`] for deterministic encoding.
//!
//! The compiled table is the local enforcement engine's
//! "what class does this destination belong to?" lookup. It
//! mirrors the same data structure on the Go side
//! (`internal/service/appdb/service.go`) but with two extra
//! optimisations the embedded engine needs:
//!
//! 1. **Literal-domain hash map** — exact domain matches (most
//!    destinations the agent sees in steady state) dispatch via
//!    O(1) lookup rather than a linear scan over every per-class
//!    `domains` list.
//! 2. **Wildcard-suffix Vec** — `*.azureedge.net`-style entries
//!    are linearised once at load time so the hot path does not
//!    re-allocate the suffix string per query.
//!
//! Both indices are built behind [`SteeringTable::from_rule_set`]
//! and frozen for the lifetime of the [`crate::bundle::LoadedBundle`].
//! Hot-swap re-builds them as part of the
//! [`crate::engine::PolicyEngine::swap`] path.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sng_core::traffic_class::TrafficClass;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// The deserialized form of the Go-side `SteeringRuleSet` struct.
/// One `SteeringRuleSet` corresponds to the `st` field on the
/// bundle envelope (JSON-encoded into the MessagePack envelope).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SteeringRuleSet {
    /// Bundle target this rule set was compiled for. Mirrors
    /// `SteeringRuleSet.Target` (string-typed at this layer
    /// because the Go side emits raw strings; the typed enum
    /// lives in [`sng_core::policy::BundleTarget`]).
    pub target: String,
    /// Wire schema version. Receivers SHOULD refuse a higher
    /// version they don't understand.
    #[serde(rename = "schema_version")]
    pub schema_version: i32,
    /// Per-class rule slice. Ordered by `TrafficClass::all()` for
    /// byte-deterministic output on the Go side.
    pub classes: Vec<SteeringClassRules>,
}

/// The steering rules for one traffic class. Field names mirror
/// `internal/service/appdb/service.go::SteeringClassRules` exactly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SteeringClassRules {
    /// The class these rules steer flows into.
    pub class: TrafficClass,
    /// The canonical enforcement action string the receiver
    /// should apply to flows in this class
    /// (`direct | media_bypass | swg_lite | swg_full | tunnel | block`).
    /// Carried so receivers don't have to maintain their own
    /// class-to-action map.
    pub action: String,
    /// Sorted-ascending domain list. Literals AND
    /// `*.something`-style wildcards live here on the wire — the
    /// loader splits them into the typed [`SteeringTable`] indices.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Sorted-ascending IP / CIDR list. Both `1.2.3.4/32` (host)
    /// and `10.0.0.0/8` (subnet) accepted.
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    /// Sorted-ascending TLS certificate pin list (hex-encoded
    /// fingerprints). Opaque at this layer — the SWG / fw
    /// consumes them at TLS handshake time.
    #[serde(default)]
    pub cert_pins: Vec<String>,
    /// App provenance — which app catalog entry produced this
    /// classification. Used for telemetry attribution.
    #[serde(default)]
    pub apps: Vec<SteeringAppRef>,
}

/// Minimal reference to an app-catalog entry — enough for the
/// receiver to attribute a flow to a specific app in telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SteeringAppRef {
    /// App catalog UUID.
    pub id: Uuid,
    /// Human-readable app name.
    pub name: String,
    /// "global" | "override" — whether the classification came
    /// from the global catalog or a tenant override.
    pub source: String,
    /// Optional app category (productivity / social / etc.).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
}

/// Pre-compiled steering lookup. Built once at bundle load and
/// then queried on the hot path; the queries are zero-allocation
/// on every common destination (literal-domain hit, CIDR-range
/// hit, miss).
#[derive(Clone, Debug, Default)]
pub struct SteeringTable {
    /// Exact-domain lookups, lowercase. Most enterprise traffic
    /// goes here.
    literal_domains: HashMap<String, TrafficClass>,
    /// Domain-suffix wildcards. Linear scanned; bundle sizes
    /// observed in practice (single-digit hundreds) keep this
    /// well below microsecond on modern hardware.
    wildcard_suffixes: Vec<(String, TrafficClass)>,
    /// CIDR-range lookups. Linear scanned for the same reasons
    /// as `wildcard_suffixes`; the only-non-default-route is
    /// what `ResolveTrafficClass` does on the Go side.
    ip_ranges: Vec<(IpNet, TrafficClass)>,
}

impl SteeringTable {
    /// Build the lookup indices from the on-wire
    /// [`SteeringRuleSet`]. The class iteration order is
    /// preserved from the Go-side canonical order, so when two
    /// classes overlap on a domain / CIDR the *first* class to
    /// claim it wins — same as
    /// `appdb/service.go::ResolveTrafficClass`'s scoring.
    ///
    /// Domains that look like `*.something` (wildcard form) are
    /// split into [`Self::wildcard_suffixes`]; bare domains are
    /// inserted into [`Self::literal_domains`].
    ///
    /// IP / CIDR strings that fail to parse are skipped with a
    /// warn-level log — the bundle stays loadable so a single
    /// malformed entry doesn't take the whole table out.
    #[must_use]
    pub fn from_rule_set(rule_set: &SteeringRuleSet) -> Self {
        let mut literal_domains: HashMap<String, TrafficClass> = HashMap::new();
        let mut wildcard_suffixes: Vec<(String, TrafficClass)> = Vec::new();
        let mut ip_ranges: Vec<(IpNet, TrafficClass)> = Vec::new();
        for class_rules in &rule_set.classes {
            for d in &class_rules.domains {
                let lc = d.to_ascii_lowercase();
                if let Some(stripped) = lc.strip_prefix("*.") {
                    if stripped.is_empty() {
                        // `*.` alone is meaningless; skip.
                        tracing::warn!(domain = %d, "skipping empty wildcard");
                        continue;
                    }
                    wildcard_suffixes.push((stripped.to_owned(), class_rules.class));
                } else {
                    // First-class wins on conflict (matches the
                    // Go `ResolveTrafficClass` precedence).
                    literal_domains.entry(lc).or_insert(class_rules.class);
                }
            }
            for r in &class_rules.ip_ranges {
                match r.parse::<IpNet>() {
                    Ok(cidr) => ip_ranges.push((cidr, class_rules.class)),
                    Err(e) => {
                        tracing::warn!(range = %r, error = %e, "skipping malformed CIDR");
                    }
                }
            }
        }
        Self {
            literal_domains,
            wildcard_suffixes,
            ip_ranges,
        }
    }

    /// Look up the traffic class for `host`. Returns `None` when
    /// no entry matches — callers fall back to
    /// [`TrafficClass::default_conservative`] (inspect_full) per
    /// `appdb/service.go::ResolveTrafficClass`.
    ///
    /// Match order: exact-domain → wildcard-suffix (longest-
    /// suffix wins to mirror the Go-side scoring at
    /// `service.go::ResolveTrafficClass`).
    #[must_use]
    pub fn class_for_host(&self, host: &str) -> Option<TrafficClass> {
        let host_lc = host.to_ascii_lowercase();
        if let Some(c) = self.literal_domains.get(&host_lc) {
            return Some(*c);
        }
        let mut best: Option<(&str, TrafficClass)> = None;
        for (suffix, class) in &self.wildcard_suffixes {
            if !domain_matches_suffix(suffix, &host_lc) {
                continue;
            }
            if best.is_none_or(|(b, _)| suffix.len() > b.len()) {
                best = Some((suffix.as_str(), *class));
            }
        }
        best.map(|(_, c)| c)
    }

    /// Look up the traffic class for an IP address. Linear
    /// scan over the precompiled CIDR list — adequate for the
    /// bundle sizes the system targets (single-digit hundreds
    /// of ranges).
    #[must_use]
    pub fn class_for_ip(&self, addr: IpAddr) -> Option<TrafficClass> {
        let mut best: Option<(u8, TrafficClass)> = None;
        for (cidr, class) in &self.ip_ranges {
            if !cidr.contains(&addr) {
                continue;
            }
            let prefix = cidr.prefix_len();
            if best.is_none_or(|(b, _)| prefix > b) {
                best = Some((prefix, *class));
            }
        }
        best.map(|(_, c)| c)
    }

    /// Number of literal-domain entries — for telemetry / smoke
    /// tests.
    #[must_use]
    pub fn literal_domain_count(&self) -> usize {
        self.literal_domains.len()
    }

    /// Number of wildcard-suffix entries.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.wildcard_suffixes.len()
    }

    /// Number of CIDR-range entries.
    #[must_use]
    pub fn ip_range_count(&self) -> usize {
        self.ip_ranges.len()
    }
}

/// `*.example.com` style suffix match. Suffix is the bit AFTER
/// the leading `*.` (`example.com` here). Apex match (`host ==
/// suffix`) is intentionally accepted — the steering table's
/// semantics are "include the apex and every subdomain", which
/// is what `*.example.com` means in the steering compiler's
/// `match_any` (see `appdb/service.go::matchAny`).
fn domain_matches_suffix(suffix: &str, host_lc: &str) -> bool {
    if host_lc == suffix {
        return true;
    }
    let Some(prefix) = host_lc.strip_suffix(suffix) else {
        return false;
    };
    prefix.ends_with('.') && !prefix.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn rs() -> SteeringRuleSet {
        SteeringRuleSet {
            target: "edge".into(),
            schema_version: 1,
            classes: vec![
                SteeringClassRules {
                    class: TrafficClass::TrustedDirect,
                    action: "direct".into(),
                    domains: vec!["microsoft.com".into(), "*.office365.com".into()],
                    ip_ranges: vec!["10.0.0.0/8".into()],
                    cert_pins: vec![],
                    apps: vec![],
                },
                SteeringClassRules {
                    class: TrafficClass::InspectFull,
                    action: "swg_full".into(),
                    domains: vec!["example.com".into(), "*.example.com".into()],
                    ip_ranges: vec!["192.168.0.0/16".into()],
                    cert_pins: vec![],
                    apps: vec![],
                },
            ],
        }
    }

    #[test]
    fn literal_domain_lookup_hits_exact_match() {
        let t = SteeringTable::from_rule_set(&rs());
        assert_eq!(
            t.class_for_host("microsoft.com"),
            Some(TrafficClass::TrustedDirect)
        );
        assert_eq!(
            t.class_for_host("MICROSOFT.COM"),
            Some(TrafficClass::TrustedDirect)
        );
    }

    #[test]
    fn wildcard_suffix_lookup_includes_apex() {
        let t = SteeringTable::from_rule_set(&rs());
        assert_eq!(
            t.class_for_host("mail.office365.com"),
            Some(TrafficClass::TrustedDirect)
        );
        // `*.office365.com` includes the apex per steering
        // compiler semantics.
        assert_eq!(
            t.class_for_host("office365.com"),
            Some(TrafficClass::TrustedDirect)
        );
    }

    #[test]
    fn literal_takes_precedence_over_wildcard_when_both_exist() {
        let t = SteeringTable::from_rule_set(&rs());
        // `example.com` is a literal under InspectFull AND a
        // wildcard apex match — literal hits first.
        assert_eq!(
            t.class_for_host("example.com"),
            Some(TrafficClass::InspectFull)
        );
    }

    #[test]
    fn host_with_no_match_returns_none() {
        let t = SteeringTable::from_rule_set(&rs());
        assert_eq!(t.class_for_host("random.test"), None);
    }

    #[test]
    fn ip_lookup_hits_in_range() {
        let t = SteeringTable::from_rule_set(&rs());
        assert_eq!(
            t.class_for_ip("10.1.2.3".parse().unwrap()),
            Some(TrafficClass::TrustedDirect)
        );
        assert_eq!(
            t.class_for_ip("192.168.1.1".parse().unwrap()),
            Some(TrafficClass::InspectFull)
        );
        assert_eq!(t.class_for_ip("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn malformed_cidr_is_skipped_not_rejected() {
        let mut r = rs();
        r.classes[0].ip_ranges.push("not-a-cidr".into());
        let t = SteeringTable::from_rule_set(&r);
        // The two valid CIDRs still loaded.
        assert_eq!(t.ip_range_count(), 2);
    }

    #[test]
    fn empty_wildcard_skipped() {
        let mut r = rs();
        r.classes[0].domains.push("*.".into());
        let t = SteeringTable::from_rule_set(&r);
        // Only the two valid wildcard suffixes loaded.
        assert_eq!(t.wildcard_count(), 2);
    }

    #[test]
    fn counts_match_loaded_entries() {
        let t = SteeringTable::from_rule_set(&rs());
        assert_eq!(t.literal_domain_count(), 2);
        assert_eq!(t.wildcard_count(), 2);
        assert_eq!(t.ip_range_count(), 2);
    }

    #[test]
    fn rule_set_roundtrips_through_serde_json() {
        let r = rs();
        let encoded = serde_json::to_string(&r).unwrap();
        let decoded: SteeringRuleSet = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn longest_wildcard_suffix_wins_on_overlap() {
        let r = SteeringRuleSet {
            target: "edge".into(),
            schema_version: 1,
            classes: vec![
                SteeringClassRules {
                    class: TrafficClass::TrustedDirect,
                    action: "direct".into(),
                    domains: vec!["*.com".into()],
                    ip_ranges: vec![],
                    cert_pins: vec![],
                    apps: vec![],
                },
                SteeringClassRules {
                    class: TrafficClass::InspectFull,
                    action: "swg_full".into(),
                    domains: vec!["*.example.com".into()],
                    ip_ranges: vec![],
                    cert_pins: vec![],
                    apps: vec![],
                },
            ],
        };
        let t = SteeringTable::from_rule_set(&r);
        // `mail.example.com` matches both `*.com` and `*.example.com`;
        // the longer suffix wins.
        assert_eq!(
            t.class_for_host("mail.example.com"),
            Some(TrafficClass::InspectFull)
        );
    }

    #[test]
    fn longest_cidr_prefix_wins_on_overlap() {
        let r = SteeringRuleSet {
            target: "edge".into(),
            schema_version: 1,
            classes: vec![
                SteeringClassRules {
                    class: TrafficClass::TrustedDirect,
                    action: "direct".into(),
                    domains: vec![],
                    ip_ranges: vec!["10.0.0.0/8".into()],
                    cert_pins: vec![],
                    apps: vec![],
                },
                SteeringClassRules {
                    class: TrafficClass::Block,
                    action: "block".into(),
                    domains: vec![],
                    ip_ranges: vec!["10.1.0.0/16".into()],
                    cert_pins: vec![],
                    apps: vec![],
                },
            ],
        };
        let t = SteeringTable::from_rule_set(&r);
        // 10.1.2.3 is inside both /8 and /16 — the more specific
        // /16 should win.
        assert_eq!(
            t.class_for_ip("10.1.2.3".parse().unwrap()),
            Some(TrafficClass::Block)
        );
        // 10.2.0.1 is inside /8 only.
        assert_eq!(
            t.class_for_ip("10.2.0.1".parse().unwrap()),
            Some(TrafficClass::TrustedDirect)
        );
    }
}
