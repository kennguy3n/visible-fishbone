//! Zone-based segmentation model.
//!
//! A `Zone` is a named bundle of L3 networks (CIDR + interface
//! pairs). `ZonePolicy` is the operator's declaration of which
//! zone-to-zone flows are permitted; the default between any two
//! zones is `Deny`, matching the SNG architecture's
//! "default-deny inter-zone" posture (ARCHITECTURE.md §4.2).
//!
//! The zone table is the input to two pieces of compilation:
//!
//! 1. The nftables emitter: each zone gets an ingress set + an
//!    egress set, and inter-zone policy chains hang off them so
//!    a flow's effective verdict is `lookup(from_zone, to_zone)`.
//! 2. The rule compiler: a [`crate::rule::FirewallRule`] with a
//!    non-empty `from_zones` / `to_zones` restricts that rule to
//!    the listed pairs.
//!
//! Zone names are case-sensitive, dotted-lowercase by convention
//! (`branch.lan`, `dmz.publish`, `vpn.users`). The compiler
//! treats them as opaque strings; the only structural check is
//! "every name referenced by a rule exists in the zone table".

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::error::FirewallError;
use crate::rule::RuleAction;

/// Address family of an IP network. Used by the nftables
/// compiler to decide whether to render a rule as `ip` (IPv4)
/// or `ip6` (IPv6) — every nft rule predicate is
/// family-qualified, so a single logical rule that spans both
/// families compiles down to one rule per family.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressFamily {
    /// IPv4 — `ip saddr` / `ip daddr` matches, `zone_<name>`
    /// sets keyed on `ipv4_addr`.
    V4,
    /// IPv6 — `ip6 saddr` / `ip6 daddr` matches, `zone6_<name>`
    /// sets keyed on `ipv6_addr`.
    V6,
}

impl AddressFamily {
    /// nftables address-family qualifier prefix — `ip` for v4,
    /// `ip6` for v6.
    #[must_use]
    pub const fn nft_qualifier(self) -> &'static str {
        match self {
            Self::V4 => "ip",
            Self::V6 => "ip6",
        }
    }

    /// nftables set-name prefix for a per-zone set in this
    /// family — `zone_` for v4, `zone6_` for v6.
    #[must_use]
    pub const fn nft_zone_set_prefix(self) -> &'static str {
        match self {
            Self::V4 => "zone_",
            Self::V6 => "zone6_",
        }
    }

    /// Family of an `IpNet`.
    #[must_use]
    pub const fn of(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => Self::V4,
            IpNet::V6(_) => Self::V6,
        }
    }
}

/// A zone: a name plus the L3 networks that belong to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    /// Operator-facing identifier. Used both in policy bundles
    /// and in the rendered nftables (as a chain / set name).
    pub name: String,
    /// L3 networks the zone covers. A packet's source / dest
    /// address falls into the zone if it matches any listed CIDR.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<IpNet>,
    /// Operator-facing description, surfaced on telemetry.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl Zone {
    /// Does the supplied address fall into one of this zone's
    /// networks?
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.networks.iter().any(|c| c.contains(&addr))
    }

    /// Does this zone hold any networks of the given family?
    /// Used by the nftables emitter to skip rendering rules
    /// that would reference a non-existent per-family zone set.
    #[must_use]
    pub fn has_family(&self, family: AddressFamily) -> bool {
        self.networks.iter().any(|n| AddressFamily::of(n) == family)
    }

    /// Validate the zone body.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.name.is_empty() {
            return Err(FirewallError::RuleInvalid(
                "zone name must not be empty".into(),
            ));
        }
        // A zone with no networks would silently degrade in the
        // compiler: `has_family` returns false for both V4 and
        // V6, so `rule_address_families` collapses the rule into
        // a family-agnostic slot — but the slot still references
        // `zone_<name>` / `zone6_<name>` sets that are never
        // emitted. Reject empty zones at the source so the
        // compiler can rely on `has_family` actually meaning
        // "the zone has CIDRs of this family".
        if self.networks.is_empty() {
            return Err(FirewallError::RuleInvalid(format!(
                "zone {} must contain at least one network",
                self.name,
            )));
        }
        Ok(())
    }
}

/// Inter-zone policy decision. Distinct from [`RuleAction`] so
/// the zone-default semantics are explicit at the type level:
/// the closed set is exactly `Allow` / `Deny` (no
/// `Inspect` / `Steer` — those belong on the rule chain that
/// runs *after* the zone gate).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZonePolicy {
    /// Inter-zone flow permitted; continues into the per-rule
    /// chain.
    Allow,
    /// Inter-zone flow refused at the zone gate. The packet is
    /// dropped without consulting the rule list — this is the
    /// default for any pair the operator hasn't explicitly
    /// allowed.
    #[default]
    Deny,
}

impl ZonePolicy {
    /// Convert to the post-evaluation [`RuleAction`] the engine
    /// dispatches off when a zone gate is the final decision.
    #[must_use]
    pub const fn as_action(self) -> RuleAction {
        match self {
            Self::Allow => RuleAction::Allow,
            Self::Deny => RuleAction::Deny,
        }
    }
}

/// The full zone table: zones + the policy matrix.
///
/// Policy is stored as a sorted map keyed by `(from, to)` so
/// rendering is deterministic — two equivalent inputs produce
/// byte-identical nftables script output, which is what
/// `compile::CompiledRuleSet` hashes for hot-swap detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneTable {
    /// Zones keyed by name.
    #[serde(default)]
    pub zones: BTreeMap<String, Zone>,
    /// Per-pair operator policy, keyed as `policy[from][to]`.
    /// The nested layout (instead of `BTreeMap<(String,
    /// String), ZonePolicy>`) lets [`Self::lookup`] do a
    /// borrow-only `get(&str)` chain on the hot path — the
    /// engine calls it once per packet after classification, so
    /// the original tuple-keyed layout cost two `String`
    /// allocations per lookup. Missing pairs default to
    /// [`ZonePolicy::Deny`].
    #[serde(default)]
    pub policy: BTreeMap<String, BTreeMap<String, ZonePolicy>>,
    /// Optional intra-zone (`from == to`) override. The
    /// SNG default is `Allow` for intra-zone flows (a host in
    /// `branch.lan` can talk to another host in `branch.lan`
    /// without an explicit operator rule); operators that want
    /// strict micro-segmentation can flip this to `Deny`.
    #[serde(default = "default_intra_zone")]
    pub default_intra: ZonePolicy,
    /// Inter-zone default — the value returned for any `(a, b)`
    /// pair the operator did not explicitly declare. Default
    /// `Deny`. Operators can flip this to `Allow` to inherit
    /// a transit-network posture.
    #[serde(default = "default_inter_zone")]
    pub default_inter: ZonePolicy,
}

const fn default_intra_zone() -> ZonePolicy {
    ZonePolicy::Allow
}

const fn default_inter_zone() -> ZonePolicy {
    ZonePolicy::Deny
}

impl Default for ZoneTable {
    /// Default zone table: empty zones, default-allow
    /// intra-zone and default-deny inter-zone — matches the
    /// SNG architecture's "trust within a zone, gate between
    /// zones" baseline. The derived `Default` of `ZonePolicy`
    /// is `Deny`, so we cannot rely on the derive macro for the
    /// intra-zone field — we hand-roll the impl to set the
    /// right baseline.
    fn default() -> Self {
        Self {
            zones: BTreeMap::new(),
            policy: BTreeMap::new(),
            default_intra: default_intra_zone(),
            default_inter: default_inter_zone(),
        }
    }
}

impl ZoneTable {
    /// Build an empty zone table with default-deny inter-zone
    /// and default-allow intra-zone. Operators add zones and
    /// policy entries via [`Self::add_zone`] / [`Self::set_policy`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a zone. Replaces any zone of the same name.
    pub fn add_zone(&mut self, zone: Zone) -> Result<(), FirewallError> {
        zone.validate()?;
        self.zones.insert(zone.name.clone(), zone);
        Ok(())
    }

    /// Declare a policy for an ordered `(from, to)` pair. The
    /// zones must already be registered, otherwise this returns
    /// [`FirewallError::RuleInvalid`].
    pub fn set_policy(
        &mut self,
        from: &str,
        to: &str,
        policy: ZonePolicy,
    ) -> Result<(), FirewallError> {
        if !self.zones.contains_key(from) {
            return Err(FirewallError::RuleInvalid(format!(
                "zone policy references unknown from-zone: {from}"
            )));
        }
        if !self.zones.contains_key(to) {
            return Err(FirewallError::RuleInvalid(format!(
                "zone policy references unknown to-zone: {to}"
            )));
        }
        self.policy
            .entry(from.to_owned())
            .or_default()
            .insert(to.to_owned(), policy);
        Ok(())
    }

    /// Look up the policy for `(from, to)`. Returns the
    /// per-pair declaration if present, otherwise the
    /// intra / inter default.
    ///
    /// This is on the per-packet hot path — the engine calls
    /// it once per evaluated flow after zone classification.
    /// The nested-map layout (`policy[from][to]`) lets us
    /// `get(&str)` on the borrowed slices directly, with no
    /// `String` allocation per call.
    #[must_use]
    pub fn lookup(&self, from: &str, to: &str) -> ZonePolicy {
        if let Some(inner) = self.policy.get(from) {
            if let Some(p) = inner.get(to) {
                return *p;
            }
        }
        if from == to {
            self.default_intra
        } else {
            self.default_inter
        }
    }

    /// Classify an IP into its zone. Returns `None` if the
    /// address belongs to no registered zone — the caller must
    /// decide how to handle unclassified packets (the engine
    /// fail-closes by default).
    ///
    /// When zones overlap (e.g. a broad `10.0.0.0/8` trusted
    /// zone plus a narrower `10.1.0.0/16` dmz zone), the
    /// **longest-prefix match wins** — the same semantics
    /// nftables's `flags interval` sets use when the engine's
    /// rendered script runs in the kernel. Falling back to the
    /// `BTreeMap`'s alphabetical iteration order (as the
    /// previous implementation did) made the in-memory verdict
    /// silently diverge from the kernel verdict whenever the
    /// alphabetically-first zone happened to also be the
    /// shorter / more general one. Tie-breaking on equal
    /// prefix length falls back to `BTreeMap` key order, so
    /// classification is still deterministic across runs.
    #[must_use]
    pub fn classify(&self, addr: IpAddr) -> Option<&str> {
        let mut best: Option<(u8, &str)> = None;
        for z in self.zones.values() {
            for n in &z.networks {
                if n.contains(&addr) {
                    let prefix = n.prefix_len();
                    if best.is_none_or(|(b, _)| prefix > b) {
                        best = Some((prefix, z.name.as_str()));
                    }
                }
            }
        }
        best.map(|(_, n)| n)
    }

    /// Validate every cross-reference in the table. Used by the
    /// compiler so a malformed table fails fast.
    ///
    /// In addition to checking that policy entries reference
    /// declared zones, this rejects **cross-zone network
    /// overlap**: two distinct zones whose CIDR sets contain a
    /// common address. The reason is a deliberate engine /
    /// kernel divergence elimination —
    /// [`Self::classify`] resolves an overlap via longest-prefix
    /// match (so `10.1.5.5` belongs to the narrower zone), but
    /// the rendered nftables `flags interval` sets at
    /// `crates/sng-fw/src/compile.rs:393-394` are unordered
    /// containment checks: a rule scoped to the broader zone
    /// would still fire on `10.1.5.5` in the kernel even though
    /// the in-memory engine routed it to the narrower zone and
    /// skipped the rule. The two views would silently disagree.
    ///
    /// Operators who genuinely want a "broad bucket plus narrow
    /// carveouts" topology should express that as a single zone
    /// with multiple CIDRs plus per-rule CIDR predicates, not as
    /// overlapping zones. This validator surfaces the
    /// misconfiguration at bundle-compile time so the bundle
    /// signer never publishes a ruleset whose semantics depend
    /// on which side of the engine you ask.
    pub fn validate(&self) -> Result<(), FirewallError> {
        for z in self.zones.values() {
            z.validate()?;
        }
        for (from, inner) in &self.policy {
            if !self.zones.contains_key(from) {
                return Err(FirewallError::RuleInvalid(format!(
                    "zone policy references unknown from-zone: {from}"
                )));
            }
            for to in inner.keys() {
                if !self.zones.contains_key(to) {
                    return Err(FirewallError::RuleInvalid(format!(
                        "zone policy references unknown to-zone: {to}"
                    )));
                }
            }
        }
        self.reject_cross_zone_overlap()?;
        Ok(())
    }

    fn reject_cross_zone_overlap(&self) -> Result<(), FirewallError> {
        // BTreeMap iteration is alphabetical so the error
        // message names the same pair on every run — keeps the
        // bundle compiler's failure deterministic.
        let zs: Vec<(&String, &Zone)> = self.zones.iter().collect();
        for i in 0..zs.len() {
            for j in (i + 1)..zs.len() {
                let (a_name, a) = zs[i];
                let (b_name, b) = zs[j];
                for na in &a.networks {
                    for nb in &b.networks {
                        if networks_overlap(na, nb) {
                            return Err(FirewallError::RuleInvalid(format!(
                                "zones {a_name:?} and {b_name:?} have overlapping networks \
                                 ({na} vs {nb}); engine LPM and kernel interval-set \
                                 lookup would disagree on the classification — collapse \
                                 the overlap into one zone with per-rule CIDR predicates"
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Sorted set of zone names — convenience for the nftables
    /// emitter, which must iterate zones in deterministic order
    /// to produce reproducible script output.
    #[must_use]
    pub fn zone_names(&self) -> BTreeSet<&str> {
        self.zones.keys().map(String::as_str).collect()
    }
}

/// Two IP networks overlap when at least one of them is a
/// (loose) subset of the other. `IpNet` doesn't expose a direct
/// `intersects` API, so this is the canonical equivalent: their
/// families must match and one must `contains(network())` the
/// other (a network is a subset of itself; the broader network
/// contains the narrower one's network address).
fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_)) => {
            a.contains(&b.network()) || b.contains(&a.network())
        }
        // Different address families can never overlap; the
        // engine routes V4 traffic against V4 zones and V6
        // traffic against V6 zones.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn zone(name: &str, networks: &[&str]) -> Zone {
        Zone {
            name: name.into(),
            networks: networks.iter().map(|n| n.parse().unwrap()).collect(),
            description: String::new(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_table_returns_inter_default_for_distinct_zones() {
        let t = ZoneTable::new();
        // Lookup against an empty table still answers — the
        // defaults are the contract, not a side-effect of zone
        // population.
        assert_eq!(t.lookup("a", "b"), ZonePolicy::Deny);
        assert_eq!(t.lookup("a", "a"), ZonePolicy::Allow);
    }

    #[test]
    fn explicit_policy_overrides_defaults() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        t.set_policy("trusted", "dmz", ZonePolicy::Allow).unwrap();
        assert_eq!(t.lookup("trusted", "dmz"), ZonePolicy::Allow);
        // Reverse direction not declared — still default-deny.
        assert_eq!(t.lookup("dmz", "trusted"), ZonePolicy::Deny);
    }

    #[test]
    fn set_policy_rejects_unknown_zone() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        let e = t
            .set_policy("trusted", "ghost", ZonePolicy::Allow)
            .unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn classify_uses_longest_prefix_match() {
        // Longest-prefix match matches the kernel's `flags
        // interval` set semantics: when a packet's address
        // falls into multiple zones' networks, the one with the
        // most specific (longest-prefix) network wins, NOT the
        // alphabetically-first zone. The previous BTreeMap-
        // iteration-order behaviour was a silent divergence
        // from the rendered nftables script.
        let mut t = ZoneTable::new();
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        assert_eq!(t.classify(ip("10.1.5.5")), Some("dmz"));
        assert_eq!(t.classify(ip("10.2.0.1")), Some("trusted"));
        assert_eq!(t.classify(ip("172.16.0.1")), None);
    }

    #[test]
    fn classify_lpm_picks_specific_over_broad_regardless_of_zone_name() {
        // Regression: with the old iteration-order code, a
        // narrow `narrow` zone (broad-coverage CIDR) would have
        // beaten a `wide` zone with the more specific CIDR if
        // their names happened to sort the broad zone first.
        // Use a name pair that sorts the BROAD-zone first
        // (`aaa` < `zzz`) but expect classify to return the
        // narrow zone for an address only the narrow CIDR
        // covers narrowly.
        let mut t = ZoneTable::new();
        t.add_zone(zone("aaa-broad", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("zzz-narrow", &["10.5.0.0/16"])).unwrap();
        assert_eq!(t.classify(ip("10.5.1.1")), Some("zzz-narrow"));
        assert_eq!(t.classify(ip("10.6.1.1")), Some("aaa-broad"));
    }

    #[test]
    fn classify_lpm_breaks_ties_deterministically() {
        // Two zones with equally-specific CIDRs that cover
        // the same address \u2014 deterministic tie-break by
        // BTreeMap key order (alphabetical zone name).
        let mut t = ZoneTable::new();
        t.add_zone(zone("alpha", &["10.0.0.0/24"])).unwrap();
        t.add_zone(zone("beta", &["10.0.0.0/24"])).unwrap();
        assert_eq!(t.classify(ip("10.0.0.5")), Some("alpha"));
    }

    #[test]
    fn classify_lpm_picks_longest_prefix_within_single_zone() {
        // A single zone with overlapping CIDRs (operator gave
        // the same zone both a broad transit /16 and a narrow
        // /24 inside it). Classification is by zone, so the
        // result is the same zone name either way \u2014 the LPM
        // logic must still walk all networks rather than break
        // out on first match, otherwise narrower networks in
        // OTHER zones with the same /24 could be missed.
        let mut t = ZoneTable::new();
        t.add_zone(zone("broad", &["10.0.0.0/8"])).unwrap();
        let mut z = zone("multi", &["10.10.0.0/16"]);
        z.networks.push("10.10.5.0/24".parse().unwrap());
        t.add_zone(z).unwrap();
        // Address only matches the /24 in `multi` and the /8 in
        // `broad`; /24 wins.
        assert_eq!(t.classify(ip("10.10.5.42")), Some("multi"));
    }

    #[test]
    fn intra_zone_default_can_be_overridden_to_deny() {
        let mut t = ZoneTable {
            default_intra: ZonePolicy::Deny,
            ..ZoneTable::default()
        };
        t.add_zone(zone("isolated", &["192.168.1.0/24"])).unwrap();
        // No explicit policy -> intra default -> Deny.
        assert_eq!(t.lookup("isolated", "isolated"), ZonePolicy::Deny);
        // Explicit override still works.
        t.set_policy("isolated", "isolated", ZonePolicy::Allow)
            .unwrap();
        assert_eq!(t.lookup("isolated", "isolated"), ZonePolicy::Allow);
    }

    #[test]
    fn inter_zone_default_can_be_overridden_to_allow() {
        let t = ZoneTable {
            default_inter: ZonePolicy::Allow,
            ..ZoneTable::default()
        };
        assert_eq!(t.lookup("a", "b"), ZonePolicy::Allow);
    }

    #[test]
    fn validate_catches_dangling_policy_after_zone_removed() {
        let mut t = ZoneTable::new();
        // Disjoint /16s — the dangling-policy check is what we
        // want to assert, so steer clear of the cross-zone
        // overlap rejection added below.
        t.add_zone(zone("trusted", &["10.0.0.0/16"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        t.set_policy("trusted", "dmz", ZonePolicy::Allow).unwrap();
        // Mutate behind the API to simulate a malformed bundle
        // that compiled `policy` referencing a removed zone.
        t.zones.remove("dmz");
        let e = t.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn validate_rejects_overlapping_zones_v4_broad_then_narrow() {
        // The compiler-time check exists because the classify()
        // resolver and the kernel's interval-set lookup disagree
        // on which zone owns 10.1.5.5 when a broader /8 and a
        // narrower /16 overlap. Reject before that divergence
        // can desync the engine and the data path.
        let mut t = ZoneTable::new();
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        let e = t.validate().unwrap_err();
        match e {
            FirewallError::RuleInvalid(msg) => {
                assert!(
                    msg.contains("overlapping networks"),
                    "unexpected error: {msg}"
                );
                assert!(msg.contains("trusted") && msg.contains("dmz"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_overlapping_zones_v4_identical_cidr() {
        // The narrower fallback (`network()` containment) must
        // catch identical CIDRs too — otherwise the operator can
        // declare two zones with the exact same backing range
        // and the classifier returns whichever the HashMap
        // iteration happens to surface first.
        let mut t = ZoneTable::new();
        t.add_zone(zone("a", &["10.0.0.0/16"])).unwrap();
        t.add_zone(zone("b", &["10.0.0.0/16"])).unwrap();
        let e = t.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn validate_allows_disjoint_v4_zones() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("a", &["10.0.0.0/16"])).unwrap();
        t.add_zone(zone("b", &["10.1.0.0/16"])).unwrap();
        t.add_zone(zone("c", &["192.168.0.0/16"])).unwrap();
        t.validate().unwrap();
    }

    #[test]
    fn validate_rejects_overlapping_zones_v6() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("v6broad", &["2001:db8::/32"])).unwrap();
        t.add_zone(zone("v6narrow", &["2001:db8:abcd::/48"]))
            .unwrap();
        let e = t.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn validate_allows_overlap_across_address_families() {
        // 10.0.0.0/8 and ::/0 "contain" the same numeric space
        // semantically, but the engine routes V4 traffic against
        // V4 zones only and V6 against V6 only, so the
        // cross-family pair is safe.
        let mut t = ZoneTable::new();
        t.add_zone(zone("v4", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("v6", &["::/0"])).unwrap();
        t.validate().unwrap();
    }

    #[test]
    fn validate_rejects_overlap_when_one_zone_has_multiple_networks() {
        // The pair iteration also has to walk inside-zone
        // network lists, not just one-CIDR-per-zone.
        let mut t = ZoneTable::new();
        t.add_zone(zone("left", &["10.0.0.0/16", "192.168.1.0/24"]))
            .unwrap();
        t.add_zone(zone("right", &["172.16.0.0/16", "192.168.0.0/16"]))
            .unwrap();
        let e = t.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn add_zone_rejects_empty_name() {
        let mut t = ZoneTable::new();
        let e = t.add_zone(Zone {
            name: String::new(),
            networks: vec![],
            description: String::new(),
        });
        assert!(matches!(e, Err(FirewallError::RuleInvalid(_))));
    }

    #[test]
    fn add_zone_rejects_empty_networks() {
        // A zone with no networks would make `has_family` lie:
        // it would report neither V4 nor V6, which collapses
        // every rule that references the zone into a
        // family-agnostic slot — and the compiler would then
        // emit `@zone_<name>` references against a set it
        // never created. Reject at the source.
        let mut t = ZoneTable::new();
        let e = t.add_zone(Zone {
            name: "lan".into(),
            networks: vec![],
            description: String::new(),
        });
        let err = e.unwrap_err();
        match err {
            FirewallError::RuleInvalid(msg) => {
                assert!(msg.contains("lan"), "{msg}");
                assert!(msg.contains("network"), "{msg}");
            }
            other => panic!("expected RuleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn zone_policy_maps_to_rule_action() {
        assert_eq!(ZonePolicy::Allow.as_action(), RuleAction::Allow);
        assert_eq!(ZonePolicy::Deny.as_action(), RuleAction::Deny);
    }

    #[test]
    fn zone_names_returns_sorted_set() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("z3", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("z1", &["10.1.0.0/16"])).unwrap();
        t.add_zone(zone("z2", &["10.2.0.0/16"])).unwrap();
        let names: Vec<&str> = t.zone_names().into_iter().collect();
        assert_eq!(names, vec!["z1", "z2", "z3"]);
    }
}
