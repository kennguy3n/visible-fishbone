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

    /// Validate the zone body.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.name.is_empty() {
            return Err(FirewallError::RuleInvalid(
                "zone name must not be empty".into(),
            ));
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
    /// Per-pair operator policy. Missing pairs default to
    /// [`ZonePolicy::Deny`].
    #[serde(default)]
    pub policy: BTreeMap<(String, String), ZonePolicy>,
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
        self.policy.insert((from.into(), to.into()), policy);
        Ok(())
    }

    /// Look up the policy for `(from, to)`. Returns the
    /// per-pair declaration if present, otherwise the
    /// intra / inter default.
    #[must_use]
    pub fn lookup(&self, from: &str, to: &str) -> ZonePolicy {
        if let Some(p) = self.policy.get(&(from.into(), to.into())) {
            return *p;
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
    #[must_use]
    pub fn classify(&self, addr: IpAddr) -> Option<&str> {
        // BTreeMap preserves ordering so classification is
        // deterministic when networks overlap.
        for z in self.zones.values() {
            if z.contains(addr) {
                return Some(&z.name);
            }
        }
        None
    }

    /// Validate every cross-reference in the table. Used by the
    /// compiler so a malformed table fails fast.
    pub fn validate(&self) -> Result<(), FirewallError> {
        for z in self.zones.values() {
            z.validate()?;
        }
        for (from, to) in self.policy.keys() {
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
    fn classify_matches_first_listed_zone_for_address() {
        let mut t = ZoneTable::new();
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        // BTreeMap iteration is sorted by key, so dmz comes
        // before trusted alphabetically — the dmz CIDR is a
        // subnet of trusted, so a packet in 10.1.0.0/16 must
        // classify as dmz, not trusted.
        assert_eq!(t.classify(ip("10.1.5.5")), Some("dmz"));
        assert_eq!(t.classify(ip("10.2.0.1")), Some("trusted"));
        assert_eq!(t.classify(ip("172.16.0.1")), None);
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
        t.add_zone(zone("trusted", &["10.0.0.0/8"])).unwrap();
        t.add_zone(zone("dmz", &["10.1.0.0/16"])).unwrap();
        t.set_policy("trusted", "dmz", ZonePolicy::Allow).unwrap();
        // Mutate behind the API to simulate a malformed bundle
        // that compiled `policy` referencing a removed zone.
        t.zones.remove("dmz");
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
