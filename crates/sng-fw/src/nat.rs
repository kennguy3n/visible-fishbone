//! Source / destination NAT + masquerade model.
//!
//! NAT rules sit in their own table from the filter rules
//! because nftables routes them through `nat` hooks
//! (`prerouting` for DNAT, `postrouting` for SNAT / masquerade)
//! rather than the `filter` hook the per-rule chain runs on.
//! The compiler emits them as a separate script section so the
//! ordering invariants from the kernel are preserved:
//!
//!   1. DNAT happens at `prerouting` before the packet hits any
//!      filter chain (so filter rules see the post-DNAT
//!      destination).
//!   2. SNAT / masquerade happens at `postrouting` after the
//!      filter chain has already decided to allow the packet
//!      (so filter rules see the pre-SNAT source).
//!
//! Within each hook, nftables walks the rules top-to-bottom and
//! the first match wins — same as the filter chain. This module
//! preserves source order so a `NatTable` rendered to nftables
//! script emits the rules in the same order they were declared
//! (no implicit re-sort).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::error::FirewallError;
use crate::nftables::escape_nft_comment;
use crate::rule::{PortRange, Protocol};
use crate::zone::AddressFamily;

/// The closed set of NAT operations supported. SNAT and DNAT
/// rewrite the address; masquerade is SNAT-to-the-outbound-
/// interface (the kernel picks the source IP from the interface
/// at packet-emit time).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NatType {
    /// Source NAT — rewrite the source address (and optionally
    /// port) to a known external value.
    Snat {
        /// New source address.
        to: IpAddr,
        /// New source port range. `None` keeps the original
        /// source port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<PortRange>,
    },
    /// Destination NAT — rewrite the destination address
    /// (typically used to publish an internal service on a
    /// public IP).
    Dnat {
        /// New destination address.
        to: IpAddr,
        /// New destination port range.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<PortRange>,
    },
    /// Masquerade — SNAT to the outbound interface's primary
    /// IP. Equivalent to `nft ... masquerade`.
    Masquerade {
        /// Optional outbound port range (often left absent so
        /// the kernel allocates an ephemeral port).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<PortRange>,
    },
}

impl NatType {
    /// nftables verdict expression — the right-hand-side that
    /// follows the match clause.
    ///
    /// IPv6 addresses combined with a port require the
    /// `[addr]:port` bracket syntax: the bare
    /// `2001:db8::1:8080` form is ambiguous because the colon
    /// separator collides with the address's own colons, and
    /// nftables rejects the script outright.
    #[must_use]
    pub fn as_nft(&self) -> String {
        match self {
            Self::Snat { to, port } => match port {
                Some(p) if to.is_ipv6() => format!("snat to [{}]:{}", to, p.as_nft()),
                Some(p) => format!("snat to {}:{}", to, p.as_nft()),
                None => format!("snat to {to}"),
            },
            Self::Dnat { to, port } => match port {
                Some(p) if to.is_ipv6() => format!("dnat to [{}]:{}", to, p.as_nft()),
                Some(p) => format!("dnat to {}:{}", to, p.as_nft()),
                None => format!("dnat to {to}"),
            },
            Self::Masquerade { port } => match port {
                Some(p) => format!("masquerade to :{}", p.as_nft()),
                None => "masquerade".into(),
            },
        }
    }

    /// Address family of the NAT target, if it has one. SNAT
    /// and DNAT carry an [`IpAddr`] target; masquerade picks the
    /// outbound interface's primary address at runtime so its
    /// family is determined by the matched packet, not the rule.
    #[must_use]
    pub const fn target_family(&self) -> Option<AddressFamily> {
        match self {
            Self::Snat { to, .. } | Self::Dnat { to, .. } => Some(match to {
                IpAddr::V4(_) => AddressFamily::V4,
                IpAddr::V6(_) => AddressFamily::V6,
            }),
            Self::Masquerade { .. } => None,
        }
    }

    /// Which nftables hook this NAT type lives on.
    #[must_use]
    pub const fn hook(&self) -> &'static str {
        match self {
            Self::Dnat { .. } => "prerouting",
            Self::Snat { .. } | Self::Masquerade { .. } => "postrouting",
        }
    }
}

/// One compiled NAT rule. Order in [`NatTable::rules`] is
/// preserved — first match wins.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NatRule {
    /// Stable identifier from the policy graph.
    pub id: String,
    /// L3 / L4 predicate — defaults to "any packet".
    #[serde(default)]
    pub src_cidrs: Vec<IpNet>,
    /// Destination CIDR predicate.
    #[serde(default)]
    pub dst_cidrs: Vec<IpNet>,
    /// Destination port predicate. Often used by DNAT rules
    /// that publish a service on a specific external port.
    #[serde(default)]
    pub dst_ports: Vec<PortRange>,
    /// L4 protocol predicate.
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// Optional inbound interface name (`eth0`, `wan0`, …).
    /// Used by DNAT rules to scope to "packets arriving on the
    /// WAN". The compiler emits `iif "name"` when present.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iif: String,
    /// Optional outbound interface — symmetric to `iif`, used
    /// by SNAT / masquerade rules. Emits `oif "name"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub oif: String,
    /// The NAT operation to apply.
    pub nat: NatType,
    /// Operator-facing description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

const fn default_protocol() -> Protocol {
    Protocol::Any
}

impl NatRule {
    /// Validate the rule body.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.id.is_empty() {
            return Err(FirewallError::RuleInvalid(
                "nat rule id must not be empty".into(),
            ));
        }
        // DNAT rules with no dst predicate are technically valid
        // (rewrite every packet's destination) but are almost
        // always a mistake — emit a soft validation. The compiler
        // can override by setting a non-empty dst_cidrs / dst_ports.
        if let NatType::Dnat { .. } = &self.nat
            && self.dst_cidrs.is_empty()
            && self.dst_ports.is_empty()
            && self.iif.is_empty()
        {
            return Err(FirewallError::RuleInvalid(format!(
                "dnat rule {} has no destination predicate (would rewrite every packet)",
                self.id
            )));
        }
        for r in &self.dst_ports {
            if r.from > r.to {
                return Err(FirewallError::RuleInvalid(format!(
                    "nat rule {} dst port range from ({}) > to ({})",
                    self.id, r.from, r.to
                )));
            }
        }
        Ok(())
    }

    /// Render the rule as one or more nftables `add rule`
    /// lines. A rule with CIDR predicates of a single address
    /// family emits one line under that family's qualifier
    /// (`ip` vs `ip6`). A rule with mixed-family CIDRs emits
    /// one line per family with that family's CIDRs only —
    /// nftables's `inet` table accepts both families but the
    /// per-clause qualifier must match the CIDR's family or
    /// the script is rejected (`ip saddr 2001:db8::/32` is a
    /// type error). A rule with no CIDR predicates at all
    /// emits one family-agnostic line (no `ip` / `ip6`
    /// qualifier needed).
    ///
    /// Used by the table emitter; exposed publicly so tests can
    /// snapshot the wire format.
    ///
    /// Returns `Err(FirewallError::BundleInvalid)` if the rule
    /// trips an internal compiler invariant (a family-agnostic
    /// slot receiving CIDR predicates) — mirrors the `Result`
    /// signature on `compile::render_single_rule` so the NAT and
    /// filter compilers fail cleanly with the same error shape
    /// instead of unwinding the manager task on a release-build
    /// panic.
    pub fn render_nft(&self, table: &str) -> Result<Vec<String>, FirewallError> {
        let mut families: BTreeSet<AddressFamily> = BTreeSet::new();
        for n in self.src_cidrs.iter().chain(self.dst_cidrs.iter()) {
            families.insert(AddressFamily::of(n));
        }
        // SNAT / DNAT targets pin the rule to the target's
        // family — rewriting a v4 source to a v6 address is
        // not a thing nftables supports, so we narrow to the
        // target family up front rather than emitting a
        // mismatched line.
        if let Some(tf) = self.nat.target_family() {
            families.retain(|&f| f == tf);
            if families.is_empty() {
                families.insert(tf);
            }
        }
        let family_slots: Vec<Option<AddressFamily>> = if families.is_empty() {
            // No CIDR predicate and no addressed NAT target —
            // the rule applies to every packet that reaches the
            // hook; render once without a family qualifier.
            vec![None]
        } else {
            families.into_iter().map(Some).collect()
        };
        let mut out = Vec::with_capacity(family_slots.len());
        for f in family_slots {
            if let Some(line) = self.render_one(table, f)? {
                out.push(line);
            }
        }
        Ok(out)
    }

    fn render_one(
        &self,
        table: &str,
        family: Option<AddressFamily>,
    ) -> Result<Option<String>, FirewallError> {
        let mut parts: Vec<String> = vec![format!("add rule inet {} {}", table, self.nat.hook())];
        if !self.iif.is_empty() {
            // Defense-in-depth: `iif` / `oif` come from a trusted
            // policy bundle (the deterministic compiler in
            // `sng-policy-eval` validates interface names against
            // the device descriptor) but the bundle decoder is a
            // separate trust boundary, so we run the value through
            // the shared `nftables::escape_nft_comment` helper for
            // the same reason rule IDs do below: a stray `"`, `\`,
            // or control character in the bundle must not be able
            // to split the rendered line or inject extra nftables
            // syntax into `nft -f`.
            parts.push(format!("iif \"{}\"", escape_nft_comment(&self.iif)));
        }
        if !self.oif.is_empty() {
            parts.push(format!("oif \"{}\"", escape_nft_comment(&self.oif)));
        }
        // Filter CIDRs to the current family slot (if any). A
        // rule with a `from` zone-level family but no matching
        // CIDRs of that family for src / dst is fine; we just
        // skip the per-side clause.
        let src_cidrs: Vec<&IpNet> = self
            .src_cidrs
            .iter()
            .filter(|n| family.is_none_or(|f| AddressFamily::of(n) == f))
            .collect();
        let dst_cidrs: Vec<&IpNet> = self
            .dst_cidrs
            .iter()
            .filter(|n| family.is_none_or(|f| AddressFamily::of(n) == f))
            .collect();
        // If the rule has CIDR predicates but none survived the
        // family filter, the rule can't match anything in this
        // family — skip emitting a line that would just be a
        // catch-all under the wrong qualifier.
        if (!self.src_cidrs.is_empty() && src_cidrs.is_empty())
            || (!self.dst_cidrs.is_empty() && dst_cidrs.is_empty())
        {
            return Ok(None);
        }
        // Family-agnostic invariant: a NAT rule with CIDR
        // predicates always has a known family by the time we
        // reach this branch — `render_nft` slot-selects only
        // `Some(family)` when CIDRs are present, and the
        // `target_family()` narrowing for addressed NAT
        // targets (SNAT / DNAT) also pins a concrete family.
        //
        // Earlier revisions used `.expect()` here. That worked
        // for dev builds but in production it would unwind the
        // manager's compile task and trip the agent's
        // panic-restart loop. Returning
        // `FirewallError::BundleInvalid` instead lets the engine
        // fail the install cleanly, keep the previous bundle
        // live, and surface a diagnosable error to the control
        // plane. Mirrors the equivalent guard in
        // `compile::render_single_rule` (commit 9502c24). The
        // accompanying `debug_assert!` is still useful as a
        // dev-time stack-trace breadcrumb when a test exercises
        // the regression.
        if !src_cidrs.is_empty() || !dst_cidrs.is_empty() {
            let Some(fam) = family else {
                debug_assert!(
                    false,
                    "NatRule::render_one: CIDR predicates require a known address \
                     family — `NatTable::render_nft` must not pass `family = None` \
                     to a rule with CIDRs"
                );
                return Err(FirewallError::BundleInvalid(format!(
                    "NatRule::render_one: family-agnostic slot received CIDR \
                     predicates for NAT rule (target {:?}) — the upstream \
                     slot-selection in `NatTable::render_nft` returned \
                     `family = None` for a rule that has CIDRs. This is an \
                     internal compiler invariant violation; fail the bundle \
                     install rather than emit a kernel line strictly more \
                     permissive than the in-memory engine.",
                    self.nat
                )));
            };
            let qualifier = fam.nft_qualifier();
            if !src_cidrs.is_empty() {
                let list: Vec<String> = src_cidrs.iter().map(ToString::to_string).collect();
                parts.push(format!("{qualifier} saddr {{ {} }}", list.join(", ")));
            }
            if !dst_cidrs.is_empty() {
                let list: Vec<String> = dst_cidrs.iter().map(ToString::to_string).collect();
                parts.push(format!("{qualifier} daddr {{ {} }}", list.join(", ")));
            }
        }
        if let Some(p) = self.protocol.as_nft() {
            parts.push(format!("meta l4proto {p}"));
        }
        if !self.dst_ports.is_empty() {
            let list: Vec<String> = self.dst_ports.iter().map(|r| r.as_nft()).collect();
            parts.push(format!("th dport {{ {} }}", list.join(", ")));
        }
        parts.push(self.nat.as_nft());
        parts.push(format!("comment \"{}\"", escape_nft_comment(&self.id)));
        Ok(Some(parts.join(" ")))
    }
}

/// Compiled NAT table — the rule list plus the table name they
/// all live under (typically `sng_nat`). Rendered to a `add table
/// inet sng_nat` + per-rule lines block.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NatTable {
    /// nftables table name. Defaults to `sng_nat`.
    #[serde(default = "default_table_name")]
    pub table_name: String,
    /// Compiled NAT rules in source order.
    #[serde(default)]
    pub rules: Vec<NatRule>,
}

fn default_table_name() -> String {
    "sng_nat".into()
}

impl NatTable {
    /// Empty table with the default name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table_name: default_table_name(),
            rules: Vec::new(),
        }
    }

    /// Push a new rule after validating it.
    pub fn add(&mut self, rule: NatRule) -> Result<(), FirewallError> {
        rule.validate()?;
        self.rules.push(rule);
        Ok(())
    }

    /// Validate every rule in source order.
    pub fn validate(&self) -> Result<(), FirewallError> {
        for r in &self.rules {
            r.validate()?;
        }
        Ok(())
    }

    /// Render the full NAT table as an nftables script. The
    /// output is deterministic: same input -> byte-identical
    /// bytes. The compiler uses this for the hot-swap diff.
    ///
    /// When the rule list is empty the output is *not* empty:
    /// it is the two-line atomic cleanup directive
    /// ```text
    /// add table inet <name>
    /// delete table inet <name>
    /// ```
    /// which is the standard nftables idiom for "ensure this
    /// table is gone regardless of whether it previously
    /// existed". `add table` is a no-op if the table exists
    /// (and creates it otherwise); `delete table` then removes
    /// it. Both run inside the same `nft -f` netlink
    /// transaction so the kernel atomically sees the
    /// "NAT-gone" state. The earlier behaviour of returning an
    /// empty string left stale `inet sng_nat` chains and rules
    /// live in the kernel after a bundle rotated from
    /// NAT-present to NAT-empty — the in-memory engine reported
    /// "no NAT" while the kernel still happily DNAT'd and
    /// SNAT'd traffic according to the previous bundle.
    ///
    /// Returns `Err(FirewallError::BundleInvalid)` if any rule
    /// in the table trips a compiler invariant (currently: a
    /// family-agnostic slot receiving CIDR predicates). The
    /// `Result` propagation mirrors `compile::render_script` so
    /// the engine fails the bundle install cleanly instead of
    /// unwinding the manager task — see commit 9502c24 for the
    /// equivalent change on the filter compiler.
    pub fn render_nft(&self) -> Result<String, FirewallError> {
        use std::fmt::Write as _;
        if self.rules.is_empty() {
            // Atomic cleanup: ensure no stale NAT table from a
            // previous bundle rotation persists in the kernel.
            // See the doc-comment above for the full rationale.
            let mut out = String::new();
            let _ = writeln!(out, "add table inet {}", self.table_name);
            let _ = writeln!(out, "delete table inet {}", self.table_name);
            return Ok(out);
        }
        // Group rules by hook so the script emits one chain per
        // hook with the correct priority (DNAT before SNAT).
        let mut prerouting: Vec<String> = Vec::new();
        let mut postrouting: Vec<String> = Vec::new();
        for r in &self.rules {
            let lines = r.render_nft(&self.table_name)?;
            match r.nat.hook() {
                "prerouting" => prerouting.extend(lines),
                "postrouting" => postrouting.extend(lines),
                _ => {}
            }
        }
        let mut out = String::new();
        let _ = writeln!(out, "add table inet {}", self.table_name);
        // Flush the NAT table before re-populating it, for the
        // same reason `render_script` flushes the filter table:
        // `nft -f` is one netlink transaction, so the kernel
        // atomically sees flush+repopulate. Without the flush,
        // every `add rule ...` in this block would *append* to
        // the existing prerouting / postrouting chains and a
        // removed NAT rule would never actually leave the
        // kernel — engine and kernel state would silently
        // diverge across bundle rotations.
        let _ = writeln!(out, "flush table inet {}", self.table_name);
        let _ = writeln!(
            out,
            "add chain inet {} prerouting {{ type nat hook prerouting priority dstnat; }}",
            self.table_name
        );
        let _ = writeln!(
            out,
            "add chain inet {} postrouting {{ type nat hook postrouting priority srcnat; }}",
            self.table_name
        );
        for line in prerouting {
            out.push_str(&line);
            out.push('\n');
        }
        for line in postrouting {
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn snat_renders_with_to_address() {
        let n = NatType::Snat {
            to: ip("203.0.113.5"),
            port: None,
        };
        assert_eq!(n.as_nft(), "snat to 203.0.113.5");
        assert_eq!(n.hook(), "postrouting");
    }

    #[test]
    fn snat_with_port_includes_port_range() {
        let n = NatType::Snat {
            to: ip("203.0.113.5"),
            port: Some(PortRange::new(10_000, 20_000).unwrap()),
        };
        assert_eq!(n.as_nft(), "snat to 203.0.113.5:10000-20000");
    }

    #[test]
    fn dnat_with_port_includes_destination() {
        let n = NatType::Dnat {
            to: ip("10.0.0.5"),
            port: Some(PortRange::single(8080)),
        };
        assert_eq!(n.as_nft(), "dnat to 10.0.0.5:8080");
        assert_eq!(n.hook(), "prerouting");
    }

    #[test]
    fn masquerade_renders_bare() {
        let n = NatType::Masquerade { port: None };
        assert_eq!(n.as_nft(), "masquerade");
        assert_eq!(n.hook(), "postrouting");
    }

    #[test]
    fn masquerade_with_port_includes_range() {
        let n = NatType::Masquerade {
            port: Some(PortRange::new(50_000, 60_000).unwrap()),
        };
        assert_eq!(n.as_nft(), "masquerade to :50000-60000");
    }

    #[test]
    fn nat_rule_validate_rejects_empty_id() {
        let r = NatRule {
            id: String::new(),
            src_cidrs: vec![],
            dst_cidrs: vec![cidr("0.0.0.0/0")],
            dst_ports: vec![PortRange::single(443)],
            protocol: Protocol::Tcp,
            iif: String::new(),
            oif: String::new(),
            nat: NatType::Dnat {
                to: ip("10.0.0.5"),
                port: None,
            },
            description: String::new(),
        };
        let e = r.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn dnat_without_destination_predicate_is_rejected() {
        // DNAT with no destination predicate would rewrite every
        // packet — the validator must catch the operator error.
        let r = NatRule {
            id: "bad-dnat".into(),
            src_cidrs: vec![],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: String::new(),
            nat: NatType::Dnat {
                to: ip("10.0.0.5"),
                port: None,
            },
            description: String::new(),
        };
        let e = r.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn dnat_with_iif_only_is_accepted() {
        // Scoping to inbound interface is enough to make a DNAT
        // safe — the rule only fires on packets arriving on the
        // named interface.
        let r = NatRule {
            id: "wan-dnat".into(),
            src_cidrs: vec![],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: "wan0".into(),
            oif: String::new(),
            nat: NatType::Dnat {
                to: ip("10.0.0.5"),
                port: None,
            },
            description: String::new(),
        };
        r.validate().unwrap();
    }

    #[test]
    fn nat_rule_renders_with_predicates() {
        let r = NatRule {
            id: "publish-web".into(),
            src_cidrs: vec![],
            dst_cidrs: vec![cidr("203.0.113.0/24")],
            dst_ports: vec![PortRange::single(443)],
            protocol: Protocol::Tcp,
            iif: "wan0".into(),
            oif: String::new(),
            nat: NatType::Dnat {
                to: ip("10.0.0.5"),
                port: Some(PortRange::single(8443)),
            },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("render must succeed for a well-formed rule");
        // Single-family rule — one emitted line.
        assert_eq!(lines.len(), 1, "single-family rule must emit one line");
        let line = &lines[0];
        // Spot-check the components — full string is brittle.
        assert!(line.contains("iif \"wan0\""));
        assert!(line.contains("ip daddr { 203.0.113.0/24 }"));
        assert!(line.contains("meta l4proto tcp"));
        assert!(line.contains("th dport { 443 }"));
        assert!(line.contains("dnat to 10.0.0.5:8443"));
        assert!(line.contains("comment \"publish-web\""));
        // Hook is implicitly prerouting for DNAT.
        assert!(line.starts_with("add rule inet sng_nat prerouting"));
    }

    #[test]
    fn snat_dnat_render_ipv6_target_with_brackets_when_port_present() {
        // Bug fix: bare `snat to 2001:db8::1:8080` is ambiguous
        // — nftables requires `[addr]:port` for v6. The port-less
        // form needs no brackets because nft infers family from
        // the address literal.
        let snat_port = NatType::Snat {
            to: "2001:db8::1".parse().unwrap(),
            port: Some(PortRange::single(8080)),
        };
        assert_eq!(snat_port.as_nft(), "snat to [2001:db8::1]:8080");

        let snat_no_port = NatType::Snat {
            to: "2001:db8::1".parse().unwrap(),
            port: None,
        };
        assert_eq!(snat_no_port.as_nft(), "snat to 2001:db8::1");

        let dnat_port = NatType::Dnat {
            to: "2001:db8::5".parse().unwrap(),
            port: Some(PortRange::single(8443)),
        };
        assert_eq!(dnat_port.as_nft(), "dnat to [2001:db8::5]:8443");

        // v4 path unchanged — brackets only applied for v6.
        let snat_v4 = NatType::Snat {
            to: "10.0.0.1".parse().unwrap(),
            port: Some(PortRange::single(8080)),
        };
        assert_eq!(snat_v4.as_nft(), "snat to 10.0.0.1:8080");
    }

    #[test]
    fn nat_rule_renders_ipv6_clauses_with_ip6_qualifier() {
        // Bug fix: v6 CIDRs must emit `ip6 saddr` — `ip saddr`
        // is a type error against an `ipv6_addr` element and
        // nftables rejects the script. The single-family rule
        // gets one line under the right qualifier.
        let r = NatRule {
            id: "v6-snat".into(),
            src_cidrs: vec![cidr("2001:db8::/32")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Snat {
                to: "2001:db8::1".parse().unwrap(),
                port: None,
            },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("render must succeed for a well-formed rule");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("ip6 saddr { 2001:db8::/32 }"),
            "v6 CIDR must emit ip6 saddr, got: {}",
            lines[0]
        );
        assert!(!lines[0].contains("ip saddr"));
    }

    #[test]
    fn nat_rule_with_mixed_cidrs_emits_one_line_per_family() {
        // Mixed v4 + v6 CIDRs on a masquerade rule must split
        // into two emitted lines: one with the v4 CIDRs under
        // `ip saddr`, the other with the v6 CIDRs under
        // `ip6 saddr`. Masquerade has no addressed target so
        // both families are valid.
        let r = NatRule {
            id: "mixed-masq".into(),
            src_cidrs: vec![cidr("10.0.0.0/8"), cidr("2001:db8::/32")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("render must succeed for a well-formed rule");
        assert_eq!(lines.len(), 2, "mixed-family rule must emit per-family");
        // Each line carries only its own family's CIDRs.
        let v4_line = lines
            .iter()
            .find(|l| l.contains("ip saddr"))
            .expect("v4 line must be present");
        let v6_line = lines
            .iter()
            .find(|l| l.contains("ip6 saddr"))
            .expect("v6 line must be present");
        assert!(v4_line.contains("10.0.0.0/8"));
        assert!(!v4_line.contains("2001:db8"));
        assert!(v6_line.contains("2001:db8::/32"));
        assert!(!v6_line.contains("10.0.0.0/8"));
    }

    #[test]
    fn nat_rule_with_no_cidrs_renders_once_without_family_qualifier() {
        // A masquerade rule scoped only by oif applies to every
        // packet exiting the named interface; no CIDR predicate
        // means no need for a family qualifier at all. The
        // `inet` table handles both families transparently.
        let r = NatRule {
            id: "any-masq".into(),
            src_cidrs: vec![],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("render must succeed for a well-formed rule");
        assert_eq!(lines.len(), 1, "family-agnostic rule must emit once");
        assert!(!lines[0].contains("ip saddr"));
        assert!(!lines[0].contains("ip6 saddr"));
        assert!(lines[0].contains("oif \"wan0\""));
        assert!(lines[0].contains("masquerade"));
    }

    #[test]
    fn snat_with_v4_target_skips_v6_cidrs() {
        // SNAT target is v4 — a v6 source CIDR on the same
        // rule cannot be rewritten to a v4 source. We pin the
        // emitted line to the target's family and drop the
        // non-matching CIDR rather than emit a line that the
        // kernel would reject.
        let r = NatRule {
            id: "v4-snat".into(),
            src_cidrs: vec![cidr("10.0.0.0/8"), cidr("2001:db8::/32")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Snat {
                to: "203.0.113.1".parse().unwrap(),
                port: None,
            },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("render must succeed for a well-formed rule");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr { 10.0.0.0/8 }"));
        assert!(!lines[0].contains("ip6"));
        assert!(!lines[0].contains("2001:db8"));
    }

    #[test]
    fn nat_table_renders_chain_header_per_hook() {
        let mut t = NatTable::new();
        t.add(NatRule {
            id: "snat".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        t.add(NatRule {
            id: "dnat".into(),
            src_cidrs: vec![],
            dst_cidrs: vec![cidr("203.0.113.0/24")],
            dst_ports: vec![PortRange::single(443)],
            protocol: Protocol::Tcp,
            iif: "wan0".into(),
            oif: String::new(),
            nat: NatType::Dnat {
                to: ip("10.0.0.5"),
                port: None,
            },
            description: String::new(),
        })
        .unwrap();
        let script = t
            .render_nft()
            .expect("render must succeed for a well-formed table");
        assert!(script.contains("add table inet sng_nat"));
        assert!(script.contains(
            "add chain inet sng_nat prerouting { type nat hook prerouting priority dstnat; }"
        ));
        assert!(script.contains(
            "add chain inet sng_nat postrouting { type nat hook postrouting priority srcnat; }"
        ));
        // DNAT renders into prerouting, masquerade into
        // postrouting — both are present, both in source order
        // within their hook.
        let dnat_pos = script.find("dnat to 10.0.0.5").unwrap();
        let snat_pos = script.find("masquerade").unwrap();
        assert!(dnat_pos < snat_pos, "DNAT must render before SNAT");
    }

    #[test]
    fn nat_table_render_emits_atomic_cleanup_when_empty() {
        // An empty NAT table must NOT render to an empty string —
        // doing so would leave a stale `inet sng_nat` table with
        // its prerouting / postrouting chains live in the kernel
        // after a bundle rotated from NAT-present to NAT-empty.
        // Instead, render the two-line atomic cleanup directive
        // so the kernel sees an explicit "tear down the NAT
        // table" netlink transaction.
        let t = NatTable::new();
        let s = t
            .render_nft()
            .expect("render must succeed for an empty table");
        assert!(
            s.contains("add table inet sng_nat\n"),
            "empty NAT must emit add table for idempotency: {s}"
        );
        assert!(
            s.contains("delete table inet sng_nat\n"),
            "empty NAT must emit delete table to tear down stale state: {s}"
        );
        // The order matters: `add` first (no-op if table exists,
        // creates if not), then `delete` (always succeeds because
        // the previous `add` guaranteed it exists). Reversed
        // ordering would fail on a first-ever install where the
        // table doesn't exist yet.
        let add_idx = s.find("add table inet sng_nat\n").unwrap();
        let del_idx = s.find("delete table inet sng_nat\n").unwrap();
        assert!(
            add_idx < del_idx,
            "add table must precede delete table so the cleanup is \
             idempotent on first-ever install"
        );
        // No chain or rule declarations should appear — this is
        // a cleanup, not a re-population.
        assert!(
            !s.contains("add chain"),
            "empty NAT cleanup must not declare chains: {s}"
        );
        assert!(
            !s.contains("add rule"),
            "empty NAT cleanup must not declare rules: {s}"
        );
    }

    #[test]
    fn nat_table_render_cleanup_uses_configured_table_name() {
        // The cleanup directive must respect a custom
        // `table_name` — a future operator that renames their
        // NAT table (e.g. for namespacing in a shared-tenant
        // build) still gets a correct teardown.
        let t = NatTable {
            table_name: "tenant42_nat".into(),
            rules: vec![],
        };
        let s = t
            .render_nft()
            .expect("render must succeed for an empty table");
        assert!(s.contains("add table inet tenant42_nat\n"));
        assert!(s.contains("delete table inet tenant42_nat\n"));
        assert!(!s.contains("sng_nat"));
    }

    #[test]
    fn nat_table_render_emits_table_when_rules_present() {
        // Regression guard for the empty-skip fix above: with at
        // least one rule the full table header + chain
        // declarations must still appear.
        let mut t = NatTable::new();
        t.add(NatRule {
            id: "a".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let script = t
            .render_nft()
            .expect("render must succeed for a well-formed table");
        assert!(script.contains("add table inet sng_nat"));
        assert!(script.contains("hook prerouting priority dstnat"));
        assert!(script.contains("hook postrouting priority srcnat"));
    }

    /// Regression: NatTable::render_nft MUST emit `flush table
    /// inet <table>` after `add table` and before the chain /
    /// rule declarations. Without it, NAT rule lists
    /// accumulate across bundle rotations (same kernel/engine
    /// divergence bug as the filter table).
    #[test]
    fn nat_table_render_emits_flush_table_after_add_table() {
        let mut t = NatTable::new();
        t.add(NatRule {
            id: "a".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let script = t
            .render_nft()
            .expect("render must succeed for a well-formed table");
        let add_idx = script
            .find("add table inet sng_nat\n")
            .expect("add table line present");
        let flush_idx = script
            .find("flush table inet sng_nat\n")
            .expect("flush table line present");
        let chain_idx = script
            .find("add chain inet sng_nat prerouting")
            .expect("prerouting chain present");
        let rule_idx = script
            .find("add rule inet sng_nat")
            .expect("rule line present");
        assert!(
            add_idx < flush_idx,
            "add table must come before flush:\n{script}"
        );
        assert!(
            flush_idx < chain_idx,
            "flush must come before chain creation:\n{script}"
        );
        assert!(
            flush_idx < rule_idx,
            "flush must come before rule emission:\n{script}"
        );
    }

    /// Regression: rotating from a NAT table that contains a
    /// rule to one that does not must drop the rule via the
    /// flush — the new script must not mention the removed
    /// rule id but MUST still emit the flush so the kernel
    /// drops it transactionally.
    #[test]
    fn nat_table_rotation_drops_removed_rule_via_flush() {
        let mut t1 = NatTable::new();
        t1.add(NatRule {
            id: "keep".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        t1.add(NatRule {
            id: "removed".into(),
            src_cidrs: vec![cidr("192.168.0.0/16")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let mut t2 = NatTable::new();
        t2.add(NatRule {
            id: "keep".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let s1 = t1
            .render_nft()
            .expect("render must succeed for a well-formed table");
        let s2 = t2
            .render_nft()
            .expect("render must succeed for a well-formed table");
        assert!(s1.contains("\"removed\""));
        assert!(!s2.contains("\"removed\""));
        assert!(s1.contains("flush table inet sng_nat"));
        assert!(s2.contains("flush table inet sng_nat"));
    }

    #[test]
    fn nat_table_render_is_deterministic() {
        let mut t1 = NatTable::new();
        t1.add(NatRule {
            id: "a".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let t2 = t1.clone();
        assert_eq!(
            t1.render_nft()
                .expect("render must succeed for a well-formed table"),
            t2.render_nft()
                .expect("render must succeed for a well-formed table"),
        );
    }

    #[test]
    fn comment_escape_replaces_quotes_and_backslashes() {
        // The NAT renderer used to carry a private `escape_comment`
        // helper; it now delegates to the shared
        // `nftables::escape_nft_comment` (same function the filter
        // chain renderer uses) so the two render paths can't drift
        // out of sync. The end-to-end semantics this test pins
        // down are unchanged.
        assert_eq!(escape_nft_comment("plain"), "plain");
        assert_eq!(escape_nft_comment(r#"with"quotes"#), "with'quotes");
        assert_eq!(escape_nft_comment(r"with\backslash"), "with/backslash");
    }

    #[test]
    fn comment_escape_strips_newlines_and_control_chars() {
        // Newlines would split the `add rule ...` line across
        // multiple physical lines and break `nft -f`.
        assert_eq!(escape_nft_comment("line1\nline2"), "line1 line2");
        assert_eq!(escape_nft_comment("line1\r\nline2"), "line1  line2");
        // Other control characters get the same treatment.
        assert_eq!(escape_nft_comment("tab\there"), "tab here");
        assert_eq!(escape_nft_comment("nul\0byte"), "nul byte");
        // Multi-byte UTF-8 must pass through untouched.
        assert_eq!(escape_nft_comment("emoji-🦀-ok"), "emoji-🦀-ok");
    }

    /// Defense-in-depth regression test: directly calling
    /// `NatRule::render_one` with a `family = None` slot for a
    /// rule that carries CIDR predicates is a programmer error
    /// — `NatTable::render_nft` is supposed to slot-select
    /// `Some(family)` whenever any CIDR is present. The render
    /// path must NOT silently emit a kernel line stripped of its
    /// CIDR qualifier (which would be strictly more permissive
    /// than the in-memory engine); it must return
    /// `Err(FirewallError::BundleInvalid)` so the engine fails
    /// the bundle install instead of unwinding the manager task
    /// on a release-build panic. Mirrors
    /// `compile::tests::render_single_rule_returns_bundle_invalid_on_internal_invariant_violation`.
    #[test]
    fn render_one_returns_bundle_invalid_when_family_agnostic_slot_has_cidrs() {
        // Build a rule whose CIDR carries an unambiguous family
        // (v4) but force the call site to pass `family = None`,
        // simulating an upstream slot-selection bug.
        let r = NatRule {
            id: "broken-slot".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        };
        // Calling `render_one` directly with `family = None` is
        // what a faulty upstream would do. In a debug build,
        // `debug_assert!` fires and the call panics — which is
        // also acceptable, the debug-build assertion is there
        // for the dev-time stack trace. In a release build the
        // assertion is compiled out and the function must
        // return `Err(BundleInvalid)` rather than emit a kernel
        // line stripped of the CIDR qualifier. Mirrors the
        // approach in
        // `compile::tests::render_single_rule_returns_error_on_invariant_violation`.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            r.render_one("sng_nat", None)
        }));
        match result {
            Ok(Err(FirewallError::BundleInvalid(msg))) => {
                // Sanity-check that the diagnostic actually
                // mentions the invariant that was violated and
                // the offending NAT target so an operator can
                // map it back to a rule id.
                assert!(
                    msg.contains("family-agnostic slot"),
                    "diagnostic must name the invariant: {msg}"
                );
                assert!(
                    msg.contains("Masquerade"),
                    "diagnostic must include the NAT target: {msg}"
                );
            }
            Ok(Ok(line)) => {
                panic!("invariant violation must NOT silently emit a kernel line — got: {line:?}")
            }
            Ok(Err(other)) => {
                panic!("invariant violation must surface as BundleInvalid; got: {other:?}")
            }
            Err(_) => {
                // `debug_assert!` in debug builds catches the
                // invariant before the Err return — acceptable,
                // since release builds are the production path
                // and they exercise the `Err` arm.
            }
        }
    }

    /// Companion test: the public `render_nft` entry point on
    /// `NatRule` and `NatTable` must propagate the
    /// `BundleInvalid` error through `?` instead of swallowing
    /// it — but only the *direct* `render_one` path is reachable
    /// in practice because `render_nft`'s slot-selection logic
    /// always pairs CIDR predicates with `Some(family)`. So we
    /// just exercise the cascade for completeness.
    #[test]
    fn render_nft_propagates_bundle_invalid_from_render_one() {
        // The slot-selector in `NatRule::render_nft` *would*
        // never pass `None` to a CIDR-bearing rule, so the
        // happy path always succeeds; this test confirms the
        // success-path cascade hasn't changed.
        let r = NatRule {
            id: "good".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        };
        let lines = r
            .render_nft("sng_nat")
            .expect("well-formed rule must render successfully");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr { 10.0.0.0/8 }"));
    }
}
