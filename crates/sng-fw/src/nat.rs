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
use std::net::IpAddr;

use crate::error::FirewallError;
use crate::rule::{PortRange, Protocol};

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
    #[must_use]
    pub fn as_nft(&self) -> String {
        match self {
            Self::Snat { to, port } => match port {
                Some(p) => format!("snat to {}:{}", to, p.as_nft()),
                None => format!("snat to {to}"),
            },
            Self::Dnat { to, port } => match port {
                Some(p) => format!("dnat to {}:{}", to, p.as_nft()),
                None => format!("dnat to {to}"),
            },
            Self::Masquerade { port } => match port {
                Some(p) => format!("masquerade to :{}", p.as_nft()),
                None => "masquerade".into(),
            },
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
        if let NatType::Dnat { .. } = &self.nat {
            if self.dst_cidrs.is_empty() && self.dst_ports.is_empty() && self.iif.is_empty() {
                return Err(FirewallError::RuleInvalid(format!(
                    "dnat rule {} has no destination predicate (would rewrite every packet)",
                    self.id
                )));
            }
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

    /// Render the rule as a single nftables `add rule` line.
    /// Used by the table emitter; exposed publicly so tests can
    /// snapshot the wire format.
    #[must_use]
    pub fn render_nft(&self, table: &str) -> String {
        let mut parts: Vec<String> = vec![format!("add rule inet {} {}", table, self.nat.hook())];
        if !self.iif.is_empty() {
            parts.push(format!("iif \"{}\"", self.iif));
        }
        if !self.oif.is_empty() {
            parts.push(format!("oif \"{}\"", self.oif));
        }
        if !self.src_cidrs.is_empty() {
            let list: Vec<String> = self.src_cidrs.iter().map(ToString::to_string).collect();
            parts.push(format!("ip saddr {{ {} }}", list.join(", ")));
        }
        if !self.dst_cidrs.is_empty() {
            let list: Vec<String> = self.dst_cidrs.iter().map(ToString::to_string).collect();
            parts.push(format!("ip daddr {{ {} }}", list.join(", ")));
        }
        if let Some(p) = self.protocol.as_nft() {
            parts.push(format!("meta l4proto {p}"));
        }
        if !self.dst_ports.is_empty() {
            let list: Vec<String> = self.dst_ports.iter().map(|r| r.as_nft()).collect();
            parts.push(format!("th dport {{ {} }}", list.join(", ")));
        }
        parts.push(self.nat.as_nft());
        parts.push(format!("comment \"{}\"", escape_comment(&self.id)));
        parts.join(" ")
    }
}

fn escape_comment(s: &str) -> String {
    s.replace('"', "'").replace('\\', "/")
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
    #[must_use]
    pub fn render_nft(&self) -> String {
        use std::fmt::Write as _;
        // Group rules by hook so the script emits one chain per
        // hook with the correct priority (DNAT before SNAT).
        let mut prerouting: Vec<String> = Vec::new();
        let mut postrouting: Vec<String> = Vec::new();
        for r in &self.rules {
            let line = r.render_nft(&self.table_name);
            match r.nat.hook() {
                "prerouting" => prerouting.push(line),
                "postrouting" => postrouting.push(line),
                _ => {}
            }
        }
        let mut out = String::new();
        let _ = writeln!(out, "add table inet {}", self.table_name);
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
        out
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
        let line = r.render_nft("sng_nat");
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
        let script = t.render_nft();
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
        assert_eq!(t1.render_nft(), t2.render_nft());
    }

    #[test]
    fn comment_escape_replaces_quotes_and_backslashes() {
        assert_eq!(escape_comment("plain"), "plain");
        assert_eq!(escape_comment(r#"with"quotes"#), "with'quotes");
        assert_eq!(escape_comment(r"with\backslash"), "with/backslash");
    }
}
