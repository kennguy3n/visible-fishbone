//! L3 / L4 firewall rule model.
//!
//! A `FirewallRule` is the compiled, fully-resolved form of an
//! NGFW rule from the policy bundle. Each rule carries a closed
//! set of L3 / L4 predicates ([`RuleMatch`]) and exactly one
//! [`RuleAction`]; the evaluator walks the rule list in source
//! order and returns the first match (longest-prefix CIDR /
//! narrowest port range wins by virtue of rule ordering at
//! compile time, not by re-sorting at eval time — that's the
//! Go-side compiler's contract and we preserve it here).
//!
//! Inline matchers reuse [`sng_policy_eval::matcher::SubjectMatch`]
//! so an `ngfw` rule in a graph compiles into the same predicate
//! tree the SWG / DNS subsystems see. Subject references
//! (`subject_refs`) are resolved during compilation into the
//! [`SubjectMatch`] enum so the eval hot path doesn't have to
//! re-traverse the bundle's subject map.
//!
//! Rule actions are intentionally L3/L4-only on this type. L7
//! application identification, TLS interception, and SD-WAN
//! steering all dispatch off [`RuleAction::Inspect`] or
//! [`RuleAction::Steer`] verdicts via the upper-layer engine.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use sng_policy_eval::matcher::SubjectMatch;

use crate::error::FirewallError;

/// IP protocol the rule matches. The set is closed by design —
/// any L4 protocol we don't enumerate here is matched via
/// [`Protocol::Other`] (the rule predicate carries the numeric
/// IANA assignment so a future kernel that introduces a new
/// protocol still gets enforced).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "name", content = "number", rename_all = "snake_case")]
pub enum Protocol {
    /// TCP (IANA 6).
    Tcp,
    /// UDP (IANA 17).
    Udp,
    /// ICMP (IANA 1) — v4 only.
    Icmp,
    /// ICMPv6 (IANA 58).
    Icmpv6,
    /// SCTP (IANA 132).
    Sctp,
    /// GRE (IANA 47).
    Gre,
    /// ESP (IANA 50).
    Esp,
    /// AH (IANA 51).
    Ah,
    /// Any L4 protocol the closed set above does not cover —
    /// carries the IANA assignment so nftables can emit the
    /// numeric `meta l4proto N` match the kernel needs.
    Other(u8),
    /// Wildcard — matches every L4 protocol. Used by all-protocol
    /// allow / deny / log rules.
    #[default]
    Any,
}

impl Protocol {
    /// Canonical nftables expression — the right-hand-side of
    /// `meta l4proto X` (or `ip protocol X` on IPv4-only rules).
    /// `Any` returns `None` (the rule omits the protocol match
    /// entirely rather than writing `meta l4proto any`).
    #[must_use]
    pub fn as_nft(self) -> Option<String> {
        match self {
            Self::Tcp => Some("tcp".into()),
            Self::Udp => Some("udp".into()),
            Self::Icmp => Some("icmp".into()),
            Self::Icmpv6 => Some("icmpv6".into()),
            Self::Sctp => Some("sctp".into()),
            Self::Gre => Some("47".into()),
            Self::Esp => Some("esp".into()),
            Self::Ah => Some("ah".into()),
            Self::Other(n) => Some(n.to_string()),
            Self::Any => None,
        }
    }

    /// IANA protocol number. `Any` yields `None`.
    #[must_use]
    pub const fn iana_number(self) -> Option<u8> {
        match self {
            Self::Icmp => Some(1),
            Self::Tcp => Some(6),
            Self::Udp => Some(17),
            Self::Gre => Some(47),
            Self::Esp => Some(50),
            Self::Ah => Some(51),
            Self::Sctp => Some(132),
            Self::Icmpv6 => Some(58),
            Self::Other(n) => Some(n),
            Self::Any => None,
        }
    }
}

/// Closed L3 / L4 port range. Inclusive on both ends. A single
/// port maps to `from == to`. `Any` is encoded via the
/// [`RuleMatch::ports`] / `dst_ports` field being absent rather
/// than via a sentinel value here.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    /// Lower bound, inclusive.
    pub from: u16,
    /// Upper bound, inclusive. `to >= from`.
    pub to: u16,
}

impl PortRange {
    /// Build a port range and validate the invariant.
    pub fn new(from: u16, to: u16) -> Result<Self, FirewallError> {
        if from > to {
            return Err(FirewallError::RuleInvalid(format!(
                "port range from ({from}) > to ({to})"
            )));
        }
        Ok(Self { from, to })
    }

    /// Single-port helper.
    #[must_use]
    pub const fn single(port: u16) -> Self {
        Self {
            from: port,
            to: port,
        }
    }

    /// Does this range contain `port`?
    #[must_use]
    pub const fn contains(&self, port: u16) -> bool {
        port >= self.from && port <= self.to
    }

    /// nftables expression — `from-to` (or just the port when
    /// single).
    #[must_use]
    pub fn as_nft(self) -> String {
        if self.from == self.to {
            self.from.to_string()
        } else {
            format!("{}-{}", self.from, self.to)
        }
    }
}

/// L3 / L4 predicate set on a [`FirewallRule`]. Every field
/// defaults to "any"; an empty `RuleMatch::default()` matches
/// every packet.
///
/// Multiple values in `src_cidrs` / `dst_cidrs` are OR-ed; the
/// rule matches if the source address falls in any listed CIDR.
/// Likewise for ports. Across fields the predicates are AND-ed —
/// e.g. a rule with `src_cidrs = [10.0.0.0/8]` and
/// `dst_ports = [443]` matches when both hold.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Source CIDR allowlist. Empty = "any source".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src_cidrs: Vec<IpNet>,
    /// Destination CIDR allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_cidrs: Vec<IpNet>,
    /// Source port range allowlist. Empty = "any source port".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src_ports: Vec<PortRange>,
    /// Destination port range allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_ports: Vec<PortRange>,
    /// L4 protocol. Defaults to [`Protocol::Any`].
    #[serde(default = "any_protocol")]
    pub protocol: Protocol,
    /// Inline subject matcher inherited from the policy bundle —
    /// the rule applies when the resolved subject (user / device /
    /// app) matches. Defaults to [`SubjectMatch::Any`].
    #[serde(default)]
    pub subject: SubjectMatch,
}

const fn any_protocol() -> Protocol {
    Protocol::Any
}

impl RuleMatch {
    /// Does this predicate set match the supplied 5-tuple? The
    /// caller is responsible for resolving any subject reference
    /// before calling — pass the resolved subject value (e.g. the
    /// user id) as `subject_value`. If the rule's subject matcher
    /// is [`SubjectMatch::Any`], the `subject_value` is ignored.
    #[must_use]
    pub fn matches(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        subject_value: Option<&str>,
    ) -> bool {
        // Source CIDR.
        if !self.src_cidrs.is_empty() && !self.src_cidrs.iter().any(|c| c.contains(&src_ip)) {
            return false;
        }
        // Destination CIDR.
        if !self.dst_cidrs.is_empty() && !self.dst_cidrs.iter().any(|c| c.contains(&dst_ip)) {
            return false;
        }
        // Source port.
        if !self.src_ports.is_empty() && !self.src_ports.iter().any(|p| p.contains(src_port)) {
            return false;
        }
        // Destination port.
        if !self.dst_ports.is_empty() && !self.dst_ports.iter().any(|p| p.contains(dst_port)) {
            return false;
        }
        // Protocol: `Any` on either side wildcards.
        match (self.protocol, protocol) {
            (Protocol::Any, _) | (_, Protocol::Any) => {}
            (a, b) if a == b => {}
            _ => return false,
        }
        // Subject — only enforce when both the rule has a
        // non-wildcard matcher AND the caller supplied a value.
        // A non-wildcard matcher with no supplied subject value
        // is rejected (fail-closed): the rule is gated on a
        // subject the engine could not determine.
        match (&self.subject, subject_value) {
            (SubjectMatch::Any, _) => true,
            (m, Some(v)) => m.matches_string(v),
            (_, None) => false,
        }
    }

    /// Validate the predicate set — used at compile time so a
    /// malformed rule fails fast rather than producing a runtime
    /// match anomaly. Returns the first violation found.
    pub fn validate(&self) -> Result<(), FirewallError> {
        for r in &self.src_ports {
            if r.from > r.to {
                return Err(FirewallError::RuleInvalid(format!(
                    "src port range from ({}) > to ({})",
                    r.from, r.to
                )));
            }
        }
        for r in &self.dst_ports {
            if r.from > r.to {
                return Err(FirewallError::RuleInvalid(format!(
                    "dst port range from ({}) > to ({})",
                    r.from, r.to
                )));
            }
        }
        Ok(())
    }
}

/// Verdict the firewall applies on rule match. The set is closed
/// — the upper-layer engine dispatches off these and only these,
/// so adding a new variant is a contract change that requires
/// wiring through every dispatch site.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Permit the packet. Does NOT short-circuit logging — the
    /// rule chain still runs the log accumulator.
    Allow,
    /// Refuse the packet. nftables emits `drop`; a future
    /// `Reject` extension would emit `reject with icmp` and is
    /// intentionally not present today (`drop` is the safer
    /// default; `reject` leaks rule presence to the sender).
    Deny,
    /// Permit + flag for deep inspection — the SWG / IPS chains
    /// consume the marked packet. Implemented in nftables as a
    /// `meta mark` set, picked up by `tproxy` / `tc` further
    /// down the chain.
    Inspect,
    /// Permit + emit metadata to the telemetry pipeline. No
    /// short-circuit: subsequent rules still match.
    Log,
    /// Permit + steer to a non-default outbound path
    /// (sd-wan / cloud connector). Carries the traffic class as
    /// a payload so the steering engine can dispatch.
    Steer,
}

impl RuleAction {
    /// nftables verdict (right-hand-side of an `add rule`).
    /// `Inspect` / `Log` / `Steer` are realised as a `meta mark`
    /// set; the table emitter knows which mark each action gets.
    #[must_use]
    pub const fn as_nft_verdict(self) -> &'static str {
        // `Allow` and the marked-packet actions
        // (`Inspect` / `Log` / `Steer`) both emit `accept` as
        // their nftables verdict — for the marked-packet ones
        // the table emitter prepends `meta mark set N` so the
        // downstream pipeline (Suricata for Inspect, the
        // telemetry tap for Log, the SD-WAN steerer for Steer)
        // can dispatch on the mark. The verdict here is just
        // "do not drop this packet at the filter chain".
        match self {
            Self::Allow | Self::Inspect | Self::Log | Self::Steer => "accept",
            Self::Deny => "drop",
        }
    }

    /// Does this action terminate rule chain evaluation?
    /// `Allow` / `Deny` / `Inspect` / `Steer` are terminal;
    /// `Log` continues so an operator can layer logging onto
    /// downstream rules.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Allow | Self::Deny | Self::Inspect | Self::Steer => true,
            Self::Log => false,
        }
    }

    /// Conntrack mark value the table emitter uses to flag the
    /// packet for downstream dispatch. `Allow` / `Deny` never
    /// set a mark; the others have a stable assignment that the
    /// SWG / IPS / SD-WAN engines decode the same way.
    #[must_use]
    pub const fn meta_mark(self) -> Option<u32> {
        match self {
            Self::Inspect => Some(0x1001),
            Self::Log => Some(0x1002),
            Self::Steer => Some(0x1003),
            Self::Allow | Self::Deny => None,
        }
    }
}

/// One compiled firewall rule. The compiler emits these from the
/// NGFW slice of the policy bundle; the engine walks the list
/// in source order on every packet (terminal action wins).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Stable identifier from the policy graph. Surfaces into
    /// telemetry so an operator can trace "which rule denied
    /// this packet" without re-compiling the bundle.
    pub id: String,
    /// L3 / L4 predicates.
    pub matches: RuleMatch,
    /// Verdict on match.
    pub action: RuleAction,
    /// Optional zone filter — when present the rule only applies
    /// to flows whose ingress zone is in this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_zones: Vec<String>,
    /// Optional zone filter for egress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_zones: Vec<String>,
    /// Operator-facing description, surfaced on telemetry.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl FirewallRule {
    /// Validate the rule body. Returns the first violation
    /// found — the compiler calls this on every rule before the
    /// bundle is considered loaded so a malformed rule fails the
    /// load rather than producing a runtime anomaly.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.id.is_empty() {
            return Err(FirewallError::RuleInvalid(
                "rule id must not be empty".into(),
            ));
        }
        self.matches.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use pretty_assertions::assert_eq;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn port_range_single_helper() {
        let p = PortRange::single(443);
        assert_eq!(p.from, 443);
        assert_eq!(p.to, 443);
        assert!(p.contains(443));
        assert!(!p.contains(442));
        assert!(!p.contains(444));
    }

    #[test]
    fn port_range_new_rejects_inverted() {
        let e = PortRange::new(100, 50).unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn port_range_new_accepts_equal() {
        let p = PortRange::new(443, 443).unwrap();
        assert_eq!(p, PortRange::single(443));
    }

    #[test]
    fn port_range_nft_emits_single_or_range() {
        assert_eq!(PortRange::single(80).as_nft(), "80");
        assert_eq!(PortRange::new(1024, 65535).unwrap().as_nft(), "1024-65535");
    }

    #[test]
    fn protocol_iana_numbers_are_correct() {
        assert_eq!(Protocol::Tcp.iana_number(), Some(6));
        assert_eq!(Protocol::Udp.iana_number(), Some(17));
        assert_eq!(Protocol::Icmp.iana_number(), Some(1));
        assert_eq!(Protocol::Icmpv6.iana_number(), Some(58));
        assert_eq!(Protocol::Sctp.iana_number(), Some(132));
        assert_eq!(Protocol::Gre.iana_number(), Some(47));
        assert_eq!(Protocol::Esp.iana_number(), Some(50));
        assert_eq!(Protocol::Ah.iana_number(), Some(51));
        assert_eq!(Protocol::Other(99).iana_number(), Some(99));
        assert_eq!(Protocol::Any.iana_number(), None);
    }

    #[test]
    fn protocol_nft_strings_are_canonical() {
        assert_eq!(Protocol::Tcp.as_nft().as_deref(), Some("tcp"));
        assert_eq!(Protocol::Udp.as_nft().as_deref(), Some("udp"));
        assert_eq!(Protocol::Other(132).as_nft().as_deref(), Some("132"));
        assert_eq!(Protocol::Any.as_nft(), None);
    }

    #[test]
    fn rule_match_default_matches_everything() {
        let m = RuleMatch::default();
        assert!(m.matches(
            ip("10.0.0.1"),
            ip("8.8.8.8"),
            12345,
            443,
            Protocol::Tcp,
            None
        ));
    }

    #[test]
    fn rule_match_src_cidr_filters() {
        let m = RuleMatch {
            src_cidrs: vec![cidr("10.0.0.0/8")],
            ..RuleMatch::default()
        };
        assert!(m.matches(ip("10.1.2.3"), ip("8.8.8.8"), 1, 1, Protocol::Tcp, None));
        assert!(!m.matches(ip("192.168.1.1"), ip("8.8.8.8"), 1, 1, Protocol::Tcp, None));
    }

    #[test]
    fn rule_match_dst_port_filters() {
        let m = RuleMatch {
            dst_ports: vec![PortRange::single(443)],
            ..RuleMatch::default()
        };
        assert!(m.matches(
            ip("10.0.0.1"),
            ip("8.8.8.8"),
            12345,
            443,
            Protocol::Tcp,
            None
        ));
        assert!(!m.matches(
            ip("10.0.0.1"),
            ip("8.8.8.8"),
            12345,
            80,
            Protocol::Tcp,
            None
        ));
    }

    #[test]
    fn rule_match_protocol_wildcard_either_side() {
        let m = RuleMatch {
            protocol: Protocol::Any,
            ..RuleMatch::default()
        };
        assert!(m.matches(ip("1.1.1.1"), ip("2.2.2.2"), 1, 1, Protocol::Tcp, None));
        assert!(m.matches(ip("1.1.1.1"), ip("2.2.2.2"), 1, 1, Protocol::Udp, None));

        let m = RuleMatch {
            protocol: Protocol::Tcp,
            ..RuleMatch::default()
        };
        assert!(m.matches(ip("1.1.1.1"), ip("2.2.2.2"), 1, 1, Protocol::Tcp, None));
        assert!(!m.matches(ip("1.1.1.1"), ip("2.2.2.2"), 1, 1, Protocol::Udp, None));
    }

    #[test]
    fn rule_match_subject_required_when_matcher_non_wildcard() {
        let m = RuleMatch {
            subject: SubjectMatch::Literal {
                value: "alice".into(),
            },
            ..RuleMatch::default()
        };
        // No subject value supplied -> fail-closed.
        assert!(!m.matches(ip("10.0.0.1"), ip("8.8.8.8"), 1, 1, Protocol::Tcp, None));
        // Subject matches.
        assert!(m.matches(
            ip("10.0.0.1"),
            ip("8.8.8.8"),
            1,
            1,
            Protocol::Tcp,
            Some("alice")
        ));
        // Subject does not match.
        assert!(!m.matches(
            ip("10.0.0.1"),
            ip("8.8.8.8"),
            1,
            1,
            Protocol::Tcp,
            Some("bob")
        ));
    }

    #[test]
    fn rule_action_terminality_is_consistent() {
        for a in [
            RuleAction::Allow,
            RuleAction::Deny,
            RuleAction::Inspect,
            RuleAction::Steer,
        ] {
            assert!(a.is_terminal(), "{a:?} should be terminal");
        }
        assert!(!RuleAction::Log.is_terminal());
    }

    #[test]
    fn rule_action_marks_for_downstream_actions() {
        assert_eq!(RuleAction::Inspect.meta_mark(), Some(0x1001));
        assert_eq!(RuleAction::Log.meta_mark(), Some(0x1002));
        assert_eq!(RuleAction::Steer.meta_mark(), Some(0x1003));
        assert_eq!(RuleAction::Allow.meta_mark(), None);
        assert_eq!(RuleAction::Deny.meta_mark(), None);
    }

    #[test]
    fn rule_validate_rejects_empty_id() {
        let r = FirewallRule {
            id: String::new(),
            matches: RuleMatch::default(),
            action: RuleAction::Allow,
            from_zones: vec![],
            to_zones: vec![],
            description: String::new(),
        };
        let e = r.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn rule_validate_propagates_port_range_failure() {
        // Skip `PortRange::new` so the invalid range survives
        // until `validate`. Used by the compiler to fail-fast
        // on a bundle that smuggled an inverted range past the
        // Go-side schema validator.
        let r = FirewallRule {
            id: "r1".into(),
            matches: RuleMatch {
                dst_ports: vec![PortRange { from: 200, to: 100 }],
                ..RuleMatch::default()
            },
            action: RuleAction::Deny,
            from_zones: vec![],
            to_zones: vec![],
            description: String::new(),
        };
        let e = r.validate().unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn rule_serde_roundtrip_preserves_action() {
        let r = FirewallRule {
            id: "r1".into(),
            matches: RuleMatch {
                dst_ports: vec![PortRange::single(443)],
                protocol: Protocol::Tcp,
                ..RuleMatch::default()
            },
            action: RuleAction::Inspect,
            from_zones: vec!["trusted".into()],
            to_zones: vec!["internet".into()],
            description: "inspect HTTPS".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: FirewallRule = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(json.contains("\"action\":\"inspect\""));
        assert!(json.contains("\"protocol\":{\"name\":\"tcp\"}"));
    }

    #[test]
    fn rule_action_nft_verdict_strings() {
        assert_eq!(RuleAction::Allow.as_nft_verdict(), "accept");
        assert_eq!(RuleAction::Deny.as_nft_verdict(), "drop");
        // Inspect / Log / Steer realise as marks + accept.
        assert_eq!(RuleAction::Inspect.as_nft_verdict(), "accept");
        assert_eq!(RuleAction::Log.as_nft_verdict(), "accept");
        assert_eq!(RuleAction::Steer.as_nft_verdict(), "accept");
    }
}
