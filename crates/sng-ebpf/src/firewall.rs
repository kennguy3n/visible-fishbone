//! Hot-path L3/L4 firewall rule evaluation offloaded to XDP.
//!
//! The XDP fast path only enforces the *hot-path subset* of the firewall
//! ruleset: rules whose predicates are pure L3/L4 (source / destination
//! CIDR, port range, protocol) and whose action is a terminal
//! accept-or-drop. Rules that need a resolved subject, a zone lookup, or
//! an L7 / inspection / steering verdict are not representable in XDP and
//! stay on the nftables slow path — the translation that decides
//! eligibility lives in `sng-fw`'s `EbpfBackend`, which owns the
//! `FirewallRule` type. This module is the offload *target*: a compact,
//! first-match-wins rule set the kernel walks per packet.
//!
//! Match semantics deliberately mirror `sng_fw::rule::RuleMatch::matches`
//! for the L3/L4 fields so a rule that XDP accepts is one nftables would
//! also accept — the fast path never diverges from the slow path on a
//! flow it claims to own.

use ipnet::IpNet;
use std::net::IpAddr;

/// Inclusive L4 port range. Mirrors `sng_fw::PortRange` for the hot-path
/// subset; a single port has `from == to`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortRange {
    /// Lower bound, inclusive.
    pub from: u16,
    /// Upper bound, inclusive. Must satisfy `to >= from`.
    pub to: u16,
}

impl PortRange {
    /// Build a range, rejecting `from > to`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::EbpfError::RuleInvalid`] if `from > to`.
    pub fn new(from: u16, to: u16) -> Result<Self, crate::EbpfError> {
        if from > to {
            return Err(crate::EbpfError::RuleInvalid(format!(
                "port range from ({from}) > to ({to})"
            )));
        }
        Ok(Self { from, to })
    }

    /// Single-port range.
    #[must_use]
    pub const fn single(port: u16) -> Self {
        Self {
            from: port,
            to: port,
        }
    }

    /// Does the range contain `port`?
    #[must_use]
    pub const fn contains(&self, port: u16) -> bool {
        port >= self.from && port <= self.to
    }
}

/// The verdict the fast path applies to a packet. XDP can only express a
/// terminal accept or drop on the hot path; anything richer is left to
/// the slow path, so a rule that compiled into this set is guaranteed to
/// carry exactly one of these.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XdpRuleAction {
    /// Accept — let the packet continue (`XDP_PASS`).
    Pass = 0,
    /// Drop the packet at XDP (`XDP_DROP`).
    Drop = 1,
}

impl XdpRuleAction {
    /// The XDP return action this verdict realises.
    #[must_use]
    pub const fn xdp_action(self) -> crate::class::XdpAction {
        match self {
            Self::Pass => crate::class::XdpAction::Pass,
            Self::Drop => crate::class::XdpAction::Drop,
        }
    }
}

/// One compiled hot-path firewall rule. All match fields default to
/// "any"; an empty match set matches every packet (used for the
/// catch-all that realises the chain default).
#[derive(Clone, Debug, PartialEq)]
pub struct XdpRule {
    /// Stable rule id from the policy graph, retained for telemetry.
    pub id: String,
    /// Source CIDR allowlist. Empty = any source.
    pub src_cidrs: Vec<IpNet>,
    /// Destination CIDR allowlist. Empty = any destination.
    pub dst_cidrs: Vec<IpNet>,
    /// Source port allowlist. Empty = any source port.
    pub src_ports: Vec<PortRange>,
    /// Destination port allowlist. Empty = any destination port.
    pub dst_ports: Vec<PortRange>,
    /// IANA L4 protocol number, or `None` for "any protocol".
    pub protocol: Option<u8>,
    /// Verdict on match.
    pub action: XdpRuleAction,
}

impl XdpRule {
    /// Build a match-anything rule with the given id and action — the
    /// shape the chain-default catch-all takes.
    #[must_use]
    pub fn catch_all(id: impl Into<String>, action: XdpRuleAction) -> Self {
        Self {
            id: id.into(),
            src_cidrs: Vec::new(),
            dst_cidrs: Vec::new(),
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            protocol: None,
            action,
        }
    }

    /// Does this rule's predicate set match the supplied 5-tuple?
    ///
    /// Within a field the listed values are OR-ed (match if any element
    /// matches); across fields they are AND-ed — identical to
    /// `sng_fw::RuleMatch::matches` restricted to the L3/L4 predicates.
    #[must_use]
    pub fn matches(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> bool {
        if !self.src_cidrs.is_empty() && !self.src_cidrs.iter().any(|c| c.contains(&src_ip)) {
            return false;
        }
        if !self.dst_cidrs.is_empty() && !self.dst_cidrs.iter().any(|c| c.contains(&dst_ip)) {
            return false;
        }
        if !self.src_ports.is_empty() && !self.src_ports.iter().any(|p| p.contains(src_port)) {
            return false;
        }
        if !self.dst_ports.is_empty() && !self.dst_ports.iter().any(|p| p.contains(dst_port)) {
            return false;
        }
        // `None` protocol on the rule is a wildcard.
        if let Some(proto) = self.protocol
            && proto != protocol
        {
            return false;
        }
        true
    }

    /// Validate the rule body — rejects an empty id and any inverted port
    /// range.
    ///
    /// # Errors
    ///
    /// Returns [`crate::EbpfError::RuleInvalid`] on the first violation.
    pub fn validate(&self) -> Result<(), crate::EbpfError> {
        if self.id.is_empty() {
            return Err(crate::EbpfError::RuleInvalid(
                "rule id must not be empty".into(),
            ));
        }
        for r in self.src_ports.iter().chain(&self.dst_ports) {
            if r.from > r.to {
                return Err(crate::EbpfError::RuleInvalid(format!(
                    "port range from ({}) > to ({})",
                    r.from, r.to
                )));
            }
        }
        Ok(())
    }
}

/// The compiled hot-path rule set the XDP program walks per packet.
/// First-match-wins; a packet that matches no rule takes
/// [`Self::default_action`].
#[derive(Clone, Debug)]
pub struct XdpRuleSet {
    rules: Vec<XdpRule>,
    default_action: XdpRuleAction,
}

impl Default for XdpRuleSet {
    fn default() -> Self {
        // Fail-closed: with no rules every packet is dropped, matching the
        // engine's `None`-ruleset behaviour in `sng-fw`.
        Self {
            rules: Vec::new(),
            default_action: XdpRuleAction::Drop,
        }
    }
}

impl XdpRuleSet {
    /// Build a rule set with an explicit default action.
    #[must_use]
    pub fn new(rules: Vec<XdpRule>, default_action: XdpRuleAction) -> Self {
        Self {
            rules,
            default_action,
        }
    }

    /// Validate every rule. Returns the first violation found.
    ///
    /// # Errors
    ///
    /// Propagates the first [`crate::EbpfError::RuleInvalid`] from a
    /// member rule.
    pub fn validate(&self) -> Result<(), crate::EbpfError> {
        for r in &self.rules {
            r.validate()?;
        }
        Ok(())
    }

    /// Number of rules (excluding the implicit default).
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True iff there are no rules (every packet takes the default).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Borrow the ordered rule list.
    #[must_use]
    pub fn rules(&self) -> &[XdpRule] {
        &self.rules
    }

    /// The action applied when no rule matches.
    #[must_use]
    pub const fn default_action(&self) -> XdpRuleAction {
        self.default_action
    }

    /// Evaluate the 5-tuple against the rule set, returning the matching
    /// rule's action (and id) or the default. First match wins.
    #[must_use]
    pub fn evaluate(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> XdpDecision {
        for r in &self.rules {
            if r.matches(src_ip, dst_ip, src_port, dst_port, protocol) {
                return XdpDecision {
                    action: r.action,
                    matched_rule_id: Some(r.id.clone()),
                };
            }
        }
        XdpDecision {
            action: self.default_action,
            matched_rule_id: None,
        }
    }
}

/// The result of evaluating a packet against an [`XdpRuleSet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdpDecision {
    /// The verdict applied to the packet.
    pub action: XdpRuleAction,
    /// Id of the matching rule, or `None` when the default action fired.
    pub matched_rule_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(id: &str, dst: &str, port: u16, action: XdpRuleAction) -> XdpRule {
        XdpRule {
            id: id.into(),
            src_cidrs: Vec::new(),
            dst_cidrs: vec![net(dst)],
            src_ports: Vec::new(),
            dst_ports: vec![PortRange::single(port)],
            protocol: Some(6),
            action,
        }
    }

    #[test]
    fn port_range_rejects_inverted() {
        assert!(PortRange::new(100, 50).is_err());
        assert!(PortRange::new(50, 100).is_ok());
        assert!(PortRange::single(80).contains(80));
        assert!(!PortRange::single(80).contains(81));
    }

    #[test]
    fn rule_matches_only_when_all_fields_match() {
        let r = rule("allow-https", "203.0.113.0/24", 443, XdpRuleAction::Pass);
        assert!(r.matches(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 443, 6));
        // Wrong port.
        assert!(!r.matches(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 80, 6));
        // Wrong dst.
        assert!(!r.matches(ip("10.0.0.1"), ip("198.51.100.5"), 5000, 443, 6));
        // Wrong protocol (UDP=17).
        assert!(!r.matches(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 443, 17));
    }

    #[test]
    fn empty_match_is_wildcard() {
        let r = XdpRule::catch_all("any", XdpRuleAction::Pass);
        assert!(r.matches(ip("1.2.3.4"), ip("5.6.7.8"), 1, 2, 6));
        assert!(r.matches(ip("::1"), ip("::2"), 1, 2, 17));
    }

    #[test]
    fn first_match_wins_else_default() {
        let set = XdpRuleSet::new(
            vec![
                rule("drop-bad", "192.0.2.0/24", 23, XdpRuleAction::Drop),
                rule("allow-web", "203.0.113.0/24", 443, XdpRuleAction::Pass),
            ],
            XdpRuleAction::Drop,
        );
        let hit = set.evaluate(ip("10.0.0.1"), ip("203.0.113.9"), 4000, 443, 6);
        assert_eq!(hit.action, XdpRuleAction::Pass);
        assert_eq!(hit.matched_rule_id.as_deref(), Some("allow-web"));

        let miss = set.evaluate(ip("10.0.0.1"), ip("8.8.8.8"), 4000, 443, 6);
        assert_eq!(miss.action, XdpRuleAction::Drop);
        assert_eq!(miss.matched_rule_id, None);
    }

    #[test]
    fn default_ruleset_is_fail_closed() {
        let set = XdpRuleSet::default();
        assert!(set.is_empty());
        assert_eq!(set.default_action(), XdpRuleAction::Drop);
        let d = set.evaluate(ip("1.1.1.1"), ip("2.2.2.2"), 1, 2, 6);
        assert_eq!(d.action, XdpRuleAction::Drop);
    }

    #[test]
    fn validate_rejects_empty_id_and_inverted_range() {
        let mut r = XdpRule::catch_all("ok", XdpRuleAction::Pass);
        assert!(r.validate().is_ok());
        r.id = String::new();
        assert!(r.validate().is_err());

        let bad = XdpRule {
            id: "bad".into(),
            src_cidrs: Vec::new(),
            dst_cidrs: Vec::new(),
            src_ports: Vec::new(),
            dst_ports: vec![PortRange { from: 100, to: 50 }],
            protocol: None,
            action: XdpRuleAction::Pass,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn action_maps_to_xdp_action() {
        assert_eq!(
            XdpRuleAction::Pass.xdp_action(),
            crate::class::XdpAction::Pass
        );
        assert_eq!(
            XdpRuleAction::Drop.xdp_action(),
            crate::class::XdpAction::Drop
        );
    }
}
