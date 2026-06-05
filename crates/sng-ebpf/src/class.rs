//! XDP packet classification — the 6 traffic-class steering tiers.
//!
//! The classifier is the XDP fast path's first decision: given a flow's
//! destination it assigns one of the six [`TrafficClass`] tiers from
//! `docs/TRAFFIC_CLASSIFICATION.md` and derives the XDP verdict
//! ([`ClassVerdict`]) the kernel program returns.
//!
//! Classification is a destination match against an ordered,
//! longest-prefix table ([`Classifier`]): the control plane compiles the
//! tenant's app-registry destinations into [`ClassRule`]s and pushes them
//! into the XDP classification map. A flow with no match falls back to
//! [`TrafficClass::default_conservative`] (`inspect_full`) — the same
//! fail-conservative default the Go envelope validator uses.

use ipnet::IpNet;
use std::net::IpAddr;

use sng_core::TrafficClass;

/// The action an XDP program returns for a packet. Discriminants match
/// the kernel `XDP_*` return codes so the userspace-side and kernel-side
/// `u8`/`u32` encodings agree (and so [`Self::as_xdp_code`] needs no
/// lookup table).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum XdpAction {
    /// `XDP_ABORTED` — drop and raise a tracepoint. The fast path uses
    /// this only for malformed packets it cannot parse.
    Aborted = 0,
    /// `XDP_DROP` — drop at the earliest point (the `block` tier and
    /// hot-path `deny` rules).
    Drop = 1,
    /// `XDP_PASS` — hand the packet up the kernel network stack (for
    /// tiers that need slow-path inspection, and for accepted flows that
    /// continue to nftables / the socket layer).
    Pass = 2,
    /// `XDP_TX` — bounce the packet back out the ingress interface.
    /// Reserved for future symmetric-routing fast paths; not emitted by
    /// the current classifier.
    Tx = 3,
    /// `XDP_REDIRECT` — redirect to another interface / CPU / AF_XDP
    /// socket. Reserved for the TC-steering integration.
    Redirect = 4,
}

impl XdpAction {
    /// The kernel `XDP_*` return code.
    #[must_use]
    pub const fn as_xdp_code(self) -> u32 {
        self as u32
    }

    /// The `u8` discriminant stored in [`crate::maps::VerdictCacheEntry`].
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The full XDP verdict for a classified flow: the assigned tier, the
/// XDP action the kernel program returns, and whether the packet still
/// needs slow-path (kernel stack / userspace SWG) inspection after the
/// fast path lets it through.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClassVerdict {
    /// The steering tier assigned to the flow.
    pub class: TrafficClass,
    /// The XDP return action.
    pub action: XdpAction,
    /// True iff the packet must be punted to the slow path for deeper
    /// inspection (DNS / URL-category / TLS-decrypt / ZTNA overlay) even
    /// though XDP did not drop it. `false` for the fully-trusted tiers
    /// the fast path can shortcut, and for `block` (which is terminal).
    pub punt_to_slow_path: bool,
}

/// Derive the XDP verdict for a [`TrafficClass`]. This is the policy that
/// turns a steering tier into a fast-path action:
///
/// * `trusted_direct` / `trusted_media_bypass` — fully trusted; XDP
///   passes them straight through with no slow-path punt.
/// * `inspect_lite` / `inspect_full` / `tunnel_private` — XDP passes the
///   packet but flags it for slow-path handling (URL category, full SWG
///   decrypt, or the mTLS ZTNA overlay respectively).
/// * `block` — dropped at XDP, the earliest enforcement point.
#[must_use]
pub fn verdict_for(class: TrafficClass) -> ClassVerdict {
    let (action, punt) = match class {
        TrafficClass::TrustedDirect | TrafficClass::TrustedMediaBypass => (XdpAction::Pass, false),
        TrafficClass::InspectLite | TrafficClass::InspectFull | TrafficClass::TunnelPrivate => {
            (XdpAction::Pass, true)
        }
        TrafficClass::Block => (XdpAction::Drop, false),
    };
    ClassVerdict {
        class,
        action,
        punt_to_slow_path: punt,
    }
}

/// One classification entry: a destination predicate mapped to a tier.
///
/// A flow matches when its destination address falls inside `dst` and,
/// if `dst_port` is set, its destination port equals it. Entries are
/// evaluated longest-prefix-first by [`Classifier`] so a `/32` host
/// override beats a `/8` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassRule {
    /// Destination network the rule matches.
    pub dst: IpNet,
    /// Optional destination port constraint. `None` matches any port.
    pub dst_port: Option<u16>,
    /// The tier assigned to a matching flow.
    pub class: TrafficClass,
}

impl ClassRule {
    /// New classification rule.
    #[must_use]
    pub fn new(dst: IpNet, dst_port: Option<u16>, class: TrafficClass) -> Self {
        Self {
            dst,
            dst_port,
            class,
        }
    }

    /// Does this rule match the supplied destination?
    #[must_use]
    pub fn matches(&self, dst_ip: IpAddr, dst_port: u16) -> bool {
        if !self.dst.contains(&dst_ip) {
            return false;
        }
        self.dst_port.is_none_or(|p| p == dst_port)
    }
}

/// The XDP classification table — an ordered set of [`ClassRule`]s plus a
/// fallback tier.
///
/// The control plane builds one of these from the tenant's app registry
/// and pushes it into the kernel classification map. The userspace copy
/// is retained so the control plane (and tests) can classify a flow
/// identically to the kernel without a round-trip through a BPF map.
#[derive(Clone, Debug)]
pub struct Classifier {
    /// Rules sorted by descending prefix length (longest-prefix-first).
    rules: Vec<ClassRule>,
    /// Tier for a flow that matches no rule.
    fallback: TrafficClass,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Classifier {
    /// Build a classifier from `rules`, sorting them longest-prefix-first
    /// so the most specific destination wins. The fallback tier is the
    /// conservative `inspect_full` default.
    #[must_use]
    pub fn new(mut rules: Vec<ClassRule>) -> Self {
        Self::sort_longest_prefix(&mut rules);
        Self {
            rules,
            fallback: TrafficClass::default_conservative(),
        }
    }

    /// Build a classifier with an explicit fallback tier.
    #[must_use]
    pub fn with_fallback(mut rules: Vec<ClassRule>, fallback: TrafficClass) -> Self {
        Self::sort_longest_prefix(&mut rules);
        Self { rules, fallback }
    }

    fn sort_longest_prefix(rules: &mut [ClassRule]) {
        // Longest prefix first; among equal prefixes a port-specific rule
        // (Some) outranks a port-agnostic one (None) so a per-port
        // override is not shadowed by a broader same-prefix entry.
        rules.sort_by(|a, b| {
            b.dst
                .prefix_len()
                .cmp(&a.dst.prefix_len())
                .then_with(|| b.dst_port.is_some().cmp(&a.dst_port.is_some()))
        });
    }

    /// Number of classification rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True iff the classifier holds no rules (every flow hits the
    /// fallback tier).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The fallback tier applied when no rule matches.
    #[must_use]
    pub const fn fallback(&self) -> TrafficClass {
        self.fallback
    }

    /// Borrow the ordered rule list (longest-prefix-first).
    #[must_use]
    pub fn rules(&self) -> &[ClassRule] {
        &self.rules
    }

    /// Classify a flow by destination, returning the assigned tier.
    #[must_use]
    pub fn classify(&self, dst_ip: IpAddr, dst_port: u16) -> TrafficClass {
        self.rules
            .iter()
            .find(|r| r.matches(dst_ip, dst_port))
            .map_or(self.fallback, |r| r.class)
    }

    /// Classify a flow and derive its full XDP verdict.
    #[must_use]
    pub fn classify_verdict(&self, dst_ip: IpAddr, dst_port: u16) -> ClassVerdict {
        verdict_for(self.classify(dst_ip, dst_port))
    }
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

    #[test]
    fn xdp_codes_match_kernel_constants() {
        assert_eq!(XdpAction::Aborted.as_xdp_code(), 0);
        assert_eq!(XdpAction::Drop.as_xdp_code(), 1);
        assert_eq!(XdpAction::Pass.as_xdp_code(), 2);
        assert_eq!(XdpAction::Tx.as_xdp_code(), 3);
        assert_eq!(XdpAction::Redirect.as_xdp_code(), 4);
    }

    #[test]
    fn verdict_for_covers_all_six_tiers() {
        for class in TrafficClass::all() {
            let v = verdict_for(class);
            assert_eq!(v.class, class);
            match class {
                TrafficClass::Block => {
                    assert_eq!(v.action, XdpAction::Drop);
                    assert!(!v.punt_to_slow_path);
                }
                TrafficClass::TrustedDirect | TrafficClass::TrustedMediaBypass => {
                    assert_eq!(v.action, XdpAction::Pass);
                    assert!(!v.punt_to_slow_path);
                }
                TrafficClass::InspectLite
                | TrafficClass::InspectFull
                | TrafficClass::TunnelPrivate => {
                    assert_eq!(v.action, XdpAction::Pass);
                    assert!(v.punt_to_slow_path);
                }
            }
        }
    }

    #[test]
    fn classify_falls_back_to_inspect_full_when_empty() {
        let c = Classifier::default();
        assert!(c.is_empty());
        assert_eq!(
            c.classify(ip("203.0.113.5"), 443),
            TrafficClass::InspectFull
        );
    }

    #[test]
    fn longest_prefix_override_wins() {
        let c = Classifier::new(vec![
            ClassRule::new(net("10.0.0.0/8"), None, TrafficClass::InspectFull),
            ClassRule::new(net("10.1.2.0/24"), None, TrafficClass::TunnelPrivate),
            ClassRule::new(net("10.1.2.3/32"), None, TrafficClass::Block),
        ]);
        assert_eq!(c.classify(ip("10.9.9.9"), 0), TrafficClass::InspectFull);
        assert_eq!(c.classify(ip("10.1.2.50"), 0), TrafficClass::TunnelPrivate);
        assert_eq!(c.classify(ip("10.1.2.3"), 0), TrafficClass::Block);
    }

    #[test]
    fn port_specific_rule_outranks_same_prefix_port_agnostic() {
        let c = Classifier::new(vec![
            ClassRule::new(net("198.51.100.0/24"), None, TrafficClass::InspectFull),
            ClassRule::new(
                net("198.51.100.0/24"),
                Some(443),
                TrafficClass::TrustedMediaBypass,
            ),
        ]);
        assert_eq!(
            c.classify(ip("198.51.100.7"), 443),
            TrafficClass::TrustedMediaBypass
        );
        assert_eq!(
            c.classify(ip("198.51.100.7"), 80),
            TrafficClass::InspectFull
        );
    }

    #[test]
    fn classify_verdict_threads_through_classification() {
        let c = Classifier::new(vec![ClassRule::new(
            net("192.0.2.0/24"),
            None,
            TrafficClass::Block,
        )]);
        let v = c.classify_verdict(ip("192.0.2.10"), 80);
        assert_eq!(v.class, TrafficClass::Block);
        assert_eq!(v.action, XdpAction::Drop);
    }
}
