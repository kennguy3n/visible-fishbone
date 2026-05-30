//! Signature types — `Signature`, `Pattern`, `Severity`,
//! `Action`. These are the typed representations of the IPS
//! rules a policy bundle ships. The matcher in
//! [`crate::matcher`] consumes the [`Signature`]s and produces
//! a compiled, immutable [`crate::matcher::SignatureSet`] the
//! data path can scan against.
//!
//! ### Wire shape
//!
//! Signatures are decoded from the policy bundle's
//! `signatures` section. The wire shape is a flat list of
//! records keyed by short field names to keep MessagePack
//! payloads compact:
//!
//! ```text
//! { sid, msg, sev, act, proto, src?, dst?, sport?, dport?,
//!   patterns: [ { kind, value, nocase, anchor? } ] }
//! ```
//!
//! The crate decodes that shape into the typed [`Signature`]
//! below, then [`crate::matcher::SignatureSet::compile`]
//! turns the patterns into a multi-pattern matcher.

use serde::{Deserialize, Serialize};
use sng_fw::flow::IpProtocol;

/// Severity of an IPS hit, in the order operators sort
/// alerts by. The wire string matches the dashboard
/// convention (`info` / `low` / `medium` / `high` /
/// `critical`); the byte ordering matches the severity
/// ordering so a snapshot of severities can be sorted by
/// numeric value.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — surfaced on dashboards but no alarm.
    Info,
    /// Low — alarm bell at the top of the noise floor.
    Low,
    /// Medium — review within a business day.
    Medium,
    /// High — review immediately; possible automated response.
    High,
    /// Critical — kill-switch / paging event.
    Critical,
}

impl Severity {
    /// Stable wire string the [`sng_core::events::IpsEvent`]
    /// expects in its `sev` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// What the IPS does when a signature hits. The same flow
/// can take exactly one action; conflicting actions across
/// signatures fold to the most-severe one (Drop > Reset >
/// Block > Alert) — see
/// [`crate::matcher::IpsHit::fold_action`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Log the hit, do not interfere with the flow. The
    /// default for `signal-only` signatures the security team
    /// is still tuning.
    Alert,
    /// Drop the offending packet and let upstream TCP
    /// retransmit handle the rest. Cheaper than Reset but
    /// the flow can recover on retransmit; for signatures
    /// like SQLi we typically prefer Reset.
    Drop,
    /// Send a TCP RST on the flow so both endpoints tear it
    /// down immediately. Use when the IPS wants the user to
    /// see the failure (e.g. a content-policy violation, not
    /// an exploit).
    Reset,
    /// Synonym for Reset on flows that the data path knows
    /// how to forcibly close at the L3 layer (UDP, ICMP).
    /// The IPS service folds Block onto Reset before
    /// surfacing the action string on
    /// [`sng_core::events::IpsEvent::action`].
    Block,
}

impl Action {
    /// Stable wire string the [`sng_core::events::IpsEvent`]
    /// expects in its `act` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Drop => "drop",
            Self::Reset => "reset",
            Self::Block => "block",
        }
    }

    /// True if the action terminates the flow. Used by
    /// [`crate::service::IpsService`] to decide whether to
    /// escalate the firewall verdict from Allow to Deny.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Drop | Self::Reset | Self::Block)
    }
}

/// A pattern carried inside a [`Signature`]. The matcher
/// distinguishes literal patterns (Boyer-Moore /
/// Aho-Corasick fast path) from regex patterns (slower
/// per-byte automaton) at compile time.
///
/// Anchors are expressed as offset hints rather than regex
/// anchors so the literal fast path stays usable on
/// anchored literals (a Suricata `content` rule with
/// `depth: N` becomes `Literal { value, anchor: Some(N) }`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Pattern {
    /// Match a literal byte sequence anywhere in the payload
    /// (subject to `Signature::anchor`). The vast majority
    /// of IPS rules are literals — Aho-Corasick scans these
    /// at multi-GB/s and is the workhorse of the matcher.
    Literal(Vec<u8>),
    /// Match an anchored regex. The matcher uses
    /// `regex::bytes::Regex` so binary payloads can match
    /// without going through UTF-8 validation. Patterns
    /// must be valid `regex::bytes` syntax.
    Regex(String),
}

impl Pattern {
    /// Returns the literal bytes if this is a `Literal`
    /// pattern, otherwise `None`. Used by the compiler to
    /// route the pattern to the Aho-Corasick fast path.
    #[must_use]
    pub fn as_literal(&self) -> Option<&[u8]> {
        match self {
            Self::Literal(b) => Some(b.as_slice()),
            Self::Regex(_) => None,
        }
    }

    /// Returns the regex source if this is a `Regex`
    /// pattern, otherwise `None`. Used by the compiler to
    /// route the pattern to the regex slow path.
    #[must_use]
    pub fn as_regex(&self) -> Option<&str> {
        match self {
            Self::Regex(s) => Some(s.as_str()),
            Self::Literal(_) => None,
        }
    }
}

/// Optional offset anchor — restricts where in the payload
/// the pattern is allowed to match. Matches Suricata's
/// `offset:N; depth:M;` semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Anchor {
    /// Lower bound (inclusive). Match must start at or after
    /// this byte offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Upper bound (exclusive). Match must end at or before
    /// `offset + depth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
}

impl Anchor {
    /// True if the match position `match_start` (zero-based,
    /// in the payload coordinates) satisfies the anchor.
    #[must_use]
    pub fn permits(self, match_start: usize, match_len: usize) -> bool {
        if let Some(lo) = self.offset {
            if match_start < lo {
                return false;
            }
        }
        if let (Some(lo), Some(d)) = (self.offset, self.depth) {
            let hi = lo.saturating_add(d);
            if match_start.saturating_add(match_len) > hi {
                return false;
            }
        } else if let Some(d) = self.depth {
            if match_start.saturating_add(match_len) > d {
                return false;
            }
        }
        true
    }
}

/// Source / destination filter on a signature — Suricata's
/// `src` / `dst` keywords. Empty is "any".
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PortFilter {
    /// Permitted source port. None means "any source port".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<u16>,
    /// Permitted destination port. None means "any
    /// destination port".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<u16>,
}

impl PortFilter {
    /// True if the (sport, dport) pair satisfies the filter.
    #[must_use]
    pub fn permits(&self, sport: u16, dport: u16) -> bool {
        if let Some(s) = self.source {
            if s != sport {
                return false;
            }
        }
        if let Some(d) = self.destination {
            if d != dport {
                return false;
            }
        }
        true
    }
}

/// One IPS signature. The list of [`Pattern`]s is conjunctive
/// (ALL must match in the same payload — see
/// [`crate::matcher::SignatureSet::scan`]); cross-pattern
/// ordering is encoded by [`Signature::anchor`] on each
/// pattern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Suricata-style SID. Unique within a bundle; the
    /// matcher uses it for hit dedup and ops dashboards
    /// index alerts on it.
    #[serde(rename = "sid")]
    pub sid: u32,
    /// Human-readable signature description. Lands in
    /// [`sng_core::events::IpsEvent::signature`].
    #[serde(rename = "msg")]
    pub msg: String,
    /// Severity bucket; folds into [`crate::matcher::IpsHit::severity`].
    #[serde(rename = "sev")]
    pub severity: Severity,
    /// Action to take on hit; folds into
    /// [`crate::matcher::IpsHit::action`].
    #[serde(rename = "act")]
    pub action: Action,
    /// Protocol the signature applies to. Filters out flows
    /// at scan time so a TCP signature never wastes cycles
    /// against UDP / ICMP payloads.
    #[serde(rename = "proto")]
    pub protocol: IpProtocol,
    /// Port filter — narrows the signature to flows on
    /// specific (sport, dport). Empty filter = any port.
    #[serde(rename = "pf", default, skip_serializing_if = "is_default_port_filter")]
    pub ports: PortFilter,
    /// One or more patterns. All must match.
    #[serde(rename = "p")]
    pub patterns: Vec<Pattern>,
    /// Optional offset/depth anchor — applies to ALL patterns
    /// in the signature uniformly. Matches Suricata's
    /// `offset` / `depth` keywords being signature-scoped
    /// rather than per-content. For per-pattern anchors,
    /// split into multiple signatures.
    #[serde(rename = "a", default)]
    pub anchor: Anchor,
}

fn is_default_port_filter(f: &PortFilter) -> bool {
    f.source.is_none() && f.destination.is_none()
}

impl Signature {
    /// True if the (proto, sport, dport) tuple from a flow
    /// matches this signature's pre-filter. Cheap; called
    /// for every payload before any pattern matching runs.
    #[must_use]
    pub fn applies_to(&self, proto: IpProtocol, sport: u16, dport: u16) -> bool {
        if self.protocol != proto {
            return false;
        }
        self.ports.permits(sport, dport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn severity_wire_strings_match_event_field() {
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Critical.as_str(), "critical");
    }

    #[test]
    fn severity_ordering_is_total() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn action_wire_strings_match_event_field() {
        assert_eq!(Action::Alert.as_str(), "alert");
        assert_eq!(Action::Drop.as_str(), "drop");
        assert_eq!(Action::Reset.as_str(), "reset");
        assert_eq!(Action::Block.as_str(), "block");
    }

    #[test]
    fn terminal_actions_match_definition() {
        assert!(!Action::Alert.is_terminal());
        assert!(Action::Drop.is_terminal());
        assert!(Action::Reset.is_terminal());
        assert!(Action::Block.is_terminal());
    }

    #[test]
    fn pattern_as_literal_returns_bytes() {
        let p = Pattern::Literal(b"' OR '1'='1".to_vec());
        assert_eq!(p.as_literal(), Some(b"' OR '1'='1".as_slice()));
        assert_eq!(p.as_regex(), None);
    }

    #[test]
    fn pattern_as_regex_returns_source() {
        let p = Pattern::Regex(r"(?i)union\s+select".into());
        assert_eq!(p.as_regex(), Some(r"(?i)union\s+select"));
        assert_eq!(p.as_literal(), None);
    }

    #[test]
    fn anchor_default_permits_any_position() {
        let a = Anchor::default();
        assert!(a.permits(0, 1));
        assert!(a.permits(1024, 8));
        assert!(a.permits(usize::MAX - 1, 1));
    }

    #[test]
    fn anchor_offset_rejects_earlier_matches() {
        let a = Anchor {
            offset: Some(16),
            depth: None,
        };
        assert!(!a.permits(0, 4));
        assert!(!a.permits(15, 4));
        assert!(a.permits(16, 4));
        assert!(a.permits(1000, 4));
    }

    #[test]
    fn anchor_depth_rejects_matches_past_window() {
        let a = Anchor {
            offset: None,
            depth: Some(32),
        };
        assert!(a.permits(0, 32));
        assert!(!a.permits(0, 33));
        assert!(!a.permits(28, 8));
        assert!(a.permits(28, 4));
    }

    #[test]
    fn anchor_offset_plus_depth_creates_window() {
        let a = Anchor {
            offset: Some(8),
            depth: Some(16),
        };
        // Window is [8, 24).
        assert!(!a.permits(7, 1));
        assert!(a.permits(8, 1));
        assert!(a.permits(20, 4));
        assert!(!a.permits(20, 5));
        assert!(!a.permits(24, 1));
    }

    #[test]
    fn port_filter_default_permits_any() {
        let pf = PortFilter::default();
        assert!(pf.permits(443, 80));
        assert!(pf.permits(0, 0));
    }

    #[test]
    fn port_filter_source_narrows() {
        let pf = PortFilter {
            source: Some(443),
            destination: None,
        };
        assert!(pf.permits(443, 80));
        assert!(!pf.permits(80, 80));
    }

    #[test]
    fn port_filter_destination_narrows() {
        let pf = PortFilter {
            source: None,
            destination: Some(80),
        };
        assert!(pf.permits(0, 80));
        assert!(!pf.permits(0, 443));
    }

    #[test]
    fn port_filter_both_required_match() {
        let pf = PortFilter {
            source: Some(0),
            destination: Some(80),
        };
        assert!(pf.permits(0, 80));
        assert!(!pf.permits(0, 443));
        assert!(!pf.permits(443, 80));
    }

    #[test]
    fn signature_applies_to_filters_protocol() {
        let s = Signature {
            sid: 100,
            msg: "test".into(),
            severity: Severity::Low,
            action: Action::Alert,
            protocol: IpProtocol::Tcp,
            ports: PortFilter::default(),
            patterns: vec![Pattern::Literal(b"x".to_vec())],
            anchor: Anchor::default(),
        };
        assert!(s.applies_to(IpProtocol::Tcp, 0, 0));
        assert!(!s.applies_to(IpProtocol::Udp, 0, 0));
    }

    #[test]
    fn signature_applies_to_respects_port_filter() {
        let s = Signature {
            sid: 100,
            msg: "test".into(),
            severity: Severity::Low,
            action: Action::Alert,
            protocol: IpProtocol::Tcp,
            ports: PortFilter {
                source: None,
                destination: Some(80),
            },
            patterns: vec![Pattern::Literal(b"x".to_vec())],
            anchor: Anchor::default(),
        };
        assert!(s.applies_to(IpProtocol::Tcp, 0, 80));
        assert!(!s.applies_to(IpProtocol::Tcp, 0, 443));
    }

    #[test]
    fn signature_serde_roundtrips_through_json() {
        let sig = Signature {
            sid: 1001,
            msg: "SQLi blind union".into(),
            severity: Severity::High,
            action: Action::Reset,
            protocol: IpProtocol::Tcp,
            ports: PortFilter {
                source: None,
                destination: Some(80),
            },
            patterns: vec![
                Pattern::Literal(b"' OR '1'='1".to_vec()),
                Pattern::Regex(r"(?i)union\s+select".into()),
            ],
            anchor: Anchor {
                offset: Some(0),
                depth: Some(8192),
            },
        };
        let s = serde_json::to_string(&sig).unwrap();
        let round: Signature = serde_json::from_str(&s).unwrap();
        assert_eq!(sig, round);
    }
}
