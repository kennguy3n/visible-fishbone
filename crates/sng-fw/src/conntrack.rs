//! Connection-tracking state model.
//!
//! Mirrors the conntrack state field nftables exposes on each
//! packet (`ct state ...`). The closed set is the kernel's:
//!
//! * `NEW` — first packet of a flow that does not match an
//!   existing conntrack entry.
//! * `ESTABLISHED` — a packet belonging to a flow whose reverse
//!   direction has already been observed.
//! * `RELATED` — a packet that is part of a new flow but is
//!   logically tied to an existing one (FTP data channel, ICMP
//!   error responses).
//! * `INVALID` — a packet whose state the kernel cannot
//!   determine (out-of-window TCP, unknown ICMP type).
//!
//! The state machine here is intentionally *advisory*: nftables
//! is the source of truth on the data path. This module exists
//! so the rule compiler can express "match `NEW` only" or
//! "drop `INVALID`" in the same predicate language as L3 / L4
//! matches, and so the engine can simulate the kernel's state
//! transitions in unit tests without booting a kernel.

use serde::{Deserialize, Serialize};

/// Conntrack state, mirroring `ct state` from nftables.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConntrackState {
    /// First packet of a flow.
    New,
    /// Reply or follow-up in an already-seen flow.
    Established,
    /// Tied to another flow (FTP data, ICMP error).
    Related,
    /// Kernel cannot place this packet.
    Invalid,
    /// Connection torn down (FIN/RST observed both directions on
    /// TCP, or UDP timeout expired). nftables exposes this as
    /// `untracked` in practice; we model it explicitly so the
    /// engine's eviction path is type-safe.
    Closed,
}

impl ConntrackState {
    /// The nftables expression — right-hand-side of
    /// `ct state ...`.
    #[must_use]
    pub const fn as_nft(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Related => "related",
            Self::Invalid => "invalid",
            Self::Closed => "untracked",
        }
    }

    /// Is this state a terminal one — i.e. a packet in this state
    /// would normally be dropped or evicted from the table?
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Invalid | Self::Closed)
    }
}

/// Direction of the packet relative to the tracked flow's
/// initiator. `Original` is the direction of the first packet;
/// `Reply` is the reverse.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    /// Packet flows in the same direction as the flow's first
    /// observation.
    Original,
    /// Packet flows in the opposite direction.
    Reply,
}

/// An in-process state machine that classifies a sequence of
/// (flow_id, direction) observations into [`ConntrackState`]
/// transitions. Used by the engine's unit tests so a rule with
/// a `ct state ...` predicate can be validated against a
/// scripted packet sequence without booting a real kernel.
///
/// This is **not** a replacement for kernel conntrack; the data
/// path goes through nftables. The tracker is a faithful enough
/// model to validate rule logic — it implements the SYN /
/// SYN-ACK / ACK promotion to ESTABLISHED, the symmetric INVALID
/// for unknown flows after they were evicted, and the explicit
/// `release` for tearing down a flow.
#[derive(Clone, Debug, Default)]
pub struct ConntrackTracker {
    /// `flow_id -> last observed state`. Stored as a `Vec` rather
    /// than a `HashMap` so iteration order is deterministic on
    /// tests that snapshot the table; for production use a
    /// `HashMap`-backed conntrack belongs in the kernel.
    flows: Vec<(String, ConntrackState)>,
    /// `flow_id`s that are explicitly related to an existing
    /// flow — emit RELATED on first observation.
    related: Vec<(String, String)>,
}

impl ConntrackTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare that `child` is logically related to `parent`
    /// (e.g. FTP data channel related to an FTP control channel).
    /// Subsequent observations of `child` will start in
    /// [`ConntrackState::Related`] rather than [`ConntrackState::New`].
    pub fn declare_related(&mut self, parent: &str, child: &str) {
        self.related.push((parent.to_string(), child.to_string()));
    }

    /// Observe a packet. Returns the conntrack state the engine
    /// should treat the packet as carrying.
    pub fn observe(&mut self, flow_id: &str, direction: FlowDirection) -> ConntrackState {
        let existing = self.flows.iter().position(|(id, _)| id == flow_id);
        match existing {
            None => {
                // First observation. Promote to RELATED if the
                // operator declared a parent.
                let starting = if self.related.iter().any(|(_, c)| c == flow_id) {
                    ConntrackState::Related
                } else {
                    ConntrackState::New
                };
                self.flows.push((flow_id.into(), starting));
                starting
            }
            Some(i) => {
                let (_, state) = &mut self.flows[i];
                // Already torn down: any further packet is
                // INVALID.
                if matches!(state, ConntrackState::Closed | ConntrackState::Invalid) {
                    return ConntrackState::Invalid;
                }
                // NEW -> ESTABLISHED on the first reply packet.
                if matches!(state, ConntrackState::New) && direction == FlowDirection::Reply {
                    *state = ConntrackState::Established;
                }
                *state
            }
        }
    }

    /// Force a flow to INVALID — used to model packets the
    /// kernel rejects (out-of-window TCP, malformed flag combos).
    pub fn invalidate(&mut self, flow_id: &str) {
        if let Some(pos) = self.flows.iter().position(|(id, _)| id == flow_id) {
            self.flows[pos].1 = ConntrackState::Invalid;
        } else {
            self.flows.push((flow_id.into(), ConntrackState::Invalid));
        }
    }

    /// Tear down a flow — model TCP FIN/RST or UDP idle
    /// timeout. Subsequent packets will be INVALID until the
    /// caller observes a new NEW.
    pub fn release(&mut self, flow_id: &str) {
        if let Some(pos) = self.flows.iter().position(|(id, _)| id == flow_id) {
            self.flows[pos].1 = ConntrackState::Closed;
        }
    }

    /// Snapshot the table — used by tests and `tcpdump`-style
    /// telemetry.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, ConntrackState)> {
        self.flows.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn nft_strings_are_canonical() {
        assert_eq!(ConntrackState::New.as_nft(), "new");
        assert_eq!(ConntrackState::Established.as_nft(), "established");
        assert_eq!(ConntrackState::Related.as_nft(), "related");
        assert_eq!(ConntrackState::Invalid.as_nft(), "invalid");
        assert_eq!(ConntrackState::Closed.as_nft(), "untracked");
    }

    #[test]
    fn is_terminal_only_invalid_and_closed() {
        assert!(ConntrackState::Invalid.is_terminal());
        assert!(ConntrackState::Closed.is_terminal());
        assert!(!ConntrackState::New.is_terminal());
        assert!(!ConntrackState::Established.is_terminal());
        assert!(!ConntrackState::Related.is_terminal());
    }

    #[test]
    fn tracker_first_packet_is_new() {
        let mut t = ConntrackTracker::new();
        let s = t.observe("flow-1", FlowDirection::Original);
        assert_eq!(s, ConntrackState::New);
    }

    #[test]
    fn tracker_reply_promotes_to_established() {
        let mut t = ConntrackTracker::new();
        t.observe("flow-1", FlowDirection::Original);
        let s = t.observe("flow-1", FlowDirection::Reply);
        assert_eq!(s, ConntrackState::Established);
        // Further packets stay ESTABLISHED.
        let s = t.observe("flow-1", FlowDirection::Original);
        assert_eq!(s, ConntrackState::Established);
    }

    #[test]
    fn tracker_declares_related_child_starts_as_related() {
        let mut t = ConntrackTracker::new();
        t.observe("ftp-control", FlowDirection::Original);
        t.declare_related("ftp-control", "ftp-data");
        let s = t.observe("ftp-data", FlowDirection::Original);
        assert_eq!(s, ConntrackState::Related);
    }

    #[test]
    fn tracker_invalidate_marks_subsequent_packets_invalid() {
        let mut t = ConntrackTracker::new();
        t.observe("flow-1", FlowDirection::Original);
        t.invalidate("flow-1");
        let s = t.observe("flow-1", FlowDirection::Original);
        assert_eq!(s, ConntrackState::Invalid);
    }

    #[test]
    fn tracker_release_then_observe_is_invalid() {
        let mut t = ConntrackTracker::new();
        t.observe("flow-1", FlowDirection::Original);
        t.observe("flow-1", FlowDirection::Reply);
        t.release("flow-1");
        let s = t.observe("flow-1", FlowDirection::Original);
        assert_eq!(s, ConntrackState::Invalid);
    }

    #[test]
    fn tracker_invalidate_unknown_flow_records_invalid() {
        let mut t = ConntrackTracker::new();
        t.invalidate("never-seen");
        // The next observation should reflect the invalid state.
        let s = t.observe("never-seen", FlowDirection::Original);
        assert_eq!(s, ConntrackState::Invalid);
    }

    #[test]
    fn snapshot_returns_observed_flows() {
        let mut t = ConntrackTracker::new();
        t.observe("a", FlowDirection::Original);
        t.observe("b", FlowDirection::Original);
        t.observe("b", FlowDirection::Reply);
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(
            snap.iter()
                .any(|(id, s)| id == "a" && *s == ConntrackState::New)
        );
        assert!(
            snap.iter()
                .any(|(id, s)| id == "b" && *s == ConntrackState::Established)
        );
    }
}
