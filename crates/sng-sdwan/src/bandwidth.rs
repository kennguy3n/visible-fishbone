//! Bandwidth aggregation — bonding multiple WAN links for
//! a single flow class.
//!
//! [`BandwidthAggregator`] spreads packets of one bonded
//! flow class across several underlay paths to exceed a
//! single link's capacity. Each emitted packet carries a
//! monotonically-increasing **sequence number** so the
//! peer (the far-end SD-WAN node) can reorder packets that
//! arrive out of order across links of differing latency.
//!
//! ## Activation gate
//!
//! Bonding is only safe when every member link is healthy:
//! striping a flow across a degraded link injects loss the
//! peer must paper over. The aggregator therefore
//! **activates only when all members are healthy** (and at
//! least [`BandwidthAggregator`]'s `min_members` of them
//! exist). If any member is unhealthy it **degrades to
//! single-path** — every packet goes to the first healthy
//! member — until the link recovers. The returned
//! [`PacketAssignment::bonded`] flag tells the data path
//! which mode produced the assignment.
//!
//! ## Scheduling
//!
//! - [`AggregationMode::RoundRobin`] cycles members evenly.
//! - [`AggregationMode::Weighted`] distributes in
//!   proportion to each member's `weight` (e.g. a 100 Mbps
//!   and a 50 Mbps link get weights 2 and 1).
//!
//! The schedulers are wait-free: a [`std::sync::atomic`]
//! cursor advances per packet, so [`BandwidthAggregator::assign`]
//! allocates nothing on the hot path beyond the returned
//! [`PathId`] clone.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::SdwanError;
use crate::path::PathId;

/// One member link of a bond, with its relative weight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondMember {
    /// The underlay path.
    pub path: PathId,
    /// Relative weight for [`AggregationMode::Weighted`].
    /// Ignored by [`AggregationMode::RoundRobin`]. Must be
    /// non-zero.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

const fn default_weight() -> u32 {
    1
}

impl BondMember {
    /// Construct a member with the given weight.
    pub fn new(path: impl Into<PathId>, weight: u32) -> Self {
        Self {
            path: path.into(),
            weight,
        }
    }
}

/// How packets are distributed across bonded members.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMode {
    /// Even cycling across healthy members.
    RoundRobin,
    /// Distribution proportional to each member's weight.
    Weighted,
}

impl AggregationMode {
    /// Wire string for telemetry / dashboards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Weighted => "weighted",
        }
    }
}

/// The path + sequence number a packet is assigned to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketAssignment {
    /// Underlay path this packet egresses on.
    pub path: PathId,
    /// Per-flow monotonically-increasing sequence number
    /// for peer-side reordering.
    pub seq: u64,
    /// `true` when bonding is active (multiple healthy
    /// members), `false` when degraded to single-path.
    pub bonded: bool,
}

/// Bonds multiple WAN links for one flow class.
#[derive(Debug)]
pub struct BandwidthAggregator {
    members: Vec<BondMember>,
    mode: AggregationMode,
    min_members: usize,
    seq: AtomicU64,
    rr_cursor: AtomicUsize,
    weighted_cursor: AtomicU64,
}

impl BandwidthAggregator {
    /// Construct an aggregator over `members` using `mode`.
    /// The minimum-members threshold for bonding defaults
    /// to 2 (bonding a single link is meaningless).
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when there are
    /// fewer than two members, when any path id is empty,
    /// when a path id is duplicated, or when
    /// [`AggregationMode::Weighted`] is used with any
    /// zero-weight member.
    pub fn new(members: Vec<BondMember>, mode: AggregationMode) -> Result<Self, SdwanError> {
        if members.len() < 2 {
            return Err(SdwanError::InvalidPolicy(
                "bandwidth aggregation needs at least two member links".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for m in &members {
            if m.path.as_str().is_empty() {
                return Err(SdwanError::InvalidPolicy(
                    "bandwidth member path id must not be empty".into(),
                ));
            }
            if !seen.insert(&m.path) {
                return Err(SdwanError::InvalidPolicy(format!(
                    "bandwidth member {:?} appears more than once",
                    m.path.as_str()
                )));
            }
            if mode == AggregationMode::Weighted && m.weight == 0 {
                return Err(SdwanError::InvalidPolicy(format!(
                    "bandwidth member {:?} has zero weight under weighted mode",
                    m.path.as_str()
                )));
            }
        }
        Ok(Self {
            min_members: members.len().min(2),
            members,
            mode,
            seq: AtomicU64::new(0),
            rr_cursor: AtomicUsize::new(0),
            weighted_cursor: AtomicU64::new(0),
        })
    }

    /// The configured members in priority order.
    #[must_use]
    pub fn members(&self) -> &[BondMember] {
        &self.members
    }

    /// The aggregation mode.
    #[must_use]
    pub fn mode(&self) -> AggregationMode {
        self.mode
    }

    /// Assign the next packet to a path, given the set of
    /// currently-healthy paths.
    ///
    /// - All members healthy (and `>= min_members`): bond —
    ///   schedule across members by [`AggregationMode`].
    /// - Some members unhealthy: degrade to single-path —
    ///   the first healthy member, every packet.
    /// - No members healthy: `None`.
    ///
    /// Every returned assignment carries a fresh sequence
    /// number regardless of mode so the peer can reorder
    /// across a bonding ↔ single-path transition without a
    /// sequence discontinuity.
    pub fn assign(&self, healthy: &[PathId]) -> Option<PacketAssignment> {
        let all_healthy = self.members.iter().all(|m| healthy.contains(&m.path));
        let bonded = all_healthy && self.members.len() >= self.min_members;

        if bonded {
            let path = match self.mode {
                AggregationMode::RoundRobin => self.next_round_robin(),
                AggregationMode::Weighted => self.next_weighted(),
            };
            return Some(self.assignment(path, true));
        }

        // Degraded: first healthy member in priority order.
        let path = self
            .members
            .iter()
            .find(|m| healthy.contains(&m.path))
            .map(|m| m.path.clone())?;
        Some(self.assignment(path, false))
    }

    fn assignment(&self, path: PathId, bonded: bool) -> PacketAssignment {
        PacketAssignment {
            path,
            seq: self.seq.fetch_add(1, Ordering::Relaxed),
            bonded,
        }
    }

    fn next_round_robin(&self) -> PathId {
        let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.members.len();
        self.members[idx].path.clone()
    }

    fn next_weighted(&self) -> PathId {
        let total: u64 = self.members.iter().map(|m| u64::from(m.weight)).sum();
        // total is >= members.len() >= 2 (weights validated
        // non-zero), so the modulo is well-defined.
        let pos = self.weighted_cursor.fetch_add(1, Ordering::Relaxed) % total;
        let mut acc = 0u64;
        for m in &self.members {
            acc += u64::from(m.weight);
            if pos < acc {
                return m.path.clone();
            }
        }
        // Unreachable given the modulo bound, but fall back
        // to the last member rather than panicking.
        self.members[self.members.len() - 1].path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn rr() -> BandwidthAggregator {
        BandwidthAggregator::new(
            vec![BondMember::new("inet", 1), BondMember::new("lte", 1)],
            AggregationMode::RoundRobin,
        )
        .expect("valid")
    }

    #[test]
    fn round_robin_alternates_when_all_healthy() {
        let agg = rr();
        let healthy = vec![PathId::new("inet"), PathId::new("lte")];
        let a = agg.assign(&healthy).unwrap();
        let b = agg.assign(&healthy).unwrap();
        let c = agg.assign(&healthy).unwrap();
        assert!(a.bonded && b.bonded && c.bonded);
        assert_eq!(a.path, PathId::new("inet"));
        assert_eq!(b.path, PathId::new("lte"));
        assert_eq!(c.path, PathId::new("inet"));
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let agg = rr();
        let healthy = vec![PathId::new("inet"), PathId::new("lte")];
        let seqs: Vec<u64> = (0..5).map(|_| agg.assign(&healthy).unwrap().seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn degrades_to_single_path_when_member_unhealthy() {
        let agg = rr();
        // Only inet healthy → single-path, all packets inet,
        // bonded=false.
        let healthy = vec![PathId::new("inet")];
        let a = agg.assign(&healthy).unwrap();
        let b = agg.assign(&healthy).unwrap();
        assert!(!a.bonded && !b.bonded);
        assert_eq!(a.path, PathId::new("inet"));
        assert_eq!(b.path, PathId::new("inet"));
        // Sequence still advances across the degraded packets.
        assert_eq!(a.seq + 1, b.seq);
    }

    #[test]
    fn no_healthy_member_yields_none() {
        let agg = rr();
        assert!(agg.assign(&[]).is_none());
    }

    #[test]
    fn weighted_distribution_respects_weights() {
        let agg = BandwidthAggregator::new(
            vec![BondMember::new("big", 3), BondMember::new("small", 1)],
            AggregationMode::Weighted,
        )
        .unwrap();
        let healthy = vec![PathId::new("big"), PathId::new("small")];
        let mut big = 0;
        let mut small = 0;
        for _ in 0..4 {
            let a = agg.assign(&healthy).unwrap();
            if a.path == PathId::new("big") {
                big += 1;
            } else {
                small += 1;
            }
        }
        // Over one full period (weight sum = 4): 3 big, 1 small.
        assert_eq!(big, 3);
        assert_eq!(small, 1);
    }

    #[test]
    fn new_rejects_single_member() {
        let err = BandwidthAggregator::new(
            vec![BondMember::new("inet", 1)],
            AggregationMode::RoundRobin,
        );
        assert!(err.is_err());
    }

    #[test]
    fn new_rejects_duplicate_member() {
        let err = BandwidthAggregator::new(
            vec![BondMember::new("inet", 1), BondMember::new("inet", 1)],
            AggregationMode::RoundRobin,
        );
        assert!(err.is_err());
    }

    #[test]
    fn new_rejects_zero_weight_in_weighted_mode() {
        let err = BandwidthAggregator::new(
            vec![BondMember::new("inet", 0), BondMember::new("lte", 1)],
            AggregationMode::Weighted,
        );
        assert!(err.is_err());
    }

    #[test]
    fn zero_weight_allowed_in_round_robin_mode() {
        // RoundRobin ignores weights, so a zero is harmless.
        let agg = BandwidthAggregator::new(
            vec![BondMember::new("inet", 0), BondMember::new("lte", 0)],
            AggregationMode::RoundRobin,
        );
        assert!(agg.is_ok());
    }
}
