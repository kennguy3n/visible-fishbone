//! TC (traffic-control) egress steering hooks.
//!
//! Classification decides *what* a flow is; egress steering decides
//! *where* it leaves. After the XDP ingress program tags a flow with its
//! [`TrafficClass`], a TC `clsact` egress program reads that tag and
//! redirects or marks the packet onto the right underlay — the SD-WAN
//! overlay for `tunnel_private`, a cloud-connector interface for the
//! inspect tiers, the default route for `trusted_direct`, and so on.
//!
//! This module is the userspace model of the steering map the TC program
//! consumes: a per-[`TrafficClass`] table of [`SteeringTarget`]s. The
//! control plane fills it from the deployment's egress topology and
//! pushes it into the BPF map; the TC hook does a single map lookup per
//! egress packet keyed on the flow's class tag.

use sng_core::TrafficClass;

/// What the TC egress hook does with a packet once it has resolved the
/// flow's class to a target.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SteeringAction {
    /// Leave on the default route, untouched (`TC_ACT_OK`). The fast path
    /// for `trusted_direct`.
    Pass = 0,
    /// Set an `skb` mark and let routing pick the underlay from a policy
    /// route table keyed on the mark. Used where redirection is done by
    /// the kernel's policy routing rather than a direct egress redirect.
    Mark = 1,
    /// Redirect the packet out a specific interface (`bpf_redirect` →
    /// `TC_ACT_REDIRECT`). Used for SD-WAN / cloud-connector egress.
    Redirect = 2,
    /// Drop on egress (`TC_ACT_SHOT`). The egress realisation of the
    /// `block` tier, for defence in depth behind the XDP ingress drop.
    Drop = 3,
}

/// A resolved egress target for one traffic class.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SteeringTarget {
    /// What to do with the packet.
    pub action: SteeringAction,
    /// Explicit padding to align `ifindex`.
    pad: [u8; 3],
    /// Egress interface index for [`SteeringAction::Redirect`]. Zero when
    /// the action does not redirect.
    pub ifindex: u32,
    /// `skb` mark applied for [`SteeringAction::Mark`] (and optionally
    /// alongside a redirect for downstream classification). Zero = no
    /// mark.
    pub mark: u32,
}

impl SteeringTarget {
    /// Pass on the default route with no mark or redirect.
    #[must_use]
    pub const fn pass() -> Self {
        Self {
            action: SteeringAction::Pass,
            pad: [0; 3],
            ifindex: 0,
            mark: 0,
        }
    }

    /// Redirect out `ifindex`, optionally tagging the packet with `mark`.
    #[must_use]
    pub const fn redirect(ifindex: u32, mark: u32) -> Self {
        Self {
            action: SteeringAction::Redirect,
            pad: [0; 3],
            ifindex,
            mark,
        }
    }

    /// Apply `mark` and defer the egress interface choice to policy
    /// routing.
    #[must_use]
    pub const fn mark(mark: u32) -> Self {
        Self {
            action: SteeringAction::Mark,
            pad: [0; 3],
            ifindex: 0,
            mark,
        }
    }

    /// Drop on egress.
    #[must_use]
    pub const fn drop() -> Self {
        Self {
            action: SteeringAction::Drop,
            pad: [0; 3],
            ifindex: 0,
            mark: 0,
        }
    }
}

/// Per-traffic-class egress steering table — the userspace model of the
/// TC steering BPF map.
///
/// Indexed by the six [`TrafficClass`] tiers via the closed
/// [`TrafficClass::all`] ordering, so a lookup is an array index on the
/// class discriminant with no hashing. A class with no explicit target
/// defaults to [`SteeringTarget::pass`] — the safe "leave on the default
/// route" behaviour.
#[derive(Clone, Debug)]
pub struct EgressSteeringTable {
    targets: [SteeringTarget; 6],
}

impl Default for EgressSteeringTable {
    fn default() -> Self {
        // Default topology: drop `block`, pass everything else on the
        // default route. Deployments override per class via `set`.
        let mut table = Self {
            targets: [SteeringTarget::pass(); 6],
        };
        table.set(TrafficClass::Block, SteeringTarget::drop());
        table
    }
}

impl EgressSteeringTable {
    /// New table with every class on [`SteeringTarget::pass`] except
    /// `block`, which drops.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stable array index for a class — its position in
    /// [`TrafficClass::all`].
    ///
    /// Written as an exhaustive `match` (not a runtime search with a
    /// fallback) on purpose: adding a `TrafficClass` variant must be a
    /// *compile* error here, not a silent fail-open. A search with
    /// `unwrap_or(0)` would map any unmodelled class to slot 0
    /// (`TrustedDirect`) — defaulting an unknown class to the most-trusted
    /// egress tier in a security data path is exactly the failure mode to
    /// avoid. The arm order mirrors [`TrafficClass::all`], which
    /// `index_matches_all_ordering` pins so the BPF map layout stays
    /// correct.
    fn index(class: TrafficClass) -> usize {
        match class {
            TrafficClass::TrustedDirect => 0,
            TrafficClass::TrustedMediaBypass => 1,
            TrafficClass::InspectLite => 2,
            TrafficClass::InspectFull => 3,
            TrafficClass::TunnelPrivate => 4,
            TrafficClass::Block => 5,
        }
    }

    /// Set the egress target for `class`.
    pub fn set(&mut self, class: TrafficClass, target: SteeringTarget) {
        self.targets[Self::index(class)] = target;
    }

    /// Resolve the egress target for `class`.
    #[must_use]
    pub fn target_for(&self, class: TrafficClass) -> SteeringTarget {
        self.targets[Self::index(class)]
    }

    /// Borrow the raw target array in [`TrafficClass::all`] order — the
    /// layout pushed into the BPF map.
    #[must_use]
    pub fn targets(&self) -> &[SteeringTarget; 6] {
        &self.targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_drops_block_passes_rest() {
        let t = EgressSteeringTable::new();
        assert_eq!(
            t.target_for(TrafficClass::Block).action,
            SteeringAction::Drop
        );
        for class in TrafficClass::all() {
            if class != TrafficClass::Block {
                assert_eq!(t.target_for(class).action, SteeringAction::Pass);
            }
        }
    }

    #[test]
    fn set_and_resolve_per_class() {
        let mut t = EgressSteeringTable::new();
        t.set(
            TrafficClass::TunnelPrivate,
            SteeringTarget::redirect(7, 0x55),
        );
        let target = t.target_for(TrafficClass::TunnelPrivate);
        assert_eq!(target.action, SteeringAction::Redirect);
        assert_eq!(target.ifindex, 7);
        assert_eq!(target.mark, 0x55);
        // Other classes are unaffected.
        assert_eq!(
            t.target_for(TrafficClass::TrustedDirect).action,
            SteeringAction::Pass
        );
    }

    #[test]
    fn index_matches_all_ordering() {
        // The hardcoded slots in `index` must stay aligned with
        // `TrafficClass::all` ordering — that ordering defines the BPF map
        // layout the TC program reads.
        for (slot, class) in TrafficClass::all().into_iter().enumerate() {
            assert_eq!(EgressSteeringTable::index(class), slot);
        }
    }

    #[test]
    fn every_class_has_a_distinct_slot() {
        // Setting each class to a unique mark must not collide.
        let mut t = EgressSteeringTable::new();
        for (i, class) in TrafficClass::all().into_iter().enumerate() {
            let mark = u32::try_from(i).unwrap() + 1;
            t.set(class, SteeringTarget::mark(mark));
        }
        for (i, class) in TrafficClass::all().into_iter().enumerate() {
            assert_eq!(t.target_for(class).mark, u32::try_from(i).unwrap() + 1);
        }
    }
}
