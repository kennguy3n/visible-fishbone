//! Dual-WAN automatic failover.
//!
//! [`FailoverEngine`] owns the *currently-active* path for
//! a primary/backup group and switches it on SLA health
//! transitions. The design target is **sub-second
//! failover**: the engine pre-computes the active path on
//! every health change and stores it behind an
//! [`arc_swap::ArcSwap`], so the data path's switch is a
//! single wait-free atomic load — no scan of the backup
//! list, no lock, no allocation on the hot read path.
//!
//! ## Model
//!
//! - [`FailoverPolicy`] declares an ordered group: one
//!   `primary_path` and a priority-ordered list of
//!   `backup_paths`. The first healthy member of
//!   `[primary, backups…]` is the active path.
//! - Health is driven externally: the
//!   [`crate::sla::SlaMonitor`] (or any liveness source)
//!   calls [`FailoverEngine::on_violation`] /
//!   [`FailoverEngine::on_recovery`] as paths breach and
//!   recover their SLA. The engine never probes directly —
//!   it stays I/O-free and deterministic.
//! - [`FailbackMode`] controls what happens when the
//!   primary recovers: `Immediate` switches back at once,
//!   `Manual` holds on the backup until an operator calls
//!   [`FailoverEngine::manual_failback`], and
//!   `DelaySeconds` waits a stabilisation window (checked
//!   by [`FailoverEngine::poll`]) to avoid flapping on a
//!   primary that recovers and re-breaches repeatedly.

use std::collections::HashSet;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::SdwanError;
use crate::path::PathId;

/// What the engine does when the primary path recovers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FailbackMode {
    /// Switch back to the highest-priority healthy member
    /// (normally the primary) the instant it recovers.
    Immediate,
    /// Stay on the current backup after recovery; an
    /// operator triggers the switch-back explicitly via
    /// [`FailoverEngine::manual_failback`].
    Manual,
    /// Wait `seconds` of sustained primary health before
    /// switching back. Dampens flapping when a primary
    /// recovers then re-breaches inside the window.
    Delay {
        /// Stabilisation window in seconds.
        seconds: u64,
    },
}

impl FailbackMode {
    /// Wire string for telemetry / dashboards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Manual => "manual",
            Self::Delay { .. } => "delay",
        }
    }
}

/// An ordered primary/backup failover group.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FailoverPolicy {
    /// The preferred path while healthy.
    pub primary_path: PathId,
    /// Backup paths in descending priority. The first
    /// healthy backup wins when the primary is unhealthy.
    #[serde(default)]
    pub backup_paths: Vec<PathId>,
    /// Failback behaviour on primary recovery.
    pub failback: FailbackMode,
}

impl FailoverPolicy {
    /// Construct an `Immediate`-failback policy.
    pub fn new<I>(primary_path: impl Into<PathId>, backup_paths: I) -> Self
    where
        I: IntoIterator<Item = PathId>,
    {
        Self {
            primary_path: primary_path.into(),
            backup_paths: backup_paths.into_iter().collect(),
            failback: FailbackMode::Immediate,
        }
    }

    /// Set the failback mode (builder shape).
    #[must_use]
    pub fn with_failback(mut self, failback: FailbackMode) -> Self {
        self.failback = failback;
        self
    }

    /// The ordered member list `[primary, backups…]`.
    fn members(&self) -> impl Iterator<Item = &PathId> {
        std::iter::once(&self.primary_path).chain(self.backup_paths.iter())
    }

    /// Validate the value domain.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when the
    /// primary id is empty, when any backup id is empty,
    /// or when a path id appears more than once (an
    /// ambiguous priority order).
    pub fn validate(&self) -> Result<(), SdwanError> {
        if self.primary_path.as_str().is_empty() {
            return Err(SdwanError::InvalidPolicy(
                "failover.primary_path must not be empty".into(),
            ));
        }
        let mut seen = HashSet::new();
        for member in self.members() {
            if member.as_str().is_empty() {
                return Err(SdwanError::InvalidPolicy(
                    "failover backup path id must not be empty".into(),
                ));
            }
            if !seen.insert(member) {
                return Err(SdwanError::InvalidPolicy(format!(
                    "failover path {:?} appears more than once",
                    member.as_str()
                )));
            }
        }
        Ok(())
    }
}

/// Mutable failover state, guarded by a single mutex. The
/// *resolved* active path is mirrored into the engine's
/// `ArcSwap` on every change so reads stay lock-free.
#[derive(Debug)]
struct FailoverState {
    /// Paths currently considered unhealthy.
    unhealthy: HashSet<PathId>,
    /// For `DelaySeconds` failback: the wall-clock ms at
    /// which the primary became continuously healthy
    /// again while a backup was active. `None` when the
    /// primary is unhealthy or already active.
    primary_healthy_since_ms: Option<u64>,
}

/// The number of failover switches the engine has
/// performed, exposed for observability.
#[derive(Debug, Default)]
struct FailoverCounters {
    switches: std::sync::atomic::AtomicU64,
}

/// Owns the active path for one [`FailoverPolicy`] and
/// switches it on health transitions.
#[derive(Debug)]
pub struct FailoverEngine {
    policy: FailoverPolicy,
    // Pre-computed active path. The data path reads this
    // with one atomic load — the "single atomic path-table
    // update" the failover target requires.
    active: ArcSwap<PathId>,
    state: Mutex<FailoverState>,
    counters: FailoverCounters,
}

impl FailoverEngine {
    /// Construct an engine for `policy`, starting on the
    /// primary path (all members assumed healthy).
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when `policy`
    /// fails [`FailoverPolicy::validate`].
    pub fn new(policy: FailoverPolicy) -> Result<Self, SdwanError> {
        policy.validate()?;
        let active = ArcSwap::from_pointee(policy.primary_path.clone());
        Ok(Self {
            policy,
            active,
            state: Mutex::new(FailoverState {
                unhealthy: HashSet::new(),
                primary_healthy_since_ms: None,
            }),
            counters: FailoverCounters::default(),
        })
    }

    /// The currently-active path. Wait-free single atomic
    /// load — this is the read the data path performs per
    /// flow to decide which underlay to use.
    #[must_use]
    pub fn active(&self) -> PathId {
        PathId::clone(&self.active.load_full())
    }

    /// The configured policy.
    #[must_use]
    pub fn policy(&self) -> &FailoverPolicy {
        &self.policy
    }

    /// Cumulative number of active-path switches performed.
    #[must_use]
    pub fn switches(&self) -> u64 {
        self.counters
            .switches
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True iff `path` is currently marked unhealthy.
    #[must_use]
    pub fn is_unhealthy(&self, path: &PathId) -> bool {
        self.state.lock().unhealthy.contains(path)
    }

    /// Record that `path` breached its SLA. Marks it
    /// unhealthy and recomputes the active path. If the
    /// path was the active one, the switch to the next
    /// healthy member is published atomically before this
    /// returns.
    pub fn on_violation(&self, path: &PathId, now_ms: u64) {
        let mut state = self.state.lock();
        state.unhealthy.insert(path.clone());
        if *path == self.policy.primary_path {
            // Primary is down — cancel any pending failback
            // timer.
            state.primary_healthy_since_ms = None;
        }
        self.recompute(&mut state, now_ms);
    }

    /// Record that `path` recovered its SLA. Clears the
    /// unhealthy mark and, subject to [`FailbackMode`],
    /// may switch back.
    pub fn on_recovery(&self, path: &PathId, now_ms: u64) {
        let mut state = self.state.lock();
        state.unhealthy.remove(path);
        if *path == self.policy.primary_path {
            // Arm the failback timer for DelaySeconds mode;
            // Immediate/Manual ignore it.
            state.primary_healthy_since_ms = Some(now_ms);
        }
        self.recompute(&mut state, now_ms);
    }

    /// Operator-triggered failback for [`FailbackMode::Manual`].
    /// Recomputes the active path as if failback were due;
    /// a no-op when the primary is still unhealthy.
    pub fn manual_failback(&self, now_ms: u64) {
        let mut state = self.state.lock();
        // Force the timer open so `recompute` treats the
        // primary as failback-eligible this pass.
        if !state.unhealthy.contains(&self.policy.primary_path) {
            state.primary_healthy_since_ms = Some(0);
        }
        self.recompute_force_failback(&mut state, now_ms);
    }

    /// Drive time-based transitions ([`FailbackMode::Delay`]).
    /// Call periodically (e.g. from the SLA monitor's tick).
    /// Switches back to the primary once it has been healthy
    /// for the configured window.
    pub fn poll(&self, now_ms: u64) {
        let mut state = self.state.lock();
        self.recompute(&mut state, now_ms);
    }

    /// Recompute the active path under the standard
    /// failback rules and publish it if it changed.
    fn recompute(&self, state: &mut FailoverState, now_ms: u64) {
        let resolved = self.resolve_active(state, now_ms, false);
        self.publish(resolved);
    }

    /// Recompute treating the primary as failback-eligible
    /// regardless of the delay window (used by
    /// [`Self::manual_failback`]).
    fn recompute_force_failback(&self, state: &mut FailoverState, now_ms: u64) {
        let resolved = self.resolve_active(state, now_ms, true);
        self.publish(resolved);
    }

    /// Resolve the path that should be active given the
    /// current health set and failback policy.
    fn resolve_active(&self, state: &FailoverState, now_ms: u64, force_failback: bool) -> PathId {
        let primary = &self.policy.primary_path;
        let primary_healthy = !state.unhealthy.contains(primary);
        let currently_on_primary = *self.active.load_full().as_ref() == *primary;

        // When the primary is healthy, whether we return to
        // it depends on the failback policy — but only if we
        // are not already on it (no policy gate needed to
        // *stay* on a healthy primary).
        if primary_healthy {
            if currently_on_primary {
                return primary.clone();
            }
            if force_failback || self.failback_due(state, now_ms) {
                return primary.clone();
            }
            // Failback not yet due: keep serving from the
            // best healthy backup so we don't strand the
            // flow, but leave the primary timer running.
            return self
                .first_healthy_backup(state)
                .unwrap_or_else(|| primary.clone());
        }

        // Primary unhealthy: first healthy member in
        // priority order, falling back to the primary id
        // itself when everything is down (fail to a defined
        // path rather than an empty one — the data path
        // treats a down primary as deny via the selector).
        self.first_healthy_member(state)
            .unwrap_or_else(|| primary.clone())
    }

    /// Whether a primary failback is due under the policy.
    fn failback_due(&self, state: &FailoverState, now_ms: u64) -> bool {
        match self.policy.failback {
            FailbackMode::Immediate => true,
            FailbackMode::Manual => false,
            FailbackMode::Delay { seconds } => match state.primary_healthy_since_ms {
                Some(since) => now_ms.saturating_sub(since) >= seconds.saturating_mul(1_000),
                None => false,
            },
        }
    }

    /// First healthy member of `[primary, backups…]`.
    fn first_healthy_member(&self, state: &FailoverState) -> Option<PathId> {
        self.policy
            .members()
            .find(|m| !state.unhealthy.contains(*m))
            .cloned()
    }

    /// First healthy backup (excludes the primary).
    fn first_healthy_backup(&self, state: &FailoverState) -> Option<PathId> {
        self.policy
            .backup_paths
            .iter()
            .find(|m| !state.unhealthy.contains(*m))
            .cloned()
    }

    /// Atomically publish `resolved` as the active path,
    /// bumping the switch counter when it actually changed.
    fn publish(&self, resolved: PathId) {
        let current = self.active.load_full();
        if *current.as_ref() != resolved {
            self.active.store(Arc::new(resolved));
            self.counters
                .switches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn engine(failback: FailbackMode) -> FailoverEngine {
        let policy = FailoverPolicy::new(
            PathId::new("mpls"),
            [PathId::new("inet"), PathId::new("lte")],
        )
        .with_failback(failback);
        FailoverEngine::new(policy).expect("valid policy")
    }

    #[test]
    fn starts_on_primary() {
        let e = engine(FailbackMode::Immediate);
        assert_eq!(e.active(), PathId::new("mpls"));
        assert_eq!(e.switches(), 0);
    }

    #[test]
    fn primary_violation_switches_to_first_backup() {
        let e = engine(FailbackMode::Immediate);
        e.on_violation(&PathId::new("mpls"), 1_000);
        assert_eq!(e.active(), PathId::new("inet"));
        assert_eq!(e.switches(), 1);
    }

    #[test]
    fn cascading_violations_walk_the_backup_order() {
        let e = engine(FailbackMode::Immediate);
        e.on_violation(&PathId::new("mpls"), 1_000);
        assert_eq!(e.active(), PathId::new("inet"));
        e.on_violation(&PathId::new("inet"), 1_100);
        assert_eq!(e.active(), PathId::new("lte"));
    }

    #[test]
    fn immediate_failback_returns_to_primary_on_recovery() {
        let e = engine(FailbackMode::Immediate);
        e.on_violation(&PathId::new("mpls"), 1_000);
        assert_eq!(e.active(), PathId::new("inet"));
        e.on_recovery(&PathId::new("mpls"), 2_000);
        assert_eq!(e.active(), PathId::new("mpls"));
    }

    #[test]
    fn manual_failback_holds_on_backup_until_triggered() {
        let e = engine(FailbackMode::Manual);
        e.on_violation(&PathId::new("mpls"), 1_000);
        assert_eq!(e.active(), PathId::new("inet"));
        // Primary recovers but we stay on the backup.
        e.on_recovery(&PathId::new("mpls"), 2_000);
        assert_eq!(e.active(), PathId::new("inet"));
        // Operator triggers the switch-back.
        e.manual_failback(3_000);
        assert_eq!(e.active(), PathId::new("mpls"));
    }

    #[test]
    fn delay_failback_waits_for_stabilisation_window() {
        let e = engine(FailbackMode::Delay { seconds: 10 });
        e.on_violation(&PathId::new("mpls"), 1_000);
        assert_eq!(e.active(), PathId::new("inet"));
        // Primary recovers at t=2s; failback window is 10s.
        e.on_recovery(&PathId::new("mpls"), 2_000);
        assert_eq!(e.active(), PathId::new("inet"));
        // Poll before the window elapses — still on backup.
        e.poll(8_000);
        assert_eq!(e.active(), PathId::new("inet"));
        // Poll after the window — failback to primary.
        e.poll(12_000);
        assert_eq!(e.active(), PathId::new("mpls"));
    }

    #[test]
    fn delay_failback_canceled_if_primary_rebreaches() {
        let e = engine(FailbackMode::Delay { seconds: 10 });
        e.on_violation(&PathId::new("mpls"), 1_000);
        e.on_recovery(&PathId::new("mpls"), 2_000);
        // Primary breaches again before the window elapses.
        e.on_violation(&PathId::new("mpls"), 5_000);
        e.poll(20_000);
        assert_eq!(e.active(), PathId::new("inet"));
    }

    #[test]
    fn all_members_down_stays_on_primary_id() {
        let e = engine(FailbackMode::Immediate);
        e.on_violation(&PathId::new("mpls"), 1_000);
        e.on_violation(&PathId::new("inet"), 1_100);
        e.on_violation(&PathId::new("lte"), 1_200);
        // Nothing healthy — resolve to the primary id (the
        // selector maps a down primary to deny).
        assert_eq!(e.active(), PathId::new("mpls"));
    }

    #[test]
    fn repeated_recovery_does_not_double_count_switches() {
        let e = engine(FailbackMode::Immediate);
        e.on_violation(&PathId::new("mpls"), 1_000); // switch 1
        e.on_recovery(&PathId::new("mpls"), 2_000); // switch 2
        e.on_recovery(&PathId::new("mpls"), 2_500); // no-op
        assert_eq!(e.switches(), 2);
    }

    #[test]
    fn validate_rejects_duplicate_member() {
        let policy = FailoverPolicy::new(PathId::new("mpls"), [PathId::new("mpls")]);
        assert!(FailoverEngine::new(policy).is_err());
    }

    #[test]
    fn validate_rejects_empty_primary() {
        let policy = FailoverPolicy::new(PathId::new(""), [PathId::new("inet")]);
        assert!(FailoverEngine::new(policy).is_err());
    }
}
