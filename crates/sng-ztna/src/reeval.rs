//! Continuous re-evaluation of active ZTNA sessions.
//!
//! [`ReevalLoop`] is the "continuous" half of continuous adaptive
//! ZTNA. Where [`ZtnaService::evaluate`](crate::service::ZtnaService::evaluate)
//! decides access *once*, at the moment a session opens, the
//! re-eval loop periodically re-runs that same evaluator over every
//! live session recorded in the [`SessionTracker`] and tears down
//! the ones whose verdict has flipped to deny — because the device
//! posture decayed, the user's MFA lapsed, the device or user was
//! revoked, or the app was de-listed from the catalog.
//!
//! # Why re-use the evaluator
//!
//! The loop never re-implements the access decision. It rebuilds
//! the original [`AccessRequest`](crate::request::AccessRequest)
//! with a refreshed timestamp and calls
//! [`ZtnaService::evaluate`](crate::service::ZtnaService::evaluate)
//! again. That keeps a single source of truth for "is this access
//! allowed" — every policy rule, the cross-tenant guard, and the
//! revocation check all apply identically on re-evaluation, so a
//! tracked grant can never keep access alive that a fresh request
//! would be denied.
//!
//! # Cadence
//!
//! The sweep interval is read from the live policy snapshot
//! ([`ZtnaPolicy::reeval_interval_ms`](crate::policy::ZtnaPolicy::reeval_interval_ms),
//! default 60 s) on every iteration, so a bundle reload that
//! retunes the interval takes effect on the next cycle without
//! restarting the loop.
//!
//! # Out-of-cycle re-evaluation
//!
//! A device posture push (see the Go-side `posture_push` consumer)
//! should not wait up to a full interval to take effect. The loop
//! exposes [`ReevalLoop::reevaluate_device`] so the posture path
//! can re-evaluate just the sessions on the affected device
//! immediately after the new posture lands, bounding the
//! revocation latency for a posture regression to the push latency
//! rather than the sweep interval.
//!
//! # Revocation events
//!
//! Each torn-down session emits a [`SessionRevoked`] on the
//! caller-supplied channel — `try_send`, never blocking the sweep.
//! Downstream that event drives the proxy to drop the live
//! connection and feeds the audit / telemetry trail. A saturated
//! channel drops the event (counted in [`SweepStats`]); the session
//! is still removed from the tracker, so a dropped notification
//! degrades observability, never safety.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::policy::ZtnaDecisionReason;
use crate::service::ZtnaService;
use crate::session::{AccessGrant, GuardedRemoval, SessionTracker};

/// A millisecond clock supplying "now" to the re-eval loop.
///
/// The one hard contract is *shared time base*: this clock must
/// read the same base the producer stamps on
/// [`AccessRequest`](crate::request::AccessRequest)s, so a grant's
/// recorded timestamp and the loop's "now" are comparable. Freshness
/// (e.g. MFA age) is then `now.saturating_sub(stamp)`.
///
/// Strict monotonicity is *not* required: the only arithmetic on the
/// returned value is `saturating_sub`, so a backward step (NTP slew,
/// leap second) can only shrink a computed age — i.e. err toward
/// *retaining* a session one extra sweep, never toward wrongly
/// revoking it — and the next sweep self-corrects.
/// [`ReevalLoop::with_system_clock`] therefore supplies a wall-clock
/// source. A deployment that wants ages to keep advancing across
/// wall-clock adjustments should pass a monotonic source (e.g. one
/// derived from [`std::time::Instant`]) via [`ReevalLoop::new`],
/// using the same base on its access requests.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Emitted when the re-evaluation loop revokes a session whose
/// verdict flipped from allow to deny.
///
/// Carries enough context for the proxy to drop the right
/// connection and for the audit trail to record *why* without a
/// second lookup. The `reason` is the authoritative deny bucket
/// from the re-evaluation (e.g. `device_posture_insufficient`,
/// `mfa_stale`, `revoked`, `device_not_enrolled`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRevoked {
    /// The revoked session's id.
    pub session_id: String,
    /// Tenant that owned the session.
    pub tenant_id: String,
    /// Application the session targeted.
    pub app_id: String,
    /// Device the session ran on.
    pub device_id: String,
    /// User the session belonged to.
    pub user_id: String,
    /// Authoritative deny reason at re-evaluation.
    pub reason: ZtnaDecisionReason,
    /// Monotonic millisecond timestamp of the revoking sweep.
    pub revoked_at_ms: u64,
}

/// Per-sweep tally returned by [`ReevalLoop::sweep`] and
/// [`ReevalLoop::reevaluate_device`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Sessions re-evaluated and still allowed.
    pub retained: u64,
    /// Sessions revoked (verdict flipped to deny).
    pub revoked: u64,
    /// [`SessionRevoked`] events dropped because the channel was
    /// full. The sessions were still removed from the tracker.
    pub revocation_emit_dropped: u64,
    /// Sessions that disappeared mid-sweep: the grant was cloned
    /// while present but the producer closed the session before this
    /// sweep could act on it (a retained session whose stamp found
    /// nothing, or a deny flip whose guarded remove found nothing).
    /// Counted separately so [`Self::examined`] reconciles exactly
    /// with the number of grants iterated, distinguishing a benign
    /// close race from a retain / revoke.
    pub vanished: u64,
    /// Sessions whose verdict flipped to deny but were *not* revoked
    /// because the producer re-recorded the session (e.g. a step-up
    /// re-auth) between the sweep's clone and the revoke. The stale
    /// verdict was discarded and the refreshed grant left in place to
    /// be judged on its own merits next sweep. Counted separately so
    /// a legitimate re-auth that dodged revocation is observable and
    /// never miscounted as a revoke.
    pub superseded: u64,
}

impl SweepStats {
    /// Total sessions examined by the sweep — every grant the sweep
    /// iterated ends up in exactly one bucket: retained, revoked,
    /// vanished (closed concurrently), or superseded (re-recorded
    /// concurrently).
    #[must_use]
    pub fn examined(&self) -> u64 {
        self.retained + self.revoked + self.vanished + self.superseded
    }
}

/// The continuous re-evaluation loop. Cheap to share via [`Arc`]:
/// every field is itself an `Arc` / clone-cheap handle.
#[derive(Clone)]
pub struct ReevalLoop {
    service: Arc<ZtnaService>,
    tracker: Arc<SessionTracker>,
    revoked_tx: mpsc::Sender<SessionRevoked>,
    clock: ClockFn,
}

impl std::fmt::Debug for ReevalLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReevalLoop")
            .field("service", &self.service)
            .field("tracked_sessions", &self.tracker.len())
            .finish_non_exhaustive()
    }
}

impl ReevalLoop {
    /// Construct a loop over `service` + `tracker`, emitting
    /// revocations on `revoked_tx`, measuring time with `clock`.
    #[must_use]
    pub fn new(
        service: Arc<ZtnaService>,
        tracker: Arc<SessionTracker>,
        revoked_tx: mpsc::Sender<SessionRevoked>,
        clock: ClockFn,
    ) -> Self {
        Self {
            service,
            tracker,
            revoked_tx,
            clock,
        }
    }

    /// Convenience constructor using a wall-clock millisecond time
    /// base (`SystemTime` since the Unix epoch). Suitable when the
    /// producer also stamps wall-clock millis on its access
    /// requests; deployments using a custom monotonic source should
    /// pass that source via [`Self::new`] instead.
    #[must_use]
    pub fn with_system_clock(
        service: Arc<ZtnaService>,
        tracker: Arc<SessionTracker>,
        revoked_tx: mpsc::Sender<SessionRevoked>,
    ) -> Self {
        Self::new(service, tracker, revoked_tx, Arc::new(system_clock_ms))
    }

    /// The tracker this loop re-evaluates. Exposed so the producer
    /// can record / remove grants against the same store the loop
    /// sweeps.
    #[must_use]
    pub fn tracker(&self) -> &Arc<SessionTracker> {
        &self.tracker
    }

    /// The current sweep interval, read live from the policy
    /// snapshot. Always non-zero — [`ZtnaPolicy::validate`](crate::policy::ZtnaPolicy::validate)
    /// rejects a zero interval.
    #[must_use]
    pub fn current_interval(&self) -> Duration {
        let ms = self.service.policy().snapshot().reeval_interval_ms.max(1);
        Duration::from_millis(ms)
    }

    /// Run the continuous re-evaluation loop until `stop` signals
    /// shutdown. Intended to be driven on a Tokio task by the
    /// caller (e.g. `tokio::spawn(loop.clone().run(stop))`).
    ///
    /// The loop sleeps for [`Self::current_interval`] between
    /// sweeps, re-reading the interval each cycle so a policy
    /// reload retunes the cadence without a restart. It exits
    /// promptly when `stop` is set to `true` or when every
    /// [`tokio::sync::watch::Sender`] for `stop` is dropped (the
    /// controlling owner went away).
    pub async fn run(&self, mut stop: tokio::sync::watch::Receiver<bool>) {
        if *stop.borrow() {
            return;
        }
        loop {
            let interval = self.current_interval();
            // Wait for either the interval to elapse (-> sweep) or
            // the stop signal to change (-> re-check / exit). Using
            // a timeout around `changed()` keeps the loop on the
            // `time` + `sync` Tokio features without pulling in the
            // `macros` feature that `select!` would require.
            match tokio::time::timeout(interval, stop.changed()).await {
                // Interval elapsed without a stop signal: sweep.
                Err(_elapsed) => {
                    let now = (self.clock)();
                    self.sweep(now);
                }
                // Stop signal changed: exit if set, else loop.
                Ok(Ok(())) => {
                    if *stop.borrow() {
                        return;
                    }
                }
                // All senders dropped: the owner is gone, shut down.
                Ok(Err(_closed)) => return,
            }
        }
    }

    /// Re-evaluate every tracked session once and revoke any whose
    /// verdict flipped to deny. Walks the tracker one shard at a
    /// time so evaluation never holds a shard lock and peak memory
    /// is bounded to a single shard's grants.
    pub fn sweep(&self, now_ms: u64) -> SweepStats {
        let mut stats = SweepStats::default();
        for idx in 0..self.tracker.shard_count() {
            for grant in self.tracker.shard_grants(idx) {
                self.process_grant(&grant, now_ms, &mut stats);
            }
        }
        stats
    }

    /// Re-evaluate just the sessions running on `device_id` and
    /// revoke any that no longer pass. Used by the posture-push
    /// path to react to a device's posture change out of cycle,
    /// without waiting for the next full sweep.
    pub fn reevaluate_device(&self, device_id: &str, now_ms: u64) -> SweepStats {
        let mut stats = SweepStats::default();
        for grant in self.tracker.sessions_for_device(device_id) {
            self.process_grant(&grant, now_ms, &mut stats);
        }
        stats
    }

    /// Re-evaluate one grant, updating `stats` and (on a flip to
    /// deny) removing the session and emitting a [`SessionRevoked`].
    fn process_grant(&self, grant: &AccessGrant, now_ms: u64, stats: &mut SweepStats) {
        match self.verdict(grant, now_ms) {
            // Still allowed: refresh the grant's evaluation metadata
            // in place and keep it. If the stamp finds nothing the
            // producer closed the session between the shard clone and
            // here — count it as vanished, not retained, so the tally
            // reconciles with the grants iterated.
            None => {
                if self
                    .tracker
                    .mark_evaluated(&grant.session_id, now_ms, ZtnaDecisionReason::Allow)
                {
                    stats.retained += 1;
                } else {
                    stats.vanished += 1;
                }
            }
            // Flipped to deny: tear the session down — but only the
            // exact generation we judged. A guarded remove keyed on
            // the grant's `granted_at_ms` ensures we never delete a
            // session the producer re-recorded in the clone→remove
            // window (a step-up re-auth that refreshed the very
            // credentials this verdict found stale). Removed → revoke;
            // Superseded → a fresh grant survives for next sweep;
            // Absent → the producer closed it concurrently.
            Some(reason) => match self
                .tracker
                .remove_if_unchanged(&grant.session_id, grant.granted_at_ms)
            {
                GuardedRemoval::Removed(_) => {
                    stats.revoked += 1;
                    let event = SessionRevoked {
                        session_id: grant.session_id.clone(),
                        tenant_id: grant.tenant_id.clone(),
                        app_id: grant.request.app_id.clone(),
                        device_id: grant.request.device_id.clone(),
                        user_id: grant.request.user_id.clone(),
                        reason,
                        revoked_at_ms: now_ms,
                    };
                    if self.revoked_tx.try_send(event).is_err() {
                        stats.revocation_emit_dropped += 1;
                    }
                }
                GuardedRemoval::Superseded => stats.superseded += 1,
                GuardedRemoval::Absent => stats.vanished += 1,
            },
        }
    }

    /// Re-run the evaluator for `grant` at `now_ms`. Returns `None`
    /// when access is still allowed, or `Some(reason)` with the
    /// authoritative deny bucket when the verdict has flipped.
    ///
    /// A provider-resolution miss (app de-listed, device
    /// de-enrolled, identity removed) surfaces from
    /// [`ZtnaService::evaluate`](crate::service::ZtnaService::evaluate)
    /// as an `Err`; those are genuine revocation causes — the
    /// session must die — so they map to the corresponding deny
    /// reason rather than being treated as "still allowed".
    fn verdict(&self, grant: &AccessGrant, now_ms: u64) -> Option<ZtnaDecisionReason> {
        let request = grant.reeval_request(now_ms);
        // Telemetry-free evaluation: a sweep re-runs the evaluator over
        // every live session, so it must not flood the access-path
        // telemetry channel nor double-count into the access decision
        // counters. The sweep's own SweepStats + SessionRevoked events
        // are its observability.
        match self.service.evaluate_for_reeval(&request) {
            Ok(decision) => {
                if decision.allow {
                    None
                } else {
                    Some(decision.reason)
                }
            }
            Err(err) => Some(err.as_decision_reason()),
        }
    }
}

/// Wall-clock millisecond time base used by
/// [`ReevalLoop::with_system_clock`].
fn system_clock_ms() -> u64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::app::{App, StaticAppCatalog};
    use crate::device::{DevicePosture, DeviceTrust, StaticDeviceTrustProvider};
    use crate::identity::{StaticIdentityProvider, UserIdentity};
    use crate::policy::{PostureRequirement, StaticRevocationList, ZtnaPolicy, ZtnaPolicyHolder};
    use crate::request::AccessRequest;
    use crate::service::{ZtnaService, ZtnaServiceBuilder};
    use crate::session::AccessGrant;
    use sng_telemetry::TelemetryEvent;

    const TENANT: &str = "t1";

    fn app(id: &str, posture: PostureRequirement, groups: &[&str]) -> App {
        App {
            app_id: id.into(),
            display_name: id.into(),
            host_patterns: vec![],
            required_groups: groups.iter().map(|s| (*s).to_string()).collect(),
            posture_requirement: posture,
            mfa_max_age_override_ms: None,
            conditions: crate::policy::AccessConditions::default(),
            tags: std::collections::HashMap::new(),
        }
    }

    fn device(id: &str, tenant: &str, posture: DevicePosture) -> DeviceTrust {
        DeviceTrust {
            device_id: id.into(),
            tenant_id: tenant.into(),
            posture,
            tags: std::collections::HashMap::new(),
        }
    }

    fn user(id: &str, tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: id.into(),
            tenant_id: tenant.into(),
            groups: groups
                .iter()
                .map(|s| (*s).to_string())
                .collect::<HashSet<_>>(),
            mfa_at_ms,
            tags: std::collections::HashMap::new(),
        }
    }

    /// Build a service with shared, individually-mutable providers
    /// so a test can mutate posture / identity / revocation after a
    /// grant and observe the re-eval verdict change.
    struct Harness {
        service: Arc<ZtnaService>,
        devices: Arc<StaticDeviceTrustProvider>,
        identities: Arc<StaticIdentityProvider>,
        apps: Arc<StaticAppCatalog>,
        revocation: Arc<StaticRevocationList>,
        policy: Arc<ZtnaPolicyHolder>,
        _telemetry_rx: mpsc::Receiver<TelemetryEvent>,
    }

    fn harness(apps: Vec<App>, devices: Vec<DeviceTrust>, users: Vec<UserIdentity>) -> Harness {
        let app_catalog = Arc::new(StaticAppCatalog::new(apps));
        let device_provider = Arc::new(StaticDeviceTrustProvider::new(devices));
        let identity_provider = Arc::new(StaticIdentityProvider::new(users));
        let revocation = Arc::new(StaticRevocationList::default());
        let policy = Arc::new(ZtnaPolicyHolder::new(ZtnaPolicy {
            tenant_id: TENANT.into(),
            ..ZtnaPolicy::default()
        }));
        let (tx, rx) = mpsc::channel(256);
        let service = ZtnaServiceBuilder::new()
            .with_policy(policy.clone())
            .with_app_catalog(app_catalog.clone())
            .with_device_trust(device_provider.clone())
            .with_identity(identity_provider.clone())
            .with_revocation(revocation.clone())
            .build(tx);
        Harness {
            service: Arc::new(service),
            devices: device_provider,
            identities: identity_provider,
            apps: app_catalog,
            revocation,
            policy,
            _telemetry_rx: rx,
        }
    }

    /// The grant epoch every test stamps its sessions / providers at.
    const TEST_EPOCH_MS: u64 = 1_000_000;

    /// A clock backed by a settable cell. Seeded to `now`; the cell is
    /// returned so a test driving [`ReevalLoop::run`] can advance the
    /// loop's notion of time and exercise time-based revocation (MFA /
    /// posture freshness) on the periodic path, not just via direct
    /// `sweep(now)` calls.
    fn settable_clock(now: u64) -> (ClockFn, Arc<std::sync::atomic::AtomicU64>) {
        let cell = Arc::new(std::sync::atomic::AtomicU64::new(now));
        let reader = cell.clone();
        let clock: ClockFn = Arc::new(move || reader.load(std::sync::atomic::Ordering::Relaxed));
        (clock, cell)
    }

    fn loop_with(
        h: &Harness,
    ) -> (
        ReevalLoop,
        Arc<SessionTracker>,
        mpsc::Receiver<SessionRevoked>,
    ) {
        let tracker = Arc::new(SessionTracker::with_shards(8));
        let (tx, rx) = mpsc::channel(256);
        // Seed the loop clock to the grant epoch (not 0): freshness
        // budgets are `now - stamped_at`, so a zero clock would make
        // every age `0` (saturating) and mask any time-based verdict
        // on the `run` path. Tests that want to age the clock forward
        // use `settable_clock` directly.
        let (clock, _) = settable_clock(TEST_EPOCH_MS);
        let lp = ReevalLoop::new(h.service.clone(), tracker.clone(), tx, clock);
        (lp, tracker, rx)
    }

    /// Record a session for `now` after confirming it currently
    /// evaluates to allow.
    fn grant_session(
        h: &Harness,
        tracker: &SessionTracker,
        session: &str,
        device: &str,
        user: &str,
        app: &str,
        now: u64,
    ) {
        let req = AccessRequest::new(app, device, user, now);
        let decision = h.service.evaluate(&req).expect("grant-time evaluation");
        assert!(decision.allow, "precondition: session must start allowed");
        tracker.record(AccessGrant::new(session, TENANT, req, now));
    }

    #[test]
    fn posture_degrades_revokes_session() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::BASIC, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // Posture degrades below the app's floor (disk encryption
        // off + OS unpatched drops the score (to 50) under the
        // app's BASIC floor (60).
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                disk_encrypted: false,
                os_patched: false,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert_eq!(stats.retained, 0);
        assert!(!tracker.contains("s1"), "revoked session must be removed");
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.session_id, "s1");
        assert_eq!(ev.reason, ZtnaDecisionReason::DevicePostureInsufficient);
        assert_eq!(ev.tenant_id, TENANT);
    }

    #[test]
    fn degraded_edr_revokes_session() {
        // App demands a healthy EDR sensor via the hard gate but
        // imposes no score floor, so only the EDR signal can flip
        // the verdict — isolating the new gate from the weighted
        // score.
        let now = TEST_EPOCH_MS;
        let h = harness(
            vec![app(
                "crm",
                PostureRequirement::new(0).with_require_edr(true),
                &[],
            )],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "crm", now);

        // The EDR sensor is killed; every other signal (and the
        // score, which still reads 100) stays healthy.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                edr_healthy: false,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"), "killed EDR must revoke");
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::DevicePostureInsufficient);
    }

    #[test]
    fn stale_av_definitions_revoke_session() {
        let now = TEST_EPOCH_MS;
        let h = harness(
            vec![app(
                "crm",
                PostureRequirement::new(0).with_max_av_definition_age_hours(24),
                &[],
            )],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "crm", now);

        // AV stays enabled but its definitions age past the 24h
        // ceiling — the device is now scanning with stale sigs.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                antivirus_definitions_age_hours: 72,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"), "stale AV defs must revoke");
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::DevicePostureInsufficient);
    }

    #[test]
    fn out_of_date_patch_revokes_session_on_posture_push() {
        // Exercise the out-of-cycle posture-push path
        // (`reevaluate_device`) rather than the periodic sweep, so
        // the patch-recency gate is shown to bound revocation
        // latency to the push.
        let now = TEST_EPOCH_MS;
        let h = harness(
            vec![app(
                "crm",
                PostureRequirement::new(0).with_min_patch_days(7),
                &[],
            )],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "crm", now);

        // The most recent OS patch slips to 30 days old, past the
        // app's 7-day cadence. `os_patched` (and thus the score)
        // stays true, proving the gate is what denies.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                os_patch_days_since: 30,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.reevaluate_device("dev-1", now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"), "out-of-date patch must revoke");
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::DevicePostureInsufficient);
    }

    #[test]
    fn healthy_expanded_signals_retain_session() {
        // All three new gates declared at once; a device meeting
        // every one keeps its session through a sweep. Guards
        // against a gate that denies a compliant device.
        let now = TEST_EPOCH_MS;
        let strict = PostureRequirement::new(60)
            .with_require_edr(true)
            .with_min_patch_days(30)
            .with_max_av_definition_age_hours(48);
        let h = harness(
            vec![app("crm", strict, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "crm", now);

        // Re-attest with healthy expanded signals (well within
        // every ceiling) at the same instant.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                os_patch_days_since: 3,
                antivirus_definitions_age_hours: 6,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.retained, 1);
        assert!(tracker.contains("s1"), "compliant device must be retained");
        assert!(
            rx.try_recv().is_err(),
            "no revocation for a compliant device"
        );
    }

    #[test]
    fn sweep_does_not_revoke_a_concurrently_reauthed_session() {
        let now = TEST_EPOCH_MS;
        let h = harness(
            vec![app("wiki", PostureRequirement::BASIC, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);

        // A session opened at the epoch (grant generation == `now`).
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);
        // The sweep clones the grant it is about to judge.
        let stale = tracker.get("s1").expect("session recorded");

        // Posture degrades: judged on its own, this clone flips to deny.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                disk_encrypted: false,
                os_patched: false,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        // Meanwhile the producer re-records the session (a step-up
        // re-auth) with a newer grant generation, after the clone.
        let reauth_at = now + 10;
        let req = AccessRequest::new("wiki", "dev-1", "alice", reauth_at);
        tracker.record(AccessGrant::new("s1", TENANT, req, reauth_at));

        // Acting on the stale verdict must not delete the fresh grant.
        let mut stats = SweepStats::default();
        lp.process_grant(&stale, now, &mut stats);

        assert_eq!(stats.superseded, 1);
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.vanished, 0);
        assert_eq!(stats.examined(), 1);
        assert!(tracker.contains("s1"), "re-authed session must survive");
        assert_eq!(tracker.get("s1").unwrap().granted_at_ms, reauth_at);
        assert!(
            rx.try_recv().is_err(),
            "no revocation event for a superseded session"
        );
    }

    #[test]
    fn mfa_expires_revokes_session() {
        let grant_time = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(grant_time))],
            vec![user("alice", TENANT, &[], grant_time)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", grant_time);

        // Advance the clock past the MFA freshness budget (8h
        // default). Posture stays fresh because attestation age is
        // measured the same way — keep the device re-attesting so
        // only MFA goes stale.
        let mfa_budget = h.policy.snapshot().mfa_max_age_ms;
        let later = grant_time + mfa_budget + 1;
        h.devices
            .record(device("dev-1", TENANT, DevicePosture::pristine(later)));

        let stats = lp.sweep(later);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"));
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::MfaStale);
    }

    #[test]
    fn device_revoked_revokes_session() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // Control plane revokes the device (compromise / theft).
        h.revocation
            .replace_devices(["dev-1".to_owned()].into_iter().collect());

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"));
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::Revoked);
    }

    #[test]
    fn device_de_enrolled_revokes_session() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // Device is offboarded entirely — the trust provider no
        // longer knows it. evaluate() returns Err(DeviceNotEnrolled),
        // which must still revoke the live session.
        h.devices.forget("dev-1");

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"));
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::DeviceNotEnrolled);
    }

    #[test]
    fn identity_removed_revokes_session() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // User is offboarded — the identity provider no longer
        // knows them. evaluate() returns Err(IdentityNotFound),
        // which must revoke the live session.
        h.identities.replace(vec![]);

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"));
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::IdentityNotFound);
    }

    #[test]
    fn posture_improves_session_stays_allowed() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::BASIC, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // Posture is re-attested at full strength (an "improvement"
        // / steady-state healthy push). The session must survive.
        h.devices
            .record(device("dev-1", TENANT, DevicePosture::pristine(now)));

        let stats = lp.sweep(now);
        assert_eq!(stats.retained, 1);
        assert_eq!(stats.revoked, 0);
        assert!(tracker.contains("s1"), "healthy session must be retained");
        assert!(
            rx.try_recv().is_err(),
            "no revocation event for a retained session"
        );
        // The retained grant's evaluation metadata is refreshed.
        assert_eq!(
            tracker.get("s1").unwrap().last_reason,
            ZtnaDecisionReason::Allow
        );
    }

    #[test]
    fn reevaluate_device_only_touches_that_device() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::BASIC, &[])],
            vec![
                device("dev-1", TENANT, DevicePosture::pristine(now)),
                device("dev-2", TENANT, DevicePosture::pristine(now)),
            ],
            vec![
                user("alice", TENANT, &[], now),
                user("bob", TENANT, &[], now),
            ],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);
        grant_session(&h, &tracker, "s2", "dev-2", "bob", "wiki", now);

        // Only dev-1's posture regresses.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                disk_encrypted: false,
                os_patched: false,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));

        let stats = lp.reevaluate_device("dev-1", now);
        assert_eq!(stats.examined(), 1, "only dev-1's session is examined");
        assert_eq!(stats.revoked, 1);
        assert!(!tracker.contains("s1"));
        assert!(tracker.contains("s2"), "dev-2's session is untouched");
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.device_id, "dev-1");
    }

    #[test]
    fn sweep_handles_many_sessions_across_shards() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, _rx) = loop_with(&h);
        for i in 0..1000 {
            grant_session(
                &h,
                &tracker,
                &format!("s{i}"),
                "dev-1",
                "alice",
                "wiki",
                now,
            );
        }
        assert_eq!(tracker.len(), 1000);
        let stats = lp.sweep(now);
        assert_eq!(stats.retained, 1000);
        assert_eq!(stats.revoked, 0);
        assert_eq!(tracker.len(), 1000);
    }

    #[test]
    fn app_delisted_revokes_session() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        // App is removed from the catalog (publisher unpublished it).
        h.apps.replace(vec![]);

        let stats = lp.sweep(now);
        assert_eq!(stats.revoked, 1);
        let ev = rx.try_recv().expect("revocation event emitted");
        assert_eq!(ev.reason, ZtnaDecisionReason::UnknownApp);
    }

    #[tokio::test(start_paused = true)]
    async fn run_sweeps_on_interval_and_stops() {
        let now = 1_000_000;
        let h = harness(
            vec![app("wiki", PostureRequirement::BASIC, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        // Tighten the interval so the paused-clock test advances
        // quickly.
        h.service
            .reload_policy(ZtnaPolicy {
                tenant_id: TENANT.into(),
                reeval_interval_ms: 1_000,
                ..ZtnaPolicy::default()
            })
            .expect("valid policy");
        let (lp, tracker, mut rx) = loop_with(&h);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let lp_run = lp.clone();
        let handle = tokio::spawn(async move { lp_run.run(stop_rx).await });

        // Degrade posture, then let one interval elapse.
        h.devices.record(device(
            "dev-1",
            TENANT,
            DevicePosture {
                disk_encrypted: false,
                os_patched: false,
                attested_at_ms: now,
                ..DevicePosture::pristine(now)
            },
        ));
        tokio::time::advance(Duration::from_millis(1_100)).await;
        // Yield so the spawned loop runs its sweep.
        tokio::task::yield_now().await;

        let ev = rx
            .recv()
            .await
            .expect("revocation event from the running loop");
        assert_eq!(ev.session_id, "s1");
        assert!(!tracker.contains("s1"));

        stop_tx.send(true).expect("signal stop");
        handle.await.expect("loop task joins after stop");
    }

    #[tokio::test(start_paused = true)]
    async fn run_revokes_on_time_based_mfa_expiry() {
        // Regression guard for the `run` path's clock: a session whose
        // MFA ages past its budget must be revoked by the periodic
        // loop even when nothing else about the device or posture
        // changes. A clock pinned at 0 would mask this — every
        // freshness age would saturate to 0 and the session would
        // wrongly survive — so this exercises the loop reading an
        // advancing clock end to end.
        let now = TEST_EPOCH_MS;
        let h = harness(
            vec![app("wiki", PostureRequirement::NONE, &[])],
            vec![device("dev-1", TENANT, DevicePosture::pristine(now))],
            vec![user("alice", TENANT, &[], now)],
        );
        h.service
            .reload_policy(ZtnaPolicy {
                tenant_id: TENANT.into(),
                reeval_interval_ms: 1_000,
                ..ZtnaPolicy::default()
            })
            .expect("valid policy");

        let tracker = Arc::new(SessionTracker::with_shards(8));
        let (tx, mut rx) = mpsc::channel(256);
        let (clock, clock_cell) = settable_clock(now);
        let lp = ReevalLoop::new(h.service.clone(), tracker.clone(), tx, clock);
        grant_session(&h, &tracker, "s1", "dev-1", "alice", "wiki", now);

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let lp_run = lp.clone();
        let handle = tokio::spawn(async move { lp_run.run(stop_rx).await });

        // Age the loop clock past the MFA budget; keep posture fresh
        // by re-attesting at the new time so only MFA goes stale.
        let mfa_budget = h.policy.snapshot().mfa_max_age_ms;
        let later = now + mfa_budget + 1;
        h.devices
            .record(device("dev-1", TENANT, DevicePosture::pristine(later)));
        clock_cell.store(later, std::sync::atomic::Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(1_100)).await;
        tokio::task::yield_now().await;

        let ev = rx
            .recv()
            .await
            .expect("revocation event from the running loop");
        assert_eq!(ev.session_id, "s1");
        assert_eq!(ev.reason, ZtnaDecisionReason::MfaStale);
        assert!(!tracker.contains("s1"));

        stop_tx.send(true).expect("signal stop");
        handle.await.expect("loop task joins after stop");
    }

    #[tokio::test]
    async fn run_exits_immediately_when_stop_already_set() {
        let h = harness(vec![], vec![], vec![]);
        let (lp, _tracker, _rx) = loop_with(&h);
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(true);
        // Should return without hanging.
        lp.run(stop_rx).await;
    }
}
