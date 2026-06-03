//! SLA monitoring — per-class thresholds, breach
//! detection, and violation events.
//!
//! The SD-WAN brain scores paths continuously
//! ([`crate::score::score_path`]) and gates them against
//! per-metric SLO floors ([`crate::SdwanPolicy`]). Those
//! floors answer "is this path good enough to *select*
//! right now?". SLA monitoring answers a different,
//! operator-facing question: "has this path *sustained* a
//! breach long enough that ops should be alerted and
//! failover should kick in?".
//!
//! The two are intentionally decoupled. A single bad
//! probe nudges the score but must not page anyone — a
//! microburst of loss is normal. A breach that persists
//! for [`SlaPolicy::consecutive_breaches`] probe intervals
//! is a real degradation and emits an [`SlaViolation`].
//!
//! ## SLA classes vs. traffic classes
//!
//! [`SlaClass`] is the *named SLA template* an operator
//! assigns to a path — `business-critical`, `real-time`,
//! `best-effort`. It is distinct from
//! [`crate::TrafficClass`] (the steering-eligibility
//! bucket on a [`crate::Path`]) and from
//! [`sng_core::traffic_class::TrafficClass`] (the
//! six-tier security taxonomy the classification engine
//! emits). The control plane compiles per-tenant SLA
//! templates (see `internal/service/policy/sdwan_sla.go`)
//! into the [`SlaPolicySet`] the brain runs against.
//!
//! ## Monitor model
//!
//! [`SlaMonitor`] is the background evaluator. It holds:
//!
//! - an [`SlaPolicySet`] (one [`SlaPolicy`] per assigned
//!   [`SlaClass`]),
//! - a shared [`crate::ProbeProvider`] (the same probe
//!   table the selector reads),
//! - a watch list of `(PathId, SlaClass)` assignments —
//!   which path is held to which SLA template,
//! - a bounded per-path consecutive-breach counter map.
//!
//! Each [`SlaMonitor::tick`] joins every watched path with
//! its latest probe, evaluates it against the assigned
//! policy, advances or resets the path's consecutive-breach
//! counter, and emits an [`SlaViolation`] to telemetry the
//! moment a path's counter reaches the policy's threshold.
//! `tick` is pure-of-IO except for the non-blocking
//! telemetry `try_send`, so it is unit-testable without a
//! runtime. [`SlaMonitor::run`] wraps `tick` in a
//! [`tokio::time::interval`] loop for production wiring.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use sng_core::events::SdwanEvent;
use sng_telemetry::TelemetryEvent;

use crate::error::SdwanError;
use crate::path::PathId;
use crate::probe::{PathProbe, SharedProbeProvider};
use crate::stats::SdwanStats;

/// Named SLA template assigned to a path.
///
/// Wire strings match the Go control plane's default
/// templates (`internal/service/policy/sdwan_sla.go`):
/// `business-critical`, `real-time`, `best-effort`. New
/// variants extend the set rather than renaming existing
/// ones so the bundle wire form stays stable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaClass {
    /// Tightest SLA — low latency + near-zero loss. Maps
    /// from `inspect_full` apps in
    /// [`crate::app_steering`].
    BusinessCritical,
    /// Latency / jitter sensitive media. Maps from
    /// `trusted_media_bypass` apps.
    RealTime,
    /// No SLA enforcement — the path is never reported as
    /// violating.
    BestEffort,
}

impl SlaClass {
    /// Stable wire string. Hyphenated to match the Go
    /// control-plane template names exactly (the serde
    /// representation above is snake_case for JSON bundle
    /// round-trips; this method is the human / template
    /// name used in telemetry labels and the control
    /// plane).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BusinessCritical => "business-critical",
            Self::RealTime => "real-time",
            Self::BestEffort => "best-effort",
        }
    }
}

/// Which metric breached the SLA. Surfaced on
/// [`SlaViolation::breached`] so dashboards attribute a
/// violation to its dominant cause.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaMetric {
    /// `latency_ms` exceeded `max_latency_ms`.
    Latency,
    /// `loss_pct` exceeded `max_loss_pct`.
    Loss,
    /// `jitter_ms` exceeded `max_jitter_ms`.
    Jitter,
    /// Observed throughput fell below
    /// `min_throughput_mbps`.
    Throughput,
}

impl SlaMetric {
    /// Stable wire string for telemetry / dashboards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Loss => "loss",
            Self::Jitter => "jitter",
            Self::Throughput => "throughput",
        }
    }
}

/// Default consecutive-breach count before a violation is
/// emitted. A single bad probe is noise; three in a row
/// is a sustained degradation.
const fn default_consecutive_breaches() -> u32 {
    3
}

/// Per-class SLA thresholds.
///
/// Every threshold is optional — a `None` means the metric
/// is not SLA-gating for this class (it still feeds the
/// score and the selector's SLO floors, which are a
/// separate mechanism). A [`SlaClass::BestEffort`] policy
/// typically leaves every threshold `None`, which makes
/// [`Self::evaluate`] return an empty breach set
/// unconditionally.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlaPolicy {
    /// Maximum tolerated latency in milliseconds.
    #[serde(default)]
    pub max_latency_ms: Option<f32>,
    /// Maximum tolerated loss percent, in `[0, 100]`.
    #[serde(default)]
    pub max_loss_pct: Option<f32>,
    /// Maximum tolerated jitter in milliseconds.
    #[serde(default)]
    pub max_jitter_ms: Option<f32>,
    /// Minimum required throughput in megabits/sec. A path
    /// whose observed throughput drops below this breaches
    /// the SLA. `None` disables the throughput gate.
    #[serde(default)]
    pub min_throughput_mbps: Option<f32>,
    /// Number of consecutive breaching probe intervals
    /// required before a violation is emitted. Clamped to
    /// `>= 1` by [`Self::validate`] — a value of zero would
    /// emit a violation on a clean path.
    #[serde(default = "default_consecutive_breaches")]
    pub consecutive_breaches: u32,
}

impl Default for SlaPolicy {
    fn default() -> Self {
        Self {
            max_latency_ms: None,
            max_loss_pct: None,
            max_jitter_ms: None,
            min_throughput_mbps: None,
            consecutive_breaches: default_consecutive_breaches(),
        }
    }
}

impl SlaPolicy {
    /// Validate the value domain.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when any
    /// threshold is non-finite or negative, when
    /// `max_loss_pct` falls outside `[0, 100]`, or when
    /// `consecutive_breaches` is zero.
    pub fn validate(&self) -> Result<(), SdwanError> {
        check_non_negative("sla.max_latency_ms", self.max_latency_ms)?;
        check_loss("sla.max_loss_pct", self.max_loss_pct)?;
        check_non_negative("sla.max_jitter_ms", self.max_jitter_ms)?;
        check_non_negative("sla.min_throughput_mbps", self.min_throughput_mbps)?;
        if self.consecutive_breaches == 0 {
            return Err(SdwanError::InvalidPolicy(
                "sla.consecutive_breaches must be >= 1 — zero would alert on a clean path".into(),
            ));
        }
        Ok(())
    }

    /// Evaluate one observation against this policy,
    /// returning the set of breached metrics (empty when
    /// the path is inside SLA).
    ///
    /// `throughput_mbps` is supplied separately because
    /// [`PathProbe`] does not carry throughput — the BFD /
    /// flow-stats collector feeds it alongside the probe.
    /// A `None` throughput with a configured
    /// `min_throughput_mbps` is treated as a breach
    /// (fail-closed: we cannot prove the link meets the
    /// floor).
    ///
    /// Non-finite probe metrics fail closed — a `NaN`
    /// latency is reported as a [`SlaMetric::Latency`]
    /// breach rather than silently passing, mirroring the
    /// selector's `probe_is_usable` contract.
    #[must_use]
    pub fn evaluate(&self, probe: &PathProbe, throughput_mbps: Option<f32>) -> Vec<SlaMetric> {
        let mut breaches = Vec::new();
        if let Some(cap) = self.max_latency_ms {
            if !probe.latency_ms.is_finite() || probe.latency_ms > cap {
                breaches.push(SlaMetric::Latency);
            }
        }
        if let Some(cap) = self.max_loss_pct {
            if !probe.loss_pct.is_finite() || probe.loss_pct > cap {
                breaches.push(SlaMetric::Loss);
            }
        }
        if let Some(cap) = self.max_jitter_ms {
            if !probe.jitter_ms.is_finite() || probe.jitter_ms > cap {
                breaches.push(SlaMetric::Jitter);
            }
        }
        if let Some(floor) = self.min_throughput_mbps {
            match throughput_mbps {
                Some(tp) if tp.is_finite() && tp >= floor => {}
                _ => breaches.push(SlaMetric::Throughput),
            }
        }
        breaches
    }
}

fn check_non_negative(label: &str, value: Option<f32>) -> Result<(), SdwanError> {
    if let Some(v) = value {
        if !v.is_finite() || v < 0.0 {
            return Err(SdwanError::InvalidPolicy(format!(
                "{label} must be finite and >= 0"
            )));
        }
    }
    Ok(())
}

fn check_loss(label: &str, value: Option<f32>) -> Result<(), SdwanError> {
    if let Some(v) = value {
        if !v.is_finite() || !(0.0..=100.0).contains(&v) {
            return Err(SdwanError::InvalidPolicy(format!(
                "{label} must be finite and in [0, 100]"
            )));
        }
    }
    Ok(())
}

/// The set of SLA policies the monitor evaluates against,
/// keyed by [`SlaClass`]. Cheap to clone (one `HashMap`
/// clone); the bundle adapter rebuilds this on policy
/// reload.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SlaPolicySet {
    by_class: HashMap<SlaClass, SlaPolicy>,
}

impl SlaPolicySet {
    /// Build from an iterator of `(class, policy)` pairs.
    /// A duplicate class keeps the last entry.
    pub fn from_policies<I>(policies: I) -> Self
    where
        I: IntoIterator<Item = (SlaClass, SlaPolicy)>,
    {
        Self {
            by_class: policies.into_iter().collect(),
        }
    }

    /// The default three-template set matching the Go
    /// control plane: `business-critical` (50 ms / 0.1 %),
    /// `real-time` (15 ms jitter), `best-effort` (no SLA).
    #[must_use]
    pub fn default_templates() -> Self {
        Self::from_policies([
            (
                SlaClass::BusinessCritical,
                SlaPolicy {
                    max_latency_ms: Some(50.0),
                    max_loss_pct: Some(0.1),
                    ..SlaPolicy::default()
                },
            ),
            (
                SlaClass::RealTime,
                SlaPolicy {
                    max_jitter_ms: Some(15.0),
                    ..SlaPolicy::default()
                },
            ),
            (SlaClass::BestEffort, SlaPolicy::default()),
        ])
    }

    /// Policy for `class`, if one is configured.
    #[must_use]
    pub fn get(&self, class: SlaClass) -> Option<&SlaPolicy> {
        self.by_class.get(&class)
    }

    /// Insert / overwrite a class policy.
    pub fn insert(&mut self, class: SlaClass, policy: SlaPolicy) {
        self.by_class.insert(class, policy);
    }

    /// Number of configured class policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_class.len()
    }

    /// True iff no class policies are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_class.is_empty()
    }

    /// Validate every contained policy.
    ///
    /// # Errors
    ///
    /// Propagates the first [`SdwanError::InvalidPolicy`]
    /// from any contained [`SlaPolicy::validate`].
    pub fn validate(&self) -> Result<(), SdwanError> {
        for policy in self.by_class.values() {
            policy.validate()?;
        }
        Ok(())
    }
}

/// A sustained SLA breach on one path.
///
/// Emitted by [`SlaMonitor`] when a watched path's
/// consecutive-breach counter reaches its policy's
/// [`SlaPolicy::consecutive_breaches`] threshold. Carries
/// the structured cause so the failover engine and ops
/// dashboards can react without re-deriving it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlaViolation {
    /// The path that breached.
    pub path_id: PathId,
    /// The SLA template the path is held to.
    pub sla_class: SlaClass,
    /// Which metric(s) breached on the triggering probe.
    pub breached: Vec<SlaMetric>,
    /// Consecutive breaching intervals at emission time
    /// (equals the policy's threshold).
    pub consecutive: u32,
    /// Wall-clock millisecond timestamp of the triggering
    /// evaluation.
    pub observed_at_ms: u64,
}

/// One `(path, SLA class)` assignment the monitor watches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaWatch {
    /// Path to monitor.
    pub path_id: PathId,
    /// SLA template the path is held to.
    pub sla_class: SlaClass,
}

impl SlaWatch {
    /// Convenience constructor.
    pub fn new(path_id: impl Into<PathId>, sla_class: SlaClass) -> Self {
        Self {
            path_id: path_id.into(),
            sla_class,
        }
    }
}

/// Background SLA evaluator.
///
/// See the module docs for the model. Construct via
/// [`SlaMonitor::new`], drive with [`SlaMonitor::tick`]
/// (one evaluation pass) or [`SlaMonitor::run`] (interval
/// loop for production).
pub struct SlaMonitor {
    policies: SlaPolicySet,
    probes: SharedProbeProvider,
    watches: Vec<SlaWatch>,
    telemetry: mpsc::Sender<TelemetryEvent>,
    stats: Arc<SdwanStats>,
    // Per-path consecutive-breach counter. Bounded by the
    // watch-list length (we only ever insert keys drawn
    // from `watches`), so it cannot grow without bound.
    counters: Mutex<HashMap<PathId, u32>>,
}

impl std::fmt::Debug for SlaMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlaMonitor")
            .field("policies", &self.policies)
            .field("probes", &"<provider>")
            .field("watches", &self.watches.len())
            .finish_non_exhaustive()
    }
}

impl SlaMonitor {
    /// Construct a monitor.
    ///
    /// `telemetry` is the same egress channel the
    /// [`crate::SdwanService`] uses; violations are emitted
    /// as [`TelemetryEvent::Sdwan`] events (the SD-WAN wire
    /// shape has no dedicated violation variant, so the
    /// `steering_decision` field carries an
    /// `sla_violation:<class>` label — see
    /// [`Self::tick`]). `stats` credits dropped emissions
    /// via [`SdwanStats::record_telemetry_drop`].
    #[must_use]
    pub fn new(
        policies: SlaPolicySet,
        probes: SharedProbeProvider,
        watches: Vec<SlaWatch>,
        telemetry: mpsc::Sender<TelemetryEvent>,
        stats: Arc<SdwanStats>,
    ) -> Self {
        Self {
            policies,
            probes,
            watches,
            telemetry,
            stats,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Read-only access to the policy set.
    #[must_use]
    pub fn policies(&self) -> &SlaPolicySet {
        &self.policies
    }

    /// The current consecutive-breach count for `path_id`
    /// (zero when the path is inside SLA or unseen).
    #[must_use]
    pub fn breach_count(&self, path_id: &PathId) -> u32 {
        self.counters.lock().get(path_id).copied().unwrap_or(0)
    }

    /// Evaluate every watched path once against its
    /// assigned policy, advancing or resetting the
    /// per-path consecutive-breach counter, and emit an
    /// [`SlaViolation`] for every path that has just
    /// reached its threshold.
    ///
    /// Returns the violations emitted this pass (also sent
    /// to telemetry). A path with no fresh probe, or whose
    /// class has no policy, is skipped (its counter is left
    /// untouched — absence of data is not evidence of a
    /// breach).
    ///
    /// Throughput is not available from the probe provider,
    /// so [`SlaMetric::Throughput`] gates are only evaluated
    /// via [`Self::tick_with_throughput`]; plain `tick`
    /// passes `None` throughput, which breaches a configured
    /// `min_throughput_mbps` (fail-closed). Most deployments
    /// set throughput floors only on classes fed by the
    /// throughput-aware path.
    pub fn tick(&self, now_ms: u64) -> Vec<SlaViolation> {
        self.tick_with_throughput(now_ms, &HashMap::new())
    }

    /// Like [`Self::tick`] but with per-path observed
    /// throughput supplied by the caller (the flow-stats
    /// collector). Paths absent from `throughput` are
    /// evaluated with `None` throughput.
    pub fn tick_with_throughput(
        &self,
        now_ms: u64,
        throughput: &HashMap<PathId, f32>,
    ) -> Vec<SlaViolation> {
        let mut emitted = Vec::new();
        for watch in &self.watches {
            let Some(policy) = self.policies.get(watch.sla_class) else {
                continue;
            };
            let Some(probe) = self.probes.get(&watch.path_id) else {
                continue;
            };
            let tp = throughput.get(&watch.path_id).copied();
            let breaches = policy.evaluate(&probe, tp);
            if let Some(violation) = self.record_evaluation(watch, policy, &breaches, now_ms) {
                self.emit(&violation);
                emitted.push(violation);
            }
        }
        emitted
    }

    /// Advance the per-path counter for one evaluation,
    /// returning a violation when the threshold is reached.
    fn record_evaluation(
        &self,
        watch: &SlaWatch,
        policy: &SlaPolicy,
        breaches: &[SlaMetric],
        now_ms: u64,
    ) -> Option<SlaViolation> {
        let mut counters = self.counters.lock();
        if breaches.is_empty() {
            // Inside SLA — clear any accumulated breach
            // streak so a future violation needs a fresh
            // run of `consecutive_breaches` intervals.
            counters.remove(&watch.path_id);
            return None;
        }
        let count = counters.entry(watch.path_id.clone()).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= policy.consecutive_breaches {
            // Re-arm: reset to zero so we emit once per
            // sustained breach run rather than on every
            // tick past the threshold. Re-entering breach
            // accrues a fresh streak.
            *count = 0;
            Some(SlaViolation {
                path_id: watch.path_id.clone(),
                sla_class: watch.sla_class,
                breached: breaches.to_vec(),
                consecutive: policy.consecutive_breaches,
                observed_at_ms: now_ms,
            })
        } else {
            None
        }
    }

    /// Emit a violation onto the telemetry channel. Never
    /// blocks — a saturated channel drops the event and
    /// credits [`SdwanStats::record_telemetry_drop`].
    fn emit(&self, violation: &SlaViolation) {
        let probe = self.probes.get(&violation.path_id);
        let event = SdwanEvent {
            path_id: violation.path_id.as_str().to_string(),
            latency_ms: probe.map_or(0.0, |p| p.latency_ms),
            loss_pct: probe.map_or(0.0, |p| p.loss_pct),
            jitter_ms: probe.map_or(0.0, |p| p.jitter_ms),
            score: 0.0,
            steering_decision: format!("sla_violation:{}", violation.sla_class.as_str()),
        };
        if self
            .telemetry
            .try_send(TelemetryEvent::Sdwan(event))
            .is_err()
        {
            self.stats.record_telemetry_drop();
        }
    }

    /// Run the monitor as a background task: evaluate every
    /// `interval`, sourcing the wall-clock millisecond
    /// timestamp from `now`, until `shutdown` flips to
    /// `true`.
    ///
    /// The caller owns spawning (`tokio::spawn(monitor.run(...))`)
    /// so this crate need not pull in the tokio runtime
    /// feature. The loop ticks first, then checks shutdown,
    /// so a `true` already latched before the first tick is
    /// honoured promptly.
    pub async fn run(
        self,
        interval: Duration,
        now: impl Fn() -> u64 + Send,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut ticker = tokio::time::interval(interval);
        // Skip missed ticks rather than bursting to catch
        // up — a stalled evaluator must not flood telemetry.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow_and_update() {
                return;
            }
            ticker.tick().await;
            if *shutdown.borrow_and_update() {
                return;
            }
            let _ = self.tick(now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    use crate::probe::StaticProbeProvider;

    fn telemetry() -> (mpsc::Sender<TelemetryEvent>, mpsc::Receiver<TelemetryEvent>) {
        mpsc::channel(16)
    }

    fn monitor_with(
        policies: SlaPolicySet,
        probes: Vec<(PathId, PathProbe)>,
        watches: Vec<SlaWatch>,
    ) -> (SlaMonitor, mpsc::Receiver<TelemetryEvent>) {
        let (tx, rx) = telemetry();
        let provider: SharedProbeProvider = Arc::new(StaticProbeProvider::from_probes(probes));
        let mon = SlaMonitor::new(
            policies,
            provider,
            watches,
            tx,
            Arc::new(SdwanStats::default()),
        );
        (mon, rx)
    }

    #[test]
    fn evaluate_flags_each_breached_metric() {
        let policy = SlaPolicy {
            max_latency_ms: Some(50.0),
            max_loss_pct: Some(0.1),
            max_jitter_ms: Some(15.0),
            min_throughput_mbps: Some(100.0),
            ..SlaPolicy::default()
        };
        let probe = PathProbe::new(80.0, 1.0, 30.0, 1_000);
        let breaches = policy.evaluate(&probe, Some(50.0));
        assert_eq!(
            breaches,
            vec![
                SlaMetric::Latency,
                SlaMetric::Loss,
                SlaMetric::Jitter,
                SlaMetric::Throughput
            ]
        );
    }

    #[test]
    fn evaluate_clean_path_has_no_breaches() {
        let policy = SlaPolicy {
            max_latency_ms: Some(50.0),
            max_loss_pct: Some(0.1),
            ..SlaPolicy::default()
        };
        let probe = PathProbe::new(10.0, 0.0, 1.0, 1_000);
        assert!(policy.evaluate(&probe, None).is_empty());
    }

    #[test]
    fn evaluate_missing_throughput_is_breach_when_floor_set() {
        let policy = SlaPolicy {
            min_throughput_mbps: Some(100.0),
            ..SlaPolicy::default()
        };
        let probe = PathProbe::new(10.0, 0.0, 1.0, 1_000);
        assert_eq!(policy.evaluate(&probe, None), vec![SlaMetric::Throughput]);
    }

    #[test]
    fn evaluate_nan_latency_fails_closed() {
        let policy = SlaPolicy {
            max_latency_ms: Some(50.0),
            ..SlaPolicy::default()
        };
        let probe = PathProbe::new(f32::NAN, 0.0, 1.0, 1_000);
        assert_eq!(policy.evaluate(&probe, None), vec![SlaMetric::Latency]);
    }

    #[test]
    fn violation_emitted_only_after_consecutive_threshold() {
        let policies = SlaPolicySet::from_policies([(
            SlaClass::BusinessCritical,
            SlaPolicy {
                max_latency_ms: Some(50.0),
                consecutive_breaches: 3,
                ..SlaPolicy::default()
            },
        )]);
        let probes = vec![(PathId::new("mpls"), PathProbe::new(90.0, 0.0, 1.0, 1_000))];
        let watches = vec![SlaWatch::new("mpls", SlaClass::BusinessCritical)];
        let (mon, _rx) = monitor_with(policies, probes, watches);

        assert!(mon.tick(1_000).is_empty());
        assert_eq!(mon.breach_count(&PathId::new("mpls")), 1);
        assert!(mon.tick(2_000).is_empty());
        assert_eq!(mon.breach_count(&PathId::new("mpls")), 2);
        let v = mon.tick(3_000);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].sla_class, SlaClass::BusinessCritical);
        assert_eq!(v[0].breached, vec![SlaMetric::Latency]);
        assert_eq!(v[0].consecutive, 3);
        // Counter re-armed to zero after emission.
        assert_eq!(mon.breach_count(&PathId::new("mpls")), 0);
    }

    #[test]
    fn clean_probe_resets_breach_streak() {
        let policies = SlaPolicySet::from_policies([(
            SlaClass::BusinessCritical,
            SlaPolicy {
                max_latency_ms: Some(50.0),
                consecutive_breaches: 3,
                ..SlaPolicy::default()
            },
        )]);
        // Probe is in-SLA; counter must stay at zero.
        let probes = vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 1.0, 1_000))];
        let watches = vec![SlaWatch::new("mpls", SlaClass::BusinessCritical)];
        let (mon, _rx) = monitor_with(policies, probes, watches);
        assert!(mon.tick(1_000).is_empty());
        assert_eq!(mon.breach_count(&PathId::new("mpls")), 0);
    }

    #[test]
    fn violation_event_reaches_telemetry() {
        let policies = SlaPolicySet::from_policies([(
            SlaClass::RealTime,
            SlaPolicy {
                max_jitter_ms: Some(15.0),
                consecutive_breaches: 1,
                ..SlaPolicy::default()
            },
        )]);
        let probes = vec![(PathId::new("lte"), PathProbe::new(20.0, 0.0, 40.0, 1_000))];
        let watches = vec![SlaWatch::new("lte", SlaClass::RealTime)];
        let (mon, mut rx) = monitor_with(policies, probes, watches);
        let v = mon.tick(1_000);
        assert_eq!(v.len(), 1);
        let event = rx.try_recv().expect("violation event on channel");
        match event {
            TelemetryEvent::Sdwan(e) => {
                assert_eq!(e.path_id, "lte");
                assert_eq!(e.steering_decision, "sla_violation:real-time");
                assert_eq!(e.jitter_ms, 40.0);
            }
            other => panic!("unexpected telemetry event: {other:?}"),
        }
    }

    #[test]
    fn best_effort_class_never_violates() {
        let policies = SlaPolicySet::default_templates();
        let probes = vec![(
            PathId::new("inet"),
            PathProbe::new(500.0, 50.0, 99.0, 1_000),
        )];
        let watches = vec![SlaWatch::new("inet", SlaClass::BestEffort)];
        let (mon, _rx) = monitor_with(policies, probes, watches);
        for now in 1..=10 {
            assert!(mon.tick(now * 1_000).is_empty());
        }
    }

    #[test]
    fn validate_rejects_zero_consecutive_breaches() {
        let p = SlaPolicy {
            consecutive_breaches: 0,
            ..SlaPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_loss_above_100() {
        let p = SlaPolicy {
            max_loss_pct: Some(101.0),
            ..SlaPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn default_templates_validate() {
        assert!(SlaPolicySet::default_templates().validate().is_ok());
    }

    #[test]
    fn sla_class_wire_strings_are_stable() {
        assert_eq!(SlaClass::BusinessCritical.as_str(), "business-critical");
        assert_eq!(SlaClass::RealTime.as_str(), "real-time");
        assert_eq!(SlaClass::BestEffort.as_str(), "best-effort");
    }
}
