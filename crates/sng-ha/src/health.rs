//! Health probing that drives voluntary demotion.
//!
//! The active (Master) instance is only fit to hold the VIP
//! while every *mandatory* signal is green: its data-plane
//! interface is up, the control plane is reachable, Suricata is
//! responsive, and a policy bundle is loaded. If any mandatory
//! probe goes red, the Master must not keep blackholing traffic
//! behind a VIP it can no longer serve — it drops its VRRP
//! priority to [`crate::vrrp::PRIORITY_RELEASE`] so the healthy
//! peer takes over.
//!
//! Each signal is a [`HealthProbe`]. The crate ships two
//! production probe shapes plus a test double:
//!
//! * [`FlagProbe`] reads an [`AtomicBool`] another subsystem
//!   flips — a lock-free, allocation-free read on the health
//!   path. The comms subsystem flips the control-plane flag on
//!   each successful poll, the IPS subsystem flips the Suricata
//!   flag from its stats socket, and the policy-eval subsystem
//!   flips the bundle-loaded flag on first successful swap.
//! * [`InterfaceUpProbe`] reads the Linux
//!   `/sys/class/net/<iface>/operstate` sysfs file (the same
//!   source `ip link` reports `state UP` from). The sysfs root
//!   is injectable so the probe is testable against a temp dir.
//! * [`StaticHealthProbe`] is the `StaticXxxProvider`-style
//!   test double used throughout the workspace.

use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Result of a single probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    /// Probe name (stable, lowercase).
    pub name: &'static str,
    /// Whether this probe is mandatory for holding Master.
    pub mandatory: bool,
    /// Whether the signal is currently green.
    pub healthy: bool,
    /// Optional human-readable detail for the ops log.
    pub detail: Option<String>,
}

/// A single health signal the HA controller polls. Probes are
/// cheap and side-effect-free reads; anything expensive (an
/// actual network round-trip) is performed by the owning
/// subsystem, which publishes its result into a [`FlagProbe`].
#[async_trait]
pub trait HealthProbe: Send + Sync + std::fmt::Debug {
    /// Stable, lowercase probe name.
    fn name(&self) -> &'static str;

    /// Whether a red reading on this probe forces demotion. A
    /// non-mandatory probe contributes to the report but never
    /// triggers a release on its own.
    fn mandatory(&self) -> bool;

    /// Sample the signal.
    async fn check(&self) -> ProbeReport;
}

/// Aggregated verdict across every registered probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthVerdict {
    /// Per-probe detail in registration order.
    pub reports: Vec<ProbeReport>,
    /// `true` when every mandatory probe is green.
    pub fit_for_master: bool,
}

impl HealthVerdict {
    /// Names of the mandatory probes that were red. Empty when
    /// [`Self::fit_for_master`] is `true`.
    #[must_use]
    pub fn failing_mandatory(&self) -> Vec<&'static str> {
        self.reports
            .iter()
            .filter(|r| r.mandatory && !r.healthy)
            .map(|r| r.name)
            .collect()
    }
}

/// Ordered set of probes the controller evaluates each tick.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    probes: Vec<Arc<dyn HealthProbe>>,
}

impl HealthRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a probe, preserving insertion order. Builder
    /// style so the controller can chain registrations.
    #[must_use]
    pub fn with_probe(mut self, probe: Arc<dyn HealthProbe>) -> Self {
        self.probes.push(probe);
        self
    }

    /// Add a probe in place.
    pub fn push(&mut self, probe: Arc<dyn HealthProbe>) {
        self.probes.push(probe);
    }

    /// Number of registered probes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// True when no probes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// Poll every probe and aggregate. With no probes
    /// registered the instance is trivially fit (an HA pair with
    /// no health signals configured behaves like plain VRRP).
    pub async fn evaluate(&self) -> HealthVerdict {
        let mut reports = Vec::with_capacity(self.probes.len());
        let mut fit_for_master = true;
        for probe in &self.probes {
            let report = probe.check().await;
            if report.mandatory && !report.healthy {
                fit_for_master = false;
            }
            reports.push(report);
        }
        HealthVerdict {
            reports,
            fit_for_master,
        }
    }
}

/// Probe backed by an [`AtomicBool`] another subsystem owns.
/// The read is `Ordering::Acquire` so a writer's
/// `Ordering::Release` store is observed; both are lock-free.
#[derive(Clone, Debug)]
pub struct FlagProbe {
    name: &'static str,
    mandatory: bool,
    flag: Arc<AtomicBool>,
}

impl FlagProbe {
    /// Build a probe reading `flag`. The owning subsystem keeps
    /// a clone of the same `Arc<AtomicBool>` and stores into it.
    #[must_use]
    pub fn new(name: &'static str, mandatory: bool, flag: Arc<AtomicBool>) -> Self {
        Self {
            name,
            mandatory,
            flag,
        }
    }

    /// Construct the probe and hand back the shared flag for the
    /// producer side to write through.
    #[must_use]
    pub fn with_handle(
        name: &'static str,
        mandatory: bool,
        initial: bool,
    ) -> (Self, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(initial));
        (Self::new(name, mandatory, Arc::clone(&flag)), flag)
    }
}

#[async_trait]
impl HealthProbe for FlagProbe {
    fn name(&self) -> &'static str {
        self.name
    }

    fn mandatory(&self) -> bool {
        self.mandatory
    }

    async fn check(&self) -> ProbeReport {
        let healthy = self.flag.load(Ordering::Acquire);
        ProbeReport {
            name: self.name,
            mandatory: self.mandatory,
            healthy,
            detail: None,
        }
    }
}

/// Probe that reads the Linux operational state of a network
/// interface from sysfs. Green when `operstate` is `up`.
#[derive(Clone, Debug)]
pub struct InterfaceUpProbe {
    interface: String,
    sysfs_root: PathBuf,
    mandatory: bool,
}

impl InterfaceUpProbe {
    /// Probe `interface` against the real `/sys` mount.
    #[must_use]
    pub fn new(interface: impl Into<String>, mandatory: bool) -> Self {
        Self::with_sysfs_root(interface, "/sys", mandatory)
    }

    /// Probe `interface` against an explicit sysfs root. Tests
    /// point this at a temp dir laid out as
    /// `class/net/<iface>/operstate`.
    #[must_use]
    pub fn with_sysfs_root(
        interface: impl Into<String>,
        sysfs_root: impl Into<PathBuf>,
        mandatory: bool,
    ) -> Self {
        Self {
            interface: interface.into(),
            sysfs_root: sysfs_root.into(),
            mandatory,
        }
    }

    fn operstate_path(&self) -> PathBuf {
        self.sysfs_root
            .join("class")
            .join("net")
            .join(&self.interface)
            .join("operstate")
    }
}

#[async_trait]
impl HealthProbe for InterfaceUpProbe {
    fn name(&self) -> &'static str {
        "interface_up"
    }

    fn mandatory(&self) -> bool {
        self.mandatory
    }

    async fn check(&self) -> ProbeReport {
        let path = self.operstate_path();
        let (healthy, detail) = match tokio::fs::read_to_string(&path).await {
            Ok(s) => {
                let state = s.trim();
                // A loopback-style always-up interface reports
                // `unknown`; a cabled NIC reports `up`/`down`.
                // Treat `up` and `unknown` as serving — `unknown`
                // is what a tap / veth used in lab edge pairs
                // reports and is not a fault.
                let up = state == "up" || state == "unknown";
                (up, Some(format!("{}: operstate={state}", self.interface)))
            }
            Err(e) => (
                false,
                Some(format!("{}: read {}: {e}", self.interface, path.display())),
            ),
        };
        ProbeReport {
            name: self.name(),
            mandatory: self.mandatory,
            healthy,
            detail,
        }
    }
}

/// Test double returning a fixed report. Mirrors the
/// `StaticXxxProvider` doubles used in the other crates.
#[derive(Clone, Debug)]
pub struct StaticHealthProbe {
    name: &'static str,
    mandatory: bool,
    healthy: Arc<AtomicBool>,
}

impl StaticHealthProbe {
    /// Construct with an initial health value.
    #[must_use]
    pub fn new(name: &'static str, mandatory: bool, healthy: bool) -> Self {
        Self {
            name,
            mandatory,
            healthy: Arc::new(AtomicBool::new(healthy)),
        }
    }

    /// Flip the reported health (lets a test drive a recovery /
    /// failure mid-run).
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Release);
    }
}

#[async_trait]
impl HealthProbe for StaticHealthProbe {
    fn name(&self) -> &'static str {
        self.name
    }

    fn mandatory(&self) -> bool {
        self.mandatory
    }

    async fn check(&self) -> ProbeReport {
        ProbeReport {
            name: self.name,
            mandatory: self.mandatory,
            healthy: self.healthy.load(Ordering::Acquire),
            detail: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn empty_registry_is_fit() {
        let v = HealthRegistry::new().evaluate().await;
        assert!(v.fit_for_master);
        assert!(v.reports.is_empty());
    }

    #[tokio::test]
    async fn failing_mandatory_probe_makes_unfit() {
        let reg = HealthRegistry::new()
            .with_probe(Arc::new(StaticHealthProbe::new("a", true, true)))
            .with_probe(Arc::new(StaticHealthProbe::new("b", true, false)));
        let v = reg.evaluate().await;
        assert!(!v.fit_for_master);
        assert_eq!(v.failing_mandatory(), vec!["b"]);
    }

    #[tokio::test]
    async fn failing_optional_probe_does_not_make_unfit() {
        let reg = HealthRegistry::new()
            .with_probe(Arc::new(StaticHealthProbe::new("a", true, true)))
            .with_probe(Arc::new(StaticHealthProbe::new("opt", false, false)));
        let v = reg.evaluate().await;
        assert!(v.fit_for_master);
        assert!(v.failing_mandatory().is_empty());
    }

    #[tokio::test]
    async fn flag_probe_tracks_shared_atomic() {
        let (probe, flag) = FlagProbe::with_handle("cp", true, false);
        assert!(!probe.check().await.healthy);
        flag.store(true, Ordering::Release);
        assert!(probe.check().await.healthy);
    }

    #[tokio::test]
    async fn interface_probe_reads_operstate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let net = dir.path().join("class").join("net").join("eth0");
        tokio::fs::create_dir_all(&net).await.expect("mkdir");
        tokio::fs::write(net.join("operstate"), "up\n")
            .await
            .expect("write");
        let probe = InterfaceUpProbe::with_sysfs_root("eth0", dir.path(), true);
        assert!(probe.check().await.healthy);

        tokio::fs::write(net.join("operstate"), "down\n")
            .await
            .expect("write");
        assert!(!probe.check().await.healthy);
    }

    #[tokio::test]
    async fn interface_probe_missing_file_is_unhealthy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = InterfaceUpProbe::with_sysfs_root("nope0", dir.path(), true);
        let r = probe.check().await;
        assert!(!r.healthy);
        assert!(r.detail.is_some());
    }

    #[tokio::test]
    async fn static_probe_set_healthy_flips_reading() {
        let p = StaticHealthProbe::new("x", true, false);
        assert!(!p.check().await.healthy);
        p.set_healthy(true);
        assert!(p.check().await.healthy);
    }
}
