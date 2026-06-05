//! Userspace control plane — loads, pins, and updates the data path.
//!
//! [`XdpControlPlane`] is the single handle the firewall crate's
//! `EbpfBackend` drives. It owns a [`ProgramLoader`] (the no-op model by
//! default, the `aya` kernel loader under the `xdp` feature) plus the
//! authoritative userspace copy of the classification table, hot-path
//! rule set, and egress steering table, so callers can inspect what is
//! installed without reading back from a BPF map.
//!
//! All mutating methods take `&self` — the control plane is built once at
//! startup and shared; interior mutability lives in the loader and in the
//! snapshot/stat fields.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::class::Classifier;
use crate::error::EbpfError;
use crate::firewall::XdpRuleSet;
use crate::loader::{NoopLoader, ProgramLoader, XdpMode};
use crate::tc::EgressSteeringTable;

/// What the data path can do — surfaced to the firewall crate's
/// `DataPathCapabilities` so the edge can reason about which enforcement
/// the eBPF path actually accelerates.
///
/// The four flags are independent capability bits (a struct of named
/// bools rather than a bitflags type to keep the boundary self-describing
/// in logs and JSON), so `struct_excessive_bools` does not apply here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct XdpCapabilities {
    /// True iff a real kernel loader is attached (vs. the userspace
    /// model). Mirrors [`ProgramLoader::is_supported`].
    pub kernel_offload: bool,
    /// XDP ingress classification + L3/L4 firewall is available.
    pub xdp_ingress: bool,
    /// TC egress steering is available.
    pub tc_egress: bool,
    /// Per-flow state, conntrack, and verdict-cache maps are available.
    pub flow_maps: bool,
}

/// Point-in-time counters for the eBPF data path.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct XdpStats {
    /// Hot-path firewall rules currently installed.
    pub rules_active: u64,
    /// Classification entries currently installed.
    pub classification_entries: u64,
    /// Total successful map updates (rules + classification + steering)
    /// since startup.
    pub updates_total: u64,
    /// Total failed map updates since startup.
    pub update_failures: u64,
    /// True iff the programs have been loaded.
    pub loaded: bool,
    /// True iff a real kernel loader backs this control plane.
    pub kernel_offload: bool,
}

/// Snapshot of the userspace-authoritative data-path configuration.
#[derive(Debug, Default)]
struct InstalledState {
    rules: XdpRuleSet,
    classifier: Classifier,
    steering: EgressSteeringTable,
    loaded: bool,
}

/// The eBPF/XDP userspace control plane.
pub struct XdpControlPlane {
    loader: Box<dyn ProgramLoader>,
    state: Mutex<InstalledState>,
    updates_total: AtomicU64,
    update_failures: AtomicU64,
}

impl std::fmt::Debug for XdpControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpControlPlane")
            .field("loader", &self.loader)
            .field("updates_total", &self.updates_total.load(Ordering::Relaxed))
            .field(
                "update_failures",
                &self.update_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl XdpControlPlane {
    /// Build a control plane over an explicit loader.
    #[must_use]
    pub fn new(loader: Box<dyn ProgramLoader>) -> Self {
        Self {
            loader,
            state: Mutex::new(InstalledState::default()),
            updates_total: AtomicU64::new(0),
            update_failures: AtomicU64::new(0),
        }
    }

    /// Build a control plane over the always-available [`NoopLoader`] —
    /// the userspace model used when no kernel offload is present.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(Box::new(NoopLoader::new()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InstalledState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Load the programs and attach them to `iface` (XDP ingress + TC
    /// egress).
    ///
    /// # Errors
    ///
    /// Propagates [`EbpfError`] from the underlying loader.
    pub fn load_and_attach(&self, iface: &str, mode: XdpMode) -> Result<(), EbpfError> {
        self.loader.load()?;
        self.loader.attach_xdp(iface, mode)?;
        self.loader.attach_tc_egress(iface)?;
        self.lock().loaded = true;
        Ok(())
    }

    /// Pin the programs and maps under `base`.
    ///
    /// # Errors
    ///
    /// Propagates [`EbpfError::Pin`] from the loader.
    pub fn pin(&self, base: &Path) -> Result<(), EbpfError> {
        self.loader.pin(base)
    }

    /// Install the hot-path firewall rule set, replacing any previously
    /// installed rules.
    ///
    /// # Errors
    ///
    /// Propagates rule-validation / map-update failures from the loader.
    pub fn install_rules(&self, rules: XdpRuleSet) -> Result<(), EbpfError> {
        self.run_update(rules, |l, r| l.update_rules(r), |s, r| s.rules = r)
    }

    /// Install the classification table, replacing any previous one.
    ///
    /// # Errors
    ///
    /// Propagates map-update failures from the loader.
    pub fn install_classification(&self, classifier: Classifier) -> Result<(), EbpfError> {
        self.run_update(
            classifier,
            |l, c| l.update_classification(c),
            |s, c| s.classifier = c,
        )
    }

    /// Install the egress steering table, replacing any previous one.
    ///
    /// # Errors
    ///
    /// Propagates map-update failures from the loader.
    pub fn install_steering(&self, steering: EgressSteeringTable) -> Result<(), EbpfError> {
        self.run_update(
            steering,
            |l, s| l.update_steering(s),
            |st, s| st.steering = s,
        )
    }

    /// Run a loader update, recording success / failure in the counters
    /// and committing the userspace snapshot only on success. The new
    /// value is borrowed for the loader push, then moved into the
    /// snapshot on success — never cloned.
    fn run_update<T>(
        &self,
        value: T,
        update: impl FnOnce(&dyn ProgramLoader, &T) -> Result<(), EbpfError>,
        commit: impl FnOnce(&mut InstalledState, T),
    ) -> Result<(), EbpfError> {
        match update(self.loader.as_ref(), &value) {
            Ok(()) => {
                commit(&mut self.lock(), value);
                self.updates_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.update_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Capabilities of the underlying data path.
    #[must_use]
    pub fn capabilities(&self) -> XdpCapabilities {
        let kernel = self.loader.is_supported();
        XdpCapabilities {
            kernel_offload: kernel,
            xdp_ingress: true,
            tc_egress: true,
            flow_maps: true,
        }
    }

    /// Point-in-time statistics.
    #[must_use]
    pub fn stats(&self) -> XdpStats {
        let state = self.lock();
        XdpStats {
            rules_active: u64::try_from(state.rules.len()).unwrap_or(u64::MAX),
            classification_entries: u64::try_from(state.classifier.len()).unwrap_or(u64::MAX),
            updates_total: self.updates_total.load(Ordering::Relaxed),
            update_failures: self.update_failures.load(Ordering::Relaxed),
            loaded: state.loaded,
            kernel_offload: self.loader.is_supported(),
        }
    }

    /// True iff the programs have been loaded and attached.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.lock().loaded
    }
}

impl Default for XdpControlPlane {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{ClassRule, Classifier};
    use crate::firewall::{XdpRule, XdpRuleAction, XdpRuleSet};
    use pretty_assertions::assert_eq;
    use sng_core::TrafficClass;

    fn sample_rules() -> XdpRuleSet {
        XdpRuleSet::new(
            vec![
                XdpRule::catch_all("a", XdpRuleAction::Pass),
                XdpRule::catch_all("b", XdpRuleAction::Drop),
            ],
            XdpRuleAction::Drop,
        )
    }

    #[test]
    fn in_memory_load_attach_and_install() {
        let cp = XdpControlPlane::in_memory();
        assert!(!cp.is_loaded());
        cp.load_and_attach("eth0", XdpMode::Skb).unwrap();
        assert!(cp.is_loaded());

        cp.install_rules(sample_rules()).unwrap();
        cp.install_classification(Classifier::new(vec![ClassRule::new(
            "10.0.0.0/8".parse().unwrap(),
            None,
            TrafficClass::TrustedDirect,
        )]))
        .unwrap();
        cp.install_steering(EgressSteeringTable::new()).unwrap();

        let stats = cp.stats();
        assert_eq!(stats.rules_active, 2);
        assert_eq!(stats.classification_entries, 1);
        assert_eq!(stats.updates_total, 3);
        assert_eq!(stats.update_failures, 0);
        assert!(stats.loaded);
        assert!(!stats.kernel_offload);
    }

    #[test]
    fn capabilities_report_userspace_model() {
        let cp = XdpControlPlane::in_memory();
        let caps = cp.capabilities();
        assert!(!caps.kernel_offload);
        assert!(caps.xdp_ingress);
        assert!(caps.tc_egress);
        assert!(caps.flow_maps);
    }

    #[test]
    fn invalid_rules_increment_failure_counter() {
        let cp = XdpControlPlane::in_memory();
        let bad = XdpRuleSet::new(
            vec![XdpRule::catch_all("", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        assert!(cp.install_rules(bad).is_err());
        let stats = cp.stats();
        assert_eq!(stats.updates_total, 0);
        assert_eq!(stats.update_failures, 1);
        // The failed update did not commit a snapshot.
        assert_eq!(stats.rules_active, 0);
    }
}
