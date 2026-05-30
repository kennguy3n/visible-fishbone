//! Device trust + posture provider.
//!
//! The agent on a managed device periodically attests
//! the device's posture (disk-encrypted? OS up to date?
//! anti-malware running? firewall on? screen lock < N
//! minutes?). The control plane stores the latest
//! attestation and surfaces it via this provider.
//!
//! The data path's `device_id` is the **mTLS certificate
//! fingerprint** the proxy observed on the incoming
//! connection; the agent registers the same fingerprint
//! with the control plane when it enrolls. So the join
//! between "this connection" and "this device's posture"
//! is deterministic — the cert fingerprint is the key.

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// One posture snapshot. The field set mirrors what the
/// agent reports on `sng-agent` startup + every hour.
///
/// The `struct_excessive_bools` lint normally flags a
/// struct with more than three `bool` fields as a smell
/// (suggesting it should be modelled as flags / an enum).
/// Here the booleans are the *wire shape* the agent emits
/// — disk encryption, OS patch level, antimalware,
/// firewall, screen lock — and the names are part of the
/// dashboard contract. Folding them into a single bitmask
/// would force every dashboard / event / SQL projection
/// to grow a decoder, for no operational gain. Allowed
/// deliberately.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePosture {
    /// Disk encryption is on (FileVault / BitLocker / LUKS).
    pub disk_encrypted: bool,
    /// OS patch level meets the tenant minimum.
    pub os_patched: bool,
    /// Endpoint antimalware is running.
    pub antimalware_running: bool,
    /// Host firewall is on.
    pub firewall_enabled: bool,
    /// Screen lock is configured to engage within the
    /// tenant-required idle window.
    pub screen_lock_configured: bool,
    /// When the agent last submitted this snapshot
    /// (millisecond epoch, monotonic on the agent host).
    pub attested_at_ms: u64,
}

impl DevicePosture {
    /// Convenience: a posture where every signal is on
    /// and the attestation is "now".
    #[must_use]
    pub fn pristine(now_ms: u64) -> Self {
        Self {
            disk_encrypted: true,
            os_patched: true,
            antimalware_running: true,
            firewall_enabled: true,
            screen_lock_configured: true,
            attested_at_ms: now_ms,
        }
    }

    /// Convenience: a posture where every signal is off
    /// (i.e. an un-attested device).
    #[must_use]
    pub fn unmanaged() -> Self {
        Self {
            disk_encrypted: false,
            os_patched: false,
            antimalware_running: false,
            firewall_enabled: false,
            screen_lock_configured: false,
            attested_at_ms: 0,
        }
    }
}

/// What the device-trust provider knows about one
/// device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrust {
    /// Stable device id (mTLS cert fingerprint).
    pub device_id: String,
    /// Tenant the device belongs to.
    pub tenant_id: String,
    /// Latest posture snapshot reported by the agent.
    pub posture: DevicePosture,
}

impl DeviceTrust {
    /// True iff this device's posture was attested no
    /// longer ago than `max_age_ms` relative to `now_ms`.
    ///
    /// The check is `now_ms - attested_at_ms <= max_age_ms`;
    /// when the device was attested *in the future* (which
    /// shouldn't happen but can if the agent's clock is
    /// skewed and the control plane forwards the
    /// agent-supplied timestamp), the check still passes —
    /// we'd rather over-trust a forward-skewed timestamp
    /// than starve the user of access when the wall clock
    /// drifts.
    #[must_use]
    pub fn posture_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms
            .saturating_sub(self.posture.attested_at_ms)
            .le(&max_age_ms)
    }
}

/// Device-trust provider. Production swaps a
/// tenant-aware implementation (e.g. control-plane API
/// backed) behind this trait.
pub trait DeviceTrustProvider: Send + Sync + 'static {
    /// Look up trust for `device_id`.
    ///
    /// Returns `None` when the device is not enrolled.
    /// The orchestrator translates this into a deny with
    /// reason `device_not_enrolled`.
    fn get(&self, device_id: &str) -> Option<DeviceTrust>;
}

/// In-memory provider supporting per-entry record /
/// forget mutations from the enrollment / re-attestation
/// callback paths. The map is kept under a `parking_lot`
/// `Mutex` rather than an `ArcSwap` because the access
/// pattern is single-entry insert / get, not whole-table
/// swap; see the malware provider in `sng-swg` for the
/// same trade-off.
#[derive(Debug, Default)]
pub struct StaticDeviceTrustProvider {
    table: Mutex<HashMap<String, DeviceTrust>>,
}

impl StaticDeviceTrustProvider {
    /// Construct from an existing list of trusts.
    #[must_use]
    pub fn new(trusts: Vec<DeviceTrust>) -> Self {
        let table = trusts
            .into_iter()
            .map(|t| (t.device_id.clone(), t))
            .collect::<HashMap<_, _>>();
        Self {
            table: Mutex::new(table),
        }
    }

    /// Insert / replace a single entry.
    pub fn record(&self, trust: DeviceTrust) {
        let mut t = self.table.lock();
        t.insert(trust.device_id.clone(), trust);
    }

    /// Remove a single entry (e.g. on offboarding).
    pub fn forget(&self, device_id: &str) {
        let mut t = self.table.lock();
        t.remove(device_id);
    }

    /// Replace the entire table atomically.
    pub fn replace_all(&self, trusts: Vec<DeviceTrust>) {
        let new_table = trusts
            .into_iter()
            .map(|t| (t.device_id.clone(), t))
            .collect::<HashMap<_, _>>();
        let mut t = self.table.lock();
        *t = new_table;
    }

    /// Number of devices in the provider.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.lock().len()
    }

    /// True iff the provider has no devices.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.lock().is_empty()
    }
}

impl DeviceTrustProvider for StaticDeviceTrustProvider {
    fn get(&self, device_id: &str) -> Option<DeviceTrust> {
        self.table.lock().get(device_id).cloned()
    }
}

/// Marker type so `StaticDeviceTrustProvider` can also
/// be referenced through a static-arc-swap façade if a
/// downstream module wants whole-table swap semantics —
/// not used directly by the brain but exposed so the
/// bundle adapter can keep its policy-rev book without
/// taking a per-entry lock.
#[derive(Debug, Default)]
pub struct ArcSwapDeviceTrustProvider {
    table: ArcSwap<HashMap<String, DeviceTrust>>,
}

impl ArcSwapDeviceTrustProvider {
    /// Construct from an existing list of trusts.
    #[must_use]
    pub fn new(trusts: Vec<DeviceTrust>) -> Self {
        let table = trusts
            .into_iter()
            .map(|t| (t.device_id.clone(), t))
            .collect::<HashMap<_, _>>();
        Self {
            table: ArcSwap::new(Arc::new(table)),
        }
    }

    /// Replace the entire table atomically.
    pub fn replace(&self, trusts: Vec<DeviceTrust>) {
        let table = trusts
            .into_iter()
            .map(|t| (t.device_id.clone(), t))
            .collect::<HashMap<_, _>>();
        self.table.store(Arc::new(table));
    }
}

impl DeviceTrustProvider for ArcSwapDeviceTrustProvider {
    fn get(&self, device_id: &str) -> Option<DeviceTrust> {
        self.table.load().get(device_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn trust(id: &str) -> DeviceTrust {
        DeviceTrust {
            device_id: id.into(),
            tenant_id: "t1".into(),
            posture: DevicePosture::pristine(1_000),
        }
    }

    #[test]
    fn record_then_get_returns_trust() {
        let p = StaticDeviceTrustProvider::default();
        p.record(trust("dev-1"));
        let got = p.get("dev-1").unwrap();
        assert_eq!(got.device_id, "dev-1");
    }

    #[test]
    fn forget_removes_entry() {
        let p = StaticDeviceTrustProvider::new(vec![trust("dev-1")]);
        p.forget("dev-1");
        assert!(p.get("dev-1").is_none());
    }

    #[test]
    fn replace_all_drops_previous_entries() {
        let p = StaticDeviceTrustProvider::new(vec![trust("dev-1")]);
        p.replace_all(vec![trust("dev-2")]);
        assert!(p.get("dev-1").is_none());
        assert!(p.get("dev-2").is_some());
    }

    #[test]
    fn posture_fresh_respects_max_age() {
        let mut t = trust("dev-1");
        t.posture.attested_at_ms = 500;
        // now_ms - attested_at_ms = 500 → fresh under 1000
        assert!(t.posture_fresh(1_000, 1_000));
        // now_ms - attested_at_ms = 1000 → fresh under
        // 1000 (inclusive boundary).
        assert!(t.posture_fresh(1_500, 1_000));
        // now_ms - attested_at_ms = 1500 → stale under
        // 1000.
        assert!(!t.posture_fresh(2_000, 1_000));
    }

    #[test]
    fn posture_fresh_tolerates_forward_skew() {
        // attested_at_ms in the future (clock skew on
        // agent host): saturating_sub bottoms at 0, so
        // the freshness check passes.
        let mut t = trust("dev-1");
        t.posture.attested_at_ms = 10_000;
        assert!(t.posture_fresh(1_000, 1_000));
    }

    #[test]
    fn arc_swap_provider_swaps_atomically() {
        let p = ArcSwapDeviceTrustProvider::new(vec![trust("dev-1")]);
        p.replace(vec![trust("dev-2")]);
        assert!(p.get("dev-1").is_none());
        assert!(p.get("dev-2").is_some());
    }
}
