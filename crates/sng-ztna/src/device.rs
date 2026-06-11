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

/// Health of the device's locally-stored identity
/// certificate (the mTLS leaf the agent enrolled with).
///
/// The agent knows its own certificate's validity window
/// from enrollment, so it can report whether the leaf is
/// still healthy, approaching expiry, or already expired
/// without the control plane having to re-parse the chain
/// on every posture push. A leaf that has expired is a
/// hard posture regression — the device can no longer
/// prove its identity — so dashboards and the evaluator
/// treat anything other than [`Self::Healthy`] as a
/// degraded signal.
///
/// [`Self::Unknown`] is the fail-closed default: a snapshot
/// from an older agent that does not report certificate
/// health (or one whose probe could not read the leaf)
/// deserialises to `Unknown` rather than `Healthy`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateHealth {
    /// The identity certificate is present and well within
    /// its validity window.
    Healthy,
    /// The certificate is still valid but inside the
    /// renewal window (expiring soon). Surfaced so the
    /// fleet can be re-enrolled before access breaks.
    Expiring,
    /// The certificate is past `notAfter` (or before
    /// `notBefore`). The device can no longer present a
    /// valid identity.
    Expired,
    /// Health could not be determined — no certificate
    /// found, unreadable, or not reported by the agent.
    #[default]
    Unknown,
}

/// One posture snapshot. The field set mirrors what the
/// agent reports on `sng-agent` startup + every hour.
///
/// The `struct_excessive_bools` lint normally flags a
/// struct with more than three `bool` fields as a smell
/// (suggesting it should be modelled as flags / an enum).
/// Here the booleans are the *wire shape* the agent emits
/// — disk encryption, OS patch level, antimalware,
/// firewall, screen lock, EDR health, antivirus — and the
/// names are part of the dashboard contract. Folding them
/// into a single bitmask would force every dashboard /
/// event / SQL projection to grow a decoder, for no
/// operational gain. Allowed deliberately.
///
/// # Wire compatibility
///
/// The signals added for the expanded posture model
/// (`edr_healthy`, `os_patch_level`, `os_patch_days_since`,
/// `certificate_health`, `antivirus_enabled`,
/// `antivirus_definitions_age_hours`) all carry
/// `#[serde(default = …)]` with **fail-closed** defaults:
/// a snapshot from an older agent that predates these
/// fields deserialises as if EDR/AV were off and the OS /
/// AV definitions were last touched in the distant past.
/// That keeps the deny-by-default contract — a missing
/// signal can never silently satisfy a posture floor.
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
    /// EDR (Endpoint Detection & Response) agent is
    /// installed, running, and reporting healthy. A device
    /// whose EDR sensor has been killed or has stopped
    /// checking in reports `false`.
    #[serde(default)]
    pub edr_healthy: bool,
    /// Free-form OS patch-level identifier the agent
    /// reports (e.g. a Windows UBR build string
    /// `10.0.19045.4170`, a macOS `14.4.1 (23E224)`, or a
    /// Linux kernel release). Carried for audit /
    /// dashboards; the numeric gate is
    /// [`Self::os_patch_days_since`]. Empty when unknown.
    #[serde(default)]
    pub os_patch_level: String,
    /// Days since the most recent OS patch was applied.
    /// Larger is worse; [`crate::policy::PostureRequirement::min_patch_days`]
    /// gates on it. Defaults to [`u32::MAX`] ("effectively
    /// never patched") so a missing signal fails any
    /// patch-recency floor.
    #[serde(default = "default_stale_u32")]
    pub os_patch_days_since: u32,
    /// Health of the device's mTLS identity certificate.
    #[serde(default)]
    pub certificate_health: CertificateHealth,
    /// Antivirus engine is enabled (real-time protection
    /// on). Distinct from [`Self::antimalware_running`],
    /// which only asserts a process is alive — this asserts
    /// the AV product reports itself active.
    #[serde(default)]
    pub antivirus_enabled: bool,
    /// Age, in hours, of the antivirus signature
    /// definitions. Larger is worse;
    /// [`crate::policy::PostureRequirement::max_av_definition_age_hours`]
    /// gates on it. Defaults to [`u32::MAX`] ("definitions
    /// of unknown age") so a missing signal fails any
    /// freshness floor.
    #[serde(default = "default_stale_u32")]
    pub antivirus_definitions_age_hours: u32,
    /// When the agent last submitted this snapshot
    /// (millisecond epoch, monotonic on the agent host).
    pub attested_at_ms: u64,
}

/// `serde` default for the staleness-counter fields: the
/// maximum `u32`, i.e. fail-closed. Used so a posture
/// snapshot that omits `os_patch_days_since` /
/// `antivirus_definitions_age_hours` (an older agent) is
/// treated as maximally stale rather than freshly updated.
const fn default_stale_u32() -> u32 {
    u32::MAX
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
            edr_healthy: true,
            os_patch_level: "current".to_owned(),
            os_patch_days_since: 0,
            certificate_health: CertificateHealth::Healthy,
            antivirus_enabled: true,
            antivirus_definitions_age_hours: 0,
            attested_at_ms: now_ms,
        }
    }

    /// Weighted compliance score in `0..=100`, summed
    /// from the individual posture signals:
    ///
    /// | Signal                | Weight |
    /// |-----------------------|--------|
    /// | `disk_encrypted`      | 25     |
    /// | `os_patched`          | 25     |
    /// | `antimalware_running` | 20     |
    /// | `firewall_enabled`    | 15     |
    /// | `screen_lock_configured` | 15  |
    ///
    /// A fully-attested device scores 100; an un-attested
    /// one scores 0. [`crate::policy::PostureRequirement`]
    /// gates on this score, letting operators pick a floor
    /// at any granularity instead of three fixed buckets.
    ///
    /// The expanded posture signals (`edr_healthy`,
    /// `os_patch_days_since`, `antivirus_*`) are
    /// deliberately **not** folded into this weighted score:
    /// the score keeps its original five-signal contract
    /// (so existing per-app floors keep their meaning) and
    /// the new signals are enforced as independent hard
    /// gates on [`crate::policy::PostureRequirement`]
    /// (`require_edr`, `min_patch_days`,
    /// `max_av_definition_age_hours`). That separation lets
    /// an operator demand, say, a *healthy EDR sensor*
    /// without having to re-tune every numeric floor.
    #[must_use]
    pub const fn risk_score(&self) -> u8 {
        let mut score: u8 = 0;
        if self.disk_encrypted {
            score += 25;
        }
        if self.os_patched {
            score += 25;
        }
        if self.antimalware_running {
            score += 20;
        }
        if self.firewall_enabled {
            score += 15;
        }
        if self.screen_lock_configured {
            score += 15;
        }
        score
    }

    /// Convenience: a posture where every signal is off
    /// (i.e. an un-attested device). The staleness counters
    /// are pinned to [`u32::MAX`] and the certificate health
    /// to [`CertificateHealth::Unknown`] so an unmanaged
    /// device fails every patch / AV-freshness floor as well
    /// as the score floor.
    #[must_use]
    pub fn unmanaged() -> Self {
        Self {
            disk_encrypted: false,
            os_patched: false,
            antimalware_running: false,
            firewall_enabled: false,
            screen_lock_configured: false,
            edr_healthy: false,
            os_patch_level: String::new(),
            os_patch_days_since: u32::MAX,
            certificate_health: CertificateHealth::Unknown,
            antivirus_enabled: false,
            antivirus_definitions_age_hours: u32::MAX,
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
    /// Free-form device tags from the control-plane
    /// bundle (e.g. `managed=true`, `compliance_level=high`).
    /// Evaluated against
    /// [`crate::policy::AccessConditions::device_tag_conditions`].
    #[serde(default)]
    pub tags: HashMap<String, String>,
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
            tags: HashMap::new(),
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
