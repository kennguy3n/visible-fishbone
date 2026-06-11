//! Endpoint posture collection.
//!
//! Posture data drives the ZTNA gate: a connection grant from
//! the control plane is conditional on the device's reported
//! posture remaining `pass`. The collector probes the OS for
//! the canonical posture primitives:
//!
//! * **Disk encryption** — BitLocker on Windows, FileVault on
//!   macOS, LUKS on Linux.
//! * **Firewall state** — Windows Firewall, macOS pf /
//!   socketfilterfw, Linux iptables / nftables.
//! * **Screen-lock state** — interactive lock active /
//!   inactive.
//! * **OS patch level** — last applied update, and how long
//!   ago it landed.
//! * **EDR health** — is an Endpoint Detection & Response
//!   sensor installed, running, and reporting healthy
//!   (Windows Security Center, macOS Endpoint Security system
//!   extensions, a Linux process probe).
//! * **Antivirus** — is real-time AV enabled and how old are
//!   its signature definitions.
//! * **Certificate health** — is the device's identity
//!   certificate still inside its validity window.
//!
//! Each primitive is normalised into a typed enum so the
//! control plane's evaluator can match against the same shape
//! regardless of OS family.
//!
//! # Layout
//!
//! The OS-specific collectors live in sibling files behind a
//! `cfg(target_os)` gate ([`linux`], [`macos`], `windows_impl`).
//! All the *pure* parsing / classification logic those backends
//! rely on — Security Center bitfield decoding, hotfix-date
//! parsing, `systemextensionsctl` scanning, age arithmetic — is
//! factored into the cross-platform [`parse`] module so it
//! compiles and is unit-tested on every target (including CI's
//! headless Linux), even for the signals whose *probe* only runs
//! on Windows / macOS.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

pub(crate) mod parse;

/// Disk-encryption state. Mirrors the three-state model the
/// control-plane posture rules evaluate against.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskEncryptionState {
    /// The system volume is encrypted and protectors are
    /// enabled (BitLocker `On`, FileVault `On`, LUKS open).
    Enabled,
    /// Encryption is provisioned but currently disabled (e.g.
    /// BitLocker `SuspendedForReboot`).
    Suspended,
    /// No encryption is in effect.
    Disabled,
    /// The probe could not determine the state (permission
    /// denied, API not available).
    Unknown,
}

/// Firewall state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallState {
    /// Firewall is on, default-deny posture in effect.
    Enabled,
    /// Firewall is off.
    Disabled,
    /// State could not be determined.
    Unknown,
}

/// Screen-lock state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenLockState {
    /// Interactive session is locked.
    Locked,
    /// Interactive session is unlocked.
    Unlocked,
    /// State could not be determined (e.g. headless host,
    /// remote service account).
    Unknown,
}

/// Endpoint Detection & Response sensor health.
///
/// EDR is the highest-value posture signal for an SME fleet —
/// a killed or stalled sensor is the canonical precursor to a
/// hands-on-keyboard intrusion — so it is modelled as its own
/// four-state enum rather than a bare boolean.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrState {
    /// A known EDR sensor is installed, running, and (where the
    /// OS exposes it) reporting healthy.
    Healthy,
    /// A sensor is installed but not running / not reporting
    /// healthy (Windows Security Center reports it out of date
    /// or off, a macOS extension is registered but not enabled,
    /// the Linux daemon is not in the process table).
    Unhealthy,
    /// No EDR sensor could be found at all.
    NotInstalled,
    /// State could not be determined (probe unavailable /
    /// permission denied).
    Unknown,
}

/// Antivirus real-time-protection state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntivirusStatus {
    /// AV is present with real-time protection enabled.
    Enabled,
    /// AV is present but real-time protection is off.
    Disabled,
    /// State could not be determined / no AV product found.
    Unknown,
}

/// Health of the device's locally-stored identity certificate.
///
/// PAL-local mirror of `sng_ztna::CertificateHealth`; kept here
/// so the PAL crate does not take a dependency on the ZTNA
/// broker (the dependency runs the other way — the agent maps
/// this snapshot onto the broker's `DevicePosture`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateHealth {
    /// Certificate present and well within its validity window.
    Healthy,
    /// Still valid but inside the renewal window.
    Expiring,
    /// Past `notAfter` (or before `notBefore`).
    Expired,
    /// Could not be determined / not reported.
    #[default]
    Unknown,
}

/// Typed posture snapshot. Serialised onto the AgentEvent
/// envelope as the opaque posture payload.
///
/// The signals added for the expanded posture model carry
/// `#[serde(default)]` so a snapshot produced by an older agent
/// (or by the [`UnknownPostureCollector`] fallback) round-trips
/// without them — they deserialise to the fail-closed
/// `Unknown` / `None` values rather than erroring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PostureSnapshot {
    /// Snapshot time.
    pub collected_at: DateTime<Utc>,
    /// Disk-encryption state.
    pub disk_encryption: DiskEncryptionState,
    /// Firewall state.
    pub firewall: FirewallState,
    /// Screen-lock state.
    pub screen_lock: ScreenLockState,
    /// Last OS update time, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_os_update: Option<DateTime<Utc>>,
    /// EDR sensor health.
    #[serde(default = "edr_unknown")]
    pub edr: EdrState,
    /// Antivirus real-time-protection state.
    #[serde(default = "av_unknown")]
    pub antivirus: AntivirusStatus,
    /// Age, in hours, of the antivirus signature definitions,
    /// if an AV product was found and reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub antivirus_definitions_age_hours: Option<u32>,
    /// Free-form OS patch-level identifier (Windows UBR build,
    /// macOS product version + build, Linux kernel release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_patch_level: Option<String>,
    /// Days since the most recent OS patch, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_patch_age_days: Option<u32>,
    /// Identity-certificate health.
    #[serde(default)]
    pub certificate_health: CertificateHealth,
}

/// `serde` default for [`PostureSnapshot::edr`].
const fn edr_unknown() -> EdrState {
    EdrState::Unknown
}

/// `serde` default for [`PostureSnapshot::antivirus`].
const fn av_unknown() -> AntivirusStatus {
    AntivirusStatus::Unknown
}

impl PostureSnapshot {
    /// A snapshot with every signal `Unknown` / `None` and the
    /// supplied collection time. Backends start from this and
    /// fill in the signals their OS probe can determine, so
    /// adding a new posture field never silently defaults an
    /// existing backend to a *passing* value.
    #[must_use]
    pub fn unknown_at(collected_at: DateTime<Utc>) -> Self {
        Self {
            collected_at,
            disk_encryption: DiskEncryptionState::Unknown,
            firewall: FirewallState::Unknown,
            screen_lock: ScreenLockState::Unknown,
            last_os_update: None,
            edr: EdrState::Unknown,
            antivirus: AntivirusStatus::Unknown,
            antivirus_definitions_age_hours: None,
            os_patch_level: None,
            os_patch_age_days: None,
            certificate_health: CertificateHealth::Unknown,
        }
    }
}

/// Posture-collection error.
#[derive(Debug, Error)]
pub enum PostureError {
    /// IO failure from a probe.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The probe needed a privilege the running process does
    /// not have (CAP_SYS_ADMIN on Linux, Full Disk Access on
    /// macOS, admin elevation on Windows).
    #[error("permission denied: {0}")]
    Permission(String),
    /// The probe ran but could not produce a typed answer.
    #[error("parse: {0}")]
    Parse(String),
}

/// Async trait — backends may need to await on OS APIs (UWP /
/// XPC) — implemented by every PAL backend.
#[async_trait]
pub trait PostureCollector: Send + Sync {
    /// Produce a fresh posture snapshot. Probes that cannot
    /// determine a value report `Unknown` rather than erroring;
    /// the operator dashboard treats `Unknown` as a posture
    /// fail by default.
    async fn collect(&self) -> Result<PostureSnapshot, PostureError>;
}

/// "Always Unknown" collector — used as the fallback on
/// platforms where no real probe is wired in yet, and as the
/// default in unit tests that don't exercise the OS path.
#[derive(Copy, Clone, Debug, Default)]
pub struct UnknownPostureCollector;

#[async_trait]
impl PostureCollector for UnknownPostureCollector {
    async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
        Ok(PostureSnapshot::unknown_at(Utc::now()))
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxPostureCollector;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacPostureCollector;

#[cfg(target_os = "windows")]
mod windows_impl;
#[cfg(target_os = "windows")]
pub use windows_impl::WindowsPostureCollector;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_collector_returns_unknowns() {
        let c = UnknownPostureCollector;
        let s = c.collect().await.expect("ok");
        assert_eq!(s.disk_encryption, DiskEncryptionState::Unknown);
        assert_eq!(s.firewall, FirewallState::Unknown);
        assert_eq!(s.screen_lock, ScreenLockState::Unknown);
        assert_eq!(s.edr, EdrState::Unknown);
        assert_eq!(s.antivirus, AntivirusStatus::Unknown);
        assert_eq!(s.antivirus_definitions_age_hours, None);
        assert_eq!(s.os_patch_age_days, None);
        assert_eq!(s.certificate_health, CertificateHealth::Unknown);
    }

    #[test]
    fn snapshot_serialises_round_trip() {
        let s = PostureSnapshot {
            collected_at: Utc::now(),
            disk_encryption: DiskEncryptionState::Enabled,
            firewall: FirewallState::Enabled,
            screen_lock: ScreenLockState::Locked,
            last_os_update: None,
            edr: EdrState::Healthy,
            antivirus: AntivirusStatus::Enabled,
            antivirus_definitions_age_hours: Some(6),
            os_patch_level: Some("10.0.19045.4170".to_owned()),
            os_patch_age_days: Some(3),
            certificate_health: CertificateHealth::Healthy,
        };
        let json = serde_json::to_string(&s).expect("ok");
        let back: PostureSnapshot = serde_json::from_str(&json).expect("ok");
        assert_eq!(s, back);
    }

    #[test]
    fn legacy_snapshot_without_expanded_fields_deserialises_fail_closed() {
        // A payload from a pre-expansion agent: only the
        // original five fields. The new signals must default to
        // the fail-closed Unknown/None values, never to a value
        // that would silently satisfy a posture floor.
        let legacy = r#"{
            "collected_at": "2026-01-01T00:00:00Z",
            "disk_encryption": "enabled",
            "firewall": "enabled",
            "screen_lock": "locked"
        }"#;
        let snap: PostureSnapshot = serde_json::from_str(legacy).expect("ok");
        assert_eq!(snap.edr, EdrState::Unknown);
        assert_eq!(snap.antivirus, AntivirusStatus::Unknown);
        assert_eq!(snap.antivirus_definitions_age_hours, None);
        assert_eq!(snap.os_patch_level, None);
        assert_eq!(snap.os_patch_age_days, None);
        assert_eq!(snap.certificate_health, CertificateHealth::Unknown);
    }

    #[test]
    fn disk_encryption_state_uses_snake_case_wire_strings() {
        let cases = [
            (DiskEncryptionState::Enabled, "\"enabled\""),
            (DiskEncryptionState::Suspended, "\"suspended\""),
            (DiskEncryptionState::Disabled, "\"disabled\""),
            (DiskEncryptionState::Unknown, "\"unknown\""),
        ];
        for (state, expected) in cases {
            let json = serde_json::to_string(&state).expect("ok");
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn expanded_state_enums_use_snake_case_wire_strings() {
        assert_eq!(
            serde_json::to_string(&EdrState::NotInstalled).expect("ok"),
            "\"not_installed\""
        );
        assert_eq!(
            serde_json::to_string(&AntivirusStatus::Enabled).expect("ok"),
            "\"enabled\""
        );
        assert_eq!(
            serde_json::to_string(&CertificateHealth::Expiring).expect("ok"),
            "\"expiring\""
        );
    }
}
