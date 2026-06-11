//! Windows backend.
//!
//! The WS4 posture signals are read through PowerShell, which
//! every supported Windows SKU ships and which exposes the
//! relevant providers without pulling the heavyweight `wmi` /
//! `windows::Management` crates into the agent binary:
//!
//! * **Antivirus + EDR** — the Windows Security Center
//!   (`root\SecurityCenter2`) `AntiVirusProduct` class. Its
//!   `productState` bitfield gives real-time-protection on/off
//!   and whether signature definitions are current; a listed
//!   product whose name looks like an EDR/XDR sensor drives the
//!   EDR signal.
//! * **OS patch age** — `Win32_QuickFixEngineering`'s newest
//!   `InstalledOn` date.
//! * **OS patch level** — the `CurrentBuild`.`UBR` revision
//!   from the `CurrentVersion` registry key.
//! * **Certificate health** — from the device identity leaf's
//!   validity window (injected from enrollment).
//!
//! Disk-encryption (BitLocker) and Defender Firewall posture
//! remain `Unknown` here — they are owned by the separate
//! sng-pal Windows track and are out of scope for WS4.

// The per-OS probe helpers are kept as methods on the collector
// for symmetry with the stateful Linux backend, even where a
// probe reads no instance state; and the certificate-window
// fields deliberately share a `cert_` prefix. Both are
// pedantic-only style lints that add no signal on this thin OS
// shim (which only compiles on Windows, not in CI).
#![allow(clippy::unused_self, clippy::struct_field_names)]

use super::parse;
use super::{
    AntivirusStatus, CertificateHealth, DiskEncryptionState, EdrState, FirewallState,
    PostureCollector, PostureError, PostureSnapshot, ScreenLockState,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct WindowsPostureCollector {
    cert_not_before: Option<DateTime<Utc>>,
    cert_not_after: Option<DateTime<Utc>>,
    cert_renew_within_days: i64,
}

impl Default for WindowsPostureCollector {
    fn default() -> Self {
        Self {
            cert_not_before: None,
            cert_not_after: None,
            cert_renew_within_days: 14,
        }
    }
}

impl WindowsPostureCollector {
    /// Supply the device identity leaf's validity window.
    #[must_use]
    pub fn with_certificate_window(
        mut self,
        not_before: Option<DateTime<Utc>>,
        not_after: DateTime<Utc>,
    ) -> Self {
        self.cert_not_before = not_before;
        self.cert_not_after = Some(not_after);
        self
    }

    /// AV status, definition age, and EDR health from Security
    /// Center. Definition age is derived from "definitions out
    /// of date": a current product reports `Some(0)` (fresh),
    /// an out-of-date one reports `None` so the policy floor's
    /// `max_av_definition_age_hours` treats it as stale.
    fn detect_security_center(&self) -> (AntivirusStatus, Option<u32>, EdrState) {
        let script = "Get-CimInstance -Namespace root/SecurityCenter2 \
             -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | \
             ForEach-Object { \"$($_.displayName)|$($_.productState)\" }";
        let Some(stdout) = run_powershell(script) else {
            return (AntivirusStatus::Unknown, None, EdrState::Unknown);
        };
        match parse::select_av_product(&stdout) {
            None => (AntivirusStatus::Unknown, None, EdrState::NotInstalled),
            Some(av) => {
                let def_age = if av.definitions_up_to_date {
                    Some(0)
                } else {
                    None
                };
                let edr =
                    parse::edr_state_from_security_center(av.found_edr_product, av.edr_realtime_on);
                (av.status, def_age, edr)
            }
        }
    }

    fn last_os_update(&self) -> Option<DateTime<Utc>> {
        let script = "Get-CimInstance -ClassName Win32_QuickFixEngineering \
             -ErrorAction SilentlyContinue | \
             Where-Object { $_.InstalledOn } | \
             ForEach-Object { $_.InstalledOn.ToString('yyyy-MM-dd') }";
        let stdout = run_powershell(script)?;
        parse::newest_hotfix_date(&stdout)
    }

    fn os_patch_level(&self) -> Option<String> {
        let script = "$k = Get-ItemProperty \
             'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; \
             \"$($k.CurrentBuild).$($k.UBR)\"";
        let out = run_powershell(script)?;
        let out = out.trim();
        // A bare ".", or empty, means the query produced nothing
        // useful.
        if out.is_empty() || out == "." {
            None
        } else {
            Some(out.to_owned())
        }
    }

    fn certificate_health(&self, now: DateTime<Utc>) -> CertificateHealth {
        match self.cert_not_after {
            Some(not_after) => parse::certificate_health(
                self.cert_not_before,
                not_after,
                now,
                self.cert_renew_within_days,
            ),
            None => CertificateHealth::Unknown,
        }
    }
}

/// Run a PowerShell one-liner with no profile and return its
/// trimmed stdout on a zero exit. Returns `None` on spawn
/// failure / non-zero exit so the caller reports `Unknown`.
fn run_powershell(script: &str) -> Option<String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[async_trait]
impl PostureCollector for WindowsPostureCollector {
    async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
        let now = Utc::now();
        let (antivirus, antivirus_definitions_age_hours, edr) = self.detect_security_center();
        let last_os_update = self.last_os_update();
        Ok(PostureSnapshot {
            collected_at: now,
            disk_encryption: DiskEncryptionState::Unknown,
            firewall: FirewallState::Unknown,
            screen_lock: ScreenLockState::Unknown,
            last_os_update,
            edr,
            antivirus,
            antivirus_definitions_age_hours,
            os_patch_level: self.os_patch_level(),
            os_patch_age_days: last_os_update.map(|u| parse::days_since(u, now)),
            certificate_health: self.certificate_health(now),
        })
    }
}
