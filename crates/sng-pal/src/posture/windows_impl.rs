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
    /// Center. Definition age is derived from the "definitions out
    /// of date" bit: an out-of-date product reports `None` so the
    /// policy floor's `max_av_definition_age_hours` treats it as
    /// stale (fail-closed). A current product reports `Some(0)` —
    /// except for Microsoft Defender, where the exact signature
    /// timestamp is available (see [`Self::refined_definition_age`])
    /// and used instead so freshness gates compare real hours.
    fn detect_security_center(
        &self,
        now: DateTime<Utc>,
    ) -> (AntivirusStatus, Option<u32>, EdrState) {
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
                    Some(self.refined_definition_age(&av.display_name, now))
                } else {
                    None
                };
                let edr =
                    parse::edr_state_from_security_center(av.found_edr_product, av.edr_realtime_on);
                (av.status, def_age, edr)
            }
        }
    }

    /// Refine the coarse Security Center "fresh" verdict into exact
    /// hours for Microsoft Defender, whose real
    /// `AntivirusSignatureLastUpdated` instant is queryable via
    /// `Get-MpComputerStatus`. Third-party AVs expose no such
    /// timestamp, so they keep the binary `0` (fresh).
    ///
    /// This is **strictness-only**: it is reached only on the
    /// `definitions_up_to_date` branch, so it can turn `0` into a
    /// larger age (tightening a `max_av_definition_age_hours` gate
    /// toward operator intent) but can never relax a stale verdict.
    /// A failed / empty Defender query falls back to `0`, never to a
    /// fail-open value.
    fn refined_definition_age(&self, display_name: &str, now: DateTime<Utc>) -> u32 {
        if !parse::is_microsoft_defender(display_name) {
            return 0;
        }
        self.defender_signature_age_hours(now).unwrap_or(0)
    }

    /// Whole hours since Microsoft Defender last updated its
    /// antivirus signatures, or `None` if Defender is absent or the
    /// query fails. The instant is emitted in UTC so the parse step
    /// is timezone-unambiguous and unit-testable on the CI host.
    fn defender_signature_age_hours(&self, now: DateTime<Utc>) -> Option<u32> {
        let script = "Get-MpComputerStatus -ErrorAction SilentlyContinue | \
             ForEach-Object { \
             $_.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }";
        let stdout = run_powershell(script)?;
        let updated = parse::parse_defender_signature_timestamp(&stdout)?;
        Some(parse::hours_since(updated, now))
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
        let (antivirus, antivirus_definitions_age_hours, edr) = self.detect_security_center(now);
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
