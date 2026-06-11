//! macOS backend.
//!
//! * **FileVault** — `/usr/bin/fdesetup status` (`FileVault is
//!   On` / `Off`).
//! * **Firewall** — `defaults read
//!   /Library/Preferences/com.apple.alf globalstate` (`0`
//!   disabled, `1`/`2` enabled).
//! * **EDR** — `systemextensionsctl list`: macOS Endpoint
//!   Security agents (CrowdStrike, SentinelOne, Defender for
//!   Endpoint, …) register a system extension; an
//!   `[activated enabled]` entry for a recognised vendor is a
//!   healthy sensor.
//! * **OS patch level / age** — `sw_vers` for the product
//!   version + build, and `softwareupdate`'s last-successful
//!   timestamp (`com.apple.SoftwareUpdate
//!   LastFullSuccessfulDate`) for how long ago patches landed.
//! * **Antivirus** — Apple's built-in XProtect; its presence is
//!   real-time AV, and the bundle mtime gives the definition
//!   age.
//! * **Certificate health** — from the device identity leaf's
//!   validity window (injected from enrollment).

// The per-OS probe helpers are kept as methods on the collector
// for symmetry with the stateful Linux backend, even where a
// probe reads no instance state; and the certificate-window
// fields deliberately share a `cert_` prefix. Both are
// pedantic-only style lints that add no signal on this thin OS
// shim (which only compiles on macOS, not in CI).
#![allow(clippy::unused_self, clippy::struct_field_names)]

use super::parse;
use super::{
    AntivirusStatus, CertificateHealth, DiskEncryptionState, EdrState, FirewallState,
    PostureCollector, PostureError, PostureSnapshot, ScreenLockState,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Candidate XProtect bundle locations across macOS releases.
const XPROTECT_PATHS: &[&str] = &[
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
    "/System/Library/CoreServices/XProtect.bundle",
];

#[derive(Clone, Debug)]
pub struct MacPostureCollector {
    cert_not_before: Option<DateTime<Utc>>,
    cert_not_after: Option<DateTime<Utc>>,
    cert_renew_within_days: i64,
}

impl Default for MacPostureCollector {
    fn default() -> Self {
        Self {
            cert_not_before: None,
            cert_not_after: None,
            cert_renew_within_days: 14,
        }
    }
}

impl MacPostureCollector {
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

    fn detect_filevault(&self) -> DiskEncryptionState {
        if !Path::new("/usr/bin/fdesetup").exists() {
            return DiskEncryptionState::Unknown;
        }
        let Ok(output) = Command::new("/usr/bin/fdesetup").arg("status").output() else {
            return DiskEncryptionState::Unknown;
        };
        let s = String::from_utf8_lossy(&output.stdout);
        if s.contains("FileVault is On") {
            DiskEncryptionState::Enabled
        } else if s.contains("FileVault is Off") {
            DiskEncryptionState::Disabled
        } else {
            DiskEncryptionState::Unknown
        }
    }

    fn detect_alf(&self) -> FirewallState {
        let Ok(output) = Command::new("/usr/bin/defaults")
            .args(["read", "/Library/Preferences/com.apple.alf", "globalstate"])
            .output()
        else {
            return FirewallState::Unknown;
        };
        let s = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        match s.as_str() {
            "0" => FirewallState::Disabled,
            "1" | "2" => FirewallState::Enabled,
            _ => FirewallState::Unknown,
        }
    }

    fn detect_edr(&self) -> EdrState {
        let Ok(output) = Command::new("/usr/bin/systemextensionsctl")
            .arg("list")
            .output()
        else {
            return EdrState::Unknown;
        };
        if !output.status.success() {
            return EdrState::Unknown;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse::edr_state_from_systemextensions(&stdout)
    }

    /// `<productVersion> (<buildVersion>)`, e.g. `14.4.1 (23E224)`.
    fn os_patch_level(&self) -> Option<String> {
        let product = run_capture("/usr/bin/sw_vers", &["-productVersion"])?;
        let build = run_capture("/usr/bin/sw_vers", &["-buildVersion"]).unwrap_or_default();
        let product = product.trim();
        if product.is_empty() {
            return None;
        }
        let build = build.trim();
        if build.is_empty() {
            Some(product.to_owned())
        } else {
            Some(format!("{product} ({build})"))
        }
    }

    /// Last successful software-update time from the
    /// `SoftwareUpdate` preference domain.
    fn last_os_update(&self) -> Option<DateTime<Utc>> {
        let raw = run_capture(
            "/usr/bin/defaults",
            &[
                "read",
                "/Library/Preferences/com.apple.SoftwareUpdate",
                "LastFullSuccessfulDate",
            ],
        )?;
        parse::parse_macos_defaults_date(&raw)
    }

    /// XProtect presence (real-time AV) + definition age from the
    /// bundle mtime.
    fn detect_antivirus(&self, now: DateTime<Utc>) -> (AntivirusStatus, Option<u32>) {
        let bundle = XPROTECT_PATHS
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
        match bundle {
            None => (AntivirusStatus::Unknown, None),
            Some(path) => {
                let age = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(system_time_to_chrono)
                    .map(|updated| parse::hours_since(updated, now));
                (AntivirusStatus::Enabled, age)
            }
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

/// Run a command and return its trimmed stdout on a zero exit,
/// or `None` on spawn failure / non-zero exit.
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn system_time_to_chrono(t: SystemTime) -> Option<DateTime<Utc>> {
    let duration = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let secs = i64::try_from(duration.as_secs()).ok()?;
    DateTime::from_timestamp(secs, duration.subsec_nanos())
}

#[async_trait]
impl PostureCollector for MacPostureCollector {
    async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
        let now = Utc::now();
        let last_os_update = self.last_os_update();
        let (antivirus, antivirus_definitions_age_hours) = self.detect_antivirus(now);
        Ok(PostureSnapshot {
            collected_at: now,
            disk_encryption: self.detect_filevault(),
            firewall: self.detect_alf(),
            screen_lock: ScreenLockState::Unknown,
            last_os_update,
            edr: self.detect_edr(),
            antivirus,
            antivirus_definitions_age_hours,
            os_patch_level: self.os_patch_level(),
            os_patch_age_days: last_os_update.map(|u| parse::days_since(u, now)),
            certificate_health: self.certificate_health(now),
        })
    }
}
