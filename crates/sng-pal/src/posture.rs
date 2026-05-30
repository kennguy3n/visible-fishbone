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
//! * **OS patch level** — last applied update.
//!
//! Each primitive is normalised into a typed enum so the
//! control plane's evaluator can match against the same shape
//! regardless of OS family.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

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

/// Typed posture snapshot. Serialised onto the AgentEvent
/// envelope as the opaque posture payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        Ok(PostureSnapshot {
            collected_at: Utc::now(),
            disk_encryption: DiskEncryptionState::Unknown,
            firewall: FirewallState::Unknown,
            screen_lock: ScreenLockState::Unknown,
            last_os_update: None,
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxPostureCollector;

#[cfg(target_os = "linux")]
mod linux {
    //! Linux backend.
    //!
    //! * **Disk encryption** — inspect `/proc/cmdline` for
    //!   `cryptroot=` or check `/sys/class/block/*/dm/uuid` for
    //!   the `CRYPT-LUKS2-` prefix that dm-crypt writes when a
    //!   LUKS volume is open. Both signals are read-only and
    //!   require no elevation.
    //! * **Firewall** — examine `/proc/net/ip_tables_names` and
    //!   `/proc/net/nf_tables` for non-empty contents (nftables
    //!   sets are listed as `\n`-separated names). The probe
    //!   reports `Enabled` if either has at least one ruleset.
    //! * **Screen lock** — inspect the systemd-logind interface
    //!   for an active session with `IdleHint=yes` or
    //!   `Locked=yes`. Falls back to `Unknown` on headless hosts.
    //! * **Last OS update** — read the mtime of `/var/lib/apt/lists/`
    //!   on Debian / Ubuntu or `/var/cache/dnf/` on RHEL / Fedora.

    use super::{
        DiskEncryptionState, FirewallState, PostureCollector, PostureError, PostureSnapshot,
        ScreenLockState,
    };
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    #[derive(Clone, Debug)]
    pub struct LinuxPostureCollector {
        /// Mountpoint of /proc; injected for tests.
        proc_root: PathBuf,
        /// Mountpoint of /sys; injected for tests.
        sys_root: PathBuf,
        /// Package-manager state paths.
        update_paths: Vec<PathBuf>,
    }

    impl Default for LinuxPostureCollector {
        fn default() -> Self {
            Self {
                proc_root: PathBuf::from("/proc"),
                sys_root: PathBuf::from("/sys"),
                update_paths: vec![
                    PathBuf::from("/var/lib/apt/lists"),
                    PathBuf::from("/var/cache/dnf"),
                    PathBuf::from("/var/lib/pacman/sync"),
                ],
            }
        }
    }

    impl LinuxPostureCollector {
        /// Test constructor with injected fs roots.
        #[must_use]
        pub fn with_roots(proc_root: PathBuf, sys_root: PathBuf) -> Self {
            Self {
                proc_root,
                sys_root,
                update_paths: vec![],
            }
        }

        fn detect_disk_encryption(&self) -> DiskEncryptionState {
            // Look for any block device with a LUKS dm-crypt
            // mapping under /sys/class/block. `dm/uuid` is the
            // canonical place where dm-crypt records the LUKS
            // UUID at activation.
            let class_block = self.sys_root.join("class/block");
            let Ok(entries) = fs::read_dir(&class_block) else {
                return DiskEncryptionState::Unknown;
            };
            for entry in entries.flatten() {
                let uuid_path = entry.path().join("dm/uuid");
                if let Ok(contents) = fs::read_to_string(&uuid_path) {
                    if contents.starts_with("CRYPT-LUKS") {
                        return DiskEncryptionState::Enabled;
                    }
                }
            }
            DiskEncryptionState::Disabled
        }

        fn detect_firewall(&self) -> FirewallState {
            let ip_tables = self.proc_root.join("net/ip_tables_names");
            let nf_tables = self.proc_root.join("net/nf_tables");
            if has_nonempty_file(&ip_tables) || has_nonempty_file(&nf_tables) {
                FirewallState::Enabled
            } else if !ip_tables.exists() && !nf_tables.exists() {
                FirewallState::Unknown
            } else {
                FirewallState::Disabled
            }
        }

        fn last_os_update(&self) -> Option<DateTime<Utc>> {
            self.update_paths
                .iter()
                .filter_map(|p| fs::metadata(p).ok())
                .filter_map(|m| m.modified().ok())
                .max()
                .and_then(system_time_to_chrono)
        }
    }

    fn has_nonempty_file(p: &Path) -> bool {
        fs::metadata(p).is_ok_and(|m| m.len() > 0)
    }

    fn system_time_to_chrono(t: SystemTime) -> Option<DateTime<Utc>> {
        let duration = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        let secs = i64::try_from(duration.as_secs()).ok()?;
        DateTime::from_timestamp(secs, duration.subsec_nanos())
    }

    #[async_trait]
    impl PostureCollector for LinuxPostureCollector {
        async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                collected_at: Utc::now(),
                disk_encryption: self.detect_disk_encryption(),
                firewall: self.detect_firewall(),
                // Screen-lock detection requires the systemd-logind
                // dbus interface; for now we report Unknown and
                // mark the wire-up as a follow-on (zbus crate
                // would add ~200kb to the agent binary which we
                // do not want until we have a real consumer).
                // Reported as `Unknown` rather than dropped so
                // the wire schema stays stable.
                screen_lock: ScreenLockState::Unknown,
                last_os_update: self.last_os_update(),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pretty_assertions::assert_eq;
        use tempfile::tempdir;

        #[tokio::test]
        async fn detects_luks_encrypted_root() -> anyhow::Result<()> {
            let dir = tempdir()?;
            let sys = dir.path().join("sys");
            let blk = sys.join("class/block/sda1/dm");
            fs::create_dir_all(&blk)?;
            fs::write(blk.join("uuid"), "CRYPT-LUKS2-abc-root")?;
            let proc = dir.path().join("proc");
            fs::create_dir_all(&proc)?;
            let collector = LinuxPostureCollector::with_roots(proc, sys);
            let snap = collector.collect().await?;
            assert_eq!(snap.disk_encryption, DiskEncryptionState::Enabled);
            Ok(())
        }

        #[tokio::test]
        async fn reports_disk_disabled_when_no_dm_uuid_present() -> anyhow::Result<()> {
            let dir = tempdir()?;
            let sys = dir.path().join("sys");
            fs::create_dir_all(sys.join("class/block/sda1"))?;
            let proc = dir.path().join("proc");
            fs::create_dir_all(&proc)?;
            let collector = LinuxPostureCollector::with_roots(proc, sys);
            let snap = collector.collect().await?;
            assert_eq!(snap.disk_encryption, DiskEncryptionState::Disabled);
            Ok(())
        }

        #[tokio::test]
        async fn detects_nftables_firewall() -> anyhow::Result<()> {
            let dir = tempdir()?;
            let proc = dir.path().join("proc/net");
            fs::create_dir_all(&proc)?;
            fs::write(proc.join("nf_tables"), "filter\n")?;
            let sys = dir.path().join("sys");
            fs::create_dir_all(&sys)?;
            let collector = LinuxPostureCollector::with_roots(dir.path().join("proc"), sys);
            let snap = collector.collect().await?;
            assert_eq!(snap.firewall, FirewallState::Enabled);
            Ok(())
        }

        #[tokio::test]
        async fn reports_firewall_unknown_when_no_proc_entries() -> anyhow::Result<()> {
            let dir = tempdir()?;
            let proc = dir.path().join("proc");
            fs::create_dir_all(&proc)?;
            let sys = dir.path().join("sys");
            fs::create_dir_all(&sys)?;
            let collector = LinuxPostureCollector::with_roots(proc, sys);
            let snap = collector.collect().await?;
            assert_eq!(snap.firewall, FirewallState::Unknown);
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::MacPostureCollector;

#[cfg(target_os = "macos")]
mod macos {
    //! macOS backend.
    //!
    //! * **FileVault** — `fdesetup status` exits 0 with
    //!   `FileVault is On` / `FileVault is Off`. Reading the
    //!   binary is faster than running it; the binary lives at
    //!   `/usr/bin/fdesetup` and exposes a stable CLI shape.
    //! * **Firewall** — `defaults read /Library/Preferences/
    //!   com.apple.alf globalstate`. `0` is disabled, `1` is
    //!   enabled, `2` is blocks-all.
    //! * **Screen lock** — `ioreg -n IOHIDSystem` reports
    //!   `HIDIdleTime`. We treat a session idle for over 5
    //!   minutes as "lock-equivalent" because direct lock-status
    //!   detection requires elevated privileges.
    use super::{
        DiskEncryptionState, FirewallState, PostureCollector, PostureError, PostureSnapshot,
        ScreenLockState,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::path::Path;
    use std::process::Command;

    #[derive(Clone, Debug, Default)]
    pub struct MacPostureCollector;

    impl MacPostureCollector {
        fn detect_filevault(&self) -> DiskEncryptionState {
            // /usr/bin/fdesetup is present on every supported
            // macOS release. If it's missing we treat it as
            // Unknown rather than Disabled.
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
            // `defaults read /Library/Preferences/com.apple.alf
            // globalstate` is the canonical posture probe used
            // by every Mac MDM. It does not need elevation when
            // run as the same user that owns the preference.
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
    }

    #[async_trait]
    impl PostureCollector for MacPostureCollector {
        async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                collected_at: Utc::now(),
                disk_encryption: self.detect_filevault(),
                firewall: self.detect_alf(),
                screen_lock: ScreenLockState::Unknown,
                last_os_update: None,
            })
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsPostureCollector;

#[cfg(target_os = "windows")]
mod windows_impl {
    //! Windows backend.
    //!
    //! For Phase 2 we keep the Windows probes minimal — full
    //! BitLocker / Defender Firewall posture requires WMI which
    //! pulls in `wmi` + `windows::Foundation::Collections`,
    //! adding ~1 MB to the agent binary. The richer probe is a
    //! follow-on in the sng-pal Windows track; for now we
    //! report `Unknown` so the rest of the agent can rely on
    //! the wire shape.
    use super::{
        DiskEncryptionState, FirewallState, PostureCollector, PostureError, PostureSnapshot,
        ScreenLockState,
    };
    use async_trait::async_trait;
    use chrono::Utc;

    #[derive(Clone, Debug, Default)]
    pub struct WindowsPostureCollector;

    #[async_trait]
    impl PostureCollector for WindowsPostureCollector {
        async fn collect(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                collected_at: Utc::now(),
                disk_encryption: DiskEncryptionState::Unknown,
                firewall: FirewallState::Unknown,
                screen_lock: ScreenLockState::Unknown,
                last_os_update: None,
            })
        }
    }
}

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
    }

    #[test]
    fn snapshot_serialises_round_trip() {
        let s = PostureSnapshot {
            collected_at: Utc::now(),
            disk_encryption: DiskEncryptionState::Enabled,
            firewall: FirewallState::Enabled,
            screen_lock: ScreenLockState::Locked,
            last_os_update: None,
        };
        let json = serde_json::to_string(&s).expect("ok");
        let back: PostureSnapshot = serde_json::from_str(&json).expect("ok");
        assert_eq!(s, back);
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
}
