//! Linux backend.
//!
//! * **Disk encryption** — inspect `/sys/class/block/*/dm/uuid`
//!   for the `CRYPT-LUKS` prefix that dm-crypt writes when a
//!   LUKS volume is open. Read-only, no elevation.
//! * **Firewall** — examine `/proc/net/ip_tables_names` and
//!   `/proc/net/nf_tables` for non-empty contents.
//! * **Screen lock** — requires the systemd-logind dbus
//!   interface; reported `Unknown` for now (see note below).
//! * **Last OS update / patch age** — newest mtime across the
//!   package-manager state dirs (`/var/lib/apt/lists`,
//!   `/var/cache/dnf`, `/var/lib/pacman/sync`).
//! * **OS patch level** — the running kernel release from
//!   `/proc/sys/kernel/osrelease`.
//! * **EDR** — scan `/proc/<pid>/comm` for a recognised EDR
//!   sensor process (CrowdStrike, SentinelOne, Defender for
//!   Endpoint, Carbon Black, …). Linux has no Security-Center
//!   health bit, so a running sensor process is treated as
//!   healthy.
//! * **Antivirus** — a running `clamd` / `freshclam` daemon
//!   with the signature DB mtime under `/var/lib/clamav`
//!   yielding the definition age.
//! * **Certificate health** — derived from the device identity
//!   leaf's validity window, which the agent knows from
//!   enrollment (injected; not re-parsed on every tick).

use super::parse;
use super::{
    AntivirusStatus, CertificateHealth, DiskEncryptionState, EdrState, FirewallState,
    PostureCollector, PostureError, PostureSnapshot, ScreenLockState,
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
    /// ClamAV signature-database files; newest mtime gives the
    /// AV definition age.
    av_definition_paths: Vec<PathBuf>,
    /// Process names whose presence means an AV engine is
    /// active (lower-cased substring match).
    av_process_markers: Vec<String>,
    /// Device identity leaf validity window (from enrollment).
    cert_not_before: Option<DateTime<Utc>>,
    cert_not_after: Option<DateTime<Utc>>,
    /// Lead time before `cert_not_after` to flag `Expiring`.
    cert_renew_within_days: i64,
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
            av_definition_paths: vec![
                PathBuf::from("/var/lib/clamav/daily.cvd"),
                PathBuf::from("/var/lib/clamav/daily.cld"),
                PathBuf::from("/var/lib/clamav/main.cvd"),
                PathBuf::from("/var/lib/clamav/main.cld"),
            ],
            av_process_markers: vec!["clamd".to_owned(), "freshclam".to_owned()],
            cert_not_before: None,
            cert_not_after: None,
            cert_renew_within_days: 14,
        }
    }
}

impl LinuxPostureCollector {
    /// Test constructor with injected fs roots. Leaves the
    /// package-manager / AV / certificate inputs empty so a
    /// test exercises exactly the signal it sets up.
    #[must_use]
    pub fn with_roots(proc_root: PathBuf, sys_root: PathBuf) -> Self {
        Self {
            proc_root,
            sys_root,
            update_paths: vec![],
            av_definition_paths: vec![],
            av_process_markers: vec!["clamd".to_owned(), "freshclam".to_owned()],
            cert_not_before: None,
            cert_not_after: None,
            cert_renew_within_days: 14,
        }
    }

    /// Override the package-manager state paths (test seam).
    #[must_use]
    pub fn with_update_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.update_paths = paths;
        self
    }

    /// Override the AV signature-database paths (test seam).
    #[must_use]
    pub fn with_av_definition_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.av_definition_paths = paths;
        self
    }

    /// Supply the device identity leaf's validity window so the
    /// collector can report certificate health.
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

    fn detect_disk_encryption(&self) -> DiskEncryptionState {
        let class_block = self.sys_root.join("class/block");
        let Ok(entries) = fs::read_dir(&class_block) else {
            return DiskEncryptionState::Unknown;
        };
        for entry in entries.flatten() {
            let uuid_path = entry.path().join("dm/uuid");
            if let Ok(contents) = fs::read_to_string(&uuid_path)
                && contents.starts_with("CRYPT-LUKS")
            {
                return DiskEncryptionState::Enabled;
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

    /// Read the running kernel release (`uname -r` equivalent)
    /// as the OS patch-level identifier.
    fn os_patch_level(&self) -> Option<String> {
        let path = self.proc_root.join("sys/kernel/osrelease");
        let s = fs::read_to_string(path).ok()?;
        let s = s.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_owned())
        }
    }

    /// Enumerate `/proc/<pid>/comm` to get the set of running
    /// process names. The second return value is whether the
    /// scan could be performed at all (so a permission failure
    /// reports `Unknown` rather than a false `NotInstalled`).
    fn running_process_names(&self) -> (Vec<String>, bool) {
        let Ok(entries) = fs::read_dir(&self.proc_root) else {
            return (Vec::new(), false);
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            // Only numeric (pid) directories.
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let comm_path = entry.path().join("comm");
            if let Ok(comm) = fs::read_to_string(&comm_path) {
                let trimmed = comm.trim();
                if !trimmed.is_empty() {
                    names.push(trimmed.to_owned());
                }
            }
        }
        (names, true)
    }

    fn detect_edr(&self) -> EdrState {
        let (names, ok) = self.running_process_names();
        parse::edr_state_from_processes(&names, ok)
    }

    /// AV status from a running clamd/freshclam process, plus
    /// the signature-definition age from the newest DB file
    /// mtime.
    fn detect_antivirus(&self, now: DateTime<Utc>) -> (AntivirusStatus, Option<u32>) {
        let (names, ok) = self.running_process_names();
        let running = ok
            && names.iter().any(|n| {
                let ln = n.to_ascii_lowercase();
                self.av_process_markers
                    .iter()
                    .any(|m| ln.contains(m.as_str()))
            });
        let def_age = self
            .av_definition_paths
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .filter_map(|m| m.modified().ok())
            .filter_map(system_time_to_chrono)
            .max()
            .map(|updated| parse::hours_since(updated, now));
        // Definitions present is strong evidence AV is installed;
        // a running daemon means real-time scanning is on.
        let status = if running {
            AntivirusStatus::Enabled
        } else if def_age.is_some() {
            AntivirusStatus::Disabled
        } else {
            AntivirusStatus::Unknown
        };
        (status, def_age)
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
        let now = Utc::now();
        let last_os_update = self.last_os_update();
        let (antivirus, antivirus_definitions_age_hours) = self.detect_antivirus(now);
        Ok(PostureSnapshot {
            collected_at: now,
            disk_encryption: self.detect_disk_encryption(),
            firewall: self.detect_firewall(),
            // Screen-lock detection requires the systemd-logind
            // dbus interface; reported `Unknown` rather than
            // dropped so the wire schema stays stable (zbus would
            // add ~200kb to the agent binary we do not want until
            // there is a real consumer).
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::tempdir;

    fn write_pid_comm(proc_root: &Path, pid: u32, comm: &str) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
    }

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

    #[tokio::test]
    async fn detects_edr_process_and_kernel_patch_level() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        // Kernel release file.
        let krel = proc.join("sys/kernel");
        fs::create_dir_all(&krel)?;
        fs::write(krel.join("osrelease"), "6.5.0-35-generic\n")?;
        // A running EDR sensor + some noise processes.
        write_pid_comm(&proc, 1, "systemd");
        write_pid_comm(&proc, 1234, "falcon-sensor");
        write_pid_comm(&proc, 9999, "bash");
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        let collector = LinuxPostureCollector::with_roots(proc, sys);
        let snap = collector.collect().await?;
        assert_eq!(snap.edr, EdrState::Healthy);
        assert_eq!(snap.os_patch_level.as_deref(), Some("6.5.0-35-generic"));
        Ok(())
    }

    #[tokio::test]
    async fn reports_edr_not_installed_when_no_sensor() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        write_pid_comm(&proc, 1, "systemd");
        write_pid_comm(&proc, 42, "sshd");
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        let collector = LinuxPostureCollector::with_roots(proc, sys);
        let snap = collector.collect().await?;
        assert_eq!(snap.edr, EdrState::NotInstalled);
        Ok(())
    }

    #[tokio::test]
    async fn antivirus_enabled_and_definition_age_wired_from_db() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        // clamd running -> real-time AV enabled.
        write_pid_comm(&proc, 7, "clamd");
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        // A freshly-written definition DB file (mtime ~now), so
        // the reported age is small and, crucially, present.
        let db = dir.path().join("daily.cld");
        fs::write(&db, "sigs")?;
        let collector =
            LinuxPostureCollector::with_roots(proc, sys).with_av_definition_paths(vec![db]);
        let snap = collector.collect().await?;
        assert_eq!(snap.antivirus, AntivirusStatus::Enabled);
        let age = snap.antivirus_definitions_age_hours.expect("age present");
        assert!(age <= 1, "freshly written db should be ~0h old, got {age}");
        Ok(())
    }

    #[tokio::test]
    async fn antivirus_disabled_when_defs_present_but_no_daemon() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        write_pid_comm(&proc, 1, "systemd");
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        let db = dir.path().join("main.cvd");
        fs::write(&db, "sigs")?;
        let collector =
            LinuxPostureCollector::with_roots(proc, sys).with_av_definition_paths(vec![db]);
        let snap = collector.collect().await?;
        assert_eq!(snap.antivirus, AntivirusStatus::Disabled);
        assert!(snap.antivirus_definitions_age_hours.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn antivirus_unknown_when_nothing_found() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        write_pid_comm(&proc, 1, "systemd");
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        let collector = LinuxPostureCollector::with_roots(proc, sys);
        let snap = collector.collect().await?;
        assert_eq!(snap.antivirus, AntivirusStatus::Unknown);
        assert_eq!(snap.antivirus_definitions_age_hours, None);
        Ok(())
    }

    #[tokio::test]
    async fn certificate_health_from_window() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        // Expired leaf.
        let collector = LinuxPostureCollector::with_roots(proc, sys).with_certificate_window(
            None,
            Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap(),
        );
        let snap = collector.collect().await?;
        assert_eq!(snap.certificate_health, CertificateHealth::Expired);
        Ok(())
    }

    #[tokio::test]
    async fn os_patch_age_wired_from_update_path_mtime() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        // Freshly-created package-manager state dir (mtime ~now).
        let apt = dir.path().join("apt-lists");
        fs::create_dir_all(&apt)?;
        let collector =
            LinuxPostureCollector::with_roots(proc, sys).with_update_paths(vec![apt]);
        let snap = collector.collect().await?;
        assert!(snap.last_os_update.is_some());
        assert_eq!(snap.os_patch_age_days, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn os_patch_age_none_when_no_update_paths() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let proc = dir.path().join("proc");
        fs::create_dir_all(&proc)?;
        let sys = dir.path().join("sys");
        fs::create_dir_all(&sys)?;
        let collector = LinuxPostureCollector::with_roots(proc, sys);
        let snap = collector.collect().await?;
        assert_eq!(snap.os_patch_age_days, None);
        Ok(())
    }
}
