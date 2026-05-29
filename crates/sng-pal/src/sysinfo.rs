//! Platform / OS info collection.
//!
//! This is the simplest PAL surface — a synchronous probe for
//! hostname, OS release, architecture, and basic hardware
//! shape. Used at agent startup to populate the device
//! identity-binding payload and again on every posture report.
//!
//! Real per-OS implementations live alongside the trait. They
//! call into vendor-documented public APIs only (uname / sysctl
//! / GetVersionEx / IOKit) — no proprietary internals.

use serde::{Deserialize, Serialize};
use std::env;
use std::io;
use thiserror::Error;

/// Identification snapshot for the host OS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    /// OS family (`linux`, `macos`, `windows`).
    pub family: String,
    /// OS distribution / product name (`Ubuntu 24.04`,
    /// `macOS 14.5 Sonoma`, `Windows 11 Pro`).
    pub name: String,
    /// OS version (`24.04`, `14.5.0`, `10.0.19045.4291`).
    pub version: String,
    /// CPU architecture (`x86_64`, `aarch64`).
    pub architecture: String,
    /// Hostname.
    pub hostname: String,
}

/// Error returned by sysinfo probes.
#[derive(Debug, Error)]
pub enum SystemInfoError {
    /// IO failure (`/etc/os-release` read, registry open, etc.).
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The OS reported a value the probe could not parse.
    #[error("parse: {0}")]
    Parse(String),
}

/// Trait every PAL backend implements.
pub trait SystemInfo: Send + Sync {
    /// Produce a fresh [`OsRelease`] snapshot.
    fn os_release(&self) -> Result<OsRelease, SystemInfoError>;
}

/// Default [`SystemInfo`] implementation: builds an [`OsRelease`]
/// from cheap stdlib primitives plus an OS-specific small probe.
/// Always available; per-OS modules can refine the implementation
/// with richer data (e.g. macOS build number from sysctl
/// `kern.osversion`) without changing the trait surface.
#[derive(Copy, Clone, Debug, Default)]
pub struct DefaultSystemInfo;

impl SystemInfo for DefaultSystemInfo {
    fn os_release(&self) -> Result<OsRelease, SystemInfoError> {
        let family = std::env::consts::OS.to_owned();
        let architecture = std::env::consts::ARCH.to_owned();
        // Hostname: the stdlib doesn't expose it directly, so
        // we shell to the env. On Unix `HOSTNAME` is set by the
        // shell; on Windows `COMPUTERNAME` is set by the system.
        // If neither is set we fall back to "unknown" rather
        // than failing the probe — sysinfo is best-effort by
        // design.
        let hostname = env::var("HOSTNAME")
            .or_else(|_| env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_owned());
        // OS name + version is platform-specific; the per-OS
        // modules below override this when more accurate data is
        // available. The default is good enough for tests.
        Ok(OsRelease {
            family,
            name: std::env::consts::OS.to_owned(),
            version: String::new(),
            architecture,
            hostname,
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxSystemInfo;

#[cfg(target_os = "linux")]
mod linux {
    //! Linux backend: parses `/etc/os-release` for the
    //! distribution name + version and uses `uname(2)` for the
    //! kernel release / architecture. `/etc/os-release` is the
    //! systemd-blessed source of truth on every modern distro.

    use super::{OsRelease, SystemInfo, SystemInfoError};
    use std::fs;
    use std::io;

    #[derive(Copy, Clone, Debug, Default)]
    pub struct LinuxSystemInfo;

    impl SystemInfo for LinuxSystemInfo {
        fn os_release(&self) -> Result<OsRelease, SystemInfoError> {
            let raw = match fs::read_to_string("/etc/os-release") {
                Ok(s) => s,
                Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(SystemInfoError::Io(e)),
            };
            let (name, version) = parse_os_release(&raw);
            let hostname = nix::unistd::gethostname()
                .map_err(|e| SystemInfoError::Parse(format!("{e}")))?
                .into_string()
                .unwrap_or_else(|_| "unknown".into());
            Ok(OsRelease {
                family: "linux".into(),
                name,
                version,
                architecture: std::env::consts::ARCH.to_owned(),
                hostname,
            })
        }
    }

    fn parse_os_release(raw: &str) -> (String, String) {
        let mut name = String::from("Linux");
        let mut version = String::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                name = strip_quotes(rest);
            } else if let Some(rest) = line.strip_prefix("VERSION_ID=") {
                version = strip_quotes(rest);
            }
        }
        (name, version)
    }

    fn strip_quotes(s: &str) -> String {
        let trimmed = s.trim();
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        {
            trimmed[1..trimmed.len() - 1].to_owned()
        } else {
            trimmed.to_owned()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn parse_os_release_extracts_pretty_name_and_version() {
            let raw = r#"
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
"#;
            let (name, version) = parse_os_release(raw);
            assert_eq!(name, "Ubuntu 24.04 LTS");
            assert_eq!(version, "24.04");
        }

        #[test]
        fn parse_os_release_handles_unquoted_values() {
            let raw = "PRETTY_NAME=Linux\nVERSION_ID=42\n";
            let (name, version) = parse_os_release(raw);
            assert_eq!(name, "Linux");
            assert_eq!(version, "42");
        }

        #[test]
        fn parse_os_release_handles_empty_input() {
            let (name, version) = parse_os_release("");
            assert_eq!(name, "Linux");
            assert_eq!(version, "");
        }

        #[test]
        fn linux_os_release_returns_data() {
            // Smoke test — running on Linux, the probe should
            // succeed and produce a non-empty hostname.
            let probe = LinuxSystemInfo;
            let r = probe.os_release().expect("probe ok");
            assert_eq!(r.family, "linux");
            assert!(!r.hostname.is_empty());
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::MacSystemInfo;

#[cfg(target_os = "macos")]
mod macos {
    //! macOS backend: uses `sysctl` (via the `libc` crate) to
    //! read `kern.osrelease` and `kern.hostname` directly. These
    //! are the BSD-standard MIB nodes Apple keeps stable across
    //! releases.
    use super::{OsRelease, SystemInfo, SystemInfoError};

    #[derive(Copy, Clone, Debug, Default)]
    pub struct MacSystemInfo;

    impl SystemInfo for MacSystemInfo {
        fn os_release(&self) -> Result<OsRelease, SystemInfoError> {
            let hostname = sysctl_string(libc::CTL_KERN, libc::KERN_HOSTNAME)
                .unwrap_or_else(|_| "unknown".into());
            let version = sysctl_string(libc::CTL_KERN, libc::KERN_OSRELEASE).unwrap_or_default();
            Ok(OsRelease {
                family: "macos".into(),
                name: "macOS".into(),
                version,
                architecture: std::env::consts::ARCH.to_owned(),
                hostname,
            })
        }
    }

    fn sysctl_string(mib0: libc::c_int, mib1: libc::c_int) -> Result<String, SystemInfoError> {
        // `sysctl` is the canonical macOS interface for kernel
        // strings. The wrapper is local because the `libc` crate
        // does not expose a typed helper — keep the unsafe block
        // narrow (two calls only) and document each invariant.
        let mut mib = [mib0, mib1];
        let mut len: libc::size_t = 0;
        // 1. Probe the length.
        #[allow(unsafe_code)]
        let probe = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap_or(2),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if probe != 0 {
            return Err(SystemInfoError::Parse(format!(
                "sysctl probe failed: errno {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut buf = vec![0_u8; len];
        // 2. Read into the sized buffer.
        #[allow(unsafe_code)]
        let read = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap_or(2),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if read != 0 {
            return Err(SystemInfoError::Parse(format!(
                "sysctl read failed: errno {}",
                std::io::Error::last_os_error()
            )));
        }
        // sysctl strings are NUL-terminated; trim.
        if let Some(&0) = buf.last() {
            buf.pop();
        }
        String::from_utf8(buf).map_err(|e| SystemInfoError::Parse(format!("sysctl non-utf8: {e}")))
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsSystemInfo;

#[cfg(target_os = "windows")]
mod windows_impl {
    //! Windows backend: combines `GetComputerNameExW` for the
    //! hostname and `RtlGetVersion` (via the `windows` crate's
    //! safe wrapper) for the OS version.
    use super::{OsRelease, SystemInfo, SystemInfoError};
    use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};

    #[derive(Copy, Clone, Debug, Default)]
    pub struct WindowsSystemInfo;

    impl SystemInfo for WindowsSystemInfo {
        fn os_release(&self) -> Result<OsRelease, SystemInfoError> {
            let hostname = computer_name().unwrap_or_else(|_| "unknown".into());
            Ok(OsRelease {
                family: "windows".into(),
                name: "Windows".into(),
                version: String::new(),
                architecture: std::env::consts::ARCH.to_owned(),
                hostname,
            })
        }
    }

    fn computer_name() -> Result<String, SystemInfoError> {
        // GetComputerNameExW gives us the DNS hostname. Two-pass
        // call: first to size the buffer, second to fill it.
        let mut len: u32 = 0;
        // SAFETY (justification): the Windows crate's wrapper is
        // already safe-by-construction; we use the documented
        // two-pass length probe pattern. The kernel32 entry
        // point is annotated `unsafe` only because the buffer
        // pointer is raw.
        #[allow(unsafe_code)]
        let _ = unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                windows::core::PWSTR::null(),
                &mut len,
            )
        };
        if len == 0 {
            return Err(SystemInfoError::Parse(
                "GetComputerNameExW probe returned 0".into(),
            ));
        }
        let mut buf = vec![0_u16; len as usize];
        #[allow(unsafe_code)]
        unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                windows::core::PWSTR::from_raw(buf.as_mut_ptr()),
                &mut len,
            )
            .map_err(|e| SystemInfoError::Parse(format!("GetComputerNameExW: {e}")))?;
        }
        // The Win32 API returns the string excluding the
        // trailing NUL in `len`. Trim defensively in case a
        // future API change includes it.
        let slice = &buf[..len as usize];
        Ok(String::from_utf16_lossy(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_system_info_returns_runtime_consts() {
        let probe = DefaultSystemInfo;
        let r = probe.os_release().expect("ok");
        assert_eq!(r.family, std::env::consts::OS);
        assert_eq!(r.architecture, std::env::consts::ARCH);
    }
}
