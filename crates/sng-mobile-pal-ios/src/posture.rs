// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! [`IosPostureCollector`] — the iOS [`MobilePostureCollector`] backend.
//!
//! It assembles a [`MobilePostureSnapshot`] from:
//!
//! * **`os_version`** — `NSProcessInfo.operatingSystemVersion`.
//! * **`passcode_set`** — `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`
//!   (fails with `LAErrorPasscodeNotSet` when no passcode is set).
//! * **`biometric_ready`** — `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
//! * **`jailbroken`** — a union of cheap, independent heuristics, any of
//!   which flags the device: a known jailbreak artifact **path** exists
//!   (Cydia, the substrate dylib, an unsandboxed shell, …); a **`fork()`**
//!   succeeds (the app sandbox normally forbids spawning processes); a
//!   protected **system path** under `/private/` is writable; or a
//!   jailbreak-manager **URL scheme** (`cydia://`/`sileo://`) reports
//!   openable via `UIApplication.canOpenURL` (requires the schemes to be
//!   declared in `LSApplicationQueriesSchemes`).
//! * **`mdm_enrolled`** — presence of an MDM-pushed *Managed App
//!   Configuration* under the documented `NSUserDefaults` key, which an
//!   app can read with no special entitlement.
//! * **`root_detected`** — always `None`: it is the Android-only signal,
//!   left unknown on iOS per the `MobilePostureSnapshot` contract.
//!
//! The signal→snapshot mapping and the jailbreak decision are pure and
//! host-tested; only the platform probes are `#[cfg(target_os = "ios")]`.
//! The host fallback returns [`PostureError::Unavailable`].

use async_trait::async_trait;
use sng_mobile_core::{MobilePostureCollector, MobilePostureSnapshot, PostureError};

/// iOS [`MobilePostureCollector`].
#[derive(Debug, Clone)]
pub struct IosPostureCollector {
    // Read only by the iOS `collect()` path to stamp the snapshot; the
    // host fallback returns `Unavailable` before touching it.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    agent_version: String,
}

impl Default for IosPostureCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosPostureCollector {
    /// Construct a collector that stamps snapshots with this crate's
    /// version as the agent version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Construct a collector that stamps snapshots with a caller-chosen
    /// agent version (e.g. the host app's marketing version).
    #[must_use]
    pub fn with_agent_version(agent_version: impl Into<String>) -> Self {
        Self {
            agent_version: agent_version.into(),
        }
    }
}

/// Filesystem paths whose presence indicates a jailbroken device.
///
/// `pub` so the host app / tests can audit exactly what is probed.
pub const JAILBREAK_PATHS: &[&str] = &[
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/var/jb",
];

/// Platform-independent posture helpers — compiled on iOS (used by the
/// probe) and under `test` (host-verified); gated out of the plain
/// Linux library build to keep the `-D warnings` build dead-code-free.
#[cfg(any(target_os = "ios", test))]
mod logic {
    use chrono::Utc;
    use sng_mobile_core::MobilePostureSnapshot;

    /// Raw, platform-gathered posture signals, before mapping onto the
    /// wire snapshot. `None` means "could not determine".
    #[derive(Debug, Default, Clone)]
    pub(super) struct IosPostureSignals {
        pub os_version: String,
        pub passcode_set: Option<bool>,
        pub biometric_ready: Option<bool>,
        pub jailbroken: Option<bool>,
        pub mdm_enrolled: Option<bool>,
    }

    /// Path-existence half of the jailbreak heuristic. Pure so the host
    /// tests can drive it with a fake filesystem; on device it is fed
    /// real `Path::exists`. Feeds [`JailbreakSignals::suspicious_path_present`].
    pub(super) fn detect_jailbreak<F: Fn(&str) -> bool>(exists: F) -> bool {
        super::JAILBREAK_PATHS.iter().any(|p| exists(p))
    }

    /// The independent, cheap jailbreak heuristics, already reduced to
    /// booleans by the platform probes. Kept separate from the decision
    /// so the decision stays pure and host-testable over the full truth
    /// table.
    // The fields are genuinely independent, equally-weighted boolean
    // signals (not a state machine), so a flat record is the clearest
    // model; the pedantic `struct_excessive_bools` heuristic does not fit.
    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug, Default, Clone, Copy)]
    pub(super) struct JailbreakSignals {
        /// A known jailbreak artifact path exists on disk.
        pub suspicious_path_present: bool,
        /// `fork()` succeeded — the app sandbox normally forbids it.
        pub can_fork: bool,
        /// A protected system path (under `/private/`) was writable.
        pub system_path_writable: bool,
        /// A jailbreak-manager URL scheme (`cydia://`/`sileo://`) is
        /// reported openable by `UIApplication.canOpenURL`.
        pub jailbreak_scheme_openable: bool,
    }

    /// Decide jailbreak from the collected signals. Pure: the device is
    /// flagged if *any* heuristic fires (each is individually a strong
    /// indicator, so the union maximizes detection).
    pub(super) fn is_jailbroken(signals: &JailbreakSignals) -> bool {
        signals.suspicious_path_present
            || signals.can_fork
            || signals.system_path_writable
            || signals.jailbreak_scheme_openable
    }

    /// Map raw signals + agent metadata onto the wire snapshot.
    /// `root_detected` is always `None` (Android-only).
    pub(super) fn to_snapshot(
        signals: IosPostureSignals,
        agent_version: &str,
    ) -> MobilePostureSnapshot {
        MobilePostureSnapshot {
            os_version: signals.os_version,
            agent_version: agent_version.to_owned(),
            collected_at: Some(Utc::now()),
            passcode_set: signals.passcode_set,
            jailbroken: signals.jailbroken,
            root_detected: None,
            biometric_ready: signals.biometric_ready,
            mdm_enrolled: signals.mdm_enrolled,
        }
    }
}

// ---------------------------------------------------------------------
// iOS backend
// ---------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod probe {
    use super::logic::{IosPostureSignals, JailbreakSignals, detect_jailbreak, is_jailbroken};
    use objc2::MainThreadMarker;
    use objc2_foundation::{NSProcessInfo, NSString, NSURL, NSUserDefaults};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use objc2_ui_kit::UIApplication;

    /// `NSUserDefaults` key under which an MDM pushes Managed App
    /// Configuration.
    const MANAGED_CONFIG_KEY: &str = "com.apple.configuration.managed";

    /// A protected path the app sandbox forbids writing to; writability
    /// is a jailbreak signal.
    const PRIVATE_WRITE_PROBE: &str = "/private/.sng_jailbreak_probe";

    /// Jailbreak-manager URL schemes probed via `canOpenURL`. The host
    /// app must list these under `LSApplicationQueriesSchemes` for the
    /// query to return a meaningful result.
    const JAILBREAK_URL_SCHEMES: &[&str] = &["cydia://package/test", "sileo://"];

    fn os_version() -> String {
        let v = NSProcessInfo::processInfo().operatingSystemVersion();
        format!("{}.{}.{}", v.majorVersion, v.minorVersion, v.patchVersion)
    }

    #[allow(unsafe_code)]
    fn can_evaluate(policy: LAPolicy) -> bool {
        // SAFETY: `LAContext::new()` yields a fresh context with no
        // outstanding invariants, and `canEvaluatePolicy:error:` is a
        // read-only capability query that takes only the policy enum.
        // No raw pointers or aliasing are involved.
        unsafe {
            let ctx = LAContext::new();
            ctx.canEvaluatePolicy_error(policy).is_ok()
        }
    }

    fn mdm_enrolled() -> bool {
        let key = NSString::from_str(MANAGED_CONFIG_KEY);
        NSUserDefaults::standardUserDefaults()
            .objectForKey(&key)
            .is_some()
    }

    /// `fork()` succeeds only outside the app sandbox, so a successful
    /// fork is a strong jailbreak signal. The child terminates
    /// immediately and the parent reaps it.
    #[allow(unsafe_code)]
    fn fork_succeeds() -> bool {
        // SAFETY: `fork` has no preconditions. In the child we call only
        // the async-signal-safe `_exit`, touching no shared state across
        // the boundary; the parent reaps the child via `waitpid`.
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                return false; // sandbox refused the fork: not jailbroken.
            }
            if pid == 0 {
                libc::_exit(0); // child: terminate immediately (diverges).
            }
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &raw mut status, 0);
            true
        }
    }

    /// A non-jailbroken sandbox cannot write under `/private/`; if the
    /// write succeeds the device is jailbroken. The probe file is
    /// removed afterwards.
    fn system_path_writable() -> bool {
        use std::io::Write as _;
        let Ok(mut file) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(PRIVATE_WRITE_PROBE)
        else {
            return false;
        };
        let wrote = file.write_all(b"sng").is_ok();
        drop(file);
        let _ = std::fs::remove_file(PRIVATE_WRITE_PROBE);
        wrote
    }

    /// Probe whether a jailbreak-manager URL scheme is openable. Must run
    /// on the main thread; if it cannot, the signal is treated as absent
    /// (the other heuristics still apply).
    fn jailbreak_scheme_openable() -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        let app = UIApplication::sharedApplication(mtm);
        JAILBREAK_URL_SCHEMES.iter().any(|scheme| {
            NSURL::URLWithString(&NSString::from_str(scheme))
                .is_some_and(|url| app.canOpenURL(&url))
        })
    }

    /// Gather every signal from the live device.
    pub(super) fn collect_signals() -> IosPostureSignals {
        let jailbreak = JailbreakSignals {
            suspicious_path_present: detect_jailbreak(|p| std::path::Path::new(p).exists()),
            can_fork: fork_succeeds(),
            system_path_writable: system_path_writable(),
            jailbreak_scheme_openable: jailbreak_scheme_openable(),
        };
        IosPostureSignals {
            os_version: os_version(),
            passcode_set: Some(can_evaluate(LAPolicy::DeviceOwnerAuthentication)),
            biometric_ready: Some(can_evaluate(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            )),
            jailbroken: Some(is_jailbroken(&jailbreak)),
            mdm_enrolled: Some(mdm_enrolled()),
        }
    }
}

#[cfg(target_os = "ios")]
#[async_trait]
impl MobilePostureCollector for IosPostureCollector {
    async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError> {
        let signals = probe::collect_signals();
        Ok(logic::to_snapshot(signals, &self.agent_version))
    }
}

// ---------------------------------------------------------------------
// Host fallback (Linux CI / desktop dev): typed "unsupported".
// ---------------------------------------------------------------------
#[cfg(not(target_os = "ios"))]
#[async_trait]
impl MobilePostureCollector for IosPostureCollector {
    async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("posture collect".into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::logic::{
        IosPostureSignals, JailbreakSignals, detect_jailbreak, is_jailbroken, to_snapshot,
    };
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    #[test]
    fn clean_device_is_not_jailbroken() {
        // No path exists.
        assert!(!detect_jailbreak(|_| false));
    }

    #[test]
    fn any_suspicious_path_flags_jailbreak() {
        // Only Cydia present.
        let present: HashSet<&str> = ["/Applications/Cydia.app"].into_iter().collect();
        assert!(detect_jailbreak(|p| present.contains(p)));
        // A path that is not in the heuristic list does not flag.
        let unrelated: HashSet<&str> = ["/Applications/Safari.app"].into_iter().collect();
        assert!(!detect_jailbreak(|p| unrelated.contains(p)));
    }

    #[test]
    fn no_signal_means_not_jailbroken() {
        // All heuristics negative → clean device.
        assert!(!is_jailbroken(&JailbreakSignals::default()));
    }

    #[test]
    fn any_single_signal_flags_jailbreak() {
        // Each heuristic alone is sufficient to flag the device.
        for signals in [
            JailbreakSignals {
                suspicious_path_present: true,
                ..Default::default()
            },
            JailbreakSignals {
                can_fork: true,
                ..Default::default()
            },
            JailbreakSignals {
                system_path_writable: true,
                ..Default::default()
            },
            JailbreakSignals {
                jailbreak_scheme_openable: true,
                ..Default::default()
            },
        ] {
            assert!(
                is_jailbroken(&signals),
                "expected jailbreak for {signals:?}"
            );
        }
    }

    #[test]
    fn all_signals_set_flags_jailbreak() {
        assert!(is_jailbroken(&JailbreakSignals {
            suspicious_path_present: true,
            can_fork: true,
            system_path_writable: true,
            jailbreak_scheme_openable: true,
        }));
    }

    #[test]
    fn mapping_fills_fields_and_leaves_root_unknown() {
        let signals = IosPostureSignals {
            os_version: "17.4.1".into(),
            passcode_set: Some(true),
            biometric_ready: Some(true),
            jailbroken: Some(false),
            mdm_enrolled: Some(true),
        };
        let snap = to_snapshot(signals, "9.9.9");
        assert_eq!(snap.os_version, "17.4.1");
        assert_eq!(snap.agent_version, "9.9.9");
        assert_eq!(snap.passcode_set, Some(true));
        assert_eq!(snap.biometric_ready, Some(true));
        assert_eq!(snap.jailbroken, Some(false));
        assert_eq!(snap.mdm_enrolled, Some(true));
        // Android-only signal stays unknown on iOS.
        assert_eq!(snap.root_detected, None);
        assert!(snap.collected_at.is_some());
        assert!(!snap.is_compromised());
    }

    #[test]
    fn mapping_propagates_unknown_signals() {
        let snap = to_snapshot(IosPostureSignals::default(), "1.0.0");
        assert_eq!(snap.passcode_set, None);
        assert_eq!(snap.biometric_ready, None);
        assert_eq!(snap.jailbroken, None);
        assert_eq!(snap.mdm_enrolled, None);
        // Unknown jailbreak must not be read as compromised.
        assert!(!snap.is_compromised());
    }

    #[test]
    fn jailbroken_snapshot_is_compromised() {
        let signals = IosPostureSignals {
            jailbroken: Some(true),
            ..Default::default()
        };
        assert!(to_snapshot(signals, "1.0.0").is_compromised());
    }

    #[test]
    fn collector_defaults_to_crate_version() {
        let c = IosPostureCollector::new();
        assert_eq!(c.agent_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            IosPostureCollector::with_agent_version("2.3.4").agent_version,
            "2.3.4"
        );
    }

    #[cfg(not(target_os = "ios"))]
    #[tokio::test]
    async fn host_fallback_is_unsupported_not_panic() {
        let c = IosPostureCollector::new();
        assert!(matches!(
            c.collect().await,
            Err(PostureError::Unavailable(_))
        ));
    }
}
