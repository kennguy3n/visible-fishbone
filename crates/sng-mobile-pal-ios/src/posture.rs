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
//! * **`jailbroken`** — a filesystem heuristic: the presence of any of a
//!   set of paths that only exist on a jailbroken device (Cydia, the
//!   substrate dylib, an unsandboxed shell, …).
//! * **`mdm_enrolled`** — presence of an MDM-pushed *Managed App
//!   Configuration* under the documented `NSUserDefaults` key, which an
//!   app can read with no special entitlement.
//! * **`root_detected`** — always `None`: it is the Android-only signal,
//!   left unknown on iOS per the `MobilePostureSnapshot` contract.
//!
//! The signal→snapshot mapping and the jailbreak heuristic are pure and
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

    /// Decide jailbreak from the path-existence predicate. Pure so the
    /// host tests can drive it with a fake filesystem.
    pub(super) fn detect_jailbreak<F: Fn(&str) -> bool>(exists: F) -> bool {
        super::JAILBREAK_PATHS.iter().any(|p| exists(p))
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
    use super::logic::{IosPostureSignals, detect_jailbreak};
    use objc2_foundation::{NSProcessInfo, NSString, NSUserDefaults};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// `NSUserDefaults` key under which an MDM pushes Managed App
    /// Configuration.
    const MANAGED_CONFIG_KEY: &str = "com.apple.configuration.managed";

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

    /// Gather every signal from the live device.
    pub(super) fn collect_signals() -> IosPostureSignals {
        IosPostureSignals {
            os_version: os_version(),
            passcode_set: Some(can_evaluate(LAPolicy::DeviceOwnerAuthentication)),
            biometric_ready: Some(can_evaluate(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            )),
            jailbroken: Some(detect_jailbreak(|p| std::path::Path::new(p).exists())),
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
    use super::logic::{IosPostureSignals, detect_jailbreak, to_snapshot};
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
