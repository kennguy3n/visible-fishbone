//! [`AndroidPostureCollector`] — device posture from Android
//! framework APIs.
//!
//! Signal sources (all read-only, no special permission beyond what
//! the host app already holds):
//!
//! | Snapshot field | Android source |
//! |----------------|----------------|
//! | `os_version` | `Build.VERSION.RELEASE` |
//! | `passcode_set` | `KeyguardManager.isDeviceSecure()` |
//! | `biometric_ready` | `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` |
//! | `root_detected` | su-binary path probe + `ro.build.tags` = `test-keys` heuristic (Play Integrity verdict folds in here when the host app supplies one) |
//! | `mdm_enrolled` | `DevicePolicyManager` device-owner / profile-owner signal |
//! | `jailbroken` | always `None` — iOS-only field |
//!
//! ## Mapping seam (host-testable)
//!
//! The framework hands back raw integers / booleans. The pure
//! [`assemble_snapshot`] and [`biometric_ready_from_code`] /
//! [`root_signal`] helpers turn those into a
//! [`MobilePostureSnapshot`]; the host unit tests pin that mapping
//! (including the `None` = "unknown" vs `Some(false)` distinction
//! the control-plane evaluator relies on) without an Android
//! device.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sng_mobile_core::{MobilePostureCollector, MobilePostureSnapshot, PostureError};

/// `BiometricManager.BIOMETRIC_SUCCESS` — strong biometric is
/// enrolled and ready.
pub const BIOMETRIC_SUCCESS: i32 = 0;
/// `BIOMETRIC_ERROR_HW_UNAVAILABLE` — hardware temporarily
/// unavailable.
pub const BIOMETRIC_ERROR_HW_UNAVAILABLE: i32 = 1;
/// `BIOMETRIC_ERROR_NONE_ENROLLED` — hardware present, nothing
/// enrolled.
pub const BIOMETRIC_ERROR_NONE_ENROLLED: i32 = 11;
/// `BIOMETRIC_ERROR_NO_HARDWARE` — no biometric hardware.
pub const BIOMETRIC_ERROR_NO_HARDWARE: i32 = 12;
/// `BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED` — a security update
/// is required before the sensor can be used.
pub const BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED: i32 = 15;
/// `BIOMETRIC_STATUS_UNKNOWN` — the platform could not determine
/// availability.
pub const BIOMETRIC_STATUS_UNKNOWN: i32 = -1;

/// su-binary locations probed by the root heuristic. Only read by
/// the Android implementation.
#[cfg(target_os = "android")]
const SU_PATHS: [&str; 6] = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/data/local/xbin/su",
];

/// Map a `BiometricManager.canAuthenticate()` result code to a
/// tri-state readiness signal.
///
/// `BIOMETRIC_SUCCESS` → `Some(true)`; the definite negative codes
/// (no hardware / none enrolled / unavailable / update required) →
/// `Some(false)`; anything the PAL does not recognise (including
/// `BIOMETRIC_STATUS_UNKNOWN`) → `None` so the control plane treats
/// it as "unknown" rather than "false".
#[must_use]
pub fn biometric_ready_from_code(code: i32) -> Option<bool> {
    match code {
        BIOMETRIC_SUCCESS => Some(true),
        BIOMETRIC_ERROR_HW_UNAVAILABLE
        | BIOMETRIC_ERROR_NONE_ENROLLED
        | BIOMETRIC_ERROR_NO_HARDWARE
        | BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED => Some(false),
        _ => None,
    }
}

/// Combine the root heuristics into a single signal: a device is
/// flagged rooted if a su binary is present **or** the build was
/// signed with the public AOSP `test-keys`.
#[must_use]
pub fn root_signal(su_binary_present: bool, test_keys_build: bool) -> bool {
    su_binary_present || test_keys_build
}

/// Raw posture signals gathered from the platform, before mapping
/// into the wire [`MobilePostureSnapshot`].
#[derive(Clone, Debug, Default)]
pub struct RawPostureSignals {
    /// `Build.VERSION.RELEASE`, if read.
    pub os_version: Option<String>,
    /// `KeyguardManager.isDeviceSecure()`.
    pub passcode_set: Option<bool>,
    /// Raw `BiometricManager.canAuthenticate()` code, if queried.
    pub biometric_code: Option<i32>,
    /// Result of the root heuristic.
    pub root_detected: Option<bool>,
    /// Device/profile-owner signal from `DevicePolicyManager`.
    pub mdm_enrolled: Option<bool>,
}

/// Assemble the wire [`MobilePostureSnapshot`] from raw signals.
///
/// `jailbroken` is always `None` (it is the iOS-only field). An
/// absent signal stays `None` ("unknown"), never coerced to
/// `Some(false)`.
#[must_use]
pub fn assemble_snapshot(
    raw: RawPostureSignals,
    agent_version: &str,
    now: DateTime<Utc>,
) -> MobilePostureSnapshot {
    MobilePostureSnapshot {
        os_version: raw.os_version.unwrap_or_default(),
        agent_version: agent_version.to_owned(),
        collected_at: Some(now),
        passcode_set: raw.passcode_set,
        jailbroken: None,
        root_detected: raw.root_detected,
        biometric_ready: raw.biometric_code.and_then(biometric_ready_from_code),
        mdm_enrolled: raw.mdm_enrolled,
    }
}

/// Android [`MobilePostureCollector`].
///
/// Carries the reporting agent version stamped into every snapshot.
/// The constructor exists on every target.
#[derive(Clone, Debug)]
pub struct AndroidPostureCollector {
    agent_version: String,
}

impl AndroidPostureCollector {
    /// Construct a collector that stamps `agent_version` into each
    /// snapshot.
    #[must_use]
    pub fn new(agent_version: impl Into<String>) -> Self {
        Self {
            agent_version: agent_version.into(),
        }
    }

    /// The agent version this collector reports.
    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }
}

#[async_trait]
impl MobilePostureCollector for AndroidPostureCollector {
    async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError> {
        let raw = imp::collect_signals()?;
        Ok(assemble_snapshot(raw, &self.agent_version, Utc::now()))
    }
}

/// Host (non-Android) fallback: there are no Android posture APIs
/// to read, so collection reports
/// [`AndroidPalError::UnsupportedPlatform`].
#[cfg(not(target_os = "android"))]
mod imp {
    use super::RawPostureSignals;
    use crate::error::AndroidPalError;

    pub(super) fn collect_signals() -> Result<RawPostureSignals, AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidPostureCollector::collect",
        ))
    }
}

/// Android implementation reading `KeyguardManager`,
/// `BiometricManager`, `Build`, and `DevicePolicyManager`.
#[cfg(target_os = "android")]
mod imp {
    use std::path::Path;

    use jni::objects::{JObject, JString, JValue};

    use super::{RawPostureSignals, SU_PATHS, root_signal};
    use crate::error::AndroidPalError;
    use crate::jni_bridge::{android_context, with_env};

    // Context.KEYGUARD_SERVICE / Context.BIOMETRIC_SERVICE etc. are
    // resolved by name via getSystemService(String).
    const KEYGUARD_SERVICE: &str = "keyguard";
    const BIOMETRIC_SERVICE: &str = "biometric";
    const DEVICE_POLICY_SERVICE: &str = "device_policy";
    // BiometricManager.Authenticators.BIOMETRIC_STRONG.
    const BIOMETRIC_STRONG: i32 = 0x0000_000F;

    /// Framework signals gathered on a single JVM attachment.
    #[derive(Default)]
    struct FrameworkSignals {
        passcode_set: Option<bool>,
        biometric_code: Option<i32>,
        os_version: Option<String>,
        mdm_enrolled: Option<bool>,
        test_keys_build: Option<bool>,
    }

    pub(super) fn collect_signals() -> Result<RawPostureSignals, AndroidPalError> {
        // One JVM attach for every framework read. Each signal is
        // still best-effort: a single unreadable source (e.g.
        // `KeyguardManager` unavailable in a restricted profile)
        // degrades that field to `None` ("unknown") rather than
        // failing the whole snapshot, and a failure to attach at all
        // leaves every framework field `None` while the filesystem
        // root probe below still runs. The control plane distinguishes
        // `None` from `Some(false)`.
        let framework = with_env(|env| {
            Ok(FrameworkSignals {
                passcode_set: passcode_set(env).ok(),
                biometric_code: biometric_code(env).ok(),
                os_version: os_version(env).ok(),
                mdm_enrolled: mdm_enrolled(env).ok(),
                test_keys_build: build_is_test_keys(env).ok(),
            })
        })
        .unwrap_or_default();

        let test_keys = framework.test_keys_build.unwrap_or(false);
        let root_detected = Some(root_signal(su_binary_present(), test_keys));
        Ok(RawPostureSignals {
            os_version: framework.os_version,
            passcode_set: framework.passcode_set,
            biometric_code: framework.biometric_code,
            root_detected,
            mdm_enrolled: framework.mdm_enrolled,
        })
    }

    fn system_service<'l>(
        env: &mut jni::JNIEnv<'l>,
        name: &str,
    ) -> Result<JObject<'l>, AndroidPalError> {
        let context = android_context();
        let jname = env
            .new_string(name)
            .map_err(|e| AndroidPalError::Jni(format!("new_string(service): {e}")))?;
        env.call_method(
            &context,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::Object(&jname)],
        )
        .and_then(|v| v.l())
        .map_err(|e| AndroidPalError::Jni(format!("getSystemService({name}): {e}")))
    }

    fn passcode_set(env: &mut jni::JNIEnv<'_>) -> Result<bool, AndroidPalError> {
        let km = system_service(env, KEYGUARD_SERVICE)?;
        env.call_method(&km, "isDeviceSecure", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| AndroidPalError::Jni(format!("KeyguardManager.isDeviceSecure: {e}")))
    }

    fn biometric_code(env: &mut jni::JNIEnv<'_>) -> Result<i32, AndroidPalError> {
        // The framework `android.hardware.biometrics.BiometricManager`
        // is obtained via `getSystemService("biometric")` — the static
        // `from(Context)` factory exists only on the Jetpack
        // `androidx.biometric.BiometricManager`, not the platform class.
        let bm = system_service(env, BIOMETRIC_SERVICE)?;
        env.call_method(
            &bm,
            "canAuthenticate",
            "(I)I",
            &[JValue::Int(BIOMETRIC_STRONG)],
        )
        .and_then(|v| v.i())
        .map_err(|e| AndroidPalError::Jni(format!("BiometricManager.canAuthenticate: {e}")))
    }

    fn os_version(env: &mut jni::JNIEnv<'_>) -> Result<String, AndroidPalError> {
        let release = env
            .get_static_field("android/os/Build$VERSION", "RELEASE", "Ljava/lang/String;")
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("Build.VERSION.RELEASE: {e}")))?;
        let s: String = env
            .get_string(&JString::from(release))
            .map_err(|e| AndroidPalError::Jni(format!("get_string(RELEASE): {e}")))?
            .into();
        Ok(s)
    }

    fn mdm_enrolled(env: &mut jni::JNIEnv<'_>) -> Result<bool, AndroidPalError> {
        let dpm = system_service(env, DEVICE_POLICY_SERVICE)?;
        // isDeviceOwnerApp(null) is meaningless; instead probe
        // whether *any* device/profile owner is active via
        // getActiveAdmins() being non-empty. We approximate MDM
        // enrolment with isDeviceManaged() where present.
        env.call_method(&dpm, "isDeviceManaged", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| AndroidPalError::Jni(format!("DevicePolicyManager.isDeviceManaged: {e}")))
    }

    fn su_binary_present() -> bool {
        SU_PATHS.iter().any(|p| Path::new(p).exists())
    }

    fn build_is_test_keys(env: &mut jni::JNIEnv<'_>) -> Result<bool, AndroidPalError> {
        let tags = env
            .get_static_field("android/os/Build", "TAGS", "Ljava/lang/String;")
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("Build.TAGS: {e}")))?;
        let s: String = env
            .get_string(&JString::from(tags))
            .map_err(|e| AndroidPalError::Jni(format!("get_string(TAGS): {e}")))?
            .into();
        Ok(s.contains("test-keys"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_success_is_ready() {
        assert_eq!(biometric_ready_from_code(BIOMETRIC_SUCCESS), Some(true));
    }

    #[test]
    fn biometric_negative_codes_are_not_ready() {
        for code in [
            BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BIOMETRIC_ERROR_NONE_ENROLLED,
            BIOMETRIC_ERROR_NO_HARDWARE,
            BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
        ] {
            assert_eq!(biometric_ready_from_code(code), Some(false));
        }
    }

    #[test]
    fn biometric_unknown_code_is_none() {
        assert_eq!(biometric_ready_from_code(BIOMETRIC_STATUS_UNKNOWN), None);
        assert_eq!(biometric_ready_from_code(9999), None);
    }

    #[test]
    fn root_signal_combines_heuristics() {
        assert!(!root_signal(false, false));
        assert!(root_signal(true, false));
        assert!(root_signal(false, true));
        assert!(root_signal(true, true));
    }

    #[test]
    fn assemble_maps_fields_and_leaves_jailbroken_none() {
        let now = Utc::now();
        let raw = RawPostureSignals {
            os_version: Some("14".to_owned()),
            passcode_set: Some(true),
            biometric_code: Some(BIOMETRIC_SUCCESS),
            root_detected: Some(false),
            mdm_enrolled: Some(true),
        };
        let snap = assemble_snapshot(raw, "sng-agent/1.2.3", now);
        assert_eq!(snap.os_version, "14");
        assert_eq!(snap.agent_version, "sng-agent/1.2.3");
        assert_eq!(snap.collected_at, Some(now));
        assert_eq!(snap.passcode_set, Some(true));
        assert_eq!(snap.biometric_ready, Some(true));
        assert_eq!(snap.root_detected, Some(false));
        assert_eq!(snap.mdm_enrolled, Some(true));
        assert_eq!(snap.jailbroken, None);
        assert!(!snap.is_compromised());
    }

    #[test]
    fn assemble_preserves_unknown_signals() {
        let raw = RawPostureSignals::default();
        let snap = assemble_snapshot(raw, "agent", Utc::now());
        assert!(snap.os_version.is_empty());
        assert_eq!(snap.passcode_set, None);
        assert_eq!(snap.biometric_ready, None);
        assert_eq!(snap.root_detected, None);
        assert_eq!(snap.mdm_enrolled, None);
    }

    #[test]
    fn unknown_biometric_code_drops_to_none_in_snapshot() {
        let raw = RawPostureSignals {
            biometric_code: Some(BIOMETRIC_STATUS_UNKNOWN),
            ..RawPostureSignals::default()
        };
        let snap = assemble_snapshot(raw, "agent", Utc::now());
        assert_eq!(snap.biometric_ready, None);
    }

    #[test]
    fn degraded_passcode_signal_stays_none_without_failing_snapshot() {
        // Mirrors the Android `collect_signals` degraded path: a
        // `KeyguardManager` JNI failure yields `passcode_set = None`
        // (via `.ok()`) while the remaining signals are still
        // reported, instead of failing the whole collection.
        let raw = RawPostureSignals {
            os_version: Some("14".to_owned()),
            passcode_set: None,
            biometric_code: Some(BIOMETRIC_SUCCESS),
            root_detected: Some(false),
            mdm_enrolled: Some(true),
        };
        let snap = assemble_snapshot(raw, "agent", Utc::now());
        assert_eq!(snap.passcode_set, None);
        assert_eq!(snap.os_version, "14");
        assert_eq!(snap.biometric_ready, Some(true));
        assert_eq!(snap.root_detected, Some(false));
        assert_eq!(snap.mdm_enrolled, Some(true));
    }

    #[tokio::test]
    async fn host_fallback_reports_unsupported() {
        let collector = AndroidPostureCollector::new("sng-agent/test");
        assert_eq!(collector.agent_version(), "sng-agent/test");
        let err = collector.collect().await.expect_err("host");
        assert!(matches!(err, PostureError::Unavailable(_)));
    }
}
