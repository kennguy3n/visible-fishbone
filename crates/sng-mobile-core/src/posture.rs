//! Mobile device posture: the snapshot shape + the collector trait.
//!
//! [`MobilePostureSnapshot`] mirrors the mobile-specific subset of
//! the Go control plane's `repository.Posture`
//! (`internal/repository/types.go`) field-for-field, including the
//! `omitempty` JSON shape, so a snapshot this crate serializes
//! round-trips cleanly into the device record the operator console
//! reads. The desktop-only signals (disk encryption, firewall, …)
//! are intentionally omitted — a mobile agent must not claim to
//! report posture facts the OS does not expose to it.
//!
//! [`MobilePostureCollector`] is the trait the PAL implements to
//! gather those signals from the platform APIs (iOS
//! `LAContext` / `UIDevice` / jailbreak heuristics, Android
//! `KeyguardManager` / SafetyNet / Play Integrity).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A point-in-time mobile posture snapshot.
///
/// Every signal is an `Option` because a given platform / OS
/// version may not be able to determine it: `None` means "unknown"
/// (the control plane's posture evaluator treats unknown distinctly
/// from `false`), not "false". The field names + `omitempty`
/// behaviour match the Go `repository.Posture` mobile section so
/// the serialized form is wire-compatible with the enrolment /
/// posture-report endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobilePostureSnapshot {
    /// OS version string (e.g. `17.4.1`, `14`). Empty when unknown.
    #[serde(
        rename = "os_version",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub os_version: String,
    /// Reporting agent's version. Empty when unset.
    #[serde(
        rename = "agent_version",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub agent_version: String,
    /// When the snapshot was collected.
    #[serde(
        rename = "collected_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub collected_at: Option<DateTime<Utc>>,
    /// Whether a device passcode / screen lock is set.
    #[serde(
        rename = "passcode_set",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub passcode_set: Option<bool>,
    /// iOS: whether the device appears jailbroken.
    #[serde(
        rename = "jailbroken",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jailbroken: Option<bool>,
    /// Android: whether the device appears rooted.
    #[serde(
        rename = "root_detected",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub root_detected: Option<bool>,
    /// Whether biometric auth (Face ID / Touch ID / fingerprint)
    /// is enrolled and ready.
    #[serde(
        rename = "biometric_ready",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub biometric_ready: Option<bool>,
    /// Whether the device is enrolled in an MDM.
    #[serde(
        rename = "mdm_enrolled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mdm_enrolled: Option<bool>,
}

impl MobilePostureSnapshot {
    /// Whether the snapshot reports a posture that should be
    /// treated as compromised: a jailbroken (iOS) or rooted
    /// (Android) device. Unknown (`None`) is *not* treated as
    /// compromised here — that policy call belongs to the control
    /// plane's evaluator, not the collector.
    #[must_use]
    pub fn is_compromised(&self) -> bool {
        self.jailbroken == Some(true) || self.root_detected == Some(true)
    }

    /// Serialize to a JSON value for embedding in the
    /// [`sng_core::events::AgentEvent::posture_snapshot`] telemetry
    /// field.
    pub fn to_json(&self) -> Result<serde_json::Value, PostureError> {
        serde_json::to_value(self).map_err(|e| PostureError::Encode(e.to_string()))
    }
}

/// Failure modes of the [`MobilePostureCollector`] surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PostureError {
    /// The platform API needed to determine a signal was
    /// unavailable or errored.
    #[error("posture source unavailable: {0}")]
    Unavailable(String),
    /// The snapshot could not be encoded for telemetry.
    #[error("posture encode: {0}")]
    Encode(String),
}

/// Collects a [`MobilePostureSnapshot`] from the platform.
///
/// Object-safe so the agent holds it as
/// `Arc<dyn MobilePostureCollector>`. Implemented by the PAL over
/// the platform-native posture APIs.
#[async_trait]
pub trait MobilePostureCollector: Send + Sync {
    /// Gather a fresh posture snapshot. Implementations should
    /// keep this cheap and non-blocking where possible — it runs
    /// on the agent's posture-collection timer.
    async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn empty_snapshot_serializes_to_empty_object() {
        let snap = MobilePostureSnapshot::default();
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn field_names_match_go_wire_shape() {
        let snap = MobilePostureSnapshot {
            os_version: "17.4".into(),
            passcode_set: Some(true),
            jailbroken: Some(false),
            mdm_enrolled: Some(true),
            ..Default::default()
        };
        let value: serde_json::Value = serde_json::to_value(&snap).unwrap();
        assert_eq!(value["os_version"], "17.4");
        assert_eq!(value["passcode_set"], true);
        assert_eq!(value["jailbroken"], false);
        assert_eq!(value["mdm_enrolled"], true);
        // Unset optionals are omitted entirely (Go `omitempty`).
        assert!(value.get("root_detected").is_none());
        assert!(value.get("biometric_ready").is_none());
    }

    #[test]
    fn roundtrips_through_json() {
        let snap = MobilePostureSnapshot {
            os_version: "14".into(),
            agent_version: "1.2.3".into(),
            collected_at: Some(Utc::now()),
            passcode_set: Some(true),
            root_detected: Some(true),
            biometric_ready: Some(false),
            mdm_enrolled: Some(false),
            jailbroken: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: MobilePostureSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn compromised_detects_jailbreak_and_root() {
        assert!(
            MobilePostureSnapshot {
                jailbroken: Some(true),
                ..Default::default()
            }
            .is_compromised()
        );
        assert!(
            MobilePostureSnapshot {
                root_detected: Some(true),
                ..Default::default()
            }
            .is_compromised()
        );
        assert!(!MobilePostureSnapshot::default().is_compromised());
    }
}
