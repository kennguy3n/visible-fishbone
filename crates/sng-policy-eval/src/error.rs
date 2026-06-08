//! Error taxonomy for sng-policy-eval.
//!
//! Mirrors the agent-side codes in
//! [`sng_core::error::ErrorCode`] so a [`PolicyEvalError`] can be
//! reported through the same telemetry envelope shape that
//! `sng-comms` already speaks. Each variant carries enough
//! context for an operator to triage without re-running the
//! agent — the bundle id, the offending field, the wire
//! position, etc.

use sng_core::error::ErrorCode;
use sng_core::ids::PolicyBundleId;
use thiserror::Error;

/// Things that can go wrong while loading or evaluating a
/// policy bundle.
#[derive(Debug, Error)]
pub enum PolicyEvalError {
    /// The MessagePack envelope `body` is malformed. The
    /// signature has already been verified (this layer only
    /// runs against a verified body) — a malformed envelope at
    /// this point indicates a wire-shape mismatch with the Go
    /// compiler, not tampering.
    #[error("decode bundle envelope: {0}")]
    EnvelopeDecode(String),

    /// The JSON-encoded `r` rules sub-document is malformed.
    /// Wraps the underlying `serde_json` error.
    #[error("decode rule table: {0}")]
    RulesDecode(String),

    /// The JSON-encoded `st` steering sub-document is malformed.
    #[error("decode steering table: {0}")]
    SteeringDecode(String),

    /// The JSON-encoded `mw` malware-hash sub-document is malformed.
    #[error("decode malware table: {0}")]
    MalwareDecode(String),

    /// The bundle's `v` schema version is newer than this
    /// engine supports. Receivers refuse rather than guessing —
    /// a future-versioned bundle could embed semantics this
    /// engine misinterprets.
    #[error("schema version {found} not supported (max: {supported})")]
    SchemaVersionTooNew {
        /// The version encoded in the bundle.
        found: u8,
        /// The maximum version this engine understands.
        supported: u8,
    },

    /// The bundle's `t` target does not match the operator-
    /// configured target for this engine instance. Defends
    /// against a misrouted bundle being applied to the wrong
    /// enforcement surface.
    #[error("bundle target {actual} does not match engine target {expected}")]
    TargetMismatch {
        /// The target encoded in the bundle.
        actual: String,
        /// The target the engine is configured for.
        expected: String,
    },

    /// A swap attempt rejected an older bundle. The engine
    /// preserves the currently-loaded bundle and surfaces the
    /// finding so the orchestrator can re-pull a fresher one.
    #[error("bundle {bundle_id} version {found} older than loaded {current}")]
    Stale {
        /// The bundle whose swap was rejected.
        bundle_id: PolicyBundleId,
        /// The version inside the rejected bundle.
        found: i64,
        /// The version that was already loaded.
        current: i64,
    },

    /// A rule (or the bundle-level default action) carries
    /// `verb = suggest_only` without a `suggested_verb` companion.
    /// `SuggestOnly` is an advisory state — the operator UI surfaces
    /// *"this rule **would** have applied {verb}"* — and the
    /// would-be verb has to come from somewhere. The Go compiler
    /// emits `suggested_verb` on every suggest-only rule; a bundle
    /// that omits it is malformed.
    #[error(
        "rule {rule_id:?} has verb=suggest_only but no suggested_verb (or suggested_verb is itself suggest_only)"
    )]
    SuggestOnlyMissingSuggestion {
        /// The offending rule's id, or `None` when the default-
        /// action verb itself was the violation.
        rule_id: Option<String>,
    },
}

impl PolicyEvalError {
    /// Map onto the agent-side [`ErrorCode`] taxonomy so the
    /// `sng-telemetry` envelope can carry the right code. The
    /// mapping is intentionally narrow — every variant here
    /// indicates an issue with policy material the agent
    /// cannot fix locally, so the code is always something the
    /// control plane will see in logs.
    #[must_use]
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::EnvelopeDecode(_)
            | Self::RulesDecode(_)
            | Self::SteeringDecode(_)
            | Self::MalwareDecode(_)
            | Self::SchemaVersionTooNew { .. }
            | Self::SuggestOnlyMissingSuggestion { .. } => ErrorCode::BundleRejected,
            Self::TargetMismatch { .. } => ErrorCode::PolicyBundleTargetMismatch,
            Self::Stale { .. } => ErrorCode::PolicyBundleStale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn error_code_mapping() {
        assert_eq!(
            PolicyEvalError::EnvelopeDecode("boom".into()).error_code(),
            ErrorCode::BundleRejected
        );
        assert_eq!(
            PolicyEvalError::RulesDecode("boom".into()).error_code(),
            ErrorCode::BundleRejected
        );
        assert_eq!(
            PolicyEvalError::SteeringDecode("boom".into()).error_code(),
            ErrorCode::BundleRejected
        );
        assert_eq!(
            PolicyEvalError::SchemaVersionTooNew {
                found: 99,
                supported: 1
            }
            .error_code(),
            ErrorCode::BundleRejected
        );
        assert_eq!(
            PolicyEvalError::TargetMismatch {
                actual: "edge".into(),
                expected: "endpoint".into(),
            }
            .error_code(),
            ErrorCode::PolicyBundleTargetMismatch
        );
        let bundle_id = PolicyBundleId::new_v4();
        assert_eq!(
            PolicyEvalError::Stale {
                bundle_id,
                found: 1,
                current: 2,
            }
            .error_code(),
            ErrorCode::PolicyBundleStale
        );
        assert_eq!(
            PolicyEvalError::SuggestOnlyMissingSuggestion {
                rule_id: Some("r-1".into()),
            }
            .error_code(),
            ErrorCode::BundleRejected
        );
    }
}
