//! Typed errors for the endpoint DLP crate.
//!
//! Every fallible surface in `sng-dlp` converges on [`DlpError`].
//! Each variant carries a stable [`DlpErrorCode`] whose string form
//! is dotted / lowercase / scoped (`dlp.rule.*`, `dlp.policy.*`),
//! matching the workspace error-code convention in
//! [`sng_core::error`] so SRE dashboards can correlate endpoint DLP
//! failures with the rest of the stack.

use thiserror::Error;

/// Stable error code identifying the failure class.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DlpErrorCode {
    /// A rule's `pattern_data` could not be compiled (bad regex,
    /// malformed fingerprint hex, empty keyword dictionary).
    RuleCompileFailed,
    /// The endpoint DLP policy blob failed to deserialise.
    PolicyDecodeFailed,
    /// The policy decoded but referenced an enforcement target
    /// other than `endpoint`.
    PolicyTargetMismatch,
    /// The policy decoded but violated an invariant (duplicate rule
    /// id, unknown channel, schema version too new).
    PolicyInvalid,
}

impl DlpErrorCode {
    /// Canonical dotted wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuleCompileFailed => "dlp.rule.compile_failed",
            Self::PolicyDecodeFailed => "dlp.policy.decode_failed",
            Self::PolicyTargetMismatch => "dlp.policy.target_mismatch",
            Self::PolicyInvalid => "dlp.policy.invalid",
        }
    }
}

impl std::fmt::Display for DlpErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The endpoint DLP error type.
#[derive(Debug, Error)]
pub enum DlpError {
    /// A rule could not be compiled into its runtime matcher.
    #[error("dlp.rule.compile_failed: rule {rule_id}: {reason}")]
    RuleCompile {
        /// The offending rule's stable id.
        rule_id: String,
        /// Human-readable reason (regex parse error, bad hex, …).
        reason: String,
    },
    /// The policy blob failed to deserialise from JSON.
    #[error("dlp.policy.decode_failed: {0}")]
    PolicyDecode(String),
    /// The policy targeted a non-endpoint enforcement plane.
    #[error("dlp.policy.target_mismatch: expected endpoint, got {got}")]
    PolicyTargetMismatch {
        /// The wire string of the target that was actually present.
        got: String,
    },
    /// The policy violated a structural invariant.
    #[error("dlp.policy.invalid: {0}")]
    PolicyInvalid(String),
}

impl DlpError {
    /// The stable [`DlpErrorCode`] for this error.
    #[must_use]
    pub const fn code(&self) -> DlpErrorCode {
        match self {
            Self::RuleCompile { .. } => DlpErrorCode::RuleCompileFailed,
            Self::PolicyDecode(_) => DlpErrorCode::PolicyDecodeFailed,
            Self::PolicyTargetMismatch { .. } => DlpErrorCode::PolicyTargetMismatch,
            Self::PolicyInvalid(_) => DlpErrorCode::PolicyInvalid,
        }
    }
}

/// Convenience alias.
pub type DlpResult<T> = Result<T, DlpError>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn codes_are_stable_dotted_strings() {
        assert_eq!(
            DlpErrorCode::RuleCompileFailed.as_str(),
            "dlp.rule.compile_failed"
        );
        assert_eq!(
            DlpErrorCode::PolicyDecodeFailed.as_str(),
            "dlp.policy.decode_failed"
        );
        assert_eq!(
            DlpErrorCode::PolicyTargetMismatch.as_str(),
            "dlp.policy.target_mismatch"
        );
        assert_eq!(DlpErrorCode::PolicyInvalid.as_str(), "dlp.policy.invalid");
    }

    #[test]
    fn error_maps_to_its_code() {
        let e = DlpError::RuleCompile {
            rule_id: "r1".into(),
            reason: "bad regex".into(),
        };
        assert_eq!(e.code(), DlpErrorCode::RuleCompileFailed);
        assert!(e.to_string().contains("r1"));
    }
}
