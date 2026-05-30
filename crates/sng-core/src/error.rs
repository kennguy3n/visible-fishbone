//! Workspace error taxonomy.
//!
//! [`SngError`] is the error type every public API in this
//! workspace converges on. Each variant carries:
//!
//! * a structured payload appropriate to the failure class
//!   (parse error, IO error, signature failure, …);
//! * a stable [`ErrorCode`] that maps onto the Go control
//!   plane's error code schema (e.g. `policy.bundle.signature.invalid`
//!   on both sides), so a single dashboard can group failures
//!   across the stack without per-language translation;
//! * a `tracing` log-friendly `Display` impl.
//!
//! The error codes are stable contract — adding a variant is
//! additive, but renaming or repurposing an existing code is a
//! breaking change to the observability schema and requires a
//! coordinated rollout on the Go side first.

use std::io;
use thiserror::Error;

/// Stable error code identifying the failure class. The string
/// form is the wire and observability contract: stable, dotted,
/// lowercase, scoped (`policy.bundle.*`, `config.*`, `wire.*`,
/// `lifecycle.*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Configuration loading failed (missing required key,
    /// malformed file, env var parse error).
    ConfigInvalid,
    /// A required configuration key was absent.
    ConfigMissing,
    /// Wire encoding failure (MessagePack marshal / unmarshal).
    WireEncoding,
    /// Wire decoding produced bytes that failed schema
    /// validation (unknown event class, missing required field).
    WireSchema,
    /// Policy bundle signature did not verify against any key in
    /// the configured trust store.
    PolicyBundleSignatureInvalid,
    /// Policy bundle was signed but the signing key id is not
    /// present in the operator-provided trust store.
    PolicyBundleSigningKeyUnknown,
    /// Policy bundle deserialised but its target type does not
    /// match what the verifier was asked to load.
    PolicyBundleTargetMismatch,
    /// Policy bundle deserialised but its version field is older
    /// than the version currently active (replay / downgrade
    /// protection).
    PolicyBundleStale,
    /// IO error from the host (file system, socket, child
    /// process spawn).
    Io,
    /// The lifecycle shutdown signal was triggered and the
    /// operation could not complete in time.
    LifecycleShutdown,
    /// A subsystem reported itself unhealthy through the
    /// [`crate::lifecycle::HealthCheck`] interface and the
    /// caller declined to proceed.
    HealthUnhealthy,
    /// Catch-all for failures that genuinely do not fit one of
    /// the more specific buckets. Use sparingly — a new code is
    /// almost always preferable so dashboards can break the rate
    /// down accurately.
    Other,
}

impl ErrorCode {
    /// The stable dotted lowercase wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "config.invalid",
            Self::ConfigMissing => "config.missing",
            Self::WireEncoding => "wire.encoding",
            Self::WireSchema => "wire.schema",
            Self::PolicyBundleSignatureInvalid => "policy.bundle.signature.invalid",
            Self::PolicyBundleSigningKeyUnknown => "policy.bundle.signing_key.unknown",
            Self::PolicyBundleTargetMismatch => "policy.bundle.target.mismatch",
            Self::PolicyBundleStale => "policy.bundle.stale",
            Self::Io => "io",
            Self::LifecycleShutdown => "lifecycle.shutdown",
            Self::HealthUnhealthy => "health.unhealthy",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Workspace error type. Every public fallible API in `sng-core`
/// returns either [`SngError`] directly or a type that converts
/// into it via `?`.
///
/// The variants are intentionally coarse — a tracing span carries
/// the fine-grained source error, while the variant itself maps
/// onto an [`ErrorCode`] for dashboards. New leaf failure modes
/// add a new variant + new code rather than overloading an
/// existing one.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SngError {
    /// Configuration loading failed.
    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Wire-format encode or decode failure.
    #[error("wire: {0}")]
    Wire(#[from] crate::envelope::WireError),

    /// Policy bundle verification failure.
    #[error("policy bundle: {0}")]
    Policy(#[from] crate::policy::VerificationError),

    /// IO error.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// Lifecycle / shutdown protocol violation.
    #[error("lifecycle: {0}")]
    Lifecycle(String),

    /// Health check failed.
    #[error("health: {0}")]
    Health(String),

    /// Catch-all. Use sparingly.
    #[error("{0}")]
    Other(String),
}

impl SngError {
    /// The stable [`ErrorCode`] for this error. Used by the
    /// observability layer to populate the `error.code` log
    /// field that dashboards group on.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Config(e) => e.code(),
            Self::Wire(e) => e.code(),
            Self::Policy(e) => e.code(),
            Self::Io(_) => ErrorCode::Io,
            Self::Lifecycle(_) => ErrorCode::LifecycleShutdown,
            Self::Health(_) => ErrorCode::HealthUnhealthy,
            Self::Other(_) => ErrorCode::Other,
        }
    }
}

/// Convenience result alias for workspace public APIs.
pub type SngResult<T> = Result<T, SngError>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn error_code_strings_are_stable_dotted_lowercase() {
        // Stability test: changing any of these is a breaking
        // change to dashboards and runbooks on the Go side. Any
        // change here MUST be coordinated with the control-
        // plane error code schema.
        let cases = [
            (ErrorCode::ConfigInvalid, "config.invalid"),
            (ErrorCode::ConfigMissing, "config.missing"),
            (ErrorCode::WireEncoding, "wire.encoding"),
            (ErrorCode::WireSchema, "wire.schema"),
            (
                ErrorCode::PolicyBundleSignatureInvalid,
                "policy.bundle.signature.invalid",
            ),
            (
                ErrorCode::PolicyBundleSigningKeyUnknown,
                "policy.bundle.signing_key.unknown",
            ),
            (
                ErrorCode::PolicyBundleTargetMismatch,
                "policy.bundle.target.mismatch",
            ),
            (ErrorCode::PolicyBundleStale, "policy.bundle.stale"),
            (ErrorCode::Io, "io"),
            (ErrorCode::LifecycleShutdown, "lifecycle.shutdown"),
            (ErrorCode::HealthUnhealthy, "health.unhealthy"),
            (ErrorCode::Other, "other"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert_eq!(code.to_string(), expected);
            // Every code string must be lowercase, must contain
            // only [a-z._], and must not start or end with a dot.
            assert!(
                code.as_str()
                    .chars()
                    .all(|c| matches!(c, 'a'..='z' | '.' | '_')),
                "code {code:?} has invalid characters: {}",
                code.as_str()
            );
            assert!(!code.as_str().starts_with('.'));
            assert!(!code.as_str().ends_with('.'));
        }
    }

    #[test]
    fn io_error_converts_with_question_mark() {
        fn f() -> SngResult<()> {
            let _ = std::fs::read("/does/not/exist/nope")?;
            Ok(())
        }
        let err = f().expect_err("should fail");
        assert_eq!(err.code(), ErrorCode::Io);
    }
}
