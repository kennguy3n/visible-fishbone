//! Error taxonomy for the application-identification subsystem.

use thiserror::Error;

/// Errors produced while loading or validating a signature catalog.
///
/// Every variant is recoverable from the caller's perspective: a
/// loader that fails to parse or validate a runtime bundle is expected
/// to log the error and fall back to its embedded baseline rather than
/// propagating a panic into the data path.
#[derive(Debug, Error)]
pub enum AppIdError {
    /// The catalog document was not valid JSON or did not match the
    /// expected schema.
    #[error("appid: malformed catalog: {0}")]
    Malformed(String),

    /// The catalog parsed but failed a structural invariant (duplicate
    /// app id, empty app id, out-of-range confidence, unknown
    /// transport, malformed byte prefix, …).
    #[error("appid: invalid catalog: {0}")]
    Invalid(String),

    /// The catalog declared a schema version this build does not
    /// understand. Carries the version that was seen.
    #[error("appid: unsupported catalog schema version {0}")]
    UnsupportedSchema(u32),
}
