//! SWG subsystem error taxonomy.
//!
//! Errors are grouped by failure surface — process lifecycle,
//! config rendering, URL category bundle verification, ext-authz
//! request decoding, and IO. Every variant maps to a stable
//! [`sng_core::error::ErrorCode`] so the telemetry pipeline can
//! attach a structured code to verdict / error events without
//! string-matching on the variant.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// All failures the SWG subsystem can return.
///
/// Implements `Clone` so the `MockEnvoy` (and any other test
/// fixture that scripts a SwgError outcome) can reproduce the
/// same error on every call without needing per-variant
/// match arms. All variants carry owned data (no
/// `std::io::Error`, no file handles, no socket addresses) so
/// `Clone` is a cheap structural copy.
#[derive(Clone, Debug, Error)]
pub enum SwgError {
    /// Generic IO failure (file read, pipe write, process spawn).
    #[error("io error: {0}")]
    Io(String),

    /// Envoy process management failure (spawn, wait, signal).
    /// Distinct from [`Self::Io`] so the supervisor can trigger a
    /// restart for `Process` failures while leaving `Io`
    /// failures (e.g. a transient socket read) to be retried in
    /// place.
    #[error("envoy process error: {0}")]
    Process(String),

    /// The on-disk `envoy.yaml` render produced an invalid
    /// document (impossible character in a string the writer
    /// cannot escape). Should not happen for compiler-produced
    /// inputs — surfaces a bug in [`crate::config`].
    #[error("config render error: {0}")]
    Config(String),

    /// `envoy --mode validate` on the staged config failed.
    /// The new config is syntactically invalid and the supervisor
    /// must not swap it in.
    #[error("config validation failed: {0}")]
    ConfigValidate(String),

    /// URL category bundle failed Ed25519 signature verification.
    #[error("category bundle signature invalid")]
    CategoryBundleSignatureInvalid,

    /// URL category bundle was signed with a key id the operator
    /// trust store does not know about.
    #[error("category bundle signed with unknown key: {0}")]
    CategoryBundleUnknownKey(String),

    /// URL category bundle version is older than or equal to the
    /// installed bundle. Prevents the control plane from
    /// accidentally rolling back to a previous category set,
    /// which would silently drop coverage.
    #[error("category bundle is stale: incoming version {incoming} <= current {current}")]
    CategoryBundleStale { incoming: u64, current: u64 },

    /// URL category bundle body failed to decode.
    #[error("category bundle body decode failed: {0}")]
    CategoryBundleBodyDecode(String),

    /// Ext-authz request from Envoy could not be decoded into a
    /// well-formed [`crate::verdict::RequestContext`].
    #[error("ext_authz request decode error: {0}")]
    ExtAuthzDecode(String),
}

impl SwgError {
    /// Map to the stable workspace error code so the telemetry
    /// pipeline can attach a structured code to the error event.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Io(_) => ErrorCode::Io,
            Self::Process(_) => ErrorCode::SwgProcessFailure,
            Self::Config(_) => ErrorCode::SwgConfigInvalid,
            Self::ConfigValidate(_) => ErrorCode::SwgConfigValidate,
            Self::CategoryBundleSignatureInvalid => ErrorCode::SwgCategoryBundleSignatureInvalid,
            Self::CategoryBundleUnknownKey(_) => ErrorCode::SwgCategoryBundleSigningKeyUnknown,
            Self::CategoryBundleStale { .. } => ErrorCode::SwgCategoryBundleStale,
            Self::CategoryBundleBodyDecode(_) => ErrorCode::SwgCategoryBundleBodyDecode,
            Self::ExtAuthzDecode(_) => ErrorCode::SwgExtAuthzDecode,
        }
    }
}

impl From<std::io::Error> for SwgError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn every_variant_maps_to_a_swg_or_io_code() {
        // Sanity check: codes are in the SWG-specific range (or
        // the shared IO code) so a telemetry consumer that filters
        // on `code.starts_with("swg")` or `== "io"` does not miss
        // any SWG error.
        let cases: Vec<SwgError> = vec![
            SwgError::Io("x".into()),
            SwgError::Process("x".into()),
            SwgError::Config("x".into()),
            SwgError::ConfigValidate("x".into()),
            SwgError::CategoryBundleSignatureInvalid,
            SwgError::CategoryBundleUnknownKey("x".into()),
            SwgError::CategoryBundleStale {
                incoming: 1,
                current: 2,
            },
            SwgError::CategoryBundleBodyDecode("x".into()),
            SwgError::ExtAuthzDecode("x".into()),
        ];
        for err in cases {
            let s = err.code().as_str();
            assert!(
                s == "io" || s.starts_with("swg."),
                "{err:?} has unexpected code {s}"
            );
        }
    }

    #[test]
    fn io_error_converts_via_from() {
        // The `?` operator must work on std::io::Error in the
        // crate, otherwise every file read needs an explicit
        // `.map_err(SwgError::Io)`.
        let e = std::io::Error::other("nope");
        let swg: SwgError = e.into();
        assert_eq!(swg.code(), ErrorCode::Io);
    }

    #[test]
    fn stale_bundle_error_format_includes_versions() {
        // The Display impl must carry both versions so an
        // operator triaging a "stale bundle" telemetry alert can
        // see at a glance whether they pushed a stale bundle or
        // whether the device is ahead of expectations.
        let e = SwgError::CategoryBundleStale {
            incoming: 5,
            current: 12,
        };
        let s = e.to_string();
        assert!(s.contains('5'), "{s}");
        assert!(s.contains("12"), "{s}");
    }
}
