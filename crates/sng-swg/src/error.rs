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

    /// YARA rule bundle failed Ed25519 signature verification.
    #[error("yara rule bundle signature invalid")]
    YaraBundleSignatureInvalid,

    /// YARA rule bundle was signed with a key id the operator
    /// trust store does not know about.
    #[error("yara rule bundle signed with unknown key: {0}")]
    YaraBundleUnknownKey(String),

    /// YARA rule bundle version is older than or equal to the
    /// installed bundle. Downgrade protection — a stale bundle
    /// would silently drop signature coverage.
    #[error("yara rule bundle is stale: incoming version {incoming} <= current {current}")]
    YaraBundleStale { incoming: u64, current: u64 },

    /// YARA rule bundle body failed to decode from MessagePack.
    #[error("yara rule bundle body decode failed: {0}")]
    YaraBundleBodyDecode(String),

    /// YARA rule text failed to compile. The live rule set is left
    /// untouched; the staged bundle is rejected.
    #[error("yara rule compile failed: {0}")]
    YaraRuleCompile(String),

    /// [`crate::manager::SwgManager::stop`] could not acquire
    /// the internal `install_lock` within the
    /// [`crate::manager::SwgManagerConfig::install_lock_timeout`]
    /// budget. The supervisor is currently mid-install; the
    /// caller should retry once the install completes or escalate
    /// to a forced teardown if the install appears stuck. This
    /// variant is only emitted when the operator opted in to a
    /// bounded wait by setting `install_lock_timeout` to
    /// `Some(_)` — the default `None` waits indefinitely and
    /// never produces `InstallBusy`.
    #[error("install/stop is busy: install_lock_timeout elapsed before lock was acquired")]
    InstallBusy,

    /// URL categorisation ML model bundle failed Ed25519 signature
    /// verification.
    #[error("url model bundle signature invalid")]
    UrlModelSignatureInvalid,

    /// URL categorisation ML model bundle was signed with a key id
    /// the operator trust store does not know about.
    #[error("url model bundle signed with unknown key: {0}")]
    UrlModelUnknownKey(String),

    /// URL categorisation ML model bundle version is older than or
    /// equal to the installed model. Downgrade protection — a stale
    /// model must never silently regress categorisation accuracy.
    #[error("url model bundle is stale: incoming version {incoming} <= current {current}")]
    UrlModelStale { incoming: u64, current: u64 },

    /// URL categorisation ML model bundle body failed to decode
    /// from MessagePack.
    #[error("url model bundle body decode failed: {0}")]
    UrlModelBodyDecode(String),

    /// URL categorisation ML model bundle body failed to encode to
    /// MessagePack. Kept distinct from [`Self::UrlModelBodyDecode`]
    /// so dashboards filtering on `swg.url_model.body.decode` do not
    /// misclassify a failure on the outbound encode path.
    #[error("url model bundle body encode failed: {0}")]
    UrlModelBodyEncode(String),

    /// URL categorisation ML model decoded but failed structural
    /// validation (dimension mismatch, out-of-range vocabulary
    /// index, empty class set). The staged model is rejected and the
    /// live model is left untouched.
    #[error("url model is structurally invalid: {0}")]
    UrlModelInvalid(String),
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
            Self::YaraBundleSignatureInvalid => ErrorCode::SwgYaraBundleSignatureInvalid,
            Self::YaraBundleUnknownKey(_) => ErrorCode::SwgYaraBundleSigningKeyUnknown,
            Self::YaraBundleStale { .. } => ErrorCode::SwgYaraBundleStale,
            Self::YaraBundleBodyDecode(_) => ErrorCode::SwgYaraBundleBodyDecode,
            Self::YaraRuleCompile(_) => ErrorCode::SwgYaraRuleCompile,
            // `InstallBusy` is a backpressure signal — operator
            // response (lower install rate, extend timeout, wait
            // for in-flight install) differs from a process
            // failure (investigate Envoy logs, restart the
            // supervisor) so it gets its own dedicated
            // dashboard-visible code.
            Self::InstallBusy => ErrorCode::SwgInstallBusy,
            Self::UrlModelSignatureInvalid => ErrorCode::SwgUrlModelSignatureInvalid,
            Self::UrlModelUnknownKey(_) => ErrorCode::SwgUrlModelSigningKeyUnknown,
            Self::UrlModelStale { .. } => ErrorCode::SwgUrlModelStale,
            Self::UrlModelBodyDecode(_) => ErrorCode::SwgUrlModelBodyDecode,
            Self::UrlModelBodyEncode(_) => ErrorCode::SwgUrlModelBodyEncode,
            Self::UrlModelInvalid(_) => ErrorCode::SwgUrlModelInvalid,
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
            SwgError::YaraBundleSignatureInvalid,
            SwgError::YaraBundleUnknownKey("x".into()),
            SwgError::YaraBundleStale {
                incoming: 1,
                current: 2,
            },
            SwgError::YaraBundleBodyDecode("x".into()),
            SwgError::YaraRuleCompile("x".into()),
            SwgError::InstallBusy,
            SwgError::UrlModelSignatureInvalid,
            SwgError::UrlModelUnknownKey("x".into()),
            SwgError::UrlModelStale {
                incoming: 1,
                current: 2,
            },
            SwgError::UrlModelBodyDecode("x".into()),
            SwgError::UrlModelBodyEncode("x".into()),
            SwgError::UrlModelInvalid("x".into()),
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
