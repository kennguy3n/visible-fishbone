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
    /// Device identity (Ed25519 keypair + client certificate) failed
    /// to load or did not match its leaf cert's
    /// SubjectPublicKeyInfo. Permanent under the current files on
    /// disk; the agent must point at a different identity or
    /// re-enrol.
    IdentityInvalid,
    /// Server rejected the device identity at the mTLS handshake
    /// or the application-layer auth check (HTTP 401 / 403).
    /// Permanent under the current credentials; the agent must
    /// re-enrol.
    IdentityRejected,
    /// The control plane was unreachable — connect timeout, TLS
    /// handshake failure, h2 ALPN mismatch, 5xx server error, or
    /// 429 rate limit. Retryable after a backoff.
    ControlPlaneUnreachable,
    /// A resource the agent requested (policy bundle, signing key,
    /// device record) is not present on the control plane for
    /// this tenant binding.
    ResourceMissing,
    /// A signed policy bundle failed an invariant check that is
    /// neither a signature failure (covered by
    /// [`Self::PolicyBundleSignatureInvalid`]) nor a target
    /// mismatch (covered by [`Self::PolicyBundleTargetMismatch`])
    /// nor a downgrade (covered by [`Self::PolicyBundleStale`]) —
    /// e.g. the server response carried no version header, or the
    /// claims block could not be decoded.
    BundleRejected,
    /// Monotonic sequence number regressed below the high-water
    /// mark on a stream. Either a replay attack or a server bug;
    /// the agent fails the stream closed and reconnects.
    SequenceRegression,
    /// Suricata supervisor failed to spawn, signal, or wait on
    /// the child process. Triggers a managed restart in
    /// `sng-ips::manager`.
    IpsProcessFailure,
    /// `suricata.yaml` render produced an invalid document (the
    /// renderer is fully under our control so this surfaces a
    /// bug in `sng-ips::config`, not an operator misconfig).
    IpsConfigInvalid,
    /// IPS rule bundle's Ed25519 signature did not verify.
    /// Mirror of [`Self::PolicyBundleSignatureInvalid`] but for
    /// the IPS rule bundle plane — kept separate so dashboards
    /// can break out IPS-rule signature failures from policy
    /// bundle signature failures even though both go through the
    /// same key infrastructure.
    IpsRuleSignatureInvalid,
    /// IPS rule bundle was signed with a key id the operator
    /// trust store does not know about.
    IpsRuleSigningKeyUnknown,
    /// Incoming IPS rule bundle has a version <= the currently
    /// installed bundle. Downgrade-protection mirror of
    /// [`Self::PolicyBundleStale`].
    IpsRuleStale,
    /// IPS rule bundle body failed to decode (corrupt download,
    /// schema mismatch).
    IpsRuleBodyDecode,
    /// IPS rule bundle body failed to encode (serializer rejected
    /// the in-memory claims struct). Pragmatically unreachable for
    /// the current `IpsRuleBundleClaims` shape — `rmp_serde` does
    /// not fail on a well-formed Rust struct — but kept distinct
    /// from [`Self::IpsRuleBodyDecode`] so dashboards filtering on
    /// `ips.rule.body.decode` do not misclassify a failure on the
    /// outbound encode path.
    IpsRuleBodyEncode,
    /// `suricata -T` dry-run on the staged rule set failed —
    /// the new rules are syntactically invalid. The supervisor
    /// keeps the previous rule set installed.
    IpsRuleValidate,
    /// EVE JSON line could not be parsed. Almost always indicates
    /// a Suricata version that emits a new EVE event type — the
    /// supervisor logs and continues so a single malformed line
    /// does not stop the tail reader.
    IpsEveDecode,
    /// Envoy supervisor failed to spawn, signal, or wait on the
    /// child process. Mirrors [`Self::IpsProcessFailure`] but for
    /// the SWG plane so dashboards can break out per-subsystem.
    SwgProcessFailure,
    /// Envoy config render produced an invalid YAML document
    /// (impossible character in a string the writer cannot
    /// escape). Surfaces a bug in `sng-swg::config`.
    SwgConfigInvalid,
    /// URL category bundle failed Ed25519 signature verification.
    SwgCategoryBundleSignatureInvalid,
    /// URL category bundle was signed with a key id the operator
    /// trust store does not know about.
    SwgCategoryBundleSigningKeyUnknown,
    /// URL category bundle version is older than or equal to the
    /// installed bundle. Downgrade protection.
    SwgCategoryBundleStale,
    /// URL category bundle body failed to decode.
    SwgCategoryBundleBodyDecode,
    /// `envoy --mode validate` dry-run on the staged config
    /// failed — the new config is syntactically invalid, the
    /// supervisor keeps the previous config installed.
    SwgConfigValidate,
    /// Ext-authz request from Envoy could not be decoded into a
    /// well-formed `RequestContext` (missing required header,
    /// malformed body). The handler returns a 400 to Envoy and
    /// the request is denied via the proxy's failure-mode.
    SwgExtAuthzDecode,
    /// Operator-issued `install` or `stop` on the SWG supervisor
    /// could not acquire the install serialisation lock within
    /// the configured `install_lock_timeout`. Distinct from
    /// [`Self::SwgProcessFailure`] because the corresponding
    /// operator response differs: a process failure means Envoy
    /// is unhealthy (investigate logs / restart the supervisor),
    /// while an install-busy is pure backpressure (lower the
    /// install rate, extend the timeout, or wait for the
    /// in-flight install to drain).
    SwgInstallBusy,
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
            Self::IdentityInvalid => "identity.invalid",
            Self::IdentityRejected => "identity.rejected",
            Self::ControlPlaneUnreachable => "control_plane.unreachable",
            Self::ResourceMissing => "resource.missing",
            Self::BundleRejected => "policy.bundle.rejected",
            Self::SequenceRegression => "sequence.regression",
            Self::IpsProcessFailure => "ips.process.failure",
            Self::IpsConfigInvalid => "ips.config.invalid",
            Self::IpsRuleSignatureInvalid => "ips.rule.signature.invalid",
            Self::IpsRuleSigningKeyUnknown => "ips.rule.signing_key.unknown",
            Self::IpsRuleStale => "ips.rule.stale",
            Self::IpsRuleBodyDecode => "ips.rule.body.decode",
            Self::IpsRuleBodyEncode => "ips.rule.body.encode",
            Self::IpsRuleValidate => "ips.rule.validate",
            Self::IpsEveDecode => "ips.eve.decode",
            Self::SwgProcessFailure => "swg.process.failure",
            Self::SwgConfigInvalid => "swg.config.invalid",
            Self::SwgCategoryBundleSignatureInvalid => "swg.category.bundle.signature.invalid",
            Self::SwgCategoryBundleSigningKeyUnknown => "swg.category.bundle.signing_key.unknown",
            Self::SwgCategoryBundleStale => "swg.category.bundle.stale",
            Self::SwgCategoryBundleBodyDecode => "swg.category.bundle.body.decode",
            Self::SwgConfigValidate => "swg.config.validate",
            Self::SwgExtAuthzDecode => "swg.ext_authz.decode",
            Self::SwgInstallBusy => "swg.install.busy",
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
            (ErrorCode::IdentityInvalid, "identity.invalid"),
            (ErrorCode::IdentityRejected, "identity.rejected"),
            (
                ErrorCode::ControlPlaneUnreachable,
                "control_plane.unreachable",
            ),
            (ErrorCode::ResourceMissing, "resource.missing"),
            (ErrorCode::BundleRejected, "policy.bundle.rejected"),
            (ErrorCode::SequenceRegression, "sequence.regression"),
            (ErrorCode::IpsProcessFailure, "ips.process.failure"),
            (ErrorCode::IpsConfigInvalid, "ips.config.invalid"),
            (
                ErrorCode::IpsRuleSignatureInvalid,
                "ips.rule.signature.invalid",
            ),
            (
                ErrorCode::IpsRuleSigningKeyUnknown,
                "ips.rule.signing_key.unknown",
            ),
            (ErrorCode::IpsRuleStale, "ips.rule.stale"),
            (ErrorCode::IpsRuleBodyDecode, "ips.rule.body.decode"),
            (ErrorCode::IpsRuleBodyEncode, "ips.rule.body.encode"),
            (ErrorCode::IpsRuleValidate, "ips.rule.validate"),
            (ErrorCode::IpsEveDecode, "ips.eve.decode"),
            (ErrorCode::SwgProcessFailure, "swg.process.failure"),
            (ErrorCode::SwgConfigInvalid, "swg.config.invalid"),
            (
                ErrorCode::SwgCategoryBundleSignatureInvalid,
                "swg.category.bundle.signature.invalid",
            ),
            (
                ErrorCode::SwgCategoryBundleSigningKeyUnknown,
                "swg.category.bundle.signing_key.unknown",
            ),
            (
                ErrorCode::SwgCategoryBundleStale,
                "swg.category.bundle.stale",
            ),
            (
                ErrorCode::SwgCategoryBundleBodyDecode,
                "swg.category.bundle.body.decode",
            ),
            (ErrorCode::SwgConfigValidate, "swg.config.validate"),
            (ErrorCode::SwgExtAuthzDecode, "swg.ext_authz.decode"),
            (ErrorCode::SwgInstallBusy, "swg.install.busy"),
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
