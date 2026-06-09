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
    /// An automatic rule-feed pull (Emerging Threats, Suricata-Update,
    /// custom org feed) failed to fetch the signed bundle from its
    /// configured URL. The scheduler records the failure and keeps
    /// the previously installed rule set; one unreachable feed does
    /// not stall the others.
    IpsRuleFeedFetch,
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
    /// YARA rule bundle failed Ed25519 signature verification.
    SwgYaraBundleSignatureInvalid,
    /// YARA rule bundle was signed with a key id the operator
    /// trust store does not know about.
    SwgYaraBundleSigningKeyUnknown,
    /// YARA rule bundle version is older than or equal to the
    /// installed bundle. Downgrade protection.
    SwgYaraBundleStale,
    /// YARA rule bundle body failed to decode.
    SwgYaraBundleBodyDecode,
    /// YARA rule text failed to compile; the staged bundle is
    /// rejected and the live rule set is left untouched.
    SwgYaraRuleCompile,
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
    /// URL categorisation ML model bundle failed Ed25519 signature
    /// verification. The bytes were tampered with in transit or the
    /// signing key id does not match the public key the operator
    /// installed. The classifier keeps the previously installed
    /// model (or stays model-less) and falls back to the
    /// deterministic tiers.
    SwgUrlModelSignatureInvalid,
    /// URL categorisation ML model bundle was signed with a key id
    /// the operator trust store does not know about. Mirrors
    /// [`Self::SwgYaraBundleSigningKeyUnknown`] for the model
    /// pipeline — the classifier fails closed and never installs an
    /// unverifiable model.
    SwgUrlModelSigningKeyUnknown,
    /// URL categorisation ML model bundle version is older than or
    /// equal to the installed model. Downgrade protection: a stale
    /// model would silently regress categorisation accuracy.
    SwgUrlModelStale,
    /// URL categorisation ML model bundle body failed to decode
    /// from MessagePack — the control plane and the agent disagree
    /// on the model schema or the body was truncated.
    SwgUrlModelBodyDecode,
    /// URL categorisation ML model bundle decoded but failed
    /// structural validation (dimension mismatch between weights,
    /// vocabulary and idf vectors; out-of-range vocabulary index;
    /// empty class set). The staged model is rejected and the live
    /// model is left untouched.
    SwgUrlModelInvalid,
    /// Self-update engine could not decode an update manifest
    /// envelope. The signed body bytes are not a well-formed
    /// `manifestPayload` MessagePack map — either the engine and
    /// the control plane disagree on the manifest schema version
    /// or the body bytes were truncated in transit. Distinct from
    /// [`Self::UpdaterManifestSignatureInvalid`] because the
    /// operator response differs: a decode failure means the
    /// release pipeline is producing malformed manifests, while a
    /// signature failure means the signing key is wrong (or the
    /// bytes were tampered with).
    UpdaterManifestBodyDecode,
    /// Update manifest failed Ed25519 signature verification
    /// against the trust store. The bytes were tampered with or
    /// the signing key id does not match the public key the
    /// operator installed at agent enrolment.
    UpdaterManifestSignatureInvalid,
    /// Update manifest was signed with a key id that is not in
    /// the trust store. Mirrors
    /// [`Self::PolicyBundleSigningKeyUnknown`] for the manifest
    /// pipeline: either the operator forgot to install the key,
    /// or the manifest was signed by a foreign key. The engine
    /// fails closed and the previous image stays committed.
    UpdaterManifestSigningKeyUnknown,
    /// Update manifest version is less than or equal to the
    /// currently-committed image version. Downgrade prevention.
    /// The engine refuses to even download the image bytes for a
    /// stale manifest — downgrades are a security-relevant
    /// rollback to an older image whose vulnerabilities have
    /// since been patched. Distinct from
    /// [`Self::UpdaterManifestTargetMismatch`] because the
    /// operator response differs: a downgrade means the operator
    /// is intentionally pinning the wrong release (or the
    /// release pipeline is republishing an old artifact), while a
    /// target mismatch means the artifact was published for the
    /// wrong appliance class.
    UpdaterManifestStale,
    /// Operator-issued install was refused because the requested
    /// version matches a version that was previously rolled back
    /// from the *target* (inactive) slot. The current policy
    /// (`allow_reinstall_of_rolled_back_version = false`) treats
    /// re-shipping a rolled-back release as an operator mistake
    /// — typically a regressed release reappearing on the
    /// manifest source — and fails closed. Distinct from
    /// [`Self::UpdaterManifestStale`] because the manifest is
    /// not stale relative to the *committed* slot: the appliance
    /// is still running the rolled-back version's predecessor,
    /// and the operator response is "investigate the release
    /// pipeline that re-published a known-bad version" rather
    /// than "re-cut the manifest with a higher version number."
    UpdaterReinstallOfRolledBackVersion,
    /// Post-bootloader-commit bookkeeping (mark_committed and
    /// set_active on the bank writer) failed even after the
    /// orchestrator retried with backoff. The bootloader was
    /// committed atomically, so the appliance WILL boot the new
    /// slot — but the bank-writer metadata is now out of sync
    /// with the bootloader's view. Operators must manually
    /// reconcile the metadata partition. Distinct from
    /// [`Self::UpdaterBankWriteFailure`] because the install
    /// fundamentally succeeded (the bootloader committed); only
    /// the orchestrator-side cache diverged.
    UpdaterPostCommitLayoutSync,
    /// Install refused because the orchestrator is in
    /// post-commit layout divergence: a prior install committed
    /// on the bootloader but failed every retry of the
    /// bank-writer bookkeeping step (see
    /// [`Self::UpdaterPostCommitLayoutSync`]). The bootloader
    /// is pinned to one slot while the bank-writer metadata
    /// still believes the other slot is active. A follow-up
    /// install would target the wrong slot (the one the
    /// bootloader just committed to) and corrupt the running
    /// image. The engine fails closed and refuses every install
    /// attempt until an operator reconciles the metadata
    /// partition AND clears the divergence flag. Distinct from
    /// [`Self::UpdaterPostCommitLayoutSync`] because the
    /// originating install is over; this code surfaces the
    /// *blocked* state of every subsequent install.
    UpdaterLayoutDiverged,
    /// Update manifest was published for a different appliance
    /// target than the running binary. Mirrors
    /// [`Self::PolicyBundleTargetMismatch`]: e.g. an `sng-agent`
    /// trying to apply an `sng-edge` manifest. The engine fails
    /// closed and the previous image stays committed.
    UpdaterManifestTargetMismatch,
    /// Downloaded image bytes hashed to a value that does not
    /// match the manifest's `sha256` claim. Either the download
    /// was corrupted in transit or the manifest's hash claim is
    /// stale relative to the published artifact. The engine
    /// discards the partial download and the previous image stays
    /// committed. Distinct from
    /// [`Self::UpdaterManifestSignatureInvalid`] because the
    /// signed manifest itself can be valid while the image bytes
    /// the URL serves are not the bytes the operator signed.
    UpdaterImageHashMismatch,
    /// Image download exceeded the per-attempt size budget
    /// declared in [`Self::UpdaterManifestBodyDecode`]'s
    /// `image_size_bytes` field. Defends against an upstream
    /// serving an unbounded body that would exhaust local disk
    /// before the hash check ran.
    UpdaterImageSizeExceeded,
    /// Inactive bank could not be written: the slot does not
    /// exist, or the underlying writer returned an error
    /// (typically I/O on the persistence layer). The engine
    /// aborts the install and the previous image stays committed.
    UpdaterBankWriteFailure,
    /// Bootloader rejected the atomic bank-swap request. The
    /// previous image stays committed.
    UpdaterBootloaderFailure,
    /// Health check after boot timed out before reporting
    /// healthy. The supervisor rolls back to the previously-
    /// committed bank and surfaces this code on the rollback
    /// event so dashboards can break out
    /// "timed out" vs. "actively reported unhealthy".
    UpdaterHealthCheckTimeout,
    /// Health check after boot actively reported unhealthy. The
    /// supervisor rolls back to the previously-committed bank.
    /// Distinct from [`Self::UpdaterHealthCheckTimeout`] because
    /// the operator response differs: a timeout means the new
    /// image never came up, while an unhealthy report means it
    /// did come up but failed an active probe.
    UpdaterHealthCheckFailed,
    /// Operator-issued `install` on the updater could not
    /// acquire the install serialisation lock — another install
    /// is already in progress. Mirrors
    /// [`Self::SwgInstallBusy`] for the updater plane: pure
    /// backpressure, not a failure of the in-flight install.
    UpdaterInstallBusy,
    /// The state machine was driven from a state from which the
    /// requested transition is not allowed (e.g. `commit` from
    /// `Downloading`, or `install` from `HealthChecking`). The
    /// install is aborted; the previous image stays committed.
    /// Indicates a caller bug — the state machine is the
    /// authoritative source for legal transitions.
    UpdaterStateInvalidTransition,
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
            Self::IpsRuleFeedFetch => "ips.rule.feed.fetch",
            Self::SwgProcessFailure => "swg.process.failure",
            Self::SwgConfigInvalid => "swg.config.invalid",
            Self::SwgCategoryBundleSignatureInvalid => "swg.category.bundle.signature.invalid",
            Self::SwgCategoryBundleSigningKeyUnknown => "swg.category.bundle.signing_key.unknown",
            Self::SwgCategoryBundleStale => "swg.category.bundle.stale",
            Self::SwgCategoryBundleBodyDecode => "swg.category.bundle.body.decode",
            Self::SwgConfigValidate => "swg.config.validate",
            Self::SwgExtAuthzDecode => "swg.ext_authz.decode",
            Self::SwgYaraBundleSignatureInvalid => "swg.yara.bundle.signature.invalid",
            Self::SwgYaraBundleSigningKeyUnknown => "swg.yara.bundle.signing_key.unknown",
            Self::SwgYaraBundleStale => "swg.yara.bundle.stale",
            Self::SwgYaraBundleBodyDecode => "swg.yara.bundle.body.decode",
            Self::SwgYaraRuleCompile => "swg.yara.rule.compile",
            Self::SwgInstallBusy => "swg.install.busy",
            Self::SwgUrlModelSignatureInvalid => "swg.url_model.signature.invalid",
            Self::SwgUrlModelSigningKeyUnknown => "swg.url_model.signing_key.unknown",
            Self::SwgUrlModelStale => "swg.url_model.stale",
            Self::SwgUrlModelBodyDecode => "swg.url_model.body.decode",
            Self::SwgUrlModelInvalid => "swg.url_model.invalid",
            Self::UpdaterManifestBodyDecode => "updater.manifest.body.decode",
            Self::UpdaterManifestSignatureInvalid => "updater.manifest.signature.invalid",
            Self::UpdaterManifestSigningKeyUnknown => "updater.manifest.signing_key.unknown",
            Self::UpdaterManifestStale => "updater.manifest.stale",
            Self::UpdaterReinstallOfRolledBackVersion => {
                "updater.manifest.reinstall_of_rolled_back"
            }
            Self::UpdaterPostCommitLayoutSync => "updater.commit.layout_sync_failure",
            Self::UpdaterLayoutDiverged => "updater.commit.layout_diverged",
            Self::UpdaterManifestTargetMismatch => "updater.manifest.target.mismatch",
            Self::UpdaterImageHashMismatch => "updater.image.hash.mismatch",
            Self::UpdaterImageSizeExceeded => "updater.image.size.exceeded",
            Self::UpdaterBankWriteFailure => "updater.bank.write.failure",
            Self::UpdaterBootloaderFailure => "updater.bootloader.failure",
            Self::UpdaterHealthCheckTimeout => "updater.health_check.timeout",
            Self::UpdaterHealthCheckFailed => "updater.health_check.failed",
            Self::UpdaterInstallBusy => "updater.install.busy",
            Self::UpdaterStateInvalidTransition => "updater.state.invalid_transition",
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
    #[allow(clippy::too_many_lines)]
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
            (ErrorCode::IpsRuleFeedFetch, "ips.rule.feed.fetch"),
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
            (
                ErrorCode::SwgYaraBundleSignatureInvalid,
                "swg.yara.bundle.signature.invalid",
            ),
            (
                ErrorCode::SwgYaraBundleSigningKeyUnknown,
                "swg.yara.bundle.signing_key.unknown",
            ),
            (ErrorCode::SwgYaraBundleStale, "swg.yara.bundle.stale"),
            (
                ErrorCode::SwgYaraBundleBodyDecode,
                "swg.yara.bundle.body.decode",
            ),
            (ErrorCode::SwgYaraRuleCompile, "swg.yara.rule.compile"),
            (ErrorCode::SwgInstallBusy, "swg.install.busy"),
            (
                ErrorCode::SwgUrlModelSignatureInvalid,
                "swg.url_model.signature.invalid",
            ),
            (
                ErrorCode::SwgUrlModelSigningKeyUnknown,
                "swg.url_model.signing_key.unknown",
            ),
            (ErrorCode::SwgUrlModelStale, "swg.url_model.stale"),
            (
                ErrorCode::SwgUrlModelBodyDecode,
                "swg.url_model.body.decode",
            ),
            (ErrorCode::SwgUrlModelInvalid, "swg.url_model.invalid"),
            (
                ErrorCode::UpdaterManifestBodyDecode,
                "updater.manifest.body.decode",
            ),
            (
                ErrorCode::UpdaterManifestSignatureInvalid,
                "updater.manifest.signature.invalid",
            ),
            (
                ErrorCode::UpdaterManifestSigningKeyUnknown,
                "updater.manifest.signing_key.unknown",
            ),
            (ErrorCode::UpdaterManifestStale, "updater.manifest.stale"),
            (
                ErrorCode::UpdaterReinstallOfRolledBackVersion,
                "updater.manifest.reinstall_of_rolled_back",
            ),
            (
                ErrorCode::UpdaterPostCommitLayoutSync,
                "updater.commit.layout_sync_failure",
            ),
            (
                ErrorCode::UpdaterLayoutDiverged,
                "updater.commit.layout_diverged",
            ),
            (
                ErrorCode::UpdaterManifestTargetMismatch,
                "updater.manifest.target.mismatch",
            ),
            (
                ErrorCode::UpdaterImageHashMismatch,
                "updater.image.hash.mismatch",
            ),
            (
                ErrorCode::UpdaterImageSizeExceeded,
                "updater.image.size.exceeded",
            ),
            (
                ErrorCode::UpdaterBankWriteFailure,
                "updater.bank.write.failure",
            ),
            (
                ErrorCode::UpdaterBootloaderFailure,
                "updater.bootloader.failure",
            ),
            (
                ErrorCode::UpdaterHealthCheckTimeout,
                "updater.health_check.timeout",
            ),
            (
                ErrorCode::UpdaterHealthCheckFailed,
                "updater.health_check.failed",
            ),
            (ErrorCode::UpdaterInstallBusy, "updater.install.busy"),
            (
                ErrorCode::UpdaterStateInvalidTransition,
                "updater.state.invalid_transition",
            ),
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
