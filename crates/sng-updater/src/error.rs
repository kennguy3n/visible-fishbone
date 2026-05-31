//! Self-update engine error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and ops
//! dashboards bucket updater failures into the same dotted-
//! lowercase namespace as every other subsystem. The variants
//! split out the discriminations operators actually need at
//! triage time: "rejected at signature check" vs. "rejected at
//! version check" vs. "downloaded bytes did not match the
//! signed hash claim" vs. "the new image came up but did not
//! pass health checks". A single `UpdaterError::Invalid` lump
//! would force every dashboard alert to grep the message body
//! to decide what to page on.

use crate::manifest::{ImageVersion, ManifestSigningKeyId, UpdateTarget};
use crate::state::StateTransitionError;
use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the self-update engine.
#[derive(Debug, Error)]
pub enum UpdaterError {
    /// The signed manifest envelope failed to decode. The body
    /// bytes are not a well-formed `manifestPayload` MessagePack
    /// map. Distinct from [`Self::SignatureInvalid`] so
    /// dashboards can break out "control plane is producing
    /// malformed manifests" from "control plane is signing
    /// manifests with a key the operator does not trust".
    #[error("manifest decode: {0}")]
    BodyDecode(String),
    /// Manifest carried the ephemeral signing-key sentinel. The
    /// updater refuses to install anything signed under the
    /// sentinel — there is no operator-provisioned key for it
    /// and accepting one would only ever create a foot-gun.
    #[error(
        "manifest carries ephemeral signing-key id; production updaters must use a persisted key"
    )]
    EphemeralSigningKey,
    /// Manifest's claimed signing-key id is not in the trust
    /// store. Mirrors
    /// [`sng_core::error::ErrorCode::PolicyBundleSigningKeyUnknown`]
    /// for the manifest pipeline.
    #[error("manifest signed with unknown key id: {0}")]
    UnknownSigningKey(ManifestSigningKeyId),
    /// Manifest body signature verification failed. Either the
    /// bytes were tampered with in transit, or the manifest was
    /// signed by a key the trust store does not have, or the
    /// claimed signing-key id pointed at the wrong key.
    #[error("manifest signature verification failed")]
    SignatureInvalid,
    /// Manifest version is less than or equal to the currently-
    /// committed image version. Downgrade prevention. The
    /// engine refuses to even download the image bytes for a
    /// stale manifest.
    #[error("manifest version {found} is not strictly newer than committed {current}")]
    ManifestStale {
        /// Version on the rejected manifest.
        found: ImageVersion,
        /// Version of the image currently committed on disk.
        current: ImageVersion,
    },
    /// Install refused because the requested version matches the
    /// version that was previously rolled back from the *target*
    /// (inactive) slot. Distinct from [`Self::ManifestStale`]
    /// because the manifest is NOT stale relative to the
    /// committed slot — the operator response differs (the
    /// release pipeline is republishing a known-bad version, not
    /// shipping a downgrade).
    #[error(
        "refusing to re-install version {version} on slot {slot} which was previously rolled back"
    )]
    ReinstallOfRolledBackVersion {
        /// Version on the rejected manifest, which matches the
        /// `RolledBack` record on `slot`.
        version: ImageVersion,
        /// Target slot that holds the matching `RolledBack`
        /// state.
        slot: crate::bank::Bank,
    },
    /// Post-bootloader-commit bookkeeping (`mark_committed` /
    /// `set_active` on the bank writer) failed even after the
    /// orchestrator retried with backoff. The bootloader was
    /// committed atomically, so the appliance WILL boot the new
    /// slot — but the bank-writer metadata is now out of sync
    /// with the bootloader's view. Operators must manually
    /// reconcile the metadata partition.
    #[error(
        "post-commit layout sync failed after {attempts} attempts on slot {slot} \
         (install IS committed on the bootloader; metadata divergence): {last_error}"
    )]
    PostCommitLayoutSync {
        /// Slot whose post-commit bookkeeping diverged.
        slot: crate::bank::Bank,
        /// Version that was committed.
        version: ImageVersion,
        /// Number of attempts the orchestrator made before
        /// giving up.
        attempts: u32,
        /// Last error message surfaced by the bank writer.
        last_error: String,
    },
    /// Install refused because the orchestrator is in
    /// post-commit layout divergence: a prior install hit
    /// [`Self::PostCommitLayoutSync`] and the bootloader
    /// committed atomically to one slot while the bank-writer
    /// metadata still points at the previously-active slot.
    /// Until an operator manually reconciles the metadata
    /// partition and calls
    /// [`crate::service::UpdaterService::clear_layout_divergence`],
    /// the engine MUST refuse every install attempt — a
    /// follow-up install would consult the stale layout,
    /// compute `inactive()` as the slot the bootloader just
    /// committed to, and `open_for_write` would succeed,
    /// overwriting the running image. This is the only path
    /// in the engine that fails closed without consulting the
    /// state machine or the install lock.
    #[error(
        "post-commit layout divergence active; refusing install until operator reconciles \
         the metadata partition and clears the divergence flag"
    )]
    LayoutDiverged,
    /// Manifest was published for a different appliance target
    /// than the running binary. e.g. an `sng-agent` updater
    /// asked to consume an `sng-edge` manifest.
    #[error("manifest target {actual} does not match expected {expected}")]
    TargetMismatch {
        /// Target the manifest claims to publish for.
        actual: UpdateTarget,
        /// Target the running engine is expecting.
        expected: UpdateTarget,
    },
    /// Downloaded image bytes hashed to a value that does not
    /// match the manifest's `sha256` claim. Either the download
    /// was corrupted in transit or the manifest's hash claim is
    /// stale relative to the published artifact.
    #[error("image sha256 {actual} does not match manifest sha256 {expected}")]
    ImageHashMismatch {
        /// Manifest-claimed SHA-256 (hex).
        expected: String,
        /// Observed SHA-256 of the downloaded bytes (hex).
        actual: String,
    },
    /// Image download exceeded the per-attempt size budget
    /// declared on the manifest. Defends against an upstream
    /// serving an unbounded body that would exhaust local disk
    /// before the hash check could ever run.
    #[error("image download exceeded declared size: read {read} bytes, manifest claimed {claimed}")]
    ImageSizeExceeded {
        /// Bytes the manifest claimed.
        claimed: u64,
        /// Bytes the downloader had read when the limit was
        /// reached (always `> claimed`).
        read: u64,
    },
    /// Image download underflowed the declared size — the
    /// upstream closed the stream before delivering all the
    /// bytes the manifest promised. Surfaced as a hash mismatch
    /// would also be, but the cause is distinct (server-side
    /// truncation vs. byte-level corruption).
    #[error("image download truncated: read {read} bytes, manifest claimed {claimed}")]
    ImageTruncated {
        /// Bytes the manifest claimed.
        claimed: u64,
        /// Bytes actually received before stream close.
        read: u64,
    },
    /// Underlying download adapter returned an error (network
    /// I/O failure, HTTP non-2xx, etc.). The supervisor's
    /// retry policy decides whether to back off and retry.
    #[error("image download failure: {0}")]
    DownloadFailure(String),
    /// Inactive-bank writer rejected the install. Either the
    /// slot does not exist on the host's dual-bank layout, the
    /// slot is the *active* bank (which would corrupt the
    /// running image), or the underlying I/O failed.
    #[error("bank write failure: {0}")]
    BankWrite(String),
    /// Bootloader rejected the atomic active-bank swap. The
    /// previous image stays committed.
    #[error("bootloader: {0}")]
    Bootloader(String),
    /// Health check after boot timed out before reporting
    /// healthy.
    #[error("health check timed out after {0}ms")]
    HealthCheckTimeout(u64),
    /// Health check after boot actively reported unhealthy.
    /// Distinct from [`Self::HealthCheckTimeout`] because the
    /// operator response differs: a timeout means the new image
    /// never came up; an unhealthy report means it did come up
    /// but failed an active probe.
    #[error("health check failed: {0}")]
    HealthCheckFailed(String),
    /// Operator-issued `install` could not acquire the install
    /// serialisation lock — another install is already in
    /// progress. Mirrors `SwgInstallBusy` for the updater plane.
    #[error("install busy: another install operation is in progress")]
    InstallBusy,
    /// State-machine transition rejected because it is not legal
    /// from the current state. Indicates a caller bug — the
    /// state machine is the authoritative source for legal
    /// transitions.
    #[error("state transition: {0}")]
    StateTransition(#[from] StateTransitionError),
}

impl UpdaterError {
    /// Map to the stable workspace error code.
    ///
    /// The mapping is the contract dashboards rely on: a code is
    /// what alert rules and runbook lookups key off, while the
    /// variant carries the human-readable detail for triage.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BodyDecode(_) => ErrorCode::UpdaterManifestBodyDecode,
            Self::EphemeralSigningKey | Self::UnknownSigningKey(_) => {
                ErrorCode::UpdaterManifestSigningKeyUnknown
            }
            Self::SignatureInvalid => ErrorCode::UpdaterManifestSignatureInvalid,
            Self::ManifestStale { .. } => ErrorCode::UpdaterManifestStale,
            Self::ReinstallOfRolledBackVersion { .. } => {
                ErrorCode::UpdaterReinstallOfRolledBackVersion
            }
            Self::PostCommitLayoutSync { .. } => ErrorCode::UpdaterPostCommitLayoutSync,
            Self::LayoutDiverged => ErrorCode::UpdaterLayoutDiverged,
            Self::TargetMismatch { .. } => ErrorCode::UpdaterManifestTargetMismatch,
            Self::ImageHashMismatch { .. } | Self::ImageTruncated { .. } => {
                ErrorCode::UpdaterImageHashMismatch
            }
            Self::ImageSizeExceeded { .. } => ErrorCode::UpdaterImageSizeExceeded,
            Self::DownloadFailure(_) => ErrorCode::Io,
            Self::BankWrite(_) => ErrorCode::UpdaterBankWriteFailure,
            Self::Bootloader(_) => ErrorCode::UpdaterBootloaderFailure,
            Self::HealthCheckTimeout(_) => ErrorCode::UpdaterHealthCheckTimeout,
            Self::HealthCheckFailed(_) => ErrorCode::UpdaterHealthCheckFailed,
            Self::InstallBusy => ErrorCode::UpdaterInstallBusy,
            Self::StateTransition(_) => ErrorCode::UpdaterStateInvalidTransition,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ImageVersion, ManifestSigningKeyId, UpdateTarget};
    use crate::state::{StateTransitionError, UpdateState};
    use pretty_assertions::assert_eq;

    #[test]
    fn body_decode_maps_to_manifest_body_decode_code() {
        // Decode failures are categorically distinct from
        // signature failures: the operator response is
        // "investigate the release pipeline that produced this
        // malformed envelope", not "rotate the trust store".
        // The dashboard alert tied to
        // `updater.manifest.body.decode` therefore goes to the
        // release engineering rota; the one tied to
        // `updater.manifest.signature.invalid` goes to security.
        let e = UpdaterError::BodyDecode("eof at offset 17".into());
        assert_eq!(e.code(), ErrorCode::UpdaterManifestBodyDecode);
    }

    #[test]
    fn unknown_signing_key_maps_to_signing_key_unknown() {
        let id = ManifestSigningKeyId::new("deadbeef").expect("valid id shape");
        let e = UpdaterError::UnknownSigningKey(id);
        assert_eq!(e.code(), ErrorCode::UpdaterManifestSigningKeyUnknown);
    }

    #[test]
    fn ephemeral_key_buckets_with_unknown_for_dashboards() {
        // Both `EphemeralSigningKey` and `UnknownSigningKey` map
        // to the same dashboard code so a single alert covers
        // "manifest signed by an untrusted key, for any reason".
        // The variant itself carries the discrimination operators
        // need at log-read time.
        let e = UpdaterError::EphemeralSigningKey;
        assert_eq!(e.code(), ErrorCode::UpdaterManifestSigningKeyUnknown);
    }

    #[test]
    fn signature_invalid_maps_to_signature_invalid() {
        let e = UpdaterError::SignatureInvalid;
        assert_eq!(e.code(), ErrorCode::UpdaterManifestSignatureInvalid);
    }

    #[test]
    fn stale_manifest_maps_to_stale() {
        let e = UpdaterError::ManifestStale {
            found: ImageVersion::new(1, 0, 0),
            current: ImageVersion::new(1, 2, 3),
        };
        assert_eq!(e.code(), ErrorCode::UpdaterManifestStale);
    }

    #[test]
    fn reinstall_of_rolled_back_has_distinct_code_from_stale() {
        // Stale and ReinstallOfRolledBackVersion are operator-
        // facing-distinct concepts: "stale" means the manifest
        // is older than the running release; "reinstall of
        // rolled-back" means the release pipeline is re-publishing
        // a version that was previously rolled back from the
        // target slot. Dashboards must be able to alert on these
        // separately because the remediation differs.
        let stale = UpdaterError::ManifestStale {
            found: ImageVersion::new(1, 0, 0),
            current: ImageVersion::new(1, 2, 3),
        };
        let reinstall = UpdaterError::ReinstallOfRolledBackVersion {
            version: ImageVersion::new(2, 0, 0),
            slot: crate::bank::Bank::B,
        };
        assert_eq!(stale.code(), ErrorCode::UpdaterManifestStale);
        assert_eq!(
            reinstall.code(),
            ErrorCode::UpdaterReinstallOfRolledBackVersion
        );
        assert_ne!(stale.code(), reinstall.code());
    }

    #[test]
    fn layout_diverged_has_distinct_code_from_post_commit_sync() {
        // PostCommitLayoutSync is the *originating* event — the
        // single install that committed on the bootloader but
        // couldn't update the metadata partition. LayoutDiverged
        // is the *follow-up* state: every subsequent install is
        // refused at the door until an operator clears the flag.
        // Distinct dashboard codes let operators see both the
        // one-time event and the ongoing block separately.
        let originating = UpdaterError::PostCommitLayoutSync {
            slot: crate::bank::Bank::B,
            version: ImageVersion::new(2, 0, 0),
            attempts: 3,
            last_error: "forced: emulated transient io".into(),
        };
        let blocked = UpdaterError::LayoutDiverged;
        assert_eq!(originating.code(), ErrorCode::UpdaterPostCommitLayoutSync);
        assert_eq!(blocked.code(), ErrorCode::UpdaterLayoutDiverged);
        assert_ne!(originating.code(), blocked.code());
    }

    #[test]
    fn post_commit_layout_sync_maps_to_distinct_code() {
        // The install is committed on the bootloader; only the
        // orchestrator-side cache diverged. Operators must be
        // able to alert on this separately from generic bank-
        // write failure because the remediation differs (manual
        // metadata reconciliation vs. retry the install).
        let e = UpdaterError::PostCommitLayoutSync {
            slot: crate::bank::Bank::B,
            version: ImageVersion::new(2, 0, 0),
            attempts: 3,
            last_error: "forced: emulated transient io".into(),
        };
        assert_eq!(e.code(), ErrorCode::UpdaterPostCommitLayoutSync);
        let bw = UpdaterError::BankWrite("io error".into());
        assert_ne!(e.code(), bw.code());
    }

    #[test]
    fn target_mismatch_maps_to_target_mismatch() {
        let e = UpdaterError::TargetMismatch {
            actual: UpdateTarget::Edge,
            expected: UpdateTarget::Agent,
        };
        assert_eq!(e.code(), ErrorCode::UpdaterManifestTargetMismatch);
    }

    #[test]
    fn hash_and_truncation_share_a_dashboard_code() {
        // Wire-bytes-don't-match-claim is one operator-facing
        // concept regardless of whether it manifests as
        // mid-stream corruption (`ImageHashMismatch`) or
        // server-side premature close (`ImageTruncated`). The
        // remediation is the same in both cases: retry the
        // download, escalate if it persists.
        let hash = UpdaterError::ImageHashMismatch {
            expected: "aaaa".into(),
            actual: "bbbb".into(),
        };
        let trunc = UpdaterError::ImageTruncated {
            claimed: 1024,
            read: 512,
        };
        assert_eq!(hash.code(), ErrorCode::UpdaterImageHashMismatch);
        assert_eq!(trunc.code(), ErrorCode::UpdaterImageHashMismatch);
    }

    #[test]
    fn size_exceeded_maps_to_size_exceeded() {
        let e = UpdaterError::ImageSizeExceeded {
            claimed: 1024,
            read: 1025,
        };
        assert_eq!(e.code(), ErrorCode::UpdaterImageSizeExceeded);
    }

    #[test]
    fn bank_write_and_bootloader_have_distinct_codes() {
        // Disk write failure vs. bootloader rejection are
        // categorically different operator responses (replace
        // the disk vs. fix the bootloader config), so they get
        // distinct codes even though both lead to "previous
        // image stays committed".
        let bw = UpdaterError::BankWrite("io error".into());
        let bl = UpdaterError::Bootloader("efi vars locked".into());
        assert_eq!(bw.code(), ErrorCode::UpdaterBankWriteFailure);
        assert_eq!(bl.code(), ErrorCode::UpdaterBootloaderFailure);
        assert_ne!(bw.code(), bl.code());
    }

    #[test]
    fn health_check_timeout_and_failure_are_distinct() {
        let to = UpdaterError::HealthCheckTimeout(5_000);
        let fl = UpdaterError::HealthCheckFailed("nats unreachable".into());
        assert_eq!(to.code(), ErrorCode::UpdaterHealthCheckTimeout);
        assert_eq!(fl.code(), ErrorCode::UpdaterHealthCheckFailed);
        assert_ne!(to.code(), fl.code());
    }

    #[test]
    fn install_busy_maps_to_install_busy() {
        let e = UpdaterError::InstallBusy;
        assert_eq!(e.code(), ErrorCode::UpdaterInstallBusy);
    }

    #[test]
    fn state_transition_maps_to_invalid_transition() {
        let e: UpdaterError = StateTransitionError {
            from: UpdateState::Idle,
            to: UpdateState::Committed,
        }
        .into();
        assert_eq!(e.code(), ErrorCode::UpdaterStateInvalidTransition);
    }

    #[test]
    fn download_failure_buckets_under_generic_io() {
        // Network I/O failures fall under the workspace-generic
        // `io` code rather than a downloader-specific bucket:
        // the operator response is the same as for any other
        // I/O failure (check the upstream is reachable). A
        // dedicated `updater.download.failure` code would only
        // add dashboard noise.
        let e = UpdaterError::DownloadFailure("connection refused".into());
        assert_eq!(e.code(), ErrorCode::Io);
    }
}
