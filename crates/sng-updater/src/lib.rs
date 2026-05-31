//! # sng-updater — Self-update engine
//!
//! The updater is the brain that decides *when*, *what*, and
//! *how* to install a new release of `sng-edge` or `sng-agent`
//! onto the running appliance. It does not itself ship bytes
//! across the wire (that is `sng-comms`) and it does not itself
//! reboot the host (that is the bootloader binding); it
//! orchestrates the verified hand-off between those layers so
//! that:
//!
//! 1. Only an Ed25519-signed manifest from a key the operator
//!    has explicitly provisioned can drive an install.
//! 2. Only a manifest whose version is strictly newer than the
//!    currently-committed image can be downloaded — the engine
//!    rejects downgrades up front, before the image bytes hit
//!    disk.
//! 3. Only the bytes whose SHA-256 matches the signed manifest's
//!    `sha256` claim can be written to the inactive bank — the
//!    signed manifest authenticates the entire image transitively
//!    through the hash claim, exactly the way `sng-policy-eval`
//!    authenticates the rule table transitively through the
//!    bundle body signature.
//! 4. Only an image that comes back healthy within a configurable
//!    window after the bank swap remains committed; if the health
//!    check fails (or times out), the bootloader is asked to
//!    re-pin the previous bank and the install is recorded as
//!    rolled-back.
//!
//! ## Architecture
//!
//! All side-effects on the edge VM (downloading bytes, writing a
//! disk partition, asking the bootloader to swap banks, running a
//! health check) live behind a trait so the engine can be
//! exercised end-to-end in a unit test without touching any of
//! the real-OS primitives. See [`ARCHITECTURE.md` §4.9 "Dual-Bank
//! Image Upgrades"](https://github.com/kennguy3n/visible-fishbone/blob/main/ARCHITECTURE.md#49-dual-bank-image-upgrades)
//! for the deployment-time picture.
//!
//! ## Crate layout
//!
//! - [`error`] — `UpdaterError` taxonomy mapped onto the
//!   workspace [`sng_core::error::ErrorCode`].
//! - [`manifest`] — `UpdateManifest`, `UpdateTarget`,
//!   `ImageVersion`, and the signed-envelope shape.
//! - [`verifier`] — `ManifestVerifier`: trust-store-backed
//!   Ed25519 verification plus version-monotonicity and target
//!   checks.
//! - [`source`] — `ManifestSource` trait + in-process
//!   `StaticManifestSource` test double.
//! - [`download`] — `ImageDownloader` trait + the streaming
//!   SHA-256 verifier that wraps every implementation.
//! - [`bank`] — `Bank`, `BankSlotState`, `BankLayout`, plus the
//!   `BankWriter` trait and the in-process `InMemoryBankWriter`.
//! - [`bootloader`] — `Bootloader` trait + `InMemoryBootloader`
//!   test double.
//! - [`healthcheck`] — `HealthCheck` trait + composite checker
//!   that ANDs an arbitrary set of probes.
//! - [`state`] — the `UpdateState` enum and its legal
//!   transition graph.
//! - [`policy`] — `UpdaterPolicy` (download budgets, health-
//!   check window, retry caps) and `UpdaterPolicyHolder`
//!   (ArcSwap-wrapped hot-swap).
//! - [`service`] — `UpdaterService` orchestrator +
//!   `UpdaterServiceBuilder`.
//! - [`stats`] — atomic counters + serializable snapshot.

// Test-only allows mirror the sister sng-fw / sng-dns /
// sng-ips / sng-swg / sng-ztna / sng-sdwan crates so the
// workspace lints stay consistent.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::float_cmp,
        clippy::useless_vec,
        clippy::explicit_iter_loop,
        clippy::single_match_else,
        clippy::match_wildcard_for_single_variants,
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools,
        clippy::struct_excessive_bools,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::cast_precision_loss
    )
)]

pub mod bank;
pub mod bootloader;
pub mod download;
pub mod error;
pub mod healthcheck;
pub mod manifest;
pub mod policy;
pub mod service;
pub mod source;
pub mod state;
pub mod stats;
pub mod verifier;

pub use bank::{
    Bank, BankLayout, BankSlotState, BankWriter, InMemoryBankWriter, WriteHandle, WriteOutcome,
};
pub use bootloader::{ActiveBankState, Bootloader, InMemoryBootloader};
pub use download::{ImageDownloader, ImageReceipt, InMemoryDownloader, StreamingHasher};
pub use error::UpdaterError;
pub use healthcheck::{HealthCheck, HealthReport, StaticHealthCheck};
pub use manifest::{
    ImageHash, ImageVersion, ManifestSignature, ManifestSigningKeyId, ReleaseChannel,
    SignedManifest, UpdateManifest, UpdateTarget,
};
pub use policy::{UpdaterPolicy, UpdaterPolicyHolder};
pub use service::{InstallOutcome, RollbackReason, UpdaterService, UpdaterServiceBuilder};
pub use source::{ManifestSource, StaticManifestSource};
pub use state::UpdateState;
pub use stats::{UpdaterStats, UpdaterStatsSnapshot};
pub use verifier::{
    AddManifestKeyError, ManifestVerifier, ManifestVerifyError, VersionMonotonicity,
};
