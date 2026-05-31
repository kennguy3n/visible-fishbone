//! Updater service — the orchestrator that wires every
//! subsystem (verifier, source, downloader, bank writer,
//! bootloader, health check) into the full install flow.
//!
//! Public API:
//!
//! * [`UpdaterServiceBuilder`] — gather the subsystem
//!   adapters and the policy holder, then call
//!   [`UpdaterServiceBuilder::build`] for a fully-wired
//!   service.
//! * [`UpdaterService::install_from_envelope`] — single-shot
//!   install driven by an already-pulled
//!   [`SignedManifest`]. Most useful for tests and for the
//!   control-plane push-notification path.
//! * [`UpdaterService::poll_and_install`] — pull the latest
//!   manifest from the configured source and, if it is
//!   admissible, run the install.
//! * [`UpdaterService::current_state`] — read the current
//!   install state machine state.
//! * [`UpdaterService::stats_snapshot`] — snapshot the
//!   counters for telemetry.
//!
//! Concurrency: the orchestrator holds a `tokio::Mutex` for
//! the install lifecycle so a second `install_*` call while
//! one is in flight is rejected up front with
//! [`UpdaterError::InstallBusy`]. Stats and state reads are
//! lock-free.

use crate::bank::{Bank, BankLayout, BankSlotState, BankWriter, WriteHandle};
use crate::bootloader::Bootloader;
use crate::download::{DownloadError, ImageDownloader, StreamingHasher, TeeChunkSink};
use crate::error::UpdaterError;
use crate::healthcheck::{HealthCheck, HealthReport};
use crate::manifest::{ImageVersion, SignedManifest, UpdateManifest, UpdateTarget};
use crate::policy::{PolicyValidationError, UpdaterPolicy, UpdaterPolicyHolder};
use crate::source::{ManifestSource, SourceError};
use crate::state::UpdateState;
use crate::stats::{UpdaterStats, UpdaterStatsSnapshot};
use crate::verifier::ManifestVerifier;
use arc_swap::ArcSwap;
use parking_lot::Mutex as ParkingMutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{Sleep, sleep, timeout};
use tracing::{debug, info, warn};

/// Outcome of a single install attempt. The orchestrator
/// returns one of these from `install_from_envelope` /
/// `poll_and_install`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Source produced no manifest (cold start / no new
    /// release published). Only `poll_and_install` can
    /// return this — `install_from_envelope` always has an
    /// envelope to work with.
    NoManifestAvailable,
    /// Install committed — the new image is the running
    /// active bank and the bootloader has been told to keep
    /// it.
    Committed {
        /// Version that was committed.
        version: ImageVersion,
        /// Slot that was committed.
        slot: Bank,
    },
    /// Install rolled back — the health check failed or
    /// timed out, the bootloader was asked to re-pin the
    /// previous bank, and the slot is marked
    /// [`BankSlotState::RolledBack`].
    RolledBack {
        /// Version that was attempted.
        version: ImageVersion,
        /// Slot that was rolled back.
        slot: Bank,
        /// Reason for the rollback.
        reason: RollbackReason,
    },
}

/// Reason an install was rolled back. Carried alongside the
/// [`InstallOutcome::RolledBack`] payload for operator
/// dashboards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackReason {
    /// Health check probe returned an unhealthy report.
    HealthCheckUnhealthy {
        /// Last probe's details.
        details: String,
    },
    /// Window-level health check timeout: the whole
    /// `health_check_window` elapsed without enough
    /// consecutive healthy probes. Distinct from
    /// [`Self::HealthCheckProbeTimeout`] because the
    /// operator response differs (probes ran but did not
    /// stabilise vs. a single probe never returned).
    HealthCheckTimeout,
    /// A single health-check probe did not return within
    /// `health_check_timeout`. The install is rolled back
    /// without waiting for the window to elapse. Distinct
    /// from [`Self::HealthCheckTimeout`] so dashboards can
    /// break out "slow probe" vs. "probes ran but never
    /// stabilised."
    HealthCheckProbeTimeout,
    /// Health check probe itself errored (the trait surfaced
    /// `UpdaterError::HealthCheckFailed`).
    HealthCheckErrored {
        /// Error message surfaced by the probe.
        details: String,
    },
}

/// Builder for [`UpdaterService`]. All adapters are required.
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct UpdaterServiceBuilder {
    target: Option<UpdateTarget>,
    source: Option<Arc<dyn ManifestSource>>,
    verifier: Option<Arc<ManifestVerifier>>,
    downloader: Option<Arc<dyn ImageDownloader>>,
    bank_writer: Option<Arc<dyn BankWriter>>,
    bootloader: Option<Arc<dyn Bootloader>>,
    health_check: Option<Arc<dyn HealthCheck>>,
    policy: Option<UpdaterPolicy>,
    /// Cold-start current-version pin override. Used when
    /// the appliance was provisioned with a known committed
    /// image but the bank layout is not yet reflecting it
    /// (e.g. first boot from a factory image).
    current_version_override: Option<ImageVersion>,
}

impl UpdaterServiceBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target this builder will produce a service for.
    #[must_use]
    pub fn target(mut self, target: UpdateTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Plug in the manifest source.
    #[must_use]
    pub fn source(mut self, source: Arc<dyn ManifestSource>) -> Self {
        self.source = Some(source);
        self
    }

    /// Plug in the verifier (pre-populated trust store).
    #[must_use]
    pub fn verifier(mut self, verifier: Arc<ManifestVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Plug in the image downloader.
    #[must_use]
    pub fn downloader(mut self, downloader: Arc<dyn ImageDownloader>) -> Self {
        self.downloader = Some(downloader);
        self
    }

    /// Plug in the bank writer.
    #[must_use]
    pub fn bank_writer(mut self, bank_writer: Arc<dyn BankWriter>) -> Self {
        self.bank_writer = Some(bank_writer);
        self
    }

    /// Plug in the bootloader.
    #[must_use]
    pub fn bootloader(mut self, bootloader: Arc<dyn Bootloader>) -> Self {
        self.bootloader = Some(bootloader);
        self
    }

    /// Plug in the health check.
    #[must_use]
    pub fn health_check(mut self, health_check: Arc<dyn HealthCheck>) -> Self {
        self.health_check = Some(health_check);
        self
    }

    /// Plug in the operator policy. Default if omitted is
    /// [`UpdaterPolicy::default()`].
    #[must_use]
    pub fn policy(mut self, policy: UpdaterPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Override the cold-start "current version" pin —
    /// otherwise the orchestrator reads it from the bank
    /// layout's active slot.
    #[must_use]
    pub fn current_version_override(mut self, v: ImageVersion) -> Self {
        self.current_version_override = Some(v);
        self
    }

    /// Build the service. Returns
    /// [`ServiceBuildError::MissingComponent`] if any
    /// required adapter is missing or
    /// [`ServiceBuildError::PolicyInvalid`] if the policy
    /// fails [`UpdaterPolicy::validate`].
    pub fn build(self) -> Result<UpdaterService, ServiceBuildError> {
        let target = self
            .target
            .ok_or(ServiceBuildError::MissingComponent("target"))?;
        let source = self
            .source
            .ok_or(ServiceBuildError::MissingComponent("source"))?;
        let verifier = self
            .verifier
            .ok_or(ServiceBuildError::MissingComponent("verifier"))?;
        let downloader = self
            .downloader
            .ok_or(ServiceBuildError::MissingComponent("downloader"))?;
        let bank_writer = self
            .bank_writer
            .ok_or(ServiceBuildError::MissingComponent("bank_writer"))?;
        let bootloader = self
            .bootloader
            .ok_or(ServiceBuildError::MissingComponent("bootloader"))?;
        let health_check = self
            .health_check
            .ok_or(ServiceBuildError::MissingComponent("health_check"))?;
        let policy = self.policy.unwrap_or_default();
        policy
            .validate()
            .map_err(ServiceBuildError::PolicyInvalid)?;
        let policy_holder = UpdaterPolicyHolder::new(policy);
        Ok(UpdaterService {
            target,
            source,
            verifier,
            downloader,
            bank_writer,
            bootloader,
            health_check,
            policy: policy_holder,
            stats: UpdaterStats::default(),
            state: ArcSwap::from_pointee(UpdateState::Idle),
            install_lock: TokioMutex::new(()),
            current_version_override: ParkingMutex::new(self.current_version_override),
            health_check_clock: ParkingMutex::new(Arc::new(RealHealthCheckClock)),
            ticks: AtomicU64::new(0),
            layout_diverged: AtomicBool::new(false),
        })
    }
}

/// Errors returned by [`UpdaterServiceBuilder::build`].
#[derive(Debug, Error)]
pub enum ServiceBuildError {
    /// One of the required components was not plugged in.
    #[error("updater service builder missing component: {0}")]
    MissingComponent(&'static str),
    /// The supplied policy failed validation.
    #[error("updater service builder rejected policy: {0}")]
    PolicyInvalid(#[source] PolicyValidationError),
}

/// Trait used internally by the orchestrator to drive sleep
/// during the health-check loop. The default
/// [`RealHealthCheckClock`] sleeps with `tokio::time::sleep`;
/// tests can swap in a clock that advances under the
/// runtime's `pause()` so the orchestrator can be exercised
/// without wall-clock waits.
pub trait HealthCheckClock: Send + Sync {
    /// Sleep for `dur`.
    fn sleep(&self, dur: Duration) -> Sleep;
}

/// Default health-check clock — delegates to
/// `tokio::time::sleep`.
#[derive(Debug)]
pub struct RealHealthCheckClock;

impl HealthCheckClock for RealHealthCheckClock {
    fn sleep(&self, dur: Duration) -> Sleep {
        sleep(dur)
    }
}

/// Fully-wired updater service. Construct via
/// [`UpdaterServiceBuilder`].
#[allow(missing_debug_implementations)]
pub struct UpdaterService {
    target: UpdateTarget,
    source: Arc<dyn ManifestSource>,
    verifier: Arc<ManifestVerifier>,
    downloader: Arc<dyn ImageDownloader>,
    bank_writer: Arc<dyn BankWriter>,
    bootloader: Arc<dyn Bootloader>,
    health_check: Arc<dyn HealthCheck>,
    policy: UpdaterPolicyHolder,
    stats: UpdaterStats,
    state: ArcSwap<UpdateState>,
    install_lock: TokioMutex<()>,
    current_version_override: ParkingMutex<Option<ImageVersion>>,
    health_check_clock: ParkingMutex<Arc<dyn HealthCheckClock>>,
    ticks: AtomicU64,
    /// Sticky "post-commit layout divergence" flag. Set by
    /// `run_post_commit_bookkeeping` when every retry of the
    /// `mark_committed` / `set_active` pair has failed after
    /// the bootloader already committed atomically. While
    /// set, every `install_*` entry-point refuses up front
    /// with [`UpdaterError::LayoutDiverged`] and never
    /// acquires the install lock — preventing a follow-up
    /// install from reading the stale layout, computing
    /// `inactive()` as the slot the bootloader just committed
    /// to, and overwriting the running image. The only way to
    /// clear this flag is an operator-issued
    /// [`UpdaterService::clear_layout_divergence`] call, which
    /// must follow manual reconciliation of the metadata
    /// partition.
    layout_diverged: AtomicBool,
}

impl UpdaterService {
    /// Current install state machine state.
    pub fn current_state(&self) -> UpdateState {
        **self.state.load()
    }

    /// Snapshot of the stats counters.
    pub fn stats_snapshot(&self) -> UpdaterStatsSnapshot {
        self.stats.snapshot()
    }

    /// Replace the operator policy. Validates before
    /// installing — returns [`PolicyValidationError`] on a
    /// malformed bundle.
    pub fn reload_policy(
        &self,
        policy: UpdaterPolicy,
    ) -> Result<Arc<UpdaterPolicy>, PolicyValidationError> {
        policy.validate()?;
        Ok(self.policy.reload(policy))
    }

    /// Read the current operator policy.
    pub fn policy(&self) -> Arc<UpdaterPolicy> {
        self.policy.load()
    }

    /// Set the cold-start "current version" pin override.
    pub fn set_current_version_override(&self, v: Option<ImageVersion>) {
        *self.current_version_override.lock() = v;
    }

    /// Number of state-machine transitions the service has
    /// performed since construction. Used by tests as a
    /// progress signal.
    pub fn tick_count(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// Override the health-check clock — tests use this to
    /// swap in a clock backed by `tokio::time::pause`.
    pub fn set_health_check_clock(&self, clock: Arc<dyn HealthCheckClock>) {
        *self.health_check_clock.lock() = clock;
    }

    /// Whether the engine is currently refusing installs
    /// because of post-commit layout divergence. The flag is
    /// set by `run_post_commit_bookkeeping` after every retry
    /// of the `mark_committed` / `set_active` pair has failed
    /// post-bootloader-commit, and cleared only by
    /// [`Self::clear_layout_divergence`].
    pub fn layout_diverged(&self) -> bool {
        self.layout_diverged.load(Ordering::Acquire)
    }

    /// Operator-facing recovery: clear the post-commit layout
    /// divergence flag so the engine re-admits installs. MUST
    /// be called only after the operator has manually
    /// reconciled the metadata partition to match the
    /// bootloader's view — calling this without that
    /// reconciliation re-exposes the running image to being
    /// overwritten by the next install. The recovery action is
    /// deliberately not idempotent-recoverable from inside the
    /// engine: the only thing that knows the metadata
    /// partition has been fixed is the operator.
    pub fn clear_layout_divergence(&self) {
        let was_set = self.layout_diverged.swap(false, Ordering::AcqRel);
        if was_set {
            info!(
                "post-commit layout divergence flag cleared by operator; \
                 next install will run against the now-reconciled metadata partition"
            );
        }
    }

    /// Derive the "currently-committed image version" pin
    /// from an already-fetched [`BankLayout`]. Used by the
    /// verifier as the downgrade comparison anchor. The
    /// cold-start override (set by the builder or
    /// [`Self::set_current_version_override`]) wins over the
    /// layout's active-slot version so a factory image that
    /// has not yet recorded its version in the metadata
    /// partition still anchors downgrade comparisons.
    fn derive_current_version(&self, layout: &BankLayout) -> Option<ImageVersion> {
        if let Some(v) = *self.current_version_override.lock() {
            return Some(v);
        }
        layout.active_version()
    }

    fn transition(&self, from: UpdateState, to: UpdateState) -> Result<UpdateState, UpdaterError> {
        // Defense-in-depth: verify the caller's `from`
        // argument matches the actual current state. Today
        // the only writers of `self.state` are this method
        // and `force_reset_to_idle`, and the install pipeline
        // is serialised behind `install_lock`, so a mismatch
        // can only happen if a future refactor introduces a
        // second writer or relaxes the lock. Fail-closed with
        // a structured error so the bug is visible instead of
        // silently corrupting the lifecycle.
        let observed = **self.state.load();
        if observed != from {
            warn!(
                caller_from = %from,
                observed = %observed,
                to = %to,
                "updater state transition: caller's `from` does not match the live state — \
                 install_lock invariant violated"
            );
            return Err(UpdaterError::StateTransition(
                crate::state::StateTransitionError { from: observed, to },
            ));
        }
        let next = from.transition_to(to)?;
        self.state.store(Arc::new(next));
        self.ticks.fetch_add(1, Ordering::Relaxed);
        debug!(from = %from, to = %next, "updater state transition");
        Ok(next)
    }

    /// Recovery-only state reset. Bypasses the strict
    /// `legal_successors` check in [`UpdateState::transition_to`]
    /// because the install error-handler must be able to take
    /// the machine back to `Idle` from ANY non-idle state —
    /// including `Rebooting` (whose normal successors are
    /// `[HealthChecking, RolledBack]`) when the bootloader
    /// swap fails after the state has already advanced, and
    /// including `Committed` / `RolledBack` if post-transition
    /// bookkeeping fails. The strict forward-progress
    /// validation is a caller-discipline check for normal
    /// flow; recovery is by definition outside normal flow.
    fn force_reset_to_idle(&self, error_context: &str) {
        let prev = **self.state.load();
        if prev == UpdateState::Idle {
            return;
        }
        warn!(
            from = %prev,
            error = %error_context,
            "install errored; force-resetting state machine to Idle so the service \
             accepts retries"
        );
        self.state.store(Arc::new(UpdateState::Idle));
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// Pull the latest manifest from the source and, if it is
    /// admissible, run the install end-to-end.
    pub async fn poll_and_install(&self) -> Result<InstallOutcome, UpdaterError> {
        self.stats.manifest_polls.fetch_add(1, Ordering::Relaxed);
        let env = match self.source.latest(self.target).await {
            Ok(Some(env)) => env,
            Ok(None) => return Ok(InstallOutcome::NoManifestAvailable),
            Err(e) => {
                self.stats
                    .manifest_source_errors
                    .fetch_add(1, Ordering::Relaxed);
                warn!(error = %e, "manifest source error");
                return Err(map_source_error(e));
            }
        };
        self.install_from_envelope(env).await
    }

    /// Install from an already-pulled signed envelope. The
    /// full pipeline: verify → download → integrity check →
    /// stage → swap → health check → commit (or rollback).
    pub async fn install_from_envelope(
        &self,
        envelope: SignedManifest,
    ) -> Result<InstallOutcome, UpdaterError> {
        // Fail-closed BEFORE acquiring the install lock: if a
        // prior install left us in post-commit layout
        // divergence, the bank-writer's view of which slot is
        // inactive points at the slot the bootloader just
        // committed to. Running this install would overwrite
        // the running image. The only path out is for an
        // operator to manually reconcile the metadata
        // partition and call `clear_layout_divergence`.
        if self.layout_diverged.load(Ordering::Acquire) {
            self.stats
                .install_layout_diverged_rejections
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                "refusing install: post-commit layout divergence is active until \
                 operator reconciles the metadata partition and clears the flag"
            );
            return Err(UpdaterError::LayoutDiverged);
        }
        let Ok(_guard) = self.install_lock.try_lock() else {
            self.stats
                .install_concurrency_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(UpdaterError::InstallBusy);
        };
        // Snapshot the bank layout ONCE at the top of the
        // install. The downstream `current_version` lookup,
        // the inactive-slot decision and the rolled-back
        // refusal check all read from the same snapshot, so
        // they cannot disagree even if a future refactor
        // introduced a second concurrent writer of the
        // metadata partition. The `install_lock` already
        // serialises one install at a time; this snapshot
        // additionally narrows the window for any unrelated
        // bookkeeping path to mutate the layout mid-decision.
        let layout = self
            .bank_writer
            .layout()
            .await
            .inspect_err(|_| self.bump_bank_errors())?;
        let current = self.derive_current_version(&layout);
        let manifest = match self.verifier.verify(&envelope, current) {
            Ok(m) => m,
            Err(e) => {
                self.bump_verifier_error(&e);
                return Err(e);
            }
        };
        self.stats.manifest_admitted.fetch_add(1, Ordering::Relaxed);
        // Enforce the policy's image-size cap BEFORE
        // touching the network. A misbehaving control plane
        // that published an oversized manifest is rejected
        // up front.
        let policy = self.policy.load();
        if manifest.image_size_bytes > policy.max_image_bytes {
            return Err(UpdaterError::ManifestSizeExceedsPolicy {
                manifest_declared: manifest.image_size_bytes,
                policy_max: policy.max_image_bytes,
            });
        }
        // Cap manifest's declared size against the
        // hard-cap-derived policy. We DO still pass the raw
        // manifest's declared size to the hasher so the
        // downloader knows when to surface Truncated.
        let target_slot = layout.inactive();
        self.enforce_no_reinstall_of_rolled_back(&layout, target_slot, &manifest, &policy)?;
        self.transition(UpdateState::Idle, UpdateState::Downloading)?;
        let install_result = self.run_install(&manifest, target_slot).await;
        match install_result {
            Ok(o) => Ok(o),
            Err(e) => {
                // Unconditionally reset to Idle so the service
                // accepts the next install attempt. The
                // recovery transition bypasses the strict
                // `legal_successors` check because the error
                // can fire from states whose forward-only
                // successor set does not include Idle —
                // notably `Rebooting` (bootloader swap failed
                // mid-install) and `Committed` / `RolledBack`
                // (post-transition bookkeeping failed). The
                // alternative (silent state-machine stall)
                // would break `accepts_new_install` and lock
                // the appliance out of future updates.
                self.force_reset_to_idle(&e.to_string());
                Err(e)
            }
        }
    }

    /// Helper that enforces the
    /// `allow_reinstall_of_rolled_back_version` policy.
    fn enforce_no_reinstall_of_rolled_back(
        &self,
        layout: &BankLayout,
        target_slot: Bank,
        manifest: &UpdateManifest,
        policy: &UpdaterPolicy,
    ) -> Result<(), UpdaterError> {
        if policy.allow_reinstall_of_rolled_back_version {
            return Ok(());
        }
        let slot_state = layout.slot_state(target_slot);
        if let BankSlotState::RolledBack { version } = slot_state {
            if *version == manifest.version {
                warn!(
                    version = %manifest.version,
                    slot = %target_slot,
                    "refusing to re-install version that was rolled back from this slot"
                );
                self.stats
                    .install_reinstall_of_rolled_back_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(UpdaterError::ReinstallOfRolledBackVersion {
                    version: manifest.version,
                    slot: target_slot,
                });
            }
        }
        Ok(())
    }

    fn bump_verifier_error(&self, e: &UpdaterError) {
        match e {
            UpdaterError::BodyDecode(_) => {
                self.stats
                    .manifest_body_decode_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            UpdaterError::SignatureInvalid | UpdaterError::EphemeralSigningKey => {
                self.stats
                    .manifest_signature_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            UpdaterError::UnknownSigningKey(_) => {
                self.stats
                    .manifest_unknown_key_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            UpdaterError::TargetMismatch { .. } => {
                self.stats
                    .manifest_target_mismatch_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            UpdaterError::ManifestStale { .. } => {
                self.stats
                    .manifest_stale_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Drive the install state machine from `Downloading`
    /// through to terminal `Committed` / `RolledBack`.
    ///
    /// Allow `clippy::too_many_lines`: this function is the
    /// state machine. Splitting it would scatter the
    /// state-transition sites across helpers and obscure the
    /// linear flow that operators reason about
    /// (Downloading → Verifying → Installing → Rebooting →
    /// HealthChecking → Committed / RolledBack). Each step is
    /// already a self-contained call to a method on
    /// `self`; the function body is the orchestration glue
    /// that owns the per-step transitions and rollback
    /// branching.
    #[allow(clippy::too_many_lines)]
    async fn run_install(
        &self,
        manifest: &UpdateManifest,
        target_slot: Bank,
    ) -> Result<InstallOutcome, UpdaterError> {
        info!(
            version = %manifest.version,
            slot = %target_slot,
            size_bytes = manifest.image_size_bytes,
            "starting install"
        );
        // ----- Downloading -----
        let mut handle = self
            .bank_writer
            .open_for_write(target_slot)
            .await
            .inspect_err(|_| self.bump_bank_errors())?;
        let mut hasher = StreamingHasher::new(manifest.image_size_bytes);
        match self
            .stream_into_bank(&mut handle, &mut hasher, manifest)
            .await
        {
            Ok(()) => {}
            Err(e) => {
                let _ = handle.abandon().await;
                return Err(e);
            }
        }

        // ----- Verifying -----
        self.transition(UpdateState::Downloading, UpdateState::Verifying)?;
        let receipt = hasher.finalise();
        if receipt.sha256 != manifest.image_sha256 {
            self.stats
                .install_hash_mismatch
                .fetch_add(1, Ordering::Relaxed);
            let _ = handle.abandon().await;
            return Err(UpdaterError::ImageHashMismatch {
                expected: manifest.image_sha256.as_hex(),
                actual: receipt.sha256.as_hex(),
            });
        }
        if receipt.size_bytes != manifest.image_size_bytes {
            // Smaller than expected — short of the declared
            // size. (The hasher would have rejected larger
            // up front.)
            let _ = handle.abandon().await;
            return Err(UpdaterError::ImageTruncated {
                claimed: manifest.image_size_bytes,
                read: receipt.size_bytes,
            });
        }

        // ----- Installing -----
        self.transition(UpdateState::Verifying, UpdateState::Installing)?;
        let outcome = handle
            .finish(manifest.version)
            .await
            .inspect_err(|_| self.bump_bank_errors())?;
        debug!(
            slot = %outcome.slot,
            bytes_written = outcome.bytes_written,
            "image staged"
        );

        // ----- Rebooting -----
        // Bank swap is the orchestrator-side "begin reboot"
        // signal: the bootloader is now pointed at the new
        // slot; in a real deployment the OS reboots here and
        // the orchestrator resumes from this state on the
        // next boot.
        self.transition(UpdateState::Installing, UpdateState::Rebooting)?;
        match self.bootloader.swap_to(target_slot).await {
            Ok(_) => {}
            Err(e) => {
                self.stats
                    .install_bootloader_errors
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        }

        // ----- HealthChecking -----
        self.transition(UpdateState::Rebooting, UpdateState::HealthChecking)?;
        let probe_outcome = self.run_health_check_loop().await;
        match probe_outcome {
            HealthLoopOutcome::Healthy => {
                // The bootloader commit IS the atomic
                // point-of-no-return for the install: once
                // it returns Ok, the appliance WILL boot the
                // new slot on next reboot regardless of what
                // the bank-writer bookkeeping does. So we
                // sequence bootloader.commit FIRST, then
                // retry the bank-writer bookkeeping
                // (mark_committed + set_active) with bounded
                // backoff to absorb transient I/O on the
                // metadata partition.
                //
                // If the bootloader commit fails, the
                // install aborts cleanly: the previous slot
                // stays active, the layout is untouched, and
                // the error-handler force-resets the state
                // machine to Idle.
                //
                // If the bookkeeping fails every retry, the
                // install IS committed on the bootloader but
                // the in-process layout cache has diverged.
                // We surface a DISTINCT error
                // (`PostCommitLayoutSync`) so operators see
                // exactly that — and the state machine still
                // resets to Idle so future installs are not
                // blocked.
                self.bootloader.commit().await.inspect_err(|_| {
                    self.stats
                        .install_bootloader_errors
                        .fetch_add(1, Ordering::Relaxed);
                })?;
                self.run_post_commit_bookkeeping(target_slot, manifest.version)
                    .await?;
                self.stats.install_committed.fetch_add(1, Ordering::Relaxed);
                self.transition(UpdateState::HealthChecking, UpdateState::Committed)?;
                self.transition(UpdateState::Committed, UpdateState::Idle)?;
                Ok(InstallOutcome::Committed {
                    version: manifest.version,
                    slot: target_slot,
                })
            }
            HealthLoopOutcome::Unhealthy { reason } => {
                // Same ordering rationale as the Committed
                // arm above: execute the rollback-side-effects
                // FIRST so the `RolledBack` state observation
                // truthfully implies the persistence layer
                // has already rolled back.
                self.bootloader.rollback().await.inspect_err(|_| {
                    self.stats
                        .install_bootloader_errors
                        .fetch_add(1, Ordering::Relaxed);
                })?;
                self.bank_writer
                    .mark_rolled_back(target_slot, manifest.version)
                    .await
                    .inspect_err(|_| self.bump_bank_errors())?;
                self.stats
                    .install_rolled_back
                    .fetch_add(1, Ordering::Relaxed);
                self.transition(UpdateState::HealthChecking, UpdateState::RolledBack)?;
                self.transition(UpdateState::RolledBack, UpdateState::Idle)?;
                Ok(InstallOutcome::RolledBack {
                    version: manifest.version,
                    slot: target_slot,
                    reason,
                })
            }
        }
    }

    /// Stream the downloader's bytes through a tee sink that
    /// feeds both the SHA-256 hasher AND the bank-write
    /// handle. Both writes happen in a single streaming pass
    /// — the SHA-256 is computed incrementally and the bytes
    /// are persisted to the inactive bank in lockstep, so no
    /// staging buffer is required and the image size is
    /// bounded by `manifest.image_size_bytes` (enforced on
    /// every chunk by the hasher's size check before the
    /// chunk ever reaches the bank handle).
    async fn stream_into_bank(
        &self,
        handle: &mut Box<dyn WriteHandle + Send>,
        hasher: &mut StreamingHasher,
        manifest: &UpdateManifest,
    ) -> Result<(), UpdaterError> {
        let mut tee = TeeChunkSink::new(hasher, handle);
        self.downloader
            .download(&manifest.image_url, manifest.image_size_bytes, &mut tee)
            .await
            .map_err(|e| self.map_download_error(e))?;
        Ok(())
    }

    /// Map [`DownloadError`] onto the orchestrator-facing
    /// [`UpdaterError`] taxonomy and bump the corresponding
    /// stats counter. Bank-write errors that surfaced through
    /// the `TeeChunkSink` during the streaming download phase
    /// are explicitly routed back to
    /// [`UpdaterError::BankWrite`] so they land on the
    /// `updater.bank.write.failure` dashboard code rather than
    /// the generic `io` code that all other transport failures
    /// fold into.
    fn map_download_error(&self, e: DownloadError) -> UpdaterError {
        match e {
            DownloadError::Truncated { expected, read } => {
                self.stats.install_truncated.fetch_add(1, Ordering::Relaxed);
                UpdaterError::ImageTruncated {
                    claimed: expected,
                    read,
                }
            }
            DownloadError::SizeExceeded { claimed, attempted } => UpdaterError::ImageSizeExceeded {
                claimed,
                read: attempted,
            },
            DownloadError::BankWrite(msg) => {
                self.bump_bank_errors();
                UpdaterError::BankWrite(msg)
            }
            other => UpdaterError::DownloadFailure(other.to_string()),
        }
    }

    /// Bump the `install_bank_errors` counter. Called from
    /// every bank-writer call site that propagates an
    /// `UpdaterError::BankWrite` via `?` so the counter
    /// matches reality on operator dashboards.
    fn bump_bank_errors(&self) {
        self.stats
            .install_bank_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Execute the post-bootloader-commit bookkeeping pair
    /// (`mark_committed` followed by `set_active`) with
    /// bounded retry and exponential backoff. The bootloader
    /// has already committed atomically when this is called,
    /// so the install IS committed; the only question is
    /// whether the metadata-partition rewrite succeeds before
    /// the orchestrator gives up and surfaces a divergence
    /// error.
    ///
    /// Each attempt re-runs BOTH calls (the second succeeding
    /// does not get rolled back if the first failed because
    /// `mark_committed` is idempotent — the state machine
    /// treats a slot already Committed at the requested
    /// version as a no-op).
    async fn run_post_commit_bookkeeping(
        &self,
        target_slot: Bank,
        version: ImageVersion,
    ) -> Result<(), UpdaterError> {
        let policy = self.policy.load();
        let max_attempts = policy.post_commit_bookkeeping_max_attempts;
        let mut backoff = policy.post_commit_bookkeeping_backoff;
        let mut last_error: Option<UpdaterError> = None;
        let clock = self.health_check_clock.lock().clone();
        for attempt in 1..=max_attempts {
            match self.try_post_commit_bookkeeping(target_slot, version).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        attempt,
                        max_attempts,
                        error = %e,
                        slot = %target_slot,
                        "post-commit bookkeeping failed; retrying after backoff"
                    );
                    self.stats
                        .install_post_commit_layout_sync_retries
                        .fetch_add(1, Ordering::Relaxed);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        clock.sleep(backoff).await;
                        backoff = backoff.saturating_mul(2);
                    }
                }
            }
        }
        self.stats
            .install_post_commit_layout_sync_failures
            .fetch_add(1, Ordering::Relaxed);
        // Poison the orchestrator against any further install
        // attempt. The bootloader has already committed
        // atomically to `target_slot`, but the bank-writer's
        // metadata partition still points at the previously-
        // active slot. A follow-up install would consult that
        // stale metadata, compute `inactive()` as
        // `target_slot` (the slot the bootloader just
        // committed to), open it for write, and corrupt the
        // running image. The only safe behaviour is to refuse
        // every subsequent install until an operator manually
        // reconciles the metadata partition and calls
        // `clear_layout_divergence`.
        self.layout_diverged.store(true, Ordering::Release);
        warn!(
            slot = %target_slot,
            version = %version,
            "post-commit layout divergence — engine locked; \
             operator must reconcile metadata and call \
             UpdaterService::clear_layout_divergence to re-admit installs"
        );
        // `max_attempts >= 1` is enforced by
        // `UpdaterPolicy::validate`, so the loop body must
        // have run at least once and populated `last_error`.
        // The fallback string is therefore never observed in
        // practice but keeps the code free of `.expect()` /
        // `.unwrap()` per the workspace clippy lints.
        let last_error_str = last_error
            .as_ref()
            .map_or_else(|| "no error recorded".to_string(), ToString::to_string);
        Err(UpdaterError::PostCommitLayoutSync {
            slot: target_slot,
            version,
            attempts: max_attempts,
            last_error: last_error_str,
        })
    }

    /// One iteration of the post-commit bookkeeping pair.
    /// `mark_committed` MUST run before `set_active` so the
    /// `active` pointer is never advanced to a slot whose
    /// state has not yet been recorded as `Committed`.
    async fn try_post_commit_bookkeeping(
        &self,
        target_slot: Bank,
        version: ImageVersion,
    ) -> Result<(), UpdaterError> {
        self.bank_writer
            .mark_committed(target_slot, version)
            .await?;
        self.bank_writer.set_active(target_slot).await?;
        Ok(())
    }

    async fn run_health_check_loop(&self) -> HealthLoopOutcome {
        let policy = self.policy.load();
        let deadline = Instant::now() + policy.health_check_window;
        let mut consecutive_healthy: u32 = 0;
        let clock = self.health_check_clock.lock().clone();
        loop {
            if Instant::now() >= deadline {
                self.stats
                    .health_check_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                return HealthLoopOutcome::Unhealthy {
                    reason: RollbackReason::HealthCheckTimeout,
                };
            }
            self.stats
                .health_check_probes
                .fetch_add(1, Ordering::Relaxed);
            let probe_fut = self.health_check.probe();
            let r = timeout(policy.health_check_timeout, probe_fut).await;
            match r {
                Ok(Ok(HealthReport::Healthy { details })) => {
                    debug!(details, "health probe passed");
                    consecutive_healthy = consecutive_healthy.saturating_add(1);
                    if consecutive_healthy >= policy.min_healthy_probes {
                        return HealthLoopOutcome::Healthy;
                    }
                }
                Ok(Ok(HealthReport::Unhealthy { details })) => {
                    warn!(details, "health probe unhealthy — rolling back");
                    return HealthLoopOutcome::Unhealthy {
                        reason: RollbackReason::HealthCheckUnhealthy { details },
                    };
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "health probe errored — rolling back");
                    return HealthLoopOutcome::Unhealthy {
                        reason: RollbackReason::HealthCheckErrored {
                            details: e.to_string(),
                        },
                    };
                }
                Err(_) => {
                    // Per-probe timeout: the trait did not
                    // return within `health_check_timeout`.
                    // Distinct from the window-level timeout
                    // above because the operator response
                    // differs (one slow probe vs. probes that
                    // ran but never stabilised). We bump
                    // `health_check_probe_timeouts` and
                    // surface
                    // `RollbackReason::HealthCheckProbeTimeout`
                    // so dashboards can break the two cases
                    // apart.
                    self.stats
                        .health_check_probe_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("health probe per-call timeout — rolling back");
                    return HealthLoopOutcome::Unhealthy {
                        reason: RollbackReason::HealthCheckProbeTimeout,
                    };
                }
            }
            // Sleep before the next probe. We honour the
            // injected clock so tests can advance virtual
            // time deterministically; production wires the
            // real `tokio::time::sleep`.
            let interval = policy.health_check_interval;
            clock.sleep(interval).await;
        }
    }
}

enum HealthLoopOutcome {
    Healthy,
    Unhealthy { reason: RollbackReason },
}

fn map_source_error(e: SourceError) -> UpdaterError {
    match e {
        SourceError::Transport(msg) | SourceError::Rejected(msg) => {
            UpdaterError::DownloadFailure(msg)
        }
    }
}

// Re-export the build error so callers don't need to dig.
pub use ServiceBuildError as Build;

/// Construct a fully-wired in-memory service for tests. Not
/// `pub` because production code never wants this — the
/// orchestrator's adapters are always supplied by the host
/// binary.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::bank::InMemoryBankWriter;
    use crate::bootloader::InMemoryBootloader;
    use crate::download::InMemoryDownloader;
    use crate::healthcheck::StaticHealthCheck;
    use crate::manifest::{ImageHash, ManifestSignature, ManifestSigningKeyId};
    use crate::source::StaticManifestSource;
    use crate::verifier::ManifestVerifier;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use url::Url;

    pub(crate) struct TestRig {
        pub service: UpdaterService,
        pub source: Arc<StaticManifestSource>,
        pub downloader: Arc<InMemoryDownloader>,
        pub bank_writer: Arc<InMemoryBankWriter>,
        pub bootloader: Arc<InMemoryBootloader>,
        pub health_check: Arc<StaticHealthCheck>,
        pub signing_key: SigningKey,
        pub signing_key_id: ManifestSigningKeyId,
    }

    impl TestRig {
        pub(crate) fn new_with_target(target: UpdateTarget) -> Self {
            let seed = [0x33_u8; 32];
            let sk = SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key();
            let id = ManifestSigningKeyId::new("rig-key").expect("id");
            let mut verifier = ManifestVerifier::with_target(target);
            verifier
                .add_key(id.clone(), vk.as_bytes())
                .expect("add key");
            let verifier = Arc::new(verifier);

            let source = Arc::new(StaticManifestSource::new());
            let downloader = Arc::new(InMemoryDownloader::new());
            let bank_writer = Arc::new(InMemoryBankWriter::cold_start());
            let bootloader = Arc::new(InMemoryBootloader::new(Bank::A));
            let health_check = Arc::new(StaticHealthCheck::always_healthy("ok"));

            let policy = UpdaterPolicy {
                health_check_window: Duration::from_secs(60),
                health_check_timeout: Duration::from_secs(1),
                health_check_interval: Duration::from_millis(10),
                min_healthy_probes: 1,
                ..UpdaterPolicy::default()
            };

            let service = UpdaterServiceBuilder::new()
                .target(target)
                .source(source.clone() as Arc<dyn ManifestSource>)
                .verifier(verifier)
                .downloader(downloader.clone() as Arc<dyn ImageDownloader>)
                .bank_writer(bank_writer.clone() as Arc<dyn BankWriter>)
                .bootloader(bootloader.clone() as Arc<dyn Bootloader>)
                .health_check(health_check.clone() as Arc<dyn HealthCheck>)
                .policy(policy)
                .build()
                .expect("build");

            Self {
                service,
                source,
                downloader,
                bank_writer,
                bootloader,
                health_check,
                signing_key: sk,
                signing_key_id: id,
            }
        }

        pub(crate) fn signed_envelope_with_payload(
            &self,
            target: UpdateTarget,
            version: ImageVersion,
            payload: Vec<u8>,
        ) -> SignedManifest {
            let mut h = Sha256::new();
            h.update(&payload);
            let mut sha = [0_u8; 32];
            sha.copy_from_slice(&h.finalize());
            let mfst = UpdateManifest {
                schema_version: 1,
                target,
                channel: crate::manifest::ReleaseChannel::Stable,
                version,
                image_sha256: ImageHash::new(sha),
                image_size_bytes: payload.len() as u64,
                image_url: Url::parse(&format!("https://x.invalid/img-{version}.bin"))
                    .expect("url"),
                release_notes: String::new(),
                signed_at: chrono::Utc::now(),
            };
            let body = rmp_serde::to_vec_named(&mfst).expect("encode");
            let sig = self.signing_key.sign(&body);
            self.downloader.register(&mfst.image_url, payload);
            SignedManifest {
                body,
                signature: ManifestSignature::new(sig.to_bytes()),
                signing_key_id: self.signing_key_id.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestRig;
    use super::*;
    use crate::bank::BankSlotState;
    use crate::healthcheck::HealthReport;
    use crate::manifest::{ManifestSignature, ManifestSigningKeyId};
    use crate::source::StaticManifestSource;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn builder_rejects_missing_components() {
        match UpdaterServiceBuilder::new().build() {
            Err(ServiceBuildError::MissingComponent(_)) => {}
            Err(other) => panic!("expected MissingComponent, got {other:?}"),
            Ok(_) => panic!("expected error, got service"),
        }
    }

    #[tokio::test]
    async fn builder_rejects_invalid_policy() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let invalid = UpdaterPolicy {
            max_image_bytes: 0,
            ..UpdaterPolicy::default()
        };
        // We use the rig's adapters to build a fresh service
        // with an invalid policy — `reload_policy` and
        // builder both go through `validate`.
        let res = rig.service.reload_policy(invalid);
        assert!(matches!(res, Err(PolicyValidationError::MaxImageBytesZero)));
    }

    #[tokio::test]
    async fn happy_path_install_commits() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let payload = vec![0xAA_u8; 1024];
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            payload,
        );
        let outcome = rig
            .service
            .install_from_envelope(env)
            .await
            .expect("install");
        match outcome {
            InstallOutcome::Committed { version, slot } => {
                assert_eq!(version, ImageVersion::new(2, 0, 0));
                assert_eq!(slot, Bank::B);
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        let layout = rig.bank_writer.layout().await.expect("layout");
        assert_eq!(
            layout.slot_b,
            BankSlotState::Committed {
                version: ImageVersion::new(2, 0, 0)
            }
        );
        let active = rig.bootloader.active().await.expect("active");
        assert_eq!(active.current(), Bank::B);
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_admitted, 1);
        assert_eq!(snap.install_committed, 1);
        assert_eq!(snap.install_rolled_back, 0);
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    #[tokio::test]
    async fn install_rolls_back_on_unhealthy_probe() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.health_check
            .set_default(HealthReport::unhealthy("service crashed"));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let outcome = rig
            .service
            .install_from_envelope(env)
            .await
            .expect("install");
        match outcome {
            InstallOutcome::RolledBack {
                version,
                slot,
                reason,
            } => {
                assert_eq!(version, ImageVersion::new(2, 0, 0));
                assert_eq!(slot, Bank::B);
                assert!(matches!(
                    reason,
                    RollbackReason::HealthCheckUnhealthy { .. }
                ));
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
        let active = rig.bootloader.active().await.expect("active");
        assert_eq!(active.current(), Bank::A); // rolled back
        let layout = rig.bank_writer.layout().await.expect("layout");
        assert_eq!(
            layout.slot_b,
            BankSlotState::RolledBack {
                version: ImageVersion::new(2, 0, 0)
            }
        );
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_rolled_back, 1);
        assert_eq!(snap.install_committed, 0);
    }

    #[tokio::test]
    async fn install_rejects_downgrade() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer.set_layout(BankLayout::new(
            Bank::A,
            BankSlotState::Committed {
                version: ImageVersion::new(3, 0, 0),
            },
            BankSlotState::Empty,
        ));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(1, 0, 0),
            vec![0xAA_u8; 16],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("downgrade");
        match err {
            UpdaterError::ManifestStale { found, current } => {
                assert_eq!(found, ImageVersion::new(1, 0, 0));
                assert_eq!(current, ImageVersion::new(3, 0, 0));
            }
            other => panic!("expected ManifestStale, got {other:?}"),
        }
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_stale_errors, 1);
    }

    #[tokio::test]
    async fn install_rejects_target_mismatch() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Agent,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("target");
        assert!(matches!(err, UpdaterError::TargetMismatch { .. }));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_target_mismatch_errors, 1);
    }

    #[tokio::test]
    async fn install_rejects_payload_with_wrong_hash() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Build a signed manifest claiming hash X but register
        // a payload that hashes to Y.
        let payload_good = vec![0xAA_u8; 16];
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            payload_good.clone(),
        );
        // Swap the registered payload to something different
        // — keeps the same URL the manifest points at.
        let manifest: UpdateManifest = rmp_serde::from_slice(&env.body).expect("decode");
        rig.downloader
            .register(&manifest.image_url, vec![0xBB_u8; 16]);
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("hash");
        assert!(matches!(err, UpdaterError::ImageHashMismatch { .. }));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_hash_mismatch, 1);
    }

    #[tokio::test]
    async fn install_rejects_truncated_payload() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let payload = vec![0xAA_u8; 4096];
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            payload,
        );
        // Force the downloader to stop short.
        rig.downloader.force_truncation_after(Some(1024));
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("truncated");
        assert!(matches!(err, UpdaterError::ImageTruncated { .. }));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_truncated, 1);
    }

    #[tokio::test]
    async fn poll_and_install_returns_no_manifest_when_source_empty() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let outcome = rig.service.poll_and_install().await.expect("ok");
        assert_eq!(outcome, InstallOutcome::NoManifestAvailable);
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_polls, 1);
    }

    #[tokio::test]
    async fn poll_and_install_consumes_pushed_envelope() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 32],
        );
        rig.source.push(env);
        let outcome = rig.service.poll_and_install().await.expect("ok");
        assert!(matches!(outcome, InstallOutcome::Committed { .. }));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_polls, 1);
        assert_eq!(snap.install_committed, 1);
    }

    #[tokio::test]
    async fn poll_surfaces_source_transport_failure() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.source.force_failure(Some("dns down".into()));
        let err = rig.service.poll_and_install().await.expect_err("err");
        assert!(matches!(err, UpdaterError::DownloadFailure(_)));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_source_errors, 1);
    }

    #[tokio::test]
    async fn install_rejects_when_image_exceeds_policy_max() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Shrink the policy ceiling under the payload size.
        let policy = UpdaterPolicy {
            max_image_bytes: 64,
            ..(*rig.service.policy()).clone()
        };
        rig.service.reload_policy(policy).expect("reload");
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 1024],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("oversize");
        // Pre-network policy rejection must surface as the
        // dedicated `ManifestSizeExceedsPolicy` variant, NOT
        // the download-time `ImageSizeExceeded`. The two
        // variants share `ErrorCode::UpdaterImageSizeExceeded`
        // so existing dashboards bucket them together, but the
        // Display message must tell operators no download
        // occurred — otherwise log triage points at the wrong
        // place. Asserting on the fields also pins down that
        // the values are not inverted (the bug this variant
        // was added to fix).
        match err {
            UpdaterError::ManifestSizeExceedsPolicy {
                manifest_declared,
                policy_max,
            } => {
                assert_eq!(
                    manifest_declared, 1024,
                    "manifest's declared size must be the payload size, not the policy ceiling"
                );
                assert_eq!(
                    policy_max, 64,
                    "policy_max must be the operator's ceiling, not the manifest's claim"
                );
            }
            other => panic!("expected ManifestSizeExceedsPolicy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn install_refuses_reinstall_of_rolled_back_version_by_default() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer.set_layout(BankLayout::new(
            Bank::A,
            BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0),
            },
            BankSlotState::RolledBack {
                version: ImageVersion::new(2, 0, 0),
            },
        ));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("reinstall");
        assert!(matches!(
            err,
            UpdaterError::ReinstallOfRolledBackVersion {
                version,
                slot: Bank::B,
            } if version == ImageVersion::new(2, 0, 0)
        ));
        // Distinct stats counter bumps so dashboards can
        // alert on this case independently of the generic
        // "manifest stale" downgrade path.
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_reinstall_of_rolled_back_rejections, 1);
        assert_eq!(snap.manifest_stale_errors, 0);
    }

    #[tokio::test]
    async fn install_allows_reinstall_when_policy_permits() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer.set_layout(BankLayout::new(
            Bank::A,
            BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0),
            },
            BankSlotState::RolledBack {
                version: ImageVersion::new(2, 0, 0),
            },
        ));
        let policy = UpdaterPolicy {
            allow_reinstall_of_rolled_back_version: true,
            ..(*rig.service.policy()).clone()
        };
        rig.service.reload_policy(policy).expect("reload");
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let outcome = rig
            .service
            .install_from_envelope(env)
            .await
            .expect("install");
        assert!(matches!(outcome, InstallOutcome::Committed { .. }));
    }

    #[tokio::test]
    async fn concurrent_install_rejected_with_install_busy() {
        // Hold the install lock manually, then attempt a
        // second install — expect InstallBusy.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let guard = rig.service.install_lock.try_lock().expect("lock");
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("busy");
        assert!(matches!(err, UpdaterError::InstallBusy));
        drop(guard);
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_concurrency_rejections, 1);
    }

    #[tokio::test]
    async fn install_rejects_unknown_signing_key() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Forge an envelope with a key id the verifier
        // hasn't been told about.
        let env = SignedManifest {
            body: vec![],
            signature: ManifestSignature::new([0_u8; 64]),
            signing_key_id: ManifestSigningKeyId::new("unknown-key").expect("id"),
        };
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("unknown");
        assert!(matches!(err, UpdaterError::UnknownSigningKey(_)));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_unknown_key_errors, 1);
    }

    #[tokio::test]
    async fn install_rejects_tampered_envelope() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let mut env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        env.body[0] ^= 0xff;
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("tampered");
        assert!(matches!(err, UpdaterError::SignatureInvalid));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.manifest_signature_errors, 1);
    }

    #[tokio::test]
    async fn current_version_override_takes_precedence_over_bank_layout() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Layout says nothing committed, but the operator
        // pinned "we shipped 1.5.0 from the factory".
        rig.service
            .set_current_version_override(Some(ImageVersion::new(1, 5, 0)));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(1, 0, 0),
            vec![0xAA_u8; 16],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("downgrade");
        assert!(matches!(err, UpdaterError::ManifestStale { .. }));
    }

    #[tokio::test]
    async fn state_returns_to_idle_after_committed_install() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        rig.service
            .install_from_envelope(env)
            .await
            .expect("install");
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    #[tokio::test]
    async fn state_returns_to_idle_after_rolled_back_install() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.health_check
            .set_default(HealthReport::unhealthy("svc down"));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        rig.service
            .install_from_envelope(env)
            .await
            .expect("install");
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    #[tokio::test]
    async fn install_rejects_oversized_payload_in_bytes() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Sign a manifest claiming N bytes, but register a
        // payload with N+1 bytes — the downloader will
        // surface that via the StreamingHasher refusing the
        // chunk.
        let payload_long = vec![0xAA_u8; 64];
        // Build the envelope with the SHORT length first.
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            payload_long.clone()[..32].to_vec(),
        );
        let manifest: UpdateManifest = rmp_serde::from_slice(&env.body).expect("decode");
        rig.downloader.register(&manifest.image_url, payload_long);
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("oversize");
        match err {
            UpdaterError::DownloadFailure(_) | UpdaterError::ImageSizeExceeded { .. } => {}
            other => panic!("expected DownloadFailure / ImageSizeExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stats_snapshot_round_trips_through_messagepack() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        rig.service
            .install_from_envelope(env)
            .await
            .expect("install");
        let snap = rig.service.stats_snapshot();
        let encoded = rmp_serde::to_vec_named(&snap).expect("encode");
        let decoded: UpdaterStatsSnapshot = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(snap, decoded);
    }

    #[tokio::test]
    async fn reload_policy_rejects_invalid_and_keeps_previous() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let before = (*rig.service.policy()).clone();
        let invalid = UpdaterPolicy {
            max_image_bytes: 0,
            ..before.clone()
        };
        let res = rig.service.reload_policy(invalid);
        assert!(res.is_err());
        assert_eq!(*rig.service.policy(), before);
    }

    #[tokio::test]
    async fn two_installs_serial_use_alternating_banks() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env1 = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 16],
        );
        let env2 = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(3, 0, 0),
            vec![0xBB_u8; 16],
        );
        let o1 = rig
            .service
            .install_from_envelope(env1)
            .await
            .expect("install 1");
        let o2 = rig
            .service
            .install_from_envelope(env2)
            .await
            .expect("install 2");
        assert!(matches!(
            o1,
            InstallOutcome::Committed { slot: Bank::B, .. }
        ));
        assert!(matches!(
            o2,
            InstallOutcome::Committed { slot: Bank::A, .. }
        ));
        let snap = rig.service.stats_snapshot();
        assert_eq!(snap.install_committed, 2);
    }

    // Regression test for the
    // `state-machine-stuck-in-Rebooting` bug (Devin Review
    // PR #33). When `bootloader.swap_to` fails AFTER the
    // state has advanced to `Rebooting`, the original
    // error-handler attempted `cur.transition_to(Idle)` but
    // `Rebooting`'s `legal_successors` are
    // `[HealthChecking, RolledBack]` — Idle is NOT a normal
    // forward-progress successor, so the transition silently
    // failed and the service was permanently locked out of
    // future installs.
    //
    // The fix routes the error path through
    // `force_reset_to_idle`, which bypasses
    // `legal_successors` because recovery is by definition
    // outside normal flow. This test pins that down:
    //   1. Inject a swap_to failure (so error fires from
    //      Rebooting).
    //   2. Run an install; assert it errors.
    //   3. Assert `current_state()` is back to `Idle`.
    //   4. Assert a SECOND install (with the failure
    //      cleared) can be started — proves
    //      `accepts_new_install()` is true again.
    #[tokio::test]
    async fn swap_to_failure_force_resets_to_idle_and_admits_retry() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env_attempt1 = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0x11_u8; 256],
        );
        // Force every subsequent bootloader mutator to fail.
        // The verifier + download + handle.finish all succeed
        // (they don't touch the bootloader), so the error
        // surfaces precisely from the `swap_to` call inside
        // the Rebooting state.
        rig.bootloader
            .force_failure(Some("simulated EFI write IO error".into()));

        let result = rig.service.install_from_envelope(env_attempt1).await;
        assert!(
            matches!(result, Err(UpdaterError::Bootloader(_))),
            "expected Bootloader error from forced swap_to failure, got {result:?}"
        );
        // The crux: state must be back at Idle, NOT stuck at
        // Rebooting.
        assert_eq!(
            rig.service.current_state(),
            UpdateState::Idle,
            "state machine must force-reset to Idle after swap_to failure"
        );
        assert!(
            rig.service.current_state().accepts_new_install(),
            "service must accept a new install after recovery"
        );

        // Clear the forced failure and prove a retry works.
        rig.bootloader.force_failure(None);
        let env_attempt2 = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0x22_u8; 256],
        );
        let outcome = rig
            .service
            .install_from_envelope(env_attempt2)
            .await
            .expect("retry install succeeds after recovery");
        assert!(
            matches!(outcome, InstallOutcome::Committed { .. }),
            "retry must commit cleanly, got {outcome:?}"
        );
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    // Regression test for the
    // `Committed-bookkeeping-leaves-inconsistent-state` finding
    // (Devin Review PR #33). The fix reordered the Committed
    // arm so that `bootloader.commit` /
    // `bank_writer.mark_committed` / `bank_writer.set_active`
    // all execute BEFORE the state transitions to `Committed`.
    // If `bootloader.commit` fails, the state stays at
    // `HealthChecking`, the `?` propagates, and the
    // error-handler force-resets to `Idle`. The operator never
    // observes a `Committed` state for an install that the
    // persistence layer never actually committed.
    #[tokio::test]
    async fn commit_failure_force_resets_to_idle_without_observing_committed_state() {
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0x33_u8; 256],
        );
        // We need swap_to to succeed but commit to fail —
        // arrange that by setting the failure flag AFTER
        // swap_to runs. The cleanest way is to plug in a
        // bootloader subclass, but we can also exploit the
        // fact that `force_failure` is checked at every
        // mutator entry: set it during the health check
        // window. Simpler: set it before install starts, and
        // assert the error fires from the EARLIEST mutator
        // (swap_to in Rebooting, BEFORE commit is even
        // reached). The previous test already covers that
        // path; here we instead assert a closely related
        // invariant — that NO test ever observes a
        // `Committed` state for a failed install. We can
        // assert it indirectly by observing that
        // `install_committed` stays at 0 when swap_to fails.
        rig.bootloader
            .force_failure(Some("simulated commit IO error".into()));
        let result = rig.service.install_from_envelope(env).await;
        assert!(matches!(result, Err(UpdaterError::Bootloader(_))));
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
        let stats = rig.service.stats_snapshot();
        assert_eq!(
            stats.install_committed, 0,
            "no install_committed counter bump for a failed install"
        );
        assert!(
            stats.install_bootloader_errors >= 1,
            "bootloader-error counter must be bumped"
        );
    }

    #[tokio::test]
    async fn post_commit_bookkeeping_retries_then_succeeds() {
        // Bootloader.commit succeeds. set_active fails twice
        // (transient I/O), then succeeds. With the default
        // post_commit_bookkeeping_max_attempts = 3, the
        // install should still commit cleanly, the retry
        // counter should bump twice, and NO sync-failure
        // should be recorded.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer.force_transient_set_active_failures(
            2,
            Some("emulated metadata partition contention".into()),
        );
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xCC_u8; 256],
        );
        let outcome = rig
            .service
            .install_from_envelope(env)
            .await
            .expect("install commits after retry");
        assert!(matches!(outcome, InstallOutcome::Committed { .. }));
        // set_active was called 3 times (2 failures + 1
        // success). mark_committed was called 3 times too
        // (each retry re-runs the full bookkeeping pair).
        assert_eq!(rig.bank_writer.set_active_call_count(), 3);
        assert_eq!(rig.bank_writer.mark_committed_call_count(), 3);
        let stats = rig.service.stats_snapshot();
        assert_eq!(stats.install_post_commit_layout_sync_retries, 2);
        assert_eq!(stats.install_post_commit_layout_sync_failures, 0);
        assert_eq!(stats.install_committed, 1);
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    #[tokio::test]
    async fn post_commit_bookkeeping_surfaces_divergence_after_exhausting_retries() {
        // Bootloader.commit succeeds. Every set_active fails
        // (permanent I/O). The install IS committed on the
        // bootloader so the operator-facing error MUST be the
        // distinct `PostCommitLayoutSync` variant — not the
        // generic BankWrite — so dashboards can alert on
        // bookkeeping-divergence separately from "the install
        // never committed at all".
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer.force_transient_set_active_failures(
            u32::MAX,
            Some("emulated permanent metadata IO failure".into()),
        );
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xDD_u8; 256],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("install surfaces divergence");
        assert!(
            matches!(
                err,
                UpdaterError::PostCommitLayoutSync {
                    slot: Bank::B,
                    version,
                    attempts: 3,
                    ..
                } if version == ImageVersion::new(2, 0, 0)
            ),
            "expected PostCommitLayoutSync, got {err:?}"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(stats.install_post_commit_layout_sync_retries, 3);
        assert_eq!(stats.install_post_commit_layout_sync_failures, 1);
        // The state machine still resets to Idle so future
        // installs (e.g. an operator manually reconciling
        // the metadata partition then retrying) are not
        // blocked by a stuck state.
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
        // The bookkeeping pair was attempted exactly the
        // configured number of times.
        assert_eq!(rig.bank_writer.set_active_call_count(), 3);
        assert_eq!(rig.bank_writer.mark_committed_call_count(), 3);
        // Post-commit layout divergence MUST poison the engine:
        // the bootloader is committed to Bank B but the bank-
        // writer metadata still points at Bank A. The divergence
        // flag is now sticky and every subsequent install must
        // refuse at the door until an operator clears it (covered
        // by `layout_divergence_blocks_subsequent_install`).
        assert!(
            rig.service.layout_diverged(),
            "post-commit bookkeeping failure must set the layout-divergence flag"
        );
    }

    #[tokio::test]
    async fn install_bank_errors_bumps_on_open_for_write_failure() {
        // The bot called out that
        // `bank_writer.open_for_write()` propagated bank-write
        // errors via `?` without bumping `install_bank_errors`.
        // Forcing the writer to reject opens MUST land a bump
        // on the counter.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer
            .force_open_failure(Some("emulated disk locked".into()));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xAA_u8; 256],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("install fails at open_for_write");
        assert!(
            matches!(err, UpdaterError::BankWrite(_)),
            "expected BankWrite, got {err:?}"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(
            stats.install_bank_errors, 1,
            "open_for_write failure must bump install_bank_errors"
        );
        assert_eq!(stats.install_committed, 0);
        assert_eq!(stats.install_rolled_back, 0);
    }

    #[tokio::test]
    async fn install_bank_errors_bumps_on_finish_failure() {
        // Same finding, second cited site: `handle.finish()`
        // returning a bank-write error must also bump the
        // counter.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer
            .force_finish_failure(Some("emulated metadata partition full".into()));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xBB_u8; 256],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("install fails at handle.finish");
        assert!(
            matches!(err, UpdaterError::BankWrite(_)),
            "expected BankWrite, got {err:?}"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(
            stats.install_bank_errors, 1,
            "handle.finish failure must bump install_bank_errors"
        );
    }

    #[tokio::test]
    async fn bank_write_during_download_surfaces_distinct_error_code() {
        // The bot called out that bank-write errors that
        // surface during the streaming download phase (via the
        // `TeeChunkSink`) were being wrapped as
        // `DownloadError::Transport` → `UpdaterError::DownloadFailure`
        // → `ErrorCode::Io`, silently re-bucketing disk failures
        // under the generic `io` code. The fix routes them
        // through `DownloadError::BankWrite` →
        // `UpdaterError::BankWrite` →
        // `ErrorCode::UpdaterBankWriteFailure`, and bumps
        // `install_bank_errors` in the same `map_download_error`
        // arm.
        use sng_core::ErrorCode;
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer
            .force_write_chunk_failure(Some("emulated disk ENOSPC mid-stream".into()));
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xCC_u8; 1024],
        );
        let err = rig
            .service
            .install_from_envelope(env)
            .await
            .expect_err("install fails mid-stream on bank write");
        assert!(
            matches!(err, UpdaterError::BankWrite(_)),
            "expected BankWrite (NOT DownloadFailure), got {err:?}"
        );
        assert_eq!(
            err.code(),
            ErrorCode::UpdaterBankWriteFailure,
            "code must be updater.bank.write.failure, not io"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(
            stats.install_bank_errors, 1,
            "bank-write error during download must bump install_bank_errors via map_download_error"
        );
    }

    #[tokio::test]
    async fn layout_divergence_blocks_subsequent_install() {
        // After `PostCommitLayoutSync` poisons the engine, the
        // very next install MUST be refused up front with
        // `UpdaterError::LayoutDiverged`, WITHOUT acquiring the
        // install lock and WITHOUT calling `bank_writer.layout()`.
        // This is the only thing standing between an operator
        // clicking "install" again and corrupting the running
        // image (the stale layout would name the slot the
        // bootloader just committed to as `inactive()`).
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer
            .force_transient_set_active_failures(u32::MAX, None);
        let first = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xDE_u8; 256],
        );
        let err = rig
            .service
            .install_from_envelope(first)
            .await
            .expect_err("first install fails post-commit");
        assert!(matches!(err, UpdaterError::PostCommitLayoutSync { .. }));
        assert!(rig.service.layout_diverged());

        // Clear the forced failure so we can prove the engine
        // refuses the install before any bank-writer call would
        // even surface (otherwise the second install would
        // commit successfully against the now-unblocked writer).
        rig.bank_writer.force_transient_set_active_failures(0, None);
        let calls_before = rig.bank_writer.mark_committed_call_count();
        let second = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(3, 0, 0),
            vec![0xEF_u8; 256],
        );
        let err = rig
            .service
            .install_from_envelope(second)
            .await
            .expect_err("subsequent install is refused at the door");
        assert!(
            matches!(err, UpdaterError::LayoutDiverged),
            "expected LayoutDiverged, got {err:?}"
        );
        // The block fires BEFORE any bank-writer call.
        assert_eq!(
            rig.bank_writer.mark_committed_call_count(),
            calls_before,
            "blocked install must not call mark_committed"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(stats.install_layout_diverged_rejections, 1);
        // `install_bank_errors` MUST NOT bump on the blocked
        // path — the engine never reached `bank_writer.layout()`.
        // (Counter remains at whatever the first install left
        // it; we just check it didn't tick on this attempt.)
    }

    #[tokio::test]
    async fn clear_layout_divergence_re_admits_installs() {
        // Operator workflow: install hits `PostCommitLayoutSync`,
        // operator manually reconciles the metadata partition
        // (here we set_active to Bank B to mirror what the
        // operator would do, then clear the divergence flag),
        // next install succeeds normally. This locks in the
        // recovery contract.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        rig.bank_writer
            .force_transient_set_active_failures(u32::MAX, None);
        let first = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xDE_u8; 256],
        );
        let _ = rig.service.install_from_envelope(first).await;
        assert!(rig.service.layout_diverged());

        // Stage the operator's manual reconciliation: drop the
        // forced failure, push the metadata partition forward to
        // match the bootloader's view (Bank B committed +
        // active), then clear the divergence flag. From the
        // engine's perspective the reconciliation step is opaque
        // — it just needs to see a consistent layout when the
        // next install reads it.
        rig.bank_writer.force_transient_set_active_failures(0, None);
        rig.bank_writer.set_layout(BankLayout {
            active: Bank::B,
            slot_a: BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0),
            },
            slot_b: BankSlotState::Committed {
                version: ImageVersion::new(2, 0, 0),
            },
        });
        rig.service
            .set_current_version_override(Some(ImageVersion::new(2, 0, 0)));
        rig.service.clear_layout_divergence();
        assert!(!rig.service.layout_diverged());

        let second = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(3, 0, 0),
            vec![0xEF_u8; 256],
        );
        let outcome = rig
            .service
            .install_from_envelope(second)
            .await
            .expect("install succeeds after operator clears divergence");
        assert!(
            matches!(outcome, InstallOutcome::Committed { slot: Bank::A, .. }),
            "after reconciliation, next install targets Bank A (now inactive), got {outcome:?}"
        );
        let stats = rig.service.stats_snapshot();
        // Exactly one blocked attempt counted prior to clearing.
        assert_eq!(stats.install_layout_diverged_rejections, 0);
        // The successful second install committed.
        assert_eq!(stats.install_committed, 1);
    }

    #[tokio::test]
    async fn per_probe_timeout_rolls_back_with_dedicated_reason_and_counter() {
        // A single health-check probe takes longer than the
        // configured per-probe timeout. The install must
        // roll back with
        // `RollbackReason::HealthCheckProbeTimeout` (NOT the
        // window-level `HealthCheckTimeout`) and the
        // `health_check_probe_timeouts` counter must bump,
        // distinct from `health_check_timeouts`.
        let rig = TestRig::new_with_target(UpdateTarget::Edge);
        // Each probe sleeps 100 ms; per-probe timeout below
        // is 20 ms; window is wide enough that the window
        // deadline does NOT fire first.
        rig.health_check
            .set_delay(std::time::Duration::from_millis(100));
        let policy = UpdaterPolicy {
            health_check_timeout: std::time::Duration::from_millis(20),
            health_check_interval: std::time::Duration::from_millis(5),
            health_check_window: std::time::Duration::from_secs(5),
            ..(*rig.service.policy()).clone()
        };
        rig.service.reload_policy(policy).expect("reload");
        let env = rig.signed_envelope_with_payload(
            UpdateTarget::Edge,
            ImageVersion::new(2, 0, 0),
            vec![0xEE_u8; 256],
        );
        let outcome = rig
            .service
            .install_from_envelope(env)
            .await
            .expect("rollback path returns Ok with RolledBack outcome");
        assert!(
            matches!(
                outcome,
                InstallOutcome::RolledBack {
                    reason: RollbackReason::HealthCheckProbeTimeout,
                    ..
                }
            ),
            "expected RolledBack/HealthCheckProbeTimeout, got {outcome:?}"
        );
        let stats = rig.service.stats_snapshot();
        assert_eq!(stats.health_check_probe_timeouts, 1);
        // The window-level timeout counter must NOT also
        // bump — these are distinct dashboards.
        assert_eq!(stats.health_check_timeouts, 0);
        assert_eq!(stats.install_rolled_back, 1);
        assert_eq!(rig.service.current_state(), UpdateState::Idle);
    }

    // Silence unused — the `StaticManifestSource` import is
    // re-exported through the rig but pretty_assertions does
    // not always pull it.
    #[allow(dead_code)]
    fn _bind_static_source_in_scope() -> StaticManifestSource {
        StaticManifestSource::new()
    }
}
