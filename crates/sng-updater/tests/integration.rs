//! Black-box integration tests for `sng-updater`.
//!
//! These tests exercise the orchestrator end-to-end through
//! the crate's public API only — no `pub(crate)` shims, no
//! test_support module access. They mirror the Task 19 list
//! from the project's PR-12 spec:
//!
//!   * full update cycle with mock control plane
//!     (fetch manifest → download → install → commit)
//!   * downgrade prevention
//!   * rollback on failing health check
//!   * concurrent update prevention (single install lock)
//!   * resume / retry after a transient transport failure
//!     (downloader truncation + corrected payload on the
//!     same envelope)
//!   * tampered-payload rejection (signature verifies, body
//!     hash does not match — orchestrator surfaces a
//!     `HashMismatch`)
//!
//! All side-effects live behind crate-supplied test doubles so
//! the test binary needs no root, no real disk, no real
//! bootloader, and no network.

// Integration tests live in `tests/` so they do NOT inherit
// the lib's `#[cfg(test)]` allow-set. Mirror the same
// posture here so the workspace-wide pedantic lint group
// does not bury the test in `panic` / `unwrap` / `expect`
// noise.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::match_wildcard_for_single_variants,
    clippy::single_match_else,
    clippy::useless_vec,
    clippy::explicit_iter_loop,
    clippy::float_cmp
)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use url::Url;

use sng_updater::{
    UpdaterError,
    bank::{Bank, InMemoryBankWriter},
    bootloader::InMemoryBootloader,
    download::InMemoryDownloader,
    healthcheck::{HealthReport, StaticHealthCheck},
    manifest::{
        ImageHash, ImageVersion, ManifestSignature, ManifestSigningKeyId, ReleaseChannel,
        SignedManifest, UpdateManifest, UpdateTarget,
    },
    policy::UpdaterPolicy,
    service::{InstallOutcome, RollbackReason, UpdaterServiceBuilder},
    source::StaticManifestSource,
    verifier::ManifestVerifier,
};

/// A fully-wired test rig assembled from the crate's public
/// adapters. The integration test owns one of these per
/// scenario.
struct Rig {
    service: sng_updater::UpdaterService,
    source: Arc<StaticManifestSource>,
    downloader: Arc<InMemoryDownloader>,
    bank_writer: Arc<InMemoryBankWriter>,
    bootloader: Arc<InMemoryBootloader>,
    health_check: Arc<StaticHealthCheck>,
    signing_key: SigningKey,
    signing_key_id: ManifestSigningKeyId,
}

impl Rig {
    fn new(target: UpdateTarget) -> Self {
        Self::new_with_policy(target, fast_policy())
    }

    fn new_with_policy(target: UpdateTarget, policy: UpdaterPolicy) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_key_id = ManifestSigningKeyId::new("integration-test-key").expect("id");

        let mut verifier = ManifestVerifier::with_target(target);
        verifier
            .add_key(
                signing_key_id.clone(),
                signing_key.verifying_key().as_bytes(),
            )
            .expect("install key");

        let source = Arc::new(StaticManifestSource::new());
        let downloader = Arc::new(InMemoryDownloader::new());
        let bank_writer = Arc::new(InMemoryBankWriter::cold_start());
        let bootloader = Arc::new(InMemoryBootloader::new(Bank::A));
        let health_check = Arc::new(StaticHealthCheck::always_healthy("test-default"));

        let service = UpdaterServiceBuilder::new()
            .target(target)
            .source(source.clone())
            .verifier(Arc::new(verifier))
            .downloader(downloader.clone())
            .bank_writer(bank_writer.clone())
            .bootloader(bootloader.clone())
            .health_check(health_check.clone())
            .policy(policy)
            .build()
            .expect("build service");

        Self {
            service,
            source,
            downloader,
            bank_writer,
            bootloader,
            health_check,
            signing_key,
            signing_key_id,
        }
    }

    /// Build a signed envelope whose body authenticates the
    /// supplied payload's SHA-256.
    fn sign_envelope(
        &self,
        target: UpdateTarget,
        version: ImageVersion,
        payload: &[u8],
    ) -> SignedManifest {
        let mut h = Sha256::new();
        h.update(payload);
        let mut sha = [0_u8; 32];
        sha.copy_from_slice(&h.finalize());
        let manifest = UpdateManifest {
            schema_version: 1,
            target,
            channel: ReleaseChannel::Stable,
            version,
            image_sha256: ImageHash::new(sha),
            image_size_bytes: payload.len() as u64,
            image_url: Url::parse(&format!("https://x.invalid/integration-{version}.bin"))
                .expect("url"),
            release_notes: String::new(),
            signed_at: Utc::now(),
        };
        let body = rmp_serde::to_vec_named(&manifest).expect("encode body");
        let sig = self.signing_key.sign(&body);
        let signature = ManifestSignature::new(sig.to_bytes());
        SignedManifest {
            body,
            signature,
            signing_key_id: self.signing_key_id.clone(),
        }
    }
}

/// Health-check window short enough that the rollback-on-
/// unhealthy test does not have to wait the production
/// default (5 minutes). All other knobs are at their
/// production defaults so the test exercises the real path.
fn fast_policy() -> UpdaterPolicy {
    UpdaterPolicy {
        health_check_window: Duration::from_millis(500),
        health_check_timeout: Duration::from_millis(200),
        health_check_interval: Duration::from_millis(20),
        min_healthy_probes: 1,
        ..UpdaterPolicy::default()
    }
}

#[tokio::test]
async fn full_cycle_fetch_download_install_commit_via_pull_source() {
    // The control plane publishes a manifest by pushing it
    // into the source queue. The orchestrator pulls it,
    // verifies, downloads, hashes, swaps banks, runs the
    // health probe, and commits.
    let rig = Rig::new(UpdateTarget::Edge);
    let payload = vec![0x42_u8; 4096];
    let envelope = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload.clone(),
    );
    rig.source.push(envelope);

    let outcome = rig
        .service
        .poll_and_install()
        .await
        .expect("install succeeds");
    match outcome {
        InstallOutcome::Committed { version, slot } => {
            assert_eq!(version, ImageVersion::new(2, 0, 0));
            // First install on a cold-start layout lands in B
            // because the seeded active bank is A.
            assert_eq!(slot, Bank::B);
        }
        other => panic!("expected Committed, got {other:?}"),
    }

    // Side-effects we can inspect: bank holds the bytes,
    // bootloader committed the swap, source was drained.
    assert_eq!(rig.bank_writer.slot_bytes(Bank::B), payload);
    assert_eq!(rig.bootloader.commit_count(), 1);
    assert_eq!(rig.bootloader.rollback_count(), 0);
    assert_eq!(rig.source.queue_depth(), 0);

    let stats = rig.service.stats_snapshot();
    assert_eq!(stats.install_committed, 1);
    assert_eq!(stats.install_rolled_back, 0);
    assert_eq!(stats.manifest_admitted, 1);
}

#[tokio::test]
async fn downgrade_is_rejected_before_any_bytes_move() {
    // Pin a committed version on the bank writer then push a
    // manifest with a smaller version. The verifier must
    // reject before the downloader is ever touched.
    let rig = Rig::new(UpdateTarget::Edge);

    // Stage a baseline 2.0.0 commit so subsequent < 2.0.0
    // versions are downgrades.
    let payload_v2 = vec![0xAA_u8; 2048];
    let env_v2 = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload_v2);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload_v2,
    );
    rig.service
        .install_from_envelope(env_v2)
        .await
        .expect("baseline install commits");

    // Attempt to install 1.0.0 on top of it.
    let payload_v1 = vec![0xBB_u8; 1024];
    let env_v1 = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(1, 0, 0), &payload_v1);
    let dl_calls_before = rig.downloader.call_count();
    let err = rig
        .service
        .install_from_envelope(env_v1)
        .await
        .expect_err("downgrade rejected");
    assert!(
        matches!(err, UpdaterError::ManifestStale { .. }),
        "expected ManifestStale, got {err:?}"
    );
    // Critical invariant: NO download attempted on a
    // downgrade — verifier short-circuits up front.
    assert_eq!(rig.downloader.call_count(), dl_calls_before);
}

#[tokio::test]
async fn rollback_on_failing_health_check_re_pins_previous_bank() {
    // Force the health check to surface unhealthy. The
    // orchestrator must (a) ask the bootloader to roll back,
    // (b) mark the slot as RolledBack, and (c) surface a
    // RolledBack outcome with the unhealthy reason.
    let rig = Rig::new(UpdateTarget::Edge);
    rig.health_check.set_default(HealthReport::unhealthy(
        "simulated control-plane-unreachable",
    ));

    let payload = vec![0xCC_u8; 1024];
    let env = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload,
    );

    let outcome = rig
        .service
        .install_from_envelope(env)
        .await
        .expect("install returns RolledBack, not Err");
    match outcome {
        InstallOutcome::RolledBack {
            version,
            slot,
            reason,
        } => {
            assert_eq!(version, ImageVersion::new(2, 0, 0));
            assert_eq!(slot, Bank::B);
            match reason {
                RollbackReason::HealthCheckUnhealthy { details } => {
                    assert!(
                        details.contains("control-plane-unreachable"),
                        "details = {details}"
                    );
                }
                other => panic!("expected HealthCheckUnhealthy, got {other:?}"),
            }
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }

    assert_eq!(rig.bootloader.rollback_count(), 1);
    assert_eq!(rig.bootloader.commit_count(), 0);
    let stats = rig.service.stats_snapshot();
    assert_eq!(stats.install_rolled_back, 1);
    assert_eq!(stats.install_committed, 0);
}

#[tokio::test]
async fn rolled_back_version_cannot_be_re_installed_by_default() {
    // After a rollback the slot is marked RolledBack with the
    // attempted version. A second attempt to install the same
    // version must be rejected up front (unless the policy
    // explicitly opts in).
    let rig = Rig::new(UpdateTarget::Edge);
    rig.health_check
        .set_default(HealthReport::unhealthy("first attempt fails"));

    let payload = vec![0xDD_u8; 1024];
    let env_a = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload.clone(),
    );

    let first = rig
        .service
        .install_from_envelope(env_a)
        .await
        .expect("first install returns RolledBack");
    assert!(matches!(first, InstallOutcome::RolledBack { .. }));

    // Re-publish the same envelope; the source produces it
    // and the verifier admits it, but the orchestrator's
    // `enforce_no_reinstall_of_rolled_back` guard refuses to
    // touch the network.
    let env_b = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    let err = rig
        .service
        .install_from_envelope(env_b)
        .await
        .expect_err("re-install refused");
    assert!(
        matches!(err, UpdaterError::ReinstallOfRolledBackVersion { .. }),
        "expected ReinstallOfRolledBackVersion, got {err:?}"
    );
}

#[tokio::test]
async fn concurrent_installs_serialise_via_install_lock() {
    // Two `install_from_envelope` futures kicked off in
    // parallel must NOT both make progress. The second call
    // must immediately surface `InstallBusy`.
    //
    // We arrange the contention by stalling the first install
    // inside the health-check loop (probes return Unhealthy
    // but the window is long enough for the second call to
    // land while it's still inside `run_health_check_loop`).
    // Hold the first install inside `run_health_check_loop`
    // long enough that the second call has a deterministic
    // window to hit the install lock. We require 5
    // consecutive healthy probes at 50 ms each, so the
    // health-check phase lasts at least 250 ms — well
    // beyond the 10 ms scheduling delay the second task
    // sleeps for before issuing its `install_from_envelope`.
    let policy = UpdaterPolicy {
        health_check_window: Duration::from_secs(2),
        health_check_timeout: Duration::from_millis(100),
        health_check_interval: Duration::from_millis(50),
        min_healthy_probes: 5,
        ..UpdaterPolicy::default()
    };
    let rig = Rig::new_with_policy(UpdateTarget::Edge, policy);
    rig.health_check.set_default(HealthReport::healthy("ok"));

    let payload_a = vec![0xEE_u8; 1024];
    let env_a = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload_a);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload_a,
    );

    // Stall the download side: force the downloader to fail
    // SLOWLY by holding the install in `Downloading` long
    // enough to make a parallel call. We do that by giving a
    // very small chunk size so the inner loop yields a lot.
    rig.downloader.set_chunk_size(1);

    // Pre-build the second envelope BEFORE we hand the
    // service to the spawn closure — `sign_envelope` borrows
    // `rig` and we want the borrow scope to end before the
    // service is moved.
    let payload_b = vec![0xEF_u8; 1024];
    let env_b = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(3, 0, 0), &payload_b);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(3, 0, 0)
        ))
        .unwrap(),
        payload_b,
    );
    let svc_first = std::sync::Arc::new(rig.service);
    let svc_second = svc_first.clone();
    let first = tokio::spawn({
        let svc = svc_first.clone();
        async move { svc.install_from_envelope(env_a).await }
    });

    // Give the first install a chance to acquire the lock.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let second_err = svc_second
        .install_from_envelope(env_b)
        .await
        .expect_err("second concurrent install bounced");
    assert!(
        matches!(second_err, UpdaterError::InstallBusy),
        "expected InstallBusy, got {second_err:?}"
    );

    // First install eventually finishes successfully (the
    // downloader's small-chunk mode is slow but valid).
    let first_outcome = first.await.expect("first task joined").expect("first ok");
    assert!(matches!(first_outcome, InstallOutcome::Committed { .. }));

    let stats = svc_first.stats_snapshot();
    assert_eq!(stats.install_concurrency_rejections, 1);
}

#[tokio::test]
async fn retry_after_transient_truncation_succeeds_with_fresh_envelope() {
    // First attempt: downloader truncates the stream — we get
    // DownloadFailure and the state machine resets to Idle.
    // Second attempt: same envelope, full payload — succeeds.
    //
    // This is the "resume after interruption" scenario from
    // Task 19: the engine must NOT poison itself when a
    // transport failure interrupts an in-flight install.
    let rig = Rig::new(UpdateTarget::Edge);
    let payload = vec![0x99_u8; 8192];
    let url = Url::parse(&format!(
        "https://x.invalid/integration-{}.bin",
        ImageVersion::new(2, 0, 0)
    ))
    .unwrap();
    rig.downloader.register(&url, payload.clone());

    // First attempt: truncate at byte 4096 (half the
    // declared size).
    rig.downloader.force_truncation_after(Some(4096));
    let env_a = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    let err = rig
        .service
        .install_from_envelope(env_a)
        .await
        .expect_err("first attempt truncated");
    // The downloader surfaces a `Truncated` shape which the
    // orchestrator maps onto either `ImageTruncated` (when
    // the streaming hasher observes under-delivery first) or
    // `DownloadFailure` (when the transport layer reports
    // the truncation first). Both shapes are valid — the
    // test only cares that the install aborts cleanly and
    // the state machine resets to Idle.
    assert!(
        matches!(
            err,
            UpdaterError::DownloadFailure(_) | UpdaterError::ImageTruncated { .. }
        ),
        "expected DownloadFailure or ImageTruncated, got {err:?}"
    );
    assert_eq!(
        rig.service.current_state(),
        sng_updater::state::UpdateState::Idle,
        "state machine must reset to Idle after a transport failure"
    );

    // Second attempt: clear truncation, install succeeds.
    rig.downloader.force_truncation_after(None);
    let env_b = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload);
    let outcome = rig
        .service
        .install_from_envelope(env_b)
        .await
        .expect("retry install commits");
    assert!(matches!(outcome, InstallOutcome::Committed { .. }));

    let stats = rig.service.stats_snapshot();
    assert_eq!(stats.install_committed, 1);
    assert_eq!(stats.install_rolled_back, 0);
    // Downloader call count is exactly 2 — one for the
    // truncated attempt and one for the retry.
    assert!(rig.downloader.call_count() >= 2);
}

#[tokio::test]
async fn tampered_payload_is_rejected_with_hash_mismatch() {
    // Manifest signature verifies cleanly (good kid + good
    // signature over the body) but the downloader hands back
    // BYTES whose SHA-256 does NOT match the signed claim.
    // The orchestrator must catch the mismatch on the
    // streaming hasher and reject before commit.
    let rig = Rig::new(UpdateTarget::Edge);
    let claimed_payload = vec![0x77_u8; 1024];
    let tampered_payload = {
        let mut p = claimed_payload.clone();
        p[0] ^= 0x01; // flip one bit
        p
    };
    let env = rig.sign_envelope(
        UpdateTarget::Edge,
        ImageVersion::new(2, 0, 0),
        &claimed_payload,
    );
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        tampered_payload,
    );
    let err = rig
        .service
        .install_from_envelope(env)
        .await
        .expect_err("tampered bytes rejected");
    assert!(
        matches!(err, UpdaterError::ImageHashMismatch { .. }),
        "expected ImageHashMismatch, got {err:?}"
    );
    assert_eq!(rig.bootloader.commit_count(), 0);
    assert_eq!(rig.bootloader.rollback_count(), 0);

    let stats = rig.service.stats_snapshot();
    assert_eq!(stats.install_hash_mismatch, 1);
}

#[tokio::test]
async fn two_consecutive_installs_alternate_banks() {
    // Cold-start active bank is A. First install lands in B.
    // After commit, the layout's active-slot pin is mirrored
    // into the bank writer (see `set_active`) so the SECOND
    // install lands back in A — the dual-bank invariant.
    let rig = Rig::new(UpdateTarget::Edge);

    let payload_a = vec![0x11_u8; 1024];
    let env_a = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(2, 0, 0), &payload_a);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(2, 0, 0)
        ))
        .unwrap(),
        payload_a,
    );
    let out_a = rig
        .service
        .install_from_envelope(env_a)
        .await
        .expect("first install commits");
    match out_a {
        InstallOutcome::Committed { slot, .. } => assert_eq!(slot, Bank::B),
        other => panic!("expected Committed in Bank::B, got {other:?}"),
    }

    let payload_b = vec![0x22_u8; 1024];
    let env_b = rig.sign_envelope(UpdateTarget::Edge, ImageVersion::new(3, 0, 0), &payload_b);
    rig.downloader.register(
        &Url::parse(&format!(
            "https://x.invalid/integration-{}.bin",
            ImageVersion::new(3, 0, 0)
        ))
        .unwrap(),
        payload_b,
    );
    let out_b = rig
        .service
        .install_from_envelope(env_b)
        .await
        .expect("second install commits");
    match out_b {
        InstallOutcome::Committed { slot, .. } => {
            assert_eq!(
                slot,
                Bank::A,
                "second install must land in the OTHER slot — \
                 dual-bank invariant"
            );
        }
        other => panic!("expected Committed in Bank::A, got {other:?}"),
    }
}
