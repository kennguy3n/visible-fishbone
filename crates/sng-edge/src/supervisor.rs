// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Binary-local supervisor wiring.
//!
//! This module composes every subsystem adapter from
//! [`crate::subsystems`] into a single
//! [`sng_core::Supervisor`]. The wiring is deliberately written
//! by hand (no DI framework, no macro indirection) so an
//! operator chasing a misbehaving subsystem can grep for the
//! adapter name in this file and see exactly which constructor
//! produced it, with which config slice, and which trait deps
//! it received.
//!
//! Boot order (top-down):
//!
//! 1. [`crate::subsystems::TelemetrySubsystem`] — must be built
//!    first so every other subsystem can clone its
//!    [`sng_telemetry::PipelineHandle`] at construction time.
//! 2. [`crate::subsystems::CommsSubsystem`] — owns the
//!    long-running mTLS connection to the control plane and the
//!    policy-bundle puller. The puller's bundle publisher is
//!    wired at this step to dispatch fresh bundles into
//!    [`crate::subsystems::PolicyEvalSubsystem`].
//! 3. [`crate::subsystems::PolicyEvalSubsystem`] — pure-function
//!    evaluator pre-loaded with an empty bootstrap bundle.
//! 4. [`crate::subsystems::DnsSubsystem`] — reputation / category
//!    / sinkhole filter chain.
//! 5. [`crate::subsystems::FwSubsystem`] — nftables ruleset
//!    holder; the rule set is empty at boot and populated by the
//!    policy bundle.
//! 6. [`crate::subsystems::IpsSubsystem`] — Suricata subprocess
//!    manager. Honours `cfg.ips.enable` at boot — operator can
//!    deploy with the manager registered but no process running.
//! 7. [`crate::subsystems::SwgSubsystem`] — Envoy subprocess
//!    manager. Same enable semantics as IPS.
//! 8. [`crate::subsystems::ZtnaSubsystem`] — synchronous ZTNA
//!    evaluator.
//! 9. [`crate::subsystems::SdwanSubsystem`] — synchronous SD-WAN
//!    steering evaluator.
//! 10. [`crate::subsystems::UpdaterSubsystem`] — self-update
//!     state machine. Last so the engine isn't tempted to
//!     swap the bank while a sister subsystem is still
//!     mid-boot.

use crate::cli::{Cli, PalBackend, UpdaterBackend};
use crate::config::EdgeConfig;
use crate::subsystems::{
    CommsSubsystem, DnsSubsystem, FwSubsystem, IpsSubsystem, PolicyEvalSubsystem, SdwanSubsystem,
    SwgSubsystem, TelemetrySubsystem, UpdaterSubsystem,
    comms::{BundlePublisher, CommsBuildError},
    telemetry::TelemetryBuildError,
    updater::UpdaterSubsystemError,
    ztna::ZtnaSubsystem,
};
use sng_comms::PolicyTrustStore;
use sng_core::envelope::Platform;
use sng_core::{BundleTarget, Supervisor, SupervisorBuilder, SupervisorReport, SupervisorRunError};
use sng_telemetry::TelemetryEvent;
use sng_ztna::ZtnaServiceConfig;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;

/// Errors raised by [`build_edge`].
#[derive(Debug, Error)]
pub enum EdgeBuildError {
    /// Operator selected an updater backend not bundled with this
    /// build. The disk-backed bank writer / EFI bootloader ship
    /// as a separate crate; see [`Cli::updater_backend`].
    #[error("unsupported updater backend `{0:?}` — disk-backed updater ships in a separate crate")]
    UnsupportedUpdaterBackend(UpdaterBackend),
    /// Operator selected a PAL backend not bundled with this
    /// build. Native PAL adapters ship as separate crates; see
    /// [`Cli::pal_backend`].
    #[error("unsupported PAL backend `{0:?}` — native PAL adapters ship in separate crates")]
    UnsupportedPalBackend(PalBackend),
    /// Comms subsystem build failed (TLS / identity / client
    /// init).
    #[error("comms subsystem build failed: {0}")]
    Comms(#[from] CommsBuildError),
    /// Telemetry subsystem build failed (pipeline identity
    /// contract).
    #[error("telemetry subsystem build failed: {0}")]
    Telemetry(#[from] TelemetryBuildError),
    /// Updater subsystem build failed.
    #[error("updater subsystem build failed: {0}")]
    Updater(#[from] UpdaterSubsystemError),
    /// Initial policy bundle was rejected by the engine. The
    /// edge appliance boots with an empty bootstrap bundle that
    /// the control plane is expected to replace on the first
    /// poll; this error fires only when even the empty
    /// bootstrap fails validation, which would indicate a build
    /// regression rather than an operator config issue.
    #[error("bootstrap policy bundle rejected: {0}")]
    BootstrapBundle(#[from] sng_policy_eval::PolicyEvalError),
    /// Supervisor run task itself returned an error (e.g. one of
    /// the subsystems' `start` calls failed during boot).
    #[error("supervisor failed during boot: {0}")]
    SupervisorRun(#[from] SupervisorRunError),
}

/// Composed edge appliance: the supervisor plus handles to every
/// adapter so the integration tests can drive shutdown, scrape
/// stats, and assert on per-subsystem post-drain state without
/// going through the binary's `ExitCode`.
///
/// The fields are pub so test code can reach into them; the
/// binary path only touches `supervisor` via [`run_edge`].
pub struct BuiltEdge {
    /// The fully-wired supervisor. Call `supervisor.run()` to
    /// drive the appliance to completion.
    pub supervisor: Supervisor,
    /// Telemetry adapter. Tests use this to assert pipeline
    /// drain count + egress flush count.
    pub telemetry: Arc<TelemetrySubsystem>,
    /// Comms adapter. Tests assert pulls / connect / publish
    /// counters here.
    pub comms: Arc<CommsSubsystem>,
    /// Policy-eval adapter. Tests assert that swap_bundle was
    /// called with the test-fixture body and that the current
    /// bundle matches.
    pub policy_eval: Arc<PolicyEvalSubsystem>,
    /// DNS adapter. Tests assert reputation reload counters.
    pub dns: Arc<DnsSubsystem>,
    /// Firewall adapter. Tests assert ruleset apply counters.
    pub fw: Arc<FwSubsystem>,
    /// IPS adapter.
    pub ips: Arc<IpsSubsystem>,
    /// SWG adapter.
    pub swg: Arc<SwgSubsystem>,
    /// ZTNA adapter.
    pub ztna: Arc<ZtnaSubsystem>,
    /// SD-WAN adapter.
    pub sdwan: Arc<SdwanSubsystem>,
    /// Updater adapter.
    pub updater: Arc<UpdaterSubsystem>,
}

impl std::fmt::Debug for BuiltEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltEdge")
            .field("supervisor", &"Supervisor { .. }")
            .field("subsystems", &10_usize)
            .finish_non_exhaustive()
    }
}

/// Deny-all bootstrap bundle body the policy engine boots with
/// before the comms puller delivers a real bundle. Until the
/// control plane responds, every flow evaluation falls through
/// to the bundle's default verb (`Verb::Deny`) — the
/// deliberate fail-closed posture for a freshly-imaged
/// appliance.
///
/// Encoded as a raw (unsigned) payload — the engine accepts
/// this form when constructed via `from_body` with an empty
/// trust store at boot, which matches the deliberate
/// bootstrap-vs-steady-state distinction in
/// [`sng_policy_eval::deny_all_skeleton_body`]'s docs.
fn bootstrap_bundle_body() -> Vec<u8> {
    sng_policy_eval::deny_all_skeleton_body(BundleTarget::Edge)
}

/// Construct every subsystem adapter, register them with a
/// fresh [`Supervisor`], and return the composed
/// [`BuiltEdge`] for the caller to drive.
///
/// This function does *not* call `supervisor.run()` — the
/// caller (either [`run_edge`] or an integration test) owns the
/// run loop. Splitting build vs run lets tests inspect the
/// adapter handles before the supervisor's spawn pass starts.
///
/// # Errors
///
/// Returns [`EdgeBuildError`] for any per-subsystem build
/// failure or for an unsupported `--updater-backend` /
/// `--pal-backend` selection.
pub fn build_edge(cli: &Cli, cfg: &EdgeConfig) -> Result<BuiltEdge, EdgeBuildError> {
    // Refuse unsupported backends up front so the operator gets
    // a clear error before any subsystem starts allocating disk
    // or sockets. The deliberate scope cuts are documented on
    // the CLI flags themselves.
    if !matches!(cli.updater_backend, UpdaterBackend::InMemory) {
        return Err(EdgeBuildError::UnsupportedUpdaterBackend(
            cli.updater_backend,
        ));
    }
    if !matches!(cli.pal_backend, PalBackend::InMemory) {
        return Err(EdgeBuildError::UnsupportedPalBackend(cli.pal_backend));
    }

    let platform = host_platform();

    // 1. Policy evaluator. Boots with an empty bootstrap
    //    bundle; the comms puller replaces it on first poll.
    let bootstrap_body = bootstrap_bundle_body();
    let policy_eval = Arc::new(PolicyEvalSubsystem::new(&bootstrap_body)?);

    // 2. Comms. Builds the long-lived ControlPlaneClient
    //    internally from the operator-supplied TLS material;
    //    the telemetry subsystem will reuse the same client
    //    via `comms.client()` so cert / trust store / endpoint
    //    are configured in exactly one place. Wire the bundle
    //    publisher to dispatch fresh bundles into the policy
    //    evaluator. Future subsystems that need their own
    //    bundle slice (compiled IPS rules, Envoy config) will
    //    subscribe to a fan-out built on top of this single
    //    publisher; for now the policy_eval subsystem is the
    //    only consumer.
    let publisher = make_bundle_publisher(Arc::clone(&policy_eval));
    let trust_store = Arc::new(PolicyTrustStore::new());
    let comms = Arc::new(CommsSubsystem::new(
        &cfg.comms,
        &cfg.identity,
        &cfg.policy,
        BundleTarget::Edge,
        trust_store,
        publisher,
    )?);

    // 3. Telemetry — its PipelineHandle is shared with every
    //    other producer subsystem. Reuses the comms client so
    //    bundle pulls and event uploads share one TLS config.
    let telemetry = Arc::new(TelemetrySubsystem::new(
        &cfg.telemetry,
        &cfg.identity,
        platform,
        Arc::clone(comms.client()),
    )?);

    // 4. DNS. The telemetry sender is the producer-facing
    //    mpsc::Sender half of the telemetry pipeline.
    let telemetry_tx = pipeline_handle_to_telemetry_sender(&telemetry);
    let dns = Arc::new(DnsSubsystem::new(&cfg.dns, telemetry_tx.clone()));

    // 5. Firewall.
    let fw = Arc::new(FwSubsystem::new(&cfg.fw));

    // 6. IPS.
    let ips = Arc::new(IpsSubsystem::new(&cfg.ips));

    // 7. SWG.
    let swg = Arc::new(SwgSubsystem::new(&cfg.swg));

    // 8. ZTNA. The edge config's `max_inflight` maps onto
    //    ZtnaServiceConfig's `max_sessions` — both name the
    //    producer-enforced ceiling on concurrent ZTNA
    //    evaluations the brain has advertised it can handle
    //    (the brain is stateless per-request; load shedding
    //    happens at this producer layer).
    let ztna_cfg = ZtnaServiceConfig {
        max_sessions: cfg.ztna.max_inflight,
    };
    let ztna = Arc::new(ZtnaSubsystem::new(ztna_cfg, telemetry_tx.clone()));

    // 9. SD-WAN.
    let sdwan = Arc::new(SdwanSubsystem::new(&cfg.sdwan, telemetry_tx));

    // 10. Updater.
    let updater = Arc::new(UpdaterSubsystem::default_in_memory(&cfg.updater)?);

    // Assemble the supervisor. Boot order matters: telemetry +
    // comms first so producer subsystems have a live channel +
    // bundle source by the time they spawn, then everything
    // else.
    let mut builder = SupervisorBuilder::default()
        .with_health_interval(cfg.supervisor.health_interval)
        .with_health_probe_budget(cfg.supervisor.health_probe_budget);
    builder = builder.with_subsystem(Arc::clone(&telemetry));
    builder = builder.with_subsystem(Arc::clone(&comms));
    builder = builder.with_subsystem(Arc::clone(&policy_eval));
    builder = builder.with_subsystem(Arc::clone(&dns));
    builder = builder.with_subsystem(Arc::clone(&fw));
    builder = builder.with_subsystem(Arc::clone(&ips));
    builder = builder.with_subsystem(Arc::clone(&swg));
    builder = builder.with_subsystem(Arc::clone(&ztna));
    builder = builder.with_subsystem(Arc::clone(&sdwan));
    builder = builder.with_subsystem(Arc::clone(&updater));

    let supervisor = builder.build();

    Ok(BuiltEdge {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        dns,
        fw,
        ips,
        swg,
        ztna,
        sdwan,
        updater,
    })
}

/// Build the edge appliance then drive its supervisor to
/// completion. The binary's `main.rs` calls this; integration
/// tests typically call [`build_edge`] directly so they can
/// scrape adapter handles before drain.
///
/// # Errors
///
/// Returns [`EdgeBuildError`] for any per-subsystem build
/// failure, unsupported backend selection, or supervisor-level
/// boot failure. Run-time per-subsystem failures are reported
/// through the returned [`SupervisorReport`]'s `drain_results`.
pub async fn run_edge(cli: Cli, cfg: EdgeConfig) -> Result<SupervisorReport, EdgeBuildError> {
    let built = build_edge(&cli, &cfg)?;
    tracing::info!(
        target: "sng_edge::supervisor",
        updater_backend = ?cli.updater_backend,
        pal_backend = ?cli.pal_backend,
        "sng-edge composed; entering supervisor run loop"
    );
    let report = built.supervisor.run().await?;
    Ok(report)
}

/// Build the host [`Platform`] descriptor. Stamped onto every
/// telemetry envelope so the control plane can join per-OS
/// dashboards without a separate enrollment record. The
/// envelope schema only enumerates Windows / macOS / Linux /
/// iOS / Android — for an unrecognised host we fall back to
/// Linux as the most likely server-OS shape (the edge
/// appliance ships as a Linux VM image; the macOS / Windows
/// arms exist so the same binary can run for a developer on
/// their laptop).
fn host_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        // Edge appliance is Linux-by-default in production;
        // any other host is treated as Linux on the wire so
        // dashboards still join on a known facet.
        Platform::Linux
    }
}

/// Bridge the telemetry pipeline's [`sng_telemetry::PipelineHandle`]
/// onto the [`mpsc::Sender<TelemetryEvent>`] surface the DNS /
/// ZTNA / SD-WAN producer subsystems expect.
///
/// The two halves intentionally do not share a single channel
/// type: producer subsystems were written against the
/// `mpsc::Sender<TelemetryEvent>` surface long before the
/// pipeline existed (the policy puller subsystems all use a
/// raw tokio `mpsc` channel), and the pipeline owns its own
/// channel for dedup / redact / enrich. The shim spawned here
/// reads from the producer channel and submits into the
/// pipeline handle, so each producer keeps its existing
/// signature while the events still go through the canonical
/// pipeline.
fn pipeline_handle_to_telemetry_sender(
    telemetry: &Arc<TelemetrySubsystem>,
) -> mpsc::Sender<TelemetryEvent> {
    let (tx, mut rx) = mpsc::channel::<TelemetryEvent>(1024);
    let handle = telemetry.pipeline_handle();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            // Submit through the canonical PipelineHandle.
            // We use the non-blocking `try_submit` form so a
            // saturated pipeline never wedges a producer
            // subsystem; the dropped event is logged at
            // debug-level and is accounted for in the
            // pipeline's own stats counters when the channel
            // is closed.
            if let Err(err) = handle.try_submit(event) {
                tracing::debug!(
                    target: "sng_edge::telemetry_bridge",
                    "pipeline submit rejected event: {err:?}"
                );
            }
        }
        // Producer side dropped: nothing more to forward.
    });
    tx
}

/// Build the bundle publisher closure that the comms puller
/// invokes on every fresh bundle. For the Edge target we
/// dispatch into the policy evaluator. Subsystems whose
/// compiled artifacts are derived from the policy bundle (IPS
/// rules, nftables ruleset, Envoy config, SD-WAN paths, ZTNA
/// catalog) will subscribe to a fan-out built on top of the
/// policy evaluator's swap notification in a follow-up PR;
/// today they boot with empty providers and the policy
/// evaluator is the single consumer.
fn make_bundle_publisher(policy_eval: Arc<PolicyEvalSubsystem>) -> BundlePublisher {
    Arc::new(move |target, body| {
        match target {
            BundleTarget::Edge => {
                policy_eval
                    .swap_bundle(&body, false)
                    .map_err(|e| format!("policy_eval swap rejected bundle: {e}"))?;
                tracing::info!(
                    target: "sng_edge::bundle_publisher",
                    body_bytes = body.len(),
                    "policy_eval bundle swap accepted"
                );
                Ok(())
            }
            other => {
                // Edge appliances should never receive a non-
                // Edge bundle through this publisher, but the
                // puller's target is configured separately, so
                // surface the mismatch as an error rather than
                // silently swapping the wrong target.
                Err(format!(
                    "edge bundle publisher rejected non-Edge bundle target {other:?}"
                ))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_platform_returns_known_variant() {
        // Only asserting the function returns a value — the
        // exact variant depends on the build host, which CI
        // varies by job matrix.
        let _ = host_platform();
    }
}
