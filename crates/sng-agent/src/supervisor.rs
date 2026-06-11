// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Binary-local supervisor wiring for `sng-agent`.
//!
//! Composes every endpoint-tier subsystem adapter from
//! [`crate::subsystems`] into a single
//! [`sng_core::Supervisor`]. Mirrors the structure of
//! [`sng_edge::supervisor`] but with the strict subset of
//! subsystems an endpoint agent runs (no DNS / FW / IPS /
//! SWG / SD-WAN / updater) plus the three PAL adapters
//! (`pal_capture` / `pal_posture` / `pal_tunnel`).
//!
//! Boot order (top-down):
//!
//! 1. [`crate::subsystems::TelemetrySubsystem`] — must be
//!    built first so every producer subsystem can clone its
//!    [`sng_telemetry::PipelineHandle`] at construction time.
//! 2. [`crate::subsystems::CommsSubsystem`] — owns the
//!    long-running mTLS connection to the control plane and
//!    the policy-bundle puller. The puller's bundle
//!    publisher is wired at this step to dispatch fresh
//!    bundles into [`crate::subsystems::PolicyEvalSubsystem`].
//! 3. [`crate::subsystems::PolicyEvalSubsystem`] — pure-
//!    function evaluator pre-loaded with the deny-all
//!    bootstrap bundle.
//! 4. [`crate::subsystems::ZtnaSubsystem`] — synchronous
//!    ZTNA evaluator.
//! 5. [`crate::subsystems::PalCaptureSubsystem`] — traffic-
//!    capture polling loop. Feeds observed flows through the
//!    policy engine + telemetry pipeline.
//! 6. [`crate::subsystems::PalPostureSubsystem`] — posture-
//!    snapshot cadence. Fans snapshots onto the telemetry
//!    pipeline and a `watch::Receiver` that other subsystems
//!    (today: none; tomorrow: the ZTNA gate's
//!    posture-staleness check) can subscribe to.
//! 7. [`crate::subsystems::PalTunnelSubsystem`] — tunnel
//!    reconciler. Compares the desired tunnel set (driven by
//!    the control plane) against the active set on the PAL
//!    backend and converges via `start` / `stop` calls.

use crate::cli::{Cli, PalBackend};
use crate::config::AgentConfig;
use crate::subsystems::{
    CommsSubsystem, DlpSubsystem, PalCaptureSubsystem, PalPostureSubsystem, PalTunnelSubsystem,
    PolicyEvalSubsystem, TelemetrySubsystem, TracingDlpSink, ZtnaSubsystem,
    comms::{BundlePublisher, CommsBuildError},
    telemetry::TelemetryBuildError,
};
use sng_comms::PolicyTrustStore;
use sng_core::envelope::Platform;
use sng_core::{
    BundleTarget, ShutdownSignal, Supervisor, SupervisorBuilder, SupervisorReport,
    SupervisorRunError,
};
use sng_dlp::{ChannelInterceptor, DlpEngine, DlpPolicy};
use sng_pal::posture::{PostureCollector, UnknownPostureCollector};
use sng_pal::traffic::{InMemoryCapture, TrafficCapture};
use sng_pal::tunnel::{InMemoryTunnelProvider, TunnelConfig, TunnelProvider};
use sng_telemetry::TelemetryEvent;
use sng_ztna::ZtnaServiceConfig;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

/// Errors raised by [`build_agent`].
#[derive(Debug, Error)]
pub enum AgentBuildError {
    /// Operator selected a PAL backend not bundled with this
    /// build. Native PAL adapters ship as separate per-OS
    /// crates and not part of this PR; requesting `native`
    /// here fails fast so the operator knows to upgrade
    /// their build instead of silently running on the test
    /// backend. The selector that failed is included so the
    /// operator can immediately see whether it was the
    /// unified [`Cli::pal_backend`] or a per-sub-adapter
    /// override (`--capture-backend` / `--posture-backend`
    /// / `--tunnel-backend`).
    #[error(
        "unsupported PAL backend `{backend:?}` selected for `{selector}` — \
         native PAL adapters ship in separate crates"
    )]
    UnsupportedPalBackend {
        /// Which PAL adapter slot the operator tried to
        /// pin to `native`.
        selector: &'static str,
        /// The backend variant requested.
        backend: PalBackend,
    },
    /// Comms subsystem build failed (TLS / identity / client
    /// init).
    #[error("comms subsystem build failed: {0}")]
    Comms(#[from] CommsBuildError),
    /// Telemetry subsystem build failed (pipeline identity
    /// contract).
    #[error("telemetry subsystem build failed: {0}")]
    Telemetry(#[from] TelemetryBuildError),
    /// Initial policy bundle was rejected by the engine. The
    /// endpoint agent boots with the deny-all bootstrap
    /// bundle that the control plane is expected to replace
    /// on the first poll; this error fires only when even
    /// the deny-all bootstrap fails validation, which would
    /// indicate a build regression rather than an operator
    /// config issue.
    #[error("bootstrap policy bundle rejected: {0}")]
    BootstrapBundle(#[from] sng_policy_eval::PolicyEvalError),
    /// Supervisor run task itself returned an error (e.g. one
    /// of the subsystems' `start` calls failed during boot).
    #[error("supervisor failed during boot: {0}")]
    SupervisorRun(#[from] SupervisorRunError),
    /// The endpoint DLP engine rejected its bootstrap policy. The
    /// agent boots the DLP engine with the empty (fail-open)
    /// [`DlpPolicy::default`], so this fires only on a build
    /// regression that makes the default policy invalid, not on
    /// any operator config.
    #[error("endpoint DLP engine init failed: {0}")]
    Dlp(#[from] sng_dlp::DlpError),
}

/// Composed endpoint agent: the supervisor plus handles to
/// every adapter so the integration tests can drive
/// shutdown, scrape stats, and assert on per-subsystem
/// post-drain state without going through the binary's
/// `ExitCode`.
pub struct BuiltAgent {
    /// The fully-wired supervisor. Call `supervisor.run()`
    /// to drive the agent to completion.
    pub supervisor: Supervisor,
    /// Telemetry adapter.
    pub telemetry: Arc<TelemetrySubsystem>,
    /// Comms adapter.
    pub comms: Arc<CommsSubsystem>,
    /// Policy-eval adapter.
    pub policy_eval: Arc<PolicyEvalSubsystem>,
    /// ZTNA adapter.
    pub ztna: Arc<ZtnaSubsystem>,
    /// PAL traffic-capture adapter.
    pub pal_capture: Arc<PalCaptureSubsystem>,
    /// PAL posture-collector adapter.
    pub pal_posture: Arc<PalPostureSubsystem>,
    /// PAL tunnel-provider adapter.
    pub pal_tunnel: Arc<PalTunnelSubsystem>,
    /// Endpoint DLP adapter. `None` when `[dlp] enabled = false`
    /// (the default) — the subsystem is not registered and the
    /// agent pays no DLP monitoring cost.
    pub dlp: Option<Arc<DlpSubsystem>>,
    /// Sender half of the desired-tunnel watch channel.
    /// Held so integration tests can push a desired-set
    /// update without going through the comms subsystem.
    /// In production this sender is owned by the future
    /// "control-plane tunnel directive" consumer; for now
    /// the binary boots with an empty desired set and the
    /// sender is kept on the BuiltAgent so the channel is
    /// not dropped.
    pub desired_tunnels_tx: watch::Sender<Vec<TunnelConfig>>,
}

impl std::fmt::Debug for BuiltAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltAgent")
            .field("supervisor", &"Supervisor { .. }")
            .field("subsystems", &(7_usize + usize::from(self.dlp.is_some())))
            .finish_non_exhaustive()
    }
}

/// Deny-all bootstrap bundle body the policy engine boots
/// with before the comms puller delivers a real bundle.
/// Until the control plane responds, every flow evaluation
/// falls through to the bundle's default verb (`Verb::Deny`)
/// — the deliberate fail-closed posture for a freshly-
/// enrolled endpoint.
fn bootstrap_bundle_body() -> Vec<u8> {
    sng_policy_eval::deny_all_skeleton_body(BundleTarget::Endpoint)
}

/// Construct every subsystem adapter, register them with a
/// fresh [`Supervisor`], and return the composed
/// [`BuiltAgent`] for the caller to drive.
///
/// This function does *not* call `supervisor.run()` — the
/// caller (either [`run_agent`] or an integration test)
/// owns the run loop. Splitting build vs run lets tests
/// inspect the adapter handles before the supervisor's
/// spawn pass starts.
///
/// # Runtime requirement
///
/// Although `build_agent` itself is a sync function, it
/// spawns the telemetry-bridge task via [`tokio::spawn`].
/// The caller MUST therefore be executing inside a tokio
/// runtime — i.e. it must be called from an `async fn` on
/// a tokio runtime, from inside a `tokio::main`-decorated
/// function, or from inside a [`tokio::runtime::Runtime`]
/// `block_on` / `enter` scope. The two real callers are
/// [`run_agent`] (an `async fn` invoked from
/// `#[tokio::main]`) and the integration tests (each
/// decorated with `#[tokio::test]`); both satisfy the
/// constraint. The signature is deliberately sync because
/// every per-subsystem build step is itself sync — making
/// `build_agent` async would force every test harness
/// (and the binary's `main`) to thread an unnecessary
/// `.await` through the call site for a single internal
/// `tokio::spawn`.
///
/// # Errors
///
/// Returns [`AgentBuildError`] for any per-subsystem build
/// failure or for an unsupported `--pal-backend` /
/// `--capture-backend` / `--posture-backend` /
/// `--tunnel-backend` selection.
///
/// # Panics
///
/// Panics if called from outside a tokio runtime context,
/// because the telemetry-bridge `tokio::spawn` requires
/// one.
pub fn build_agent(cli: &Cli, cfg: &AgentConfig) -> Result<BuiltAgent, AgentBuildError> {
    // Refuse unsupported backends up front so the operator
    // gets a clear error before any subsystem starts
    // allocating disk or sockets.
    let (capture_backend, posture_backend, tunnel_backend) = resolve_pal_backends(cli)?;

    let platform = host_platform();

    // 1. Policy evaluator. Boots with the deny-all
    //    bootstrap bundle; the comms puller replaces it on
    //    first poll.
    let bootstrap_body = bootstrap_bundle_body();
    let policy_eval = Arc::new(PolicyEvalSubsystem::new(&bootstrap_body)?);

    // Endpoint DLP engine. Built here — ahead of the bundle
    // publisher — so two consumers can share one live engine: the
    // publisher hot-swaps its policy on each fresh bundle, and the
    // DLP subsystem (built later) runs channel inspection against the
    // same instance. `None` when `[dlp] enabled = false`, so a
    // deployment without endpoint DLP pays no cost. `with_limit` over
    // the default (empty) policy is infallible today; propagate the
    // error anyway so a future fallible default surfaces as a clean
    // boot error rather than a panic.
    let dlp_engine: Option<Arc<DlpEngine>> = if cfg.dlp.enabled {
        Some(Arc::new(DlpEngine::with_limit(
            DlpPolicy::default(),
            cfg.dlp.max_file_bytes,
        )?))
    } else {
        None
    };

    // 2. Comms. Builds the long-lived ControlPlaneClient
    //    internally from the operator-supplied TLS
    //    material; the telemetry subsystem will reuse the
    //    same client via `comms.client()` so cert / trust
    //    store / endpoint are configured in exactly one
    //    place. Wire the bundle publisher to dispatch fresh
    //    bundles into the policy evaluator.
    let publisher = make_bundle_publisher(Arc::clone(&policy_eval), dlp_engine.clone());
    let trust_store = Arc::new(PolicyTrustStore::new());
    let comms = Arc::new(CommsSubsystem::new(
        &cfg.comms,
        &cfg.identity,
        &cfg.policy,
        BundleTarget::Endpoint,
        trust_store,
        publisher,
    )?);

    // 3. Telemetry — its PipelineHandle is shared with
    //    every other producer subsystem. Reuses the comms
    //    client so bundle pulls and event uploads share one
    //    TLS config.
    let telemetry = Arc::new(TelemetrySubsystem::new(
        &cfg.telemetry,
        &cfg.identity,
        platform,
        Arc::clone(comms.client()),
    )?);

    // Create the supervisor builder up front so we can pull
    // a `ShutdownSignal` clone for non-subsystem helper tasks
    // (the telemetry pipeline-handle bridge below) BEFORE
    // the supervisor itself is built. The bridge owns a
    // `PipelineHandle` clone and would otherwise have no way
    // to observe drain; it would pin the pipeline's
    // producer-side mpsc sender for the entire process
    // lifetime and deadlock the telemetry subsystem's drain.
    // The builder lazily creates the trigger/signal pair in
    // its `Default` impl so this is always safe.
    let mut builder = SupervisorBuilder::default()
        .with_health_interval(cfg.supervisor.health_interval)
        .with_health_probe_budget(cfg.supervisor.health_probe_budget);
    let shutdown_signal_for_bridges = builder.shutdown_signal();

    // 4. ZTNA. The agent config's `max_inflight` maps onto
    //    ZtnaServiceConfig's `max_sessions` — both name the
    //    producer-enforced ceiling on concurrent ZTNA
    //    evaluations the brain has advertised it can
    //    handle.
    let telemetry_tx = pipeline_handle_to_telemetry_sender(&telemetry, shutdown_signal_for_bridges);
    let ztna_cfg = ZtnaServiceConfig {
        max_sessions: cfg.ztna.max_inflight,
    };
    let ztna = Arc::new(ZtnaSubsystem::new(ztna_cfg, telemetry_tx));

    // 5. PAL traffic capture.
    let capture: Arc<dyn TrafficCapture> = match capture_backend {
        PalBackend::InMemory => Arc::new(InMemoryCapture::new()),
        // Already rejected above; the match is exhaustive
        // so the compiler doesn't force a `_ => unreachable!()`
        // arm that would hide a future variant.
        PalBackend::Native => {
            return Err(AgentBuildError::UnsupportedPalBackend {
                selector: "capture",
                backend: capture_backend,
            });
        }
    };
    let pal_capture = Arc::new(PalCaptureSubsystem::new(
        &cfg.capture,
        capture,
        Arc::clone(policy_eval.engine()),
        telemetry.pipeline_handle(),
    ));

    // 6. PAL posture collector.
    let collector: Arc<dyn PostureCollector> = match posture_backend {
        PalBackend::InMemory => Arc::new(UnknownPostureCollector),
        PalBackend::Native => {
            return Err(AgentBuildError::UnsupportedPalBackend {
                selector: "posture",
                backend: posture_backend,
            });
        }
    };
    let pal_posture = Arc::new(PalPostureSubsystem::new(
        &cfg.posture,
        collector,
        platform,
        cfg.identity.device_id.to_string(),
        telemetry.pipeline_handle(),
    ));

    // 7. PAL tunnel provider.
    let provider: Arc<dyn TunnelProvider> = match tunnel_backend {
        PalBackend::InMemory => Arc::new(InMemoryTunnelProvider::new()),
        PalBackend::Native => {
            return Err(AgentBuildError::UnsupportedPalBackend {
                selector: "tunnel",
                backend: tunnel_backend,
            });
        }
    };
    // Desired tunnel set is currently empty at boot — the
    // control plane delivers the actual set in a follow-up
    // PR (Tasks 25-27, end-to-end integration). The sender
    // is kept on BuiltAgent so the watch channel is not
    // dropped while the subsystem is still subscribed.
    let (desired_tunnels_tx, desired_tunnels_rx) = watch::channel(Vec::new());
    let pal_tunnel = Arc::new(PalTunnelSubsystem::new(
        &cfg.tunnel,
        provider,
        desired_tunnels_rx,
    ));

    // 8. Endpoint DLP — opt-in; `None` unless `[dlp] enabled`. Shares
    //    the engine built above so the bundle publisher and the
    //    channel interceptors operate on the same live policy.
    let dlp = match &dlp_engine {
        Some(engine) => Some(build_dlp_subsystem(
            &cfg.dlp,
            telemetry.pipeline_handle(),
            Arc::clone(engine),
        )?),
        None => None,
    };

    // Register subsystems onto the builder we created above.
    // Boot order matters: telemetry + comms first so producer
    // subsystems have a live channel + bundle source by the
    // time they spawn, then everything else.
    builder = builder.with_subsystem(Arc::clone(&telemetry));
    builder = builder.with_subsystem(Arc::clone(&comms));
    builder = builder.with_subsystem(Arc::clone(&policy_eval));
    builder = builder.with_subsystem(Arc::clone(&ztna));
    builder = builder.with_subsystem(Arc::clone(&pal_capture));
    builder = builder.with_subsystem(Arc::clone(&pal_posture));
    builder = builder.with_subsystem(Arc::clone(&pal_tunnel));
    if let Some(dlp) = &dlp {
        builder = builder.with_subsystem(Arc::clone(dlp));
    }

    let supervisor = builder.build();

    Ok(BuiltAgent {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        ztna,
        pal_capture,
        pal_posture,
        pal_tunnel,
        dlp,
        desired_tunnels_tx,
    })
}

/// Construct the endpoint DLP subsystem from its config section.
///
/// The engine boots with an empty [`DlpPolicy`] (fail-open: no
/// rule matches, every event is `Allow`) so an endpoint with no
/// authored DLP policy never produces a false positive; the
/// control plane installs the real policy at runtime.
///
/// The interceptor set is built from the portable, dependency-free
/// [`SensitiveDirWatcher`] over the configured `watch_dirs`, tagged
/// as [`DlpChannel::FileWrite`]. It is warm-started so the files
/// already present when the agent boots are recorded as the
/// watermark rather than re-reported as fresh writes. The
/// edge-triggered native backends (USN journal / FSEvents /
/// inotify) and the clipboard / USB / print interceptors documented
/// in `sng_pal::dlp` attach to the same set behind their per-OS
/// `cfg` gates without changing this wiring. When `watch_dirs` is
/// empty the set is empty: the subsystem still registers (so health
/// reports it) but observes nothing.
///
/// The `engine` is built by [`build_agent`] and shared with the
/// bundle publisher, which hot-swaps the live policy on every fresh
/// endpoint bundle via [`DlpEngine::install`] +
/// [`DlpEngine::set_ai_app_policy`]. The caller only invokes this when
/// `[dlp] enabled` is set, so a deployment that hasn't authored
/// endpoint DLP rules pays no monitoring cost.
fn build_dlp_subsystem(
    cfg: &crate::config::DlpConfig,
    telemetry: sng_telemetry::PipelineHandle,
    engine: Arc<DlpEngine>,
) -> Result<Arc<DlpSubsystem>, AgentBuildError> {
    let mut interceptors: Vec<Arc<dyn ChannelInterceptor>> = Vec::new();
    // File-write channel: native edge-triggered watcher over the
    // configured sensitive directories (each per-OS backend falls back
    // to the portable poll watcher when its native hook is unavailable).
    // An empty `watch_dirs` leaves the file-write channel idle.
    if !cfg.watch_dirs.is_empty() {
        interceptors.push(file_write_interceptor(cfg));
    }
    // Clipboard / USB / print: per-OS native backends, each gated by its
    // own config flag so an operator can pare the channel set down.
    push_native_interceptors(cfg, &mut interceptors);

    Ok(Arc::new(DlpSubsystem::new(
        engine,
        interceptors,
        Arc::new(TracingDlpSink),
        telemetry,
        cfg.idle_sleep,
    )))
}

/// Build the file-write interceptor for the host OS. On the three
/// desktop platforms this is the native edge-triggered watcher
/// (inotify / FSEvents / `ReadDirectoryChangesW`), each of which
/// transparently falls back to the portable [`SensitiveDirWatcher`]
/// when its kernel hook cannot be initialised. On any other target the
/// portable watcher is used directly.
fn file_write_interceptor(cfg: &crate::config::DlpConfig) -> Arc<dyn ChannelInterceptor> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let opts = sng_pal::dlp::FileWatchOptions {
        max_file_bytes: cfg.max_file_bytes,
        poll_interval: cfg.poll_interval,
    };
    #[cfg(target_os = "linux")]
    {
        Arc::new(sng_pal::dlp::LinuxFileWriteMonitor::with_options(
            cfg.watch_dirs.clone(),
            opts,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(sng_pal::dlp::MacFileWriteMonitor::with_options(
            cfg.watch_dirs.clone(),
            opts,
        ))
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(sng_pal::dlp::WindowsFileWriteMonitor::with_options(
            cfg.watch_dirs.clone(),
            opts,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        use sng_dlp::DlpChannel;
        use sng_pal::dlp::SensitiveDirWatcher;
        Arc::new(
            SensitiveDirWatcher::new(DlpChannel::FileWrite, cfg.watch_dirs.clone())
                .with_max_file_bytes(cfg.max_file_bytes)
                .with_poll_interval(cfg.poll_interval)
                .warm_started(),
        )
    }
}

/// Register the clipboard / USB / print interceptors for the host OS.
/// Each channel is gated by its own [`crate::config::DlpConfig`] flag.
/// On a non-desktop target none of the native backends exist, so the
/// set is left unchanged (the file-write poll watcher still runs).
#[cfg(target_os = "linux")]
fn push_native_interceptors(
    cfg: &crate::config::DlpConfig,
    interceptors: &mut Vec<Arc<dyn ChannelInterceptor>>,
) {
    use sng_pal::dlp::{
        FileWatchOptions, LinuxClipboardMonitor, LinuxPrintMonitor, LinuxRemovableStorageMonitor,
        LinuxUsbTransferMonitor,
    };
    let opts = FileWatchOptions {
        max_file_bytes: cfg.max_file_bytes,
        poll_interval: cfg.poll_interval,
    };
    if cfg.clipboard {
        interceptors.push(Arc::new(LinuxClipboardMonitor::new()));
    }
    if cfg.usb {
        interceptors.push(Arc::new(LinuxUsbTransferMonitor::new(
            LinuxRemovableStorageMonitor::default(),
            opts,
        )));
    }
    if cfg.print {
        interceptors.push(Arc::new(LinuxPrintMonitor::new(
            cfg.print_spool_dir.clone(),
            opts,
        )));
    }
}

#[cfg(target_os = "macos")]
fn push_native_interceptors(
    cfg: &crate::config::DlpConfig,
    interceptors: &mut Vec<Arc<dyn ChannelInterceptor>>,
) {
    use sng_pal::dlp::{
        FileWatchOptions, MacClipboardMonitor, MacPrintMonitor, MacUsbTransferMonitor,
    };
    let opts = FileWatchOptions {
        max_file_bytes: cfg.max_file_bytes,
        poll_interval: cfg.poll_interval,
    };
    if cfg.clipboard {
        interceptors.push(Arc::new(MacClipboardMonitor::new()));
    }
    if cfg.usb {
        interceptors.push(Arc::new(MacUsbTransferMonitor::new(opts)));
    }
    if cfg.print {
        interceptors.push(Arc::new(MacPrintMonitor::new(
            cfg.print_spool_dir.clone(),
            opts,
        )));
    }
}

#[cfg(target_os = "windows")]
fn push_native_interceptors(
    cfg: &crate::config::DlpConfig,
    interceptors: &mut Vec<Arc<dyn ChannelInterceptor>>,
) {
    use sng_pal::dlp::{
        FileWatchOptions, WindowsClipboardMonitor, WindowsPrintMonitor, WindowsUsbTransferMonitor,
    };
    let opts = FileWatchOptions {
        max_file_bytes: cfg.max_file_bytes,
        poll_interval: cfg.poll_interval,
    };
    if cfg.clipboard {
        interceptors.push(Arc::new(WindowsClipboardMonitor::new()));
    }
    if cfg.usb {
        interceptors.push(Arc::new(WindowsUsbTransferMonitor::new(opts)));
    }
    if cfg.print {
        interceptors.push(Arc::new(WindowsPrintMonitor::new(
            cfg.print_spool_dir.clone(),
            opts,
        )));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn push_native_interceptors(
    _cfg: &crate::config::DlpConfig,
    _interceptors: &mut Vec<Arc<dyn ChannelInterceptor>>,
) {
}

/// Build the agent then drive its supervisor to completion.
/// The binary's `main.rs` calls this; integration tests
/// typically call [`build_agent`] directly so they can
/// scrape adapter handles before drain.
///
/// # Errors
///
/// Returns [`AgentBuildError`] for any per-subsystem build
/// failure, unsupported backend selection, or supervisor-
/// level boot failure. Run-time per-subsystem failures are
/// reported through the returned [`SupervisorReport`]'s
/// `drain_results`.
pub async fn run_agent(cli: Cli, cfg: AgentConfig) -> Result<SupervisorReport, AgentBuildError> {
    let built = build_agent(&cli, &cfg)?;
    tracing::info!(
        target: "sng_agent::supervisor",
        pal_backend = ?cli.pal_backend,
        capture_backend = ?cli.effective_capture_backend(),
        posture_backend = ?cli.effective_posture_backend(),
        tunnel_backend = ?cli.effective_tunnel_backend(),
        "sng-agent composed; entering supervisor run loop"
    );
    // Move `supervisor` out and drop every other subsystem
    // Arc field BEFORE the supervisor takes over. Each
    // subsystem stores its own producer-side channel halves
    // (e.g. `TelemetrySubsystem.handle: PipelineHandle`
    // wraps an mpsc::Sender) and any extra `Arc<...Subsystem>`
    // reference outside the supervisor would keep those
    // channel ends alive across drain \u2014 the telemetry
    // pipeline can only exit when ALL producer-channel
    // senders are dropped.
    //
    // Rust would already drop the unbound fields at the
    // destructure site if we wrote `let BuiltAgent {
    // supervisor, .. } = built;` (a `..` ignore-pattern
    // moves the unmentioned fields out of the value and
    // drops them immediately, since they have no binding).
    // The fully-named destructure plus explicit `drop` of
    // each field is therefore equivalent in observable
    // behaviour for the current code, but is preferred here
    // for two reasons:
    //
    //   1. It documents the deadlock-avoidance intent
    //      explicitly on every field, so a future maintainer
    //      reading this function understands that each Arc
    //      must be released before `supervisor.run()` and
    //      cannot accidentally introduce a long-lived clone
    //      (e.g. by adding `let t = telemetry.clone();`
    //      between the destructure and the run call) without
    //      first deleting the matching `drop(...)` line.
    //   2. If `BuiltAgent` ever grows a new field, the
    //      compiler will fail the destructure rather than
    //      silently extending the deadlock-risky surface
    //      through `..`. With `..` the field would be silently
    //      dropped, which still happens to be the right
    //      behaviour today, but bypasses the chance for the
    //      author of the new field to think about whether the
    //      release ordering matters for their addition.
    //
    // The supervisor then releases its own internal Arc
    // references during `run()` per the comment in
    // `sng_core::Supervisor::run`.
    let BuiltAgent {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        ztna,
        pal_capture,
        pal_posture,
        pal_tunnel,
        dlp,
        desired_tunnels_tx,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(ztna);
    drop(pal_capture);
    drop(pal_posture);
    drop(pal_tunnel);
    drop(dlp);
    // Do NOT drop `desired_tunnels_tx`. Hold the only
    // `watch::Sender` for the desired-tunnel-set channel
    // alive for the entire `supervisor.run().await` so:
    //
    //   1. The `PalTunnelSubsystem` reconciler does not
    //      observe `desired_rx.changed() == Err(...)` on
    //      every boot. The subsystem is defensively wired
    //      against that case (the `publisher_alive` guard
    //      structurally disables the branch — see
    //      `subsystems/pal_tunnel.rs`), but tripping that
    //      path on every clean startup also emits a
    //      `tracing::warn!` log line about the publisher
    //      having dropped, which would noisy-warn every
    //      operator boot for what's actually a normal
    //      production cold-start.
    //
    //   2. The watch channel stays open so a follow-up PR
    //      that wires a real publisher (e.g. desired tunnels
    //      sourced from `policy_eval` / `ztna` authorisation
    //      decisions) can plug into the existing sender
    //      handle without restructuring this function.
    //
    // Holding a `watch::Sender` does NOT pin any subsystem
    // `Arc` and does NOT extend the life of any
    // `mpsc::Sender` clone on the telemetry / comms
    // producer side — the desired-tunnel channel is
    // entirely independent of the supervisor's drain path,
    // so this assignment is safe with respect to the
    // drain-deadlock invariant the explicit `drop`s above
    // establish.
    let _desired_tunnels_tx = desired_tunnels_tx;
    supervisor.run().await.map_err(AgentBuildError::from)
}

/// Resolve the per-selector PAL backend choice and validate
/// that each one is currently supported. Each selector is
/// independently checked so the operator can see *which*
/// adapter triggered the rejection — staged rollout typically
/// pins one adapter to native at a time.
fn resolve_pal_backends(
    cli: &Cli,
) -> Result<(PalBackend, PalBackend, PalBackend), AgentBuildError> {
    let capture_backend = cli.effective_capture_backend();
    let posture_backend = cli.effective_posture_backend();
    let tunnel_backend = cli.effective_tunnel_backend();
    for (selector, backend) in [
        ("capture", capture_backend),
        ("posture", posture_backend),
        ("tunnel", tunnel_backend),
    ] {
        if !matches!(backend, PalBackend::InMemory) {
            return Err(AgentBuildError::UnsupportedPalBackend { selector, backend });
        }
    }
    Ok((capture_backend, posture_backend, tunnel_backend))
}

/// Build the host [`Platform`] descriptor. Stamped onto
/// every telemetry envelope so the control plane can join
/// per-OS dashboards without a separate enrollment record.
/// The envelope schema enumerates Windows / macOS / Linux /
/// iOS / Android — for an unrecognised host we fall back to
/// Linux as the most likely server-OS shape (the agent
/// also ships in datacenter VMs alongside the edge crate).
fn host_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        // The agent binary ships for desktop OSes; any
        // unrecognised host is treated as Linux on the
        // wire so dashboards still join on a known facet.
        Platform::Linux
    }
}

/// Bridge the telemetry pipeline's
/// [`sng_telemetry::PipelineHandle`] onto the
/// [`mpsc::Sender<TelemetryEvent>`] surface the ZTNA
/// producer subsystem expects. The two halves intentionally
/// do not share a single channel type: the ZTNA subsystem
/// was written against the `mpsc::Sender<TelemetryEvent>`
/// surface long before the pipeline existed, and the
/// pipeline owns its own channel for dedup / redact /
/// enrich. The shim spawned here reads from the producer
/// channel and submits into the pipeline handle, so the
/// existing producer keeps its signature while the events
/// still go through the canonical pipeline.
fn pipeline_handle_to_telemetry_sender(
    telemetry: &Arc<TelemetrySubsystem>,
    shutdown: ShutdownSignal,
) -> mpsc::Sender<TelemetryEvent> {
    let (tx, mut rx) = mpsc::channel::<TelemetryEvent>(1024);
    let handle = telemetry.pipeline_handle();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // `biased;` so shutdown is polled FIRST on
                // every loop iteration. The default fair
                // polling could let a steady stream of
                // `rx.recv()`-readies starve the shutdown
                // branch for an arbitrary number of select
                // cycles \u2014 the buffer-drain step below
                // makes that semantically harmless (no event
                // is lost) but it would still delay the
                // supervisor's observable transition into the
                // drain phase. Biased polling guarantees that
                // once `shutdown` fires the very next
                // iteration breaks out of the loop into the
                // drain step deterministically, regardless of
                // how many events are queued ahead of us.
                biased;
                // Race shutdown so the bridge releases its
                // owned `PipelineHandle` (which wraps the
                // pipeline's producer-side `mpsc::Sender`)
                // when the supervisor begins drain. Without
                // this, the bridge keeps one strong sender
                // reference alive for the entire process
                // lifetime, the pipeline's `recv()` never
                // observes channel closure, the telemetry
                // subsystem's `start()` spawn task never
                // joins, and the supervisor drain deadlocks
                // \u2014 a real production-shutdown bug.
                //
                // Before exiting, drain any events still
                // buffered in the bridge's own
                // `mpsc::Receiver<TelemetryEvent>` and forward
                // them through `handle.try_submit`. The drain
                // is bounded (the channel capacity is 1024)
                // and uses non-blocking `try_recv` +
                // `try_submit`, so it cannot stall the
                // supervisor drain regardless of how slow the
                // pipeline's downstream `recv()` loop is.
                // Without this drain step, events that
                // producer subsystems (PAL capture / PAL
                // posture / ZTNA / etc.) had already enqueued
                // via the bridge's `mpsc::Sender` \u2014 but the
                // bridge hadn't yet forwarded to the pipeline
                // \u2014 would be silently lost during the
                // shutdown race window. The pipeline subsystem
                // itself applies its own drain budget to
                // whatever we hand off via `try_submit` here,
                // so this bridge-side drain only ever attempts
                // an in-process channel-to-channel move and
                // the pipeline\u2019s own drain timing
                // semantics are unchanged.
                () = shutdown.wait() => {
                    while let Ok(event) = rx.try_recv() {
                        if let Err(err) = handle.try_submit(event) {
                            tracing::debug!(
                                target: "sng_agent::telemetry_bridge",
                                "pipeline submit rejected event during shutdown drain: {err:?}"
                            );
                        }
                    }
                    break;
                }
                ev = rx.recv() => {
                    match ev {
                        Some(event) => {
                            // Submit through the canonical
                            // PipelineHandle. We use the
                            // non-blocking `try_submit` form
                            // so a saturated pipeline never
                            // wedges a producer subsystem;
                            // the dropped event is logged at
                            // debug-level and accounted for
                            // in the pipeline's own stats
                            // counters when the channel is
                            // closed.
                            if let Err(err) = handle.try_submit(event) {
                                tracing::debug!(
                                    target: "sng_agent::telemetry_bridge",
                                    "pipeline submit rejected event: {err:?}"
                                );
                            }
                        }
                        None => {
                            // Every producer dropped its
                            // sender clone \u2014 we're done.
                            break;
                        }
                    }
                }
            }
        }
        // Explicit drop so the `PipelineHandle` (and the
        // inner mpsc sender it owns) is released exactly when
        // the loop exits, regardless of which branch broke
        // us out.
        drop(handle);
    });
    tx
}

/// Build the bundle publisher closure that the comms
/// puller invokes on every fresh bundle. For the Endpoint
/// target we dispatch into the policy evaluator. Any
/// non-Endpoint bundle is rejected — the puller's target
/// is configured separately, so a mismatch is a build
/// regression rather than a hot-path concern, but we
/// surface it as an error instead of silently swapping the
/// wrong target.
fn make_bundle_publisher(
    policy_eval: Arc<PolicyEvalSubsystem>,
    dlp_engine: Option<Arc<DlpEngine>>,
) -> BundlePublisher {
    Arc::new(move |target, body| match target {
        BundleTarget::Endpoint => {
            policy_eval
                .swap_bundle(&body, false)
                .map_err(|e| format!("policy_eval swap rejected bundle: {e}"))?;
            tracing::info!(
                target: "sng_agent::bundle_publisher",
                body_bytes = body.len(),
                "policy_eval bundle swap accepted"
            );
            // Apply the bundle's DLP domain document to the live engine
            // when this agent runs endpoint DLP. The swap above already
            // decoded the bundle, so we read the `dl` section straight
            // off the now-current `LoadedBundle` rather than re-decoding
            // the body.
            if let Some(engine) = &dlp_engine {
                let loaded = policy_eval.engine().current_bundle();
                apply_dlp_document(engine, loaded.dlp.as_deref())?;
            }
            Ok(())
        }
        other => Err(format!(
            "endpoint bundle publisher rejected non-Endpoint bundle target {other:?}"
        )),
    })
}

/// Install the bundle-carried endpoint DLP document into the live
/// engine, treating the bundle as the source of truth.
///
/// `dlp` is the verbatim `dl` section from the just-applied bundle
/// (`None` when the bundle carried none). The three DLP dimensions are
/// orthogonal, so we drive them with distinct calls:
/// [`DlpEngine::install`] rotates the rule set + channel config and
/// [`DlpEngine::set_ai_app_policy`] (re)arms the AI-app exfiltration
/// detector. Absence of a `dl` section resets both to the inert
/// default, so removing all endpoint DLP policy in the control plane
/// disarms the edge rather than leaving a stale policy live.
///
/// On a decode error the engine keeps its previous (valid) policy
/// because `install` is only reached after a successful decode; we
/// surface the error so the puller logs it and counts a publish
/// failure.
fn apply_dlp_document(engine: &Arc<DlpEngine>, dlp: Option<&[u8]>) -> Result<(), String> {
    let policy = match dlp {
        Some(bytes) => DlpPolicy::from_bundle_json(bytes)
            .map_err(|e| format!("decode endpoint DLP policy: {e}"))?,
        None => DlpPolicy::default(),
    };
    let ai_app = policy.ai_app.clone();
    let rule_count = policy.rules().len();
    engine
        .install(policy)
        .map_err(|e| format!("install endpoint DLP policy: {e}"))?;
    engine
        .set_ai_app_policy(ai_app.clone())
        .map_err(|e| format!("apply endpoint AI-app policy: {e}"))?;
    tracing::info!(
        target: "sng_agent::bundle_publisher",
        rules = rule_count,
        ai_app_enabled = ai_app.is_some(),
        "endpoint DLP policy applied from bundle"
    );
    Ok(())
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

    #[test]
    fn apply_dlp_document_installs_rules_and_arms_detector() {
        // A bundle carrying a `dl` document must install its rules and,
        // when the document carries an `ai_app` block, arm the AI-app
        // detector — the wiring that makes operator-authored endpoint
        // DLP policy (and the #185 producer) actually live at the edge.
        let engine = Arc::new(DlpEngine::with_limit(DlpPolicy::default(), 1 << 20).unwrap());
        assert_eq!(engine.current_policy().rules().len(), 0);
        assert!(engine.ai_app_policy().is_none());

        let doc = serde_json::json!({
            "schema_version": 1,
            "target": "endpoint",
            "domain": "dlp",
            "rules": [{
                "id": "ssn",
                "name": "US SSN",
                "pattern_type": "regex",
                "pattern_data": "ssn_us",
                "severity": "high",
                "action": "warn"
            }],
            "ai_app": {"enabled": true, "block_opt_in": false, "block_confidence": 0.9, "min_report_confidence": 0.5, "coach_severity_floor": "high"}
        });
        let bytes = serde_json::to_vec(&doc).unwrap();

        apply_dlp_document(&engine, Some(bytes.as_slice())).unwrap();
        assert_eq!(engine.current_policy().rules().len(), 1);
        assert!(
            engine.ai_app_policy().is_some(),
            "ai_app block in the bundle must arm the detector"
        );
    }

    #[test]
    fn apply_dlp_document_without_section_disarms_engine() {
        // Removing all endpoint DLP policy in the control plane yields a
        // bundle with no `dl` section. The edge must reset to the inert
        // default rather than keep a stale policy live.
        let engine = Arc::new(DlpEngine::with_limit(DlpPolicy::default(), 1 << 20).unwrap());
        let doc = serde_json::json!({
            "schema_version": 1, "target": "endpoint", "domain": "dlp",
            "rules": [{
                "id": "ssn", "name": "US SSN", "pattern_type": "regex",
                "pattern_data": "ssn_us", "severity": "high", "action": "warn"
            }],
            "ai_app": {"enabled": true, "block_opt_in": false, "block_confidence": 0.9, "min_report_confidence": 0.5, "coach_severity_floor": "high"}
        });
        apply_dlp_document(&engine, Some(serde_json::to_vec(&doc).unwrap().as_slice())).unwrap();
        assert_eq!(engine.current_policy().rules().len(), 1);
        assert!(engine.ai_app_policy().is_some());

        // No `dl` section → disarm.
        apply_dlp_document(&engine, None).unwrap();
        assert_eq!(engine.current_policy().rules().len(), 0);
        assert!(engine.ai_app_policy().is_none());
    }

    #[test]
    fn apply_dlp_document_rejects_malformed_json_and_keeps_prior_policy() {
        // A malformed `dl` section is a compiler bug; surface it as an
        // error. Crucially, the engine must keep its previous valid
        // policy (fail-safe) rather than wipe it.
        let engine = Arc::new(DlpEngine::with_limit(DlpPolicy::default(), 1 << 20).unwrap());
        let doc = serde_json::json!({
            "schema_version": 1, "target": "endpoint", "domain": "dlp",
            "rules": [{
                "id": "ssn", "name": "US SSN", "pattern_type": "regex",
                "pattern_data": "ssn_us", "severity": "high", "action": "warn"
            }]
        });
        apply_dlp_document(&engine, Some(serde_json::to_vec(&doc).unwrap().as_slice())).unwrap();
        assert_eq!(engine.current_policy().rules().len(), 1);

        let err = apply_dlp_document(&engine, Some(b"{not valid json")).unwrap_err();
        assert!(err.contains("decode endpoint DLP policy"), "got: {err}");
        // Prior policy survived the failed apply.
        assert_eq!(engine.current_policy().rules().len(), 1);
    }
}
