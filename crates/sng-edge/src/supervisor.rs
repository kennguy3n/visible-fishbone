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
//!    evaluator, paired with
//!    [`crate::subsystems::ZtnaReevalSubsystem`] — the continuous
//!    re-evaluation loop registered right after it. That loop is
//!    default-off (idles unless `ztna.reeval_enabled` is set) and
//!    shares the evaluator's `ZtnaService` so it re-uses the exact
//!    access decision rather than re-implementing it.
//! 9. [`crate::subsystems::SdwanSubsystem`] — synchronous SD-WAN
//!    steering evaluator.
//! 10. [`crate::subsystems::UpdaterSubsystem`] — self-update
//!     state machine. Last so the engine isn't tempted to
//!     swap the bank while a sister subsystem is still
//!     mid-boot.

use crate::cli::{Cli, DataPathSelection, PalBackend, UpdaterBackend};
use crate::commodity::{CommodityProfile, SpecAssessment};
use crate::config::EdgeConfig;
use crate::subsystems::{
    CommsSubsystem, DemSubsystem, DnsSubsystem, ExtAuthzSubsystem, FwSubsystem, HaSubsystem,
    IpsSubsystem, PolicyEvalSubsystem, SdwanSubsystem, SwgSubsystem, TelemetrySubsystem,
    UpdaterSubsystem,
    comms::{BundlePublisher, CommsBuildError},
    telemetry::TelemetryBuildError,
    updater::UpdaterSubsystemError,
    ztna::ZtnaSubsystem,
    ztna_reeval::ZtnaReevalSubsystem,
};
use sng_comms::PolicyTrustStore;
use sng_core::envelope::Platform;
use sng_core::{
    BundleTarget, ShutdownSignal, Supervisor, SupervisorBuilder, SupervisorReport,
    SupervisorRunError,
};
use sng_fw::{CompiledRuleSet, NatTable, RuleCompiler, ZoneTable};
use sng_telemetry::TelemetryEvent;
use sng_ztna::{SessionTracker, ZtnaServiceConfig};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

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
    /// HA subsystem build failed (config invariant or VRRP
    /// multicast socket bind / join).
    #[error("ha subsystem build failed: {0}")]
    Ha(#[from] sng_ha::HaError),
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
    /// Ext-authz verdict-listener adapter. Default-off; idles
    /// unless `swg.ext_authz_enabled` is set.
    pub ext_authz: Arc<ExtAuthzSubsystem>,
    /// ZTNA adapter.
    pub ztna: Arc<ZtnaSubsystem>,
    /// ZTNA continuous re-evaluation adapter. Default-off; idles
    /// unless `ztna.reeval_enabled` is set. Shares the
    /// `ZtnaService` with [`Self::ztna`].
    pub ztna_reeval: Arc<ZtnaReevalSubsystem>,
    /// SD-WAN adapter.
    pub sdwan: Arc<SdwanSubsystem>,
    /// HA adapter. No-op when `[ha]` is disabled.
    pub ha: Arc<HaSubsystem>,
    /// Updater adapter.
    pub updater: Arc<UpdaterSubsystem>,
    /// DEM adapter. Default-off; idles unless `dem.enabled` is set.
    pub dem: Arc<DemSubsystem>,
    /// The resolved data-path backend (`auto` already collapsed to
    /// `ebpf`/`nftables` via the one-time XDP capability probe).
    /// Carried here so `run_edge` can size the commodity profile
    /// without re-probing the kernel.
    pub datapath: DataPathSelection,
}

impl std::fmt::Debug for BuiltEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltEdge")
            .field("supervisor", &"Supervisor { .. }")
            .field("subsystems", &14_usize)
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

/// Resolve a [`DataPathSelection`] into the concrete backend the
/// firewall subsystem will run. `Auto` consults the XDP
/// capability probe ([`sng_ebpf::detect_xdp_capable`]) and
/// collapses to `Ebpf`/`Nftables`; an explicit `Nftables` /
/// `Ebpf` / `Hardware` is returned verbatim so an operator
/// override is never silently second-guessed.
///
/// The returned value is never `Auto` — the subsystem
/// constructor always receives a settled choice. `Hardware` is
/// deliberately **never** reached from `Auto`: the offload tier
/// must be opted into explicitly because, absent real silicon,
/// it runs the software model with no throughput gain over
/// `Ebpf`.
#[must_use]
fn resolve_datapath(selection: DataPathSelection) -> DataPathSelection {
    match selection {
        DataPathSelection::Auto => {
            if sng_ebpf::detect_xdp_capable() {
                DataPathSelection::Ebpf
            } else {
                DataPathSelection::Nftables
            }
        }
        explicit => explicit,
    }
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
/// # Runtime requirement
///
/// Although `build_edge` itself is a sync function, it
/// spawns the telemetry-bridge task via [`tokio::spawn`].
/// The caller MUST therefore be executing inside a tokio
/// runtime — i.e. it must be called from an `async fn` on
/// a tokio runtime, from inside a `tokio::main`-decorated
/// function, or from inside a [`tokio::runtime::Runtime`]
/// `block_on` / `enter` scope. The two real callers are
/// [`run_edge`] (an `async fn` invoked from
/// `#[tokio::main]`) and the integration tests (each
/// decorated with `#[tokio::test]`); both satisfy the
/// constraint. The signature is deliberately sync because
/// every per-subsystem build step is itself sync — making
/// `build_edge` async would force every test harness (and
/// the binary's `main`) to thread an unnecessary `.await`
/// through the call site for a single internal
/// `tokio::spawn`.
///
/// # Errors
///
/// Returns [`EdgeBuildError`] for any per-subsystem build
/// failure or for an unsupported `--updater-backend` /
/// `--pal-backend` selection.
///
/// # Panics
///
/// Panics if called from outside a tokio runtime context,
/// because the telemetry-bridge `tokio::spawn` requires
/// one.
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

    // 1b. Firewall. Built ahead of comms (out of the numbered
    //     boot order below) because the bundle publisher wired
    //     into comms needs the firewall's ruleset sender: every
    //     accepted bundle is compiled into a `CompiledRuleSet`
    //     and pushed to the data path, so the firewall must
    //     exist before the publisher closure is constructed.
    //     Resolve the data-path selection first — `auto` probes
    //     the kernel for XDP support and picks the eBPF fast path
    //     when available, nftables otherwise — so a forced
    //     `ebpf`/`nftables` is honoured verbatim and `auto` never
    //     boot-fails on an XDP-incapable box.
    let datapath = resolve_datapath(cli.datapath);
    tracing::info!(
        target: "sng_edge::supervisor",
        requested = ?cli.datapath,
        resolved = ?datapath,
        "firewall data-path backend selected"
    );
    let fw = Arc::new(FwSubsystem::new(&cfg.fw, datapath));

    // 2. Comms. Builds the long-lived ControlPlaneClient
    //    internally from the operator-supplied TLS material;
    //    the telemetry subsystem will reuse the same client
    //    via `comms.client()` so cert / trust store / endpoint
    //    are configured in exactly one place. Wire the bundle
    //    publisher to dispatch fresh bundles into the policy
    //    evaluator and, on each accepted bundle, compile the
    //    NGFW + steering slice and push it to the firewall data
    //    path. Future subsystems that need their own bundle
    //    slice (compiled IPS rules, Envoy config) will subscribe
    //    to a fan-out built on top of this publisher.
    let publisher = make_bundle_publisher(Arc::clone(&policy_eval), fw.ruleset_sender());
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

    // Create the supervisor builder up front so we can pull a
    // `ShutdownSignal` clone for non-subsystem helper tasks
    // (specifically the telemetry pipeline-handle bridge
    // below) BEFORE the supervisor itself is built. The
    // bridge owns a `PipelineHandle` clone and would
    // otherwise have no way to observe drain; it would pin
    // the pipeline's producer-side mpsc sender for the entire
    // process lifetime and deadlock the telemetry subsystem's
    // drain. The builder lazily creates the trigger/signal
    // pair in its `Default` impl so this is always safe.
    let mut builder = SupervisorBuilder::default()
        .with_health_interval(cfg.supervisor.health_interval)
        .with_health_probe_budget(cfg.supervisor.health_probe_budget);
    let shutdown_signal_for_bridges = builder.shutdown_signal();

    // 4. DNS. The telemetry sender is the producer-facing
    //    mpsc::Sender half of the telemetry pipeline.
    let telemetry_tx = pipeline_handle_to_telemetry_sender(&telemetry, shutdown_signal_for_bridges);
    let dns = Arc::new(DnsSubsystem::new(&cfg.dns, telemetry_tx.clone()));

    // 5. Firewall is constructed earlier (step 1b) so its
    //    ruleset sender can be wired into the bundle publisher.

    // 6. IPS.
    let ips = Arc::new(IpsSubsystem::new(&cfg.ips));

    // 7. SWG.
    let swg = Arc::new(SwgSubsystem::new(&cfg.swg));

    // 7b. Ext-authz verdict listener. Owns the Unix-socket server
    //     Envoy's ext-authz filter dials — the "deployment-layer"
    //     piece the SWG manager intentionally does not own. Reads
    //     the same `[swg]` slice; default-off so an upgrade is
    //     behaviourally inert until `swg.ext_authz_enabled` is set.
    let ext_authz = Arc::new(ExtAuthzSubsystem::new(&cfg.swg, telemetry_tx.clone()));

    // 8. ZTNA. The edge config's `max_inflight` maps onto
    //    ZtnaServiceConfig's `max_sessions` — both name the
    //    producer-enforced ceiling on concurrent ZTNA
    //    evaluations the brain has advertised it can handle
    //    (the brain is stateless per-request; load shedding
    //    happens at this producer layer).
    let ztna_cfg = ZtnaServiceConfig {
        max_sessions: cfg.ztna.max_inflight,
        // Full user-subject evaluation (and the explicit
        // `identity_absent` degraded verdict) is an operator opt-in,
        // default-off and inert until `ztna.user_subject_eval_enabled`
        // is set. The subsystem reads this same flag to decide whether
        // to wire the per-subject identity cache.
        subjectless_degraded_eval: cfg.ztna.user_subject_eval_enabled,
    };
    // Session store shared by the two halves of continuous-adaptive-
    // trust: the access-path producer (`ZtnaSubsystem::open_session`)
    // records a grant per allowed session, and the re-eval loop sweeps
    // the same store. It is only wired when `ztna.reeval_enabled` is
    // set — when off, the producer is handed no tracker, so it records
    // nothing and the access path is byte-for-byte unchanged.
    let ztna_sessions = Arc::new(SessionTracker::new());
    let ztna = {
        let ztna = ZtnaSubsystem::new(ztna_cfg, telemetry_tx.clone());
        let ztna = if cfg.ztna.reeval_enabled {
            ztna.with_session_tracker(Arc::clone(&ztna_sessions))
        } else {
            ztna
        };
        let ztna = if cfg.ztna.clientless_enabled {
            let evaluator = sng_ztna::clientless::ClientlessEvaluator::new(
                Arc::clone(ztna.service()),
                cfg.ztna.clientless_idp_authorize_url.clone(),
            );
            ztna.with_clientless(evaluator, cfg.ztna.clientless_cookie_name.clone())
        } else {
            ztna
        };
        Arc::new(ztna)
    };

    // 8b. ZTNA continuous re-evaluation. Shares the synchronous
    //     evaluator's `ZtnaService` so the loop re-uses the exact
    //     access decision rather than re-implementing it, and the
    //     `ztna_sessions` tracker the producer above records into so it
    //     re-evaluates exactly the live sessions. Default-off
    //     (`ztna.reeval_enabled = false`): until an operator opts in the
    //     subsystem idles, never spawning the sweep, and the producer is
    //     handed no tracker, so an upgrade is behaviourally inert.
    let ztna_reeval = Arc::new(ZtnaReevalSubsystem::with_tracker(
        Arc::clone(ztna.service()),
        &cfg.ztna,
        ztna_sessions,
    ));

    // 9. SD-WAN.
    let sdwan = Arc::new(SdwanSubsystem::new(&cfg.sdwan, telemetry_tx));

    // 10. HA. No-op unless `[ha]` is enabled. Built before the
    //     updater so a failover demotion can quiesce the data
    //     plane before the updater is ever tempted to swap banks.
    let ha = Arc::new(HaSubsystem::new(&cfg.ha)?);

    // 11. Updater.
    let updater = Arc::new(UpdaterSubsystem::default_in_memory(&cfg.updater)?);

    // 12. DEM (Digital Experience Monitoring). Default-off; the
    //     subsystem idles (no engine, no sweep loop) unless
    //     `dem.enabled` is set.
    let dem = Arc::new(DemSubsystem::new(&cfg.dem));

    // Register subsystems onto the builder we created above.
    // Boot order matters: telemetry + comms first so producer
    // subsystems have a live channel + bundle source by the
    // time they spawn, then everything else.
    builder = builder.with_subsystem(Arc::clone(&telemetry));
    builder = builder.with_subsystem(Arc::clone(&comms));
    builder = builder.with_subsystem(Arc::clone(&policy_eval));
    builder = builder.with_subsystem(Arc::clone(&dns));
    builder = builder.with_subsystem(Arc::clone(&fw));
    builder = builder.with_subsystem(Arc::clone(&ips));
    builder = builder.with_subsystem(Arc::clone(&swg));
    builder = builder.with_subsystem(Arc::clone(&ext_authz));
    builder = builder.with_subsystem(Arc::clone(&ztna));
    builder = builder.with_subsystem(Arc::clone(&ztna_reeval));
    builder = builder.with_subsystem(Arc::clone(&sdwan));
    builder = builder.with_subsystem(Arc::clone(&ha));
    builder = builder.with_subsystem(Arc::clone(&updater));
    builder = builder.with_subsystem(Arc::clone(&dem));

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
        ext_authz,
        ztna,
        ztna_reeval,
        sdwan,
        ha,
        updater,
        dem,
        datapath,
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

    // Commodity-hardware preflight. Probe the host, assess it against
    // the documented minimum spec (2 cores / 2 GiB / 8 GiB), and log a
    // one-line summary with the NUMA-aware worker affinity plan and the
    // resolved data-path (eBPF fast-path) profile. The edge is a
    // software appliance, so an undersized host is logged loudly rather
    // than refused — operators running below spec get an unambiguous
    // boot-log signal instead of a silent degradation.
    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // Reuse the data-path the firewall already resolved in
    // build_edge rather than calling resolve_datapath again, which
    // would re-run the XDP kernel capability probe. Probe free space on
    // `cfg.data_dir` — the edge's data-partition root — not a single
    // subsystem's working dir, so the 8 GiB minimum is measured against
    // the filesystem the whole appliance actually spools onto.
    let commodity = CommodityProfile::detect(&cfg.data_dir, workers, built.datapath);
    match &commodity.assessment {
        SpecAssessment::Pass => tracing::info!(
            target: "sng_edge::commodity",
            summary = %commodity.summary(),
            "commodity-hardware preflight passed"
        ),
        SpecAssessment::Warn(_) => tracing::warn!(
            target: "sng_edge::commodity",
            summary = %commodity.summary(),
            "commodity-hardware preflight raised warnings"
        ),
        SpecAssessment::Fail(_) => tracing::error!(
            target: "sng_edge::commodity",
            summary = %commodity.summary(),
            "host is below the commodity-hardware minimum spec; \
             booting anyway (software appliance) but this configuration is unsupported"
        ),
    }

    tracing::info!(
        target: "sng_edge::supervisor",
        updater_backend = ?cli.updater_backend,
        pal_backend = ?cli.pal_backend,
        "sng-edge composed; entering supervisor run loop"
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
    // destructure site if we wrote `let BuiltEdge {
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
    //   2. If `BuiltEdge` ever grows a new field, the
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
    let BuiltEdge {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        dns,
        fw,
        ips,
        swg,
        ext_authz,
        ztna,
        ztna_reeval,
        sdwan,
        ha,
        updater,
        dem,
        // Plain Copy enum, no Arc to release; already consumed by
        // the commodity preflight above.
        datapath: _,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(dns);
    drop(fw);
    drop(ips);
    drop(swg);
    drop(ext_authz);
    drop(ztna);
    drop(ztna_reeval);
    drop(sdwan);
    drop(ha);
    drop(updater);
    drop(dem);
    supervisor.run().await.map_err(EdgeBuildError::from)
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
                // producer subsystems (DNS / IPS / ZTNA / etc.)
                // had already enqueued via the bridge's
                // `mpsc::Sender` \u2014 but the bridge hadn't yet
                // forwarded to the pipeline \u2014 would be
                // silently lost during the shutdown race
                // window. The pipeline subsystem itself
                // applies its own drain budget to whatever we
                // hand off via `try_submit` here, so this
                // bridge-side drain only ever attempts an
                // in-process channel-to-channel move and the
                // pipeline\u2019s own drain timing semantics are
                // unchanged.
                () = shutdown.wait() => {
                    while let Ok(event) = rx.try_recv() {
                        if let Err(err) = handle.try_submit(event) {
                            tracing::debug!(
                                target: "sng_edge::telemetry_bridge",
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
                                    target: "sng_edge::telemetry_bridge",
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
        // the loop exits, regardless of which branch broke us
        // out. Reads cleaner than relying on the implicit
        // move-into-closure drop semantics.
        drop(handle);
    });
    tx
}

/// Build the bundle publisher closure that the comms puller
/// invokes on every fresh bundle. For the Edge target we swap
/// the bundle into the policy evaluator (the per-flow decision
/// engine) and then compile its NGFW + steering slice into a
/// [`CompiledRuleSet`] which is pushed to the firewall data
/// path over `fw_ruleset_tx` — wiring the nftables / XDP
/// enforcement substrate to the bundle for the first time. The
/// remaining bundle-derived artifacts (IPS rules, Envoy config,
/// SD-WAN paths, ZTNA catalog) will subscribe to a fan-out built
/// on top of this publisher in a follow-up PR; today the policy
/// evaluator and the firewall are the two consumers.
///
/// The firewall compile is best-effort relative to the swap: the
/// policy evaluator has already accepted the bundle by the time
/// we compile, so a compile failure (e.g. a rule referencing an
/// undefined zone) is logged and the previous ruleset is left in
/// place rather than failing the whole publish and stalling the
/// per-flow engine on a stale bundle.
fn make_bundle_publisher(
    policy_eval: Arc<PolicyEvalSubsystem>,
    fw_ruleset_tx: watch::Sender<Option<Arc<CompiledRuleSet>>>,
) -> BundlePublisher {
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

                // The evaluator now holds the accepted bundle.
                // Compile its firewall slice (NGFW rules + the
                // steering-derived XDP classification table) and
                // push it to the data path. Zones / NAT are not
                // bundle-sourced today, so compile against empty
                // tables — rules referencing named zones compile
                // fail-closed and are surfaced below.
                let bundle = policy_eval.engine().current_bundle();
                match RuleCompiler::new().compile(
                    &bundle,
                    ZoneTable::default(),
                    NatTable::default(),
                ) {
                    Ok(compiled) => {
                        // `send` only errors when every receiver
                        // has dropped; the firewall subsystem holds
                        // one for its whole lifetime, so a send
                        // error means the appliance is shutting down
                        // and a missed ruleset is irrelevant.
                        let rules = compiled.rules.len();
                        let classes = compiled.classification.len();
                        if fw_ruleset_tx.send(Some(Arc::new(compiled))).is_ok() {
                            tracing::info!(
                                target: "sng_edge::bundle_publisher",
                                rules,
                                classification_entries = classes,
                                "firewall ruleset compiled and pushed to data path"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "sng_edge::bundle_publisher",
                            error = %e,
                            "firewall ruleset compile failed; data path retains \
                             the previous ruleset"
                        );
                    }
                }
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

    #[test]
    fn bundle_publisher_compiles_and_pushes_ruleset_to_fw() {
        // The Edge publisher must swap the bundle into the policy
        // evaluator AND compile its firewall slice onto the data
        // path's ruleset channel — the wiring this change adds.
        let body = bootstrap_bundle_body();
        let policy_eval = Arc::new(PolicyEvalSubsystem::new(&body).expect("policy_eval"));
        let (tx, rx) = watch::channel::<Option<Arc<CompiledRuleSet>>>(None);
        assert!(rx.borrow().is_none(), "fw channel starts empty");

        let publisher = make_bundle_publisher(Arc::clone(&policy_eval), tx);
        publisher(BundleTarget::Edge, body).expect("edge publish succeeds");

        let received = rx.borrow();
        let compiled = received.as_ref().expect("ruleset pushed to fw data path");
        // The deny-all bootstrap skeleton ships no steering block,
        // so the classify table is the conservative empty one.
        assert!(compiled.classification.is_empty());
    }

    #[test]
    fn bundle_publisher_rejects_non_edge_target_without_pushing() {
        let body = bootstrap_bundle_body();
        let policy_eval = Arc::new(PolicyEvalSubsystem::new(&body).expect("policy_eval"));
        let (tx, rx) = watch::channel::<Option<Arc<CompiledRuleSet>>>(None);

        let publisher = make_bundle_publisher(Arc::clone(&policy_eval), tx);
        assert!(
            publisher(BundleTarget::Endpoint, body).is_err(),
            "edge publisher must reject a non-Edge target"
        );
        // A rejected target never reaches the compile/push step.
        assert!(rx.borrow().is_none());
    }
}
