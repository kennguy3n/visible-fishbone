// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Firewall (L3/L4 + L7) subsystem adapter.
//!
//! Wraps [`sng_fw::FirewallEngine`] driving a
//! [`sng_fw::ShellNftables`] backend. The subsystem's
//! background task is the install loop: the policy puller
//! delivers compiled rulesets through a `tokio::sync::watch`
//! channel, and the install task drains them in order,
//! `await`ing the kernel apply (via
//! [`FirewallEngine::install`]) for each one.
//!
//! Like the DNS subsystem, the source of compiled rulesets
//! (the control-plane policy bundle) is wired through the
//! comms / policy_eval subsystems — at this PR's scope the
//! ruleset channel is held by the FW subsystem as a
//! [`tokio::sync::watch::Sender`] that other subsystems hand
//! new rulesets through. The supervisor's startup does NOT
//! install a default ruleset — the engine boots with `None`,
//! which the engine's own evaluate path treats as fail-closed
//! (every packet denied).

use crate::cli::DataPathSelection;
use crate::config::FwConfig;
use crate::hardware::HardwareAccelerator;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_ebpf::XdpControlPlane;
use sng_fw::{
    CompiledRuleSet, DataPathBackend, EbpfDataPath, FirewallEngine, HardwareOffloadDataPath,
    NftablesBackend, NftablesDataPath, OffloadDevice, SoftwareOffloadDevice,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;
use tokio::task;

/// Edge-tier firewall subsystem.
pub struct FwSubsystem {
    /// The firewall engine, used by other subsystems for
    /// per-packet evaluation. Shared with the data-path backend:
    /// for the nftables backend it *is* the install target; for
    /// the eBPF backend it is the nftables fallback the backend
    /// also installs into, so evaluation always sees the full
    /// ruleset.
    engine: Arc<FirewallEngine>,
    /// The selected enforcement substrate. The install loop
    /// drives [`DataPathBackend::install_rules`] on every bundle
    /// reload; which backend is live is fixed at construction.
    datapath: Arc<dyn DataPathBackend>,
    rx: watch::Receiver<Option<Arc<CompiledRuleSet>>>,
    /// Holds the producer half so the subsystem outlives the
    /// last external sender — without this, the watch channel
    /// would close once the last operator-held sender is
    /// dropped and the install loop would exit early.
    tx_anchor: watch::Sender<Option<Arc<CompiledRuleSet>>>,
    installs_total: Arc<AtomicU64>,
    install_failures: Arc<AtomicU64>,
}

impl std::fmt::Debug for FwSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FwSubsystem")
            .field(
                "installs_total",
                &self.installs_total.load(Ordering::Relaxed),
            )
            .field(
                "install_failures",
                &self.install_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl FwSubsystem {
    /// Build a subsystem honouring the operator-supplied `nft`
    /// binary override and data-path selection. `selection` is
    /// the already-resolved backend (the supervisor turns
    /// [`DataPathSelection::Auto`] into a concrete choice via the
    /// XDP capability probe before calling this). The watch
    /// channel starts with `None` (no ruleset installed); the
    /// policy puller pushes the first ruleset once it lands the
    /// first bundle.
    #[must_use]
    pub fn new(cfg: &FwConfig, selection: DataPathSelection) -> Self {
        let nft_binary = cfg
            .nft_binary
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        let (nft_dp, engine) = NftablesDataPath::with_shell(nft_binary.as_deref());
        let datapath: Arc<dyn DataPathBackend> = match selection {
            DataPathSelection::Nftables => Arc::new(nft_dp),
            // `Auto` must be resolved by the caller (the supervisor's
            // `resolve_datapath` XDP-capability probe runs before this).
            // Reaching here with `Auto` means a caller bypassed that
            // resolution; fall back to nftables (the safe default) so the
            // constructor stays total, but warn so the misuse surfaces in
            // development rather than as a silent downgrade.
            DataPathSelection::Auto => {
                tracing::warn!(
                    target: "sng_edge::fw",
                    "data-path selection reached FwSubsystem unresolved (Auto); \
                     defaulting to nftables — the supervisor should resolve Auto \
                     via the XDP capability probe before constructing the subsystem"
                );
                Arc::new(nft_dp)
            }
            DataPathSelection::Ebpf => {
                let control = Self::build_xdp_control_plane(cfg);
                let ebpf = EbpfDataPath::new(control, nft_dp);
                // Surface whether the fast path is genuinely offloading.
                // Without the `xdp` feature (or on a host that could not
                // accept the programs) the control plane runs the userspace
                // model and nftables carries all enforcement — an operator
                // who sees `datapath=ebpf` must not be misled into thinking
                // traffic is hardware/kernel-accelerated.
                if !ebpf.capabilities().kernel_offload {
                    tracing::warn!(
                        target: "sng_edge::fw",
                        "eBPF data path selected but kernel XDP offload is not \
                         active; nftables is carrying enforcement"
                    );
                }
                Arc::new(ebpf)
            }
            DataPathSelection::Hardware => {
                // Probe the boot-time accelerator and build the offload
                // device it (or, absent silicon, the software model) backs.
                let accelerator = crate::hardware::probe_accelerator();
                let device = Self::build_offload_device(accelerator.as_ref(), cfg.offload_capacity);
                let hw = HardwareOffloadDataPath::new(device, nft_dp);
                // Be loud when there is no real silicon behind the tier: the
                // software model offers no throughput gain over `ebpf`, and
                // nftables remains authoritative. An operator who asked for
                // `--datapath=hardware` must not believe a SmartNIC is live.
                if !hw.capabilities().hardware_offload {
                    tracing::warn!(
                        target: "sng_edge::fw",
                        capacity = cfg.offload_capacity,
                        "hardware-offload data path selected but no attested \
                         offload silicon is present; running the in-process \
                         software offload model — nftables carries authoritative \
                         enforcement and there is no throughput gain over ebpf"
                    );
                }
                Arc::new(hw)
            }
        };
        Self::from_parts(engine, datapath)
    }

    /// Build the offload device the hardware data path programs onto.
    ///
    /// When the boot probe reports genuine, **attested** offload silicon
    /// the device's vendor driver would be constructed here. No silicon
    /// binding ships in this build, so an offload-capable+trusted probe is
    /// logged but still backed by the software model rather than
    /// fabricating a driver — the only honest option without the
    /// hardware. A host that is not offload-capable (the shipped
    /// [`crate::hardware::HostAccelerator`]) goes straight to the software
    /// model. Either way nftables stays authoritative via the data path's
    /// fallback.
    #[must_use]
    fn build_offload_device(
        accelerator: &dyn HardwareAccelerator,
        capacity: usize,
    ) -> Arc<dyn OffloadDevice> {
        let descriptor = accelerator.descriptor();
        if descriptor.offload_capable {
            match accelerator.attest() {
                Ok(report) if report.trusted => {
                    tracing::info!(
                        target: "sng_edge::fw",
                        sku = %descriptor.name,
                        "attested offload silicon present; no vendor driver is \
                         compiled into this build, so the software offload model \
                         backs the tier"
                    );
                }
                Ok(_) => tracing::warn!(
                    target: "sng_edge::fw",
                    sku = %descriptor.name,
                    "offload silicon present but failed attestation; refusing to \
                     program it — falling back to the software offload model"
                ),
                Err(err) => tracing::warn!(
                    target: "sng_edge::fw",
                    error = %err,
                    "offload-silicon attestation errored; falling back to the \
                     software offload model"
                ),
            }
        } else {
            tracing::info!(
                target: "sng_edge::fw",
                sku = %descriptor.name,
                tpm_rooted = descriptor.tpm_rooted,
                "no offload-capable hardware detected at boot"
            );
        }
        Arc::new(SoftwareOffloadDevice::new(capacity))
    }

    /// Build the eBPF control plane for the selected fast path.
    ///
    /// With the `xdp` feature on Linux this constructs the real
    /// `aya`-backed loader from the `SNG_EBPF_OBJECT` environment
    /// variable and attempts to load + attach the XDP program to the
    /// configured interface. The attach is **fail-soft**: a host that
    /// cannot accept the program (older kernel, missing object, busy
    /// NIC) degrades to the userspace model and the nftables slow path
    /// keeps enforcing — the edge never fails to boot on a fast-path
    /// problem. Without the feature (or off Linux) the always-compiled
    /// in-memory model is returned.
    #[must_use]
    fn build_xdp_control_plane(cfg: &FwConfig) -> Arc<XdpControlPlane> {
        #[cfg(all(feature = "xdp", target_os = "linux"))]
        {
            use sng_ebpf::AyaLoader;
            match AyaLoader::from_env() {
                Ok(loader) => Self::control_plane_for_loader(Box::new(loader), &cfg.xdp_interface),
                Err(err) => {
                    tracing::warn!(
                        target: "sng_edge::fw",
                        error = %err,
                        "no XDP object available (SNG_EBPF_OBJECT unset); \
                         running userspace data-path model"
                    );
                    Arc::new(XdpControlPlane::in_memory())
                }
            }
        }
        #[cfg(not(all(feature = "xdp", target_os = "linux")))]
        {
            // `xdp` feature compiled out (or non-Linux target): the
            // userspace model is the only available backend.
            let _ = cfg;
            Arc::new(XdpControlPlane::in_memory())
        }
    }

    /// Load + attach `loader` to `iface`, returning the control plane the
    /// data path should run on.
    ///
    /// A clean attach keeps the real kernel loader. A **degraded** attach
    /// (older kernel, missing object, busy NIC) discards it for the
    /// userspace model: a loader whose programs never attached cannot
    /// service map updates, so keeping it would make every `install_rules`
    /// fail with `Unsupported` and drag the `EbpfDataPath` flush
    /// (`clear_rules`) into the same failure on *every* bundle reload —
    /// turning a one-time attach problem into perpetual install errors even
    /// though nftables enforcement is fine. Falling back to the in-memory
    /// model (identical to a missing object) lets the slow path run cleanly.
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    #[must_use]
    fn control_plane_for_loader(
        loader: Box<dyn sng_ebpf::ProgramLoader>,
        iface: &str,
    ) -> Arc<XdpControlPlane> {
        use sng_ebpf::{AttachOutcome, XdpMode};
        let control = Arc::new(XdpControlPlane::new(loader));
        match control.try_load_and_attach(iface, XdpMode::default()) {
            AttachOutcome::Attached => {
                tracing::info!(
                    target: "sng_edge::fw",
                    iface = %iface,
                    "XDP fast path attached to kernel"
                );
                control
            }
            AttachOutcome::Degraded(err) => {
                tracing::warn!(
                    target: "sng_edge::fw",
                    iface = %iface,
                    error = %err,
                    "XDP attach failed; degrading to nftables slow path"
                );
                Arc::new(XdpControlPlane::in_memory())
            }
        }
    }

    /// Build with an explicit nftables backend. Used by the
    /// integration tests so they can drive a
    /// [`sng_fw::MockNftables`] (or the in-memory test double the
    /// FW crate ships). Always selects the nftables data path.
    #[must_use]
    pub fn with_backend(backend: Arc<dyn NftablesBackend>) -> Self {
        let engine = Arc::new(FirewallEngine::new(backend));
        let datapath: Arc<dyn DataPathBackend> =
            Arc::new(NftablesDataPath::new(Arc::clone(&engine)));
        Self::from_parts(engine, datapath)
    }

    /// Assemble from an engine + a chosen data-path backend.
    #[must_use]
    fn from_parts(engine: Arc<FirewallEngine>, datapath: Arc<dyn DataPathBackend>) -> Self {
        let (tx, rx) = watch::channel(None);
        Self {
            engine,
            datapath,
            rx,
            tx_anchor: tx,
            installs_total: Arc::new(AtomicU64::new(0)),
            install_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Borrow the engine. Used by other subsystems (e.g. the
    /// firewall-RPC handler in the comms adapter) for
    /// per-packet evaluation.
    #[must_use]
    pub fn engine(&self) -> &Arc<FirewallEngine> {
        &self.engine
    }

    /// The name of the live data-path backend (`"nftables"` /
    /// `"ebpf"`). Surfaced on the health detail line so an
    /// operator can confirm which path is enforcing.
    #[must_use]
    pub fn datapath_name(&self) -> &'static str {
        self.datapath.name()
    }

    /// Producer half of the ruleset channel. Hand the result to
    /// any subsystem that produces compiled rulesets (the
    /// policy puller, integration tests).
    #[must_use]
    pub fn ruleset_sender(&self) -> watch::Sender<Option<Arc<CompiledRuleSet>>> {
        self.tx_anchor.clone()
    }
}

#[async_trait]
impl Subsystem for FwSubsystem {
    fn name(&self) -> &'static str {
        "fw"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let datapath = Arc::clone(&self.datapath);
        let mut rx = self.rx.clone();
        let installs_total = Arc::clone(&self.installs_total);
        let install_failures = Arc::clone(&self.install_failures);
        Ok(task::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    res = rx.changed() => {
                        if res.is_err() {
                            // All senders dropped — channel
                            // closed. The supervisor will see
                            // this as an early exit and drain
                            // every other subsystem, which is
                            // the correct semantics.
                            break;
                        }
                        let next = rx.borrow_and_update().clone();
                        let Some(ruleset) = next else { continue };
                        // The backend installs by reference (the
                        // nftables path clones internally for its
                        // memory-first swap; the eBPF path borrows
                        // to translate the hot-path subset), so no
                        // unwrap-or-clone of the Arc is needed.
                        match datapath.install_rules(&ruleset).await {
                            Ok(()) => {
                                installs_total.fetch_add(1, Ordering::Relaxed);
                                tracing::info!(
                                    target: "sng_edge::fw",
                                    "firewall ruleset installed"
                                );
                            }
                            Err(e) => {
                                install_failures.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(
                                    target: "sng_edge::fw",
                                    error = %e,
                                    "firewall ruleset install failed"
                                );
                            }
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

/// Derive the firewall subsystem health from its install counters and
/// whether the engine currently holds a ruleset.
///
/// `Down` is reserved for *no live enforcement*: nothing has ever
/// installed successfully **and** the engine holds no ruleset. This last
/// clause matters for the eBPF data path — a failed XDP offload still
/// commits the authoritative ruleset to the nftables fallback, so
/// `has_ruleset` is `true` and enforcement is live even though
/// `install_failures > 0` and `installs_total == 0`. That state is
/// `Degraded` (fast path lost, slow path enforcing), never `Down`.
fn fw_health_status(installs: u64, failures: u64, has_ruleset: bool) -> HealthStatus {
    if failures > 0 && installs == 0 && !has_ruleset {
        HealthStatus::Down
    } else if failures > 0 || !has_ruleset {
        HealthStatus::Degraded
    } else {
        HealthStatus::Up
    }
}

#[async_trait]
impl HealthCheck for FwSubsystem {
    fn name(&self) -> &'static str {
        "fw"
    }

    async fn check(&self) -> SubsystemHealth {
        let installs = self.installs_total.load(Ordering::Relaxed);
        let failures = self.install_failures.load(Ordering::Relaxed);
        let has_ruleset = self.engine.current_ruleset().is_some();
        // Whether enforcement is genuinely running in the kernel fast path.
        // For the eBPF backend on the in-memory control plane this is
        // `false`, so the health line distinguishes "ebpf selected" from
        // "ebpf actually offloading" — see `FwSubsystem::new`.
        let kernel_offload = self.datapath.get_stats().is_ok_and(|s| s.kernel_offload);
        let status = fw_health_status(installs, failures, has_ruleset);
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "datapath={}, kernel_offload={kernel_offload}, installs={installs}, failures={failures}, has_ruleset={has_ruleset}",
                self.datapath.name()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use sng_fw::MockNftables;
    use std::time::Duration;

    #[tokio::test]
    async fn subsystem_idles_and_drains_cleanly() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let sub = FwSubsystem::with_backend(backend);
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("drain budget");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn hardware_selection_builds_software_offload_datapath() {
        let cfg = FwConfig {
            offload_capacity: 8,
            ..FwConfig::default()
        };
        let sub = FwSubsystem::new(&cfg, DataPathSelection::Hardware);
        // The hardware-offload tier is genuinely wired and selectable.
        assert_eq!(sub.datapath.name(), "hardware-offload");
        // No real silicon on a CI host: the software model backs the tier
        // and must honestly report no kernel/hardware offload so the
        // health line and capabilities never overstate acceleration.
        let stats = sub.datapath.get_stats().expect("stats");
        assert!(!stats.kernel_offload);
        let caps = sub.datapath.capabilities();
        assert!(!caps.hardware_offload, "software model is not silicon");
        assert!(caps.l3l4_filter, "the tier still filters L3/L4");
    }

    #[test]
    fn build_offload_device_falls_back_to_software_for_host_accelerator() {
        // The shipped boot probe reports a commodity host with no offload
        // silicon, so the firewall must build the software model.
        let device = FwSubsystem::build_offload_device(&crate::hardware::HostAccelerator, 16);
        assert_eq!(device.descriptor().name, "software-model");
        assert!(!device.descriptor().silicon);
        assert_eq!(device.descriptor().capacity, 16);
    }

    #[test]
    fn build_offload_device_uses_software_model_even_for_attested_silicon() {
        // No vendor driver ships in this build, so even an attested,
        // offload-capable accelerator is backed by the software model
        // rather than a fabricated driver — the honest boundary.
        #[derive(Debug)]
        struct AttestedSilicon;
        impl crate::hardware::HardwareAccelerator for AttestedSilicon {
            fn descriptor(&self) -> crate::hardware::HardwareDescriptor {
                crate::hardware::HardwareDescriptor {
                    name: "test-smartnic".to_owned(),
                    tpm_rooted: true,
                    offload_capable: true,
                }
            }
            fn attest(
                &self,
            ) -> Result<crate::hardware::AttestationReport, Box<dyn std::error::Error + Send + Sync>>
            {
                Ok(crate::hardware::AttestationReport {
                    trusted: true,
                    quote: vec![0x01],
                })
            }
        }
        let device = FwSubsystem::build_offload_device(&AttestedSilicon, 32);
        assert_eq!(device.descriptor().name, "software-model");
        assert!(!device.descriptor().silicon);
    }

    #[tokio::test]
    async fn health_is_degraded_before_first_install() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let sub = FwSubsystem::with_backend(backend);
        let h = sub.check().await;
        // No ruleset installed yet — degraded (operator's
        // signal that the policy puller hasn't delivered).
        assert_eq!(h.status, HealthStatus::Degraded);
    }

    /// A loader that loads but whose XDP program never attaches (older
    /// kernel / busy NIC), and which—like the real `AyaLoader` before the
    /// BPF object crate lands—rejects every map update as `Unsupported`.
    /// Driving `control_plane_for_loader` with it reproduces the degraded
    /// attach the fail-soft path must not keep wrapping.
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    #[derive(Debug)]
    struct AttachFailLoader;

    #[cfg(all(feature = "xdp", target_os = "linux"))]
    impl sng_ebpf::ProgramLoader for AttachFailLoader {
        fn is_supported(&self) -> bool {
            true
        }
        fn load(&self) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn attach_xdp(&self, _: &str, _: sng_ebpf::XdpMode) -> Result<(), sng_ebpf::EbpfError> {
            Err(sng_ebpf::EbpfError::Attach("forced attach failure".into()))
        }
        fn attach_tc_egress(&self, _: &str) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn detach(&self) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn pin(&self, _: &std::path::Path) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn update_rules(&self, _: &sng_ebpf::XdpRuleSet) -> Result<(), sng_ebpf::EbpfError> {
            Err(sng_ebpf::EbpfError::Unsupported(
                "no attached object".into(),
            ))
        }
        fn update_classification(
            &self,
            _: &sng_ebpf::Classifier,
        ) -> Result<(), sng_ebpf::EbpfError> {
            Err(sng_ebpf::EbpfError::Unsupported(
                "no attached object".into(),
            ))
        }
        fn update_steering(
            &self,
            _: &sng_ebpf::EgressSteeringTable,
        ) -> Result<(), sng_ebpf::EbpfError> {
            Err(sng_ebpf::EbpfError::Unsupported(
                "no attached object".into(),
            ))
        }
        fn update_ddos(&self, _: &sng_ebpf::DdosConfig) -> Result<(), sng_ebpf::EbpfError> {
            Err(sng_ebpf::EbpfError::Unsupported(
                "no attached object".into(),
            ))
        }
    }

    /// Regression: a degraded attach must hand back the userspace model, not
    /// the unattachable loader. Otherwise every `install_rules` on the
    /// resulting plane fails (the loader rejects all map updates), turning a
    /// one-time attach failure into perpetual per-reload errors. Asserting an
    /// install succeeds proves we fell back to the in-memory model.
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    #[test]
    fn degraded_attach_falls_back_to_userspace_model() {
        use sng_ebpf::{XdpRule, XdpRuleAction, XdpRuleSet};

        let control = FwSubsystem::control_plane_for_loader(Box::new(AttachFailLoader), "eth0");

        // No kernel offload — the slow path carries enforcement.
        assert!(!control.capabilities().kernel_offload);

        // The decisive check: install_rules must succeed. With the
        // unattachable loader still wrapped this returns `Unsupported`.
        let rules = XdpRuleSet::new(
            vec![XdpRule::catch_all("a", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        control
            .install_rules(rules)
            .expect("degraded attach must fall back to a plane that accepts rule installs");
    }

    #[test]
    fn health_status_decision_table() {
        // Fresh start: nothing installed, no ruleset — degraded, not down.
        assert_eq!(fw_health_status(0, 0, false), HealthStatus::Degraded);
        // Healthy: a successful install and a live ruleset.
        assert_eq!(fw_health_status(1, 0, true), HealthStatus::Up);
        // Total failure, nothing enforcing — the only genuine `Down`.
        assert_eq!(fw_health_status(0, 1, false), HealthStatus::Down);
        // eBPF regression case: the XDP offload failed (failures>0,
        // installs==0) but the nftables fallback committed the ruleset, so
        // enforcement is live — `Degraded`, never `Down`.
        assert_eq!(fw_health_status(0, 1, true), HealthStatus::Degraded);
        // A transient failure after earlier success stays degraded.
        assert_eq!(fw_health_status(3, 1, true), HealthStatus::Degraded);
    }
}
