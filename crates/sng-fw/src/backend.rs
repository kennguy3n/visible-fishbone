//! Data-path backend abstraction — the seam between the firewall
//! engine and *where* enforcement physically happens.
//!
//! [`DataPathBackend`] lets the edge select an enforcement substrate at
//! startup without the rest of the firewall stack caring which one is
//! live:
//!
//! * [`NftablesDataPath`] — the default. Wraps the existing
//!   [`crate::FirewallEngine`] / [`crate::nftables`] slow path: compiles
//!   a ruleset and applies it to the kernel via `nft -f`.
//! * [`EbpfDataPath`] — the opt-in fast path. Translates the hot-path
//!   L3/L4 subset of a compiled ruleset into the `sng-ebpf` userspace
//!   XDP model and installs it, *and* keeps an [`NftablesDataPath`]
//!   fallback for the rules XDP cannot express (subject-gated, zoned, or
//!   L7 / inspect / steer verdicts). XDP accelerates the unambiguous
//!   early drops; everything else flows to nftables exactly as before.
//! * [`HardwareOffloadDataPath`] — the opt-in offload fast path. Programs
//!   the same hot-path L3/L4 subset onto a pluggable
//!   [`crate::offload::OffloadDevice`] (a SmartNIC / FPGA / DPDK / VPP
//!   driver, or the in-process [`crate::offload::SoftwareOffloadDevice`]
//!   model) behind an attestation gate, and keeps an [`NftablesDataPath`]
//!   fallback for everything the device cannot express — mirroring
//!   [`EbpfDataPath`]. Real silicon (ARCHITECTURE.md §4.1's VPP/DPDK fast
//!   path, the TPM-rooted appliance SKUs) plugs in as
//!   an `OffloadDevice` implementor without touching this backend.
//!
//! ## Why the trait is async
//!
//! `install_rules` is `async` rather than a synchronous `fn` because the
//! nftables apply this crate already owns is `async` (it shells out to
//! `nft -f` so the data path is never blocked). Bridging that to a sync
//! trait method would force a `block_on`, which panics inside the
//! supervisor's Tokio runtime. The trait is therefore `async` (via
//! [`async_trait`]) — the correct shape for an operation that genuinely
//! awaits the kernel — while `get_stats` / `capabilities` stay sync.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use sng_ebpf::{
    Classifier, PortRange as XdpPortRange, XdpControlPlane, XdpRule, XdpRuleAction, XdpRuleSet,
};
use sng_policy_eval::matcher::SubjectMatch;

use crate::compile::CompiledRuleSet;
use crate::engine::FirewallEngine;
use crate::error::FirewallError;
use crate::nftables::{NftablesBackend, ShellNftables};
use crate::offload::OffloadDevice;
use crate::rule::RuleAction;

/// Point-in-time counters describing one data-path backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPathStats {
    /// Stable backend name (`"nftables"`, `"ebpf"`, …).
    pub backend: &'static str,
    /// Rules currently installed in the substrate this backend reports
    /// for. For [`EbpfDataPath`] this is the hot-path subset offloaded to
    /// XDP, not the full nftables ruleset.
    pub rules_installed: u64,
    /// Successful installs since startup.
    pub installs_total: u64,
    /// Failed installs since startup.
    pub install_failures: u64,
    /// True iff enforcement is genuinely running in the kernel fast path
    /// (a loaded XDP program), as opposed to nftables or a userspace
    /// model.
    pub kernel_offload: bool,
}

/// What a data-path backend can enforce. The edge uses this to decide
/// whether a backend covers the policy it needs (e.g. an L7-heavy policy
/// on a backend with no `l7_inspection` must keep the nftables fallback).
///
/// The five flags are independent capability bits kept as named bools
/// (rather than a bitflags type) so they render legibly in logs and the
/// health surface; `struct_excessive_bools` does not add signal here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DataPathCapabilities {
    /// Stable backend name.
    pub name: &'static str,
    /// Enforces L3/L4 (CIDR / port / protocol) rules.
    pub l3l4_filter: bool,
    /// Handles L7 inspection / TLS / steering verdicts (directly or via a
    /// fallback the backend owns).
    pub l7_inspection: bool,
    /// Runs in the kernel fast path (XDP).
    pub kernel_offload: bool,
    /// Provides egress traffic steering (TC).
    pub egress_steering: bool,
    /// Uses NIC / SmartNIC hardware offload.
    pub hardware_offload: bool,
}

/// A pluggable enforcement substrate. Selected once at edge startup; the
/// install loop drives [`Self::install_rules`] on every bundle reload.
#[async_trait]
pub trait DataPathBackend: Send + Sync + std::fmt::Debug {
    /// Stable backend name, matching [`DataPathCapabilities::name`].
    fn name(&self) -> &'static str;

    /// Install a compiled ruleset into the data path. Replaces any
    /// previously installed ruleset.
    ///
    /// # Errors
    ///
    /// Returns the backend-specific [`FirewallError`] on a
    /// validation / apply / map-update failure.
    async fn install_rules(&self, compiled: &CompiledRuleSet) -> Result<(), FirewallError>;

    /// Point-in-time statistics.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError`] if the backend cannot read its counters
    /// (never, for the in-process backends).
    fn get_stats(&self) -> Result<DataPathStats, FirewallError>;

    /// Static capability descriptor.
    fn capabilities(&self) -> DataPathCapabilities;
}

/// The default nftables data path. Wraps a shared [`FirewallEngine`],
/// whose `install` performs the memory-first / kernel-second swap and the
/// `nft -f` apply.
#[derive(Debug)]
pub struct NftablesDataPath {
    engine: Arc<FirewallEngine>,
    installs_total: AtomicU64,
    install_failures: AtomicU64,
}

impl NftablesDataPath {
    /// Wrap an existing engine.
    #[must_use]
    pub fn new(engine: Arc<FirewallEngine>) -> Self {
        Self {
            engine,
            installs_total: AtomicU64::new(0),
            install_failures: AtomicU64::new(0),
        }
    }

    /// Build over a [`ShellNftables`] honouring an optional `nft` binary
    /// override, constructing the engine internally. Returns the backend
    /// and a clone of the engine handle for callers (e.g. the per-packet
    /// evaluation path) that need it.
    #[must_use]
    pub fn with_shell(nft_binary: Option<&str>) -> (Self, Arc<FirewallEngine>) {
        let backend: Arc<dyn NftablesBackend> = match nft_binary {
            Some(p) => Arc::new(ShellNftables::with_binary(p.to_owned())),
            None => Arc::new(ShellNftables::new()),
        };
        let engine = Arc::new(FirewallEngine::new(backend));
        (Self::new(Arc::clone(&engine)), engine)
    }

    /// Borrow the wrapped engine.
    #[must_use]
    pub fn engine(&self) -> &Arc<FirewallEngine> {
        &self.engine
    }
}

#[async_trait]
impl DataPathBackend for NftablesDataPath {
    fn name(&self) -> &'static str {
        "nftables"
    }

    async fn install_rules(&self, compiled: &CompiledRuleSet) -> Result<(), FirewallError> {
        match self.engine.install(compiled.clone()).await {
            Ok(()) => {
                self.installs_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.install_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn get_stats(&self) -> Result<DataPathStats, FirewallError> {
        let rules_installed = self
            .engine
            .current_ruleset()
            .as_ref()
            .as_ref()
            .map_or(0, |rs| rs.rules.len() as u64);
        Ok(DataPathStats {
            backend: self.name(),
            rules_installed,
            installs_total: self.installs_total.load(Ordering::Relaxed),
            install_failures: self.install_failures.load(Ordering::Relaxed),
            kernel_offload: false,
        })
    }

    fn capabilities(&self) -> DataPathCapabilities {
        DataPathCapabilities {
            name: "nftables",
            l3l4_filter: true,
            // nftables marks Inspect/Steer flows for the SWG/IPS/SD-WAN
            // chains, so the L7 path is covered by this backend.
            l7_inspection: true,
            kernel_offload: false,
            egress_steering: false,
            hardware_offload: false,
        }
    }
}

/// The eBPF/XDP fast path. Offloads the hot-path L3/L4 subset of a
/// compiled ruleset to XDP and defers everything else to an
/// [`NftablesDataPath`] fallback.
#[derive(Debug)]
pub struct EbpfDataPath {
    control: Arc<XdpControlPlane>,
    fallback: NftablesDataPath,
    installs_total: AtomicU64,
    install_failures: AtomicU64,
}

impl EbpfDataPath {
    /// Build over an XDP control plane and an nftables fallback. The
    /// fallback owns the full ruleset (XDP only accelerates the
    /// unambiguous early drops), so its engine is the one the per-packet
    /// evaluation path should use.
    #[must_use]
    pub fn new(control: Arc<XdpControlPlane>, fallback: NftablesDataPath) -> Self {
        Self {
            control,
            fallback,
            installs_total: AtomicU64::new(0),
            install_failures: AtomicU64::new(0),
        }
    }

    /// Borrow the nftables fallback (and thus the shared engine).
    #[must_use]
    pub fn fallback(&self) -> &NftablesDataPath {
        &self.fallback
    }

    /// Borrow the XDP control plane.
    #[must_use]
    pub fn control(&self) -> &Arc<XdpControlPlane> {
        &self.control
    }
}

#[async_trait]
impl DataPathBackend for EbpfDataPath {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    async fn install_rules(&self, compiled: &CompiledRuleSet) -> Result<(), FirewallError> {
        // Install the authoritative nftables ruleset *first*. It owns the
        // full policy and the per-packet evaluation path reads its engine,
        // so it must commit before the XDP fast path is allowed to advance.
        // If it fails it rolls back its own swap; we return without touching
        // XDP, leaving the fast path consistent with the last-good ruleset
        // rather than holding a newer version than nftables is enforcing.
        if let Err(e) = self.fallback.install_rules(compiled).await {
            self.install_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        // nftables committed. Now offload the hot-path subset to XDP. A
        // failure here is a real error (bad rule / map update) and is
        // surfaced, but enforcement is never lost because nftables already
        // holds the authoritative full ruleset.
        let hot = compile_hot_path(compiled);
        if let Err(e) = self.control.install_rules(hot).map_err(map_ebpf_err) {
            // The XDP update failed, but nftables already committed the
            // authoritative ruleset above. Flush the fast path to a
            // pass-through so it can never enforce a ruleset older than
            // nftables — without this, once a real kernel loader is
            // attached a failed map update would leave the kernel XDP
            // program matching stale verdicts while nftables enforces the
            // new ones. Best-effort: if the flush itself fails there is no
            // safe fast-path state to fall back to, so we log loudly and
            // still surface the original error (nftables stays
            // authoritative regardless).
            if let Err(flush_err) = self.control.clear_rules().map_err(map_ebpf_err) {
                tracing::error!(
                    target: "sng_fw::backend",
                    error = %flush_err,
                    "failed to flush XDP fast path after a rule-update \
                     failure; the fast path may hold stale rules until the \
                     next successful install"
                );
            }
            self.install_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        // Rules are live on the fast path; now push the destination-IP
        // traffic-class table to the XDP classify stage. The kernel runs
        // classify *before* the firewall chains, and its meta slot fails
        // closed (drop) while unwritten — so installing the table, even an
        // empty one whose inspect-full fallback punts every flow to the
        // slow path, is what makes the classify stage usable rather than a
        // drop-all, and a populated table activates the per-tier verdicts
        // (trusted fast-pass, blocked drop) the kernel pipeline already
        // implements. On failure flush the table back to that empty
        // inspect-full state rather than leave a stale tier map that could
        // mis-classify a flow, then surface the error; nftables holds the
        // authoritative full policy regardless.
        if let Err(e) = self
            .control
            .install_classification(compiled.classification.clone())
            .map_err(map_ebpf_err)
        {
            if let Err(flush_err) = self
                .control
                .install_classification(Classifier::default())
                .map_err(map_ebpf_err)
            {
                tracing::error!(
                    target: "sng_fw::backend",
                    error = %flush_err,
                    "failed to flush XDP classification table after an \
                     update failure; the classify stage may hold stale \
                     tiers until the next successful install"
                );
            }
            self.install_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        self.installs_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn get_stats(&self) -> Result<DataPathStats, FirewallError> {
        let xdp = self.control.stats();
        Ok(DataPathStats {
            backend: self.name(),
            rules_installed: xdp.rules_active,
            installs_total: self.installs_total.load(Ordering::Relaxed),
            install_failures: self.install_failures.load(Ordering::Relaxed),
            kernel_offload: xdp.kernel_offload,
        })
    }

    fn capabilities(&self) -> DataPathCapabilities {
        let xdp = self.control.capabilities();
        DataPathCapabilities {
            name: "ebpf",
            l3l4_filter: true,
            // L7 is covered by the nftables fallback this backend owns.
            l7_inspection: true,
            kernel_offload: xdp.kernel_offload,
            egress_steering: xdp.tc_egress,
            hardware_offload: false,
        }
    }
}

/// Map the XDP hot-path action a [`RuleAction`] compiles to, or `None`
/// when the action needs slow-path handling XDP cannot express.
///
/// `Allow` → `Pass` (continue to nftables / the stack), `Deny` → `Drop`
/// (the acceleration that matters — dropped at the earliest hook).
/// `Inspect` / `Steer` are terminal accepts that need a slow-path mark;
/// `Log` is non-terminal. None of those map to a terminal XDP verdict.
fn hot_path_action(action: RuleAction) -> Option<XdpRuleAction> {
    match action {
        RuleAction::Allow => Some(XdpRuleAction::Pass),
        RuleAction::Deny => Some(XdpRuleAction::Drop),
        RuleAction::Inspect | RuleAction::Steer | RuleAction::Log => None,
    }
}

/// Translate the hot-path-eligible **prefix** of a compiled ruleset into
/// the XDP rule set, preserving first-match semantics exactly.
///
/// A rule is XDP-eligible iff its predicate is pure L3/L4 (no subject
/// gate, no zone filter) and its action maps to a terminal XDP verdict
/// ([`hot_path_action`]). Eligible `Allow`/`Deny` rules are emitted in
/// source order; non-terminal `Log` rules are skipped (they never change
/// a verdict).
///
/// Crucially, on the **first** rule XDP cannot model, translation stops:
/// every later rule's verdict could depend on a decision XDP can't make,
/// so the fast path must defer the remainder (and the no-match default)
/// to nftables by passing. Only when the *entire* rule list was modelled
/// may the chain default itself be accelerated to a terminal XDP verdict.
/// This guarantees the XDP fast path never drops a packet nftables would
/// have accepted, nor accepts one nftables would have dropped.
#[must_use]
pub fn compile_hot_path(compiled: &CompiledRuleSet) -> XdpRuleSet {
    let mut rules = Vec::new();
    let mut complete = true;
    for rule in &compiled.rules {
        // Non-terminal Log rules don't change the verdict; skip without
        // disturbing first-match ordering.
        if rule.action == RuleAction::Log {
            continue;
        }
        let eligible = rule.matches.subject == SubjectMatch::Any
            && rule.from_zones.is_empty()
            && rule.to_zones.is_empty();
        let Some(action) = hot_path_action(rule.action) else {
            complete = false;
            break;
        };
        if !eligible {
            complete = false;
            break;
        }
        rules.push(XdpRule {
            id: rule.id.clone(),
            src_cidrs: rule.matches.src_cidrs.clone(),
            dst_cidrs: rule.matches.dst_cidrs.clone(),
            src_ports: rule
                .matches
                .src_ports
                .iter()
                .map(|p| XdpPortRange {
                    from: p.from,
                    to: p.to,
                })
                .collect(),
            dst_ports: rule
                .matches
                .dst_ports
                .iter()
                .map(|p| XdpPortRange {
                    from: p.from,
                    to: p.to,
                })
                .collect(),
            protocol: rule.matches.protocol.iana_number(),
            action,
        });
    }
    // The chain default may only be accelerated when the whole eligible
    // prefix was modelled; otherwise an un-modelled earlier rule could
    // have changed the verdict, so the fast path must pass the no-match
    // case to nftables.
    let default_action = if complete {
        hot_path_action(compiled.default_action).unwrap_or(XdpRuleAction::Pass)
    } else {
        XdpRuleAction::Pass
    };
    XdpRuleSet::new(rules, default_action)
}

/// Map an `sng-ebpf` error into the firewall error taxonomy so callers
/// see one error type regardless of backend.
pub(crate) fn map_ebpf_err(e: sng_ebpf::EbpfError) -> FirewallError {
    use sng_ebpf::EbpfError;
    match e {
        EbpfError::RuleInvalid(m) => FirewallError::RuleInvalid(m),
        // Everything else is an apply / load / map / unsupported failure
        // on the data path — bucket with IO so dashboards separate it
        // from operator-authored config errors.
        other => FirewallError::Io(other.to_string()),
    }
}

/// The hardware-offload fast path. Programs the hot-path L3/L4 subset of
/// a compiled ruleset onto a pluggable [`OffloadDevice`] (a SmartNIC /
/// FPGA / DPDK / VPP driver, or the in-process
/// [`crate::offload::SoftwareOffloadDevice`] model) and defers everything
/// the device cannot express to an [`NftablesDataPath`] fallback.
///
/// It mirrors [`EbpfDataPath`]'s nftables-authoritative-first contract,
/// with one extra gate before the fast path is trusted: the device must
/// **attest** (ARCHITECTURE.md §4.1). The slow path is
/// always committed first, so a device that cannot attest — or whose
/// program fails — degrades to nftables-only enforcement, never to a
/// stale or unmeasured fast path.
#[derive(Debug)]
pub struct HardwareOffloadDataPath {
    device: Arc<dyn OffloadDevice>,
    fallback: NftablesDataPath,
    installs_total: AtomicU64,
    install_failures: AtomicU64,
}

impl HardwareOffloadDataPath {
    /// Build over an offload device and an nftables fallback. The fallback
    /// owns the full ruleset (the device only accelerates the hot-path
    /// subset), so its engine is the one the per-packet evaluation path
    /// should use — exactly as for [`EbpfDataPath`].
    #[must_use]
    pub fn new(device: Arc<dyn OffloadDevice>, fallback: NftablesDataPath) -> Self {
        Self {
            device,
            fallback,
            installs_total: AtomicU64::new(0),
            install_failures: AtomicU64::new(0),
        }
    }

    /// Borrow the offload device.
    #[must_use]
    pub fn device(&self) -> &Arc<dyn OffloadDevice> {
        &self.device
    }

    /// Borrow the nftables fallback (and thus the shared engine).
    #[must_use]
    pub fn fallback(&self) -> &NftablesDataPath {
        &self.fallback
    }

    /// Flush the device to pass-through, logging loudly on failure. Called
    /// after the authoritative nftables ruleset has committed but the
    /// device must not (or could not) be advanced — so the device can
    /// never enforce a ruleset older than nftables. Best-effort: if the
    /// flush itself fails there is no safe device state to fall back to,
    /// but nftables stays authoritative regardless.
    fn flush_device_or_log(&self) {
        if let Err(flush_err) = self.device.clear() {
            tracing::error!(
                target: "sng_fw::backend",
                error = %flush_err,
                "failed to flush hardware offload device after an install \
                 failure; the device may hold stale rules until the next \
                 successful install"
            );
        }
    }
}

#[async_trait]
impl DataPathBackend for HardwareOffloadDataPath {
    fn name(&self) -> &'static str {
        "hardware-offload"
    }

    async fn install_rules(&self, compiled: &CompiledRuleSet) -> Result<(), FirewallError> {
        // 1. nftables is authoritative — commit it first, exactly as the
        //    eBPF path does. If it fails we return without touching the
        //    device, leaving the fast path consistent with the last-good
        //    ruleset.
        if let Err(e) = self.fallback.install_rules(compiled).await {
            self.install_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        // 2. Attest the device before trusting it to enforce. A device
        //    that cannot attest (or attests untrusted) must never program
        //    rules — flush it to pass-through so the authoritative nftables
        //    ruleset carries enforcement alone.
        match self.device.attest() {
            Ok(report) if report.trusted => {}
            Ok(_) => {
                self.flush_device_or_log();
                self.install_failures.fetch_add(1, Ordering::Relaxed);
                return Err(FirewallError::Io(format!(
                    "offload device '{}' failed attestation; refusing to \
                     offload (nftables remains authoritative)",
                    self.device.descriptor().name
                )));
            }
            Err(e) => {
                self.flush_device_or_log();
                self.install_failures.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        }

        // 3. Program the hot-path subset onto the attested device. On
        //    failure, flush the device so it can never enforce a ruleset
        //    older than nftables (which already committed above).
        let hot = compile_hot_path(compiled);
        match self.device.program(&hot) {
            Ok(_) => {
                self.installs_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.flush_device_or_log();
                self.install_failures.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn get_stats(&self) -> Result<DataPathStats, FirewallError> {
        Ok(DataPathStats {
            backend: self.name(),
            rules_installed: self.device.programmed_rules(),
            installs_total: self.installs_total.load(Ordering::Relaxed),
            install_failures: self.install_failures.load(Ordering::Relaxed),
            // Honest: only real silicon is hardware offload. The software
            // model reports `false` even when selected as this backend,
            // exactly as `EbpfDataPath` reports `false` on the in-memory
            // control plane.
            kernel_offload: self.device.descriptor().silicon,
        })
    }

    fn capabilities(&self) -> DataPathCapabilities {
        let silicon = self.device.descriptor().silicon;
        DataPathCapabilities {
            name: "hardware-offload",
            l3l4_filter: true,
            // L7 is covered by the nftables fallback this backend owns.
            l7_inspection: true,
            // Both bits track whether the device is genuine silicon, so the
            // health surface never reads a software model as accelerated.
            kernel_offload: silicon,
            // Egress steering is not modelled by the offload device; it
            // rides the nftables fallback, which does not accelerate it.
            egress_steering: false,
            hardware_offload: silicon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::MockNftables;
    use crate::rule::{FirewallRule, Protocol, RuleMatch};
    use ipnet::IpNet;
    use pretty_assertions::assert_eq;

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn l3l4_rule(id: &str, dst: &str, action: RuleAction) -> FirewallRule {
        FirewallRule {
            id: id.to_owned(),
            matches: RuleMatch {
                src_cidrs: Vec::new(),
                dst_cidrs: vec![cidr(dst)],
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                protocol: Protocol::Tcp,
                subject: SubjectMatch::Any,
            },
            action,
            from_zones: Vec::new(),
            to_zones: Vec::new(),
            description: String::new(),
        }
    }

    fn ruleset(rules: Vec<FirewallRule>, default_action: RuleAction) -> CompiledRuleSet {
        use crate::nat::NatTable;
        use crate::nftables::NftablesScript;
        use crate::zone::ZoneTable;
        CompiledRuleSet {
            rules,
            zones: ZoneTable::default(),
            nat: NatTable::default(),
            default_action,
            source_graph_id: "test-graph".to_owned(),
            source_graph_version: 1,
            script: NftablesScript::new(Vec::new()),
            classification: Classifier::default(),
        }
    }

    #[test]
    fn hot_path_translates_allow_and_deny_in_order() {
        let rs = ruleset(
            vec![
                l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow),
                l3l4_rule("d", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Deny,
        );
        let xdp = compile_hot_path(&rs);
        assert_eq!(xdp.len(), 2);
        assert_eq!(xdp.rules()[0].action, XdpRuleAction::Pass);
        assert_eq!(xdp.rules()[1].action, XdpRuleAction::Drop);
        // Whole list modelled → default-deny accelerated to Drop.
        assert_eq!(xdp.default_action(), XdpRuleAction::Drop);
    }

    #[test]
    fn hot_path_stops_at_first_inelegible_rule() {
        let rs = ruleset(
            vec![
                l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny),
                l3l4_rule("inspect", "10.0.0.0/8", RuleAction::Inspect),
                l3l4_rule("late", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Deny,
        );
        let xdp = compile_hot_path(&rs);
        // Only the leading Deny is modelled; translation stops at Inspect.
        assert_eq!(xdp.len(), 1);
        assert_eq!(xdp.rules()[0].id, "a");
        // Incomplete → default must defer to nftables (Pass).
        assert_eq!(xdp.default_action(), XdpRuleAction::Pass);
    }

    #[test]
    fn hot_path_skips_log_rules_without_truncating() {
        let rs = ruleset(
            vec![
                l3l4_rule("log", "0.0.0.0/0", RuleAction::Log),
                l3l4_rule("deny", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Allow,
        );
        let xdp = compile_hot_path(&rs);
        assert_eq!(xdp.len(), 1);
        assert_eq!(xdp.rules()[0].id, "deny");
        // Whole list modelled (Log skipped) → default-allow → Pass.
        assert_eq!(xdp.default_action(), XdpRuleAction::Pass);
    }

    #[test]
    fn hot_path_stops_at_subject_gated_rule() {
        let mut subj_rule = l3l4_rule("subj", "10.0.0.0/8", RuleAction::Deny);
        subj_rule.matches.subject = SubjectMatch::Literal {
            value: "alice".to_owned(),
        };
        let rs = ruleset(
            vec![
                l3l4_rule("first", "203.0.113.0/24", RuleAction::Deny),
                subj_rule,
            ],
            RuleAction::Allow,
        );
        let xdp = compile_hot_path(&rs);
        assert_eq!(xdp.len(), 1);
        assert_eq!(xdp.default_action(), XdpRuleAction::Pass);
    }

    #[test]
    fn hot_path_stops_at_zoned_rule() {
        // A pure-L3/L4 Deny that is nonetheless zone-scoped is not XDP
        // eligible (the fast path can't evaluate zone membership), so
        // translation must stop at it exactly like the subject-gated case —
        // covering the second half of the eligibility predicate
        // (`from_zones`/`to_zones` empty) so the break invariant is pinned
        // for both gates.
        let mut zoned_rule = l3l4_rule("zoned", "10.0.0.0/8", RuleAction::Deny);
        zoned_rule.from_zones = vec!["trusted".to_owned()];
        let rs = ruleset(
            vec![
                l3l4_rule("first", "203.0.113.0/24", RuleAction::Deny),
                zoned_rule,
                l3l4_rule("late", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Allow,
        );
        let xdp = compile_hot_path(&rs);
        // Only the leading Deny is modelled; the zoned rule stops translation
        // and the trailing rule is dropped from the fast path.
        assert_eq!(xdp.len(), 1);
        assert_eq!(xdp.rules()[0].id, "first");
        // Incomplete → default must defer to nftables (Pass).
        assert_eq!(xdp.default_action(), XdpRuleAction::Pass);
    }

    #[test]
    fn hot_path_stops_at_to_zone_scoped_rule() {
        // Same as above but the gate is on `to_zones`, so both zone fields
        // are exercised by the eligibility check.
        let mut zoned_rule = l3l4_rule("to-zoned", "10.0.0.0/8", RuleAction::Allow);
        zoned_rule.to_zones = vec!["dmz".to_owned()];
        let rs = ruleset(
            vec![
                l3l4_rule("first", "203.0.113.0/24", RuleAction::Allow),
                zoned_rule,
            ],
            RuleAction::Deny,
        );
        let xdp = compile_hot_path(&rs);
        assert_eq!(xdp.len(), 1);
        assert_eq!(xdp.rules()[0].id, "first");
        assert_eq!(xdp.default_action(), XdpRuleAction::Pass);
    }

    #[tokio::test]
    async fn nftables_backend_installs_and_counts() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let dp = NftablesDataPath::new(engine);
        assert_eq!(dp.name(), "nftables");
        assert!(!dp.capabilities().kernel_offload);

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow)],
            RuleAction::Deny,
        );
        dp.install_rules(&rs).await.unwrap();
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 1);
        assert_eq!(stats.install_failures, 0);
    }

    #[tokio::test]
    async fn ebpf_backend_offloads_hot_path_and_keeps_fallback() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let control = Arc::new(XdpControlPlane::in_memory());
        let dp = EbpfDataPath::new(Arc::clone(&control), NftablesDataPath::new(engine));
        assert_eq!(dp.name(), "ebpf");

        let rs = ruleset(
            vec![
                l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow),
                l3l4_rule("d", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Deny,
        );
        dp.install_rules(&rs).await.unwrap();

        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.backend, "ebpf");
        // Both hot-path rules were offloaded to XDP.
        assert_eq!(stats.rules_installed, 2);
        assert_eq!(stats.installs_total, 1);
        // In-memory control plane is not real kernel offload.
        assert!(!stats.kernel_offload);
        // Fallback installed the full ruleset too.
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 1);
    }

    #[tokio::test]
    async fn ebpf_backend_pushes_classification_to_classify_stage() {
        // The compiled ruleset carries a steering-derived classifier;
        // a successful install must program it into the XDP classify
        // stage so the kernel pipeline can tier flows instead of
        // failing closed on an empty meta slot.
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let control = Arc::new(XdpControlPlane::in_memory());
        let dp = EbpfDataPath::new(Arc::clone(&control), NftablesDataPath::new(engine));

        let mut rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow)],
            RuleAction::Deny,
        );
        rs.classification = sng_ebpf::Classifier::new(vec![
            sng_ebpf::ClassRule::new(
                cidr("10.0.0.0/8"),
                None,
                sng_ebpf::TrafficClass::TrustedDirect,
            ),
            sng_ebpf::ClassRule::new(cidr("192.0.2.0/24"), None, sng_ebpf::TrafficClass::Block),
        ]);
        dp.install_rules(&rs).await.unwrap();

        // Both class rules live on the classify stage; the install
        // counted exactly once across rules + classification.
        assert_eq!(control.stats().classification_entries, 2);
        assert_eq!(dp.get_stats().unwrap().installs_total, 1);
    }

    #[tokio::test]
    async fn ebpf_backend_does_not_advance_xdp_when_nftables_fails() {
        // nftables is authoritative; if its apply fails, the XDP fast path
        // must not be left holding a newer ruleset than nftables enforces.
        let mock = Arc::new(MockNftables::new());
        mock.fail_next_apply("kernel rejected");
        let backend: Arc<dyn NftablesBackend> = Arc::clone(&mock) as _;
        let engine = Arc::new(FirewallEngine::new(backend));
        let control = Arc::new(XdpControlPlane::in_memory());
        let dp = EbpfDataPath::new(Arc::clone(&control), NftablesDataPath::new(engine));

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        // The install fails (the nftables apply was forced to fail)…
        assert!(dp.install_rules(&rs).await.is_err());
        // …and XDP was never advanced — no rules offloaded, no install
        // counted, the failure recorded.
        assert_eq!(control.stats().rules_active, 0);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 0);
        assert_eq!(stats.install_failures, 1);
    }

    /// A loader whose XDP rule updates fail after the first successful
    /// non-empty install, while the empty pass-through flush always
    /// succeeds. Lets us drive `EbpfDataPath` into the "nftables committed,
    /// XDP update failed" branch and observe the fast-path flush.
    #[derive(Debug, Default)]
    struct FlakyXdpLoader {
        nonempty_updates: AtomicU64,
    }

    impl sng_ebpf::ProgramLoader for FlakyXdpLoader {
        fn is_supported(&self) -> bool {
            false
        }
        fn load(&self) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn attach_xdp(&self, _: &str, _: sng_ebpf::XdpMode) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
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
        fn update_rules(&self, rules: &XdpRuleSet) -> Result<(), sng_ebpf::EbpfError> {
            // The pass-through flush (empty rule set) must always succeed —
            // it is the fail-safe.
            if rules.is_empty() {
                return Ok(());
            }
            // First real install succeeds; every later one fails, modelling a
            // map update that fails after a prior good ruleset is live.
            if self.nonempty_updates.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(sng_ebpf::EbpfError::Map("forced map update failure".into()))
            }
        }
        fn update_classification(
            &self,
            _: &sng_ebpf::Classifier,
        ) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn update_steering(
            &self,
            _: &sng_ebpf::EgressSteeringTable,
        ) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn update_ddos(&self, _: &sng_ebpf::DdosConfig) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn ebpf_backend_flushes_fast_path_when_xdp_update_fails() {
        // nftables (the authoritative slow path) succeeds on every install,
        // but the XDP map update fails on the *second* install. The fast
        // path must then be flushed to a pass-through so it cannot keep
        // enforcing the first install's (now stale) rules.
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let control = Arc::new(XdpControlPlane::new(Box::new(FlakyXdpLoader::default())));
        let dp = EbpfDataPath::new(Arc::clone(&control), NftablesDataPath::new(engine));

        // First install: nftables + XDP both succeed → one rule offloaded.
        let rs1 = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        dp.install_rules(&rs1).await.unwrap();
        assert_eq!(control.stats().rules_active, 1);

        // Second install: nftables commits, but the XDP update fails. The
        // backend surfaces the error AND flushes the fast path.
        let rs2 = ruleset(
            vec![
                l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny),
                l3l4_rule("b", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Deny,
        );
        assert!(dp.install_rules(&rs2).await.is_err());

        // Fast path was flushed to pass-through (no stale rules left), so it
        // defers entirely to the nftables ruleset that did commit.
        assert_eq!(control.stats().rules_active, 0);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 1);
        assert_eq!(stats.install_failures, 1);
        // nftables committed both installs — enforcement was never lost.
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 2);
    }

    /// A loader whose rule updates always succeed but whose
    /// *classification* update fails for any populated table, while
    /// the empty flush succeeds. Drives `EbpfDataPath` into the
    /// "rules committed, classification update failed" branch.
    #[derive(Debug, Default)]
    struct ClassFlakyXdpLoader;

    impl sng_ebpf::ProgramLoader for ClassFlakyXdpLoader {
        fn is_supported(&self) -> bool {
            false
        }
        fn load(&self) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn attach_xdp(&self, _: &str, _: sng_ebpf::XdpMode) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
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
        fn update_rules(&self, _: &XdpRuleSet) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn update_classification(
            &self,
            classifier: &sng_ebpf::Classifier,
        ) -> Result<(), sng_ebpf::EbpfError> {
            // The empty flush is the fail-safe and must always
            // succeed; a populated install is forced to fail.
            if classifier.is_empty() {
                Ok(())
            } else {
                Err(sng_ebpf::EbpfError::Map(
                    "forced classification update failure".into(),
                ))
            }
        }
        fn update_steering(
            &self,
            _: &sng_ebpf::EgressSteeringTable,
        ) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
        fn update_ddos(&self, _: &sng_ebpf::DdosConfig) -> Result<(), sng_ebpf::EbpfError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn ebpf_backend_flushes_classification_when_update_fails() {
        // Rules install fine, but the classify-stage map update fails.
        // The backend must surface the error and flush the classify
        // stage back to the empty (inspect-full / punt) table rather
        // than leave a partial tier map that could mis-classify flows.
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let control = Arc::new(XdpControlPlane::new(Box::new(ClassFlakyXdpLoader)));
        let dp = EbpfDataPath::new(Arc::clone(&control), NftablesDataPath::new(engine));

        let mut rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow)],
            RuleAction::Deny,
        );
        rs.classification = sng_ebpf::Classifier::new(vec![sng_ebpf::ClassRule::new(
            cidr("10.0.0.0/8"),
            None,
            sng_ebpf::TrafficClass::TrustedDirect,
        )]);

        assert!(dp.install_rules(&rs).await.is_err());
        // Classify stage flushed back to empty; the failure was counted
        // and no install was credited.
        assert_eq!(control.stats().classification_entries, 0);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 0);
        assert_eq!(stats.install_failures, 1);
    }

    use crate::offload::{
        OffloadAttestation, OffloadDescriptor, OffloadDevice, SoftwareOffloadDevice,
    };

    /// Test double: reachable but attests *untrusted* (measurement
    /// mismatch). The data path must refuse to program it and flush it.
    #[derive(Debug, Default)]
    struct UntrustedDevice {
        cleared: AtomicU64,
    }

    impl OffloadDevice for UntrustedDevice {
        fn descriptor(&self) -> OffloadDescriptor {
            OffloadDescriptor {
                name: "untrusted".to_owned(),
                silicon: true,
                capacity: 16,
            }
        }
        fn attest(&self) -> Result<OffloadAttestation, FirewallError> {
            Ok(OffloadAttestation {
                trusted: false,
                measurement: Vec::new(),
            })
        }
        fn program(&self, _: &XdpRuleSet) -> Result<usize, FirewallError> {
            panic!("program must never be called on an untrusted device")
        }
        fn clear(&self) -> Result<(), FirewallError> {
            self.cleared.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn programmed_rules(&self) -> u64 {
            0
        }
    }

    /// Test double: attestation transport is down (returns `Err`). Same
    /// safe-degrade contract as an untrusted device.
    #[derive(Debug, Default)]
    struct FailAttestDevice {
        cleared: AtomicU64,
    }

    impl OffloadDevice for FailAttestDevice {
        fn descriptor(&self) -> OffloadDescriptor {
            OffloadDescriptor {
                name: "fail-attest".to_owned(),
                silicon: true,
                capacity: 16,
            }
        }
        fn attest(&self) -> Result<OffloadAttestation, FirewallError> {
            Err(FirewallError::Io("attestation transport down".to_owned()))
        }
        fn program(&self, _: &XdpRuleSet) -> Result<usize, FirewallError> {
            panic!("program must never be called when attestation errors")
        }
        fn clear(&self) -> Result<(), FirewallError> {
            self.cleared.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn programmed_rules(&self) -> u64 {
            0
        }
    }

    /// Test double: attests trusted, programs once, then fails — lets us
    /// drive the "nftables committed, device program failed" branch and
    /// observe the flush.
    #[derive(Debug, Default)]
    struct FlakyProgramDevice {
        programs: AtomicU64,
        cleared: AtomicU64,
    }

    impl OffloadDevice for FlakyProgramDevice {
        fn descriptor(&self) -> OffloadDescriptor {
            OffloadDescriptor {
                name: "flaky".to_owned(),
                silicon: false,
                capacity: 16,
            }
        }
        fn attest(&self) -> Result<OffloadAttestation, FirewallError> {
            Ok(OffloadAttestation {
                trusted: true,
                measurement: b"flaky".to_vec(),
            })
        }
        fn program(&self, rules: &XdpRuleSet) -> Result<usize, FirewallError> {
            if self.programs.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(rules.len())
            } else {
                Err(FirewallError::Io("forced program failure".to_owned()))
            }
        }
        fn clear(&self) -> Result<(), FirewallError> {
            self.cleared.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn programmed_rules(&self) -> u64 {
            0
        }
    }

    /// Test double: a genuine-silicon device (reports `silicon: true`), so
    /// the data path's honest capability/stat surface can be asserted.
    #[derive(Debug)]
    struct SiliconDevice;

    impl OffloadDevice for SiliconDevice {
        fn descriptor(&self) -> OffloadDescriptor {
            OffloadDescriptor {
                name: "silicon".to_owned(),
                silicon: true,
                capacity: 1024,
            }
        }
        fn attest(&self) -> Result<OffloadAttestation, FirewallError> {
            Ok(OffloadAttestation {
                trusted: true,
                measurement: b"silicon".to_vec(),
            })
        }
        fn program(&self, rules: &XdpRuleSet) -> Result<usize, FirewallError> {
            Ok(rules.len())
        }
        fn clear(&self) -> Result<(), FirewallError> {
            Ok(())
        }
        fn programmed_rules(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn hardware_offload_programs_device_and_keeps_fallback() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let device = Arc::new(SoftwareOffloadDevice::default());
        let dp = HardwareOffloadDataPath::new(device.clone(), NftablesDataPath::new(engine));
        assert_eq!(dp.name(), "hardware-offload");

        let rs = ruleset(
            vec![
                l3l4_rule("a", "203.0.113.0/24", RuleAction::Allow),
                l3l4_rule("d", "192.0.2.0/24", RuleAction::Deny),
            ],
            RuleAction::Deny,
        );
        dp.install_rules(&rs).await.unwrap();

        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.backend, "hardware-offload");
        // Both hot-path rules were programmed onto the device.
        assert_eq!(stats.rules_installed, 2);
        assert_eq!(stats.installs_total, 1);
        // Software model is not genuine silicon — reported honestly.
        assert!(!stats.kernel_offload);
        // Fallback installed the full ruleset too.
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 1);

        // The device enforces the offloaded subset identically to the slow
        // path: the Deny rule drops its target.
        let hit = device.evaluate(
            "10.0.0.1".parse().unwrap(),
            "192.0.2.5".parse().unwrap(),
            5000,
            443,
            6,
        );
        assert_eq!(hit.action, XdpRuleAction::Drop);

        // Capabilities are honest for a software device.
        let caps = dp.capabilities();
        assert!(!caps.hardware_offload);
        assert!(!caps.kernel_offload);
        assert!(caps.l3l4_filter);
        assert!(caps.l7_inspection);
    }

    #[tokio::test]
    async fn hardware_offload_does_not_program_when_nftables_fails() {
        // nftables is authoritative; if its apply fails the device must not
        // be touched at all.
        let mock = Arc::new(MockNftables::new());
        mock.fail_next_apply("kernel rejected");
        let backend: Arc<dyn NftablesBackend> = Arc::clone(&mock) as _;
        let engine = Arc::new(FirewallEngine::new(backend));
        let device = Arc::new(SoftwareOffloadDevice::default());
        let dp = HardwareOffloadDataPath::new(device.clone(), NftablesDataPath::new(engine));

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        assert!(dp.install_rules(&rs).await.is_err());
        // Device was never programmed.
        assert_eq!(device.programmed_rules(), 0);
        assert_eq!(device.programs_total(), 0);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 0);
        assert_eq!(stats.install_failures, 1);
    }

    #[tokio::test]
    async fn hardware_offload_refuses_and_flushes_untrusted_device() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let device = Arc::new(UntrustedDevice::default());
        let dp = HardwareOffloadDataPath::new(device.clone(), NftablesDataPath::new(engine));

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        assert!(dp.install_rules(&rs).await.is_err());
        // The untrusted device was flushed, never programmed.
        assert_eq!(device.cleared.load(Ordering::Relaxed), 1);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 0);
        assert_eq!(stats.install_failures, 1);
        // nftables (authoritative) still committed — enforcement is intact.
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 1);
    }

    #[tokio::test]
    async fn hardware_offload_errors_and_flushes_when_attestation_fails() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let device = Arc::new(FailAttestDevice::default());
        let dp = HardwareOffloadDataPath::new(device.clone(), NftablesDataPath::new(engine));

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        assert!(dp.install_rules(&rs).await.is_err());
        assert_eq!(device.cleared.load(Ordering::Relaxed), 1);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 0);
        assert_eq!(stats.install_failures, 1);
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 1);
    }

    #[tokio::test]
    async fn hardware_offload_flushes_device_when_program_fails() {
        // nftables succeeds on every install, but the device program fails
        // on the *second* install. The device must then be flushed so it
        // cannot keep enforcing the first install's (now stale) rules.
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let device = Arc::new(FlakyProgramDevice::default());
        let dp = HardwareOffloadDataPath::new(device.clone(), NftablesDataPath::new(engine));

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        // First install: attest + program both succeed.
        dp.install_rules(&rs).await.unwrap();
        // Second install: nftables commits, device program fails → flush.
        assert!(dp.install_rules(&rs).await.is_err());

        assert_eq!(device.cleared.load(Ordering::Relaxed), 1);
        let stats = dp.get_stats().unwrap();
        assert_eq!(stats.installs_total, 1);
        assert_eq!(stats.install_failures, 1);
        // nftables committed both installs — enforcement was never lost.
        assert_eq!(dp.fallback().get_stats().unwrap().installs_total, 2);
    }

    #[tokio::test]
    async fn hardware_offload_reports_silicon_capabilities_when_genuine() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let engine = Arc::new(FirewallEngine::new(backend));
        let device: Arc<dyn OffloadDevice> = Arc::new(SiliconDevice);
        let dp = HardwareOffloadDataPath::new(device, NftablesDataPath::new(engine));

        // Genuine silicon advertises hardware/kernel offload.
        let caps = dp.capabilities();
        assert!(caps.hardware_offload);
        assert!(caps.kernel_offload);

        let rs = ruleset(
            vec![l3l4_rule("a", "203.0.113.0/24", RuleAction::Deny)],
            RuleAction::Deny,
        );
        dp.install_rules(&rs).await.unwrap();
        assert!(dp.get_stats().unwrap().kernel_offload);
    }
}
