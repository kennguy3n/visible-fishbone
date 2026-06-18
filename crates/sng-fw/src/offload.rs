// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Hardware rule-offload substrate — the pluggable seam a SmartNIC /
//! FPGA / DPDK / VPP fast path plugs into, mirroring how
//! [`sng_ebpf::ProgramLoader`] is the seam for the kernel XDP fast path.
//!
//! ## Why this lives in `sng-fw`, not `sng-edge`
//!
//! [`crate::HardwareOffloadDataPath`] programs the offloaded rule subset,
//! so the device abstraction it drives must be reachable from `sng-fw`.
//! `sng-edge`'s `HardwareAccelerator` is the *boot-time* root-of-trust
//! probe (TPM attestation, SKU discovery) that lives one layer up and
//! hands the data path one of these devices; it cannot live here without
//! `sng-fw` depending on `sng-edge` (a crate cycle).
//!
//! ## What is and isn't real
//!
//! [`SoftwareOffloadDevice`] is a genuine, fully-evaluating model of a
//! finite-capacity match table (a TCAM): it stores the programmed rules
//! and answers [`SoftwareOffloadDevice::evaluate`] with the same
//! first-match semantics the silicon would, so the offload data path is
//! exercisable end-to-end in CI with no NIC. It reports `silicon = false`
//! and never claims kernel / hardware offload it is not performing.
//!
//! A real SmartNIC / DPDK / VPP driver is a *separate* [`OffloadDevice`]
//! implementor (behind the vendor SDK and a `#[cfg]` for the appliance
//! image) that reports `silicon = true`. The trait is the drop-in seam —
//! exactly like `AyaLoader` behind `ProgramLoader` — so wiring real
//! silicon does not touch [`crate::HardwareOffloadDataPath`] at all.

use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicU64, Ordering};

use sng_ebpf::{XdpDecision, XdpRuleAction, XdpRuleSet};

use crate::backend::map_ebpf_err;
use crate::error::FirewallError;

/// Identity + capability descriptor for an [`OffloadDevice`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffloadDescriptor {
    /// Stable device name (`"software-model"`, `"smartnic-bluefield3"`, …).
    pub name: String,
    /// True iff rules are programmed into real packet-processing silicon
    /// (SmartNIC / FPGA), false for the in-process software model. The
    /// data path surfaces this as `kernel_offload` / `hardware_offload`,
    /// so an operator is never misled into reading a software model as
    /// hardware acceleration.
    pub silicon: bool,
    /// Maximum rules the device's match table (TCAM) can hold. Programming
    /// more than this offloads the leading prefix and defers the rest to
    /// the slow path — see [`fit_to_capacity`] and [`OffloadDevice::program`].
    pub capacity: usize,
}

/// Attestation of an offload device before it is trusted to enforce.
///
/// Mirrors `sng_edge::AttestationReport`: [`crate::HardwareOffloadDataPath`]
/// refuses to program a device whose attestation is absent or untrusted
/// (the authoritative slow path still enforces), so a tampered or
/// unverified device degrades safely instead of silently dropping or
/// admitting traffic on unmeasured silicon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffloadAttestation {
    /// Whether the device's firmware / program measured as expected.
    pub trusted: bool,
    /// Opaque measurement evidence (a firmware hash, a TPM quote, …) for
    /// the control plane to verify out of band.
    pub measurement: Vec<u8>,
}

/// A pluggable hardware rule-offload device.
///
/// The rule surface mirrors [`sng_ebpf::XdpControlPlane`]
/// (`install_rules` / `clear_rules`) but for an *offload* substrate that
/// attests itself and has a finite match-table capacity. Real silicon
/// (SmartNIC / FPGA / DPDK / VPP) implements this behind its vendor SDK;
/// [`SoftwareOffloadDevice`] implements it as an in-process model so the
/// data path is testable without a NIC.
pub trait OffloadDevice: Send + Sync + std::fmt::Debug {
    /// Static identity / capability descriptor.
    fn descriptor(&self) -> OffloadDescriptor;

    /// Attest the device's firmware / program against its root of trust.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError`] if the device is unreachable or a
    /// measurement cannot be produced. A reachable-but-untrusted device
    /// returns `Ok` with `trusted = false`; the data path treats both as
    /// "do not offload".
    fn attest(&self) -> Result<OffloadAttestation, FirewallError>;

    /// Program the offloadable rule set into the device's match table,
    /// replacing any previous one. Returns the number of rules actually
    /// programmed, which may be fewer than `rules.len()` when the set
    /// exceeds [`OffloadDescriptor::capacity`] — the leading prefix is
    /// programmed and the remainder deferred to the slow path (see
    /// [`fit_to_capacity`]).
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError`] on a validation or device-write failure.
    fn program(&self, rules: &XdpRuleSet) -> Result<usize, FirewallError>;

    /// Flush the match table to an empty *pass-through* set — every packet
    /// falls through to the slow path. The fail-safe the data path invokes
    /// when attestation or programming fails after the authoritative slow
    /// path has already committed.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError`] on a device-write failure.
    fn clear(&self) -> Result<(), FirewallError>;

    /// Rules currently programmed in the device's match table.
    fn programmed_rules(&self) -> u64;
}

/// Fit an offload rule set to a device's match-table `capacity`,
/// preserving first-match semantics.
///
/// When the set fits, it is returned unchanged. When it overflows, only
/// the leading `capacity` rules are kept **and the default action is
/// forced to [`XdpRuleAction::Pass`]** so any packet that would have
/// matched a truncated rule — or hit the original default — defers to the
/// authoritative slow path instead of taking a verdict the device can no
/// longer prove. This is the same "incomplete ⇒ pass" invariant
/// [`crate::compile_hot_path`] applies when it cannot model the whole
/// chain, lifted to the capacity dimension.
#[must_use]
pub fn fit_to_capacity(rules: &XdpRuleSet, capacity: usize) -> XdpRuleSet {
    if rules.len() <= capacity {
        return rules.clone();
    }
    let kept = rules.rules()[..capacity].to_vec();
    XdpRuleSet::new(kept, XdpRuleAction::Pass)
}

/// An in-process, fully-evaluating model of a finite-capacity hardware
/// offload device.
///
/// Stores the programmed rule set and answers [`Self::evaluate`] with the
/// same first-match semantics the silicon would, so
/// [`crate::HardwareOffloadDataPath`] is exercisable end-to-end without a
/// NIC. It reports `silicon = false` and attests itself as a software
/// model — it never claims hardware offload it is not performing.
#[derive(Debug)]
pub struct SoftwareOffloadDevice {
    capacity: usize,
    installed: Mutex<XdpRuleSet>,
    programs_total: AtomicU64,
}

impl SoftwareOffloadDevice {
    /// A representative match-table size for the software model. Real
    /// silicon reports its own capacity via [`OffloadDescriptor`]; this
    /// default simply lets the capacity-overflow path be exercised without
    /// one.
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// Build a software offload device with the given match-table capacity.
    /// The table starts empty (pass-through): every packet defers to the
    /// slow path until the first [`OffloadDevice::program`].
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            installed: Mutex::new(XdpRuleSet::new(Vec::new(), XdpRuleAction::Pass)),
            programs_total: AtomicU64::new(0),
        }
    }

    /// Evaluate a 5-tuple against the currently-programmed rule set,
    /// returning the device's verdict. This is the model's stand-in for
    /// the silicon's per-packet match; it lets tests assert the offloaded
    /// subset enforces identically to the slow path.
    #[must_use]
    pub fn evaluate(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> XdpDecision {
        self.installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .evaluate(src_ip, dst_ip, src_port, dst_port, protocol)
    }

    /// Total successful [`OffloadDevice::program`] calls since construction.
    #[must_use]
    pub fn programs_total(&self) -> u64 {
        self.programs_total.load(Ordering::Relaxed)
    }
}

impl Default for SoftwareOffloadDevice {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl OffloadDevice for SoftwareOffloadDevice {
    fn descriptor(&self) -> OffloadDescriptor {
        OffloadDescriptor {
            name: "software-model".to_owned(),
            silicon: false,
            capacity: self.capacity,
        }
    }

    fn attest(&self) -> Result<OffloadAttestation, FirewallError> {
        // The software model has no hardware root of trust; it attests
        // itself as a trusted *software* device so the data path's
        // attestation gate is exercised end-to-end. Real silicon returns a
        // TPM quote / firmware measurement here and may report
        // `trusted: false` when the measured boot chain does not match
        // policy.
        Ok(OffloadAttestation {
            trusted: true,
            measurement: b"software-model".to_vec(),
        })
    }

    fn program(&self, rules: &XdpRuleSet) -> Result<usize, FirewallError> {
        // A real device rejects malformed rules at program time; mirror
        // that so the data path sees the same `RuleInvalid` taxonomy it
        // gets from the XDP fast path.
        rules.validate().map_err(map_ebpf_err)?;
        let fitted = fit_to_capacity(rules, self.capacity);
        let count = fitted.len();
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = fitted;
        self.programs_total.fetch_add(1, Ordering::Relaxed);
        Ok(count)
    }

    fn clear(&self) -> Result<(), FirewallError> {
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            XdpRuleSet::new(Vec::new(), XdpRuleAction::Pass);
        Ok(())
    }

    fn programmed_rules(&self) -> u64 {
        let len = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        u64::try_from(len).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use sng_ebpf::{PortRange, XdpRule};
    use std::net::IpAddr;
    use std::sync::Arc;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip literal")
    }

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().expect("test cidr literal")
    }

    /// A pure-L3/L4 rule matching one destination CIDR on TCP/443.
    fn https_rule(id: &str, dst: &str, action: XdpRuleAction) -> XdpRule {
        XdpRule {
            id: id.to_owned(),
            src_cidrs: Vec::new(),
            dst_cidrs: vec![net(dst)],
            src_ports: Vec::new(),
            dst_ports: vec![PortRange::single(443)],
            protocol: Some(6),
            action,
        }
    }

    #[test]
    fn fit_to_capacity_keeps_set_that_fits() {
        let rs = XdpRuleSet::new(
            vec![https_rule("a", "203.0.113.0/24", XdpRuleAction::Drop)],
            XdpRuleAction::Drop,
        );
        let fitted = fit_to_capacity(&rs, 4);
        assert_eq!(fitted.len(), 1);
        // Whole set fits → the original default is preserved.
        assert_eq!(fitted.default_action(), XdpRuleAction::Drop);
    }

    #[test]
    fn fit_to_capacity_truncates_and_forces_pass_default() {
        let rs = XdpRuleSet::new(
            vec![
                https_rule("a", "203.0.113.0/24", XdpRuleAction::Drop),
                https_rule("b", "198.51.100.0/24", XdpRuleAction::Drop),
                https_rule("c", "192.0.2.0/24", XdpRuleAction::Drop),
            ],
            XdpRuleAction::Drop,
        );
        let fitted = fit_to_capacity(&rs, 1);
        // Only the leading rule is kept…
        assert_eq!(fitted.len(), 1);
        assert_eq!(fitted.rules()[0].id, "a");
        // …and the default is forced to Pass so the truncated rules' and
        // original default's verdicts defer to the authoritative slow path.
        assert_eq!(fitted.default_action(), XdpRuleAction::Pass);
    }

    #[test]
    fn software_device_programs_and_evaluates() {
        let dev = SoftwareOffloadDevice::new(SoftwareOffloadDevice::DEFAULT_CAPACITY);
        assert_eq!(dev.descriptor().name, "software-model");
        assert!(!dev.descriptor().silicon);
        assert!(dev.attest().expect("attest").trusted);

        let rs = XdpRuleSet::new(
            vec![https_rule(
                "drop-evil",
                "203.0.113.0/24",
                XdpRuleAction::Drop,
            )],
            XdpRuleAction::Pass,
        );
        assert_eq!(dev.program(&rs).expect("program"), 1);
        assert_eq!(dev.programmed_rules(), 1);
        assert_eq!(dev.programs_total(), 1);

        // The offloaded rule enforces identically to the slow path: the
        // matching 5-tuple drops, everything else passes.
        let hit = dev.evaluate(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 443, 6);
        assert_eq!(hit.action, XdpRuleAction::Drop);
        let miss = dev.evaluate(ip("10.0.0.1"), ip("198.51.100.5"), 5000, 443, 6);
        assert_eq!(miss.action, XdpRuleAction::Pass);
    }

    #[test]
    fn software_device_overflow_offloads_prefix_and_defers_rest() {
        let dev = SoftwareOffloadDevice::new(1);
        let rs = XdpRuleSet::new(
            vec![
                https_rule("a", "203.0.113.0/24", XdpRuleAction::Drop),
                https_rule("b", "198.51.100.0/24", XdpRuleAction::Drop),
            ],
            XdpRuleAction::Drop,
        );
        // Capacity is 1, so only the leading rule is programmed.
        assert_eq!(dev.program(&rs).expect("program"), 1);
        assert_eq!(dev.programmed_rules(), 1);

        // The programmed rule still drops its target…
        let hit = dev.evaluate(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 443, 6);
        assert_eq!(hit.action, XdpRuleAction::Drop);
        // …but the truncated rule's traffic must NOT be dropped by the
        // device — it passes through to the slow path (default forced to
        // Pass), never silently admitted or dropped on the truncated set.
        let deferred = dev.evaluate(ip("10.0.0.1"), ip("198.51.100.5"), 5000, 443, 6);
        assert_eq!(deferred.action, XdpRuleAction::Pass);
    }

    #[test]
    fn software_device_clear_restores_pass_through() {
        let dev = SoftwareOffloadDevice::new(8);
        let rs = XdpRuleSet::new(
            vec![https_rule("a", "203.0.113.0/24", XdpRuleAction::Drop)],
            XdpRuleAction::Drop,
        );
        dev.program(&rs).expect("program");
        assert_eq!(dev.programmed_rules(), 1);

        dev.clear().expect("clear");
        assert_eq!(dev.programmed_rules(), 0);
        // After a flush the previously-dropped target passes through.
        let after = dev.evaluate(ip("10.0.0.1"), ip("203.0.113.5"), 5000, 443, 6);
        assert_eq!(after.action, XdpRuleAction::Pass);
    }

    #[test]
    fn software_device_is_object_safe_behind_arc() {
        let dev: Arc<dyn OffloadDevice> = Arc::new(SoftwareOffloadDevice::default());
        assert_eq!(
            dev.descriptor().capacity,
            SoftwareOffloadDevice::DEFAULT_CAPACITY
        );
        assert_eq!(dev.programmed_rules(), 0);
    }
}
