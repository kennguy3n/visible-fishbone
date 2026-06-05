// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Hardware-readiness abstraction (Phase 6 — PROPOSAL.md §10).
//!
//! The shipped edge today is a software appliance: enforcement is
//! nftables or eBPF/XDP ([`sng_fw::DataPathBackend`]), and there is no
//! hardware root of trust beyond the host OS. PROPOSAL.md §10 plans a
//! future line of TPM-rooted appliance SKUs with SmartNIC / crypto
//! offload, where the data-path backend would attest its rule program
//! against a measured boot chain before the supervisor trusts it.
//!
//! [`HardwareAccelerator`] is the **trait definition only** for that
//! future. It is deliberately not implemented or wired into
//! [`crate::build_edge`] yet — declaring it now fixes the seam the
//! Phase-6 work will fill (and gives the `ebpf` /
//! `hardware-offload` data-path backends a place to report attestation
//! state) without pulling any TPM / SmartNIC dependency into the
//! current build.
//!
//! When Phase 6 lands, a concrete accelerator (e.g. a `TpmAccelerator`
//! over `tss-esapi`, or a `SmartNicAccelerator` over the vendor SDK)
//! will implement this trait, the supervisor will probe for one at
//! boot, and [`sng_fw::HardwareOffloadDataPath`] will gate its rule
//! install on [`HardwareAccelerator::attest`] succeeding.

use std::fmt::Debug;

/// Identity and capability descriptor for a hardware accelerator.
///
/// Reported by [`HardwareAccelerator::descriptor`] so the supervisor can
/// log which SKU it booted on and surface it on the health endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareDescriptor {
    /// Human-readable accelerator / SKU name (e.g. `"tpm2-fTPM"`,
    /// `"smartnic-bluefield3"`).
    pub name: String,
    /// True iff the device exposes a TPM (or equivalent) the boot chain
    /// can be measured against.
    pub tpm_rooted: bool,
    /// True iff the device can offload packet-processing rules to
    /// hardware (SmartNIC / FPGA).
    pub offload_capable: bool,
}

/// The result of a hardware attestation.
///
/// Phase 6 will replace [`Self::quote`] with a typed quote / PCR digest;
/// it is a byte vector here so the trait shape is stable before the
/// attestation format is chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationReport {
    /// Whether the measured boot chain matched the expected policy.
    pub trusted: bool,
    /// Opaque attestation evidence (a TPM quote, a SmartNIC firmware
    /// measurement, …) for the control plane to verify out-of-band.
    pub quote: Vec<u8>,
}

/// A future TPM-rooted / SmartNIC appliance accelerator.
///
/// **Phase 6 stub — trait definition only.** No production type
/// implements this yet; see the module docs and PROPOSAL.md §10.
///
/// The trait is `Send + Sync` because the supervisor will hold the
/// accelerator behind an `Arc` shared across subsystem tasks, exactly as
/// it does for [`sng_fw::DataPathBackend`].
pub trait HardwareAccelerator: Send + Sync + Debug {
    /// Static identity / capability descriptor for the device.
    fn descriptor(&self) -> HardwareDescriptor;

    /// Measure the running data-path program against the device's root
    /// of trust and produce an attestation the control plane can verify.
    ///
    /// # Errors
    ///
    /// Returns a boxed error if the device is unreachable or the
    /// measurement fails. The concrete error type is intentionally left
    /// open until Phase 6 picks the TPM / SmartNIC binding.
    ///
    /// # TODO(stream-b/phase-6)
    ///
    /// Implement against a real device (tss-esapi for fTPM/dTPM, or the
    /// SmartNIC vendor SDK) and have
    /// [`sng_fw::HardwareOffloadDataPath`] gate rule installation on a
    /// `trusted` report.
    fn attest(&self) -> Result<AttestationReport, Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway in-test implementor proving the trait is
    /// object-safe and usable behind a trait object, which is how the
    /// supervisor will hold it in Phase 6.
    #[derive(Debug)]
    struct FakeAccelerator;

    impl HardwareAccelerator for FakeAccelerator {
        fn descriptor(&self) -> HardwareDescriptor {
            HardwareDescriptor {
                name: "fake".to_owned(),
                tpm_rooted: true,
                offload_capable: false,
            }
        }

        fn attest(&self) -> Result<AttestationReport, Box<dyn std::error::Error + Send + Sync>> {
            Ok(AttestationReport {
                trusted: true,
                quote: vec![0xde, 0xad],
            })
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let acc: Box<dyn HardwareAccelerator> = Box::new(FakeAccelerator);
        assert_eq!(acc.descriptor().name, "fake");
        assert!(acc.attest().unwrap().trusted);
    }
}
