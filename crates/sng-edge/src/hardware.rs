// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Hardware-readiness abstraction (ARCHITECTURE.md §4).
//!
//! The edge runs as a software appliance: enforcement is nftables or
//! eBPF/XDP ([`sng_fw::DataPathBackend`]), and there is no hardware root
//! of trust beyond the host OS. This abstraction is the seam for
//! TPM-rooted appliance SKUs with SmartNIC / crypto offload, where the
//! data-path backend attests its rule program against a measured boot
//! chain before the supervisor trusts it.
//!
//! [`HardwareAccelerator`] is the seam for that: the supervisor probes
//! for an accelerator at boot via [`probe_accelerator`] and, when one
//! reports itself offload-capable *and* attests trusted, the firewall
//! subsystem programs the [`sng_fw::HardwareOffloadDataPath`] onto it.
//!
//! This build ships [`HostAccelerator`] — the honest "no hardware root
//! of trust" probe result for a plain software host: it reports neither
//! TPM-rooted nor offload-capable, so the firewall always runs the
//! in-process software offload model and nftables stays authoritative.
//! A concrete silicon accelerator (a `TpmAccelerator` over `tss-esapi`,
//! a `SmartNicAccelerator` over the vendor SDK) implements this trait
//! and is selected by [`probe_accelerator`] without touching the
//! firewall subsystem or the data path.

use std::fmt::Debug;
use std::sync::Arc;

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

/// A TPM-rooted / SmartNIC appliance accelerator.
///
/// The supervisor holds the probed accelerator behind an `Arc` shared
/// across subsystem tasks (hence `Send + Sync`), exactly as it does for
/// [`sng_fw::DataPathBackend`]. The shipped implementor is
/// [`HostAccelerator`]; silicon SKUs add their own implementors selected
/// by [`probe_accelerator`].
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
    /// open so a TPM / SmartNIC binding can pick its own.
    fn attest(&self) -> Result<AttestationReport, Box<dyn std::error::Error + Send + Sync>>;
}

/// The shipped accelerator: a plain software host with no hardware root
/// of trust.
///
/// It reports neither TPM-rooted nor offload-capable, and attests
/// **untrusted** (an empty quote) — there is no measured boot chain on a
/// commodity host to vouch for. The firewall subsystem reads this and
/// runs the in-process software offload model (which is itself trusted
/// by construction, being the local process) with nftables authoritative
/// rather than pretending a SmartNIC is present.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostAccelerator;

impl HardwareAccelerator for HostAccelerator {
    fn descriptor(&self) -> HardwareDescriptor {
        HardwareDescriptor {
            name: "host-software".to_owned(),
            tpm_rooted: false,
            offload_capable: false,
        }
    }

    fn attest(&self) -> Result<AttestationReport, Box<dyn std::error::Error + Send + Sync>> {
        Ok(AttestationReport {
            trusted: false,
            quote: Vec::new(),
        })
    }
}

/// Probe the host for a hardware accelerator at boot.
///
/// Returns the accelerator the supervisor should hold for the process
/// lifetime. This build has no TPM / SmartNIC binding compiled in, so it
/// always returns a [`HostAccelerator`] — the honest "software host"
/// result. A silicon SKU adds its discovery here (behind the relevant
/// target/feature gate) and returns its own implementor; nothing else in
/// the edge changes, because the firewall subsystem consumes only the
/// [`HardwareAccelerator`] trait.
#[must_use]
pub fn probe_accelerator() -> Arc<dyn HardwareAccelerator> {
    Arc::new(HostAccelerator)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway in-test implementor proving the trait is
    /// object-safe and usable behind a trait object, which is how the
    /// supervisor holds it.
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

    #[test]
    fn probe_returns_software_host_with_no_offload() {
        let acc = probe_accelerator();
        let desc = acc.descriptor();
        assert_eq!(desc.name, "host-software");
        assert!(!desc.tpm_rooted);
        // A commodity host advertises no offload silicon, so the
        // firewall must not select a hardware-offload device for it.
        assert!(!desc.offload_capable);
        // And it does not vouch for a measured boot chain.
        assert!(!acc.attest().unwrap().trusted);
    }
}
