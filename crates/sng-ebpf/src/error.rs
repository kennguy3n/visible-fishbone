//! eBPF data-path error taxonomy.
//!
//! Mirrors [`sng_fw::error::FirewallError`]: every variant maps onto a
//! stable [`sng_core::error::ErrorCode`] so the supervisor buckets an
//! eBPF failure into the same dotted-lowercase namespace the rest of the
//! workspace uses.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the eBPF/XDP data-path control plane.
#[derive(Debug, Error)]
pub enum EbpfError {
    /// eBPF/XDP is not available in this build or on this host: the
    /// `xdp` feature is compiled out, the target is not Linux, or the
    /// running kernel / mount layout does not expose the BPF facilities
    /// the loader needs. Callers treat this as "fall back to the
    /// nftables data path" rather than a hard failure.
    #[error("ebpf unsupported: {0}")]
    Unsupported(String),

    /// The kernel rejected the program at load / verification time, or
    /// the compiled object could not be opened. Carries the loader's
    /// diagnostic so an operator can see whether the verifier complained
    /// or the object file was missing.
    #[error("ebpf program load failed: {0}")]
    Load(String),

    /// Attaching a loaded program to an interface hook (XDP ingress or
    /// TC egress) failed — typically a missing interface, an
    /// already-attached XDP program in `skb`/`drv` mode, or insufficient
    /// privilege.
    #[error("ebpf attach failed: {0}")]
    Attach(String),

    /// A map operation (create / update / pin / read) failed.
    #[error("ebpf map: {0}")]
    Map(String),

    /// Pinning a program or map to the bpf filesystem failed.
    #[error("ebpf pin: {0}")]
    Pin(String),

    /// A rule, classification entry, or steering target failed
    /// validation before it could be pushed into a map — e.g. an XDP
    /// rule that carries an action the fast path cannot realise, or a
    /// port range with `from > to`.
    #[error("ebpf rule invalid: {0}")]
    RuleInvalid(String),

    /// Transport-level I/O failure talking to the BPF subsystem
    /// (`/sys/fs/bpf`, the `bpf(2)` syscall surface) before a more
    /// specific error could be determined.
    #[error("io: {0}")]
    Io(String),
}

impl EbpfError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            // "No eBPF here" is a missing-capability condition, not a
            // misconfiguration — it maps to ResourceMissing so the
            // auto-detect fallback path is distinguishable in telemetry
            // from a genuine load failure.
            Self::Unsupported(_) => ErrorCode::ResourceMissing,
            // A rule the fast path cannot represent is a control-plane /
            // operator-authored problem — bucket with the config surface.
            Self::RuleInvalid(_) => ErrorCode::ConfigInvalid,
            // Everything else is a kernel / syscall interaction failure.
            Self::Load(_) | Self::Attach(_) | Self::Map(_) | Self::Pin(_) | Self::Io(_) => {
                ErrorCode::Io
            }
        }
    }

    /// True iff this error means the eBPF path is simply unavailable and
    /// the caller should fall back to the nftables data path rather than
    /// surface a hard failure.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn unsupported_maps_to_resource_missing() {
        let e = EbpfError::Unsupported("no kernel".into());
        assert_eq!(e.code(), ErrorCode::ResourceMissing);
        assert!(e.is_unsupported());
    }

    #[test]
    fn rule_invalid_maps_to_config_invalid() {
        let e = EbpfError::RuleInvalid("bad port range".into());
        assert_eq!(e.code(), ErrorCode::ConfigInvalid);
        assert!(!e.is_unsupported());
    }

    #[test]
    fn load_and_attach_map_to_io() {
        assert_eq!(EbpfError::Load("verifier".into()).code(), ErrorCode::Io);
        assert_eq!(EbpfError::Attach("no iface".into()).code(), ErrorCode::Io);
        assert_eq!(EbpfError::Map("update".into()).code(), ErrorCode::Io);
        assert_eq!(EbpfError::Pin("bpffs".into()).code(), ErrorCode::Io);
    }

    #[test]
    fn display_formats_with_prefix() {
        assert_eq!(
            EbpfError::Load("verifier rejected".into()).to_string(),
            "ebpf program load failed: verifier rejected",
        );
    }
}
