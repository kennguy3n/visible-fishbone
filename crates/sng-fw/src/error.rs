//! Firewall subsystem error taxonomy.
//!
//! Every error produced by this crate maps onto an
//! [`sng_core::error::ErrorCode`] so the supervisor can bucket
//! failures into the same dotted-lowercase namespace the rest of
//! the workspace uses.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the firewall subsystem.
#[derive(Debug, Error)]
pub enum FirewallError {
    /// A rule failed validation before compilation — empty action
    /// chain, malformed CIDR, port range with `from > to`, or a
    /// reference to a zone that does not exist in the supplied
    /// [`crate::ZoneTable`].
    #[error("rule invalid: {0}")]
    RuleInvalid(String),

    /// The NGFW slice of the supplied policy bundle deserialised
    /// but failed an invariant check (rule references a deleted
    /// app id, default action absent, etc.). Distinct from
    /// [`Self::RuleInvalid`] because the cause is the upstream
    /// compiler rather than the operator-authored rule body.
    #[error("bundle invalid: {0}")]
    BundleInvalid(String),

    /// The compiled rule set could not be applied to the kernel.
    /// Includes the underlying `nft -f` exit status and stderr
    /// tail so the operator can see *which* rule the kernel
    /// rejected (typically a regex mismatch or an unknown
    /// expression on a kernel older than the rule set targets).
    #[error("nftables apply failed: {0}")]
    NftablesApply(String),

    /// IO failure spawning or talking to the `nft` binary. Used
    /// when the executable is missing, not on `PATH`, or returned
    /// a transport-level error before the `apply` even started.
    #[error("io: {0}")]
    Io(String),

    /// An L7 protocol parser produced bytes that did not satisfy
    /// the protocol's structural invariants (truncated TLS
    /// `ClientHello`, HTTP method longer than the RFC 7230
    /// maximum, etc.).
    #[error("l7 parse: {0}")]
    L7Parse(String),

    /// The TLS policy refused to make a decrypt / bypass
    /// decision because the flow lacked the metadata the policy
    /// requires (no SNI on a TLS flow, missing host on a plain
    /// HTTP flow). The supervisor maps this to a bypass-default
    /// per `tls_policy::TlsPolicy::default_when_unknown`.
    #[error("tls policy underdetermined: {0}")]
    TlsPolicyUnderdetermined(String),
}

impl FirewallError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            // Rule / bundle invariants are a control-plane (or
            // operator-authored) bug — bucket with the rest of
            // the config-failure surface.
            Self::RuleInvalid(_) | Self::BundleInvalid(_) => ErrorCode::ConfigInvalid,
            // L7 parse / TLS policy underdetermined are wire /
            // schema problems — the producer (kernel, observed
            // peer) handed us bytes we cannot interpret.
            Self::L7Parse(_) | Self::TlsPolicyUnderdetermined(_) => ErrorCode::WireSchema,
            // Apply / IO failures bubble up as IO so dashboards
            // separate "kernel rejected the script" from "config
            // was wrong".
            Self::NftablesApply(_) | Self::Io(_) => ErrorCode::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn rule_invalid_maps_to_config_invalid() {
        let e = FirewallError::RuleInvalid("bad cidr".into());
        assert_eq!(e.code(), ErrorCode::ConfigInvalid);
    }

    #[test]
    fn bundle_invalid_maps_to_config_invalid() {
        let e = FirewallError::BundleInvalid("missing default action".into());
        assert_eq!(e.code(), ErrorCode::ConfigInvalid);
    }

    #[test]
    fn nftables_apply_maps_to_io() {
        let e = FirewallError::NftablesApply("rule rejected".into());
        assert_eq!(e.code(), ErrorCode::Io);
    }

    #[test]
    fn l7_parse_maps_to_wire_schema() {
        let e = FirewallError::L7Parse("truncated client hello".into());
        assert_eq!(e.code(), ErrorCode::WireSchema);
    }

    #[test]
    fn tls_underdetermined_maps_to_wire_schema() {
        let e = FirewallError::TlsPolicyUnderdetermined("no sni".into());
        assert_eq!(e.code(), ErrorCode::WireSchema);
    }

    #[test]
    fn display_formats_with_prefix() {
        assert_eq!(
            FirewallError::RuleInvalid("bad".into()).to_string(),
            "rule invalid: bad",
        );
        assert_eq!(
            FirewallError::NftablesApply("kernel".into()).to_string(),
            "nftables apply failed: kernel",
        );
    }
}
