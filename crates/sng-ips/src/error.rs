//! IPS subsystem error taxonomy.
//!
//! Errors are grouped by failure surface — process lifecycle,
//! config rendering, rule-bundle verification, EVE parsing,
//! and IO. Every variant maps to a stable
//! [`sng_core::error::ErrorCode`] so the telemetry pipeline can
//! attach a structured code to alert events without string
//! matching on the variant.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// All failures the IPS subsystem can return.
#[derive(Debug, Error)]
pub enum IpsError {
    /// Generic IO failure (file read, pipe write, process spawn).
    #[error("io error: {0}")]
    Io(String),

    /// Suricata process management failure (spawn, wait,
    /// signal). Distinct from [`Self::Io`] so the supervisor can
    /// trigger a restart for `Process` failures while leaving
    /// `Io` failures (e.g. a transient EVE read) to be retried
    /// in place.
    #[error("suricata process error: {0}")]
    Process(String),

    /// The on-disk `suricata.yaml` render produced an invalid
    /// document (impossible character in a string the writer
    /// cannot escape). Should not happen for compiler-produced
    /// inputs — surfaces a bug in [`crate::config`].
    #[error("config render error: {0}")]
    Config(String),

    /// Rule bundle failed Ed25519 signature verification.
    #[error("rule bundle signature invalid")]
    RuleSignatureInvalid,

    /// Rule bundle signed with a key id the trust store does not
    /// know about.
    #[error("rule bundle signed with unknown key: {0}")]
    RuleSignatureUnknownKey(String),

    /// Rule bundle version is older than or equal to the
    /// currently installed bundle. Prevents the control plane
    /// from accidentally rolling back to a previous rule set,
    /// which would silently drop coverage.
    #[error("rule bundle is stale: incoming version {incoming} <= current {current}")]
    RuleStale { incoming: u64, current: u64 },

    /// Rule bundle body failed to decode as MessagePack.
    #[error("rule bundle body decode failed: {0}")]
    RuleBodyDecode(String),

    /// Rule bundle body failed to encode as MessagePack.
    /// Pragmatically unreachable for the current claims struct
    /// shape — `rmp_serde::to_vec_named` does not fail on a
    /// well-formed Rust struct — but kept distinct from
    /// [`Self::RuleBodyDecode`] so the telemetry pipeline routes
    /// an encode failure under `ips.rule.body.encode` instead of
    /// misclassifying it under the decode bucket.
    #[error("rule bundle body encode failed: {0}")]
    RuleBodyEncode(String),

    /// `suricata -T` dry-run on the staged ruleset failed —
    /// the new rules are syntactically invalid and the supervisor
    /// must not swap them in.
    #[error("rule validation failed: {0}")]
    RuleValidate(String),

    /// EVE JSON line could not be decoded. Carries the original
    /// raw line for the parser test fixtures.
    #[error("eve decode error: {0}")]
    EveDecode(String),
}

impl IpsError {
    /// Map to the stable workspace error code so the telemetry
    /// pipeline can attach a structured code to the error event.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Io(_) => ErrorCode::Io,
            Self::Process(_) => ErrorCode::IpsProcessFailure,
            Self::Config(_) => ErrorCode::IpsConfigInvalid,
            Self::RuleSignatureInvalid => ErrorCode::IpsRuleSignatureInvalid,
            Self::RuleSignatureUnknownKey(_) => ErrorCode::IpsRuleSigningKeyUnknown,
            Self::RuleStale { .. } => ErrorCode::IpsRuleStale,
            Self::RuleBodyDecode(_) => ErrorCode::IpsRuleBodyDecode,
            Self::RuleBodyEncode(_) => ErrorCode::IpsRuleBodyEncode,
            Self::RuleValidate(_) => ErrorCode::IpsRuleValidate,
            Self::EveDecode(_) => ErrorCode::IpsEveDecode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn every_variant_maps_to_an_ips_or_io_code() {
        // Sanity check: codes are in the IPS-specific range (or
        // the shared IO code) so a telemetry consumer that filters
        // on `code.starts_with("IPS")` does not miss any IPS error.
        let cases = [
            IpsError::Io("x".into()),
            IpsError::Process("x".into()),
            IpsError::Config("x".into()),
            IpsError::RuleSignatureInvalid,
            IpsError::RuleSignatureUnknownKey("k".into()),
            IpsError::RuleStale {
                incoming: 1,
                current: 2,
            },
            IpsError::RuleBodyDecode("x".into()),
            IpsError::RuleBodyEncode("x".into()),
            IpsError::RuleValidate("x".into()),
            IpsError::EveDecode("x".into()),
        ];
        for e in cases {
            let code = e.code().as_str();
            assert!(
                code.starts_with("ips.") || code == "io",
                "variant {e:?} produced non-IPS code {code}"
            );
        }
    }

    #[test]
    fn each_variant_carries_a_distinct_code() {
        // Surface variants must map 1:1 to distinct error codes
        // so dashboards can split out the failure modes. (`Io`
        // is the only deliberate alias for the shared workspace
        // IO code.)
        let cases = [
            IpsError::Process("x".into()).code(),
            IpsError::Config("x".into()).code(),
            IpsError::RuleSignatureInvalid.code(),
            IpsError::RuleSignatureUnknownKey("k".into()).code(),
            IpsError::RuleStale {
                incoming: 1,
                current: 2,
            }
            .code(),
            IpsError::RuleBodyDecode("x".into()).code(),
            IpsError::RuleBodyEncode("x".into()).code(),
            IpsError::RuleValidate("x".into()).code(),
            IpsError::EveDecode("x".into()).code(),
        ];
        let unique: std::collections::HashSet<_> = cases.iter().copied().collect();
        assert_eq!(unique.len(), cases.len(), "duplicate codes: {cases:?}");
    }

    #[test]
    fn rule_body_encode_and_decode_map_to_distinct_codes() {
        // Regression guard against the previous behaviour where
        // `IpsRuleBundleClaims::encode()` mapped a serializer
        // failure to `RuleBodyDecode` — operator dashboards
        // filtering on `ips.rule.body.decode` would have
        // misclassified an outbound encode failure as a corrupt
        // inbound bundle.
        assert_ne!(
            IpsError::RuleBodyDecode("x".into()).code(),
            IpsError::RuleBodyEncode("x".into()).code(),
        );
        assert_eq!(
            IpsError::RuleBodyEncode("x".into()).code().as_str(),
            "ips.rule.body.encode",
        );
    }
}
