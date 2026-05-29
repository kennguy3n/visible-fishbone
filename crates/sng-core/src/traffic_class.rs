//! Per-flow traffic class — the closed set of six steering tiers.
//!
//! The control plane assigns one of these values to every flow
//! the classification engine processes. It travels on the event
//! envelope (`Envelope.TrafficClass`) and is promoted to a
//! ClickHouse `LowCardinality(String)` column by the hot-path
//! writer so per-class aggregates do not have to round-trip the
//! MessagePack payload.
//!
//! See `docs/TRAFFIC_CLASSIFICATION.md` for the full taxonomy and
//! `internal/repository/app_registry.go::TrafficClass` for the Go
//! definition this enum is wire-compatible with.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// One of the six per-flow steering tiers the SNG classification
/// engine emits. The serde representation is the lowercased
/// snake-case wire form (`trusted_direct`, `inspect_full`, etc.)
/// so a Rust producer round-trips byte-identical through the Go
/// envelope validator at `internal/nats/schema/envelope.go::Envelope::validate`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClass {
    /// DNS + cert-pin + IP-range binding, no proxy, no TLS
    /// decrypt. Cheapest and most trusted tier.
    TrustedDirect,
    /// Same trust guarantees as [`Self::TrustedDirect`] but
    /// telemetry is sampled for cost control on bandwidth-
    /// dominant media flows (Teams, Zoom, Webex).
    TrustedMediaBypass,
    /// DNS verification + URL-category lookup; no TLS decryption.
    InspectLite,
    /// Full SWG with TLS decrypt, AV, IPS, DLP. Default for
    /// unknown destinations — the conservative baseline.
    InspectFull,
    /// mTLS overlay to a tenant-private destination
    /// (ZTNA, internal LOB applications).
    TunnelPrivate,
    /// Connection refused at the earliest enforcement point.
    Block,
}

impl TrafficClass {
    /// The canonical enumeration order, used by validators, by
    /// the per-class output shape of the steering compiler, and
    /// by tests. Order matches
    /// `internal/repository/app_registry.go::AllTrafficClasses`.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::TrustedDirect,
            Self::TrustedMediaBypass,
            Self::InspectLite,
            Self::InspectFull,
            Self::TunnelPrivate,
            Self::Block,
        ]
    }

    /// The lowercase snake-case wire string. Stable across
    /// schema versions; new variants extend the set rather than
    /// renaming existing ones.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedDirect => "trusted_direct",
            Self::TrustedMediaBypass => "trusted_media_bypass",
            Self::InspectLite => "inspect_lite",
            Self::InspectFull => "inspect_full",
            Self::TunnelPrivate => "tunnel_private",
            Self::Block => "block",
        }
    }

    /// The conservative-baseline class. Used by the envelope
    /// validator when a legacy producer omits the `tc` field
    /// (matches the Go side default).
    #[must_use]
    pub const fn default_conservative() -> Self {
        Self::InspectFull
    }
}

impl fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`TrafficClass::from_str`] on an unknown value.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown traffic class: {0:?}")]
pub struct UnknownTrafficClass(pub String);

impl FromStr for TrafficClass {
    type Err = UnknownTrafficClass;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trusted_direct" => Ok(Self::TrustedDirect),
            "trusted_media_bypass" => Ok(Self::TrustedMediaBypass),
            "inspect_lite" => Ok(Self::InspectLite),
            "inspect_full" => Ok(Self::InspectFull),
            "tunnel_private" => Ok(Self::TunnelPrivate),
            "block" => Ok(Self::Block),
            other => Err(UnknownTrafficClass(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn all_lists_six_variants_in_canonical_order() {
        let all = TrafficClass::all();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0], TrafficClass::TrustedDirect);
        assert_eq!(all[5], TrafficClass::Block);
    }

    #[test]
    fn as_str_matches_go_side_wire_strings() {
        // These string constants are the contract with the Go
        // control plane; changing any of them is a wire-breaking
        // change.
        assert_eq!(TrafficClass::TrustedDirect.as_str(), "trusted_direct");
        assert_eq!(
            TrafficClass::TrustedMediaBypass.as_str(),
            "trusted_media_bypass"
        );
        assert_eq!(TrafficClass::InspectLite.as_str(), "inspect_lite");
        assert_eq!(TrafficClass::InspectFull.as_str(), "inspect_full");
        assert_eq!(TrafficClass::TunnelPrivate.as_str(), "tunnel_private");
        assert_eq!(TrafficClass::Block.as_str(), "block");
    }

    #[test]
    fn from_str_round_trips_through_all_variants() {
        for class in TrafficClass::all() {
            let parsed: TrafficClass = class.as_str().parse().expect("round trip");
            assert_eq!(parsed, class);
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        let err = "unknown_class".parse::<TrafficClass>().unwrap_err();
        assert_eq!(err.0, "unknown_class");
    }

    #[test]
    fn from_str_rejects_camel_case_or_pascal_case() {
        // The wire form is strict snake_case to match the Go
        // side; PascalCase / camelCase / SCREAMING_SNAKE_CASE
        // are all rejected.
        assert!("TrustedDirect".parse::<TrafficClass>().is_err());
        assert!("trustedDirect".parse::<TrafficClass>().is_err());
        assert!("TRUSTED_DIRECT".parse::<TrafficClass>().is_err());
    }

    #[test]
    fn serde_emits_snake_case_strings() {
        let json = serde_json::to_string(&TrafficClass::InspectFull).expect("serialize");
        assert_eq!(json, "\"inspect_full\"");
        let parsed: TrafficClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, TrafficClass::InspectFull);
    }

    #[test]
    fn default_conservative_is_inspect_full() {
        assert_eq!(
            TrafficClass::default_conservative(),
            TrafficClass::InspectFull
        );
    }

    #[test]
    fn display_matches_as_str() {
        for class in TrafficClass::all() {
            assert_eq!(class.to_string(), class.as_str());
        }
    }
}
