//! Per-flow [`Verdict`] — the engine's output type.
//!
//! Mirrors the verb set in `ARCHITECTURE.md` §3.2: the typed
//! policy graph emits `allow / deny / inspect / steer / decrypt /
//! log / suggest_only` verbs; the evaluation engine resolves a
//! matching rule into one of those plus enough metadata for the
//! receiver (firewall / SWG / DNS / ZTNA) to actually enforce.
//!
//! `Verdict` is intentionally a thin tagged enum — the receiver
//! subsystems hold the actual side-effect logic. The engine's
//! only job is to translate a rule + matching flow into the
//! correct variant + carry the rule's provenance through for
//! telemetry / audit.

use crate::rule::Verb;
use serde::{Deserialize, Serialize};
use sng_core::traffic_class::TrafficClass;

/// Inspection level for [`Verdict::Inspect`]. Mirrors the
/// `traffic_class.md` taxonomy: `Lite` is metadata-only (no TLS
/// decrypt), `Full` is full L7 inspection. Callers can extend
/// this in lockstep with the Go side when new tiers are added.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectLevel {
    /// DNS verify + URL category, no TLS decryption.
    Lite,
    /// Full SWG: TLS decrypt, AV, IPS, DLP.
    Full,
}

impl InspectLevel {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Full => "full",
        }
    }
}

/// The engine's per-flow output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Permit the flow.
    Allow,
    /// Refuse the flow at the earliest enforcement point.
    Deny,
    /// Permit + inspect at the given level.
    Inspect {
        /// Inspection depth.
        level: InspectLevel,
    },
    /// Permit + steer to a specific traffic class. The class is
    /// looked up via [`crate::steering::SteeringTable`] when the
    /// rule fires; if no steering binding exists for the flow,
    /// the engine falls back to [`TrafficClass::default_conservative`].
    Steer {
        /// The class to route the flow into.
        class: TrafficClass,
    },
    /// Permit + decrypt TLS for L7 inspection.
    Decrypt,
    /// Permit + log (metadata-only). No payload, no decrypt.
    Log,
    /// Suggestion only — surface to the operator UI, do not
    /// enforce. The wrapped verb is the would-be enforcement
    /// outcome.
    SuggestOnly {
        /// The verb that would have been applied. Wire shape
        /// matches the Go side's verb strings.
        suggestion: Verb,
    },
}

impl Verdict {
    /// Construct the verdict that corresponds to a verb when no
    /// extra metadata is needed (Allow / Deny / Decrypt / Log).
    /// Inspect / Steer / SuggestOnly require additional fields
    /// and are not produced by this helper.
    #[must_use]
    pub const fn from_simple_verb(verb: Verb) -> Option<Self> {
        match verb {
            Verb::Allow => Some(Self::Allow),
            Verb::Deny => Some(Self::Deny),
            Verb::Decrypt => Some(Self::Decrypt),
            Verb::Log => Some(Self::Log),
            Verb::Inspect | Verb::Steer | Verb::SuggestOnly => None,
        }
    }

    /// Convenience: would this verdict actually block traffic?
    /// `Deny` is the only blocking outcome; `SuggestOnly { Deny }`
    /// is intentionally *not* blocking (it's an advisory).
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn from_simple_verb_returns_some_for_basic_verbs() {
        assert_eq!(Verdict::from_simple_verb(Verb::Allow), Some(Verdict::Allow));
        assert_eq!(Verdict::from_simple_verb(Verb::Deny), Some(Verdict::Deny));
        assert_eq!(
            Verdict::from_simple_verb(Verb::Decrypt),
            Some(Verdict::Decrypt)
        );
        assert_eq!(Verdict::from_simple_verb(Verb::Log), Some(Verdict::Log));
    }

    #[test]
    fn from_simple_verb_returns_none_for_payload_carrying_verbs() {
        assert_eq!(Verdict::from_simple_verb(Verb::Inspect), None);
        assert_eq!(Verdict::from_simple_verb(Verb::Steer), None);
        assert_eq!(Verdict::from_simple_verb(Verb::SuggestOnly), None);
    }

    #[test]
    fn is_blocking_only_true_for_deny() {
        assert!(Verdict::Deny.is_blocking());
        assert!(!Verdict::Allow.is_blocking());
        assert!(
            !Verdict::SuggestOnly {
                suggestion: Verb::Deny
            }
            .is_blocking()
        );
        assert!(
            !Verdict::Inspect {
                level: InspectLevel::Full
            }
            .is_blocking()
        );
    }

    #[test]
    fn verdict_roundtrips_through_serde_json() {
        for v in [
            Verdict::Allow,
            Verdict::Deny,
            Verdict::Decrypt,
            Verdict::Log,
            Verdict::Inspect {
                level: InspectLevel::Full,
            },
            Verdict::Steer {
                class: TrafficClass::InspectFull,
            },
            Verdict::SuggestOnly {
                suggestion: Verb::Deny,
            },
        ] {
            let encoded = serde_json::to_string(&v).unwrap();
            let decoded: Verdict = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, v);
        }
    }
}
