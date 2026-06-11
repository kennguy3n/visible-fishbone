//! Endpoint DLP policy: the rule set + channel configuration the
//! agent loads out of the signed endpoint bundle.
//!
//! The Go control plane compiles a tenant's endpoint DLP rules into
//! a JSON blob carried under the `dlp` enforcement domain of the
//! `endpoint` policy bundle (see `internal/service/dlp`). This
//! module is the agent-side decoder + validator for that blob. It
//! is deliberately transport-agnostic: signature verification and
//! bundle envelope handling already happened in `sng-core` /
//! `sng-policy-eval`; by the time bytes reach [`DlpPolicy::from_bundle_json`]
//! they are authenticated.

use crate::ai_app::AiAppPolicy;
use crate::channels::{ChannelConfig, DlpChannel};
use crate::error::{DlpError, DlpResult};
use crate::rules::DlpRule;
use serde::{Deserialize, Serialize};
use sng_policy_eval::{BundleTarget, EnforcementDomain};
use std::collections::{BTreeMap, BTreeSet};

/// Highest policy schema version this build understands. A policy
/// declaring a newer version is rejected (fail-closed) rather than
/// silently partially-applied — the same posture
/// `sng_policy_eval::MAX_SUPPORTED_SCHEMA_VERSION` takes.
pub const MAX_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// The active endpoint DLP policy.
///
/// Not `Eq`: the optional [`AiAppPolicy`] carries `f64` confidence
/// thresholds, so the struct is only `PartialEq` (sufficient for the
/// round-trip tests and the engine's snapshot comparisons).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DlpPolicy {
    /// Schema version of this policy document.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// The enforcement plane this policy targets. Must be
    /// [`BundleTarget::Endpoint`].
    #[serde(default = "default_target")]
    pub target: BundleTarget,
    /// The policy-graph domain. Must be [`EnforcementDomain::Dlp`].
    #[serde(default = "default_domain")]
    pub domain: EnforcementDomain,
    /// The active detection rules.
    #[serde(default)]
    pub rules: Vec<DlpRule>,
    /// Per-channel configuration. Channels absent from this map use
    /// [`ChannelConfig::default`] (enabled, no action floor).
    #[serde(default)]
    pub channels: BTreeMap<DlpChannel, ChannelConfig>,
    /// Operator policy for the AI-app exfiltration detector. `None`
    /// (the default, and the shape older control planes emit) leaves
    /// the detector disabled — the false-positive-averse posture. When
    /// present, the agent enables the detector with this policy on
    /// bundle apply, so the coach-first AI-app signal becomes live
    /// without a separate distribution channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_app: Option<AiAppPolicy>,
}

const fn default_schema_version() -> u32 {
    1
}

const fn default_target() -> BundleTarget {
    BundleTarget::Endpoint
}

const fn default_domain() -> EnforcementDomain {
    EnforcementDomain::Dlp
}

impl Default for DlpPolicy {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            target: default_target(),
            domain: default_domain(),
            rules: Vec::new(),
            channels: BTreeMap::new(),
            ai_app: None,
        }
    }
}

impl DlpPolicy {
    /// Decode + validate a policy from the JSON blob carried in the
    /// endpoint bundle's `dlp` domain.
    ///
    /// # Errors
    /// * [`DlpError::PolicyDecode`] — bytes are not valid policy
    ///   JSON.
    /// * [`DlpError::PolicyTargetMismatch`] — the policy targets a
    ///   plane other than `endpoint`.
    /// * [`DlpError::PolicyInvalid`] — schema too new, wrong
    ///   domain, or a duplicate rule id.
    pub fn from_bundle_json(bytes: &[u8]) -> DlpResult<Self> {
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|e| DlpError::PolicyDecode(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Serialise the policy back to the bundle JSON shape. Useful
    /// for the control-plane round-trip tests and for tooling that
    /// re-emits a policy.
    ///
    /// # Errors
    /// [`DlpError::PolicyDecode`] if serialisation fails (only
    /// possible on a non-string map key, which cannot occur here).
    pub fn to_bundle_json(&self) -> DlpResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| DlpError::PolicyDecode(e.to_string()))
    }

    /// Validate structural invariants. Called by
    /// [`Self::from_bundle_json`]; exposed for callers that build a
    /// policy in-process.
    ///
    /// # Errors
    /// See [`Self::from_bundle_json`].
    pub fn validate(&self) -> DlpResult<()> {
        if self.target != BundleTarget::Endpoint {
            return Err(DlpError::PolicyTargetMismatch {
                got: self.target.as_str().to_owned(),
            });
        }
        if self.domain != EnforcementDomain::Dlp {
            return Err(DlpError::PolicyInvalid(format!(
                "expected dlp domain, got {}",
                self.domain.as_str()
            )));
        }
        if self.schema_version > MAX_SUPPORTED_SCHEMA_VERSION {
            return Err(DlpError::PolicyInvalid(format!(
                "schema version {} exceeds supported {}",
                self.schema_version, MAX_SUPPORTED_SCHEMA_VERSION
            )));
        }
        let mut seen = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err(DlpError::PolicyInvalid("rule with empty id".to_owned()));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(DlpError::PolicyInvalid(format!(
                    "duplicate rule id {:?}",
                    rule.id
                )));
            }
        }
        if let Some(ai) = &self.ai_app {
            for (name, v) in [
                ("block_confidence", ai.block_confidence),
                ("min_report_confidence", ai.min_report_confidence),
            ] {
                if !(0.0..=1.0).contains(&v) {
                    return Err(DlpError::PolicyInvalid(format!(
                        "ai_app {name} {v} out of [0,1]"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The configuration for `channel` — explicit if present,
    /// otherwise the default.
    #[must_use]
    pub fn channel_config(&self, channel: DlpChannel) -> ChannelConfig {
        self.channels.get(&channel).copied().unwrap_or_default()
    }

    /// Whether inspection is enabled for `channel`.
    #[must_use]
    pub fn is_channel_enabled(&self, channel: DlpChannel) -> bool {
        self.channel_config(channel).enabled
    }

    /// The active rules.
    #[must_use]
    pub fn rules(&self) -> &[DlpRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{PatternType, RuleAction, Severity};
    use pretty_assertions::assert_eq;

    fn sample_rule(id: &str) -> DlpRule {
        DlpRule {
            id: id.to_owned(),
            name: id.to_owned(),
            pattern_type: PatternType::Regex,
            pattern_data: "ssn_us".to_owned(),
            severity: Severity::Critical,
            action: RuleAction::Block,
            channels: vec![DlpChannel::FileWrite],
        }
    }

    #[test]
    fn endpoint_policy_roundtrips_through_bundle_json() {
        let mut channels = BTreeMap::new();
        channels.insert(
            DlpChannel::UsbTransfer,
            ChannelConfig {
                enabled: true,
                action_override: Some(RuleAction::Block),
            },
        );
        channels.insert(
            DlpChannel::Print,
            ChannelConfig {
                enabled: false,
                action_override: None,
            },
        );
        let policy = DlpPolicy {
            schema_version: 1,
            target: BundleTarget::Endpoint,
            domain: EnforcementDomain::Dlp,
            rules: vec![sample_rule("r1"), sample_rule("r2")],
            channels,
            ai_app: Some(AiAppPolicy::default()),
        };
        let bytes = policy.to_bundle_json().expect("encode");
        let back = DlpPolicy::from_bundle_json(&bytes).expect("decode");
        assert_eq!(policy, back);
    }

    #[test]
    fn defaults_apply_to_a_minimal_blob() {
        // Only rules supplied; target/domain/schema default in.
        let blob = br#"{"rules":[]}"#;
        let policy = DlpPolicy::from_bundle_json(blob).expect("decode");
        assert_eq!(policy.target, BundleTarget::Endpoint);
        assert_eq!(policy.domain, EnforcementDomain::Dlp);
        assert_eq!(policy.schema_version, 1);
        // Unconfigured channels default to enabled.
        assert!(policy.is_channel_enabled(DlpChannel::Clipboard));
    }

    #[test]
    fn wrong_target_is_rejected() {
        let blob = br#"{"target":"edge","rules":[]}"#;
        let err = DlpPolicy::from_bundle_json(blob).unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::PolicyTargetMismatch);
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let blob = br#"{"domain":"swg","rules":[]}"#;
        let err = DlpPolicy::from_bundle_json(blob).unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::PolicyInvalid);
    }

    #[test]
    fn schema_too_new_is_rejected() {
        let blob = br#"{"schema_version":999,"rules":[]}"#;
        let err = DlpPolicy::from_bundle_json(blob).unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::PolicyInvalid);
    }

    #[test]
    fn duplicate_rule_id_is_rejected() {
        let policy = DlpPolicy {
            rules: vec![sample_rule("dup"), sample_rule("dup")],
            ..DlpPolicy::default()
        };
        let err = policy.validate().unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::PolicyInvalid);
    }

    #[test]
    fn disabled_channel_reported() {
        let mut channels = BTreeMap::new();
        channels.insert(
            DlpChannel::Print,
            ChannelConfig {
                enabled: false,
                action_override: None,
            },
        );
        let policy = DlpPolicy {
            channels,
            ..DlpPolicy::default()
        };
        assert!(!policy.is_channel_enabled(DlpChannel::Print));
        assert!(policy.is_channel_enabled(DlpChannel::Clipboard));
    }
}
