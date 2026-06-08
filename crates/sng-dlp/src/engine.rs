//! The DLP engine: classification + policy evaluation + verdict.
//!
//! [`DlpEngine`] ties a [`DlpPolicy`] to its compiled
//! [`ContentClassifier`] and turns a content event into a
//! [`DlpVerdict`]. The active (policy, classifier) pair lives behind
//! an [`arc_swap::ArcSwap`] so the evaluation hot path
//! ([`DlpEngine::evaluate`]) never takes a lock and a policy
//! rotation ([`DlpEngine::install`]) is a single atomic pointer
//! swap — the same lock-free hot-swap discipline
//! `sng_policy_eval::PolicyEngine` uses for bundle rotation.

use crate::channels::{ContentEvent, DlpChannel};
use crate::classifier::{ClassificationResult, ContentClassifier, ContentMetadata, RuleMatch};
use crate::error::DlpResult;
use crate::ml_classifier::{MlNerDetector, ModelVerifier, NerModel, SignedModel};
use crate::policy::DlpPolicy;
use crate::rules::{RuleAction, Severity};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The metadata attached to an enforcing verdict. Carries the
/// matched-rule provenance for the audit trail — and, per the
/// redaction invariant, **only** metadata: rule ids, severities,
/// confidence, and match spans, never the matched bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerdictDetails {
    /// The channel the content was observed on.
    pub channel: DlpChannel,
    /// The resolved action (strictest across matches, after any
    /// channel action floor).
    pub action: RuleAction,
    /// The highest severity among the matched rules.
    pub severity: Severity,
    /// The individual rule matches (metadata only).
    pub matches: Vec<RuleMatch>,
}

/// The engine's decision for a single content event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum DlpVerdict {
    /// No rule matched (or the channel is disabled): permit the
    /// transfer silently.
    Allow,
    /// A rule matched at `log` strength: permit, but record the
    /// event for audit.
    LogOnly(VerdictDetails),
    /// A rule matched at `warn` strength: prompt the user but allow
    /// them to proceed.
    WarnUser(VerdictDetails),
    /// A rule matched at `block` strength: refuse the transfer.
    Block(VerdictDetails),
}

impl DlpVerdict {
    /// Whether this verdict refuses the transfer.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    /// Whether this verdict permits the transfer with no user-facing
    /// interruption (`Allow` or `LogOnly`).
    #[must_use]
    pub const fn is_silent_allow(&self) -> bool {
        matches!(self, Self::Allow | Self::LogOnly(_))
    }

    /// The resolved action, if the verdict carries one.
    #[must_use]
    pub const fn action(&self) -> Option<RuleAction> {
        match self {
            Self::Allow => None,
            Self::LogOnly(d) | Self::WarnUser(d) | Self::Block(d) => Some(d.action),
        }
    }

    /// The verdict details, if any.
    #[must_use]
    pub const fn details(&self) -> Option<&VerdictDetails> {
        match self {
            Self::Allow => None,
            Self::LogOnly(d) | Self::WarnUser(d) | Self::Block(d) => Some(d),
        }
    }

    /// Build the verdict for a resolved `action` + match set.
    fn from_action(
        action: RuleAction,
        channel: DlpChannel,
        severity: Severity,
        matches: Vec<RuleMatch>,
    ) -> Self {
        let details = VerdictDetails {
            channel,
            action,
            severity,
            matches,
        };
        match action {
            RuleAction::Log => Self::LogOnly(details),
            RuleAction::Warn => Self::WarnUser(details),
            RuleAction::Block => Self::Block(details),
        }
    }
}

/// The atomically-swappable (policy + classifier) pair.
#[derive(Debug)]
struct EngineState {
    policy: DlpPolicy,
    classifier: ContentClassifier,
    max_scan_bytes: usize,
}

/// The endpoint DLP engine.
///
/// Two atomically-swappable cells share the lock-free hot-swap
/// discipline: [`Self::state`] holds the active (policy + compiled
/// classifier) pair, and [`Self::model`] holds the currently-installed
/// ML-NER detector. The detector is held separately because the ONNX
/// model and the policy rotate on independent schedules (a model is a
/// large, slowly-changing asset; policies churn far more often). Both
/// [`Self::install`] and [`Self::install_model`] recompile the
/// classifier from these two inputs and publish the result in a single
/// `store`, so a reader in [`Self::evaluate`] always sees a consistent
/// (policy, classifier, model) triple.
#[derive(Debug)]
pub struct DlpEngine {
    state: ArcSwap<EngineState>,
    model: ArcSwap<MlNerDetector>,
}

impl DlpEngine {
    /// Build an engine from `policy`, compiling its rules with the
    /// classifier's default scan ceiling.
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::RuleCompile`] if any
    /// rule fails to compile.
    pub fn new(policy: DlpPolicy) -> DlpResult<Self> {
        Self::with_limit(policy, crate::classifier::DEFAULT_MAX_SCAN_BYTES)
    }

    /// Build an engine with an explicit per-event scan ceiling.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn with_limit(policy: DlpPolicy, max_scan_bytes: usize) -> DlpResult<Self> {
        let model = MlNerDetector::fallback_only();
        let classifier =
            ContentClassifier::compile_with_model(policy.rules(), max_scan_bytes, model.clone())?;
        Ok(Self {
            state: ArcSwap::from_pointee(EngineState {
                policy,
                classifier,
                max_scan_bytes,
            }),
            model: ArcSwap::from_pointee(model),
        })
    }

    /// Atomically install a new policy, recompiling the classifier.
    /// On success the swap is visible to every subsequent
    /// [`Self::evaluate`]; on failure the existing policy is left
    /// untouched (fail-closed: a bad bundle never disarms DLP).
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::RuleCompile`] if any
    /// rule in `policy` fails to compile. The engine is unchanged.
    pub fn install(&self, policy: DlpPolicy) -> DlpResult<()> {
        let max_scan_bytes = self.state.load().max_scan_bytes;
        let model = self.model.load().as_ref().clone();
        let classifier =
            ContentClassifier::compile_with_model(policy.rules(), max_scan_bytes, model)?;
        self.state.store(Arc::new(EngineState {
            policy,
            classifier,
            max_scan_bytes,
        }));
        Ok(())
    }

    /// Atomically install a verified ML-NER model, recompiling the
    /// active policy's classifier so its `MlNer` rules switch from the
    /// regex fallback to on-device ONNX inference. The model bytes are
    /// verified against `verifier` (the same Ed25519 trust store the
    /// policy bundle uses) *before* they are loaded — an unsigned,
    /// untrusted, or tampered model is rejected and the engine is left
    /// untouched (fail-closed).
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::ModelSignatureInvalid`] if
    /// verification fails, [`crate::error::DlpError::ModelLoad`] if the
    /// verified bytes are not a loadable ONNX graph, or
    /// [`crate::error::DlpError::RuleCompile`] if recompilation fails.
    /// In every error case the previously-active model and classifier
    /// are preserved.
    pub fn install_model(&self, signed: &SignedModel, verifier: &ModelVerifier) -> DlpResult<()> {
        let model = NerModel::load_signed(signed, verifier)?;
        let detector = MlNerDetector::with_model(Arc::new(model));
        self.recompile_with_model(detector)
    }

    /// Atomically revert to the regex-only NER fallback, recompiling
    /// the active policy's classifier. Used when an operator unassigns
    /// a model from a tenant; DLP keeps detecting (fail-safe).
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::RuleCompile`] if
    /// recompilation fails; the engine is unchanged on error.
    pub fn clear_model(&self) -> DlpResult<()> {
        self.recompile_with_model(MlNerDetector::fallback_only())
    }

    /// Whether an ONNX model is currently installed (vs. the regex
    /// fallback).
    #[must_use]
    pub fn has_ml_model(&self) -> bool {
        self.model.load().has_model()
    }

    /// Recompile the active policy with `detector`, then publish the
    /// new detector and engine state. The detector is stored only
    /// after a successful recompile so a compile failure cannot leave
    /// the stored model out of sync with the active classifier.
    fn recompile_with_model(&self, detector: MlNerDetector) -> DlpResult<()> {
        let current = self.state.load();
        let classifier = ContentClassifier::compile_with_model(
            current.policy.rules(),
            current.max_scan_bytes,
            detector.clone(),
        )?;
        let policy = current.policy.clone();
        let max_scan_bytes = current.max_scan_bytes;
        self.model.store(Arc::new(detector));
        self.state.store(Arc::new(EngineState {
            policy,
            classifier,
            max_scan_bytes,
        }));
        Ok(())
    }

    /// A snapshot of the currently-active policy.
    #[must_use]
    pub fn current_policy(&self) -> DlpPolicy {
        self.state.load().policy.clone()
    }

    /// Evaluate `content` observed on `channel` against the active
    /// policy and return the verdict.
    ///
    /// A disabled channel or an empty match set yields
    /// [`DlpVerdict::Allow`]. Otherwise the strictest action across
    /// all matching rules is taken, escalated to at least the
    /// channel's configured action floor (if any), and mapped to a
    /// verdict variant.
    #[must_use]
    pub fn evaluate(
        &self,
        channel: DlpChannel,
        content: &[u8],
        metadata: &ContentMetadata,
    ) -> DlpVerdict {
        let state = self.state.load();
        let config = state.policy.channel_config(channel);
        if !config.enabled {
            return DlpVerdict::Allow;
        }

        let result: ClassificationResult = state.classifier.classify(channel, content, metadata);
        let Some(rule_action) = result.strictest_action() else {
            return DlpVerdict::Allow;
        };

        // Apply the channel-wide action floor, if configured.
        let action = match config.action_override {
            Some(floor) => rule_action.max(floor),
            None => rule_action,
        };
        let severity = result.max_severity().unwrap_or(Severity::Low);
        DlpVerdict::from_action(action, channel, severity, result.matches)
    }

    /// Convenience wrapper that evaluates a [`ContentEvent`]
    /// produced by a `sng-pal` channel interceptor.
    #[must_use]
    pub fn evaluate_event(&self, event: &ContentEvent) -> DlpVerdict {
        self.evaluate(event.channel, &event.content, &event.metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::ChannelConfig;
    use crate::rules::{DlpRule, PatternType};
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;

    fn rule(id: &str, data: &str, action: RuleAction, sev: Severity) -> DlpRule {
        DlpRule {
            id: id.to_owned(),
            name: id.to_owned(),
            pattern_type: PatternType::Keyword,
            pattern_data: data.to_owned(),
            severity: sev,
            action,
            channels: vec![],
        }
    }

    fn engine_with(rules: Vec<DlpRule>) -> DlpEngine {
        DlpEngine::new(DlpPolicy {
            rules,
            ..DlpPolicy::default()
        })
        .expect("engine")
    }

    #[test]
    fn no_match_allows() {
        let e = engine_with(vec![rule("k", "secret", RuleAction::Block, Severity::High)]);
        let v = e.evaluate(
            DlpChannel::Clipboard,
            b"nothing sensitive",
            &ContentMetadata::default(),
        );
        assert_eq!(v, DlpVerdict::Allow);
        assert!(!v.is_blocking());
        assert!(v.is_silent_allow());
    }

    #[test]
    fn block_rule_blocks_and_carries_metadata() {
        let e = engine_with(vec![rule(
            "k",
            "secret",
            RuleAction::Block,
            Severity::Critical,
        )]);
        let v = e.evaluate(
            DlpChannel::UsbTransfer,
            b"this is secret",
            &ContentMetadata::default(),
        );
        assert!(v.is_blocking());
        let d = v.details().expect("details");
        assert_eq!(d.channel, DlpChannel::UsbTransfer);
        assert_eq!(d.action, RuleAction::Block);
        assert_eq!(d.severity, Severity::Critical);
        assert_eq!(d.matches.len(), 1);
        assert_eq!(d.matches[0].rule_id, "k");
    }

    #[test]
    fn strictest_action_wins_across_rules() {
        let e = engine_with(vec![
            rule("log", "alpha", RuleAction::Log, Severity::Low),
            rule("warn", "beta", RuleAction::Warn, Severity::Medium),
        ]);
        let v = e.evaluate(
            DlpChannel::Print,
            b"alpha and beta",
            &ContentMetadata::default(),
        );
        assert_eq!(v.action(), Some(RuleAction::Warn));
        assert!(matches!(v, DlpVerdict::WarnUser(_)));
    }

    #[test]
    fn disabled_channel_short_circuits_to_allow() {
        let mut channels = BTreeMap::new();
        channels.insert(
            DlpChannel::Clipboard,
            ChannelConfig {
                enabled: false,
                action_override: None,
            },
        );
        let e = DlpEngine::new(DlpPolicy {
            rules: vec![rule("k", "secret", RuleAction::Block, Severity::High)],
            channels,
            ..DlpPolicy::default()
        })
        .expect("engine");
        // Would match, but the channel is disabled.
        assert_eq!(
            e.evaluate(
                DlpChannel::Clipboard,
                b"secret",
                &ContentMetadata::default()
            ),
            DlpVerdict::Allow
        );
        // A different channel still enforces.
        assert!(
            e.evaluate(
                DlpChannel::FileWrite,
                b"secret",
                &ContentMetadata::default()
            )
            .is_blocking()
        );
    }

    #[test]
    fn channel_action_floor_escalates() {
        let mut channels = BTreeMap::new();
        channels.insert(
            DlpChannel::UsbTransfer,
            ChannelConfig {
                enabled: true,
                action_override: Some(RuleAction::Block),
            },
        );
        let e = DlpEngine::new(DlpPolicy {
            // Rule only asks to log...
            rules: vec![rule("k", "secret", RuleAction::Log, Severity::Low)],
            channels,
            ..DlpPolicy::default()
        })
        .expect("engine");
        // ...but the USB channel floor escalates it to block.
        let v = e.evaluate(
            DlpChannel::UsbTransfer,
            b"secret",
            &ContentMetadata::default(),
        );
        assert!(v.is_blocking());
        // On a channel without a floor, the rule's own action stands.
        let v2 = e.evaluate(
            DlpChannel::Clipboard,
            b"secret",
            &ContentMetadata::default(),
        );
        assert!(matches!(v2, DlpVerdict::LogOnly(_)));
    }

    #[test]
    fn hot_swap_installs_new_policy_atomically() {
        let e = engine_with(vec![rule("k", "alpha", RuleAction::Block, Severity::High)]);
        assert!(
            e.evaluate(DlpChannel::Clipboard, b"alpha", &ContentMetadata::default())
                .is_blocking()
        );

        e.install(DlpPolicy {
            rules: vec![rule("k2", "beta", RuleAction::Block, Severity::High)],
            ..DlpPolicy::default()
        })
        .expect("install");

        // Old rule no longer matches; new one does.
        assert_eq!(
            e.evaluate(DlpChannel::Clipboard, b"alpha", &ContentMetadata::default()),
            DlpVerdict::Allow
        );
        assert!(
            e.evaluate(DlpChannel::Clipboard, b"beta", &ContentMetadata::default())
                .is_blocking()
        );
        assert_eq!(e.current_policy().rules().len(), 1);
    }

    #[test]
    fn install_failure_leaves_engine_armed() {
        let e = engine_with(vec![rule("k", "alpha", RuleAction::Block, Severity::High)]);
        // Bad regex rule fails to compile.
        let bad = DlpPolicy {
            rules: vec![DlpRule {
                id: "bad".to_owned(),
                name: "bad".to_owned(),
                pattern_type: PatternType::Regex,
                pattern_data: "(".to_owned(),
                severity: Severity::High,
                action: RuleAction::Block,
                channels: vec![],
            }],
            ..DlpPolicy::default()
        };
        assert!(e.install(bad).is_err());
        // Original policy still enforces.
        assert!(
            e.evaluate(DlpChannel::Clipboard, b"alpha", &ContentMetadata::default())
                .is_blocking()
        );
    }

    #[test]
    fn verdict_serialises_metadata_only() {
        let e = engine_with(vec![rule("k", "secret", RuleAction::Block, Severity::High)]);
        let v = e.evaluate(
            DlpChannel::Clipboard,
            b"the secret value",
            &ContentMetadata::default(),
        );
        let json = serde_json::to_string(&v).expect("encode");
        assert!(json.contains("\"verdict\":\"block\""));
        assert!(json.contains("\"rule_id\":\"k\""));
    }

    fn ml_rule(id: &str, classes: &str, action: RuleAction, sev: Severity) -> DlpRule {
        DlpRule {
            id: id.to_owned(),
            name: id.to_owned(),
            pattern_type: PatternType::MlNer,
            pattern_data: classes.to_owned(),
            severity: sev,
            action,
            channels: vec![],
        }
    }

    #[test]
    fn ml_ner_rule_blocks_via_fallback_then_via_loaded_model() {
        let e = engine_with(vec![ml_rule(
            "phone",
            "phone_number",
            RuleAction::Block,
            Severity::High,
        )]);
        // No model installed: the fail-safe regex NER still detects.
        assert!(!e.has_ml_model());
        let v = e.evaluate(
            DlpChannel::Clipboard,
            b"call +1-202-555-0173 now",
            &ContentMetadata::default(),
        );
        assert!(
            v.is_blocking(),
            "fallback NER should detect the phone number"
        );

        // Install the real signed model and confirm detection persists
        // through the hot-swap (now via on-device ONNX inference).
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let kid = sng_core::ids::PolicySigningKeyId::new("engine-model-key").expect("kid");
        let model_bytes = include_bytes!("../assets/ner_v1.onnx");
        let sig = ed25519_dalek::Signer::sign(&key, model_bytes.as_slice());
        let signed = SignedModel {
            model: model_bytes.to_vec(),
            signature: sig.to_bytes(),
            signing_key_id: kid.clone(),
        };
        let mut verifier = ModelVerifier::new();
        verifier
            .add_key(kid, &key.verifying_key().to_bytes())
            .expect("trust key");
        e.install_model(&signed, &verifier).expect("install model");
        assert!(e.has_ml_model());
        let v = e.evaluate(
            DlpChannel::Clipboard,
            b"call +1-202-555-0173 now",
            &ContentMetadata::default(),
        );
        assert!(
            v.is_blocking(),
            "loaded ONNX model should detect the phone number"
        );

        // Reverting to the fallback keeps DLP armed.
        e.clear_model().expect("clear model");
        assert!(!e.has_ml_model());
    }

    #[test]
    fn install_model_failure_leaves_engine_on_fallback() {
        let e = engine_with(vec![ml_rule(
            "phone",
            "phone_number",
            RuleAction::Block,
            Severity::High,
        )]);
        // A model whose signature does not verify must be rejected and
        // leave the engine on its (working) fallback detector.
        let key = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let kid = sng_core::ids::PolicySigningKeyId::new("bad-model-key").expect("kid");
        let signed = SignedModel {
            model: include_bytes!("../assets/ner_v1.onnx").to_vec(),
            signature: [0u8; 64], // not a valid signature
            signing_key_id: kid.clone(),
        };
        let mut verifier = ModelVerifier::new();
        verifier
            .add_key(kid, &key.verifying_key().to_bytes())
            .expect("trust key");
        assert!(e.install_model(&signed, &verifier).is_err());
        assert!(!e.has_ml_model());
        // Detection still works via the fallback.
        assert!(
            e.evaluate(
                DlpChannel::Clipboard,
                b"call +1-202-555-0173 now",
                &ContentMetadata::default()
            )
            .is_blocking()
        );
    }
}
