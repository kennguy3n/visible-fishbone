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

use crate::ai_app::{AiAppExfilDetector, AiAppPolicy, AiAppSignal, default_pii_rules};
use crate::channels::{ContentEvent, DlpChannel};
use crate::classifier::{ClassificationResult, ContentClassifier, ContentMetadata, RuleMatch};
use crate::error::DlpResult;
use crate::ml_classifier::{MlNerDetector, ModelVerifier, NerModel, SignedModel};
use crate::policy::DlpPolicy;
use crate::rules::{RuleAction, Severity};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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

/// The atomically-swappable engine snapshot: the active policy, its
/// compiled classifier (which already has the ML-NER detector baked
/// in), the scan ceiling, and the currently-installed detector. All
/// four are published together in one [`ArcSwap`] store, so a reader
/// in [`DlpEngine::evaluate`] always sees a consistent
/// (policy, classifier, model) snapshot.
#[derive(Debug)]
struct EngineState {
    policy: DlpPolicy,
    classifier: ContentClassifier,
    max_scan_bytes: usize,
    model: MlNerDetector,
    /// The operator's AI-app exfil policy, if enabled. Kept alongside
    /// the compiled detector so every recompile (policy or model
    /// rotation) can rebuild the detector against the *current* model.
    ai_app_policy: Option<AiAppPolicy>,
    /// The compiled AI-app exfil detector, present iff `ai_app_policy`
    /// is `Some`. It reuses the engine's live ML-NER model for its PII
    /// pass (via [`AiAppExfilDetector::with_classifier`]) so a model
    /// rotation lifts AI-upload detection too.
    ai_app: Option<AiAppExfilDetector>,
}

/// Build the AI-app exfil detector for `ai_app_policy`, sharing the
/// engine's live ML-NER `model` for its reused-PII classifier so the
/// AI-upload path benefits from the same on-device model as the channel
/// classifier. Returns `None` when no AI-app policy is configured.
fn build_ai_app(
    ai_app_policy: Option<&AiAppPolicy>,
    max_scan_bytes: usize,
    model: &MlNerDetector,
) -> DlpResult<Option<AiAppExfilDetector>> {
    match ai_app_policy {
        Some(policy) => {
            let classifier = ContentClassifier::compile_with_model(
                &default_pii_rules(),
                max_scan_bytes,
                model.clone(),
            )?;
            Ok(Some(AiAppExfilDetector::with_classifier(
                classifier,
                policy.clone(),
            )))
        }
        None => Ok(None),
    }
}

/// The endpoint DLP engine.
///
/// The active (policy + compiled classifier + installed ML-NER
/// detector) snapshot lives behind a single [`arc_swap::ArcSwap`]
/// ([`Self::state`]) so the evaluation hot path ([`Self::evaluate`])
/// never takes a lock and always observes a consistent triple. Every
/// mutator ([`Self::install`], [`Self::install_model`],
/// [`Self::clear_model`]) recompiles the classifier and publishes the
/// result in one atomic `store`.
///
/// Those mutators are read-modify-write (read the live snapshot,
/// recompile, store), so two running concurrently could otherwise
/// clobber one another's update — e.g. an `install` racing an
/// `install_model` could drop the new policy or the new model.
/// [`Self::write_lock`] serialises all mutators; it is taken only by
/// the (rare) rotation paths and never by [`Self::evaluate`], so the
/// hot path stays lock-free.
#[derive(Debug)]
pub struct DlpEngine {
    state: ArcSwap<EngineState>,
    write_lock: Mutex<()>,
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
                model,
                ai_app_policy: None,
                ai_app: None,
            }),
            write_lock: Mutex::new(()),
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
    pub fn install(&self, mut policy: DlpPolicy) -> DlpResult<()> {
        let _guard = self.write_guard();
        let current = self.state.load();
        let max_scan_bytes = current.max_scan_bytes;
        let model = current.model.clone();
        let classifier =
            ContentClassifier::compile_with_model(policy.rules(), max_scan_bytes, model.clone())?;
        // `install` rotates only the rule set + channel config. The
        // AI-app detector and the ML-NER model are orthogonal
        // dimensions, each mutated by its own atomic path
        // (`set_ai_app_policy`, `install_model`), so a rule-only
        // rotation must preserve both — hence the rebuild from the
        // *current* `ai_app_policy`. The bundle-apply path does not use
        // this method: it lands the document's rules + `ai_app` block
        // together via the atomic `install_with_ai_app`, so there is no
        // redundant detector rebuild there.
        let ai_app_policy = current.ai_app_policy.clone();
        // The incoming policy carries its own `ai_app` field, but this
        // rule-only rotation keeps the *current* detector — so normalise
        // the stored struct's field to the authoritative `ai_app_policy`
        // it is paired with. Without this, `current_policy().ai_app`
        // could report a detector config the engine is not running.
        policy.ai_app = ai_app_policy.clone();
        let ai_app = build_ai_app(ai_app_policy.as_ref(), max_scan_bytes, &model)?;
        self.state.store(Arc::new(EngineState {
            policy,
            classifier,
            max_scan_bytes,
            model,
            ai_app_policy,
            ai_app,
        }));
        Ok(())
    }

    /// Atomically install a new rule-set policy *and* (re)configure the
    /// AI-app exfiltration detector in a single state swap.
    ///
    /// This is the bundle-apply path: the control plane ships the rule
    /// set + channel config and the `ai_app` detector block in one
    /// document, so they must land together. Doing it as one
    /// [`ArcSwap`] store (rather than [`Self::install`] followed by
    /// [`Self::set_ai_app_policy`]) means concurrent evaluators can
    /// never observe the new rules paired with the *previous* detector
    /// (or vice-versa) through the brief window between two separate
    /// stores. The ML-NER model dimension is untouched and preserved.
    ///
    /// Both compilations happen before the store, so on any compile
    /// failure the engine is left entirely untouched (fail-safe: a bad
    /// bundle never disarms or half-updates DLP).
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::RuleCompile`] if any rule in
    /// `policy` or the builtin AI-app PII rule set fails to compile. The
    /// engine is unchanged.
    pub fn install_with_ai_app(
        &self,
        mut policy: DlpPolicy,
        ai_app_policy: Option<AiAppPolicy>,
    ) -> DlpResult<()> {
        let _guard = self.write_guard();
        let current = self.state.load();
        let max_scan_bytes = current.max_scan_bytes;
        let model = current.model.clone();
        let classifier =
            ContentClassifier::compile_with_model(policy.rules(), max_scan_bytes, model.clone())?;
        // `ai_app_policy` is the authoritative detector config for this
        // swap; keep the stored policy struct's field in lock-step so
        // `current_policy().ai_app` and `ai_app_policy()` can never
        // disagree (the caller already passes them consistent, but this
        // makes the invariant hold structurally for any future caller).
        policy.ai_app = ai_app_policy.clone();
        let ai_app = build_ai_app(ai_app_policy.as_ref(), max_scan_bytes, &model)?;
        self.state.store(Arc::new(EngineState {
            policy,
            classifier,
            max_scan_bytes,
            model,
            ai_app_policy,
            ai_app,
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
        self.state.load().model.has_model()
    }

    /// Atomically enable (or reconfigure) the AI-app exfiltration
    /// detector with `policy`, or disable it entirely with `None`.
    ///
    /// When enabled, [`Self::evaluate`] additionally consults the
    /// detector for events on [`AiAppExfilDetector::channel`] that carry
    /// a destination in [`ContentMetadata::source`], merging its
    /// coach-first verdict with the channel-rule verdict (strictest
    /// action wins). The detector reuses the engine's live ML-NER model,
    /// so it benefits from any installed on-device model. The default
    /// engine has no AI-app detector configured (a pure no-op), so this
    /// must be called to opt a tenant in — consistent with the
    /// false-positive-averse, coach-first posture of [`AiAppPolicy`].
    ///
    /// Serialised against the other rotation paths by
    /// [`Self::write_guard`]; on a compile failure the engine is left
    /// untouched (fail-safe).
    ///
    /// # Errors
    /// Propagates [`crate::error::DlpError::RuleCompile`] if the builtin
    /// AI-app PII rule set fails to compile (a catalog bug the unit
    /// tests guard against).
    pub fn set_ai_app_policy(&self, policy: Option<AiAppPolicy>) -> DlpResult<()> {
        let _guard = self.write_guard();
        let current = self.state.load();
        let max_scan_bytes = current.max_scan_bytes;
        let model = current.model.clone();
        let ai_app = build_ai_app(policy.as_ref(), max_scan_bytes, &model)?;
        // The channel classifier is immutable and not `Clone`, so the
        // snapshot is rebuilt by recompiling the active policy against
        // the same model — only the AI-app detector actually changes.
        let classifier = ContentClassifier::compile_with_model(
            current.policy.rules(),
            max_scan_bytes,
            model.clone(),
        )?;
        self.state.store(Arc::new(EngineState {
            policy: current.policy.clone(),
            classifier,
            max_scan_bytes,
            model,
            ai_app_policy: policy,
            ai_app,
        }));
        Ok(())
    }

    /// The active AI-app exfil policy, or `None` when the detector is
    /// not configured for this engine.
    #[must_use]
    pub fn ai_app_policy(&self) -> Option<AiAppPolicy> {
        self.state.load().ai_app_policy.clone()
    }

    /// Recompile the active policy with `detector` and publish the new
    /// (policy + classifier + detector) snapshot in one atomic store.
    /// On a compile failure nothing is published, so a bad model can
    /// never leave the active classifier out of sync with the recorded
    /// detector. Serialised against the other mutators by
    /// [`Self::write_guard`].
    fn recompile_with_model(&self, detector: MlNerDetector) -> DlpResult<()> {
        let _guard = self.write_guard();
        let current = self.state.load();
        let classifier = ContentClassifier::compile_with_model(
            current.policy.rules(),
            current.max_scan_bytes,
            detector.clone(),
        )?;
        let policy = current.policy.clone();
        let max_scan_bytes = current.max_scan_bytes;
        let ai_app_policy = current.ai_app_policy.clone();
        let ai_app = build_ai_app(ai_app_policy.as_ref(), max_scan_bytes, &detector)?;
        self.state.store(Arc::new(EngineState {
            policy,
            classifier,
            max_scan_bytes,
            model: detector,
            ai_app_policy,
            ai_app,
        }));
        Ok(())
    }

    /// Acquire the mutation lock that serialises the read-modify-write
    /// rotation paths ([`Self::install`], [`Self::install_model`],
    /// [`Self::clear_model`]). The guarded data is `()`, so a poisoned
    /// lock carries no corrupt state and is simply recovered — a
    /// mutator that panicked mid-recompile left the published
    /// [`EngineState`] untouched, since the `store` is its last step.
    fn write_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A snapshot of the currently-active policy.
    #[must_use]
    pub fn current_policy(&self) -> DlpPolicy {
        self.state.load().policy.clone()
    }

    /// Evaluate `content` observed on `channel` against the active
    /// policy and return the verdict.
    ///
    /// A disabled channel skips the channel classifier; with no other
    /// signal that yields [`DlpVerdict::Allow`]. Otherwise the strictest
    /// action across all matching rules is taken, escalated to at least
    /// the channel's configured action floor (if any), and mapped to a
    /// verdict variant.
    ///
    /// When an AI-app exfil policy is configured (see
    /// [`Self::set_ai_app_policy`]) and the event is on
    /// [`AiAppExfilDetector::channel`] with a destination recorded in
    /// [`ContentMetadata::source`], the detector's coach-first verdict
    /// is merged in: the strictest action and highest severity across
    /// the channel rules and the AI-app signal win, and the two match
    /// sets are concatenated. The AI-app signal is deliberately *not*
    /// subject to the channel action floor — it applies its own
    /// (false-positive-averse) escalation policy — and, because it is a
    /// separately opted-in control, it is *not* gated by the channel's
    /// `enabled` flag either: disabling the generic upload channel does
    /// not disarm AI-app detection an operator explicitly enabled.
    #[must_use]
    pub fn evaluate(
        &self,
        channel: DlpChannel,
        content: &[u8],
        metadata: &ContentMetadata,
    ) -> DlpVerdict {
        self.evaluate_with_signal(channel, content, metadata).0
    }

    /// Like [`Self::evaluate`] but also returns the redacted
    /// [`AiAppSignal`] when the AI-app exfil detector fired on this
    /// event (the upload channel, a recorded destination, a configured
    /// detector) and the result was *flagged* (coach-first: an action
    /// above `Monitor`, or any finding). The signal is the record the
    /// control plane's human-in-the-loop review queue ingests; it is
    /// `None` for every event that is not a flagged AI-app upload, so a
    /// caller can wire telemetry without re-inspecting.
    ///
    /// The verdict and the signal come from a single inspection pass —
    /// no double scan.
    #[must_use]
    pub fn evaluate_with_signal(
        &self,
        channel: DlpChannel,
        content: &[u8],
        metadata: &ContentMetadata,
    ) -> (DlpVerdict, Option<AiAppSignal>) {
        let state = self.state.load();
        let config = state.policy.channel_config(channel);

        // Generic channel DLP runs only when the channel is enabled. The
        // AI-app exfil detector is a *separately* opted-in control
        // (`set_ai_app_policy`) with its own destination gating, so it is
        // deliberately NOT gated by the channel `enabled` flag: an
        // operator who turns down noisy generic browser-upload DLP must
        // not silently disarm the AI-app detection they explicitly
        // enabled. A disabled channel simply skips the channel classifier
        // (its rules, severity, and action floor) while the AI-app signal
        // is still evaluated below.
        let (channel_action, channel_severity, mut matches) = if config.enabled {
            let result: ClassificationResult =
                state.classifier.classify(channel, content, metadata);
            // Channel-rule action, escalated to the channel floor when a
            // rule actually fired (an unmatched channel never floors).
            let channel_action = result
                .strictest_action()
                .map(|a| match config.action_override {
                    Some(floor) => a.max(floor),
                    None => a,
                });
            (channel_action, result.max_severity(), result.matches)
        } else {
            (None, None, Vec::new())
        };

        // AI-app exfil signal: consulted only on the upload channel,
        // only when a destination is recorded, and only when a detector
        // is configured. Kept off the hot path for all other traffic.
        // One inspection pass yields both the enforcement verdict and
        // the redacted signal the review queue ingests.
        let ai = state
            .ai_app
            .as_ref()
            .filter(|_| channel == AiAppExfilDetector::channel())
            .and_then(|detector| {
                metadata
                    .source
                    .as_deref()
                    .map(|dest| detector.inspect_with_verdict(dest, content, metadata))
            });

        // Surface the signal only when the upload was actually flagged
        // (coach-first: an action above Monitor, or any finding). A
        // bare destination-only Monitor signal is not a review
        // candidate, so it never leaves the edge as telemetry.
        let signal = ai
            .as_ref()
            .map(|(signal, _)| signal)
            .filter(|signal| signal.is_flagged())
            .cloned();

        let ai_verdict = ai
            .map(|(_, verdict)| verdict)
            .filter(|verdict| !matches!(verdict, DlpVerdict::Allow));

        // Fold the (optional) channel and AI-app contributions together.
        let mut action = channel_action;
        let mut severity = channel_severity;
        if let Some(details) = ai_verdict.as_ref().and_then(DlpVerdict::details) {
            action = Some(action.map_or(details.action, |a| a.max(details.action)));
            severity = Some(severity.map_or(details.severity, |s| s.max(details.severity)));
            matches.extend(details.matches.iter().cloned());
        }

        let verdict = match action {
            Some(action) => {
                DlpVerdict::from_action(action, channel, severity.unwrap_or(Severity::Low), matches)
            }
            None => DlpVerdict::Allow,
        };
        (verdict, signal)
    }

    /// Convenience wrapper that evaluates a [`ContentEvent`]
    /// produced by a `sng-pal` channel interceptor.
    #[must_use]
    pub fn evaluate_event(&self, event: &ContentEvent) -> DlpVerdict {
        self.evaluate(event.channel, &event.content, &event.metadata)
    }

    /// Like [`Self::evaluate_event`] but also returns the redacted
    /// [`AiAppSignal`] for a flagged AI-app upload (see
    /// [`Self::evaluate_with_signal`]). Used by the agent DLP subsystem
    /// to wire both edge enforcement and the control-plane review queue
    /// from a single inspection.
    #[must_use]
    pub fn evaluate_event_with_signal(
        &self,
        event: &ContentEvent,
    ) -> (DlpVerdict, Option<AiAppSignal>) {
        self.evaluate_with_signal(event.channel, &event.content, &event.metadata)
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
        let model_bytes = include_bytes!("../assets/ner_v2.onnx");
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
            model: include_bytes!("../assets/ner_v2.onnx").to_vec(),
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

    #[test]
    fn install_preserves_active_model_and_swaps_policy() {
        // Regression guard for the single-snapshot engine state: a
        // policy rotation (`install`) must keep the currently-installed
        // ONNX model (it reads the model from the live snapshot), and
        // the swap must apply the new policy. Neither mutator may
        // clobber the other half of the (policy, model) pair.
        let e = engine_with(vec![ml_rule(
            "phone",
            "phone_number",
            RuleAction::Block,
            Severity::High,
        )]);

        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let kid = sng_core::ids::PolicySigningKeyId::new("preserve-model-key").expect("kid");
        let model_bytes = include_bytes!("../assets/ner_v2.onnx");
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

        // Rotate to a new policy: the installed model must survive.
        e.install(DlpPolicy {
            rules: vec![ml_rule(
                "phone2",
                "phone_number",
                RuleAction::Block,
                Severity::High,
            )],
            ..DlpPolicy::default()
        })
        .expect("install policy");
        assert!(
            e.has_ml_model(),
            "policy rotation must not drop the installed model"
        );
        assert_eq!(e.current_policy().rules.len(), 1);
        assert_eq!(e.current_policy().rules[0].id, "phone2");

        // Detection still runs through the loaded model after the swap.
        assert!(
            e.evaluate(
                DlpChannel::Clipboard,
                b"call +1-202-555-0173 now",
                &ContentMetadata::default(),
            )
            .is_blocking(),
            "model must still detect after policy swap"
        );
    }

    // --- AI-app exfil detector wiring -------------------------------

    /// A high-entropy GitHub token the secret scanner reliably flags.
    const SECRET_BODY: &[u8] = b"deploy key ghp_abcdefghijklmnopqrstuvwxyz0123456789 attached";

    /// Browser-upload metadata bound for a *known* AI app (ChatGPT).
    fn ai_upload_meta() -> ContentMetadata {
        ContentMetadata {
            source: Some("https://chat.openai.com/c/abc".to_owned()),
            ..ContentMetadata::default()
        }
    }

    #[test]
    fn ai_app_detector_is_off_by_default() {
        // No `set_ai_app_policy`: a secret bound for a known AI app on
        // the upload channel is allowed (the channel has no rules and
        // the detector is not wired).
        let e = engine_with(vec![]);
        assert!(e.ai_app_policy().is_none());
        assert_eq!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ai_upload_meta()
            ),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_coaches_on_secret_upload_to_known_app() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        assert_eq!(e.ai_app_policy(), Some(AiAppPolicy::default()));

        let v = e.evaluate(
            AiAppExfilDetector::channel(),
            SECRET_BODY,
            &ai_upload_meta(),
        );
        // Coach-first default: a secret always coaches (warns), never
        // blocks until the operator opts in.
        assert!(
            matches!(v, DlpVerdict::WarnUser(_)),
            "expected a coaching warn, got {v:?}"
        );
        let d = v.details().expect("details");
        assert_eq!(d.action, RuleAction::Warn);
        assert!(
            d.matches
                .iter()
                .any(|m| m.rule_id.starts_with("ai_app.secret.")),
            "expected a secret match, got {:?}",
            d.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evaluate_with_signal_surfaces_a_flagged_signal() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");

        // A flagged secret upload to a known app surfaces both the
        // coaching verdict AND the redacted signal in one pass.
        let (verdict, signal) = e.evaluate_with_signal(
            AiAppExfilDetector::channel(),
            SECRET_BODY,
            &ai_upload_meta(),
        );
        assert!(
            matches!(verdict, DlpVerdict::WarnUser(_)),
            "got {verdict:?}"
        );
        let signal = signal.expect("a flagged upload must surface a signal");
        assert!(signal.is_flagged());
        assert_eq!(signal.action, crate::ai_app::AiAppAction::Coach);
        assert!(
            !signal.findings.is_empty(),
            "a coached secret upload carries at least one finding"
        );
        // The projected wire event preserves the redaction invariant:
        // it carries label/count summaries, never the matched bytes.
        let wire = signal.to_wire_event();
        assert_eq!(wire.action, sng_core::DlpAction::Coach);
        assert!(wire.findings.iter().all(|f| !f.label.is_empty()));
    }

    #[test]
    fn evaluate_with_signal_is_none_when_not_flagged() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");

        // Benign content to a known AI app: no findings, monitor-only —
        // not a review candidate, so no signal escapes.
        let (verdict, signal) = e.evaluate_with_signal(
            AiAppExfilDetector::channel(),
            b"hello, how are you today?",
            &ai_upload_meta(),
        );
        assert_eq!(verdict, DlpVerdict::Allow);
        assert!(
            signal.is_none(),
            "a non-flagged upload must not surface a signal"
        );

        // Off the upload channel the detector never runs, so even a
        // secret yields no signal.
        let (_, off_channel) =
            e.evaluate_with_signal(DlpChannel::Clipboard, SECRET_BODY, &ai_upload_meta());
        assert!(off_channel.is_none());
    }

    #[test]
    fn ai_app_not_consulted_off_the_upload_channel() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        // Same content + destination, but a non-upload channel: the
        // detector must not run, so there is nothing to flag.
        assert_eq!(
            e.evaluate(DlpChannel::Clipboard, SECRET_BODY, &ai_upload_meta()),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_runs_even_when_the_upload_channel_is_disabled() {
        // An operator who silences noisy generic browser-upload DLP (by
        // disabling the channel) must not thereby disarm the AI-app exfil
        // control they explicitly opted into. The channel classifier is
        // skipped, but the AI-app detector still coaches on a secret bound
        // for a known AI app.
        let mut channels = BTreeMap::new();
        channels.insert(
            AiAppExfilDetector::channel(),
            ChannelConfig {
                enabled: false,
                action_override: None,
            },
        );
        let e = DlpEngine::new(DlpPolicy {
            // A channel rule that would fire if the (disabled) channel
            // classifier ran — its absence from the verdict proves the
            // classifier was skipped.
            rules: vec![rule("kw", "deploy", RuleAction::Block, Severity::Critical)],
            channels,
            ..DlpPolicy::default()
        })
        .expect("engine");
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");

        let v = e.evaluate(
            AiAppExfilDetector::channel(),
            SECRET_BODY,
            &ai_upload_meta(),
        );
        assert!(
            matches!(v, DlpVerdict::WarnUser(_)),
            "AI-app detection must survive a disabled channel, got {v:?}"
        );
        let d = v.details().expect("details");
        assert!(
            d.matches.iter().any(|m| m.rule_id.starts_with("ai_app.")),
            "expected an ai-app match, got {:?}",
            d.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
        );
        // The disabled channel's own keyword rule must NOT contribute.
        assert!(
            !d.matches.iter().any(|m| m.rule_id == "kw"),
            "disabled channel classifier must be skipped"
        );
    }

    #[test]
    fn disabled_channel_without_ai_app_still_allows() {
        // The decoupling must not change the no-AI-app case: a disabled
        // channel with a would-be-matching rule is still a pure Allow.
        let mut channels = BTreeMap::new();
        channels.insert(
            DlpChannel::Clipboard,
            ChannelConfig {
                enabled: false,
                action_override: None,
            },
        );
        let e = DlpEngine::new(DlpPolicy {
            rules: vec![rule("kw", "secret", RuleAction::Block, Severity::High)],
            channels,
            ..DlpPolicy::default()
        })
        .expect("engine");
        assert_eq!(
            e.evaluate(
                DlpChannel::Clipboard,
                b"this is secret",
                &ContentMetadata::default()
            ),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_requires_a_destination() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        // Upload channel but no destination recorded: nothing to score.
        assert_eq!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ContentMetadata::default()
            ),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_non_ai_destination_is_allowed() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        // A secret bound for an ordinary site is the channel engine's
        // business, not the AI-app detector's.
        let meta = ContentMetadata {
            source: Some("https://mail.example.com/compose".to_owned()),
            ..ContentMetadata::default()
        };
        assert_eq!(
            e.evaluate(AiAppExfilDetector::channel(), SECRET_BODY, &meta),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_blocks_a_secret_only_when_opted_in() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy {
            block_opt_in: true,
            ..AiAppPolicy::default()
        }))
        .expect("enable ai-app");
        let v = e.evaluate(
            AiAppExfilDetector::channel(),
            SECRET_BODY,
            &ai_upload_meta(),
        );
        assert!(
            v.is_blocking(),
            "opted-in secret upload should block, got {v:?}"
        );
    }

    #[test]
    fn ai_app_merges_with_channel_rule_taking_strictest_action() {
        // A channel keyword rule only logs; the AI-app secret signal
        // coaches (warn). The merged verdict takes the stricter Warn and
        // carries both match sets.
        let e = engine_with(vec![rule("kw", "deploy", RuleAction::Log, Severity::Low)]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        let v = e.evaluate(
            AiAppExfilDetector::channel(),
            SECRET_BODY,
            &ai_upload_meta(),
        );
        assert!(matches!(v, DlpVerdict::WarnUser(_)), "got {v:?}");
        let d = v.details().expect("details");
        assert!(
            d.matches.iter().any(|m| m.rule_id == "kw"),
            "channel match should survive the merge"
        );
        assert!(
            d.matches.iter().any(|m| m.rule_id.starts_with("ai_app.")),
            "ai-app match should be merged in"
        );
    }

    #[test]
    fn set_ai_app_policy_none_disables_the_detector() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        assert!(matches!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ai_upload_meta()
            ),
            DlpVerdict::WarnUser(_)
        ));
        // Turning it back off restores the pure-channel behaviour.
        e.set_ai_app_policy(None).expect("disable ai-app");
        assert!(e.ai_app_policy().is_none());
        assert_eq!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ai_upload_meta()
            ),
            DlpVerdict::Allow
        );
    }

    #[test]
    fn ai_app_policy_survives_a_policy_rotation() {
        let e = engine_with(vec![]);
        e.set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        // Rotate the channel policy; the AI-app config must persist.
        // The incoming rule-only policy deliberately carries a *stale*
        // `ai_app` field (None) that disagrees with the armed detector,
        // to prove `install` normalises the stored struct rather than
        // letting `current_policy().ai_app` drift from `ai_app_policy()`.
        e.install(DlpPolicy {
            rules: vec![rule("k2", "beta", RuleAction::Block, Severity::High)],
            ai_app: None,
            ..DlpPolicy::default()
        })
        .expect("install");
        assert_eq!(e.ai_app_policy(), Some(AiAppPolicy::default()));
        // Invariant: the stored policy's `ai_app` field always mirrors
        // the authoritative detector config after any install.
        assert_eq!(
            e.current_policy().ai_app,
            e.ai_app_policy(),
            "current_policy().ai_app must mirror ai_app_policy() after a rule-only rotation"
        );
        assert!(
            matches!(
                e.evaluate(
                    AiAppExfilDetector::channel(),
                    SECRET_BODY,
                    &ai_upload_meta()
                ),
                DlpVerdict::WarnUser(_)
            ),
            "ai-app detector must still fire after a policy rotation"
        );
    }

    #[test]
    fn install_with_ai_app_swaps_both_dimensions_atomically() {
        // The bundle-apply path installs the rule set and the AI-app
        // detector in one swap. Starting from a disarmed engine, a
        // single install_with_ai_app must land BOTH the new channel
        // rule and the armed detector — no second call required.
        let e = engine_with(vec![]);
        assert!(e.ai_app_policy().is_none(), "detector starts disarmed");

        e.install_with_ai_app(
            DlpPolicy {
                rules: vec![rule("k1", "alpha", RuleAction::Block, Severity::High)],
                ..DlpPolicy::default()
            },
            Some(AiAppPolicy::default()),
        )
        .expect("install with ai-app");

        // Rule set landed.
        assert_eq!(e.current_policy().rules.len(), 1);
        assert_eq!(e.current_policy().rules[0].id, "k1");
        // Detector armed in the same swap.
        assert_eq!(e.ai_app_policy(), Some(AiAppPolicy::default()));
        assert!(matches!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ai_upload_meta()
            ),
            DlpVerdict::WarnUser(_)
        ));

        // Passing None disarms the detector while swapping rules, so
        // clearing endpoint DLP in the control plane disarms the edge.
        e.install_with_ai_app(DlpPolicy::default(), None)
            .expect("install default");
        assert!(
            e.ai_app_policy().is_none(),
            "detector disarmed on empty doc"
        );
        assert_eq!(
            e.evaluate(
                AiAppExfilDetector::channel(),
                SECRET_BODY,
                &ai_upload_meta()
            ),
            DlpVerdict::Allow
        );
    }
}
