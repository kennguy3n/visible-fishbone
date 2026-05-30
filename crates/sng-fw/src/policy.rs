//! Bridge between the firewall's working types and the
//! workspace-wide policy engine in [`sng_policy_eval`].
//!
//! The firewall holds [`crate::flow::FlowKey`] +
//! [`crate::appid::AppId`] +
//! [`crate::flow::FlowState`]. The policy engine wants a
//! [`sng_policy_eval::Flow`] with borrowed `&'a str` fields.
//! [`FwPolicyAdapter`] is the small shim that turns the
//! former into the latter and the engine's
//! [`sng_policy_eval::Verdict`] back into a
//! [`crate::verdict::FwVerdict`].
//!
//! Why a separate module: the conversion is non-trivial
//! enough that inlining it inside `service.rs` would obscure
//! the orchestration logic. Splitting it out also keeps the
//! `sng_policy_eval` import surface to one file, which means
//! a future swap to a different evaluator backend (e.g. an
//! eBPF-resident matcher for the kernel-fast-path edge
//! variant) only requires re-implementing this adapter.

use sng_policy_eval::{EnforcementDomain, Flow, FlowBuilder, InspectLevel, PolicyEngine, Verdict};
use std::sync::Arc;

use crate::appid::AppId;
use crate::error::FwError;
use crate::flow::FlowKey;
use crate::verdict::{FwVerdict, VerdictReason};

/// Identifying context the firewall has on a flow at policy
/// evaluation time. Held as owned strings because the
/// underlying [`crate::conntrack::ConnTable`] entry lives
/// behind a mutex and we want to release the lock before
/// running the (sync but non-trivial) policy evaluation.
#[derive(Clone, Debug, Default)]
pub struct FlowIdentity {
    /// Authenticated user principal, if known. Set by the
    /// ZTNA brokering layer once auth has completed.
    pub user: Option<String>,
    /// Device identifier from the device-bound mTLS subject.
    pub device: Option<String>,
    /// Site identifier (originating branch / location).
    pub site: Option<String>,
}

/// Bridge surface: take a flow + identity and produce a
/// firewall verdict by consulting the policy engine.
///
/// The adapter owns an `Arc<PolicyEngine>` so policy bundle
/// reloads via [`PolicyEngine::swap`] are immediately visible
/// to the next evaluation without recreating the adapter.
#[derive(Debug, Clone)]
pub struct FwPolicyAdapter {
    /// The evaluator. Cheap to clone — internal state is
    /// behind ArcSwap.
    engine: Arc<PolicyEngine>,
}

impl FwPolicyAdapter {
    /// Construct an adapter from an existing engine. Most
    /// production wiring shares the same engine across the
    /// firewall, the SWG, and the DNS service.
    #[must_use]
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self { engine }
    }

    /// Evaluate the policy for `(key, app, identity)`.
    /// Returns the firewall verdict, ready to be cached and
    /// projected onto a [`sng_core::events::FlowEvent`].
    ///
    /// # Errors
    ///
    /// [`FwError::PolicyUnavailable`] when the engine cannot
    /// produce a verdict (today this is impossible — the
    /// engine always returns a verdict — but we surface the
    /// type so a future failure mode lands here rather than
    /// silently degrading to fail-closed.)
    pub fn evaluate(
        &self,
        key: &FlowKey,
        app: &AppId,
        identity: &FlowIdentity,
    ) -> Result<FwVerdict, FwError> {
        // Build the borrowed Flow snapshot. Borrows live in
        // a scope that exits before this method returns, so
        // the engine's evaluator never holds onto these
        // strings.
        let app_label = app.as_str();
        let sni = app.sni();
        let mut builder = FlowBuilder::new(EnforcementDomain::Ngfw)
            .app(app_label)
            .source_ip(key.source_ip)
            .destination_ip(key.destination_ip)
            .destination_port(key.destination_port);
        if let Some(host) = sni {
            builder = builder.destination_host(host);
        }
        if let Some(user) = identity.user.as_deref() {
            builder = builder.user(user);
        }
        if let Some(device) = identity.device.as_deref() {
            builder = builder.device(device);
        }
        if let Some(site) = identity.site.as_deref() {
            builder = builder.site(site);
        }
        let flow: Flow<'_> = builder.build();
        let raw = self.engine.evaluate(&flow);
        Ok(verdict_from_policy(&raw))
    }
}

/// Convert a [`sng_policy_eval::Verdict`] to the firewall's
/// [`FwVerdict`]. Pulled out as a free function so unit
/// tests can drive it without an `Arc<PolicyEngine>`.
#[must_use]
pub fn verdict_from_policy(raw: &Verdict) -> FwVerdict {
    match raw {
        // The engine never returns a per-rule id on the
        // verdict — that's intentional, the engine is
        // stateless and a downstream "rule attribution"
        // requirement would change the API of the engine
        // itself. For now the reason is "policy.match" with
        // an empty rule id so the verdict reason surfaces
        // through to telemetry; once the engine grows a
        // verdict_id we'll plumb it through here.
        Verdict::Allow => FwVerdict::allow(VerdictReason::PolicyMatch(String::new())),
        Verdict::Deny => FwVerdict::deny(VerdictReason::PolicyMatch(String::new())),
        Verdict::Inspect { level } => {
            // Both InspectLevels collapse to the same
            // wire-level Inspect verdict on the firewall.
            // The level itself influences how downstream
            // IPS/DPI handles the flow but doesn't change
            // whether the firewall permits it.
            let _ = level; // explicit to mark intent.
            FwVerdict::inspect(VerdictReason::PolicyMatch(String::new()))
        }
        Verdict::Steer { class } => {
            // Steering verdicts permit the flow and route it
            // via the SDWAN / traffic-class engine. The
            // wire-level verdict is Allow but we tag the
            // reason with the class as its stable wire
            // string (`trusted_direct`, `inspect_full`, …)
            // so downstream telemetry can distinguish a
            // plain allow from a steered allow and so the
            // SDWAN crate doesn't need to re-walk the policy
            // graph to recover the routing class.
            FwVerdict::allow(VerdictReason::Steering(class.to_string()))
        }
        Verdict::Decrypt => FwVerdict::inspect(VerdictReason::PolicyMatch(String::new())),
        Verdict::Log => FwVerdict::log(VerdictReason::PolicyMatch(String::new())),
        Verdict::SuggestOnly { suggestion: _ } => {
            // SuggestOnly leaves the wire-level verdict at
            // Allow — the recommendation surfaces only in
            // the operator UI. We tag the reason so a future
            // telemetry consumer can break suggest_only out
            // of the regular allow bucket.
            FwVerdict::log(VerdictReason::PolicyMatch("suggest_only".into()))
        }
    }
}

/// Helper for callers that hold an unresolved `InspectLevel`
/// and want to surface it on the FwVerdict reason. Today the
/// firewall doesn't propagate the inspect level downstream
/// (the IPS engine takes the level off the original policy
/// graph), but exposing the conversion here means a future
/// reason-bearing FwVerdict variant can hook into the same
/// surface.
#[must_use]
pub fn inspect_level_label(level: InspectLevel) -> &'static str {
    level.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_policy_eval::Verdict;

    #[test]
    fn allow_verdict_maps_to_allow() {
        let v = verdict_from_policy(&Verdict::Allow);
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Allow);
    }

    #[test]
    fn deny_verdict_maps_to_deny() {
        let v = verdict_from_policy(&Verdict::Deny);
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Deny);
    }

    #[test]
    fn inspect_lite_maps_to_inspect() {
        let v = verdict_from_policy(&Verdict::Inspect {
            level: InspectLevel::Lite,
        });
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Inspect);
    }

    #[test]
    fn inspect_full_maps_to_inspect() {
        let v = verdict_from_policy(&Verdict::Inspect {
            level: InspectLevel::Full,
        });
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Inspect);
    }

    #[test]
    fn decrypt_collapses_to_inspect_for_firewall() {
        let v = verdict_from_policy(&Verdict::Decrypt);
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Inspect);
    }

    #[test]
    fn log_maps_to_log() {
        let v = verdict_from_policy(&Verdict::Log);
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Log);
    }

    #[test]
    fn suggest_only_maps_to_log_with_distinct_reason() {
        let v = verdict_from_policy(&Verdict::SuggestOnly {
            suggestion: sng_policy_eval::Verb::Deny,
        });
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Log);
        match v.reason {
            VerdictReason::PolicyMatch(ref s) => assert_eq!(s, "suggest_only"),
            other => panic!("unexpected reason: {other:?}"),
        }
    }

    #[test]
    fn steer_maps_to_allow_with_steering_class_in_reason() {
        use sng_core::traffic_class::TrafficClass;
        let v = verdict_from_policy(&Verdict::Steer {
            class: TrafficClass::TrustedDirect,
        });
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Allow);
        // The class must be preserved on the reason so the
        // SD-WAN crate can route the flow without re-walking
        // the policy graph.
        match &v.reason {
            VerdictReason::Steering(class) => {
                assert_eq!(class.as_str(), TrafficClass::TrustedDirect.as_str());
            }
            other => panic!("expected Steering reason, got {other:?}"),
        }
        // And the helper accessor agrees.
        assert_eq!(
            v.reason.steering_class(),
            Some(TrafficClass::TrustedDirect.as_str())
        );
    }

    #[test]
    fn steer_reason_label_is_steering_prefixed() {
        use sng_core::traffic_class::TrafficClass;
        let v = verdict_from_policy(&Verdict::Steer {
            class: TrafficClass::InspectFull,
        });
        assert_eq!(
            v.reason.as_label(),
            format!("steering:{}", TrafficClass::InspectFull.as_str())
        );
    }

    #[test]
    fn inspect_level_label_round_trips() {
        assert_eq!(inspect_level_label(InspectLevel::Lite), "lite");
        assert_eq!(inspect_level_label(InspectLevel::Full), "full");
    }

    #[test]
    fn flow_identity_default_is_all_none() {
        let id = FlowIdentity::default();
        assert!(id.user.is_none());
        assert!(id.device.is_none());
        assert!(id.site.is_none());
    }

    // Note: full integration of `FwPolicyAdapter::evaluate`
    // requires a real `PolicyEngine` constructed from a
    // verified bundle body, which lives in
    // `sng-policy-eval`'s integration tests. The unit tests
    // above cover the pure verdict-shape mapping. The
    // service.rs integration tests exercise the adapter on
    // top of a `PolicyEngine::from_body` constructed from a
    // bundle fixture.
}
