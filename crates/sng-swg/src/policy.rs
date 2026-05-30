//! SWG policy: turn `(category, reputation, malware,
//! tls_intercept_preference)` into a posture.
//!
//! Where `sng-policy-eval` is the **generic** workspace
//! policy engine that runs every domain's bundle, the
//! SWG policy here is a **specialised** function that
//! converts SWG-specific signals into the SWG-specific
//! [`Posture`] enum. The generic engine is the source of
//! truth for *which* policy bundle is active; this
//! module is the bridge between that bundle's
//! SWG-section knobs and the concrete decision the
//! request-processing path takes.
//!
//! The policy is **deterministic**: given the same
//! inputs it always produces the same `Posture`. No I/O,
//! no logging.

use crate::category::Category;
use crate::malware::MalwareVerdict;
use crate::reputation::ReputationScore;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// What the SWG should do with the request.
///
/// Posture flows out of the policy module on the hot
/// path and into [`crate::service::SwgDecision`] /
/// [`sng_core::events::HttpEvent::verdict`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// Allow the request straight through (no MITM, no
    /// extra inspection). Typically applied to
    /// `Business` traffic from trusted SaaS providers.
    Allow,
    /// Allow but record. Used to canary new policy
    /// rules without enforcing.
    AlertOnly,
    /// Inspect with full TLS MITM. Triggers the proxy's
    /// MITM path; the response goes through every
    /// downstream content filter (DLP, malware scan,
    /// IPS-on-payload).
    InspectFull,
    /// Allow but route around the MITM engine. Used for
    /// `Sensitive` categories (healthcare / finance /
    /// legal) where MITM would create regulatory
    /// exposure.
    TlsBypass,
    /// Quarantine the response — the proxy serves a
    /// notice page instead of the upstream content.
    Quarantine,
    /// Drop. Used for confirmed `Malware` /
    /// `Phishing` / malicious sha256.
    Block,
}

impl Posture {
    /// Stable wire string for the
    /// [`sng_core::events::HttpEvent`] / dashboards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AlertOnly => "alert_only",
            Self::InspectFull => "inspect_full",
            Self::TlsBypass => "tls_bypass",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
        }
    }

    /// True for the postures that block the request.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Block | Self::Quarantine)
    }

    /// True for the postures that permit the request to
    /// reach the upstream server: `Allow`, `AlertOnly`,
    /// `InspectFull`, and `TlsBypass`. `Block` and
    /// `Quarantine` are the two postures that do NOT
    /// permit traffic — those return `false` here.
    ///
    /// Note: "permits traffic" is independent of whether
    /// the SWG intercepts TLS. `InspectFull` permits the
    /// request *and* enables MITM; `TlsBypass` permits the
    /// request *and* skips MITM. Callers who want the
    /// "will the brain MITM this request" predicate should
    /// match on `InspectFull` directly.
    #[must_use]
    pub const fn permits_traffic(self) -> bool {
        matches!(
            self,
            Self::Allow | Self::AlertOnly | Self::InspectFull | Self::TlsBypass
        )
    }
}

impl std::fmt::Display for Posture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-category default posture map. The fall-through
/// posture (when the request's host is uncategorised) is
/// stored explicitly so policy reviewers can see it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SwgPolicy {
    /// Per-category posture. Categories not present in
    /// the map fall back to `default_posture`.
    pub by_category: HashMap<Category, Posture>,
    /// Posture when the host has no category. Operators
    /// usually pick `InspectFull` here so unknown sites
    /// get the most coverage.
    pub default_posture: Posture,
    /// Reputation threshold at which the policy upgrades
    /// the posture from `InspectFull` (or weaker) to
    /// `Block`. The check is `score >= reputation_block_at`,
    /// so `1.0` blocks **only** the worst-possible score
    /// (since `ReputationScore` is clamped to `[0.0, 1.0]`).
    /// Operators who want to fully disable reputation-based
    /// blocking should set this to a sentinel above 1.0
    /// (e.g. `2.0`) — `ReputationScore` can never reach it
    /// so the upgrade is unreachable.
    pub reputation_block_at: f32,
    /// Reputation threshold at which the policy upgrades
    /// from `Allow` (or `AlertOnly`) to `InspectFull`. The
    /// check is `score >= reputation_inspect_at`, so `1.0`
    /// upgrades **only** the worst-possible score. Use a
    /// sentinel above 1.0 (e.g. `2.0`) to fully disable
    /// the upgrade.
    pub reputation_inspect_at: f32,
}

impl Default for SwgPolicy {
    fn default() -> Self {
        let mut by_category = HashMap::new();
        // Pre-baked sane defaults so a freshly-bootstrapped
        // agent makes the safest decisions until a tenant
        // policy lands.
        by_category.insert(Category::Malware, Posture::Block);
        by_category.insert(Category::Phishing, Posture::Block);
        by_category.insert(Category::Unwanted, Posture::Block);
        by_category.insert(Category::Risky, Posture::Quarantine);
        by_category.insert(Category::Sensitive, Posture::TlsBypass);
        by_category.insert(Category::Business, Posture::Allow);
        by_category.insert(Category::Media, Posture::Allow);
        by_category.insert(Category::Uncategorised, Posture::InspectFull);
        Self {
            by_category,
            default_posture: Posture::InspectFull,
            reputation_block_at: 0.95,
            reputation_inspect_at: 0.5,
        }
    }
}

impl SwgPolicy {
    /// Posture for `category` honouring the fallback to
    /// `default_posture`.
    #[must_use]
    pub fn posture_for(&self, category: Category) -> Posture {
        self.by_category
            .get(&category)
            .copied()
            .unwrap_or(self.default_posture)
    }
}

/// Inputs to the policy decision.
#[derive(Clone, Copy, Debug)]
pub struct DecisionInputs {
    /// Category as resolved by [`crate::category::CategoryProvider`].
    pub category: Category,
    /// Reputation score, when the provider had an
    /// opinion.
    pub reputation: Option<ReputationScore>,
    /// Malware verdict, when the proxy submitted the
    /// candidate object for scan. `None` for
    /// pre-response (request-only) decisions.
    pub malware: Option<MalwareVerdict>,
}

/// SWG-side policy holder. Wraps a [`SwgPolicy`] in an
/// [`arc_swap::ArcSwap`] so the data path can run the
/// policy without taking a lock, and a policy reload
/// from the bundle adapter is one atomic store.
#[derive(Debug)]
pub struct SwgPolicyHolder {
    inner: ArcSwap<SwgPolicy>,
}

impl SwgPolicyHolder {
    /// Construct a holder around `policy`.
    #[must_use]
    pub fn new(policy: SwgPolicy) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(policy)),
        }
    }

    /// Replace the policy atomically. In-flight
    /// evaluations see the old policy until they finish.
    pub fn replace(&self, policy: SwgPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Cheap snapshot of the current policy — clones the
    /// `Arc`, not the contents.
    #[must_use]
    pub fn snapshot(&self) -> Arc<SwgPolicy> {
        self.inner.load_full()
    }

    /// Evaluate the policy against the inputs.
    #[must_use]
    pub fn evaluate(&self, inputs: DecisionInputs) -> Posture {
        let policy = self.inner.load();
        evaluate_policy(&policy, inputs)
    }
}

impl Default for SwgPolicyHolder {
    fn default() -> Self {
        Self::new(SwgPolicy::default())
    }
}

/// Pure decision function. Exposed so callers that
/// already hold a `&SwgPolicy` can run the same logic
/// without paying for the `ArcSwap` load.
#[must_use]
pub fn evaluate_policy(policy: &SwgPolicy, inputs: DecisionInputs) -> Posture {
    // Step 1: confirmed malicious overrides everything.
    if matches!(inputs.malware, Some(MalwareVerdict::Malicious)) {
        return Posture::Block;
    }
    // Step 2: category posture.
    let mut posture = policy.posture_for(inputs.category);
    // Step 3: reputation upgrades.
    if let Some(rep) = inputs.reputation {
        if rep.at_least(policy.reputation_block_at) {
            posture = Posture::Block;
        } else if rep.at_least(policy.reputation_inspect_at) {
            // Reputation-based "upgrade to InspectFull"
            // only fires from the soft-allow postures
            // (`Allow` / `AlertOnly`). All other postures
            // are intentionally preserved:
            //   - `Block` / `Quarantine`: would be a
            //     *downgrade* — never weaken an enforcement
            //     posture on a soft reputation signal.
            //   - `InspectFull`: already the target.
            //   - `TlsBypass`: preserved deliberately. An
            //     operator chose `TlsBypass` for a
            //     regulated category (healthcare, finance,
            //     legal) where MITM would create compliance
            //     exposure. A medium-high reputation score
            //     (e.g. 0.6 on a Sensitive site) must NOT
            //     silently re-enable MITM — that would
            //     subvert the operator's intent. Operators
            //     who want reputation to override
            //     `TlsBypass` should configure that
            //     explicitly via `by_category` instead of
            //     relying on this fall-through.
            posture = match posture {
                Posture::Allow | Posture::AlertOnly => Posture::InspectFull,
                other => other,
            };
        }
    }
    // Step 4: suspicious malware verdict on an
    // otherwise-allow path → quarantine.
    if matches!(inputs.malware, Some(MalwareVerdict::Suspicious))
        && matches!(posture, Posture::Allow | Posture::AlertOnly)
    {
        posture = Posture::Quarantine;
    }
    posture
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn inp(category: Category) -> DecisionInputs {
        DecisionInputs {
            category,
            reputation: None,
            malware: None,
        }
    }

    #[test]
    fn posture_wire_strings_are_stable() {
        assert_eq!(Posture::Allow.as_str(), "allow");
        assert_eq!(Posture::AlertOnly.as_str(), "alert_only");
        assert_eq!(Posture::InspectFull.as_str(), "inspect_full");
        assert_eq!(Posture::TlsBypass.as_str(), "tls_bypass");
        assert_eq!(Posture::Quarantine.as_str(), "quarantine");
        assert_eq!(Posture::Block.as_str(), "block");
    }

    #[test]
    fn posture_blocking_predicate() {
        assert!(Posture::Block.is_blocking());
        assert!(Posture::Quarantine.is_blocking());
        assert!(!Posture::Allow.is_blocking());
        assert!(!Posture::AlertOnly.is_blocking());
        assert!(!Posture::InspectFull.is_blocking());
        assert!(!Posture::TlsBypass.is_blocking());
    }

    #[test]
    fn posture_permits_traffic_predicate() {
        assert!(Posture::Allow.permits_traffic());
        assert!(Posture::AlertOnly.permits_traffic());
        assert!(Posture::InspectFull.permits_traffic());
        assert!(Posture::TlsBypass.permits_traffic());
        assert!(!Posture::Quarantine.permits_traffic());
        assert!(!Posture::Block.permits_traffic());
    }

    #[test]
    fn default_policy_blocks_malware() {
        let h = SwgPolicyHolder::default();
        assert_eq!(h.evaluate(inp(Category::Malware)), Posture::Block);
    }

    #[test]
    fn default_policy_blocks_phishing() {
        let h = SwgPolicyHolder::default();
        assert_eq!(h.evaluate(inp(Category::Phishing)), Posture::Block);
    }

    #[test]
    fn default_policy_quarantines_risky() {
        let h = SwgPolicyHolder::default();
        assert_eq!(h.evaluate(inp(Category::Risky)), Posture::Quarantine);
    }

    #[test]
    fn default_policy_bypasses_tls_for_sensitive() {
        let h = SwgPolicyHolder::default();
        assert_eq!(h.evaluate(inp(Category::Sensitive)), Posture::TlsBypass);
    }

    #[test]
    fn default_policy_allows_business() {
        let h = SwgPolicyHolder::default();
        assert_eq!(h.evaluate(inp(Category::Business)), Posture::Allow);
    }

    #[test]
    fn default_policy_inspects_uncategorised() {
        let h = SwgPolicyHolder::default();
        assert_eq!(
            h.evaluate(inp(Category::Uncategorised)),
            Posture::InspectFull
        );
    }

    #[test]
    fn malicious_verdict_overrides_business_allow() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Business,
            reputation: None,
            malware: Some(MalwareVerdict::Malicious),
        };
        assert_eq!(h.evaluate(inputs), Posture::Block);
    }

    #[test]
    fn malicious_verdict_overrides_sensitive_tls_bypass() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Sensitive,
            reputation: None,
            malware: Some(MalwareVerdict::Malicious),
        };
        assert_eq!(h.evaluate(inputs), Posture::Block);
    }

    #[test]
    fn high_reputation_upgrades_business_to_block() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Business,
            reputation: Some(ReputationScore::new(0.99)),
            malware: None,
        };
        assert_eq!(h.evaluate(inputs), Posture::Block);
    }

    #[test]
    fn medium_reputation_upgrades_business_to_inspect_full() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Business,
            reputation: Some(ReputationScore::new(0.6)),
            malware: None,
        };
        assert_eq!(h.evaluate(inputs), Posture::InspectFull);
    }

    #[test]
    fn medium_reputation_does_not_downgrade_quarantine() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Risky,
            reputation: Some(ReputationScore::new(0.6)),
            malware: None,
        };
        assert_eq!(h.evaluate(inputs), Posture::Quarantine);
    }

    #[test]
    fn medium_reputation_does_not_override_tls_bypass() {
        // Pin the architectural contract: `TlsBypass` is
        // an operator choice driven by compliance
        // (healthcare / finance / legal). A medium-high
        // reputation signal MUST NOT silently re-enable
        // MITM by promoting `TlsBypass` to `InspectFull`.
        // Operators who want reputation to override
        // `TlsBypass` should configure that explicitly via
        // `by_category` instead of relying on this
        // fall-through.
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Sensitive,
            reputation: Some(ReputationScore::new(0.6)),
            malware: None,
        };
        assert_eq!(h.evaluate(inputs), Posture::TlsBypass);
    }

    #[test]
    fn high_reputation_still_blocks_tls_bypass() {
        // Counterpart test: even though medium reputation
        // does not weaken `TlsBypass`, the strict
        // `reputation_block_at` threshold is a separate
        // enforcement step that DOES override every
        // category — including `TlsBypass`. This is the
        // documented escape hatch for a confirmed-bad host
        // that an operator nonetheless put under a
        // Sensitive category.
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Sensitive,
            reputation: Some(ReputationScore::new(0.99)),
            malware: None,
        };
        assert_eq!(h.evaluate(inputs), Posture::Block);
    }

    #[test]
    fn suspicious_verdict_quarantines_business_allow() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Business,
            reputation: None,
            malware: Some(MalwareVerdict::Suspicious),
        };
        assert_eq!(h.evaluate(inputs), Posture::Quarantine);
    }

    #[test]
    fn suspicious_does_not_promote_inspect_full() {
        let h = SwgPolicyHolder::default();
        let inputs = DecisionInputs {
            category: Category::Uncategorised,
            reputation: None,
            malware: Some(MalwareVerdict::Suspicious),
        };
        // InspectFull stays — suspicious only quarantines
        // allow-class postures.
        assert_eq!(h.evaluate(inputs), Posture::InspectFull);
    }

    #[test]
    fn replace_swaps_policy_atomically() {
        let h = SwgPolicyHolder::default();
        // Default policy allows Business.
        assert_eq!(h.evaluate(inp(Category::Business)), Posture::Allow);
        // Replace with a stricter policy that blocks
        // Business as well.
        let mut strict = SwgPolicy::default();
        strict
            .by_category
            .insert(Category::Business, Posture::Block);
        h.replace(strict);
        assert_eq!(h.evaluate(inp(Category::Business)), Posture::Block);
    }

    #[test]
    fn snapshot_returns_current_policy() {
        let h = SwgPolicyHolder::default();
        let s = h.snapshot();
        assert!(matches!(s.posture_for(Category::Malware), Posture::Block));
    }

    #[test]
    fn policy_with_unknown_category_falls_back_to_default() {
        // Empty by_category — every lookup falls back.
        let policy = SwgPolicy {
            by_category: HashMap::new(),
            default_posture: Posture::AlertOnly,
            reputation_block_at: 1.0,
            reputation_inspect_at: 1.0,
        };
        let h = SwgPolicyHolder::new(policy);
        assert_eq!(h.evaluate(inp(Category::Malware)), Posture::AlertOnly);
        assert_eq!(h.evaluate(inp(Category::Phishing)), Posture::AlertOnly);
    }
}
