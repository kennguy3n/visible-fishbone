// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Policy-evaluation subsystem adapter.
//!
//! Wraps a [`sng_policy_eval::PolicyEngine`] pinned to the
//! [`sng_policy_eval::BundleTarget::Edge`] target. The engine is
//! stateless w.r.t. background tasks — every evaluation is a
//! synchronous function call — so the subsystem's `start` method
//! just waits on the shutdown signal. Bundle hot-swaps are
//! delivered through [`PolicyEvalSubsystem::swap_bundle`] by the
//! comms / control-plane puller subsystem; the supervisor itself
//! does not poll for them here.

use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_policy_eval::{BundleTarget, Flow, PolicyEngine, PolicyEvalError, Verdict};
use std::sync::Arc;
use tokio::task;

/// Edge-tier policy evaluation subsystem.
#[derive(Debug)]
pub struct PolicyEvalSubsystem {
    engine: Arc<PolicyEngine>,
}

impl PolicyEvalSubsystem {
    /// Construct from an initial compiled bundle body. The body
    /// is validated by [`PolicyEngine::from_body`] up front so a
    /// malformed bootstrap bundle surfaces as a hard build
    /// error, not a runtime exception after the supervisor
    /// already spawned every other subsystem.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvalError`] when the bundle body fails
    /// signature / schema validation.
    pub fn new(initial_bundle: &[u8]) -> Result<Self, PolicyEvalError> {
        let engine = PolicyEngine::from_body(initial_bundle, BundleTarget::Edge)?;
        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Construct directly from a pre-built engine. Used by the
    /// integration tests so they can share an engine with their
    /// own bundle fixtures, and by the supervisor wiring when
    /// the engine has already been pre-warmed by a sister
    /// subsystem (e.g. the comms PolicyPuller delivering the
    /// first bundle before the supervisor finishes wiring).
    #[must_use]
    pub fn from_engine(engine: Arc<PolicyEngine>) -> Self {
        Self { engine }
    }

    /// Borrow the underlying engine. The binary's other
    /// subsystem adapters use this to feed [`Flow`] inputs
    /// through the engine without copying.
    #[must_use]
    pub fn engine(&self) -> &Arc<PolicyEngine> {
        &self.engine
    }

    /// Evaluate a flow. Thin wrapper around
    /// [`PolicyEngine::evaluate`] kept on the adapter so tests
    /// (and downstream subsystems) can mock the adapter rather
    /// than the engine.
    #[must_use]
    pub fn evaluate(&self, flow: &Flow<'_>) -> Verdict {
        self.engine.evaluate(flow)
    }

    /// Hot-swap the compiled bundle. Called by the comms /
    /// policy-puller adapter after a successful pull. `force`
    /// matches [`PolicyEngine::swap`]: when `true`, the
    /// monotonicity check is skipped (used for emergency
    /// rollback).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvalError`] when the new body fails
    /// validation; the engine retains the previous bundle.
    pub fn swap_bundle(&self, body: &[u8], force: bool) -> Result<(), PolicyEvalError> {
        self.engine.swap(body, force)
    }
}

#[async_trait]
impl Subsystem for PolicyEvalSubsystem {
    fn name(&self) -> &'static str {
        "policy_eval"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        // No background task — evaluation is purely synchronous.
        // The spawned task exists only to honour the supervisor's
        // shutdown contract (every subsystem owns a join handle).
        Ok(task::spawn(async move {
            shutdown.wait().await;
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for PolicyEvalSubsystem {
    fn name(&self) -> &'static str {
        "policy_eval"
    }

    async fn check(&self) -> SubsystemHealth {
        // Engine is healthy as long as it holds a bundle.
        // `current_bundle()` returns an `Arc<LoadedBundle>`; we
        // surface the bundle's graph_version + rule_count as the
        // operator-visible detail so the dashboard can render
        // "v=42, 137 rules" without having to introspect the
        // engine itself.
        let bundle = self.engine.current_bundle();
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status: HealthStatus::Up,
            detail: Some(format!(
                "graph_version={}, rules={}",
                bundle.graph_version,
                bundle.rule_count()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;

    // The engine constructor accepts a body that is either a
    // signed envelope or a raw payload (when verification is
    // disabled in tests). Reach into the library's own test
    // fixture format by handing it the smallest valid payload
    // the schema accepts. The library exposes
    // `from_body` which performs a schema validation only when
    // no verifier is wired — for the integration tests that
    // shape is fine because the production wiring threads the
    // signed bundle through `swap_bundle` after a PolicyPuller
    // pull.
    //
    // For this unit-test we exercise the adapter on a known-
    // good fixture by building the engine through the library's
    // own test export.

    fn fixture_bundle_body() -> Vec<u8> {
        // Use the library's canonical fail-closed skeleton
        // bundle as the boot fixture. This is the same body
        // the binary's wiring uses at supervisor build time,
        // so the adapter test exercises the production code
        // path end-to-end (no test-only constructor branch).
        sng_policy_eval::deny_all_skeleton_body(BundleTarget::Edge)
    }

    #[tokio::test]
    async fn subsystem_idles_until_shutdown() {
        let body = fixture_bundle_body();
        let sub = PolicyEvalSubsystem::new(&body).expect("bundle");
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("drain budget");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn health_reports_up_with_graph_version_and_rule_count() {
        let body = fixture_bundle_body();
        let sub = PolicyEvalSubsystem::new(&body).expect("bundle");
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Up);
        let detail = h.detail.expect("detail");
        // Skeleton body sets graph_version=0 and contains
        // zero rules — both must surface verbatim so operator
        // dashboards distinguish "skeleton" from "pulled".
        assert!(detail.contains("graph_version=0"));
        assert!(detail.contains("rules=0"));
    }
}
