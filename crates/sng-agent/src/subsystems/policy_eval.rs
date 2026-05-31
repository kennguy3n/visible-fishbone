// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Policy-evaluation subsystem adapter.
//!
//! Endpoint-tier sibling of
//! [`sng_edge::subsystems::policy_eval`]. Wraps a
//! [`sng_policy_eval::PolicyEngine`] pinned to the
//! [`sng_policy_eval::BundleTarget::Endpoint`] target. The
//! engine is stateless w.r.t. background tasks — every
//! evaluation is a synchronous function call — so the
//! subsystem's `start` method just waits on the shutdown
//! signal. Bundle hot-swaps are delivered through
//! [`PolicyEvalSubsystem::swap_bundle`] by the comms /
//! control-plane puller subsystem.

use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_policy_eval::{BundleTarget, Flow, PolicyEngine, PolicyEvalError, Verdict};
use std::sync::Arc;
use tokio::task;

/// Endpoint-tier policy evaluation subsystem.
#[derive(Debug)]
pub struct PolicyEvalSubsystem {
    engine: Arc<PolicyEngine>,
}

impl PolicyEvalSubsystem {
    /// Construct from an initial compiled bundle body. The
    /// body is validated by [`PolicyEngine::from_body`] up
    /// front so a malformed bootstrap bundle surfaces as a
    /// hard build error, not a runtime exception after the
    /// supervisor already spawned every other subsystem.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvalError`] when the bundle body fails
    /// signature / schema validation.
    pub fn new(initial_bundle: &[u8]) -> Result<Self, PolicyEvalError> {
        let engine = PolicyEngine::from_body(initial_bundle, BundleTarget::Endpoint)?;
        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Construct directly from a pre-built engine. Used by
    /// the integration tests so they can share an engine
    /// with their own bundle fixtures.
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
    /// [`PolicyEngine::evaluate`] kept on the adapter so
    /// tests (and downstream subsystems) can mock the
    /// adapter rather than the engine.
    #[must_use]
    pub fn evaluate(&self, flow: &Flow<'_>) -> Verdict {
        self.engine.evaluate(flow)
    }

    /// Hot-swap the compiled bundle. Called by the comms /
    /// policy-puller adapter after a successful pull.
    /// `force` matches [`PolicyEngine::swap`]: when `true`,
    /// the monotonicity check is skipped (used for emergency
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
        // No background task — evaluation is purely
        // synchronous. The spawned task exists only to honour
        // the supervisor's shutdown contract (every subsystem
        // owns a join handle).
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
    use sng_policy_eval::deny_all_skeleton_body;

    fn bootstrap_body() -> Vec<u8> {
        deny_all_skeleton_body(BundleTarget::Endpoint)
    }

    #[tokio::test]
    async fn subsystem_start_waits_for_shutdown_and_returns_ok() {
        let subsys = PolicyEvalSubsystem::new(&bootstrap_body()).expect("engine");
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = subsys.start(signal).await.expect("start");
        trigger.fire();
        let join = handle.await.expect("join");
        assert!(join.is_ok());
    }

    #[tokio::test]
    async fn health_check_reports_up_with_graph_version_detail() {
        let subsys = PolicyEvalSubsystem::new(&bootstrap_body()).expect("engine");
        let snap = subsys.check().await;
        assert_eq!(snap.status, HealthStatus::Up);
        assert!(
            snap.detail
                .as_deref()
                .unwrap_or_default()
                .contains("graph_version=")
        );
    }

    #[test]
    fn new_rejects_invalid_bundle() {
        // Any decoder error is fine — the point of the test is
        // that a malformed bootstrap bundle surfaces as a hard
        // error from `new` so the binary refuses to boot rather
        // than panicking later when a flow is evaluated.
        let err = PolicyEvalSubsystem::new(b"not a real bundle").unwrap_err();
        // Just confirm we got an error variant; the exact one
        // is a property of the upstream bundle decoder and is
        // pinned down by sng-policy-eval's own tests.
        let _ = format!("{err:?}");
    }
}
