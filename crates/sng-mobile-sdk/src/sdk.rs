// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! The exported [`MobileSdk`] object — the single FFI entry point.
//!
//! `MobileSdk` is an opaque UniFFI `Object` that owns a fully
//! assembled [`MobileAgent`] and the OIDC session driving its
//! [`AuthSession`]. The foreign app constructs one from an
//! [`SdkMobileConfig`] and then drives the agent lifecycle through
//! the methods here. Every method is thin glue over the agent /
//! session; no orchestration logic is duplicated.
//!
//! Async methods are exported with `async_runtime = "tokio"` so the
//! agent's Tokio-based futures (per-request / connect deadlines,
//! the rustls + HTTP/2 transport, the OIDC HTTP round trips) run
//! under a Tokio context on whichever foreign thread UniFFI polls
//! them.

use std::sync::Arc;

use sng_mobile_core::{AuthSession, MobileAgent};

use crate::config::SdkMobileConfig;
use crate::deps::{self, Assembled};
use crate::error::MobileSdkError;
use crate::oidc::OidcAuthSession;
use crate::types::{
    SdkAccessDecision, SdkAccessRequest, SdkAgentHealth, SdkAuthState, SdkEnrollmentOutcome,
    SdkLifecycleState, SdkPostureSnapshot, SdkPowerState,
};

/// The mobile SDK: a foreign-friendly handle to a configured
/// [`MobileAgent`].
///
/// Cloned cheaply across the FFI boundary (UniFFI hands out an
/// `Arc`); all methods are `&self` and internally synchronised, so
/// the foreign app may call them from any thread.
#[derive(Debug, uniffi::Object)]
pub struct MobileSdk {
    agent: Arc<MobileAgent>,
    auth: Arc<OidcAuthSession>,
}

#[uniffi::export]
impl MobileSdk {
    /// Construct an SDK from `config`, assembling the platform
    /// backings (or the typed-Unsupported host fallback) and
    /// validating the configuration up front.
    ///
    /// # Errors
    ///
    /// Returns [`MobileSdkError::InvalidConfig`] if a foreign value
    /// cannot be parsed (ids, trust anchors, redirect URI) and
    /// [`MobileSdkError::Config`] if the assembled configuration
    /// fails the agent core's validation.
    // UniFFI lifts a `Record` argument as an owned value across the
    // FFI boundary — an exported constructor cannot take it by
    // reference — so the owned `config` is the required signature
    // even though it is only borrowed/cloned internally.
    #[allow(clippy::needless_pass_by_value)]
    #[uniffi::constructor]
    pub fn new(config: SdkMobileConfig) -> Result<Arc<Self>, MobileSdkError> {
        // `into_core` consumes a clone so `config` (with its
        // FFI-only fields) stays available for dependency assembly.
        let core_config = config.clone().into_core()?;
        let Assembled { deps, auth } = deps::assemble(&config, &core_config)?;
        let agent = MobileAgent::new(core_config, deps)?;
        Ok(Arc::new(Self {
            agent: Arc::new(agent),
            auth,
        }))
    }

    /// Current lifecycle phase.
    #[must_use]
    pub fn state(&self) -> SdkLifecycleState {
        self.agent.state().into()
    }

    /// Secret-free health snapshot (lifecycle, auth, allowed-app
    /// count).
    #[must_use]
    pub fn health(&self) -> SdkAgentHealth {
        self.agent.health().into()
    }

    /// Coarse, secret-free OIDC auth-session state.
    #[must_use]
    pub fn auth_state(&self) -> SdkAuthState {
        self.auth.state().into()
    }

    /// Whether the OIDC session currently holds a usable access
    /// token.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_authenticated()
    }

    /// The IdP-asserted tenant the held session is bound to (the
    /// authoritative `tenant_id` claim), or `None` before sign-in.
    #[must_use]
    pub fn tenant_id(&self) -> Option<String> {
        self.auth.tenant_id()
    }

    /// Whether the held session was established with an
    /// MFA-satisfied authentication. `false` before sign-in or when
    /// only a single factor was used; drive [`Self::step_up`]
    /// before a sensitive operation in that case.
    #[must_use]
    pub fn mfa_satisfied(&self) -> bool {
        self.auth.mfa_satisfied()
    }

    /// The most recent posture snapshot collected by the
    /// steady-state loop, if any has been taken since enrolment.
    #[must_use]
    pub fn last_posture(&self) -> Option<SdkPostureSnapshot> {
        self.agent.last_posture().map(Into::into)
    }

    /// The device power state the agent is currently pacing its
    /// heartbeat to.
    #[must_use]
    pub fn power_state(&self) -> SdkPowerState {
        self.agent.power_state().into()
    }

    /// Push a device power-state change from the host.
    ///
    /// Wire this to the platform's power-state notification — iOS
    /// `ProcessInfo.isLowPowerModeEnabled` /
    /// `NSProcessInfoPowerStateDidChange`, Android
    /// `PowerManager.isPowerSaveMode` /
    /// `ACTION_POWER_SAVE_MODE_CHANGED`. Under
    /// [`SdkPowerState::LowPower`] the agent stretches its coalesced
    /// heartbeat 4× to cut radio wakeups; the new cadence takes
    /// effect immediately even if the steady-state loop is mid-sleep.
    /// Idempotent and thread-safe; cheap enough to call on every
    /// platform notification.
    pub fn set_power_state(&self, state: SdkPowerState) {
        self.agent.set_power_state(state.into());
    }

    /// Suspend the agent (app backgrounded / network lost). Valid
    /// only from the connected state.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Lifecycle`] if the current state forbids
    /// the transition.
    pub fn suspend(&self) -> Result<(), MobileSdkError> {
        self.agent.suspend().map_err(Into::into)
    }

    /// Resume from the suspended state.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Lifecycle`] if the current state forbids
    /// the transition.
    pub fn resume(&self) -> Result<(), MobileSdkError> {
        self.agent.resume().map_err(Into::into)
    }

    /// Terminate the agent. Valid from any non-terminal state.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Lifecycle`] if the current state forbids
    /// the transition.
    pub fn terminate(&self) -> Result<(), MobileSdkError> {
        self.agent.terminate().map_err(Into::into)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl MobileSdk {
    /// Run the claim-token enrolment exchange, transitioning the
    /// agent from `Init` through `Enrolling` to `Connected`.
    ///
    /// # Errors
    ///
    /// Surfaces the agent core's enrolment / transport / key-store
    /// failures as the corresponding [`MobileSdkError`] variant.
    /// (Enrolment first opens a control-plane connection, so on a
    /// host build with no reachable control plane this surfaces as
    /// [`MobileSdkError::Comms`] / [`MobileSdkError::Timeout`]
    /// rather than reaching the secure key store.)
    pub async fn enroll(
        &self,
        claim_token: String,
    ) -> Result<SdkEnrollmentOutcome, MobileSdkError> {
        let outcome = self.agent.enroll(&claim_token).await?;
        Ok(outcome.into())
    }

    /// Collect a fresh device posture snapshot from the platform
    /// collector.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Posture`] if the platform collector fails;
    /// on the host build this is always the typed-Unsupported error.
    pub async fn collect_posture(&self) -> Result<SdkPostureSnapshot, MobileSdkError> {
        let snapshot = self.agent.collect_posture().await?;
        Ok(snapshot.into())
    }

    /// Drive the interactive OIDC sign-in flow (discovery → PKCE
    /// authorize → platform browser → code exchange → ID-token
    /// validation) and install the resulting session.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::SignIn`] for any failure in the flow,
    /// including the host build where there is no browser surface.
    pub async fn sign_in(&self) -> Result<(), MobileSdkError> {
        self.auth.sign_in().await
    }

    /// Force a refresh of the OIDC access token using the held
    /// refresh token.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Auth`] if no session is held (sign-in
    /// required) or the IdP rejected the refresh.
    pub async fn refresh_auth(&self) -> Result<(), MobileSdkError> {
        self.auth.refresh().await.map_err(MobileSdkError::from)
    }

    /// Evaluate a ZTNA access request for an application, feeding
    /// the agent's most recent device posture into the fail-closed
    /// posture pre-gate. A device that cannot be proven healthy
    /// (compromised, no screen lock, or no posture collected yet)
    /// is denied locally with `device_posture_insufficient` before
    /// the shared policy engine is consulted.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::Lifecycle`] if the post-enrolment runtime
    /// is not attached yet, or the mapped agent error for a
    /// provider miss (unknown app / unenrolled device / unknown
    /// identity).
    pub async fn check_access(
        &self,
        request: SdkAccessRequest,
    ) -> Result<SdkAccessDecision, MobileSdkError> {
        let decision = self
            .agent
            .check_access(&request.into(), chrono::Utc::now())
            .await?;
        Ok(decision.into())
    }

    /// Drive an OIDC MFA **step-up** re-authentication and, only if
    /// the returned token proves MFA, replace the held session with
    /// the stronger one. A failed step-up leaves the existing
    /// session untouched.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::SignIn`] for any failure in the flow, and
    /// specifically when the re-authenticated token is still not
    /// MFA-satisfied (fail-closed).
    pub async fn step_up(&self) -> Result<(), MobileSdkError> {
        self.auth.step_up().await
    }

    /// Wipe this device's enrolment: delete the secure-enclave
    /// device key, clear the OIDC session, and terminate the agent.
    /// Idempotent — safe to call when already wiped — so a leaver /
    /// revoke signal can be replayed without error.
    ///
    /// A leaver / revoke must revoke **every** piece of local
    /// credential material it can, even on a partial failure: the
    /// OIDC session is therefore cleared unconditionally — including
    /// when the secure store rejects the device-key deletion — so a
    /// backend error can never leave usable session tokens behind.
    /// [`OidcAuthSession::wipe`] is infallible; the key-deletion
    /// error is still surfaced afterwards so the caller retries the
    /// (idempotent) wipe to destroy the device key too.
    ///
    /// The OIDC wipe also *latches* the session terminal, so an
    /// interactive sign-in / step-up that was already in flight when
    /// the wipe landed cannot reinstall a session afterwards.
    ///
    /// # Errors
    ///
    /// [`MobileSdkError::KeyStore`] if the secure store rejects the
    /// key deletion (the OIDC session is already cleared by then).
    pub async fn wipe(&self) -> Result<(), MobileSdkError> {
        let wipe_result = self.agent.wipe().await;
        self.auth.wipe();
        wipe_result.map_err(MobileSdkError::from)
    }
}

#[cfg(all(test, not(any(target_os = "ios", target_os = "android"))))]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::config::tests::valid_config;

    fn sdk() -> Arc<MobileSdk> {
        MobileSdk::new(valid_config()).expect("host SDK builds")
    }

    #[test]
    fn new_starts_in_init_unauthenticated() {
        let sdk = sdk();
        assert_eq!(sdk.state(), SdkLifecycleState::Init);
        assert_eq!(sdk.auth_state(), SdkAuthState::Unauthenticated);
        assert!(!sdk.is_authenticated());
        assert!(sdk.last_posture().is_none());
        let health = sdk.health();
        assert_eq!(health.lifecycle, SdkLifecycleState::Init);
        assert!(!health.authenticated);
        // A fresh SDK paces itself at normal power.
        assert_eq!(health.power, SdkPowerState::Normal);
        assert_eq!(sdk.power_state(), SdkPowerState::Normal);
    }

    #[test]
    fn set_power_state_is_reflected_in_state_and_health() {
        let sdk = sdk();
        sdk.set_power_state(SdkPowerState::LowPower);
        assert_eq!(sdk.power_state(), SdkPowerState::LowPower);
        assert_eq!(sdk.health().power, SdkPowerState::LowPower);
        // Idempotent: re-asserting and clearing round-trips cleanly.
        sdk.set_power_state(SdkPowerState::LowPower);
        assert_eq!(sdk.power_state(), SdkPowerState::LowPower);
        sdk.set_power_state(SdkPowerState::Normal);
        assert_eq!(sdk.power_state(), SdkPowerState::Normal);
    }

    #[test]
    fn invalid_config_is_rejected_before_assembly() {
        let mut cfg = valid_config();
        cfg.tenant_id = "not-a-uuid".into();
        let err = MobileSdk::new(cfg).expect_err("must reject");
        assert!(
            matches!(err, MobileSdkError::InvalidConfig { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn suspend_from_init_is_a_lifecycle_error() {
        // `suspend` is only valid from `Connected`; from `Init` the
        // agent rejects the transition as a typed lifecycle error.
        let err = sdk().suspend().expect_err("invalid from Init");
        assert!(matches!(err, MobileSdkError::Lifecycle { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn collect_posture_is_unsupported_on_host() {
        // The host posture collector has no device source; it returns
        // a typed posture error rather than faking a snapshot.
        let err = sdk().collect_posture().await.expect_err("host unsupported");
        assert!(matches!(err, MobileSdkError::Posture { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn refresh_without_session_is_an_auth_error() {
        // No sign-in has installed a session, so a refresh has no
        // refresh token to use.
        let err = sdk().refresh_auth().await.expect_err("no session");
        assert!(matches!(err, MobileSdkError::Auth { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn check_access_before_runtime_is_a_lifecycle_error() {
        // Access checks require the post-enrolment runtime (ZTNA
        // manager); on a freshly constructed host SDK it is not
        // attached, so the call fails closed as a lifecycle error
        // rather than silently allowing.
        let req = SdkAccessRequest {
            app_id: "wiki".into(),
            device_id: "dev-1".into(),
            user_id: "alice".into(),
            now_ms: 1_000,
        };
        let err = sdk().check_access(req).await.expect_err("no runtime");
        assert!(matches!(err, MobileSdkError::Lifecycle { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn wipe_clears_oidc_session_even_when_key_deletion_fails() {
        // On the host build the secure store has no enclave, so the
        // agent's key deletion fails with a backend error. A leaver /
        // revoke must still revoke the local OIDC credential — the
        // session is cleared unconditionally — and the key-deletion
        // error must still surface so the caller retries.
        let sdk = sdk();
        sdk.auth.install_test_identity(Some("tenant-7"), true);
        // Precondition: the session identity is present.
        assert_eq!(sdk.tenant_id().as_deref(), Some("tenant-7"));
        assert!(sdk.mfa_satisfied());

        let err = sdk.wipe().await.expect_err("host key deletion fails");
        assert!(matches!(err, MobileSdkError::KeyStore { .. }), "{err:?}");

        // Despite the failed key deletion, the OIDC identity is gone.
        assert!(sdk.tenant_id().is_none());
        assert!(!sdk.mfa_satisfied());
    }

    #[test]
    fn access_decision_mirror_maps_reason_and_posture_labels() {
        use sng_mobile_core::{PostureResult, ZtnaDecision, ZtnaDecisionReason};
        let decision = ZtnaDecision {
            allow: false,
            reason: ZtnaDecisionReason::DevicePostureInsufficient,
            posture_result: PostureResult::Fail,
        };
        let sdk: SdkAccessDecision = decision.into();
        assert!(!sdk.allow);
        assert_eq!(sdk.reason, "device_posture_insufficient");
        assert_eq!(sdk.posture_result, "fail");
    }
}
