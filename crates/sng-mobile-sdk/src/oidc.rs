// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! The OIDC `AuthSession` the agent depends on, built from
//! `sng-oidc`.
//!
//! `sng-mobile-core` orchestrates the agent against the
//! [`AuthSession`] trait but ships no concrete implementation;
//! `sng-oidc` provides the protocol pieces (discovery, PKCE, code
//! exchange, ID-token validation, [`OidcSession`] with auto-refresh)
//! but knows nothing of that trait. This module is the **glue**
//! between them — it is the one place the SDK adds behaviour, and it
//! adds only adaptation, never new protocol logic:
//!
//! * [`OidcAuthSession`] is an [`AuthSession`] whose token state is
//!   an `Option<OidcSession>` — `None` until the user signs in,
//!   `Some` afterwards. Before sign-in every token request returns
//!   the typed [`AuthError::Unauthenticated`] the agent already
//!   knows how to surface.
//! * [`OidcAuthSession::sign_in`] drives the full
//!   authorization-code-with-PKCE flow once, using the
//!   platform-injected [`AuthSurface`] (iOS
//!   `ASWebAuthenticationSession`, Android Custom Tabs, or the host
//!   fallback) to present the browser leg, then installs the
//!   resulting [`OidcSession`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use sng_mobile_core::{AccessToken, AuthConfig, AuthError, AuthSession, AuthState};
use sng_oidc::session::SessionConfig;
use sng_oidc::{
    AuthSurface, AuthorizationRequest, CodeExchange, DiscoveryClient, IdTokenClaims,
    IdTokenValidator, JwksClient, OidcSession, PkceChallenge, TokenClient,
};

use crate::error::MobileSdkError;

/// RAII gate that clears [`OidcAuthSession::sign_in_active`] on drop,
/// so a sign-in that fails (or panics) still releases the flag.
struct SignInGate<'a>(&'a AtomicBool);

impl Drop for SignInGate<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// An [`AuthSession`] backed by `sng-oidc`.
///
/// Holds the platform [`AuthSurface`] (for the interactive browser
/// leg) and the live [`OidcSession`] once sign-in has completed. All
/// fields are `Send + Sync`, so the agent can hold it as
/// `Arc<dyn AuthSession>` and call it from any task.
#[derive(Debug)]
pub struct OidcAuthSession {
    auth: AuthConfig,
    redirect_uri: String,
    surface: Arc<dyn AuthSurface>,
    /// Held for the lifetime of the session so the provider-metadata
    /// cache persists across sign-ins: a repeat sign-in against the
    /// same issuer skips the discovery network fetch.
    discovery: DiscoveryClient,
    /// Held for the lifetime of the session so the JWKS cache
    /// persists: the ID-token validator's key-rotation retry path
    /// (`IdTokenValidator::validate`) starts warm instead of
    /// re-fetching the key set on every sign-in.
    jwks: JwksClient,
    /// `true` while an interactive [`Self::sign_in`] is in flight. A
    /// second concurrent call is rejected rather than driving a
    /// duplicate browser presentation / code exchange that would race
    /// the first and silently clobber its session.
    sign_in_active: AtomicBool,
    /// `None` until [`Self::sign_in`] succeeds. Cloned out (cheap
    /// `Arc` bump) before any `.await` so the lock is never held
    /// across the network round trip.
    session: Mutex<Option<Arc<OidcSession>>>,
}

impl OidcAuthSession {
    /// Build an as-yet-unauthenticated session around `auth`, the
    /// `redirect_uri` the IdP redirects back to, and the platform
    /// `surface`.
    ///
    /// # Errors
    /// Returns [`MobileSdkError::InvalidConfig`] if the cached
    /// discovery / JWKS HTTP clients cannot be constructed (e.g. the
    /// platform TLS backend fails to initialise). This runs at SDK
    /// construction time, not during sign-in, so the failure is
    /// surfaced as a config error rather than the `SignIn` class the
    /// blanket `From<OidcError>` would otherwise produce.
    pub fn new(
        auth: AuthConfig,
        redirect_uri: String,
        surface: Arc<dyn AuthSurface>,
    ) -> Result<Self, MobileSdkError> {
        let discovery = DiscoveryClient::new().map_err(|e| {
            MobileSdkError::invalid_config(format!(
                "failed to initialise OIDC discovery client: {e}"
            ))
        })?;
        let jwks = JwksClient::new().map_err(|e| {
            MobileSdkError::invalid_config(format!("failed to initialise JWKS client: {e}"))
        })?;
        Ok(Self {
            auth,
            redirect_uri,
            surface,
            discovery,
            jwks,
            sign_in_active: AtomicBool::new(false),
            session: Mutex::new(None),
        })
    }

    /// Whether sign-in has installed a live session.
    fn current(&self) -> Option<Arc<OidcSession>> {
        self.session.lock().clone()
    }

    /// Run the interactive OIDC authorization-code + PKCE flow and
    /// install the resulting session.
    ///
    /// Uses the `redirect_uri` supplied at construction (the
    /// callback the IdP is configured to redirect to and that the
    /// platform [`AuthSurface`] intercepts). On success the session
    /// becomes authenticated and [`Self::access_token`] starts
    /// returning live tokens.
    pub async fn sign_in(&self) -> Result<(), MobileSdkError> {
        // 0. Reject a concurrent sign-in. `compare_exchange` claims the
        //    gate atomically; the guard clears it on every exit path.
        if self
            .sign_in_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MobileSdkError::sign_in("a sign-in is already in progress"));
        }
        let _gate = SignInGate(&self.sign_in_active);

        let redirect_uri = self.redirect_uri.as_str();
        // 1. Discover the provider's endpoints from the issuer.
        let issuer = self.auth.issuer.trim_end_matches('/');
        let discovery_url = format!("{issuer}/.well-known/openid-configuration");
        let meta = self.discovery.discover(&discovery_url).await?;

        // 2. Mint the PKCE pair plus the request's `state`/`nonce`.
        //    `AuthorizationRequest::new` already generates a 256-bit
        //    random `state` (CSRF) and `nonce` (replay binding); read
        //    those back rather than overriding with lower-entropy
        //    values.
        let pkce = PkceChallenge::generate();
        let scope = self.auth.scopes.join(" ");
        let authz = AuthorizationRequest::new(&self.auth.client_id, redirect_uri, scope, &pkce);
        let state = authz.state.clone();
        let nonce = authz.nonce.clone();
        let url = authz.to_url(&meta.authorization_endpoint)?;

        // 3. Present the browser leg through the platform surface.
        let callback = self.surface.present_auth_url(&url).await?;
        // 4. Reject a callback whose `state` does not echo ours
        //    (CSRF / mix-up defence) before inspecting *any* other
        //    parameter. Per RFC 6749 §10.12 and OIDC Core §3.1.2.7 the
        //    `state` check gates everything else, so a forged callback
        //    — even one carrying `error=…` — is classified as a CSRF
        //    attempt rather than mistaken for a genuine IdP error.
        if callback.state().as_deref() != Some(state.as_str()) {
            return Err(MobileSdkError::sign_in(
                "authorization callback state did not match the request (possible CSRF)",
            ));
        }
        if let Some(err) = callback.error() {
            return Err(MobileSdkError::sign_in(format!(
                "identity provider returned an error on the callback: {err}"
            )));
        }
        let code = callback
            .code()
            .ok_or_else(|| MobileSdkError::sign_in("authorization callback carried no code"))?;

        // 5. Redeem the code for tokens (PKCE verifier proves
        //    possession; public client, no secret).
        let token_client = TokenClient::new()?;
        let exchange = CodeExchange {
            client_id: self.auth.client_id.clone(),
            code,
            redirect_uri: redirect_uri.to_owned(),
            code_verifier: pkce.verifier().to_owned(),
            client_secret: None,
        };
        let tokens = token_client
            .exchange_code(&meta.token_endpoint, &exchange)
            .await?;

        // 6. Validate the ID token (if the IdP returned one), binding
        //    it to our nonce. Absent ID token => no identity claims,
        //    but the access/refresh tokens still drive the session.
        //    The issuer compared against the `iss` claim must be the
        //    provider's canonical issuer from discovery (OIDC Core
        //    §3.1.3.7), not the user-configured input.
        let identity = self
            .validate_id_token(
                tokens.id_token.as_deref(),
                &meta.issuer,
                &meta.jwks_uri,
                &nonce,
            )
            .await?;

        // 7. Install the live session (moves `token_client` in so the
        //    auto-refresh loop reuses the same HTTP client).
        let mut config = SessionConfig::new(&meta.token_endpoint, &self.auth.client_id);
        config.refresh_skew = self.auth.refresh_skew;
        let session = OidcSession::start(token_client, config, &tokens, identity.as_ref());
        *self.session.lock() = Some(Arc::new(session));
        Ok(())
    }

    /// Validate the ID token against the discovered JWKS, binding it
    /// to `nonce`. Returns `None` when the IdP issued no ID token.
    async fn validate_id_token(
        &self,
        id_token: Option<&str>,
        canonical_issuer: &str,
        jwks_uri: &str,
        nonce: &str,
    ) -> Result<Option<IdTokenClaims>, MobileSdkError> {
        let Some(id_token) = id_token else {
            return Ok(None);
        };
        // `canonical_issuer` is `meta.issuer` from the discovery
        // document — the value the `iss` claim is compared against —
        // not `self.auth.issuer`, which may differ by a trailing
        // slash and would spuriously fail validation.
        let validator =
            IdTokenValidator::new(canonical_issuer.to_owned(), self.auth.client_id.clone())
                .with_nonce(nonce);
        let claims = validator.validate(id_token, &self.jwks, jwks_uri).await?;
        Ok(Some(claims))
    }
}

#[async_trait]
impl AuthSession for OidcAuthSession {
    async fn access_token(&self) -> Result<AccessToken, AuthError> {
        let session = self.current().ok_or(AuthError::Unauthenticated)?;
        let raw = session
            .access_token()
            .await
            .map_err(|e| AuthError::Provider(e.to_string()))?;
        Ok(AccessToken::new(raw))
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        let session = self.current().ok_or(AuthError::Unauthenticated)?;
        session
            .refresh()
            .await
            .map_err(|e| AuthError::RefreshRejected(e.to_string()))
    }

    // NOTE on the no-expiry edge case: when the IdP omits `expires_in`
    // (RECOMMENDED, not REQUIRED, by the OIDC spec) the session has no
    // known `expires_at`, so neither method below can *prove* the
    // token is currently valid and both report the conservative
    // not-authenticated view (`Expired` / `false`). The token still
    // works — `access_token()` returns it and triggers no refresh —
    // so a foreign caller that gets `Expired`/`false` should still
    // attempt the operation rather than forcing an interactive
    // sign-in.
    fn state(&self) -> AuthState {
        match self.current() {
            None => AuthState::Unauthenticated,
            Some(session) => match session.expires_at() {
                Some(expires_at) if !session.needs_refresh() => {
                    AuthState::Authenticated { expires_at }
                }
                // Either the held token is at/over the refresh skew,
                // or the session has no known expiry. In both cases
                // it cannot be proven currently valid, so report
                // `Expired` — a refresh may still recover it without
                // an interactive sign-in.
                _ => AuthState::Expired,
            },
        }
    }

    fn is_authenticated(&self) -> bool {
        self.current()
            .is_some_and(|session| session.expires_at().is_some() && !session.needs_refresh())
    }
}
