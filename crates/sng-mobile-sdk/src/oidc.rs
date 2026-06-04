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

use async_trait::async_trait;
use parking_lot::Mutex;
use sng_mobile_core::{AccessToken, AuthConfig, AuthError, AuthSession, AuthState};
use sng_oidc::session::SessionConfig;
use sng_oidc::{
    AuthSurface, AuthorizationRequest, CodeExchange, DiscoveryClient, IdTokenClaims,
    IdTokenValidator, JwksClient, OidcSession, PkceChallenge, TokenClient,
};
use uuid::Uuid;

use crate::error::MobileSdkError;

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
    /// `None` until [`Self::sign_in`] succeeds. Cloned out (cheap
    /// `Arc` bump) before any `.await` so the lock is never held
    /// across the network round trip.
    session: Mutex<Option<Arc<OidcSession>>>,
}

impl OidcAuthSession {
    /// Build an as-yet-unauthenticated session around `auth`, the
    /// `redirect_uri` the IdP redirects back to, and the platform
    /// `surface`.
    #[must_use]
    pub fn new(auth: AuthConfig, redirect_uri: String, surface: Arc<dyn AuthSurface>) -> Self {
        Self {
            auth,
            redirect_uri,
            surface,
            session: Mutex::new(None),
        }
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
        let redirect_uri = self.redirect_uri.as_str();
        // 1. Discover the provider's endpoints from the issuer.
        let issuer = self.auth.issuer.trim_end_matches('/');
        let discovery_url = format!("{issuer}/.well-known/openid-configuration");
        let discovery = DiscoveryClient::new()?;
        let meta = discovery.discover(&discovery_url).await?;

        // 2. Mint the PKCE pair and our own state/nonce so we can
        //    verify the callback and bind the ID token.
        let pkce = PkceChallenge::generate();
        let state = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let scope = self.auth.scopes.join(" ");
        let authz = AuthorizationRequest::new(&self.auth.client_id, redirect_uri, scope, &pkce)
            .with_state(state.clone())
            .with_nonce(nonce.clone());
        let url = authz.to_url(&meta.authorization_endpoint)?;

        // 3. Present the browser leg through the platform surface.
        let callback = self.surface.present_auth_url(&url).await?;
        if let Some(err) = callback.error() {
            return Err(MobileSdkError::sign_in(format!(
                "identity provider returned an error on the callback: {err}"
            )));
        }
        // 4. Reject a callback whose `state` does not echo ours
        //    (CSRF / mix-up defence) before touching the code.
        if callback.state().as_deref() != Some(state.as_str()) {
            return Err(MobileSdkError::sign_in(
                "authorization callback state did not match the request (possible CSRF)",
            ));
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
        let identity = self
            .validate_id_token(tokens.id_token.as_deref(), &meta.jwks_uri, &nonce)
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
        jwks_uri: &str,
        nonce: &str,
    ) -> Result<Option<IdTokenClaims>, MobileSdkError> {
        let Some(id_token) = id_token else {
            return Ok(None);
        };
        let validator =
            IdTokenValidator::new(self.auth.issuer.clone(), self.auth.client_id.clone())
                .with_nonce(nonce);
        let jwks_client = JwksClient::new()?;
        let claims = validator.validate(id_token, &jwks_client, jwks_uri).await?;
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
