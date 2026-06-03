//! # sng-oidc — pure-Rust OpenID Connect client for native-app SSO
//!
//! `sng-oidc` is the ShieldNet Gateway (SNG) enforcement-plane's
//! OpenID Connect (OIDC) client. It implements the full
//! Authorization Code flow with PKCE that a mobile native app
//! uses to sign a user in against their corporate IdP (Google
//! Workspace, Microsoft 365, Zoho, Okta) and to obtain the
//! `sub` + `groups` identity that the ZTNA broker
//! (`sng-ztna`) binds an access decision to.
//!
//! ## Platform independence
//!
//! This crate has **no platform dependencies** and runs the same
//! on iOS, Android, and a host test runner. The one piece that is
//! inherently platform-specific — presenting the IdP's
//! authorization URL in a system browser and capturing the
//! redirect callback — is injected through the
//! [`AuthSurface`] trait. The iOS / Android Platform Abstraction
//! Layers (PALs), built in later sessions, implement
//! `AuthSurface` over `ASWebAuthenticationSession` /
//! Android Custom Tabs respectively. Nothing in this crate
//! references an OS API.
//!
//! ## Flow
//!
//! 1. [`discovery::DiscoveryClient`] fetches the provider's
//!    `/.well-known/openid-configuration` (RFC 8414) and caches
//!    it with a TTL.
//! 2. [`pkce::PkceChallenge::generate`] mints a code verifier +
//!    `S256` challenge (RFC 7636).
//! 3. [`authorize::AuthorizationRequest`] builds the
//!    authorization URL (state for CSRF, nonce for replay,
//!    `code_challenge`, plus provider quirks such as Google's
//!    `hd` or Microsoft's `domain_hint`).
//! 4. The injected [`AuthSurface`] presents the URL and returns
//!    the [`auth_surface::CallbackUrl`].
//! 5. [`token::TokenClient`] exchanges the code (with the PKCE
//!    verifier) at the token endpoint.
//! 6. [`validation::IdTokenValidator`] verifies the ID token
//!    signature against the provider JWKS and validates `iss`,
//!    `aud`, `exp`, `iat`, `nonce`, and `azp` per OIDC Core
//!    §3.1.3.7.
//! 7. [`session::OidcSession`] owns the token lifecycle —
//!    auto-refreshing with jitter before expiry and exposing the
//!    `sub` + `groups` used for ZTNA identity binding.
//! 8. [`storage::TokenStorage`] persists tokens through an
//!    injected platform keystore.
//!
//! ## Security posture
//!
//! - `#![forbid(unsafe_code)]` — there is no `unsafe` in this
//!   crate.
//! - The HTTP client is rustls-only (`reqwest` with
//!   `default-features = false`); the workspace `deny.toml` bars
//!   the OpenSSL-FFI / `native-tls` backends.
//! - Every secret-bearing type implements a redacting `Debug` so
//!   verifiers / codes / tokens / client secrets never leak into
//!   logs: `PkceChallenge`, `TokenResponse`, `StoredTokens`,
//!   `OidcSession`, `SessionConfig`, `CodeExchange`, and
//!   `RefreshRequest`.

#![forbid(unsafe_code)]
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding and CI runs `cargo clippy --all-targets -D warnings`
// across the workspace. Allowing them in `#[cfg(test)]` only keeps
// the workspace-wide lints active for production code without
// producing dozens of per-test allow attributes.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::float_cmp,
    )
)]

pub mod auth_surface;
pub mod authorize;
pub mod discovery;
pub mod error;
pub mod pkce;
pub mod providers;
pub mod session;
pub mod storage;
pub mod token;
pub mod validation;

pub use auth_surface::{AuthSurface, AuthSurfaceError, CallbackUrl};
pub use authorize::AuthorizationRequest;
pub use discovery::{DiscoveryClient, ProviderMetadata};
pub use error::{OidcError, Result};
pub use pkce::{PkceChallenge, PkceMethod};
pub use providers::Provider;
pub use session::OidcSession;
pub use storage::{MemoryTokenStorage, StorageError, StoredTokens, TokenStorage};
pub use token::{CodeExchange, RefreshRequest, TokenClient, TokenResponse};
pub use validation::{IdTokenClaims, IdTokenValidator, Jwks, JwksClient};
