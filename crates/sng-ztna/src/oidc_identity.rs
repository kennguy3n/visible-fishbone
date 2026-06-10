//! OIDC token → [`UserIdentity`] resolution for the ZTNA access path.
//!
//! The ZTNA broker binds an access decision to a *validated* identity:
//! the stable `sub` claim plus the IdP-asserted group set. This module
//! turns a bearer OIDC ID token into a [`UserIdentity`] by validating it
//! against the **requesting tenant's** registered IdP configuration
//! (issuer + audience + JWKS) via [`sng_oidc`], then projecting the
//! token's `sub` / `groups` / MFA claims onto the ZTNA identity record.
//!
//! Tenant isolation is enforced at two points:
//!  1. The validator is selected by the *request's* tenant id, so a
//!     token is only ever checked against that tenant's provider keys.
//!  2. When the token carries an authoritative `tenant_id` claim
//!     (iam-core issued), it MUST equal the requesting tenant or the
//!     token is rejected — a token minted for tenant A can never resolve
//!     an identity under tenant B.
//!
//! Validation failures fail closed: no identity is produced and the
//! caller denies the request as identity-rejected.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use sng_oidc::validation::{IdTokenClaims, IdTokenValidator, JwksClient};

use crate::error::ZtnaError;
use crate::identity::UserIdentity;

/// A tenant's enforcement-plane OIDC configuration: the provider
/// coordinates needed to validate a token presented for that tenant.
#[derive(Clone, Debug)]
pub struct TenantIdpConfig {
    /// Tenant the configuration belongs to.
    pub tenant_id: String,
    /// Canonical issuer (`iss`) the token must carry — exact match.
    pub issuer: String,
    /// Expected audience (the OAuth2 client id).
    pub audience: String,
    /// JWKS endpoint the signing key is fetched from.
    pub jwks_uri: String,
}

/// Project validated ID-token claims onto a [`UserIdentity`] for a
/// specific tenant.
///
/// This is the pure, network-free core of token→identity resolution:
///  - `user_id` is the token `sub` (the stable provider-scoped id the
///    data path attributes a request to);
///  - `groups` are taken verbatim from the IdP group claim;
///  - `mfa_at_ms` is derived from `iat` when the token proves MFA
///    ([`IdTokenClaims::mfa_satisfied`]) and `0` otherwise, so a
///    non-MFA token never satisfies an MFA-freshness policy.
///
/// Returns [`ZtnaError::TokenRejected`] when the token's authoritative
/// `tenant_id` claim disagrees with `tenant_id`, or when `sub` is empty.
pub fn identity_from_claims(
    claims: &IdTokenClaims,
    tenant_id: &str,
) -> Result<UserIdentity, ZtnaError> {
    // Fail closed on a cross-tenant token: an iam-core token's
    // `tenant_id` claim is the sole authoritative tenant binding and
    // MUST match the tenant the request is being evaluated under.
    if let Some(token_tenant) = claims.tenant_id()
        && token_tenant != tenant_id
    {
        return Err(ZtnaError::TokenRejected {
            reason: format!(
                "token tenant {token_tenant:?} does not match request tenant {tenant_id:?}"
            ),
        });
    }

    let sub = claims.sub.trim();
    if sub.is_empty() {
        return Err(ZtnaError::TokenRejected {
            reason: "token sub claim is empty".to_owned(),
        });
    }

    let mfa_at_ms = if claims.mfa_satisfied() {
        claims
            .iat
            .and_then(|secs| u64::try_from(secs).ok())
            .map_or(0, |secs| secs.saturating_mul(1_000))
    } else {
        0
    };

    let groups: HashSet<String> = claims
        .groups
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .map(str::to_owned)
        .collect();

    Ok(UserIdentity {
        user_id: sub.to_owned(),
        tenant_id: tenant_id.to_owned(),
        groups,
        mfa_at_ms,
        tags: HashMap::new(),
    })
}

/// Resolves OIDC ID tokens into [`UserIdentity`] records, tenant by
/// tenant, against per-tenant IdP configurations.
///
/// The configuration table is held behind an [`ArcSwap`] so the
/// control-plane sync task can replace the whole set atomically (new
/// tenant onboarded, client id rotated, issuer changed) without
/// blocking in-flight token validations. The [`JwksClient`] is shared
/// and internally TTL-caches each provider's key set, so steady-state
/// validation does not hit the network.
#[derive(Debug)]
pub struct OidcIdentityResolver {
    configs: ArcSwap<HashMap<String, TenantIdpConfig>>,
    jwks: Arc<JwksClient>,
    leeway_secs: u64,
}

impl OidcIdentityResolver {
    /// Build a resolver from an initial set of per-tenant configs and a
    /// shared JWKS client. Uses [`IdTokenValidator::DEFAULT_LEEWAY_SECS`]
    /// for `exp`/`iat` clock-skew tolerance.
    #[must_use]
    pub fn new(configs: Vec<TenantIdpConfig>, jwks: Arc<JwksClient>) -> Self {
        Self {
            configs: ArcSwap::new(Arc::new(index_configs(configs))),
            jwks,
            leeway_secs: IdTokenValidator::DEFAULT_LEEWAY_SECS,
        }
    }

    /// Override the `exp`/`iat` clock-skew leeway (seconds).
    #[must_use]
    pub fn with_leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }

    /// Atomically replace the per-tenant configuration table.
    pub fn replace_configs(&self, configs: Vec<TenantIdpConfig>) {
        self.configs.store(Arc::new(index_configs(configs)));
    }

    /// Look up the IdP configuration registered for `tenant_id`.
    #[must_use]
    pub fn config_for(&self, tenant_id: &str) -> Option<TenantIdpConfig> {
        self.configs.load().get(tenant_id).cloned()
    }

    /// Validate `token` for `tenant_id` and resolve it to a
    /// [`UserIdentity`].
    ///
    /// The token is validated against the tenant's registered provider
    /// (signature via JWKS, `iss`/`aud`/`exp`/`iat` per OIDC Core), then
    /// projected onto a tenant-scoped identity. Any validation failure
    /// maps to [`ZtnaError::TokenRejected`]; an unregistered tenant maps
    /// to [`ZtnaError::IdpConfigNotFound`].
    pub async fn resolve(&self, tenant_id: &str, token: &str) -> Result<UserIdentity, ZtnaError> {
        let cfg = self
            .config_for(tenant_id)
            .ok_or_else(|| ZtnaError::IdpConfigNotFound {
                tenant_id: tenant_id.to_owned(),
            })?;

        let validator = IdTokenValidator::new(cfg.issuer.clone(), cfg.audience.clone())
            .with_leeway_secs(self.leeway_secs);

        let claims = validator
            .validate(token, &self.jwks, &cfg.jwks_uri)
            .await
            .map_err(|e| ZtnaError::TokenRejected {
                reason: e.to_string(),
            })?;

        identity_from_claims(&claims, tenant_id)
    }
}

fn index_configs(configs: Vec<TenantIdpConfig>) -> HashMap<String, TenantIdpConfig> {
    configs
        .into_iter()
        .map(|c| (c.tenant_id.clone(), c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // Deserialize claims from JSON so the test exercises the same
    // shape the validator produces (only `Deserialize` is derived on
    // `IdTokenClaims`).
    fn claims(json: serde_json::Value) -> IdTokenClaims {
        serde_json::from_value(json).expect("valid claims fixture")
    }

    #[test]
    fn projects_sub_and_groups_onto_identity() {
        let c = claims(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-123",
            "aud": ["client-abc"],
            "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64,
            "tenant_id": "tenant-a",
            "groups": ["eng", "admins", " "],
            "amr": ["pwd", "otp"],
        }));

        let identity = identity_from_claims(&c, "tenant-a").expect("identity");
        assert_eq!(identity.user_id, "user-123");
        assert_eq!(identity.tenant_id, "tenant-a");
        assert_eq!(
            identity.groups,
            ["eng", "admins"].iter().map(|s| (*s).to_owned()).collect()
        );
        // amr carries `otp` → MFA satisfied → mfa_at_ms = iat * 1000.
        assert_eq!(identity.mfa_at_ms, 1_700_000_000_000);
    }

    #[test]
    fn non_mfa_token_has_zero_mfa_freshness() {
        let c = claims(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-123",
            "aud": ["client-abc"],
            "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64,
            "groups": ["eng"],
            "amr": ["pwd"],
        }));
        let identity = identity_from_claims(&c, "tenant-a").expect("identity");
        assert_eq!(identity.mfa_at_ms, 0);
    }

    #[test]
    fn rejects_cross_tenant_token() {
        let c = claims(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-123",
            "aud": ["client-abc"],
            "exp": 9_999_999_999i64,
            "tenant_id": "tenant-b",
            "groups": [],
        }));
        let err = identity_from_claims(&c, "tenant-a").expect_err("must reject");
        assert!(matches!(err, ZtnaError::TokenRejected { .. }));
    }

    #[test]
    fn token_without_tenant_claim_binds_to_request_tenant() {
        // A provider that does not emit `tenant_id` (e.g. raw Okta)
        // resolves under the request's tenant — isolation still holds
        // because the validator was selected by that tenant's config.
        let c = claims(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-xyz",
            "aud": ["client-abc"],
            "exp": 9_999_999_999i64,
            "groups": ["sales"],
        }));
        let identity = identity_from_claims(&c, "tenant-a").expect("identity");
        assert_eq!(identity.tenant_id, "tenant-a");
        assert_eq!(identity.user_id, "user-xyz");
    }

    #[test]
    fn rejects_empty_sub() {
        let c = claims(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "   ",
            "aud": ["client-abc"],
            "exp": 9_999_999_999i64,
            "groups": [],
        }));
        let err = identity_from_claims(&c, "tenant-a").expect_err("must reject");
        assert!(matches!(err, ZtnaError::TokenRejected { .. }));
    }

    #[test]
    fn resolve_reports_missing_tenant_config() {
        let resolver = OidcIdentityResolver::new(
            vec![TenantIdpConfig {
                tenant_id: "tenant-a".into(),
                issuer: "https://idp.example.com".into(),
                audience: "client-abc".into(),
                jwks_uri: "https://idp.example.com/jwks".into(),
            }],
            Arc::new(JwksClient::new().expect("jwks client")),
        );
        assert!(resolver.config_for("tenant-a").is_some());
        assert!(resolver.config_for("tenant-z").is_none());
    }
}
