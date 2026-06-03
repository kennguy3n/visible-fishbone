//! Built-in provider profiles.
//!
//! Each [`Provider`] encodes the two things that differ between
//! IdPs but are otherwise mechanical: the discovery-document URL
//! and the provider's scope / domain-restriction quirks. The rest
//! of the flow (PKCE, authorize-URL shape, token exchange,
//! ID-token validation) is identical across providers and lives
//! in the other modules.

use std::fmt;

/// A known OpenID Connect provider.
///
/// `Microsoft365` and `Okta` are parameterised by the tenant /
/// org domain because their discovery URL is per-tenant. Google
/// and Zoho expose a single global discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provider {
    /// Google Workspace. Domain restriction is expressed with the
    /// `hd` (hosted domain) authorization parameter.
    GoogleWorkspace,
    /// Microsoft 365 / Entra ID. The discovery document is
    /// per-tenant (`{tenant}` may be a tenant GUID, a verified
    /// domain, or `organizations` / `common`). Domain restriction
    /// is expressed with the `domain_hint` parameter.
    Microsoft365 {
        /// The tenant segment of the v2.0 endpoint.
        tenant: String,
    },
    /// Zoho Directory.
    Zoho,
    /// Okta. The discovery document lives under the org domain
    /// (e.g. `dev-12345.okta.com`).
    Okta {
        /// The Okta org domain (no scheme, no trailing slash).
        domain: String,
    },
}

impl Provider {
    /// The fully-qualified OpenID Connect discovery URL
    /// (`…/.well-known/openid-configuration`).
    #[must_use]
    pub fn discovery_url(&self) -> String {
        match self {
            Self::GoogleWorkspace => {
                "https://accounts.google.com/.well-known/openid-configuration".to_owned()
            }
            Self::Microsoft365 { tenant } => format!(
                "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
            ),
            Self::Zoho => "https://accounts.zoho.com/.well-known/openid-configuration".to_owned(),
            Self::Okta { domain } => {
                format!("https://{domain}/.well-known/openid-configuration")
            }
        }
    }

    /// The recommended default scope string for this provider.
    ///
    /// All profiles request the `openid email profile` baseline;
    /// providers that issue refresh tokens only when explicitly
    /// asked add `offline_access`, and Zoho additionally needs its
    /// proprietary `AaaServer.profile.READ` scope to return a
    /// profile.
    #[must_use]
    pub fn default_scope(&self) -> &'static str {
        match self {
            Self::GoogleWorkspace => "openid email profile",
            Self::Microsoft365 { .. } | Self::Okta { .. } => "openid email profile offline_access",
            Self::Zoho => "openid email profile AaaServer.profile.READ",
        }
    }

    /// The authorization-request parameter this provider uses to
    /// restrict sign-in to a specific organization domain, if any.
    ///
    /// Returns `("hd", _)` for Google and `("domain_hint", _)` for
    /// Microsoft; Zoho and Okta have no equivalent single-param
    /// restriction, so they return [`None`] and a caller that
    /// wants tenant pinning should instead use a tenant-scoped
    /// discovery URL (Okta) or a tenant-scoped endpoint
    /// (Microsoft).
    #[must_use]
    pub fn domain_restriction_param(&self) -> Option<&'static str> {
        match self {
            Self::GoogleWorkspace => Some("hd"),
            Self::Microsoft365 { .. } => Some("domain_hint"),
            Self::Zoho | Self::Okta { .. } => None,
        }
    }

    /// A short, stable, lower-case label for logs / metrics.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::GoogleWorkspace => "google_workspace",
            Self::Microsoft365 { .. } => "microsoft_365",
            Self::Zoho => "zoho",
            Self::Okta { .. } => "okta",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn google_profile() {
        let p = Provider::GoogleWorkspace;
        assert_eq!(
            p.discovery_url(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
        assert_eq!(p.default_scope(), "openid email profile");
        assert_eq!(p.domain_restriction_param(), Some("hd"));
        assert_eq!(p.label(), "google_workspace");
    }

    #[test]
    fn microsoft_profile_is_per_tenant() {
        let p = Provider::Microsoft365 {
            tenant: "contoso.onmicrosoft.com".to_owned(),
        };
        assert_eq!(
            p.discovery_url(),
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration"
        );
        assert!(p.default_scope().contains("offline_access"));
        assert_eq!(p.domain_restriction_param(), Some("domain_hint"));
    }

    #[test]
    fn zoho_profile_requests_proprietary_scope() {
        let p = Provider::Zoho;
        assert!(p.default_scope().contains("AaaServer.profile.READ"));
        assert_eq!(p.domain_restriction_param(), None);
    }

    #[test]
    fn okta_profile_is_per_domain() {
        let p = Provider::Okta {
            domain: "dev-12345.okta.com".to_owned(),
        };
        assert_eq!(
            p.discovery_url(),
            "https://dev-12345.okta.com/.well-known/openid-configuration"
        );
        assert_eq!(p.domain_restriction_param(), None);
    }
}
