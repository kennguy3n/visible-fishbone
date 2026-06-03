//! Built-in provider profiles.
//!
//! Each [`Provider`] encodes the two things that differ between
//! IdPs but are otherwise mechanical: the discovery-document URL
//! and the provider's scope / domain-restriction quirks. The rest
//! of the flow (PKCE, authorize-URL shape, token exchange,
//! ID-token validation) is identical across providers and lives
//! in the other modules.

use std::fmt;

use url::Url;

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
            Self::Microsoft365 { tenant } => microsoft_discovery_url(tenant),
            Self::Zoho => "https://accounts.zoho.com/.well-known/openid-configuration".to_owned(),
            Self::Okta { domain } => okta_discovery_url(domain),
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

/// Build the Microsoft 365 per-tenant discovery URL.
///
/// `tenant` is admin-configured, but we still build the URL through
/// the `url` crate so the value is percent-encoded as a *single*
/// path segment: a tenant containing `/`, `?`, or `#` (e.g.
/// `"x?evil=1#"`) cannot break out of the path and re-point the
/// discovery request. The `Err` arms are unreachable for the
/// constant base; the raw `format!` fallback preserves the previous
/// behaviour rather than panicking (no `unwrap`/`expect`).
fn microsoft_discovery_url(tenant: &str) -> String {
    let raw = || {
        format!("https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration")
    };
    let Ok(mut url) = Url::parse("https://login.microsoftonline.com/") else {
        return raw();
    };
    {
        // Scope the mutable borrow so it ends before `to_string`.
        let Ok(mut segments) = url.path_segments_mut() else {
            return raw();
        };
        segments.extend([tenant, "v2.0", ".well-known", "openid-configuration"]);
    }
    url.to_string()
}

/// Build the Okta per-org discovery URL.
///
/// `domain` lands in the host position, so we set it via
/// [`Url::set_host`], which validates it as a real host and rejects
/// a value carrying a path / `?` / `#`. The documented contract is a
/// *bare* org domain, so we also reject any `:` up front: depending
/// on the `url` version, `set_host` either silently drops a
/// `host:port` suffix or honours it as a port, and neither is what
/// the caller asked for — rejecting `:` is deterministic across
/// versions and keeps a port out of the discovery authority. On
/// rejection the URL keeps its unreachable `.invalid` placeholder
/// host — so discovery can never be re-pointed at an attacker- /
/// misconfig-influenced authority — and the downstream
/// `DiscoveryClient` then fails cleanly. We never panic.
fn okta_discovery_url(domain: &str) -> String {
    const PLACEHOLDER: &str = "https://placeholder.invalid/.well-known/openid-configuration";
    if domain.contains(':') {
        return PLACEHOLDER.to_owned();
    }
    match Url::parse(PLACEHOLDER) {
        Ok(mut url) => {
            if url.set_host(Some(domain)).is_ok() && url.port().is_none() {
                url.to_string()
            } else {
                PLACEHOLDER.to_owned()
            }
        }
        Err(_) => format!("https://{domain}/.well-known/openid-configuration"),
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

    #[test]
    fn microsoft_tenant_cannot_break_out_of_path() {
        // `?` / `#` / `/` in the tenant must be percent-encoded so
        // the discovery path stays `…/{tenant}/v2.0/.well-known/…`
        // and is not turned into a query, fragment, or extra
        // segments that re-point the request.
        let p = Provider::Microsoft365 {
            tenant: "x?evil=1#frag/extra".to_owned(),
        };
        let url = p.discovery_url();
        let parsed = Url::parse(&url).expect("discovery url parses");
        assert_eq!(parsed.host_str(), Some("login.microsoftonline.com"));
        assert!(parsed.query().is_none());
        assert!(parsed.fragment().is_none());
        assert!(
            url.ends_with("/v2.0/.well-known/openid-configuration"),
            "unexpected discovery url: {url}"
        );
    }

    #[test]
    fn okta_domain_injection_does_not_change_host() {
        // A domain carrying a path can't smuggle the well-known
        // path onto an attacker-chosen host.
        let p = Provider::Okta {
            domain: "evil.example.com/legit.okta.com".to_owned(),
        };
        let url = p.discovery_url();
        if let Ok(parsed) = Url::parse(&url) {
            assert_ne!(parsed.host_str(), Some("evil.example.com"));
        }
    }

    #[test]
    fn okta_domain_with_port_is_rejected() {
        // `set_host` accepts `host:port`; a domain carrying a port
        // must not produce a discovery URL pointing at that port.
        let p = Provider::Okta {
            domain: "dev-12345.okta.com:9999".to_owned(),
        };
        let url = p.discovery_url();
        let parsed = Url::parse(&url).expect("discovery url parses");
        assert!(parsed.port().is_none(), "unexpected port in {url}");
        assert_ne!(parsed.host_str(), Some("dev-12345.okta.com"));
    }
}
