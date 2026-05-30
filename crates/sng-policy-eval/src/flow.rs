//! `Flow` — the per-evaluation input to [`crate::engine::PolicyEngine::evaluate`].
//!
//! A `Flow` is a borrowed snapshot of one packet / connection /
//! DNS query as seen by the local enforcement subsystem. Every
//! field is optional so the engine can be exercised from very
//! different call sites (the DNS resolver may only have the
//! query name + source IP; the SWG has the full L7 picture). The
//! lifetimes are tied to the caller so no per-flow allocation is
//! incurred — the hot path takes a `&Flow` and never moves data
//! out of the borrowed strings.

use crate::rule::EnforcementDomain;
use std::net::IpAddr;

/// One flow snapshot. Construct via [`FlowBuilder`] (preferred) or
/// directly when the call site already has typed fields on hand.
///
/// The engine treats absent fields as "no information" — a rule
/// whose subject requires a `user` against a `Flow` with no
/// `user` is non-matching (the safe baseline: omitted facts
/// do not silently authorise).
#[derive(Clone, Copy, Debug, Default)]
pub struct Flow<'a> {
    /// Which enforcement subsystem is asking. Rules whose
    /// [`crate::rule::Rule::domain`] does not match are skipped.
    pub enforcement_domain: EnforcementDomain,
    /// Authenticated user principal (mTLS / SSO claim subject).
    pub user: Option<&'a str>,
    /// Device identifier (device-bound mTLS subject).
    pub device: Option<&'a str>,
    /// App identifier from the app catalog (after steering
    /// classification has run).
    pub app: Option<&'a str>,
    /// Site identifier (the originating branch / location).
    pub site: Option<&'a str>,
    /// Source IP of the flow.
    pub source_ip: Option<IpAddr>,
    /// Destination hostname (DNS name) — set by the resolver /
    /// SNI extractor / Host-header parser depending on
    /// subsystem.
    pub destination_host: Option<&'a str>,
    /// Destination IP of the flow.
    pub destination_ip: Option<IpAddr>,
    /// Destination TCP/UDP port.
    pub destination_port: Option<u16>,
    /// Free-form context key/value pairs used by predicate
    /// matchers (e.g. URL category, time-of-day window, geo).
    /// Borrowed slice; caller stack-allocates per flow.
    pub context: &'a [(&'a str, &'a str)],
}

impl Default for EnforcementDomain {
    /// Default enforcement domain is NGFW — the most general
    /// (L3/L4) surface. Callers in DNS / SWG / etc. always set
    /// this explicitly; the default is only used by
    /// [`Flow::default`] for test convenience.
    fn default() -> Self {
        Self::Ngfw
    }
}

/// Builder for [`Flow`] — most call sites only have two or three
/// fields on hand and the builder pattern is more ergonomic than
/// struct-update syntax with a bunch of `None`s.
#[derive(Debug, Default)]
pub struct FlowBuilder<'a> {
    flow: Flow<'a>,
}

impl<'a> FlowBuilder<'a> {
    /// Start a new builder for the given enforcement domain.
    #[must_use]
    pub fn new(enforcement_domain: EnforcementDomain) -> Self {
        Self {
            flow: Flow {
                enforcement_domain,
                ..Flow::default()
            },
        }
    }

    /// Set the user principal.
    #[must_use]
    pub fn user(mut self, user: &'a str) -> Self {
        self.flow.user = Some(user);
        self
    }

    /// Set the device identifier.
    #[must_use]
    pub fn device(mut self, device: &'a str) -> Self {
        self.flow.device = Some(device);
        self
    }

    /// Set the app identifier.
    #[must_use]
    pub fn app(mut self, app: &'a str) -> Self {
        self.flow.app = Some(app);
        self
    }

    /// Set the site identifier.
    #[must_use]
    pub fn site(mut self, site: &'a str) -> Self {
        self.flow.site = Some(site);
        self
    }

    /// Set the source IP.
    #[must_use]
    pub fn source_ip(mut self, addr: IpAddr) -> Self {
        self.flow.source_ip = Some(addr);
        self
    }

    /// Set the destination hostname.
    #[must_use]
    pub fn destination_host(mut self, host: &'a str) -> Self {
        self.flow.destination_host = Some(host);
        self
    }

    /// Set the destination IP.
    #[must_use]
    pub fn destination_ip(mut self, addr: IpAddr) -> Self {
        self.flow.destination_ip = Some(addr);
        self
    }

    /// Set the destination port.
    #[must_use]
    pub fn destination_port(mut self, port: u16) -> Self {
        self.flow.destination_port = Some(port);
        self
    }

    /// Attach a context slice for predicate matchers.
    #[must_use]
    pub fn context(mut self, context: &'a [(&'a str, &'a str)]) -> Self {
        self.flow.context = context;
        self
    }

    /// Finalise the flow snapshot.
    #[must_use]
    pub fn build(self) -> Flow<'a> {
        self.flow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn flow_default_uses_ngfw_domain() {
        let f = Flow::default();
        assert_eq!(f.enforcement_domain, EnforcementDomain::Ngfw);
        assert!(f.user.is_none());
        assert!(f.context.is_empty());
    }

    #[test]
    fn flow_builder_sets_all_fields() {
        let ctx: &[(&str, &str)] = &[("category", "malware")];
        let f = FlowBuilder::new(EnforcementDomain::Swg)
            .user("alice")
            .device("dev-1")
            .app("app-1")
            .site("hq")
            .source_ip("10.0.0.1".parse().unwrap())
            .destination_host("evil.example.com")
            .destination_ip("1.2.3.4".parse().unwrap())
            .destination_port(443)
            .context(ctx)
            .build();
        assert_eq!(f.enforcement_domain, EnforcementDomain::Swg);
        assert_eq!(f.user, Some("alice"));
        assert_eq!(f.device, Some("dev-1"));
        assert_eq!(f.app, Some("app-1"));
        assert_eq!(f.site, Some("hq"));
        assert_eq!(f.source_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(f.destination_host, Some("evil.example.com"));
        assert_eq!(f.destination_ip, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(f.destination_port, Some(443));
        assert_eq!(f.context.len(), 1);
    }
}
