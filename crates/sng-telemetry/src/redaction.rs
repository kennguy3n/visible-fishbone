//! Metadata-first redaction of telemetry events.
//!
//! The pipeline must obey the **redaction invariant** described
//! in `ARCHITECTURE.md` §4.8: every event leaving the agent
//! carries enough metadata (5-tuple, verdict, counters, identity
//! binding) for the control-plane to correlate, but the actual
//! payload bytes (DNS answer section, HTTP body bytes, posture
//! JSON, etc.) are stripped UNLESS the active policy explicitly
//! opts in for that event class.
//!
//! Concretely, [`RedactionPolicy::redact`] is the only call site
//! that mutates a [`TelemetryEvent`] before it is encoded onto
//! the wire. The redactor strips per-class fields that carry
//! end-user-visible content while leaving the metadata that
//! makes the event useful for security analytics intact.

use sng_core::events::{AgentEvent, DnsEvent, HttpEvent};

use crate::source::TelemetryEvent;

/// Policy controlling per-class payload retention.
///
/// The default ([`Self::strict`]) strips every payload field
/// that could leak user-visible content. Operators who run the
/// agent with the explicit "payload retention" feature toggled
/// on for a given class may construct a relaxed policy via
/// [`Self::allow`].
// Allow more-than-three bools here: each flag toggles an
// independent per-class retention decision and the operator-
// facing API is clearer when the field names spell out what is
// being kept than when the bits are packed into a flag enum.
// The struct is small (4 bytes) and infrequently constructed, so
// the layout overhead a bitflags refactor would save is not
// worth the readability hit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionPolicy {
    /// Retain `DnsEvent.upstream` — the resolver the agent
    /// dialled. Off by default because it can identify the
    /// user's split-horizon configuration.
    pub keep_dns_upstream: bool,
    /// Retain `HttpEvent.url` (the full URL path + query
    /// string). Off by default — query strings frequently carry
    /// session tokens, search terms, and other user-visible
    /// content. The `host` field is always retained (it is the
    /// minimum metadata required for security analytics).
    pub keep_http_url: bool,
    /// Retain `HttpEvent.sni`. Off by default — SNI is the
    /// hostname the client requested over TLS, which is in
    /// principle the same as the `host` field but for proxied
    /// requests can leak the underlying destination.
    pub keep_http_sni: bool,
    /// Retain `AgentEvent.posture_snapshot`. Off by default —
    /// posture snapshots include device-identifying details
    /// (hostname, MAC, installed software). The
    /// `event_type` field is always retained.
    pub keep_agent_posture: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl RedactionPolicy {
    /// Strict policy — every payload field that could leak
    /// user-visible content is stripped. This is the default.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            keep_dns_upstream: false,
            keep_http_url: false,
            keep_http_sni: false,
            keep_agent_posture: false,
        }
    }

    /// Permissive policy — every payload field is retained.
    /// Use only in environments where the operator has
    /// explicitly opted in (typically a private deployment
    /// where the control plane is operated by the same legal
    /// entity as the endpoints).
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            keep_dns_upstream: true,
            keep_http_url: true,
            keep_http_sni: true,
            keep_agent_posture: true,
        }
    }

    /// Apply the policy to the event in place. Fields disabled
    /// by the policy are replaced with their "absent" wire form
    /// (typically `None` or an empty string), matching the
    /// `omitempty` semantics of the Go schema so a redacted
    /// event encodes to the same wire shape as one whose
    /// producer never recorded the value in the first place.
    pub fn redact(&self, event: &mut TelemetryEvent) {
        match event {
            TelemetryEvent::Dns(e) => self.redact_dns(e),
            TelemetryEvent::Http(e) => self.redact_http(e),
            TelemetryEvent::Agent(e) => self.redact_agent(e),
            // Flow / IPS / ZTNA / SDWAN / System / DLP events do
            // not carry user-visible payload fields — only metadata
            // (5-tuple, verdict, counters, decision, restart
            // cause). They pass through unchanged. In particular
            // a System (subsystem-restart) event is appliance
            // telemetry with no tenant/user PII to strip, and a DLP
            // event is redacted at the source by construction (the
            // AI-app signal aggregates matches into label/count
            // summaries and never carries the matched bytes), so
            // there is nothing left to strip here.
            TelemetryEvent::Flow(_)
            | TelemetryEvent::Ips(_)
            | TelemetryEvent::Ztna(_)
            | TelemetryEvent::Sdwan(_)
            | TelemetryEvent::System(_)
            | TelemetryEvent::Dlp(_) => {}
        }
    }

    fn redact_dns(&self, e: &mut DnsEvent) {
        if !self.keep_dns_upstream {
            e.upstream = None;
        }
    }

    fn redact_http(&self, e: &mut HttpEvent) {
        if !self.keep_http_url {
            // The host is metadata (kept). The url is
            // user-visible content (stripped → empty string).
            // We deliberately do not strip method, status,
            // content_type, tls_version, or bytes — those are
            // metadata fields used by every SOC report.
            e.url.clear();
        }
        if !self.keep_http_sni {
            e.sni = None;
        }
    }

    fn redact_agent(&self, e: &mut AgentEvent) {
        if !self.keep_agent_posture {
            e.posture_snapshot = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::{Platform, Verdict};
    use sng_core::events::{AgentEvent, DnsEvent, FlowEvent, HttpEvent};

    fn http() -> TelemetryEvent {
        TelemetryEvent::Http(HttpEvent {
            method: "GET".into(),
            url: "https://example.com/secret?token=abcd".into(),
            host: "example.com".into(),
            status_code: 200,
            verdict: Verdict::Allow,
            tls_version: Some("TLS1.3".into()),
            sni: Some("example.com".into()),
            content_type: Some("text/html".into()),
            bytes: Some(1_024),
        })
    }

    fn dns() -> TelemetryEvent {
        TelemetryEvent::Dns(DnsEvent {
            query: "example.com".into(),
            qtype: "A".into(),
            response_code: "NOERROR".into(),
            verdict: Verdict::Allow,
            latency_ms: 5,
            upstream: Some("1.1.1.1".into()),
        })
    }

    fn agent_with_posture() -> TelemetryEvent {
        TelemetryEvent::Agent(AgentEvent {
            device_id: "d1".into(),
            event_type: "posture".into(),
            posture_snapshot: Some(serde_json::json!({"os": "linux"})),
            reason: String::new(),
            platform: Platform::Linux,
        })
    }

    fn flow() -> TelemetryEvent {
        TelemetryEvent::Flow(FlowEvent {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 51_234,
            dst_port: 443,
            protocol: "tcp".into(),
            app_id: None,
            verdict: Verdict::Allow,
            score: None,
            bytes_in: 1_024,
            bytes_out: 2_048,
            duration_ms: 100,
        })
    }

    #[test]
    fn default_is_strict() {
        assert_eq!(RedactionPolicy::default(), RedactionPolicy::strict());
    }

    #[test]
    fn strict_strips_http_url_and_sni_keeps_metadata() {
        let p = RedactionPolicy::strict();
        let mut ev = http();
        p.redact(&mut ev);
        match ev {
            TelemetryEvent::Http(e) => {
                assert_eq!(e.url, ""); // stripped
                assert_eq!(e.sni, None); // stripped
                // Metadata kept:
                assert_eq!(e.method, "GET");
                assert_eq!(e.host, "example.com");
                assert_eq!(e.status_code, 200);
                assert_eq!(e.tls_version, Some("TLS1.3".into()));
                assert_eq!(e.bytes, Some(1_024));
                assert_eq!(e.content_type, Some("text/html".into()));
            }
            _ => panic!("event class changed"),
        }
    }

    #[test]
    fn strict_strips_dns_upstream() {
        let p = RedactionPolicy::strict();
        let mut ev = dns();
        p.redact(&mut ev);
        match ev {
            TelemetryEvent::Dns(e) => {
                assert_eq!(e.upstream, None);
                // Query name is metadata for filter analytics and
                // is NOT stripped by the default policy. Operators
                // who want full anonymisation of query names need
                // a separate hashing layer (out of scope here).
                assert_eq!(e.query, "example.com");
            }
            _ => panic!("event class changed"),
        }
    }

    #[test]
    fn strict_strips_agent_posture() {
        let p = RedactionPolicy::strict();
        let mut ev = agent_with_posture();
        p.redact(&mut ev);
        match ev {
            TelemetryEvent::Agent(e) => {
                assert!(e.posture_snapshot.is_none());
                assert_eq!(e.event_type, "posture");
                assert_eq!(e.device_id, "d1");
            }
            _ => panic!("event class changed"),
        }
    }

    #[test]
    fn allow_keeps_every_field() {
        let p = RedactionPolicy::allow();
        let mut ev = http();
        p.redact(&mut ev);
        match ev {
            TelemetryEvent::Http(e) => {
                assert_eq!(e.url, "https://example.com/secret?token=abcd");
                assert_eq!(e.sni, Some("example.com".into()));
            }
            _ => panic!("event class changed"),
        }
        let mut ev = dns();
        p.redact(&mut ev);
        match ev {
            TelemetryEvent::Dns(e) => {
                assert_eq!(e.upstream, Some("1.1.1.1".into()));
            }
            _ => panic!("event class changed"),
        }
    }

    #[test]
    fn flow_event_unchanged_by_strict_policy() {
        // Flow events have no payload field — only metadata.
        // Strict redaction must be a no-op for them.
        let p = RedactionPolicy::strict();
        let original = flow();
        let mut ev = original.clone();
        p.redact(&mut ev);
        assert_eq!(ev, original);
    }
}
