//! Application-identity enrichment for L7 verdicts.
//!
//! The legacy [`AppIdentifier`](crate::l7::AppIdentifier) recognises a
//! *closed set* of seven wire protocols (HTTP, TLS, DNS, QUIC, SSH,
//! RDP, SMB). That answers "what protocol is this?" but not "what
//! application is this?" — every HTTPS flow is just `tls`.
//!
//! This module layers a **data-driven** application identity on top,
//! without changing the protocol verdict. It feeds the features the
//! firewall already extracts on the first packet (the wire protocol,
//! the TLS SNI, the leading bytes, the port / transport) into the
//! signed, versioned [`sng_appid`] catalog and returns a best-match
//! `{app_id, category, confidence}` when one is found.
//!
//! Enrichment is **purely additive**: [`L7Enrichment::protocol`] is
//! exactly what `AppIdentifier::identify` would have returned, so
//! existing protocol-based policy keeps working unchanged; the
//! optional [`L7Enrichment::app`] is new signal the SWG / IPS / policy
//! layers may use when present and ignore when absent.
//!
//! ## Cost
//! One enrichment performs: the existing constant-time protocol probe,
//! at most one SNI parse (only for TLS), and one bounded catalog
//! lookup (hash + longest-suffix walk, capped label count, no regex /
//! no backtracking — see [`sng_appid::Matcher`]). No per-call heap
//! allocation beyond an owned copy of the matched `app_id` / category
//! strings in the returned value. Safe to call on the data path for
//! every inspected first packet across 5,000 tenants.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use sng_appid::{AppMatch, ConnFeatures, Matcher, Transport};

use crate::l7::{AppIdentifier, L7Protocol, SniExtractor};

/// The enriched first-packet L7 verdict: the legacy closed-set
/// protocol plus an optional data-driven application identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Enrichment {
    /// Wire protocol from the legacy closed-set identifier. Always
    /// present (falls back to [`L7Protocol::Unknown`]).
    pub protocol: L7Protocol,
    /// TLS SNI host, when the flow is TLS and a ClientHello SNI was
    /// parsed. Surfaced so callers can log / policy on the raw host
    /// even when no catalog entry matched.
    pub sni: Option<String>,
    /// Best-match application identity from the catalog, when one
    /// scored above zero confidence. `None` means "no app matched",
    /// never an error.
    pub app: Option<AppMatch>,
}

impl L7Enrichment {
    /// Convenience: the matched `app_id`, if any.
    #[must_use]
    pub fn app_id(&self) -> Option<&str> {
        self.app.as_ref().map(|a| a.app_id.as_str())
    }
}

/// Stateless enricher. Holds a shared, pre-compiled [`Matcher`]; the
/// protocol / SNI extractors are zero-sized so they are created on
/// demand. Cheap to clone (the matcher is behind an [`Arc`]);
/// construct once per engine and reuse across every flow.
#[derive(Clone, Debug)]
pub struct AppIdEnricher {
    matcher: Arc<Matcher>,
}

impl AppIdEnricher {
    /// Build an enricher backed by the embedded baseline catalog.
    #[must_use]
    pub fn builtin() -> Self {
        // `Matcher::builtin()` is a process-wide singleton; wrap a
        // clone in an `Arc` so this type has one uniform ownership
        // story whether it is using the baseline or a pushed bundle.
        Self::from_matcher(Arc::new(Matcher::builtin().clone()))
    }

    /// Build an enricher backed by a specific (e.g. control-plane
    /// pushed) matcher.
    #[must_use]
    pub fn from_matcher(matcher: Arc<Matcher>) -> Self {
        Self { matcher }
    }

    /// Number of applications in the backing catalog.
    #[must_use]
    pub fn catalog_len(&self) -> usize {
        self.matcher.len()
    }

    /// Identify the protocol of `payload` and enrich it with an
    /// application identity. `port` / `transport` are the flow's
    /// L4 hints (used only to nudge confidence, never to disqualify a
    /// content match). Never panics, never allocates unboundedly.
    #[must_use]
    pub fn enrich(
        &self,
        payload: &[u8],
        port: Option<u16>,
        transport: Option<Transport>,
    ) -> L7Enrichment {
        let protocol = AppIdentifier::new().identify(payload);

        // Only attempt SNI extraction for TLS — parsing a non-TLS
        // payload as a ClientHello is wasted work and the extractor
        // would just error. Both extractors are zero-sized unit
        // structs, so constructing them here is free.
        let sni = if protocol == L7Protocol::Tls {
            SniExtractor::new().extract(payload).ok().flatten()
        } else {
            None
        };

        let feat = ConnFeatures {
            sni: sni.as_deref(),
            ja3: None,
            // The legacy first-packet path does not parse the HTTP
            // Host header; SNI + byte-probes carry identification
            // today. `host` is wired through so a future HTTP host
            // extractor can enrich plaintext flows with no change
            // here.
            host: None,
            first_bytes: Some(payload),
            port,
            transport,
        };
        let app = self.matcher.identify(&feat);

        L7Enrichment { protocol, sni, app }
    }
}

impl Default for AppIdEnricher {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Minimal TLS 1.2 ClientHello carrying a single SNI extension.
    /// Mirrors the helper in `l7.rs` tests; duplicated here because
    /// that one is private to its module.
    fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
        let mut hello = Vec::<u8>::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]);
        hello.extend_from_slice(&[0x01, 0x00]);
        let ext_offset = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let ext_start = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let sni_len_offset = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let sni_data_start = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.push(0x00);
        let name_bytes = host.as_bytes();
        hello.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(name_bytes);
        let sni_data_end = hello.len();
        let server_name_list_len = (sni_data_end - sni_data_start - 2) as u16;
        let b = server_name_list_len.to_be_bytes();
        hello[sni_data_start] = b[0];
        hello[sni_data_start + 1] = b[1];
        let sni_total_len = (sni_data_end - sni_data_start) as u16;
        let b = sni_total_len.to_be_bytes();
        hello[sni_len_offset] = b[0];
        hello[sni_len_offset + 1] = b[1];
        let ext_total = (hello.len() - ext_start) as u16;
        let b = ext_total.to_be_bytes();
        hello[ext_offset] = b[0];
        hello[ext_offset + 1] = b[1];
        let hs_len = hello.len() as u32;
        let mut handshake = Vec::<u8>::with_capacity(4 + hello.len());
        handshake.push(0x01);
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&hello);
        let mut record = Vec::<u8>::with_capacity(5 + handshake.len());
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn enriches_tls_with_app_identity() {
        let e = AppIdEnricher::builtin();
        let payload = tls_client_hello_with_sni("teams.microsoft.com");
        let out = e.enrich(&payload, Some(443), Some(Transport::Tcp));
        // Legacy protocol verdict is preserved.
        assert_eq!(out.protocol, L7Protocol::Tls);
        assert_eq!(out.sni.as_deref(), Some("teams.microsoft.com"));
        // New enrichment identifies the application.
        let app = out.app.expect("app identified");
        assert_eq!(app.app_id, "microsoft.teams");
        assert_eq!(app.category, "collaboration");
        assert!(app.confidence >= 90);
    }

    #[test]
    fn enriches_tls_subdomain_via_suffix() {
        let e = AppIdEnricher::builtin();
        let payload = tls_client_hello_with_sni("edge.files.slack.com");
        let out = e.enrich(&payload, Some(443), Some(Transport::Tcp));
        assert_eq!(out.protocol, L7Protocol::Tls);
        assert_eq!(out.app_id(), Some("slack"));
    }

    #[test]
    fn enriches_ssh_via_byte_probe() {
        let e = AppIdEnricher::builtin();
        let out = e.enrich(b"SSH-2.0-OpenSSH_9.6\r\n", Some(22), Some(Transport::Tcp));
        assert_eq!(out.protocol, L7Protocol::Ssh);
        assert_eq!(out.app_id(), Some("protocol.ssh"));
        assert!(out.sni.is_none());
    }

    #[test]
    fn unknown_tls_host_keeps_protocol_drops_app() {
        let e = AppIdEnricher::builtin();
        let payload = tls_client_hello_with_sni("nope.example.invalid");
        let out = e.enrich(&payload, Some(443), Some(Transport::Tcp));
        assert_eq!(out.protocol, L7Protocol::Tls);
        // SNI surfaced even though no catalog entry matched.
        assert_eq!(out.sni.as_deref(), Some("nope.example.invalid"));
        assert!(out.app.is_none());
    }

    #[test]
    fn empty_payload_is_unknown_with_no_app() {
        let e = AppIdEnricher::builtin();
        let out = e.enrich(b"", None, None);
        assert_eq!(out.protocol, L7Protocol::Unknown);
        assert!(out.app.is_none());
        assert!(out.sni.is_none());
    }

    #[test]
    fn catalog_is_non_empty() {
        assert!(AppIdEnricher::builtin().catalog_len() >= 200);
    }
}
