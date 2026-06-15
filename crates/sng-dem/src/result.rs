//! Structured probe results — the wire contract with the control
//! plane's `internal/service/dem` ingest endpoint.
//!
//! Field names and the [`ProbeKind`] / [`ProbeErrorKind`] tokens are
//! chosen to deserialize byte-for-byte into the Go ingest DTO (which
//! rejects unknown fields), so the edge and the control plane stay in
//! lock-step without a shared schema generator.

use serde::{Deserialize, Serialize};

use crate::target::ProbeKind;

/// Why a probe did not succeed.
///
/// Serialised as a lowercase token so the control plane can bucket
/// failures without parsing free text. `Http` means the transport
/// completed but the response status was outside the healthy range
/// (the target is reachable but unhealthy) — distinct from the
/// transport-level failures (`Dns`, `Connect`, `Tls`, `Timeout`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeErrorKind {
    /// The hard per-probe deadline elapsed.
    Timeout,
    /// DNS resolution failed or returned no addresses.
    Dns,
    /// TCP connect failed (refused, unreachable, reset).
    Connect,
    /// The TLS handshake or HTTP request transport failed.
    Tls,
    /// A response arrived but its status was outside the healthy
    /// range (`>= 400`).
    Http,
    /// The target was malformed and could not be probed.
    Config,
    /// An unexpected internal fault (e.g. a panicked probe task).
    Internal,
}

impl ProbeErrorKind {
    /// The lowercase wire token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Config => "config",
            Self::Internal => "internal",
        }
    }
}

/// One probe's structured outcome.
///
/// Timing fields are optional because each probe kind populates only
/// the phases it ran (a DNS probe sets `dns_ms` only; an HTTPS probe
/// sets `dns_ms`, `tcp_ms`, `ttfb_ms`, `total_ms` and `http_status`).
/// All latencies are milliseconds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Stable target identity (the scoring dimension).
    pub target_key: String,
    /// Human-readable label captured at probe time.
    pub target_name: String,
    /// What was measured.
    pub probe_kind: ProbeKind,
    /// Whether the probe reached a healthy endpoint.
    pub success: bool,
    /// DNS resolution latency (ms).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dns_ms: Option<f64>,
    /// TCP-connect latency (ms).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tcp_ms: Option<f64>,
    /// TLS-handshake latency (ms), when measured separately.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tls_ms: Option<f64>,
    /// Time-to-first-byte latency (ms): request sent → response
    /// headers received.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttfb_ms: Option<f64>,
    /// End-to-end latency (ms): the full probe wall-clock.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_ms: Option<f64>,
    /// HTTP status code, when an HTTP response was received.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub http_status: Option<u16>,
    /// Failure classification, set iff `success == false`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_kind: Option<ProbeErrorKind>,
    /// Optional human-readable failure detail (diagnostic only; the
    /// control plane does not persist it).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_detail: Option<String>,
    /// Unix-epoch milliseconds at which the probe completed.
    pub observed_at_ms: u64,
}

impl ProbeResult {
    /// Serialise to compact JSON for egress, mapping a serde failure
    /// onto [`DemError::Encode`](crate::DemError::Encode).
    pub fn to_json(&self) -> Result<String, crate::DemError> {
        serde_json::to_string(self).map_err(|e| crate::DemError::Encode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn error_kind_tokens_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&ProbeErrorKind::Connect).unwrap(),
            "\"connect\""
        );
        assert_eq!(ProbeErrorKind::Timeout.as_str(), "timeout");
    }

    #[test]
    fn success_result_omits_error_and_none_phases() {
        let r = ProbeResult {
            target_key: "m365".into(),
            target_name: "Microsoft 365".into(),
            probe_kind: ProbeKind::Https,
            success: true,
            dns_ms: Some(3.2),
            tcp_ms: Some(11.0),
            tls_ms: None,
            ttfb_ms: Some(42.5),
            total_ms: Some(58.1),
            http_status: Some(200),
            error_kind: None,
            error_detail: None,
            observed_at_ms: 1_700_000_000_000,
        };
        let json = r.to_json().unwrap();
        // Omitted None fields keep the wire form tight and let the Go
        // DTO treat them as absent rather than explicit null.
        assert!(!json.contains("error_kind"));
        assert!(!json.contains("tls_ms"));
        assert!(json.contains("\"http_status\":200"));
        let back: ProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn failure_result_round_trips() {
        let r = ProbeResult {
            target_key: "zoom".into(),
            target_name: "Zoom".into(),
            probe_kind: ProbeKind::Tcp,
            success: false,
            dns_ms: Some(2.0),
            tcp_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            total_ms: None,
            http_status: None,
            error_kind: Some(ProbeErrorKind::Connect),
            error_detail: Some("connection refused".into()),
            observed_at_ms: 1_700_000_000_001,
        };
        let json = r.to_json().unwrap();
        let back: ProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.error_kind, Some(ProbeErrorKind::Connect));
    }
}
