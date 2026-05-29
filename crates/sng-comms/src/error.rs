//! Typed error taxonomy for the `sng-comms` crate.
//!
//! Every fallible surface in this crate maps its error variants to
//! a stable [`ErrorCode`] (defined in `sng-core::error`) via the
//! [`CommsError::code`] inherent. That gives callers a single
//! match arm to drive control-flow on (e.g. "is this retryable?",
//! "is this a permanent identity rejection?") without pattern-
//! matching on the variant body, and gives operators stable log
//! lines that survive an internal error-message refactor.
//!
//! The taxonomy is intentionally narrow at this layer. Higher-
//! level orchestrators (sng-edge, sng-agent) wrap these into their
//! own error types — they should not need to break open a
//! `CommsError` to know "I should reconnect" vs "I should
//! re-enrol".

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Coarse-grained classification of a server response. Surfaced by
/// the policy-pull and telemetry-push paths so the orchestrator
/// can drive retry / re-enrol / fail-closed transitions without
/// reading the HTTP status code itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseClass {
    /// `2xx` — the request was accepted. Caller-specific success
    /// codes (e.g. `200` vs `204`) are surfaced through the
    /// per-endpoint return type.
    Success,
    /// `304 Not Modified` — the cached resource is still
    /// authoritative. Only reachable on conditional-request paths
    /// (policy pull).
    NotModified,
    /// `401` / `403` — identity or RBAC failure. Permanent under
    /// the current credentials; the orchestrator must re-enrol or
    /// surface a configuration error rather than retry.
    Unauthorized,
    /// `400` / `422` — the request itself is malformed. Permanent
    /// under the current build; retrying is futile.
    BadRequest,
    /// `404` — the resource does not exist for this tenant /
    /// target. Permanent under the current tenant binding.
    NotFound,
    /// `429` — server-side rate limit. Retryable after a backoff.
    RateLimited,
    /// `5xx` — server-side failure. Retryable after a backoff.
    ServerError,
    /// Anything else (`1xx` informational, `3xx` redirect, `2xx`
    /// content the caller did not opt into, etc.). Treated as a
    /// permanent protocol error rather than a retryable transient
    /// fault.
    Other,
}

impl ResponseClass {
    /// Classify a numeric HTTP status code. The mapping is the
    /// stable contract this crate exposes; do not change it
    /// without bumping the crate's wire-compatibility marker.
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            304 => Self::NotModified,
            200..=299 => Self::Success,
            401 | 403 => Self::Unauthorized,
            400 | 422 => Self::BadRequest,
            404 => Self::NotFound,
            429 => Self::RateLimited,
            500..=599 => Self::ServerError,
            _ => Self::Other,
        }
    }

    /// Whether a request that received this class should be
    /// retried after a backoff.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::ServerError)
    }
}

/// Top-level error type. Every fallible surface in `sng-comms`
/// returns this; orchestrators discriminate on it (or on
/// [`Self::code`]) to drive retry / re-enrol / fail-closed.
#[derive(Debug, Error)]
pub enum CommsError {
    /// Device identity failed to load or did not match the leaf
    /// certificate. Permanent under the current files on disk —
    /// the orchestrator must either point at a different
    /// identity or re-enrol.
    #[error("device identity: {0}")]
    Identity(#[from] crate::identity::IdentityError),

    /// Underlying TLS or HTTP/2 connect / handshake failure. Surfaces
    /// the rustls or h2 error in the source chain so an operator
    /// reading logs sees the actual underlying cause.
    #[error("connect failure: {0}")]
    Connect(String),

    /// The handshake completed but the negotiated ALPN protocol
    /// was not `h2`. Per RFC 7540 §3.3 the HTTP/2 connection
    /// preface cannot be sent on a non-`h2` connection; fail
    /// fast rather than silently fall back to HTTP/1.1.
    #[error("server did not negotiate HTTP/2 (h2) ALPN")]
    AlpnMismatch,

    /// Underlying I/O error on send / receive.
    #[error("transport I/O: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP/2 protocol-level error.
    #[error("HTTP/2: {0}")]
    Http2(String),

    /// The server returned a structurally well-formed response
    /// the caller cannot accept (4xx / 5xx / unexpected 3xx /
    /// missing required header).
    #[error("server response: {class:?} ({reason})")]
    Server {
        class: ResponseClass,
        reason: String,
    },

    /// MessagePack encode / decode failure.
    #[error("msgpack: {0}")]
    Encoding(String),

    /// Compression / decompression failure.
    #[error("compression: {0}")]
    Compression(String),

    /// Bundle signature did not verify, or claims failed an
    /// authenticated post-condition check. Surfaces the sng-core
    /// `VerificationError` in the source chain.
    #[error("policy bundle: {0}")]
    Policy(#[from] sng_core::policy::VerificationError),

    /// Bundle version regressed below the currently-loaded
    /// version, or the response carried no version. Distinct
    /// from `Policy` so the orchestrator can pin the "received
    /// downgrade attempt" telemetry without wading into the
    /// signature-error variants.
    #[error("policy bundle version: {0}")]
    PolicyVersion(String),

    /// Sequence number regressed below the high-water mark on a
    /// telemetry stream. Surfaces the offending stream so the
    /// orchestrator can scope its reconnect to that stream.
    #[error("sequence regression on stream {stream}: highest={highest}, observed={observed}")]
    SequenceRegression {
        stream: String,
        highest: u64,
        observed: u64,
    },

    /// `Config` ↔ `sng-comms` wiring rejected at construction
    /// time (e.g. `control_plane_url` is not a valid `https://…`
    /// authority).
    #[error("configuration: {0}")]
    Config(String),

    /// rustls `ClientConfig` builder rejected the supplied roots,
    /// client cert, or feature flags. Permanent under the current
    /// build / files on disk.
    #[error("TLS configuration: {0}")]
    TlsConfig(#[from] crate::tls::ClientConfigError),
}

impl CommsError {
    /// Map every variant to the stable workspace error code.
    /// Orchestrators driving retry / re-enrol / fail-closed
    /// transitions should discriminate on this rather than on the
    /// variant body — the variants are subject to internal
    /// refactor, the codes are not.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Identity(_) => ErrorCode::IdentityInvalid,
            Self::Connect(_) | Self::Io(_) | Self::Http2(_) | Self::AlpnMismatch => {
                ErrorCode::ControlPlaneUnreachable
            }
            Self::Server {
                class: ResponseClass::Unauthorized,
                ..
            } => ErrorCode::IdentityRejected,
            Self::Server {
                class: ResponseClass::NotFound,
                ..
            } => ErrorCode::ResourceMissing,
            Self::Server { .. } => ErrorCode::ControlPlaneUnreachable,
            Self::Encoding(_) | Self::Compression(_) => ErrorCode::WireEncoding,
            Self::Policy(err) => err.code(),
            Self::PolicyVersion(_) => ErrorCode::BundleRejected,
            Self::SequenceRegression { .. } => ErrorCode::SequenceRegression,
            Self::Config(_) | Self::TlsConfig(_) => ErrorCode::ConfigInvalid,
        }
    }

    /// Whether the orchestrator should retry the operation after
    /// a backoff. Identity / config errors are permanent;
    /// transport / server-5xx / rate-limit are transient.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connect(_) | Self::Io(_) | Self::Http2(_) => true,
            Self::Server { class, .. } => class.is_retryable(),
            // Identity / wire-format / policy errors are permanent
            // under the current build or files on disk; ALPN
            // mismatch is permanent under the current server build.
            Self::Identity(_)
            | Self::AlpnMismatch
            | Self::Encoding(_)
            | Self::Compression(_)
            | Self::Policy(_)
            | Self::PolicyVersion(_)
            | Self::SequenceRegression { .. }
            | Self::Config(_)
            | Self::TlsConfig(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_class_maps_known_codes() {
        assert_eq!(ResponseClass::from_status(200), ResponseClass::Success);
        assert_eq!(ResponseClass::from_status(204), ResponseClass::Success);
        assert_eq!(ResponseClass::from_status(304), ResponseClass::NotModified);
        assert_eq!(ResponseClass::from_status(400), ResponseClass::BadRequest);
        assert_eq!(ResponseClass::from_status(401), ResponseClass::Unauthorized);
        assert_eq!(ResponseClass::from_status(403), ResponseClass::Unauthorized);
        assert_eq!(ResponseClass::from_status(404), ResponseClass::NotFound);
        assert_eq!(ResponseClass::from_status(422), ResponseClass::BadRequest);
        assert_eq!(ResponseClass::from_status(429), ResponseClass::RateLimited);
        assert_eq!(ResponseClass::from_status(500), ResponseClass::ServerError);
        assert_eq!(ResponseClass::from_status(503), ResponseClass::ServerError);
        assert_eq!(ResponseClass::from_status(599), ResponseClass::ServerError);
        // Outside the canonical ranges fall back to Other.
        assert_eq!(ResponseClass::from_status(100), ResponseClass::Other);
        assert_eq!(ResponseClass::from_status(301), ResponseClass::Other);
        assert_eq!(ResponseClass::from_status(600), ResponseClass::Other);
    }

    #[test]
    fn response_class_is_retryable_only_for_429_and_5xx() {
        assert!(ResponseClass::RateLimited.is_retryable());
        assert!(ResponseClass::ServerError.is_retryable());
        assert!(!ResponseClass::Success.is_retryable());
        assert!(!ResponseClass::NotModified.is_retryable());
        assert!(!ResponseClass::Unauthorized.is_retryable());
        assert!(!ResponseClass::BadRequest.is_retryable());
        assert!(!ResponseClass::NotFound.is_retryable());
        assert!(!ResponseClass::Other.is_retryable());
    }

    #[test]
    fn comms_error_is_retryable_matches_taxonomy() {
        let io = CommsError::Io(std::io::Error::other("x"));
        let h2 = CommsError::Http2("stream closed".into());
        let alpn = CommsError::AlpnMismatch;
        let cfg = CommsError::Config("bad url".into());
        let seq = CommsError::SequenceRegression {
            stream: "telemetry".into(),
            highest: 7,
            observed: 5,
        };
        let server_429 = CommsError::Server {
            class: ResponseClass::RateLimited,
            reason: "slow down".into(),
        };
        let server_500 = CommsError::Server {
            class: ResponseClass::ServerError,
            reason: "boom".into(),
        };
        let server_401 = CommsError::Server {
            class: ResponseClass::Unauthorized,
            reason: "no".into(),
        };

        assert!(io.is_retryable());
        assert!(h2.is_retryable());
        assert!(!alpn.is_retryable());
        assert!(!cfg.is_retryable());
        assert!(!seq.is_retryable());
        assert!(server_429.is_retryable());
        assert!(server_500.is_retryable());
        assert!(!server_401.is_retryable());
    }
}
