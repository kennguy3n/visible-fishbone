//! DNS subsystem error taxonomy.
//!
//! Every error produced by this crate maps onto an
//! [`sng_core::error::ErrorCode`] so the supervisor can bucket
//! failures into the same dotted-lowercase namespace the rest of
//! the workspace uses.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the DNS subsystem.
#[derive(Debug, Error)]
pub enum DnsError {
    /// The query failed validation before reaching the resolver
    /// (empty name, label too long, name longer than the
    /// 255-byte RFC 1035 limit, name contained a label with the
    /// top two bits set, etc.).
    #[error("query invalid: {0}")]
    QueryInvalid(String),

    /// Upstream resolver returned a wire-format response that
    /// could not be parsed (truncated header, malformed name
    /// pointer, RDATA length mismatch, etc.).
    #[error("wire format: {0}")]
    WireFormat(String),

    /// Upstream UDP IO failed — socket bind, send, recv, or
    /// timeout. Includes the deadline tag so the operator can
    /// distinguish a connect failure from a slow upstream.
    #[error("io: {0}")]
    Io(String),

    /// Upstream resolver returned `SERVFAIL` or another
    /// terminal RCODE that prevents the agent from acting on
    /// the answer. The variant carries the raw RCODE so the
    /// caller can surface it onto the [`crate::DnsResponse`].
    #[error("upstream rcode: {rcode}")]
    UpstreamRcode {
        /// RFC 1035 RCODE the upstream returned.
        rcode: u8,
    },

    /// A reputation feed, category DB, or sinkhole list failed
    /// to load. Distinct from [`Self::Io`] because the cause is
    /// usually a malformed feed (operator-controllable) rather
    /// than a network or disk failure.
    #[error("feed: {0}")]
    Feed(String),

    /// The egress channel into the telemetry pipeline rejected
    /// the [`sng_core::DnsEvent`] — most commonly because the
    /// pipeline task has been shut down. The variant exists so
    /// the supervisor can distinguish "no telemetry" from "DNS
    /// resolution failed".
    #[error("telemetry: {0}")]
    Telemetry(String),
}

impl DnsError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::QueryInvalid(_) | Self::WireFormat(_) => ErrorCode::WireSchema,
            // Feed parse failures are a config-level problem — the
            // operator must fix the feed file or pin a previous
            // version. Mapping to ConfigInvalid means dashboards
            // bucket them with the rest of the config-failure
            // surface rather than burying them under Io.
            Self::Feed(_) => ErrorCode::ConfigInvalid,
            Self::Io(_) | Self::UpstreamRcode { .. } | Self::Telemetry(_) => ErrorCode::Io,
        }
    }
}
