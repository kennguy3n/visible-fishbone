//! Telemetry pipeline error taxonomy.
//!
//! Every error produced by this crate maps onto an
//! [`sng_core::error::ErrorCode`] so the supervisor can bucket
//! failures into the same dotted-lowercase namespace the rest of
//! the workspace uses.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the telemetry pipeline.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// An event failed validation before entering the pipeline.
    #[error("event invalid: {0}")]
    EventInvalid(String),

    /// An event was rejected by the dedup window (duplicate).
    #[error("duplicate event: {fingerprint}")]
    Duplicate {
        /// Hex-encoded fingerprint of the duplicate.
        fingerprint: String,
    },

    /// Envelope construction failed (missing required fields,
    /// payload encode error, etc.).
    #[error("envelope: {0}")]
    Envelope(String),

    /// The egress sink (sng-comms `TelemetryClient`) rejected
    /// the envelope or is unavailable.
    #[error("egress: {0}")]
    Egress(#[source] sng_comms::CommsError),

    /// The PCAP ring buffer rejected a write (e.g. packet
    /// exceeds the per-packet size cap).
    #[error("pcap: {0}")]
    Pcap(String),
}

impl TelemetryError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::EventInvalid(_) => ErrorCode::WireSchema,
            Self::Duplicate { .. } => ErrorCode::Other,
            Self::Envelope(_) => ErrorCode::WireEncoding,
            Self::Egress(e) => e.code(),
            Self::Pcap(_) => ErrorCode::Io,
        }
    }
}

impl From<sng_comms::CommsError> for TelemetryError {
    fn from(e: sng_comms::CommsError) -> Self {
        Self::Egress(e)
    }
}
