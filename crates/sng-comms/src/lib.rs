// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding; CI runs `cargo clippy --tests -D warnings` across
// the workspace. Allow them in `#[cfg(test)]` only — production
// code paths still get the workspace-level warning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::float_cmp,
    )
)]

//! ShieldNet Gateway (SNG) native protocol client.
//!
//! This crate is the single transport library shared by the edge VM
//! appliance ([`sng-edge`]) and the endpoint agent ([`sng-agent`])
//! for talking to the control plane. The wire shape is:
//!
//! * TLS 1.3 (rustls, no OpenSSL) with mutual TLS — device identity
//!   binding is provided by [`DeviceIdentity`], which carries the
//!   Ed25519 keypair the agent enrolled with plus the client
//!   certificate chain issued by the control plane during
//!   enrolment.
//! * HTTP/2 (RFC 7540) over TLS, with ALPN identifier `h2`
//!   negotiated on every handshake. [`tls::build_client_config`]
//!   sets `alpn_protocols = [b"h2"]` so any caller that uses the
//!   helper gets the right ALPN out of the box, and
//!   [`ControlPlaneClient::connect`] fails fast if the server did
//!   not negotiate `h2`. Bare HTTP/1.1 fallback would silently
//!   break the h2 connection preface sent on the next frame.
//! * MessagePack (rmp-serde) for event envelopes and policy
//!   bundles — matches the Go control plane's
//!   `vmihailenco/msgpack/v5` codec on `internal/nats/schema/envelope.go`.
//!
//! Module map:
//!
//! * [`identity`] — [`DeviceIdentity`] (Ed25519 keypair + PEM cert
//!   chain) with a single `from_pem_files` constructor that
//!   validates the keypair against the leaf cert's
//!   SubjectPublicKeyInfo at load time.
//! * [`tls`] — rustls `ClientConfig` builder with TLS 1.3 + ALPN
//!   `h2` + optional client cert.
//! * [`backoff`] — exponential reconnect backoff with full jitter.
//! * [`client`] — [`ControlPlaneClient`]: connection lifecycle,
//!   HTTP/2 stream multiplexing, automatic reconnect with backoff,
//!   health probe.
//! * [`spool`] — bounded in-memory spool with oldest-drop-first
//!   eviction; disk-backed spool is layered on top by `sng-telemetry`
//!   (PR 5).
//! * [`ack`] — monotonic per-stream sequence tracking; regression
//!   triggers a fail-closed reconnect.
//! * [`batch`] — size-and-time-bounded [`BatchBuilder`] that flushes
//!   accumulated envelopes when the size cap or the flush interval
//!   elapses.
//! * [`policy`] — [`PolicyPuller`]: agent-side pull of compiled
//!   policy bundles via the
//!   `GET /api/v1/tenants/{tid}/policy/bundles/{target}/payload`
//!   endpoint, with ETag / If-None-Match cache validation and
//!   Ed25519 signature verification using sng-core's
//!   [`PolicyVerifier`].
//! * [`telemetry`] — [`TelemetryClient`]: batched envelope
//!   submission with local enrichment + zstd compression.
//! * [`error`] — the [`CommsError`] taxonomy + stable error codes.

mod ack;
mod backoff;
mod batch;
mod client;
mod error;
mod identity;
mod policy;
mod spool;
mod telemetry;
pub mod tls;

pub use ack::{RegressionKind, SequenceRegression, SequenceTracker};
pub use backoff::{Backoff, ReconnectBackoff};
pub use batch::{Batch, BatchBuilder, BatchConfig, BatchFlushReason};
pub use client::{
    CollectedResponse, ControlPlaneClient, ControlPlaneConnection, DEFAULT_MAX_RESPONSE_BODY_BYTES,
    RequestBody, RequestPath,
};
pub use error::{CommsError, ResponseClass};
pub use identity::{DeviceIdentity, IdentityError};
pub use policy::{
    BundlePullOutcome, CachedBundle, PolicyPuller, PolicyPullerConfig, PolicyTrustStore,
    PolicyTrustStoreError, ResponseHeaders, default_payload_path,
};
pub use spool::{BoundedSpool, PushOutcome, SpoolStats};
pub use telemetry::{
    BatchAck, BatchCompression, EnrichmentContext, FlushOutcome, TelemetryClient,
    TelemetryClientConfig,
};
pub use tls::{ClientConfigError, build_client_config, build_client_config_with_webpki_roots};
