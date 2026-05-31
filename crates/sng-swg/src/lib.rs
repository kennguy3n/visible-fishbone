// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// Test-only allows. Mirror what sng-fw and sng-ips enable so the
// test bodies can use unwrap/expect for assertion clarity without
// dragging `?` and `let ... else` boilerplate into every fixture.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::match_wildcard_for_single_variants,
        clippy::too_many_lines,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::format_push_string,
        clippy::float_cmp,
    )
)]

//! Secure Web Gateway subsystem for the SNG edge VM.
//!
//! Wraps Envoy in forward-proxy mode (HTTP CONNECT for HTTPS,
//! transparent for HTTP) and answers the proxy's per-request
//! ext-authz queries with a verdict computed from:
//!
//! * [`bypass`] — TLS bypass list evaluated against the
//!   ClientHello SNI. The matcher is re-exported from
//!   [`sng_fw::sni_suffix_match`] so the operator-curated bypass
//!   list has identical semantics in both subsystems. Industry
//!   default categories (healthcare, finance) ship as baked-in
//!   defaults that an operator can extend or override.
//!
//! * [`categorizer`] — URL categorisation over the request host
//!   plus path. The [`UrlCategorizer`] trait is the pluggable
//!   provider surface: at launch there is a single
//!   [`LocalCategoryDb`] backed by a hot-swappable
//!   [`arc_swap::ArcSwap`] of categorised hostnames sourced from a
//!   signed control-plane bundle; production deployments can swap
//!   in a remote provider that calls an external feed.
//!
//! * [`malware`] — file-download malware verdict. The
//!   [`MalwareVerdictProvider`] trait keeps the verdict cache
//!   contract narrow (`verdict(file_hash) -> Verdict`) so a
//!   remote provider can plug in behind the same surface the
//!   ext-authz handler sees.
//!
//! * [`rate_limit`] — per-(tenant, principal) token-bucket
//!   ceiling so an over-eager client cannot saturate the
//!   verdict providers. The bucket state is deterministic
//!   under an injected monotonic clock so the tests do not
//!   sleep.
//!
//! * [`auth`] — the ext-authz HTTP server itself. Envoy POSTs
//!   the candidate request to `/ext_authz` with the URL and
//!   ClientHello metadata in the body; the handler computes the
//!   verdict in one shot and replies with a JSON document Envoy
//!   translates into an allow / deny / redirect verdict on the
//!   wire. The server is `tokio::net::TcpListener`-backed and
//!   reads / writes its own minimal HTTP/1.1 frames so the
//!   crate has zero external HTTP-server dependency surface.
//!
//! * [`config`] — translates the SWG slice of a policy bundle
//!   into an `envoy.yaml`. The generator is deterministic and
//!   emits stable-ordered YAML so two identical inputs produce
//!   byte-identical configs (the manager uses the SHA-256 of
//!   the rendered config to decide whether a kernel restart is
//!   needed on a hot-swap, the same digest pattern sng-fw uses
//!   for nftables scripts).
//!
//! * [`process`] — `EnvoyProcess` trait with a production
//!   shell-out implementation (`ShellEnvoy`) and a `MockEnvoy`
//!   for tests. The trait is intentionally narrow (`start`,
//!   `stop`, `signal`, `is_alive`, `validate_config`) so the
//!   supervisor in [`manager`] can swap implementations without
//!   touching the surrounding control logic.
//!
//! * [`manager`] — owns the supervisor loop, the hot-swap path,
//!   and the ext-authz handler's snapshot of every provider.
//!   A new bundle goes through:
//!     1. Decode and verify the SWG slice.
//!     2. Render the Envoy config and `envoy --mode validate`
//!        against it.
//!     3. Build the new in-memory snapshot (categoriser,
//!        bypass list, malware provider, rate limiter).
//!     4. ArcSwap-store the snapshot (zero-lock for readers).
//!     5. SIGHUP Envoy to reload, with a digest-skip if the
//!        config bytes are byte-identical to the running set.
//!
//! Everything kernel-side (Envoy spawn, SIGHUP, listener bind) is
//! mocked in tests via the `EnvoyProcess` trait so the full
//! suite runs without root and without an actual `envoy` binary.

pub mod auth;
pub mod bypass;
pub mod categorizer;
pub mod config;
pub mod error;
pub mod health;
pub mod malware;
pub mod manager;
pub mod process;
pub mod rate_limit;
pub mod telemetry;
pub mod verdict;

pub use auth::{ExtAuthzHandler, ExtAuthzRequest, ExtAuthzResponse};
pub use bypass::{BypassDecision, BypassList, BypassReason};
pub use categorizer::{Category, CategoryEntry, LocalCategoryDb, UrlCategorizer};
pub use config::{
    DEFAULT_ADMIN_PORT, DEFAULT_EXT_AUTHZ_TIMEOUT_MS, EnvoyConfig, ListenerConfig,
    render_envoy_yaml,
};
pub use error::SwgError;
pub use health::{HealthReport, HealthState, ManagerHealth};
pub use malware::{MalwareVerdict, MalwareVerdictProvider, StaticMalwareList};
pub use manager::{SwgManager, SwgSnapshot};
pub use process::{EnvoyProcess, MockEnvoy, ShellEnvoy};
pub use rate_limit::{
    Clock, EvictionTaskHandle, EvictionTaskSpawnError, RateLimitDecision, RateLimiter, SystemClock,
    TestClock,
};
pub use telemetry::{TelemetryEmitter, VerdictEvent};
pub use verdict::{Action, RequestContext, Verdict};
