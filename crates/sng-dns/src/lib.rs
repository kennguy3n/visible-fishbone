//! DNS subsystem for the ShieldNet Gateway agent / edge.
//!
//! Wraps a recursive resolver (Unbound-class) with a per-tenant
//! filter chain (reputation feed → category filter → sinkhole)
//! and emits per-query DnsEvents into the [`sng_telemetry`]
//! pipeline.
//!
//! The crate is laid out so each responsibility is in its own
//! module and the public surface re-exports a small set of
//! types:
//!
//! - [`qtype`]: typed DNS query type + RCODE enums
//! - [`wire`]: RFC 1035 wire-format encoder / decoder
//! - [`error`]: [`DnsError`] mapped to [`sng_core::error::ErrorCode`]
//! - [`query`]: agent-facing [`DnsQuery`] / [`DnsResponse`] types
//! - [`filter`]: [`Filter`] trait + hot-swappable [`FilterChain`]
//! - [`reputation`]: exact-match reputation feed → NXDOMAIN
//! - [`category`]: per-tenant per-category Allow / Log / Block
//! - [`sinkhole`]: suffix-match list → synthetic A / AAAA
//! - [`threatintel`]: Bloom-filter known-bad feed → synthetic
//!   sinkhole answer, with an authoritative allowlist override
//! - [`tunneling`]: entropy / volume / TXT-abuse tunneling detector
//! - [`resolver`]: async [`Resolver`] trait + UDP / static impls
//! - [`service`]: end-to-end orchestrator emitting [`DnsEvent`]
//!   into the [`sng_telemetry`] pipeline

// Test-only allows: tests legitimately use `.unwrap()` and
// `.expect()` for fast-failing assertions. The workspace-level
// `unwrap_used`/`expect_used`/`panic` lints stay at `warn` for
// production code (CI catches them) but firing on every test
// module would be noise.
// Test-only allows beyond the obvious unwrap/expect/panic:
// - `match_wildcard_for_single_variants`: the `other =>
//   panic!("expected X, got {other:?}")` pattern in tests is the
//   right shape for an assert-like "exactly this variant" check;
//   binding the variant explicitly would lose the rendered Debug
//   on mismatch which is exactly the information the test author
//   needs to triage a failure.
// - `too_many_lines`: tests that walk through every branch of an
//   enum or every error variant legitimately grow past 100 lines
//   without that being a smell.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::match_wildcard_for_single_variants,
        clippy::too_many_lines
    )
)]

pub mod category;
pub mod error;
pub mod filter;
pub mod managed;
pub mod qtype;
pub mod query;
pub mod reputation;
pub mod resolver;
pub mod service;
pub mod sinkhole;
pub mod threatintel;
pub mod tunneling;
pub mod wire;

pub use category::{Category, CategoryAction, CategoryDb};
pub use error::DnsError;
pub use filter::{ChainOutcome, Filter, FilterChain, FilterDecision, combine_verdicts};
pub use managed::{
    AppliedFeed, FeedBundle, FeedBundleError, FeedVerifier, ManagedFeedApplier, SignedFeedBundle,
};
pub use qtype::{QType, RCode};
pub use query::{DnsQuery, DnsResponse, canonicalize_name, domain_suffix_match};
pub use reputation::Reputation;
pub use resolver::{Resolver, StaticResolver, UdpResolver};
pub use service::{DnsService, HandledQuery};
pub use sinkhole::Sinkhole;
pub use threatintel::{BloomFilter, ThreatIntelSinkhole};
pub use tunneling::{
    TracingTunnelingSink, TunnelingAlert, TunnelingConfig, TunnelingDetector, TunnelingKind,
    TunnelingSink, registrable_domain, shannon_entropy_bits,
};
pub use wire::{
    CLASS_IN, Header, Record, encode_query, parse_header, parse_question, parse_records,
};
