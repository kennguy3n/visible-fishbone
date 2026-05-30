//! L3-L7 firewall subsystem for the ShieldNet Gateway agent / edge.
//!
//! `sng-fw` is the **stateful connection-aware verdict layer**
//! between the underlying packet path (nftables / conntrack /
//! VPP-DPDK on the edge VM; ws2tcpip / pfctl on endpoints) and
//! the policy evaluator. It does NOT program the kernel
//! datapath itself — that responsibility belongs to the PAL
//! (`sng-pal`) in PR-2; this crate is the brain that decides
//! what verdict each flow should get and emits the telemetry
//! `FlowEvent`s that downstream analytics consume.
//!
//! The crate is intentionally laid out so each responsibility
//! lives in its own module:
//!
//! - [`error`]: [`FwError`] mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`flow`]: typed [`FlowKey`] (5-tuple + direction) and
//!   [`FlowState`] (per-flow accounting and conntrack state
//!   machine).
//! - [`appid`]: application identification — port-based
//!   heuristics + SNI extraction from TLS ClientHello.
//! - [`conntrack`]: bounded LRU connection table with
//!   idle-timeout eviction, hot-path lookup, eager closure
//!   on RST / FIN.
//! - [`verdict`]: per-flow [`FwVerdict`] with TTL caching so
//!   the policy evaluator is not re-queried for every packet
//!   of an established flow.
//! - [`policy`]: adapter that converts a [`flow::FlowKey`] +
//!   resolved [`appid::AppId`] into a
//!   [`sng_policy_eval::Flow`] and runs it through the
//!   evaluator.
//! - [`service`]: [`FwService`] orchestrator wiring conntrack,
//!   verdict cache, policy adapter, and telemetry emission
//!   into a single ingestion surface.
//! - [`stats`]: counters surfaced to ops dashboards
//!   (flows tracked, cache hits, verdicts emitted, drops).
//!
//! ### Verdict semantics
//!
//! [`FwVerdict`] is a superset of [`sng_core::envelope::Verdict`]:
//! the firewall computes a verdict in its own richer
//! representation (which distinguishes `AllowEstablished` from
//! a fresh allow, and which carries per-flow context like the
//! resolved app id and the reason the flow was denied), then
//! collapses it into the wire-level [`Verdict`] before
//! emitting a [`FlowEvent`] downstream. The richer type stays
//! crate-private to upstream callers; only the wire-level
//! verdict crosses module boundaries.
//!
//! ### Concurrency model
//!
//! The conntrack table is guarded by a
//! [`parking_lot::Mutex`] — short critical sections, no
//! `.await` under the lock. The verdict cache uses the same
//! pattern. Policy evaluation runs on the caller's tokio
//! task and is sync (the evaluator's hot path is
//! `Arc::load` + a small rule walk, not I/O).
//! Telemetry submission uses `try_submit` so the firewall
//! data path never blocks on a saturated pipeline — drops
//! are credited to a counter the operator can see.

// Test-only allows: tests legitimately use `.unwrap()` and
// `.expect()` for fast-failing assertions. The workspace-level
// `unwrap_used`/`expect_used`/`panic` lints stay at `warn` for
// production code (CI catches them) but firing on every test
// module would be noise. Plus the same allow-lints the sister
// crate `sng-dns` uses for the same reason.
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

pub mod appid;
pub mod conntrack;
pub mod error;
pub mod flow;
pub mod policy;
pub mod service;
pub mod stats;
pub mod verdict;

pub use appid::{AppId, AppIdResolver, PortHeuristicResolver, SniExtractor};
pub use conntrack::{ConnTable, ConnTableConfig, ConnTrackEntry};
pub use error::FwError;
pub use flow::{FlowDirection, FlowKey, FlowState, IpProtocol};
pub use policy::{FlowIdentity, FwPolicyAdapter};
pub use service::{FwService, PacketDecision, PacketObservation};
pub use stats::{FwStats, FwStatsSnapshot};
pub use verdict::{FwVerdict, VerdictCache, VerdictCacheConfig, VerdictReason};
