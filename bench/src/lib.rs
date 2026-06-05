//! `sng-bench` — ShieldNet Gateway edge data-path benchmark library.
//!
//! The crate is built as a library plus a thin `sng-bench` binary. The
//! library holds the reusable, unit-tested pieces:
//!
//!   * [`traffic_gen`] — synthetic frame crafting and `AF_PACKET`
//!     transmission ([`traffic_gen::TrafficGenerator`]).
//!   * [`measurement`] — throughput counters, an HdrHistogram-style
//!     latency histogram, and a `/proc` resource sampler.
//!   * [`report`] — the JSON/markdown report model and the run-over-run
//!     regression detector.
//!   * [`competitor`] — published competitor figures and the SNG
//!     inspection-depth → vendor-feature mapping.
//!   * [`datapath`] — in-process decision-throughput comparison of the
//!     nftables slow path vs the eBPF/XDP fast path (STREAM B).
//!   * [`business_report`] — aggregation of per-run reports into a single
//!     RFP-datasheet document (per-SKU matrices, competitor comparison,
//!     cost analysis).
//!
//! Keeping these in a library target (rather than private `mod`s inside
//! the binary) means their public surface is genuinely reachable API,
//! exercised directly by the test suite.

pub mod business_report;
pub mod competitor;
pub mod datapath;
pub mod measurement;
pub mod report;
pub mod traffic_gen;
