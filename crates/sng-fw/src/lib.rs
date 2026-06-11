// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
#![doc = include_str!("../README.md")]
// Test-only allows beyond the obvious unwrap/expect/panic:
// - `match_wildcard_for_single_variants`: tests legitimately use
//   `other => panic!("expected X, got {other:?}")` for exact-
//   variant assertions; rendering the unexpected Debug is the
//   triage signal a test author needs.
// - `too_many_lines`: tests that walk every action / state / NAT
//   shape grow past 100 lines without that being a smell.
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
        clippy::float_cmp,
    )
)]

//! `sng-fw` — L3-L7 firewall engine for the SNG edge VM.
//!
//! Owns the translation from the NGFW slice of a verified policy
//! bundle (consumed via `sng-policy-eval`) into a deterministic
//! nftables rule set plus the L7 / TLS interception decision
//! engine the SWG and IPS subsystems consume.

pub mod backend;
pub mod compile;
pub mod conntrack;
pub mod engine;
pub mod error;
pub mod l7;
pub mod nat;
pub mod nftables;
pub mod rule;
pub mod tls_policy;
pub mod zone;

pub use backend::{
    DataPathBackend, DataPathCapabilities, DataPathStats, DpdkDataPath, EbpfDataPath,
    HardwareOffloadDataPath, NftablesDataPath, compile_hot_path,
};
pub use compile::{CompiledRuleSet, RuleCompiler, render_nftables};
pub use conntrack::{ConntrackState, ConntrackTracker, FlowDirection};
pub use engine::{EvaluationContext, FirewallEngine, FirewallVerdict, FlowKey};
pub use error::FirewallError;
pub use l7::{
    AppIdentifier, HttpMatch, L7Match, L7Protocol, SignatureScanner, SniExtractor, sni_suffix_match,
};
pub use nat::{NatRule, NatTable, NatType};
pub use nftables::{MockNftables, NftablesBackend, NftablesScript, ShellNftables};
pub use rule::{FirewallRule, PortRange, Protocol, RuleAction, RuleMatch};
pub use tls_policy::{
    MissingSniPolicy, TlsBypassReason, TlsDecision, TlsDecryptReason, TlsPolicy, TlsPolicyConfig,
    TlsVerdict, industry_default_categories,
};
pub use zone::{Zone, ZonePolicy, ZoneTable};

// Re-export commonly needed types so callers don't need extra
// dependencies on sng-core / sng-policy-eval just to build a
// FirewallEngine.
pub use sng_core::traffic_class::TrafficClass;
pub use sng_policy_eval::BundleTarget;
