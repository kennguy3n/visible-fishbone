//! `sng-policy-eval` — local policy evaluation engine.
//!
//! Consumes verified policy bundles (signed by the control
//! plane, verified by `sng-comms`'s `PolicyTrustStore`) and
//! evaluates per-flow verdicts on the data path. Designed to
//! sit between the enforcement subsystem (DNS resolver, SWG,
//! NGFW, ZTNA, …) and the bundle delivery layer:
//!
//! ```text
//! sng-comms          → verified PolicyBundle.body bytes ↓
//! sng-policy-eval    → LoadedBundle (in-memory)         ↓
//! enforcement caller → Flow → Verdict                    ↓
//! ```
//!
//! Top-level entry point: [`PolicyEngine`]. Construct it from
//! a verified bundle body, then call [`PolicyEngine::evaluate`]
//! per flow. Hot-swap via [`PolicyEngine::swap`] is atomic and
//! does not block the read path.
//!
//! Architectural promises:
//!
//! * **Hot-swap** — bundle rotation is atomic; concurrent
//!   evaluators either see the entire old bundle or the entire
//!   new one. No locks on the read path.
//! * **Replay protection** — older `graph_version` rejected by
//!   default; explicit `force` for operator rollback.
//! * **Target binding** — engine is bound to a [`BundleTarget`]
//!   at construction; misrouted bundles are rejected.
//! * **Fail-closed** — unknown subject refs, unrecognised
//!   matcher kinds, and missing principals all skip the rule.
//!   The bundle's `default_action` (or `Deny` if absent) fires
//!   when nothing matches.
//! * **Wire-compatibility** — every public type round-trips
//!   through the Go-side wire shape (`internal/service/policy/`
//!   on the control plane).

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
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod bundle;
pub mod engine;
pub mod error;
pub mod flow;
pub mod matcher;
pub mod rule;
pub mod steering;
pub mod verdict;

pub use bundle::{LoadedBundle, MAX_SUPPORTED_SCHEMA_VERSION, deny_all_skeleton_body};
pub use engine::PolicyEngine;
pub use error::PolicyEvalError;
pub use flow::{Flow, FlowBuilder};
pub use matcher::{PredicateMatch, SubjectMatch};
pub use rule::{EnforcementDomain, Predicate, Rule, Subject, SubjectKind, Verb};
pub use steering::{SteeringAppRef, SteeringClassRules, SteeringRuleSet, SteeringTable};
pub use verdict::{InspectLevel, Verdict};

// Re-export the BundleTarget enum from sng-core so callers do
// not need a second `sng_core` dependency just to construct an
// engine.
pub use sng_core::policy::BundleTarget;
pub use sng_core::traffic_class::TrafficClass;
