// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// Test-only allows. Mirror what sng-fw enables so the test bodies
// can use unwrap/expect for assertion clarity without dragging
// `?` and `let ... else` boilerplate into every fixture.
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

//! IDS / IPS subsystem for the SNG edge VM.
//!
//! Wraps Suricata in inline (`AF_PACKET`, `IPS` mode) operation:
//!
//! * [`process`] — `SuricataProcess` trait with a production
//!   shell-out implementation (`ShellSuricata`) and a `MockSuricata`
//!   for tests. The trait is intentionally narrow (`start`,
//!   `stop`, `signal`, `stats`, `is_alive`) so the supervisor in
//!   [`manager`] can swap implementations without touching the
//!   surrounding control logic. The mock writes synthetic EVE
//!   JSON for the alert-normalisation tests.
//!
//! * [`config`] — translates the IPS slice of a policy bundle
//!   into a `suricata.yaml` document. The generator is
//!   deterministic and emits a compact stable-ordered YAML so two
//!   identical policy inputs produce byte-identical configs (the
//!   manager uses the SHA-256 of the rendered config to decide
//!   whether a kernel restart is needed on a hot-swap).
//!
//! * [`rules`] — rule bundle types and Ed25519 verification.
//!   The control plane signs Suricata rule bundles with the same
//!   key infrastructure that signs policy bundles
//!   ([`sng_core::policy::PolicyVerifier`]); this module reuses
//!   the same `VerifyingKey` shape but keeps the signature surface
//!   separate so rule-bundle pulls do not need the full
//!   `sng-comms` policy puller stack. The lifecycle (stage to
//!   temp dir → dry-run via `suricata -T` → atomic swap → SIGHUP
//!   to reload rules without dropping in-flight flows) is in
//!   [`rules::RuleStager`].
//!
//! * [`eve`] — streaming parser for Suricata's `eve.json` output.
//!   Each line is decoded into [`eve::EveRecord`] then mapped to
//!   the workspace event taxonomy
//!   ([`sng_core::events`]). Unknown event types are surfaced as
//!   `EveRecord::Unknown` rather than dropped so a Suricata
//!   upgrade that introduces a new event class does not silently
//!   lose telemetry.
//!
//! * [`health`] — three-state liveness machine
//!   (`Healthy` / `Degraded` / `Failed`) with configurable
//!   fail-open vs fail-closed per state. The manager drives
//!   state transitions from health-probe results (PID alive,
//!   stats socket reachable, recent EVE write).
//!
//! * [`manager`] — `IpsManager`: glues everything together.
//!   Spawns the process, tails EVE, runs health probes, accepts
//!   policy/rule swaps, surfaces normalised events on an
//!   [`sng_telemetry::EventSource`].
//!
//! ## Design boundary
//!
//! `sng-ips` does **not** implement the IDS itself — that is
//! Suricata's job, and re-implementing a 200 kLoC stream
//! reassembly + rule engine in Rust is explicitly out of scope.
//! The crate is the supervisor and the normaliser: it makes
//! Suricata behave like any other SNG subsystem (lifecycle hooks,
//! signed config delivery, EVE → `IpsEvent` normalisation,
//! telemetry source) so the rest of the edge VM does not need to
//! know that there is a separate process behind the API.
//!
//! The boundary is enforced by the [`process::SuricataProcess`]
//! trait: every subsystem-facing call goes through the trait, so
//! a future replacement (e.g. an eBPF / XDP IPS engine) only has
//! to implement the same surface to drop into the manager.

pub mod config;
pub mod error;
pub mod eve;
pub mod health;
pub mod manager;
pub mod process;
pub mod rules;
pub mod telemetry;

pub use config::{CaptureThreads, ConfigGenerator, IpsConfigInput, IpsRuntime, SuricataConfig};
pub use error::IpsError;
pub use eve::{EveAlert, EveAnomaly, EveDns, EveFileinfo, EveFlow, EveHttp, EveRecord, EveTls};
pub use health::{
    FailMode, HealthMonitor, HealthProbe, HealthState, HealthSupervisor, HealthSupervisorConfig,
    HealthThresholds, HealthTransition, SUBSYSTEM_NAME,
};
pub use manager::{IpsManager, IpsManagerConfig, IpsManagerStatus, SupervisorHandles};
pub use process::{
    MockSuricata, ProcessStatus, ShellSuricata, SuricataProcess, SuricataSignal, SuricataStats,
};
pub use rules::{
    AlwaysValidValidator, CategorySelection, FeedOutcome, FsRuleStager, IpsRuleBundle,
    IpsRuleBundleClaims, IpsRuleVerifier, RuleCategory, RuleFeed, RuleFeedFetcher, RuleSource,
    RuleStager, RuleStagerConfig, RuleStats, RuleUpdateReport, RuleUpdateScheduler, RuleValidator,
    SuricataValidator, filter_rules_by_category, rule_stats,
};
pub use telemetry::{IpsEventSink, IpsEventSource, SinkSendError};
