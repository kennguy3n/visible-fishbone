// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//
// The per-test allow set mirrors the block in
// `crates/sng-pal/src/lib.rs`. Rust attributes do not span crate
// boundaries, so the short list is duplicated here rather than
// shared through a macro. It relaxes the `unwrap`/`expect`/`panic`
// + float-comparison lints for `#[cfg(test)]` code only, where
// fast-failing fixture assertions are idiomatic.
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

//! `sng-dlp` — endpoint Data Loss Prevention for the ShieldNet
//! Gateway desktop agent.
//!
//! This crate is the on-device content-inspection engine. It takes
//! content as it crosses an egress [`channel`] (clipboard, file
//! write, print, USB copy, browser upload), classifies it against
//! the rules in the endpoint [`policy`] bundle, and emits a
//! [`engine::DlpVerdict`] the agent enforces locally.
//!
//! It is the endpoint counterpart to the control plane's web / SaaS
//! DLP service (`internal/service/dlp`): both speak the same rule
//! vocabulary (regex / keyword / fingerprint / MIP label) and the
//! same SimHash fingerprint primitive, so a rule authored once
//! detects the same content whether it leaves through the SWG or
//! off the endpoint.
//!
//! # Layout
//!
//! * [`rules`] — the [`rules::DlpRule`] data model.
//! * [`channels`] — the [`channels::DlpChannel`] taxonomy and the
//!   [`channels::ChannelInterceptor`] contract `sng-pal` implements
//!   per OS.
//! * [`classifier`] — the [`classifier::ContentClassifier`] that
//!   compiles rules into matchers and applies them.
//! * [`policy`] — the [`policy::DlpPolicy`] loaded from the endpoint
//!   bundle.
//! * [`engine`] — the [`engine::DlpEngine`] orchestrator.
//! * [`error`] — the [`error::DlpError`] taxonomy.
//!
//! # Redaction invariant
//!
//! No type in this crate ever serialises raw DLP-matched bytes. A
//! classification result and a verdict carry only *metadata* —
//! matched rule id, severity, action, confidence, and the
//! offset/length of a hit — so an emitted verdict can never leak
//! the sensitive content that produced it.

pub mod channels;
pub mod classifier;
pub mod doc_classifier;
pub mod engine;
pub mod error;
pub mod ml_classifier;
pub mod policy;
pub mod rules;
pub mod validators;

pub use channels::{
    ChannelConfig, ChannelError, ChannelInterceptor, ContentEvent, DlpChannel, InMemoryInterceptor,
};
pub use classifier::{
    ClassificationResult, ContentClassifier, ContentMetadata, ContextualScorer, DevicePosture,
    DEFAULT_MAX_SCAN_BYTES, FINGERPRINT_SIMILARITY_THRESHOLD, RuleMatch, builtin_pattern,
    hamming_similarity, luhn_valid, parse_simhash_hex, simhash,
};
pub use doc_classifier::{
    classify_document, ArchiveKind, DocSignal, DocumentClassification, DocumentType, ImageKind,
    OoxmlKind, RiskLevel,
};
pub use ml_classifier::{
    DetectedEntity, EntityClass, MlNerDetector, ModelVerifier, NerModel, RegexNerFallback,
    SignedModel,
};
pub use engine::{DlpEngine, DlpVerdict, VerdictDetails};
pub use error::{DlpError, DlpErrorCode, DlpResult};
pub use policy::{DlpPolicy, MAX_SUPPORTED_SCHEMA_VERSION};
pub use rules::{DlpRule, PatternType, RuleAction, Severity};
