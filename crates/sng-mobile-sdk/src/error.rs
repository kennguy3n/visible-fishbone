// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! The stable foreign error contract.
//!
//! [`MobileSdkError`] is the single error type every fallible SDK
//! method returns across the FFI boundary. It is a **flat,
//! owned-data** translation of the agent core's internal
//! [`MobileError`] taxonomy plus the SDK-level failure classes
//! (config parsing, the OIDC sign-in flow, and the
//! platform-unsupported host fallback). The internal error carries
//! `#[from]` chains and non-FFI-safe payloads (`Duration`,
//! `Arc<dyn …>`-backed sources); this type flattens each class to a
//! single human-readable `description` string so Swift / Kotlin
//! consumers get a stable, exhaustive enum they can `switch` on
//! without depending on any of the agent's transitive crates.
//!
//! ## Why `description`, not `message`
//!
//! Every variant names its payload `description` rather than the
//! more obvious `message`. UniFFI's Kotlin generator emits each
//! error variant as a subclass of `kotlin.Exception`, which already
//! exposes a `message: String?` property via `Throwable`; a variant
//! field also named `message` shadows it and produces a
//! duplicate-declaration compile error in the generated Kotlin. The
//! `Display` impl (`#[error("…")]`) still feeds `Throwable.message`
//! for logging, so nothing is lost on either binding.

use sng_mobile_core::AuthError;
use sng_oidc::{AuthSurfaceError, OidcError};

/// The foreign-facing error enum for every `sng-mobile-sdk`
/// operation.
///
/// `uniffi::Error` requires the type implement `Error`
/// (`thiserror::Error` supplies `Display` + `std::error::Error`)
/// and be `Send + Sync + 'static`, which a plain
/// `String`-payloaded enum satisfies.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum MobileSdkError {
    /// An FFI config record could not be mapped onto a valid
    /// [`sng_mobile_core::MobileAgentConfig`] (e.g. a tenant /
    /// device id that is not a UUID, or a malformed trust-anchor
    /// key). Distinct from [`Self::Config`], which is the core's
    /// own post-construction validation failure.
    #[error("invalid configuration: {description}")]
    InvalidConfig {
        /// Human-readable detail.
        description: String,
    },

    /// The agent core rejected the configuration during validation.
    #[error("config invalid: {description}")]
    Config {
        /// Human-readable detail.
        description: String,
    },

    /// The claim-token enrolment exchange failed.
    #[error("enrolment failed: {description}")]
    Enrollment {
        /// Human-readable detail.
        description: String,
    },

    /// The platform secure key store rejected an operation.
    #[error("secure key store: {description}")]
    KeyStore {
        /// Human-readable detail.
        description: String,
    },

    /// The OIDC auth session has no usable token / a refresh was
    /// rejected.
    #[error("auth session: {description}")]
    Auth {
        /// Human-readable detail.
        description: String,
    },

    /// Persisting / loading the OIDC token set failed.
    #[error("token storage: {description}")]
    TokenStorage {
        /// Human-readable detail.
        description: String,
    },

    /// The platform posture collector failed.
    #[error("posture collection: {description}")]
    Posture {
        /// Human-readable detail.
        description: String,
    },

    /// The platform tunnel provider rejected a start / stop.
    #[error("tunnel provider: {description}")]
    Tunnel {
        /// Human-readable detail.
        description: String,
    },

    /// A ZTNA access evaluation failed.
    #[error("ztna evaluation: {description}")]
    Ztna {
        /// Human-readable detail.
        description: String,
    },

    /// Control-plane transport failure.
    #[error("control plane: {description}")]
    Comms {
        /// Human-readable detail.
        description: String,
    },

    /// A signed policy bundle failed verification.
    #[error("policy bundle: {description}")]
    Policy {
        /// Human-readable detail.
        description: String,
    },

    /// Telemetry envelope encode / decode failure.
    #[error("wire: {description}")]
    Wire {
        /// Human-readable detail.
        description: String,
    },

    /// A bounded network operation exceeded its deadline.
    #[error("operation timed out: {description}")]
    Timeout {
        /// Human-readable detail.
        description: String,
    },

    /// A lifecycle transition was requested that the agent's
    /// current state does not permit.
    #[error("lifecycle: {description}")]
    Lifecycle {
        /// Human-readable detail.
        description: String,
    },

    /// The interactive OIDC sign-in flow failed (discovery,
    /// browser presentation, code exchange, or ID-token
    /// validation).
    #[error("sign-in failed: {description}")]
    SignIn {
        /// Human-readable detail.
        description: String,
    },

    /// The requested operation is not supported on the current
    /// platform. Returned by the Linux host fallback so a CI /
    /// desktop build surfaces a typed "unsupported" rather than a
    /// fake success.
    #[error("platform unsupported: {description}")]
    Unsupported {
        /// Human-readable detail.
        description: String,
    },

    /// An error class the agent core introduced after this binding
    /// was built. Reached only via the `#[non_exhaustive]`
    /// [`sng_mobile_core::MobileError`] fallback, so a new core
    /// variant surfaces as a neutral "unknown" rather than being
    /// mislabelled as a configuration error.
    #[error("unknown error: {description}")]
    Unknown {
        /// Human-readable detail.
        description: String,
    },
}

impl MobileSdkError {
    /// Construct a [`Self::InvalidConfig`] from any displayable
    /// value.
    pub(crate) fn invalid_config(detail: impl std::fmt::Display) -> Self {
        Self::InvalidConfig {
            description: detail.to_string(),
        }
    }

    /// Construct a [`Self::SignIn`] from any displayable value.
    pub(crate) fn sign_in(detail: impl std::fmt::Display) -> Self {
        Self::SignIn {
            description: detail.to_string(),
        }
    }
}

impl From<sng_mobile_core::MobileError> for MobileSdkError {
    fn from(err: sng_mobile_core::MobileError) -> Self {
        use sng_mobile_core::MobileError as E;
        // The flattened `Display` of each source preserves the
        // `#[from]` chain's detail in the single `description`
        // string. `MobileError` is `#[non_exhaustive]`, so the
        // wildcard arm keeps this mapping compiling if the core
        // adds a new failure class — it degrades to the neutral
        // `Unknown` class carrying the new variant's `Display`,
        // never a panic.
        let description = err.to_string();
        match err {
            E::Config(_) => Self::Config { description },
            E::Enrollment(_) => Self::Enrollment { description },
            E::KeyStore(_) => Self::KeyStore { description },
            E::Auth(_) => Self::Auth { description },
            E::TokenStorage(_) => Self::TokenStorage { description },
            E::Posture(_) => Self::Posture { description },
            E::Tunnel(_) => Self::Tunnel { description },
            E::Ztna(_) => Self::Ztna { description },
            E::Comms(_) => Self::Comms { description },
            E::Policy(_) => Self::Policy { description },
            E::Wire(_) => Self::Wire { description },
            E::Timeout(_) => Self::Timeout { description },
            E::Lifecycle(_) => Self::Lifecycle { description },
            // `MobileError` is `#[non_exhaustive]`: any future
            // variant maps to the neutral `Unknown` class (carrying
            // its `Display`) rather than breaking the build, leaking
            // an untyped panic, or being mislabelled as a config
            // error.
            _ => Self::Unknown { description },
        }
    }
}

impl From<AuthError> for MobileSdkError {
    fn from(err: AuthError) -> Self {
        Self::Auth {
            description: err.to_string(),
        }
    }
}

impl From<OidcError> for MobileSdkError {
    fn from(err: OidcError) -> Self {
        Self::SignIn {
            description: err.to_string(),
        }
    }
}

impl From<AuthSurfaceError> for MobileSdkError {
    fn from(err: AuthSurfaceError) -> Self {
        Self::SignIn {
            description: err.to_string(),
        }
    }
}
