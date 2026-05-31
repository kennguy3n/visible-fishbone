//! Updater policy — operator-tunable knobs that gate the
//! install flow.
//!
//! Mirrors the sister crates' (`sng-sdwan`, `sng-ztna`)
//! `PolicyHolder` pattern: the live policy is held in an
//! [`arc_swap::ArcSwap`] so reads on the hot install path are
//! lock-free and reloads are atomic. The policy is small
//! (one struct) and serialisable end-to-end so the control
//! plane can ship it as part of the per-target policy bundle.

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Duration;

/// Maximum image size the engine will accept regardless of
/// what the manifest claims. Hard upper bound — defends
/// against a control-plane bug that publishes a 1 TB manifest
/// and exhausts the appliance's disk.
pub const MAX_IMAGE_BYTES_HARD_CAP: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Default health-check window: how long the orchestrator
/// will keep probing the new bank before falling back to
/// rollback. Matches the ARCHITECTURE.md §4.9 spec ("default
/// 5 minutes").
pub const DEFAULT_HEALTH_CHECK_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Default per-probe timeout — caps any one health-check
/// call so a hanging probe does not eat the whole window.
pub const DEFAULT_HEALTH_CHECK_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Default delay between probes inside the window.
pub const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Default cap on the manifest's declared image size
/// (`image_size_bytes`). Set conservatively at 1 GiB to
/// match the realistic edge appliance image budget; can be
/// raised via [`UpdaterPolicy::max_image_bytes`].
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default number of consecutive healthy probes required
/// before the orchestrator commits the swap. Set to 1 by
/// default — operators that want a slower-to-trust rollout
/// can raise it.
pub const DEFAULT_MIN_HEALTHY_PROBES: u32 = 1;

/// Default number of attempts for the post-bootloader-commit
/// bookkeeping pair (`mark_committed` + `set_active`). The
/// bootloader has already committed atomically when this
/// runs; the retries absorb transient I/O on the
/// metadata-partition rewrite before the orchestrator gives
/// up and surfaces a divergence error.
pub const DEFAULT_POST_COMMIT_BOOKKEEPING_MAX_ATTEMPTS: u32 = 3;

/// Default initial backoff between post-commit bookkeeping
/// retries. Doubled on each successive attempt (saturating).
pub const DEFAULT_POST_COMMIT_BOOKKEEPING_BACKOFF: Duration = Duration::from_millis(50);

/// Operator-tunable policy that gates the install flow.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdaterPolicy {
    /// Maximum image size, in bytes, the engine will accept.
    /// Manifests claiming more are rejected by the verifier.
    pub max_image_bytes: u64,
    /// How long the orchestrator probes the new bank before
    /// rolling back.
    pub health_check_window: Duration,
    /// Per-probe timeout — caps any individual probe call.
    pub health_check_timeout: Duration,
    /// Delay between probes inside the window.
    pub health_check_interval: Duration,
    /// Number of consecutive healthy probes required before
    /// commit. Must be at least 1.
    pub min_healthy_probes: u32,
    /// Whether the orchestrator may install the same version
    /// into a slot that previously rolled back the same
    /// version. Defaults to `false` — defends against a
    /// known-bad release re-install loop. Operators can flip
    /// to `true` after they have manually root-caused the
    /// previous failure.
    pub allow_reinstall_of_rolled_back_version: bool,
    /// Number of attempts the orchestrator makes for the
    /// post-bootloader-commit bookkeeping pair
    /// (`mark_committed` + `set_active`) before surfacing a
    /// `PostCommitLayoutSync` divergence error. Must be at
    /// least 1. The bootloader is already committed at this
    /// point so the install IS committed; the retries are
    /// pure bookkeeping reconciliation.
    pub post_commit_bookkeeping_max_attempts: u32,
    /// Initial backoff between post-commit bookkeeping
    /// retries. Doubled on each successive attempt
    /// (saturating). Must be > 0.
    pub post_commit_bookkeeping_backoff: Duration,
}

impl Default for UpdaterPolicy {
    fn default() -> Self {
        Self {
            max_image_bytes: DEFAULT_MAX_IMAGE_BYTES,
            health_check_window: DEFAULT_HEALTH_CHECK_WINDOW,
            health_check_timeout: DEFAULT_HEALTH_CHECK_PROBE_TIMEOUT,
            health_check_interval: DEFAULT_HEALTH_CHECK_INTERVAL,
            min_healthy_probes: DEFAULT_MIN_HEALTHY_PROBES,
            allow_reinstall_of_rolled_back_version: false,
            post_commit_bookkeeping_max_attempts: DEFAULT_POST_COMMIT_BOOKKEEPING_MAX_ATTEMPTS,
            post_commit_bookkeeping_backoff: DEFAULT_POST_COMMIT_BOOKKEEPING_BACKOFF,
        }
    }
}

impl UpdaterPolicy {
    /// Validate the policy's invariants. Used by the
    /// orchestrator at construction time and on every reload
    /// so a malformed control-plane bundle fails fast rather
    /// than silently corrupting the install flow.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.max_image_bytes == 0 {
            return Err(PolicyValidationError::MaxImageBytesZero);
        }
        if self.max_image_bytes > MAX_IMAGE_BYTES_HARD_CAP {
            return Err(PolicyValidationError::MaxImageBytesExceedsHardCap {
                requested: self.max_image_bytes,
                hard_cap: MAX_IMAGE_BYTES_HARD_CAP,
            });
        }
        if self.health_check_window.is_zero() {
            return Err(PolicyValidationError::HealthCheckWindowZero);
        }
        if self.health_check_timeout.is_zero() {
            return Err(PolicyValidationError::HealthCheckTimeoutZero);
        }
        if self.health_check_interval.is_zero() {
            return Err(PolicyValidationError::HealthCheckIntervalZero);
        }
        if self.health_check_timeout > self.health_check_window {
            return Err(PolicyValidationError::HealthCheckTimeoutExceedsWindow);
        }
        if self.health_check_interval > self.health_check_window {
            return Err(PolicyValidationError::HealthCheckIntervalExceedsWindow);
        }
        if self.min_healthy_probes == 0 {
            return Err(PolicyValidationError::MinHealthyProbesZero);
        }
        if self.post_commit_bookkeeping_max_attempts == 0 {
            return Err(PolicyValidationError::PostCommitBookkeepingMaxAttemptsZero);
        }
        if self.post_commit_bookkeeping_backoff.is_zero() {
            return Err(PolicyValidationError::PostCommitBookkeepingBackoffZero);
        }
        Ok(())
    }
}

/// Policy-validation failure modes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyValidationError {
    /// `max_image_bytes` was zero.
    #[error("max_image_bytes must be > 0")]
    MaxImageBytesZero,
    /// `max_image_bytes` exceeded the hard cap.
    #[error("max_image_bytes ({requested}) exceeds hard cap ({hard_cap})")]
    MaxImageBytesExceedsHardCap {
        /// Value the operator requested.
        requested: u64,
        /// Hard cap baked into the binary.
        hard_cap: u64,
    },
    /// `health_check_window` was zero.
    #[error("health_check_window must be > 0")]
    HealthCheckWindowZero,
    /// `health_check_timeout` was zero.
    #[error("health_check_timeout must be > 0")]
    HealthCheckTimeoutZero,
    /// `health_check_interval` was zero.
    #[error("health_check_interval must be > 0")]
    HealthCheckIntervalZero,
    /// Per-probe timeout exceeded the overall window.
    #[error("health_check_timeout must not exceed health_check_window")]
    HealthCheckTimeoutExceedsWindow,
    /// Probe interval exceeded the overall window.
    #[error("health_check_interval must not exceed health_check_window")]
    HealthCheckIntervalExceedsWindow,
    /// `min_healthy_probes` was zero.
    #[error("min_healthy_probes must be >= 1")]
    MinHealthyProbesZero,
    /// `post_commit_bookkeeping_max_attempts` was zero.
    #[error("post_commit_bookkeeping_max_attempts must be >= 1")]
    PostCommitBookkeepingMaxAttemptsZero,
    /// `post_commit_bookkeeping_backoff` was zero.
    #[error("post_commit_bookkeeping_backoff must be > 0")]
    PostCommitBookkeepingBackoffZero,
}

/// Hot-swappable holder for [`UpdaterPolicy`]. Reads on the
/// install hot path go through [`Self::load`]; reloads via
/// [`Self::reload`] are atomic.
#[derive(Debug, Default)]
pub struct UpdaterPolicyHolder {
    inner: ArcSwap<UpdaterPolicy>,
}

impl UpdaterPolicyHolder {
    /// Construct from an existing policy. The policy MUST be
    /// validated before being passed in.
    #[must_use]
    pub fn new(policy: UpdaterPolicy) -> Self {
        Self {
            inner: ArcSwap::from_pointee(policy),
        }
    }

    /// Lock-free read of the current policy.
    pub fn load(&self) -> Arc<UpdaterPolicy> {
        self.inner.load_full()
    }

    /// Atomically swap to a new policy. The orchestrator
    /// validates the incoming policy before calling this; the
    /// holder itself does not re-validate (caller's
    /// responsibility).
    pub fn reload(&self, policy: UpdaterPolicy) -> Arc<UpdaterPolicy> {
        let new = Arc::new(policy);
        self.inner.store(Arc::clone(&new));
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn defaults_pass_validation() {
        UpdaterPolicy::default().validate().expect("defaults ok");
    }

    #[test]
    fn defaults_match_constants() {
        let p = UpdaterPolicy::default();
        assert_eq!(p.max_image_bytes, DEFAULT_MAX_IMAGE_BYTES);
        assert_eq!(p.health_check_window, DEFAULT_HEALTH_CHECK_WINDOW);
        assert_eq!(p.health_check_timeout, DEFAULT_HEALTH_CHECK_PROBE_TIMEOUT);
        assert_eq!(p.health_check_interval, DEFAULT_HEALTH_CHECK_INTERVAL);
        assert_eq!(p.min_healthy_probes, DEFAULT_MIN_HEALTHY_PROBES);
        assert!(!p.allow_reinstall_of_rolled_back_version);
        assert_eq!(
            p.post_commit_bookkeeping_max_attempts,
            DEFAULT_POST_COMMIT_BOOKKEEPING_MAX_ATTEMPTS
        );
        assert_eq!(
            p.post_commit_bookkeeping_backoff,
            DEFAULT_POST_COMMIT_BOOKKEEPING_BACKOFF
        );
    }

    #[test]
    fn zero_post_commit_attempts_rejected() {
        let p = UpdaterPolicy {
            post_commit_bookkeeping_max_attempts: 0,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::PostCommitBookkeepingMaxAttemptsZero)
        ));
    }

    #[test]
    fn zero_post_commit_backoff_rejected() {
        let p = UpdaterPolicy {
            post_commit_bookkeeping_backoff: Duration::ZERO,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::PostCommitBookkeepingBackoffZero)
        ));
    }

    #[test]
    fn zero_max_image_bytes_rejected() {
        let p = UpdaterPolicy {
            max_image_bytes: 0,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::MaxImageBytesZero)
        ));
    }

    #[test]
    fn max_image_bytes_above_hard_cap_rejected() {
        let p = UpdaterPolicy {
            max_image_bytes: MAX_IMAGE_BYTES_HARD_CAP + 1,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::MaxImageBytesExceedsHardCap { .. })
        ));
    }

    #[test]
    fn zero_window_rejected() {
        let p = UpdaterPolicy {
            health_check_window: Duration::ZERO,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::HealthCheckWindowZero)
        ));
    }

    #[test]
    fn zero_timeout_rejected() {
        let p = UpdaterPolicy {
            health_check_timeout: Duration::ZERO,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::HealthCheckTimeoutZero)
        ));
    }

    #[test]
    fn zero_interval_rejected() {
        let p = UpdaterPolicy {
            health_check_interval: Duration::ZERO,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::HealthCheckIntervalZero)
        ));
    }

    #[test]
    fn timeout_above_window_rejected() {
        let p = UpdaterPolicy {
            health_check_window: Duration::from_secs(10),
            health_check_timeout: Duration::from_secs(11),
            health_check_interval: Duration::from_secs(1),
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::HealthCheckTimeoutExceedsWindow)
        ));
    }

    #[test]
    fn interval_above_window_rejected() {
        let p = UpdaterPolicy {
            health_check_window: Duration::from_secs(10),
            health_check_timeout: Duration::from_secs(1),
            health_check_interval: Duration::from_secs(11),
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::HealthCheckIntervalExceedsWindow)
        ));
    }

    #[test]
    fn zero_min_healthy_probes_rejected() {
        let p = UpdaterPolicy {
            min_healthy_probes: 0,
            ..UpdaterPolicy::default()
        };
        assert!(matches!(
            p.validate(),
            Err(PolicyValidationError::MinHealthyProbesZero)
        ));
    }

    #[test]
    fn holder_reload_replaces_policy_atomically() {
        let h = UpdaterPolicyHolder::new(UpdaterPolicy::default());
        let before = h.load();
        assert_eq!(before.min_healthy_probes, DEFAULT_MIN_HEALTHY_PROBES);
        let new = UpdaterPolicy {
            min_healthy_probes: 5,
            ..UpdaterPolicy::default()
        };
        h.reload(new);
        let after = h.load();
        assert_eq!(after.min_healthy_probes, 5);
        // Old reader still sees the old value (load returns
        // an Arc snapshot — that snapshot is unaffected by
        // the reload).
        assert_eq!(before.min_healthy_probes, DEFAULT_MIN_HEALTHY_PROBES);
    }

    #[test]
    fn default_policy_holder_loads_default_policy() {
        let h = UpdaterPolicyHolder::default();
        assert_eq!(*h.load(), UpdaterPolicy::default());
    }
}
