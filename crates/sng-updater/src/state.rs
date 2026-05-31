//! Install state machine.
//!
//! The orchestrator drives the install through a strict
//! sequence of states. Every transition is enumerated up
//! front so a logic bug (e.g. "commit fired while download
//! still in flight") fails closed with a structured error
//! rather than silently doing the wrong thing.
//!
//! ## States
//!
//! ```text
//!     ┌────────┐    new manifest    ┌─────────────┐
//!     │  Idle  │ ─────────────────▶ │ Downloading │
//!     └────────┘                    └──────┬──────┘
//!         ▲                                ▼
//!         │                         ┌─────────────┐
//!         │                         │  Verifying  │
//!         │                         └──────┬──────┘
//!         │                                ▼
//!         │                         ┌─────────────┐
//!         │                         │ Installing  │
//!         │                         └──────┬──────┘
//!         │                                ▼
//!         │                         ┌─────────────┐
//!         │                         │  Rebooting  │
//!         │                         └──────┬──────┘
//!         │                                ▼
//!         │                         ┌──────────────┐
//!         │                         │HealthChecking│
//!         │                         └─┬──────────┬─┘
//!         │                           │          │
//!         │  pass                     │          │ fail / timeout
//!         │ ┌─────────────────────────┘          │
//!         │ ▼                                    ▼
//!         │ ┌──────────┐                  ┌────────────┐
//!         └─┤ Committed│                  │ RolledBack │──┐
//!           └──────────┘                  └────────────┘  │
//!                                              │          │
//!                                              ▼          │
//!                                          (back to Idle) ◀
//! ```
//!
//! ## Transitions
//!
//! Legal transitions are encoded in [`UpdateState::can_transition_to`]
//! and validated by [`UpdateState::transition_to`]. Anything else
//! returns [`UpdaterError::StateTransition`].

use thiserror::Error;

/// Error returned when a state transition is rejected.
///
/// Lives in `state.rs` (not `error.rs`) so the state machine
/// has no dependency on the broader [`crate::error::UpdaterError`]
/// taxonomy. `UpdaterError::StateTransition` wraps this via
/// `#[from]` so callers in the orchestrator continue to see a
/// single `UpdaterError` shape on the wire.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("illegal updater state transition: {from} -> {to}")]
pub struct StateTransitionError {
    /// State the orchestrator tried to transition FROM.
    pub from: UpdateState,
    /// State the orchestrator tried to transition TO.
    pub to: UpdateState,
}

/// Install state machine.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// No install in flight. Resting state — the orchestrator
    /// enters and exits the install cycle here.
    #[default]
    Idle,
    /// Streaming image bytes through the SHA-256 hasher into
    /// the inactive bank.
    Downloading,
    /// Verifying the streaming receipt against the manifest's
    /// declared SHA-256 + size. (Note: the manifest signature
    /// is verified BEFORE entering Downloading; this state is
    /// the post-download integrity check.)
    Verifying,
    /// Writing finalisation metadata into the slot (bumping
    /// it from `Empty` to `Staged`).
    Installing,
    /// Bootloader has been swapped to the staged slot;
    /// awaiting the OS-level reboot. The orchestrator's
    /// in-process state machine treats this as a checkpoint —
    /// after a real reboot the orchestrator resumes from this
    /// state and proceeds to HealthChecking.
    Rebooting,
    /// Running the post-swap health probe loop.
    HealthChecking,
    /// Probe passed within the configured window. Bootloader
    /// commit has been issued; the slot's
    /// [`crate::bank::BankSlotState`] is now `Committed`.
    Committed,
    /// Probe failed (or timed out). Bootloader rollback has
    /// been issued; the slot's
    /// [`crate::bank::BankSlotState`] is now `RolledBack`.
    RolledBack,
}

impl UpdateState {
    /// Returns the set of states this one may transition to.
    /// Used by the orchestrator to gate every step.
    ///
    /// Returns a `Vec` rather than a `&'static [UpdateState]`
    /// because `Vec` is what callers consume — and the cost
    /// is paid at most once per install attempt, which
    /// happens once every few weeks per appliance.
    #[must_use]
    pub fn legal_successors(self) -> Vec<Self> {
        match self {
            Self::Idle => vec![Self::Downloading],
            Self::Downloading => vec![Self::Verifying, Self::Idle], // Idle on abort.
            Self::Verifying => vec![Self::Installing, Self::Idle],
            Self::Installing => vec![Self::Rebooting, Self::Idle],
            Self::Rebooting => vec![Self::HealthChecking, Self::RolledBack],
            Self::HealthChecking => vec![Self::Committed, Self::RolledBack],
            Self::Committed | Self::RolledBack => vec![Self::Idle],
        }
    }

    /// Returns true iff `self` may transition to `next` per
    /// the rules in [`Self::legal_successors`].
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self.legal_successors().contains(&next)
    }

    /// Attempt to transition. Returns the new state on
    /// success; returns [`StateTransitionError`] on an illegal
    /// jump. The orchestrator wraps the error into
    /// [`crate::error::UpdaterError::StateTransition`] via its
    /// `#[from]` impl.
    pub fn transition_to(self, next: Self) -> Result<Self, StateTransitionError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(StateTransitionError {
                from: self,
                to: next,
            })
        }
    }

    /// Returns true iff this state is a terminal install
    /// outcome (either `Committed` or `RolledBack`).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack)
    }

    /// Returns true iff this state allows the orchestrator to
    /// accept a fresh manifest (i.e. start a new install).
    /// Only `Idle` qualifies.
    #[must_use]
    pub fn accepts_new_install(self) -> bool {
        matches!(self, Self::Idle)
    }
}

impl std::fmt::Display for UpdateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Idle => "idle",
            Self::Downloading => "downloading",
            Self::Verifying => "verifying",
            Self::Installing => "installing",
            Self::Rebooting => "rebooting",
            Self::HealthChecking => "health_checking",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_state_is_idle() {
        assert_eq!(UpdateState::default(), UpdateState::Idle);
    }

    #[test]
    fn idle_only_advances_to_downloading() {
        assert!(UpdateState::Idle.can_transition_to(UpdateState::Downloading));
        assert!(!UpdateState::Idle.can_transition_to(UpdateState::Verifying));
        assert!(!UpdateState::Idle.can_transition_to(UpdateState::Committed));
    }

    #[test]
    fn full_happy_path_chain_legal() {
        let chain = [
            UpdateState::Idle,
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::Installing,
            UpdateState::Rebooting,
            UpdateState::HealthChecking,
            UpdateState::Committed,
            UpdateState::Idle,
        ];
        let mut current = chain[0];
        for &next in &chain[1..] {
            current = current.transition_to(next).expect("legal");
        }
        assert_eq!(current, UpdateState::Idle);
    }

    #[test]
    fn rolled_back_chain_legal() {
        let chain = [
            UpdateState::Idle,
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::Installing,
            UpdateState::Rebooting,
            UpdateState::HealthChecking,
            UpdateState::RolledBack,
            UpdateState::Idle,
        ];
        let mut current = chain[0];
        for &next in &chain[1..] {
            current = current.transition_to(next).expect("legal");
        }
        assert_eq!(current, UpdateState::Idle);
    }

    #[test]
    fn rebooting_can_short_circuit_to_rolled_back_on_swap_failure() {
        // If the bootloader swap succeeds but the appliance
        // never boots into HealthChecking (e.g. firmware
        // crash), the orchestrator marks RolledBack directly
        // from Rebooting.
        let r = UpdateState::Rebooting
            .transition_to(UpdateState::RolledBack)
            .expect("legal");
        assert_eq!(r, UpdateState::RolledBack);
    }

    #[test]
    fn illegal_transitions_return_state_transition_error() {
        let err = UpdateState::Idle
            .transition_to(UpdateState::Committed)
            .expect_err("illegal");
        assert_eq!(err.from, UpdateState::Idle);
        assert_eq!(err.to, UpdateState::Committed);
        let msg = err.to_string();
        assert!(msg.contains("idle"));
        assert!(msg.contains("committed"));
    }

    #[test]
    fn downloading_can_abort_to_idle() {
        // Manifest signature failure / hash mismatch /
        // size overflow — the orchestrator aborts the
        // download and resets the state machine without
        // touching the bootloader.
        let r = UpdateState::Downloading
            .transition_to(UpdateState::Idle)
            .expect("abort");
        assert_eq!(r, UpdateState::Idle);
    }

    #[test]
    fn terminal_predicate_only_matches_committed_and_rolled_back() {
        for s in [
            UpdateState::Idle,
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::Installing,
            UpdateState::Rebooting,
            UpdateState::HealthChecking,
        ] {
            assert!(!s.is_terminal(), "{s:?} should not be terminal");
        }
        assert!(UpdateState::Committed.is_terminal());
        assert!(UpdateState::RolledBack.is_terminal());
    }

    #[test]
    fn accepts_new_install_only_in_idle() {
        for s in [
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::Installing,
            UpdateState::Rebooting,
            UpdateState::HealthChecking,
            UpdateState::Committed,
            UpdateState::RolledBack,
        ] {
            assert!(
                !s.accepts_new_install(),
                "{s:?} should not accept a new install"
            );
        }
        assert!(UpdateState::Idle.accepts_new_install());
    }

    #[test]
    fn display_is_snake_case_for_each_state() {
        assert_eq!(UpdateState::Idle.to_string(), "idle");
        assert_eq!(UpdateState::Downloading.to_string(), "downloading");
        assert_eq!(UpdateState::Verifying.to_string(), "verifying");
        assert_eq!(UpdateState::Installing.to_string(), "installing");
        assert_eq!(UpdateState::Rebooting.to_string(), "rebooting");
        assert_eq!(UpdateState::HealthChecking.to_string(), "health_checking");
        assert_eq!(UpdateState::Committed.to_string(), "committed");
        assert_eq!(UpdateState::RolledBack.to_string(), "rolled_back");
    }
}
