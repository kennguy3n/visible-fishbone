//! Bootloader adapter — atomic active-bank swap + commit /
//! rollback.
//!
//! After the [`crate::bank::BankWriter`] has staged an image
//! into the inactive slot, the orchestrator asks the
//! bootloader to atomically point at that slot ("swap"). On
//! the next reboot the new image is the running image. After
//! a successful health check, the orchestrator asks the
//! bootloader to commit the swap (so the next reboot keeps
//! the new bank active); on health-check failure, it asks
//! the bootloader to roll back (pin the previous bank as
//! active again).
//!
//! Real-world implementations sit on top of EFI variables
//! (UEFI appliances), `grub-editenv` (BIOS), or u-boot's
//! `fw_setenv` (embedded / raspi). The in-process
//! [`InMemoryBootloader`] keeps the state in memory so the
//! orchestrator's state machine is testable without a real
//! firmware.
//!
//! Three core operations:
//!
//! 1. [`Bootloader::active`] — read the currently-pinned
//!    active bank.
//! 2. [`Bootloader::swap_to`] — atomically point at the
//!    other bank. The pin is "uncommitted" until either
//!    `commit` or `rollback` is called.
//! 3. [`Bootloader::commit`] / [`Bootloader::rollback`] —
//!    finalise (or revert) the swap.

use crate::bank::Bank;
use crate::error::UpdaterError;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use thiserror::Error;

/// State of the active-bank pin as the bootloader sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActiveBankState {
    /// The pin is committed — surviving the next reboot.
    Committed {
        /// Currently-pinned bank.
        bank: Bank,
    },
    /// The pin is on a swap that has not yet been
    /// health-checked. If the system reboots in this state
    /// the bootloader is expected to:
    ///
    /// * boot the new bank (so the orchestrator can prove the
    ///   image works); and
    /// * if the orchestrator does not call `commit` within the
    ///   policy's health-check window, treat the swap as
    ///   failed and roll back to `previous`.
    Pending {
        /// New bank pointed at by the pending swap.
        bank: Bank,
        /// Bank that was committed before the swap.
        previous: Bank,
    },
}

impl ActiveBankState {
    /// Returns the bank the bootloader would boot right now.
    #[must_use]
    pub fn current(self) -> Bank {
        match self {
            Self::Committed { bank } | Self::Pending { bank, .. } => bank,
        }
    }
}

/// Bootloader adapter trait. Owned by the orchestrator,
/// hot-swappable at policy reload (the production swap is
/// instantaneous, the in-memory swap is instantaneous too,
/// so the trait does not need to support concurrent
/// transitions).
#[async_trait]
pub trait Bootloader: Send + Sync {
    /// Read the currently-pinned active bank.
    async fn active(&self) -> Result<ActiveBankState, UpdaterError>;

    /// Atomically point at `bank`. Implementations MUST
    /// transition the state to `Pending { bank, previous }`
    /// and return `Ok(())`. Calling `swap_to` while a swap is
    /// already pending is rejected with
    /// [`UpdaterError::Bootloader`].
    async fn swap_to(&self, bank: Bank) -> Result<ActiveBankState, UpdaterError>;

    /// Finalise the pending swap. Transitions the state to
    /// `Committed { bank }` (where `bank` is the swap's new
    /// pin). Rejected with [`UpdaterError::Bootloader`] if no
    /// swap is pending.
    async fn commit(&self) -> Result<ActiveBankState, UpdaterError>;

    /// Roll back the pending swap. Transitions the state to
    /// `Committed { bank: previous }`. Rejected with
    /// [`UpdaterError::Bootloader`] if no swap is pending.
    async fn rollback(&self) -> Result<ActiveBankState, UpdaterError>;
}

/// Error returned by the in-process bootloader's mutators.
/// Re-exported so callers can construct expected-error
/// fixtures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootloaderError {
    /// A swap is already pending — the orchestrator must
    /// commit or rollback before issuing another swap.
    #[error("swap already pending — commit or rollback before issuing another")]
    SwapAlreadyPending,
    /// `commit` / `rollback` called with no swap pending.
    #[error("no swap pending — commit / rollback is a no-op")]
    NoSwapPending,
    /// Force-fail override surfaced.
    #[error("forced failure: {0}")]
    Forced(String),
}

/// In-process bootloader for tests. Holds an
/// [`ActiveBankState`] behind a mutex.
#[derive(Debug)]
pub struct InMemoryBootloader {
    inner: Arc<InMemoryInner>,
}

#[derive(Debug)]
struct InMemoryInner {
    state: Mutex<ActiveBankState>,
    /// Optional override that makes every subsequent mutator
    /// fail with `UpdaterError::Bootloader(msg)`.
    fail_with: Mutex<Option<String>>,
    /// Counters — exposed so tests can assert "the
    /// orchestrator committed exactly once" without inspecting
    /// the surrounding state directly.
    swap_count: Mutex<u64>,
    commit_count: Mutex<u64>,
    rollback_count: Mutex<u64>,
}

impl Default for InMemoryBootloader {
    fn default() -> Self {
        Self::new(Bank::A)
    }
}

impl InMemoryBootloader {
    /// Construct a bootloader pre-pointed at `initial` with no
    /// pending swap.
    #[must_use]
    pub fn new(initial: Bank) -> Self {
        Self {
            inner: Arc::new(InMemoryInner {
                state: Mutex::new(ActiveBankState::Committed { bank: initial }),
                fail_with: Mutex::new(None),
                swap_count: Mutex::new(0),
                commit_count: Mutex::new(0),
                rollback_count: Mutex::new(0),
            }),
        }
    }

    /// Force every subsequent mutator call to fail.
    pub fn force_failure(&self, msg: Option<String>) {
        *self.inner.fail_with.lock() = msg;
    }

    /// Total number of [`Bootloader::swap_to`] calls served.
    pub fn swap_count(&self) -> u64 {
        *self.inner.swap_count.lock()
    }

    /// Total number of [`Bootloader::commit`] calls served.
    pub fn commit_count(&self) -> u64 {
        *self.inner.commit_count.lock()
    }

    /// Total number of [`Bootloader::rollback`] calls served.
    pub fn rollback_count(&self) -> u64 {
        *self.inner.rollback_count.lock()
    }

    /// Cheap shareable handle.
    #[must_use]
    pub fn handle(&self) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[async_trait]
impl Bootloader for InMemoryBootloader {
    async fn active(&self) -> Result<ActiveBankState, UpdaterError> {
        Ok(*self.inner.state.lock())
    }

    async fn swap_to(&self, bank: Bank) -> Result<ActiveBankState, UpdaterError> {
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(UpdaterError::Bootloader(format!("forced: {msg}")));
        }
        let mut state = self.inner.state.lock();
        match *state {
            ActiveBankState::Pending { .. } => {
                Err(UpdaterError::Bootloader("swap already pending".into()))
            }
            ActiveBankState::Committed { bank: prev } => {
                let next = ActiveBankState::Pending {
                    bank,
                    previous: prev,
                };
                *state = next;
                *self.inner.swap_count.lock() += 1;
                Ok(next)
            }
        }
    }

    async fn commit(&self) -> Result<ActiveBankState, UpdaterError> {
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(UpdaterError::Bootloader(format!("forced: {msg}")));
        }
        let mut state = self.inner.state.lock();
        match *state {
            ActiveBankState::Pending { bank, .. } => {
                let next = ActiveBankState::Committed { bank };
                *state = next;
                *self.inner.commit_count.lock() += 1;
                Ok(next)
            }
            ActiveBankState::Committed { .. } => Err(UpdaterError::Bootloader(
                "no swap pending — commit is a no-op".into(),
            )),
        }
    }

    async fn rollback(&self) -> Result<ActiveBankState, UpdaterError> {
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(UpdaterError::Bootloader(format!("forced: {msg}")));
        }
        let mut state = self.inner.state.lock();
        match *state {
            ActiveBankState::Pending { previous, .. } => {
                let next = ActiveBankState::Committed { bank: previous };
                *state = next;
                *self.inner.rollback_count.lock() += 1;
                Ok(next)
            }
            ActiveBankState::Committed { .. } => Err(UpdaterError::Bootloader(
                "no swap pending — rollback is a no-op".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn cold_start_is_committed_on_a() {
        let bl = InMemoryBootloader::new(Bank::A);
        assert_eq!(
            bl.active().await.expect("active"),
            ActiveBankState::Committed { bank: Bank::A }
        );
    }

    #[tokio::test]
    async fn swap_to_marks_pending_with_previous() {
        let bl = InMemoryBootloader::new(Bank::A);
        let s = bl.swap_to(Bank::B).await.expect("swap");
        assert_eq!(
            s,
            ActiveBankState::Pending {
                bank: Bank::B,
                previous: Bank::A
            }
        );
        assert_eq!(bl.swap_count(), 1);
    }

    #[tokio::test]
    async fn double_swap_is_rejected() {
        let bl = InMemoryBootloader::new(Bank::A);
        bl.swap_to(Bank::B).await.expect("first");
        let err = bl.swap_to(Bank::A).await.expect_err("second");
        assert!(matches!(err, UpdaterError::Bootloader(_)));
    }

    #[tokio::test]
    async fn commit_finalises_pending_swap() {
        let bl = InMemoryBootloader::new(Bank::A);
        bl.swap_to(Bank::B).await.expect("swap");
        let s = bl.commit().await.expect("commit");
        assert_eq!(s, ActiveBankState::Committed { bank: Bank::B });
        assert_eq!(bl.commit_count(), 1);
    }

    #[tokio::test]
    async fn rollback_restores_previous_committed_bank() {
        let bl = InMemoryBootloader::new(Bank::A);
        bl.swap_to(Bank::B).await.expect("swap");
        let s = bl.rollback().await.expect("rollback");
        assert_eq!(s, ActiveBankState::Committed { bank: Bank::A });
        assert_eq!(bl.rollback_count(), 1);
    }

    #[tokio::test]
    async fn commit_without_pending_swap_is_rejected() {
        let bl = InMemoryBootloader::new(Bank::A);
        let err = bl.commit().await.expect_err("noop");
        assert!(matches!(err, UpdaterError::Bootloader(_)));
    }

    #[tokio::test]
    async fn rollback_without_pending_swap_is_rejected() {
        let bl = InMemoryBootloader::new(Bank::A);
        let err = bl.rollback().await.expect_err("noop");
        assert!(matches!(err, UpdaterError::Bootloader(_)));
    }

    #[tokio::test]
    async fn force_failure_surfaces_on_swap() {
        let bl = InMemoryBootloader::new(Bank::A);
        bl.force_failure(Some("efi write denied".into()));
        let err = bl.swap_to(Bank::B).await.expect_err("forced");
        assert!(matches!(err, UpdaterError::Bootloader(_)));
    }

    #[tokio::test]
    async fn active_bank_state_current_returns_pin_in_either_state() {
        let bl = InMemoryBootloader::new(Bank::A);
        assert_eq!(bl.active().await.expect("active").current(), Bank::A);
        bl.swap_to(Bank::B).await.expect("swap");
        assert_eq!(bl.active().await.expect("active").current(), Bank::B);
    }

    #[tokio::test]
    async fn handle_shares_state_with_owner() {
        let owner = InMemoryBootloader::new(Bank::A);
        let handle = owner.handle();
        owner.swap_to(Bank::B).await.expect("swap");
        let s = handle.active().await.expect("active");
        assert_eq!(s.current(), Bank::B);
        assert_eq!(handle.commit_count(), 0);
    }
}
