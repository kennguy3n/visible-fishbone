//! Dual-bank image partition model.
//!
//! The edge / agent appliance keeps two image partitions on
//! disk: Bank A and Bank B. One is the *active* bank (the
//! currently-running image) and the other is the *inactive*
//! bank (eligible to be overwritten by a new install). After
//! a successful install + health check, the bootloader swaps
//! which bank is marked active; on the next reboot the new
//! image becomes the running image. On a rollback, the
//! bootloader re-pins the previously-active bank.
//!
//! This module owns the abstract model of that layout. It does
//! NOT touch the real disk — that is the [`BankWriter`] trait's
//! job, and production deployments back it with the per-host
//! partition writer (loop-mounted on raspi-style appliances,
//! `dd` to a partition on x86 metal, a tarball into an
//! overlay-fs on the cloud VM flavour). The in-process
//! [`InMemoryBankWriter`] keeps the bytes in memory so the
//! orchestrator can be exercised end-to-end in a unit test.
//!
//! The model is deliberately small:
//!
//! * [`Bank`] — the discriminant.
//! * [`BankSlotState`] — what the metadata partition records
//!   about a slot (occupied + version, empty, or invalidated
//!   on rollback).
//! * [`BankLayout`] — the cached view of both slots'
//!   metadata, threaded through every install decision.
//! * [`BankWriter`] — the trait that actually persists bytes
//!   to a slot.

use crate::error::UpdaterError;
use crate::manifest::ImageVersion;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

/// Identifier for one of the two banks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bank {
    /// Bank A.
    A,
    /// Bank B.
    B,
}

impl Bank {
    /// Returns the bank that is *not* `self`. The orchestrator
    /// uses this to find the inactive bank from the active
    /// pin.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

impl std::fmt::Display for Bank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::B => "B",
        })
    }
}

/// State of a single bank slot as recorded in the metadata
/// partition.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BankSlotState {
    /// Slot is empty / never written.
    Empty,
    /// Slot holds a committed image. The version pin is what
    /// the verifier compares the candidate manifest against.
    Committed {
        /// Semantic version of the committed image.
        version: ImageVersion,
    },
    /// Slot holds a *staged* image — bytes written but not yet
    /// committed (i.e. the bootloader was not swapped to it).
    /// Used to support resume-after-interruption: if the
    /// engine is restarted between download-complete and
    /// bank-swap, the staged version is still on disk and the
    /// re-pull is unnecessary.
    Staged {
        /// Semantic version of the staged image.
        version: ImageVersion,
    },
    /// Slot was rolled back from — the image on it was active
    /// at one point but failed health checks after the swap.
    /// Distinct from `Committed` so the engine can refuse to
    /// re-stage the same version into the same slot without
    /// operator override (defends against a known-bad image
    /// being re-installed in a tight loop).
    RolledBack {
        /// Semantic version of the image that was rolled back.
        version: ImageVersion,
    },
}

impl BankSlotState {
    /// Returns the version pin if the slot is `Committed` or
    /// `Staged`, otherwise `None`. The verifier uses this
    /// (taking the committed-slot pin) for downgrade
    /// prevention.
    #[must_use]
    pub fn version(&self) -> Option<ImageVersion> {
        match self {
            Self::Empty => None,
            Self::Committed { version }
            | Self::Staged { version }
            | Self::RolledBack { version } => Some(*version),
        }
    }
}

/// Cached view of both slots' metadata + the active pin. The
/// orchestrator threads this through every install decision so
/// the verifier knows what version is committed and the bank
/// writer knows which slot is safe to overwrite.
///
/// This is a *snapshot*; the source-of-truth lives on the
/// metadata partition (or, in test, inside an
/// [`InMemoryBankWriter`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BankLayout {
    /// Which bank is currently active.
    pub active: Bank,
    /// State of slot A.
    pub slot_a: BankSlotState,
    /// State of slot B.
    pub slot_b: BankSlotState,
}

impl BankLayout {
    /// Cold-start layout: bank A active, both slots empty.
    /// Used for the very first install on a freshly-imaged
    /// appliance.
    #[must_use]
    pub fn cold_start() -> Self {
        Self {
            active: Bank::A,
            slot_a: BankSlotState::Empty,
            slot_b: BankSlotState::Empty,
        }
    }

    /// Construct a layout from explicit slot states.
    #[must_use]
    pub fn new(active: Bank, slot_a: BankSlotState, slot_b: BankSlotState) -> Self {
        Self {
            active,
            slot_a,
            slot_b,
        }
    }

    /// Returns the state of the active slot.
    #[must_use]
    pub fn active_state(&self) -> &BankSlotState {
        self.slot_state(self.active)
    }

    /// Returns the state of the inactive slot.
    #[must_use]
    pub fn inactive_state(&self) -> &BankSlotState {
        self.slot_state(self.active.other())
    }

    /// Returns the state of the named slot.
    #[must_use]
    pub fn slot_state(&self, slot: Bank) -> &BankSlotState {
        match slot {
            Bank::A => &self.slot_a,
            Bank::B => &self.slot_b,
        }
    }

    /// Returns the version of the currently-committed active
    /// image, if there is one.
    #[must_use]
    pub fn active_version(&self) -> Option<ImageVersion> {
        self.active_state().version()
    }

    /// The inactive bank — the slot the next install will
    /// write into.
    #[must_use]
    pub fn inactive(&self) -> Bank {
        self.active.other()
    }
}

/// Handle returned by [`BankWriter::open_for_write`] that the
/// orchestrator uses to stream bytes into an inactive slot
/// and then commit (or abandon) the write.
///
/// The handle is `async`-friendly even though the in-process
/// implementation is synchronous, so the production writer
/// can drive an async file handle without imposing an extra
/// trait on the orchestrator.
#[async_trait]
pub trait WriteHandle: Send {
    /// Stream a chunk of image bytes into the slot. The
    /// implementation MUST persist the bytes such that a
    /// subsequent [`Self::finish`] commits them to the slot.
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), UpdaterError>;

    /// Finish writing — mark the slot as `Staged` with the
    /// supplied version. Returns the new slot state so the
    /// orchestrator can update its cached [`BankLayout`].
    async fn finish(
        self: Box<Self>,
        staged_version: ImageVersion,
    ) -> Result<WriteOutcome, UpdaterError>;

    /// Abandon the in-flight write — the writer MUST leave the
    /// target slot in its previous state. Called on download
    /// failure / hash mismatch / size overrun.
    async fn abandon(self: Box<Self>) -> Result<(), UpdaterError>;
}

/// Outcome returned by [`WriteHandle::finish`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Which slot was written.
    pub slot: Bank,
    /// New state of the slot — always `BankSlotState::Staged`
    /// on success.
    pub new_state: BankSlotState,
    /// Bytes written to the slot.
    pub bytes_written: u64,
}

/// Bank-write adapter. Production implementations write to a
/// real disk partition; tests use [`InMemoryBankWriter`].
///
/// The trait is the only surface the orchestrator depends on,
/// so the install logic is exercisable without a kernel.
#[async_trait]
pub trait BankWriter: Send + Sync {
    /// Snapshot the current bank layout. The orchestrator
    /// calls this at install start to decide which slot is
    /// inactive and whether the candidate version is a
    /// downgrade.
    async fn layout(&self) -> Result<BankLayout, UpdaterError>;

    /// Open a write handle for the given slot. Implementations
    /// MUST reject a request to open the *active* slot — that
    /// would corrupt the running image.
    async fn open_for_write(&self, slot: Bank)
    -> Result<Box<dyn WriteHandle + Send>, UpdaterError>;

    /// Mark the named slot as `RolledBack` with the supplied
    /// version. Called by the orchestrator on health-check
    /// failure after a bank swap.
    async fn mark_rolled_back(&self, slot: Bank, version: ImageVersion)
    -> Result<(), UpdaterError>;

    /// Mark the named slot as `Committed` with the supplied
    /// version. Called by the orchestrator after a successful
    /// post-swap health check.
    async fn mark_committed(&self, slot: Bank, version: ImageVersion) -> Result<(), UpdaterError>;

    /// Update the metadata-partition record of which slot is
    /// active. The orchestrator calls this after the
    /// bootloader has been swapped, so subsequent
    /// [`Self::layout`] calls reflect the new active slot
    /// pin. In a real deployment this is implemented as a
    /// metadata-partition rewrite alongside the bootloader
    /// config update; the in-memory writer just bumps the
    /// in-process layout.
    async fn set_active(&self, slot: Bank) -> Result<(), UpdaterError>;
}

/// Error returned by [`InMemoryBankWriter::open_for_write`].
/// Re-exported so callers can construct expected-error fixtures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BankWriterError {
    /// Caller asked to open the active slot for write.
    #[error("cannot open active slot {0} for write — that would corrupt the running image")]
    SlotIsActive(Bank),
    /// Force-fail override surfaced.
    #[error("forced failure: {0}")]
    Forced(String),
}

/// In-process bank writer for tests. Holds both slots' bytes
/// and metadata behind a mutex, exposes hooks for tests to
/// inject failure modes.
#[derive(Debug, Default)]
pub struct InMemoryBankWriter {
    inner: Arc<InMemoryInner>,
}

#[derive(Debug, Default)]
struct InMemoryInner {
    layout: Mutex<BankLayout>,
    slot_a_bytes: Mutex<Vec<u8>>,
    slot_b_bytes: Mutex<Vec<u8>>,
    /// Optional override that makes every subsequent
    /// `open_for_write` fail with the supplied message.
    fail_open_with: Mutex<Option<String>>,
    /// Optional override that makes every subsequent
    /// `finish` fail with the supplied message.
    fail_finish_with: Mutex<Option<String>>,
    /// Optional countdown of `set_active` failures — each
    /// remaining tick decrements and surfaces a forced error.
    /// When the counter reaches zero the call succeeds. Used
    /// to exercise the post-commit retry loop in the
    /// orchestrator.
    set_active_failures_remaining: Mutex<u32>,
    /// Optional message to attach to the forced `set_active`
    /// failures (defaults to `"emulated transient io"`).
    set_active_failure_message: Mutex<Option<String>>,
    /// Total `set_active` invocations — used by tests to
    /// confirm the retry loop actually ran the configured
    /// number of times.
    set_active_call_count: AtomicU32,
    /// Optional countdown of `mark_committed` failures.
    /// Same semantics as `set_active_failures_remaining`.
    mark_committed_failures_remaining: Mutex<u32>,
    /// Optional message to attach to the forced
    /// `mark_committed` failures.
    mark_committed_failure_message: Mutex<Option<String>>,
    /// Total `mark_committed` invocations.
    mark_committed_call_count: AtomicU32,
}

impl InMemoryBankWriter {
    /// Construct a cold-start writer (Bank A active, both
    /// slots empty).
    #[must_use]
    pub fn cold_start() -> Self {
        Self::with_layout(BankLayout::cold_start())
    }

    /// Construct with a specific initial layout — useful for
    /// "what happens on an already-committed appliance" tests.
    #[must_use]
    pub fn with_layout(layout: BankLayout) -> Self {
        let inner = InMemoryInner {
            layout: Mutex::new(layout),
            ..InMemoryInner::default()
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Override the layout (e.g. to simulate a bootloader swap
    /// in tests).
    pub fn set_layout(&self, layout: BankLayout) {
        *self.inner.layout.lock() = layout;
    }

    /// Inspect the bytes currently in the named slot. Returns
    /// a clone so the caller can hash / inspect without
    /// holding the lock.
    pub fn slot_bytes(&self, slot: Bank) -> Vec<u8> {
        match slot {
            Bank::A => self.inner.slot_a_bytes.lock().clone(),
            Bank::B => self.inner.slot_b_bytes.lock().clone(),
        }
    }

    /// Force every subsequent `open_for_write` call to fail.
    pub fn force_open_failure(&self, msg: Option<String>) {
        *self.inner.fail_open_with.lock() = msg;
    }

    /// Force every subsequent `finish` call to fail.
    pub fn force_finish_failure(&self, msg: Option<String>) {
        *self.inner.fail_finish_with.lock() = msg;
    }

    /// Force the next `count` `set_active` calls to fail with
    /// the supplied message (or a default). After the counter
    /// is exhausted, calls succeed normally. Used to exercise
    /// the orchestrator's post-commit retry loop without
    /// reaching for real I/O failures.
    pub fn force_transient_set_active_failures(&self, count: u32, msg: Option<String>) {
        *self.inner.set_active_failures_remaining.lock() = count;
        *self.inner.set_active_failure_message.lock() = msg;
    }

    /// Number of `set_active` calls observed since the writer
    /// was constructed.
    #[must_use]
    pub fn set_active_call_count(&self) -> u32 {
        self.inner.set_active_call_count.load(Ordering::Relaxed)
    }

    /// Force the next `count` `mark_committed` calls to fail
    /// with the supplied message. Mirror of
    /// `force_transient_set_active_failures` for the other half
    /// of the post-commit bookkeeping pair.
    pub fn force_transient_mark_committed_failures(&self, count: u32, msg: Option<String>) {
        *self.inner.mark_committed_failures_remaining.lock() = count;
        *self.inner.mark_committed_failure_message.lock() = msg;
    }

    /// Number of `mark_committed` calls observed since the
    /// writer was constructed.
    #[must_use]
    pub fn mark_committed_call_count(&self) -> u32 {
        self.inner.mark_committed_call_count.load(Ordering::Relaxed)
    }

    /// Cheap shareable handle.
    #[must_use]
    pub fn handle(&self) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

impl Default for BankLayout {
    fn default() -> Self {
        Self::cold_start()
    }
}

struct InMemoryWriteHandle {
    slot: Bank,
    buffer: Vec<u8>,
    inner: Arc<InMemoryInner>,
}

#[async_trait]
impl WriteHandle for InMemoryWriteHandle {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), UpdaterError> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(
        self: Box<Self>,
        staged_version: ImageVersion,
    ) -> Result<WriteOutcome, UpdaterError> {
        if let Some(msg) = self.inner.fail_finish_with.lock().clone() {
            return Err(UpdaterError::BankWrite(format!("forced: {msg}")));
        }
        let bytes_written = self.buffer.len() as u64;
        match self.slot {
            Bank::A => *self.inner.slot_a_bytes.lock() = self.buffer,
            Bank::B => *self.inner.slot_b_bytes.lock() = self.buffer,
        }
        let new_state = BankSlotState::Staged {
            version: staged_version,
        };
        {
            let mut layout = self.inner.layout.lock();
            match self.slot {
                Bank::A => layout.slot_a = new_state.clone(),
                Bank::B => layout.slot_b = new_state.clone(),
            }
        }
        Ok(WriteOutcome {
            slot: self.slot,
            new_state,
            bytes_written,
        })
    }

    async fn abandon(self: Box<Self>) -> Result<(), UpdaterError> {
        // Drop the buffer; the on-disk slot stays as it was
        // before `open_for_write` returned a handle. The
        // simulated metadata partition was never touched, so
        // there is nothing to roll back.
        drop(self.buffer);
        Ok(())
    }
}

#[async_trait]
impl BankWriter for InMemoryBankWriter {
    async fn layout(&self) -> Result<BankLayout, UpdaterError> {
        Ok(self.inner.layout.lock().clone())
    }

    async fn open_for_write(
        &self,
        slot: Bank,
    ) -> Result<Box<dyn WriteHandle + Send>, UpdaterError> {
        if let Some(msg) = self.inner.fail_open_with.lock().clone() {
            return Err(UpdaterError::BankWrite(format!("forced: {msg}")));
        }
        let layout = self.inner.layout.lock();
        if layout.active == slot {
            return Err(UpdaterError::BankWrite(format!(
                "cannot open active slot {slot} for write"
            )));
        }
        drop(layout);
        let h = InMemoryWriteHandle {
            slot,
            buffer: Vec::new(),
            inner: Arc::clone(&self.inner),
        };
        Ok(Box::new(h))
    }

    async fn mark_rolled_back(
        &self,
        slot: Bank,
        version: ImageVersion,
    ) -> Result<(), UpdaterError> {
        let mut layout = self.inner.layout.lock();
        let new_state = BankSlotState::RolledBack { version };
        match slot {
            Bank::A => layout.slot_a = new_state,
            Bank::B => layout.slot_b = new_state,
        }
        Ok(())
    }

    async fn mark_committed(&self, slot: Bank, version: ImageVersion) -> Result<(), UpdaterError> {
        self.inner
            .mark_committed_call_count
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut remaining = self.inner.mark_committed_failures_remaining.lock();
            if *remaining > 0 {
                *remaining -= 1;
                let msg = self
                    .inner
                    .mark_committed_failure_message
                    .lock()
                    .clone()
                    .unwrap_or_else(|| "emulated transient io".into());
                return Err(UpdaterError::BankWrite(format!("forced: {msg}")));
            }
        }
        let mut layout = self.inner.layout.lock();
        let new_state = BankSlotState::Committed { version };
        match slot {
            Bank::A => layout.slot_a = new_state,
            Bank::B => layout.slot_b = new_state,
        }
        Ok(())
    }

    async fn set_active(&self, slot: Bank) -> Result<(), UpdaterError> {
        self.inner
            .set_active_call_count
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut remaining = self.inner.set_active_failures_remaining.lock();
            if *remaining > 0 {
                *remaining -= 1;
                let msg = self
                    .inner
                    .set_active_failure_message
                    .lock()
                    .clone()
                    .unwrap_or_else(|| "emulated transient io".into());
                return Err(UpdaterError::BankWrite(format!("forced: {msg}")));
            }
        }
        self.inner.layout.lock().active = slot;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn bank_other_swaps_a_and_b() {
        assert_eq!(Bank::A.other(), Bank::B);
        assert_eq!(Bank::B.other(), Bank::A);
    }

    #[test]
    fn cold_start_layout_has_a_active_both_empty() {
        let l = BankLayout::cold_start();
        assert_eq!(l.active, Bank::A);
        assert_eq!(l.slot_a, BankSlotState::Empty);
        assert_eq!(l.slot_b, BankSlotState::Empty);
        assert!(l.active_version().is_none());
        assert_eq!(l.inactive(), Bank::B);
    }

    #[test]
    fn slot_state_version_returns_pinned_version() {
        let v = ImageVersion::new(1, 2, 3);
        assert!(BankSlotState::Empty.version().is_none());
        assert_eq!(BankSlotState::Committed { version: v }.version(), Some(v));
        assert_eq!(BankSlotState::Staged { version: v }.version(), Some(v));
        assert_eq!(BankSlotState::RolledBack { version: v }.version(), Some(v));
    }

    #[tokio::test]
    async fn in_memory_writer_reports_initial_layout() {
        let w = InMemoryBankWriter::cold_start();
        let layout = w.layout().await.expect("layout");
        assert_eq!(layout, BankLayout::cold_start());
    }

    #[tokio::test]
    async fn open_for_write_rejects_active_slot() {
        let w = InMemoryBankWriter::cold_start();
        match w.open_for_write(Bank::A).await {
            Err(UpdaterError::BankWrite(_)) => {}
            Err(other) => panic!("expected BankWrite, got {other:?}"),
            Ok(_) => panic!("expected error, got handle"),
        }
    }

    #[tokio::test]
    async fn write_and_finish_marks_slot_as_staged() {
        let w = InMemoryBankWriter::cold_start();
        let mut h = w.open_for_write(Bank::B).await.expect("open");
        h.write_chunk(&[1, 2, 3, 4]).await.expect("write");
        h.write_chunk(&[5, 6, 7, 8]).await.expect("write");
        let outcome = h.finish(ImageVersion::new(2, 0, 0)).await.expect("finish");
        assert_eq!(outcome.slot, Bank::B);
        assert_eq!(outcome.bytes_written, 8);
        assert_eq!(
            outcome.new_state,
            BankSlotState::Staged {
                version: ImageVersion::new(2, 0, 0)
            }
        );
        // Bytes were persisted to slot B.
        assert_eq!(w.slot_bytes(Bank::B), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        // Layout was updated.
        let layout = w.layout().await.expect("layout");
        assert_eq!(
            layout.slot_b,
            BankSlotState::Staged {
                version: ImageVersion::new(2, 0, 0)
            }
        );
        // Active bank UNCHANGED — that happens on the
        // bootloader swap, not on the bank-write commit.
        assert_eq!(layout.active, Bank::A);
    }

    #[tokio::test]
    async fn abandon_leaves_slot_unchanged() {
        let w = InMemoryBankWriter::cold_start();
        let mut h = w.open_for_write(Bank::B).await.expect("open");
        h.write_chunk(&[1, 2, 3]).await.expect("write");
        h.abandon().await.expect("abandon");
        assert_eq!(w.slot_bytes(Bank::B), Vec::<u8>::new());
        let layout = w.layout().await.expect("layout");
        assert_eq!(layout.slot_b, BankSlotState::Empty);
    }

    #[tokio::test]
    async fn force_open_failure_surfaces_bank_write_error() {
        let w = InMemoryBankWriter::cold_start();
        w.force_open_failure(Some("disk full".into()));
        match w.open_for_write(Bank::B).await {
            Err(UpdaterError::BankWrite(_)) => {}
            Err(other) => panic!("expected BankWrite, got {other:?}"),
            Ok(_) => panic!("expected error, got handle"),
        }
    }

    #[tokio::test]
    async fn force_finish_failure_surfaces_after_partial_write() {
        let w = InMemoryBankWriter::cold_start();
        w.force_finish_failure(Some("fsync rejected".into()));
        let mut h = w.open_for_write(Bank::B).await.expect("open");
        h.write_chunk(&[1, 2, 3]).await.expect("write");
        let err = h
            .finish(ImageVersion::new(1, 0, 0))
            .await
            .expect_err("forced");
        assert!(matches!(err, UpdaterError::BankWrite(_)));
    }

    #[tokio::test]
    async fn mark_committed_updates_slot_state() {
        let w = InMemoryBankWriter::cold_start();
        w.mark_committed(Bank::A, ImageVersion::new(1, 0, 0))
            .await
            .expect("commit");
        let l = w.layout().await.expect("layout");
        assert_eq!(
            l.slot_a,
            BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0)
            }
        );
    }

    #[tokio::test]
    async fn mark_rolled_back_updates_slot_state() {
        let w = InMemoryBankWriter::cold_start();
        w.mark_rolled_back(Bank::B, ImageVersion::new(2, 0, 0))
            .await
            .expect("rollback");
        let l = w.layout().await.expect("layout");
        assert_eq!(
            l.slot_b,
            BankSlotState::RolledBack {
                version: ImageVersion::new(2, 0, 0)
            }
        );
    }

    #[tokio::test]
    async fn handle_shares_layout_with_owner() {
        let owner = InMemoryBankWriter::cold_start();
        let handle = owner.handle();
        owner
            .mark_committed(Bank::A, ImageVersion::new(1, 1, 1))
            .await
            .expect("commit");
        let l = handle.layout().await.expect("layout");
        assert_eq!(
            l.slot_a,
            BankSlotState::Committed {
                version: ImageVersion::new(1, 1, 1)
            }
        );
    }

    #[test]
    fn bank_layout_slot_state_accessors_match_active_pin() {
        let layout = BankLayout::new(
            Bank::B,
            BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0),
            },
            BankSlotState::Committed {
                version: ImageVersion::new(2, 0, 0),
            },
        );
        assert_eq!(
            layout.active_state(),
            &BankSlotState::Committed {
                version: ImageVersion::new(2, 0, 0)
            }
        );
        assert_eq!(
            layout.inactive_state(),
            &BankSlotState::Committed {
                version: ImageVersion::new(1, 0, 0)
            }
        );
        assert_eq!(layout.active_version(), Some(ImageVersion::new(2, 0, 0)));
        assert_eq!(layout.inactive(), Bank::A);
    }
}
