//! 4G/5G cellular backup paths.
//!
//! Cellular links are the *last-resort* underlay: metered,
//! often slower, but available when every wired path is
//! down. This module adds the cellular-specific metadata
//! the brain needs to treat a [`crate::Path`] as a
//! data-capped backup, plus the budget accounting that
//! keeps the gateway from silently burning through a SIM's
//! monthly allowance.
//!
//! ## Pieces
//!
//! - [`CellularSignal`] — radio metadata (RSSI + bars /
//!   carrier-reported quality) so dashboards and steering
//!   can prefer a stronger modem.
//! - [`CellularPath`] — a [`crate::Path`] enriched with
//!   carrier, signal, and a *snapshot* of remaining data
//!   cap. The authoritative, live accounting lives in
//!   [`CellularBudget`].
//! - [`CellularBudget`] — lock-free data-cap accounting
//!   with the steering predicate
//!   [`CellularBudget::should_use_cellular`]: cellular is
//!   used **only** when wired paths have failed SLA *and*
//!   the budget is not exhausted.
//!
//! ## Failover integration
//!
//! A [`CellularPath`] is wired into a
//! [`crate::failover::FailoverPolicy`] as the *lowest-
//! priority* backup (appended last to `backup_paths`). The
//! failover engine only resolves onto it when every
//! higher-priority wired member is unhealthy, which is
//! exactly the "wired paths failed SLA" condition the
//! budget predicate also guards — see
//! [`CellularPath::into_failover_backup`].

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::SdwanError;
use crate::path::{Path, PathId};

/// Radio signal metadata for a cellular modem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellularSignal {
    /// Received signal strength indicator, dBm (negative;
    /// closer to zero is stronger, e.g. `-65` is excellent,
    /// `-110` is barely usable).
    pub rssi_dbm: i32,
    /// Carrier-reported signal bars, `0..=5`.
    pub bars: u8,
}

impl CellularSignal {
    /// Construct, clamping `bars` into `0..=5`.
    #[must_use]
    pub const fn new(rssi_dbm: i32, bars: u8) -> Self {
        Self {
            rssi_dbm,
            bars: if bars > 5 { 5 } else { bars },
        }
    }

    /// A coarse usability test: at least one bar and an
    /// RSSI above the typical `-110 dBm` floor.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        self.bars >= 1 && self.rssi_dbm > -110
    }
}

/// A [`Path`] enriched with cellular metadata.
///
/// The `path` carries the normal steering identity /
/// eligibility; the cellular fields add carrier, signal,
/// and a snapshot of remaining data cap for dashboards.
/// Live cap enforcement is [`CellularBudget`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CellularPath {
    /// The underlying steering path.
    pub path: Path,
    /// Carrier / APN label (`verizon`, `att`, …).
    pub carrier: String,
    /// Most-recent radio signal observation.
    pub signal: CellularSignal,
    /// Snapshot of remaining data cap in megabytes; `None`
    /// for an unmetered plan. Authoritative accounting is
    /// [`CellularBudget`]; this is a denormalised copy for
    /// reporting.
    #[serde(default)]
    pub data_cap_remaining_mb: Option<u64>,
}

impl CellularPath {
    /// Construct a cellular path.
    pub fn new(path: Path, carrier: impl Into<String>, signal: CellularSignal) -> Self {
        Self {
            path,
            carrier: carrier.into(),
            signal,
            data_cap_remaining_mb: None,
        }
    }

    /// Attach a remaining-cap snapshot (builder shape).
    #[must_use]
    pub fn with_data_cap_remaining_mb(mut self, remaining_mb: Option<u64>) -> Self {
        self.data_cap_remaining_mb = remaining_mb;
        self
    }

    /// This path's id, for wiring into a failover policy.
    #[must_use]
    pub fn id(&self) -> &PathId {
        &self.path.id
    }

    /// Consume into the [`PathId`] to append as the
    /// lowest-priority backup of a
    /// [`crate::failover::FailoverPolicy`].
    #[must_use]
    pub fn into_failover_backup(self) -> PathId {
        self.path.id
    }

    /// Validate the underlying path plus cellular fields.
    ///
    /// # Errors
    ///
    /// Propagates [`Path::validate`] errors and rejects an
    /// empty carrier label.
    pub fn validate(&self) -> Result<(), SdwanError> {
        self.path.validate()?;
        if self.carrier.is_empty() {
            return Err(SdwanError::InvalidPolicy(format!(
                "cellular path {:?} has an empty carrier label",
                self.path.id.as_str()
            )));
        }
        Ok(())
    }
}

/// Lock-free data-cap accounting for a cellular link.
///
/// `cap_mb == None` is an unmetered plan (never
/// exhausted). Usage is tracked with a single relaxed
/// atomic so the data path can credit bytes without a lock.
#[derive(Debug)]
pub struct CellularBudget {
    cap_mb: Option<u64>,
    used_mb: AtomicU64,
}

impl CellularBudget {
    /// A metered budget with a monthly cap in megabytes.
    #[must_use]
    pub fn metered(cap_mb: u64) -> Self {
        Self {
            cap_mb: Some(cap_mb),
            used_mb: AtomicU64::new(0),
        }
    }

    /// An unmetered budget — cellular is never gated by
    /// data cap (still last-resort by failover priority).
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            cap_mb: None,
            used_mb: AtomicU64::new(0),
        }
    }

    /// The configured cap in megabytes, if metered.
    #[must_use]
    pub fn cap_mb(&self) -> Option<u64> {
        self.cap_mb
    }

    /// Megabytes consumed so far this period.
    #[must_use]
    pub fn used_mb(&self) -> u64 {
        self.used_mb.load(Ordering::Relaxed)
    }

    /// Remaining megabytes, or `None` when unmetered.
    /// Saturates at zero.
    #[must_use]
    pub fn remaining_mb(&self) -> Option<u64> {
        self.cap_mb.map(|cap| cap.saturating_sub(self.used_mb()))
    }

    /// Credit `mb` of cellular usage. Returns the new total
    /// consumed.
    pub fn record_usage(&self, mb: u64) -> u64 {
        self.used_mb.fetch_add(mb, Ordering::Relaxed) + mb
    }

    /// Reset the period counter (e.g. on monthly rollover).
    pub fn reset(&self) {
        self.used_mb.store(0, Ordering::Relaxed);
    }

    /// True iff the cap has been reached. Unmetered budgets
    /// are never exhausted.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        match self.cap_mb {
            Some(cap) => self.used_mb() >= cap,
            None => false,
        }
    }

    /// The steering predicate: cellular should carry the
    /// flow **only** when the wired paths are not healthy
    /// *and* the budget is not exhausted.
    ///
    /// `wired_healthy` is the caller's roll-up of whether
    /// any non-cellular path currently meets SLA. This keeps
    /// the policy ("avoid cellular unless wired fails SLA")
    /// in one place.
    #[must_use]
    pub fn should_use_cellular(&self, wired_healthy: bool) -> bool {
        !wired_healthy && !self.exhausted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    use crate::path::TrafficClass;

    fn cell_path() -> CellularPath {
        let path = Path::new(PathId::new("lte"), [TrafficClass::BestEffort]);
        CellularPath::new(path, "verizon", CellularSignal::new(-72, 4))
    }

    #[test]
    fn signal_clamps_bars() {
        assert_eq!(CellularSignal::new(-70, 9).bars, 5);
    }

    #[test]
    fn signal_usability() {
        assert!(CellularSignal::new(-70, 3).is_usable());
        assert!(!CellularSignal::new(-120, 0).is_usable());
        assert!(!CellularSignal::new(-70, 0).is_usable());
    }

    #[test]
    fn metered_budget_tracks_usage() {
        let b = CellularBudget::metered(1_000);
        assert_eq!(b.remaining_mb(), Some(1_000));
        assert_eq!(b.record_usage(400), 400);
        assert_eq!(b.remaining_mb(), Some(600));
        assert!(!b.exhausted());
        b.record_usage(600);
        assert!(b.exhausted());
        assert_eq!(b.remaining_mb(), Some(0));
    }

    #[test]
    fn remaining_saturates_when_over_cap() {
        let b = CellularBudget::metered(100);
        b.record_usage(250);
        assert_eq!(b.remaining_mb(), Some(0));
        assert!(b.exhausted());
    }

    #[test]
    fn unmetered_budget_never_exhausts() {
        let b = CellularBudget::unmetered();
        b.record_usage(1_000_000);
        assert!(!b.exhausted());
        assert_eq!(b.remaining_mb(), None);
    }

    #[test]
    fn reset_clears_usage() {
        let b = CellularBudget::metered(100);
        b.record_usage(100);
        assert!(b.exhausted());
        b.reset();
        assert!(!b.exhausted());
        assert_eq!(b.used_mb(), 0);
    }

    #[test]
    fn should_use_cellular_only_when_wired_down_and_budget_left() {
        let b = CellularBudget::metered(100);
        // Wired healthy → never use cellular.
        assert!(!b.should_use_cellular(true));
        // Wired down, budget remaining → use cellular.
        assert!(b.should_use_cellular(false));
        // Wired down but budget exhausted → do not use.
        b.record_usage(100);
        assert!(!b.should_use_cellular(false));
    }

    #[test]
    fn cellular_path_validate_rejects_empty_carrier() {
        let mut p = cell_path();
        p.carrier = String::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn cellular_path_into_failover_backup_yields_id() {
        let p = cell_path();
        assert_eq!(p.into_failover_backup(), PathId::new("lte"));
    }

    #[test]
    fn cellular_path_validate_ok() {
        assert!(cell_path().validate().is_ok());
    }
}
