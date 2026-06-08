//! Application-aware steering.
//!
//! Where [`crate::SdwanService`] steers by *traffic class*
//! (the latency-sensitivity bucket on a
//! [`crate::SteeringRequest`]), application-aware steering
//! adds a finer layer: an operator maps a specific
//! application id (from the app registry the classification
//! engine resolves) onto a *preferred path order* and an
//! [`crate::sla::SlaClass`]. A flow for `app:zoom` can be
//! pinned to the low-jitter underlay and held to the
//! `real-time` SLA, independent of how the coarse traffic
//! class would have scored it.
//!
//! ## SLA-class derivation
//!
//! When an app has no explicit rule, its SLA class is
//! derived from the security [`sng_core::TrafficClass`] the
//! classification engine assigned, per the spec mapping:
//!
//! | security class           | SLA class           |
//! |--------------------------|---------------------|
//! | `inspect_full`           | `business-critical` |
//! | `trusted_media_bypass`   | `real-time`         |
//! | everything else          | `best-effort`       |
//!
//! See [`default_sla_class`].
//!
//! ## Sticky pinning
//!
//! Stateful protocols (RDP, SSH, long-lived TLS) break if
//! mid-session packets hop underlays. Each resolved
//! `(app, path)` is pinned for
//! [`AppSteeringTable`]'s configured timeout; subsequent
//! resolutions for the same app return the pinned path as
//! long as it stays among the supplied healthy candidates
//! and the pin is fresh. The pin cache is bounded and
//! sweeps expired entries on insert, mirroring the
//! flow-level sticky cache in [`crate::service`].

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use sng_core::TrafficClass as SecurityClass;

use crate::error::SdwanError;
use crate::path::PathId;
use crate::sla::SlaClass;

/// Default SLA class for a security traffic class, used
/// when no explicit [`AppSteeringRule`] applies.
///
/// `inspect_full` → business-critical (the conservative
/// baseline carries the tightest SLA so unknown but
/// inspected traffic is protected); `trusted_media_bypass`
/// → real-time (media flows are jitter-sensitive);
/// everything else → best-effort.
#[must_use]
pub const fn default_sla_class(class: SecurityClass) -> SlaClass {
    match class {
        SecurityClass::InspectFull => SlaClass::BusinessCritical,
        SecurityClass::TrustedMediaBypass => SlaClass::RealTime,
        SecurityClass::TrustedDirect
        | SecurityClass::InspectLite
        | SecurityClass::TunnelPrivate
        | SecurityClass::Block => SlaClass::BestEffort,
    }
}

/// Maps one application id onto a preferred path order and
/// an SLA class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppSteeringRule {
    /// Application identifier from the app registry
    /// (`zoom`, `o365`, `salesforce`, …).
    pub app_id: String,
    /// Preferred paths in descending priority. The
    /// resolver picks the first one present in the healthy
    /// candidate set.
    pub preferred_paths: Vec<PathId>,
    /// SLA class this app is held to (drives which
    /// [`crate::sla::SlaPolicy`] the SLA monitor applies to
    /// the app's flows).
    pub sla_class: SlaClass,
}

impl AppSteeringRule {
    /// Construct a rule.
    pub fn new<I>(app_id: impl Into<String>, preferred_paths: I, sla_class: SlaClass) -> Self
    where
        I: IntoIterator<Item = PathId>,
    {
        Self {
            app_id: app_id.into(),
            preferred_paths: preferred_paths.into_iter().collect(),
            sla_class,
        }
    }

    /// Validate the value domain.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when `app_id`
    /// is empty, when `preferred_paths` is empty (the rule
    /// could never steer), or when any preferred path id is
    /// empty.
    pub fn validate(&self) -> Result<(), SdwanError> {
        if self.app_id.is_empty() {
            return Err(SdwanError::InvalidPolicy(
                "app_steering rule app_id must not be empty".into(),
            ));
        }
        if self.preferred_paths.is_empty() {
            return Err(SdwanError::InvalidPolicy(format!(
                "app_steering rule {:?} has no preferred_paths",
                self.app_id
            )));
        }
        if self.preferred_paths.iter().any(|p| p.as_str().is_empty()) {
            return Err(SdwanError::InvalidPolicy(format!(
                "app_steering rule {:?} has an empty preferred path id",
                self.app_id
            )));
        }
        Ok(())
    }
}

/// A sticky pin: the path an app is held to until
/// `pinned_until_ms`.
#[derive(Clone, Copy, Debug)]
struct AppPin {
    path_idx: usize,
    pinned_until_ms: u64,
}

/// Default sticky-pin timeout (30 s) — long enough to
/// survive a short stall, short enough that a path that
/// went unhealthy is not pinned forever.
const DEFAULT_PIN_TIMEOUT_MS: u64 = 30_000;

/// Default sticky-pin cache capacity. Bounded so a churn
/// of distinct app ids cannot grow the map without bound.
const DEFAULT_PIN_CAPACITY: usize = 4_096;

/// Outcome of an app-steering resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SteerOutcome {
    /// Returned the previously-pinned path (sticky hit).
    Sticky(PathId),
    /// Selected a fresh preferred path and pinned it.
    Selected(PathId),
    /// No rule for the app, or no preferred path was among
    /// the healthy candidates.
    NoMatch,
}

impl SteerOutcome {
    /// The chosen path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&PathId> {
        match self {
            Self::Sticky(p) | Self::Selected(p) => Some(p),
            Self::NoMatch => None,
        }
    }
}

/// Application-aware steering table: rules + a bounded
/// sticky-pin cache.
#[derive(Debug)]
pub struct AppSteeringTable {
    rules: HashMap<String, AppSteeringRule>,
    pin_timeout_ms: u64,
    capacity: usize,
    pins: Mutex<HashMap<String, AppPin>>,
}

impl Default for AppSteeringTable {
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            pin_timeout_ms: DEFAULT_PIN_TIMEOUT_MS,
            capacity: DEFAULT_PIN_CAPACITY,
            pins: Mutex::new(HashMap::new()),
        }
    }
}

impl AppSteeringTable {
    /// Build from an iterator of rules, with the default
    /// pin timeout / capacity. A duplicate `app_id` keeps
    /// the last rule.
    pub fn from_rules<I: IntoIterator<Item = AppSteeringRule>>(rules: I) -> Self {
        let mut by_app = HashMap::new();
        for rule in rules {
            by_app.insert(rule.app_id.clone(), rule);
        }
        Self {
            rules: by_app,
            ..Self::default()
        }
    }

    /// Override the sticky-pin timeout (milliseconds).
    #[must_use]
    pub fn with_pin_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.pin_timeout_ms = timeout_ms;
        self
    }

    /// Override the sticky-pin cache capacity.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Validate every contained rule.
    ///
    /// # Errors
    ///
    /// Propagates the first [`SdwanError::InvalidPolicy`]
    /// from any [`AppSteeringRule::validate`].
    pub fn validate(&self) -> Result<(), SdwanError> {
        for rule in self.rules.values() {
            rule.validate()?;
        }
        Ok(())
    }

    /// Rule for `app_id`, if any.
    #[must_use]
    pub fn rule(&self, app_id: &str) -> Option<&AppSteeringRule> {
        self.rules.get(app_id)
    }

    /// The SLA class an app is held to: its explicit rule's
    /// class if it has one, otherwise the
    /// [`default_sla_class`] of the supplied security
    /// class.
    #[must_use]
    pub fn sla_class_for(&self, app_id: &str, security_class: SecurityClass) -> SlaClass {
        self.rules
            .get(app_id)
            .map_or_else(|| default_sla_class(security_class), |r| r.sla_class)
    }

    /// Number of live (unexpired-on-read is not enforced
    /// here) sticky pins.
    #[must_use]
    pub fn pin_count(&self) -> usize {
        self.pins.lock().len()
    }

    /// Resolve the path for `app_id` given the set of
    /// currently-healthy candidate paths and the wall-clock
    /// time.
    ///
    /// Resolution order:
    /// 1. **Sticky hit** — a fresh pin whose path is still
    ///    among `healthy` is returned unchanged (avoids
    ///    mid-session flaps).
    /// 2. **Fresh select** — the first `preferred_paths`
    ///    entry present in `healthy` is chosen and pinned.
    /// 3. **No match** — no rule, or no preferred path is
    ///    healthy.
    pub fn resolve(&self, app_id: &str, healthy: &[PathId], now_ms: u64) -> SteerOutcome {
        let Some(rule) = self.rules.get(app_id) else {
            return SteerOutcome::NoMatch;
        };

        let mut pins = self.pins.lock();

        // 1. Sticky hit: pinned path still healthy + fresh.
        if let Some(pin) = pins.get(app_id)
            && pin.pinned_until_ms > now_ms
            && let Some(path) = rule.preferred_paths.get(pin.path_idx)
            && healthy.contains(path)
        {
            return SteerOutcome::Sticky(path.clone());
        }

        // 2. Fresh select: first preferred path that is
        //    healthy, by priority order.
        let pick = rule
            .preferred_paths
            .iter()
            .enumerate()
            .find(|(_, p)| healthy.contains(p));
        let Some((idx, path)) = pick else {
            // No preferred path healthy — drop any stale pin
            // so a later resolution re-selects cleanly.
            pins.remove(app_id);
            return SteerOutcome::NoMatch;
        };

        self.insert_pin(&mut pins, app_id, idx, now_ms);
        SteerOutcome::Selected(path.clone())
    }

    /// Insert / refresh a pin, evicting expired entries
    /// first and, if still at capacity, the soonest-to-
    /// expire entry. Keeps the cache bounded.
    fn insert_pin(
        &self,
        pins: &mut HashMap<String, AppPin>,
        app_id: &str,
        path_idx: usize,
        now_ms: u64,
    ) {
        let pin = AppPin {
            path_idx,
            pinned_until_ms: now_ms.saturating_add(self.pin_timeout_ms),
        };
        if pins.contains_key(app_id) {
            pins.insert(app_id.to_string(), pin);
            return;
        }
        if pins.len() >= self.capacity {
            // Sweep expired entries first.
            pins.retain(|_, p| p.pinned_until_ms > now_ms);
            if pins.len() >= self.capacity {
                // Still full — evict the soonest-to-expire.
                if let Some(victim) = pins
                    .iter()
                    .min_by_key(|(_, p)| p.pinned_until_ms)
                    .map(|(k, _)| k.clone())
                {
                    pins.remove(&victim);
                }
            }
        }
        pins.insert(app_id.to_string(), pin);
    }

    /// Drop the sticky pin for `app_id` (e.g. on session
    /// teardown), so the next resolution re-selects.
    pub fn unpin(&self, app_id: &str) {
        self.pins.lock().remove(app_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn table() -> AppSteeringTable {
        AppSteeringTable::from_rules([
            AppSteeringRule::new(
                "zoom",
                [PathId::new("inet"), PathId::new("lte")],
                SlaClass::RealTime,
            ),
            AppSteeringRule::new(
                "o365",
                [PathId::new("mpls"), PathId::new("inet")],
                SlaClass::BusinessCritical,
            ),
        ])
    }

    #[test]
    fn default_sla_class_follows_spec_mapping() {
        assert_eq!(
            default_sla_class(SecurityClass::InspectFull),
            SlaClass::BusinessCritical
        );
        assert_eq!(
            default_sla_class(SecurityClass::TrustedMediaBypass),
            SlaClass::RealTime
        );
        assert_eq!(
            default_sla_class(SecurityClass::TrustedDirect),
            SlaClass::BestEffort
        );
        assert_eq!(
            default_sla_class(SecurityClass::Block),
            SlaClass::BestEffort
        );
    }

    #[test]
    fn sla_class_for_prefers_explicit_rule() {
        let t = table();
        // Explicit rule overrides the security-class default.
        assert_eq!(
            t.sla_class_for("zoom", SecurityClass::InspectFull),
            SlaClass::RealTime
        );
        // Unknown app falls back to the security-class default.
        assert_eq!(
            t.sla_class_for("unknown", SecurityClass::InspectFull),
            SlaClass::BusinessCritical
        );
    }

    #[test]
    fn resolve_picks_first_healthy_preferred_path() {
        let t = table();
        let healthy = vec![PathId::new("lte"), PathId::new("inet")];
        let out = t.resolve("zoom", &healthy, 1_000);
        // inet is higher priority than lte in zoom's rule.
        assert_eq!(out, SteerOutcome::Selected(PathId::new("inet")));
    }

    #[test]
    fn resolve_falls_through_to_lower_priority_when_top_unhealthy() {
        let t = table();
        let healthy = vec![PathId::new("lte")];
        let out = t.resolve("zoom", &healthy, 1_000);
        assert_eq!(out, SteerOutcome::Selected(PathId::new("lte")));
    }

    #[test]
    fn resolve_sticky_holds_path_across_calls() {
        let t = table();
        let healthy = vec![PathId::new("inet"), PathId::new("lte")];
        assert_eq!(
            t.resolve("zoom", &healthy, 1_000),
            SteerOutcome::Selected(PathId::new("inet"))
        );
        // Second call within timeout → sticky hit, same path.
        assert_eq!(
            t.resolve("zoom", &healthy, 5_000),
            SteerOutcome::Sticky(PathId::new("inet"))
        );
    }

    #[test]
    fn resolve_repins_after_timeout() {
        let t = AppSteeringTable::from_rules([AppSteeringRule::new(
            "zoom",
            [PathId::new("inet"), PathId::new("lte")],
            SlaClass::RealTime,
        )])
        .with_pin_timeout_ms(1_000);
        let healthy = vec![PathId::new("inet"), PathId::new("lte")];
        assert_eq!(
            t.resolve("zoom", &healthy, 1_000),
            SteerOutcome::Selected(PathId::new("inet"))
        );
        // Past the timeout → re-select (still inet, but a
        // fresh Selected not a Sticky).
        assert_eq!(
            t.resolve("zoom", &healthy, 3_000),
            SteerOutcome::Selected(PathId::new("inet"))
        );
    }

    #[test]
    fn resolve_unhealthy_pinned_path_reselects() {
        let t = table();
        let healthy = vec![PathId::new("inet"), PathId::new("lte")];
        assert_eq!(
            t.resolve("zoom", &healthy, 1_000),
            SteerOutcome::Selected(PathId::new("inet"))
        );
        // inet goes unhealthy → fall to lte even though pin
        // points at inet.
        let degraded = vec![PathId::new("lte")];
        assert_eq!(
            t.resolve("zoom", &degraded, 2_000),
            SteerOutcome::Selected(PathId::new("lte"))
        );
    }

    #[test]
    fn resolve_unknown_app_is_no_match() {
        let t = table();
        let healthy = vec![PathId::new("inet")];
        assert_eq!(t.resolve("unknown", &healthy, 1_000), SteerOutcome::NoMatch);
    }

    #[test]
    fn resolve_no_healthy_preferred_is_no_match() {
        let t = table();
        let healthy = vec![PathId::new("mpls")];
        assert_eq!(t.resolve("zoom", &healthy, 1_000), SteerOutcome::NoMatch);
    }

    #[test]
    fn unpin_drops_sticky() {
        let t = table();
        let healthy = vec![PathId::new("inet")];
        t.resolve("zoom", &healthy, 1_000);
        assert_eq!(t.pin_count(), 1);
        t.unpin("zoom");
        assert_eq!(t.pin_count(), 0);
    }

    #[test]
    fn pin_cache_is_bounded() {
        let t = AppSteeringTable::from_rules((0..10).map(|i| {
            AppSteeringRule::new(
                format!("app{i}"),
                [PathId::new("inet")],
                SlaClass::BestEffort,
            )
        }))
        .with_capacity(4);
        let healthy = vec![PathId::new("inet")];
        for i in 0..10 {
            t.resolve(&format!("app{i}"), &healthy, 1_000 + i);
        }
        assert!(t.pin_count() <= 4, "pin cache exceeded capacity");
    }

    #[test]
    fn validate_rejects_empty_preferred_paths() {
        let rule = AppSteeringRule::new("zoom", [], SlaClass::RealTime);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn steer_outcome_path_accessor() {
        assert_eq!(
            SteerOutcome::Selected(PathId::new("inet")).path(),
            Some(&PathId::new("inet"))
        );
        assert_eq!(SteerOutcome::NoMatch.path(), None);
    }
}
