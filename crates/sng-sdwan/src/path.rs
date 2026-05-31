//! Underlay path catalog.
//!
//! A [`Path`] is one underlay (MPLS, internet-A,
//! internet-B, LTE, …) the SD-WAN brain can steer flows
//! onto. The catalog is conceptually owned by the
//! tenant's policy bundle but exposed through a
//! [`PathProvider`] so the orchestrator stays I/O-free
//! and bundle-adapter / runtime-tests can plug in
//! different sources.
//!
//! ## Identity
//!
//! Paths are keyed by a [`PathId`] — a small, opaque
//! string the operator chose (`mpls-east`, `inet-prim`,
//! `lte-failover`). The id is also what
//! [`crate::SteeringDecision::path_id`] surfaces and what
//! [`sng_core::events::SdwanEvent::path_id`] carries on
//! the wire. The id is intentionally not numeric — it
//! shows up in dashboards and runbooks, so the human-
//! readable string wins over an interned u32.

use crate::error::SdwanError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Identifier for a single underlay path. Cheap to clone
/// because the underlying string lives inside the
/// `Arc<str>`-backed pool that policy/probe providers
/// share.
///
/// Derives `PartialOrd` / `Ord` (lex on the underlying
/// `String`) so the selector can deterministically
/// tie-break two candidates with mathematically equal
/// scores by preferring the lex-smaller id. See
/// `SdwanService::evaluate` for where this is consumed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PathId(pub String);

impl PathId {
    /// Construct from anything that converts to a `String`.
    /// No length validation here — the policy holder
    /// rejects empty ids during validation, so the type
    /// itself stays as cheap as a `String` newtype.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the underlying id as a `&str` for hashing,
    /// comparisons, and wire emission.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for PathId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for PathId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Traffic class an [`crate::SteeringRequest`] declares.
///
/// The variants are ordered from latency-sensitive
/// (`RealTime`) to bulk-throughput (`Bulk`); the path
/// catalog's [`Path::eligible_classes`] gates which
/// classes may select a given path.
///
/// Wire-stable lowercase strings are pinned in
/// [`TrafficClass::as_str`] so the
/// [`sng_core::events::SdwanEvent::steering_decision`]
/// field stays operator-readable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClass {
    /// Voice / video / interactive (e.g. SIP, WebRTC).
    /// Most latency-sensitive bucket.
    RealTime,
    /// Standard interactive (HTTPS, RDP, SSH).
    Interactive,
    /// Best-effort browsing and CDN.
    BestEffort,
    /// Bulk transfer (backup, sync, OS update). Least
    /// latency-sensitive.
    Bulk,
}

impl TrafficClass {
    /// Stable wire string. Used by the bundle adapter
    /// when encoding the eligibility set, and by ops
    /// dashboards that group decisions by traffic class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealTime => "real_time",
            Self::Interactive => "interactive",
            Self::BestEffort => "best_effort",
            Self::Bulk => "bulk",
        }
    }
}

/// One underlay path the brain can steer onto.
///
/// Construct via [`Path::new`] and feed into a
/// [`StaticPathProvider`] (or your own bundle-adapter
/// provider). The catalog is read-only on the data path;
/// reloads go through [`crate::SdwanPolicyHolder`] via
/// the `policy::SdwanPolicy::paths` field (whole-table
/// swap).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Path {
    /// Operator-chosen identifier (`mpls-east`,
    /// `inet-prim`, `lte-failover`). Surfaces in
    /// [`crate::SteeringDecision::path_id`] and on the
    /// wire as [`sng_core::events::SdwanEvent::path_id`].
    pub id: PathId,
    /// The set of traffic classes this path is eligible
    /// for. A class missing from the set is rejected at
    /// candidate-filter time (the path will never appear
    /// in a [`SteeringDecision`] for that class).
    pub eligible_classes: Vec<TrafficClass>,
    /// Static cost-bias added to the computed
    /// [`crate::ScoreBreakdown::total`] for this path.
    /// Operators use this to nudge a path down (negative
    /// bias) or up (positive bias) in the ranking without
    /// changing the global [`crate::ScoreWeights`].
    /// Defaults to `0.0`.
    ///
    /// Finiteness is enforced in two places:
    ///
    /// 1. [`Path::validate`] — the primary gate. Bundle
    ///    adapters that build a `StaticPathProvider` from
    ///    decoded bundle bytes call it on every path before
    ///    constructing the provider, so a non-finite
    ///    `static_bias` is rejected at load time alongside
    ///    other bundle-validity checks.
    /// 2. [`crate::score::score_path`] — defense-in-depth.
    ///    Even if a misbehaving adapter bypassed
    ///    `Path::validate`, the score function collapses a
    ///    non-finite bias to [`crate::ScoreBreakdown::worst`]
    ///    so the path can never win the selector.
    ///
    /// The previous version of this doc referred to
    /// `SdwanPolicy::validate`, but the
    /// [`crate::policy::SdwanPolicy`] struct does not own
    /// the path catalog — paths live in the
    /// [`PathProvider`] — so the per-`Path` validator is
    /// where this invariant actually lives.
    #[serde(default)]
    pub static_bias: f32,
}

impl Path {
    /// Construct with `id` + a list of eligible classes.
    /// `static_bias` defaults to `0.0`.
    pub fn new<I>(id: impl Into<PathId>, eligible_classes: I) -> Self
    where
        I: IntoIterator<Item = TrafficClass>,
    {
        Self {
            id: id.into(),
            eligible_classes: eligible_classes.into_iter().collect(),
            static_bias: 0.0,
        }
    }

    /// Set the static bias on this path. Builder shape so
    /// path tables read cleanly inline (`Path::new(…).with_bias(…)`).
    #[must_use]
    pub fn with_bias(mut self, bias: f32) -> Self {
        self.static_bias = bias;
        self
    }

    /// True iff this path is eligible for `class`.
    #[must_use]
    pub fn eligible(&self, class: TrafficClass) -> bool {
        self.eligible_classes.contains(&class)
    }

    /// Value-domain validation. Bundle adapters call this
    /// on every decoded path before installing the
    /// catalog so an invalid path is rejected at load
    /// time rather than silently turning into a never-
    /// winning candidate via
    /// [`crate::score::score_path`]'s defense-in-depth
    /// guard.
    ///
    /// # Errors
    ///
    /// Returns [`SdwanError::InvalidPolicy`] when:
    ///
    /// - `id` is empty (the path could not be referenced
    ///   by [`crate::SteeringDecision::path_id`] or by
    ///   the sticky-flow cache).
    /// - `eligible_classes` is empty (the path would
    ///   never appear in any candidate set).
    /// - `static_bias` is `NaN` or infinite.
    pub fn validate(&self) -> Result<(), SdwanError> {
        if self.id.as_str().is_empty() {
            return Err(SdwanError::InvalidPolicy(
                "path id must not be empty".into(),
            ));
        }
        if self.eligible_classes.is_empty() {
            return Err(SdwanError::InvalidPolicy(format!(
                "path {:?} declares no eligible_classes — it would never be selected",
                self.id.as_str()
            )));
        }
        if !self.static_bias.is_finite() {
            return Err(SdwanError::InvalidPolicy(format!(
                "path {:?} static_bias must be finite (got {})",
                self.id.as_str(),
                self.static_bias
            )));
        }
        Ok(())
    }
}

/// Read-only catalog of underlay paths.
///
/// Implementations of this trait must be cheap to call on
/// the hot path. The orchestrator calls
/// [`PathProvider::candidates`] once per
/// [`crate::SteeringRequest`].
pub trait PathProvider: Send + Sync + std::fmt::Debug {
    /// All paths eligible for the requested traffic class.
    /// The returned list MAY be empty — the orchestrator
    /// maps "empty candidates" to
    /// [`crate::SteeringReason::NoAvailablePath`].
    fn candidates(&self, class: TrafficClass) -> Vec<Arc<Path>>;

    /// Lookup a single path by id. Used by the bundle
    /// adapter to attach probes / by tests to introspect.
    fn get(&self, id: &PathId) -> Option<Arc<Path>>;
}

/// Trivial in-memory catalog. The bundle adapter
/// constructs one of these from the decoded policy
/// bundle's path table.
#[derive(Debug, Default)]
pub struct StaticPathProvider {
    by_id: HashMap<PathId, Arc<Path>>,
}

impl StaticPathProvider {
    /// Construct from an iterator of paths. Duplicate ids
    /// are not allowed — the last one wins, but the
    /// policy validator runs before this constructor so
    /// duplicates are rejected at bundle-load time.
    ///
    /// Does NOT call [`Path::validate`] — callers that
    /// want value-domain validation (bundle adapters,
    /// production wiring) should use
    /// [`Self::try_from_paths`] instead. The infallible
    /// constructor exists for tests/fixtures that
    /// intentionally exercise edge-case paths.
    pub fn from_paths<I: IntoIterator<Item = Path>>(paths: I) -> Self {
        let mut by_id: HashMap<PathId, Arc<Path>> = HashMap::new();
        for p in paths {
            by_id.insert(p.id.clone(), Arc::new(p));
        }
        Self { by_id }
    }

    /// Validating constructor. Calls [`Path::validate`]
    /// on every entry before installing the catalog and
    /// rejects duplicate ids (a duplicate would silently
    /// shadow the earlier entry).
    ///
    /// # Errors
    ///
    /// - [`SdwanError::InvalidPolicy`] when any path
    ///   fails [`Path::validate`].
    /// - [`SdwanError::InvalidPolicy`] when a duplicate
    ///   path id is observed.
    pub fn try_from_paths<I: IntoIterator<Item = Path>>(paths: I) -> Result<Self, SdwanError> {
        let mut by_id: HashMap<PathId, Arc<Path>> = HashMap::new();
        for p in paths {
            p.validate()?;
            if by_id.contains_key(&p.id) {
                return Err(SdwanError::InvalidPolicy(format!(
                    "duplicate path id {:?} in catalog",
                    p.id.as_str()
                )));
            }
            by_id.insert(p.id.clone(), Arc::new(p));
        }
        Ok(Self { by_id })
    }

    /// Empty catalog. Useful for unit tests that exercise
    /// the no-paths path.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of paths in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True iff the catalog has no paths at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl PathProvider for StaticPathProvider {
    fn candidates(&self, class: TrafficClass) -> Vec<Arc<Path>> {
        self.by_id
            .values()
            .filter(|p| p.eligible(class))
            .cloned()
            .collect()
    }

    fn get(&self, id: &PathId) -> Option<Arc<Path>> {
        self.by_id.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn traffic_class_wire_strings_are_snake_case() {
        // Dashboards and runbooks consume the wire
        // strings directly. Snake_case is the workspace
        // convention; if anyone "fixes" them to camel
        // case, dashboards break silently.
        assert_eq!(TrafficClass::RealTime.as_str(), "real_time");
        assert_eq!(TrafficClass::Interactive.as_str(), "interactive");
        assert_eq!(TrafficClass::BestEffort.as_str(), "best_effort");
        assert_eq!(TrafficClass::Bulk.as_str(), "bulk");
    }

    #[test]
    fn path_eligible_matches_only_declared_classes() {
        let p = Path::new(
            "mpls-east",
            [TrafficClass::RealTime, TrafficClass::Interactive],
        );
        assert!(p.eligible(TrafficClass::RealTime));
        assert!(p.eligible(TrafficClass::Interactive));
        assert!(!p.eligible(TrafficClass::BestEffort));
        assert!(!p.eligible(TrafficClass::Bulk));
    }

    #[test]
    fn with_bias_overrides_default_zero() {
        let p = Path::new("inet-prim", [TrafficClass::BestEffort]).with_bias(2.5);
        assert_eq!(p.static_bias, 2.5);
    }

    #[test]
    fn static_provider_filters_candidates_by_class() {
        // The provider must return only paths whose
        // eligibility set includes the requested class;
        // every other path stays invisible to the
        // selector.
        let provider = StaticPathProvider::from_paths([
            Path::new("mpls", [TrafficClass::RealTime]),
            Path::new("inet", [TrafficClass::BestEffort, TrafficClass::Bulk]),
            Path::new("lte", [TrafficClass::Bulk]),
        ]);
        let rt = provider.candidates(TrafficClass::RealTime);
        assert_eq!(rt.len(), 1);
        assert_eq!(rt[0].id, PathId::new("mpls"));
        let bulk = provider.candidates(TrafficClass::Bulk);
        let mut bulk_ids: Vec<_> = bulk.iter().map(|p| p.id.as_str().to_string()).collect();
        bulk_ids.sort();
        assert_eq!(bulk_ids, vec!["inet".to_string(), "lte".to_string()]);
    }

    #[test]
    fn static_provider_empty_returns_no_candidates() {
        let provider = StaticPathProvider::empty();
        assert!(provider.is_empty());
        assert_eq!(provider.candidates(TrafficClass::Interactive).len(), 0);
    }

    #[test]
    fn static_provider_get_resolves_by_id() {
        let provider = StaticPathProvider::from_paths([Path::new("mpls", [TrafficClass::Bulk])]);
        let got = provider.get(&PathId::new("mpls"));
        assert!(got.is_some());
        let missing = provider.get(&PathId::new("nope"));
        assert!(missing.is_none());
    }

    #[test]
    fn path_id_display_returns_inner() {
        // The id appears in logs / dashboards; the
        // Display impl must produce exactly the operator-
        // chosen string, no quoting / no surrounding
        // wrapper.
        let id = PathId::new("mpls-east");
        assert_eq!(format!("{id}"), "mpls-east");
    }

    #[test]
    fn path_validate_accepts_well_formed_path() {
        let p = Path::new("mpls", [TrafficClass::RealTime]).with_bias(1.5);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn path_validate_rejects_empty_id() {
        let p = Path::new("", [TrafficClass::Bulk]);
        let err = p.validate().expect_err("empty id must be rejected");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
        assert!(format!("{err}").contains("id must not be empty"));
    }

    #[test]
    fn path_validate_rejects_empty_eligible_classes() {
        // A path with no eligible classes would never
        // appear in `candidates(class)` for any class,
        // making it dead weight in the catalog. Bundle
        // adapters should reject it at load time rather
        // than ship an unreferenceable entry.
        let p = Path::new("mpls", std::iter::empty());
        let err = p.validate().expect_err("empty classes must be rejected");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
        assert!(format!("{err}").contains("eligible_classes"));
    }

    #[test]
    fn path_validate_rejects_nan_static_bias() {
        let p = Path::new("mpls", [TrafficClass::Bulk]).with_bias(f32::NAN);
        let err = p.validate().expect_err("nan bias must be rejected");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
        assert!(format!("{err}").contains("static_bias"));
    }

    #[test]
    fn path_validate_rejects_infinite_static_bias() {
        let p = Path::new("mpls", [TrafficClass::Bulk]).with_bias(f32::INFINITY);
        let err = p.validate().expect_err("inf bias must be rejected");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));

        let p = Path::new("mpls", [TrafficClass::Bulk]).with_bias(f32::NEG_INFINITY);
        let err = p.validate().expect_err("-inf bias must be rejected");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
    }

    #[test]
    fn try_from_paths_propagates_path_validation_errors() {
        // A non-finite bias on one path must fail the
        // whole catalog construction so the bundle
        // adapter never installs a partly-valid catalog.
        let err = StaticPathProvider::try_from_paths([
            Path::new("ok", [TrafficClass::Bulk]),
            Path::new("bad", [TrafficClass::Bulk]).with_bias(f32::NAN),
        ])
        .expect_err("bad bias must reject the catalog");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
    }

    #[test]
    fn try_from_paths_rejects_duplicate_ids() {
        let err = StaticPathProvider::try_from_paths([
            Path::new("mpls", [TrafficClass::Bulk]),
            Path::new("mpls", [TrafficClass::RealTime]),
        ])
        .expect_err("duplicate ids must reject the catalog");
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
        assert!(format!("{err}").contains("duplicate path id"));
    }

    #[test]
    fn try_from_paths_accepts_valid_catalog() {
        // Two well-formed paths with distinct ids must
        // produce a working catalog identical to the
        // infallible constructor.
        let provider = StaticPathProvider::try_from_paths([
            Path::new("mpls", [TrafficClass::RealTime]).with_bias(0.5),
            Path::new("inet", [TrafficClass::BestEffort]).with_bias(-0.5),
        ])
        .expect("well-formed catalog must construct");
        assert_eq!(provider.len(), 2);
        assert!(provider.get(&PathId::new("mpls")).is_some());
        assert!(provider.get(&PathId::new("inet")).is_some());
    }
}
