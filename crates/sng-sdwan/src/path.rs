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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Identifier for a single underlay path. Cheap to clone
/// because the underlying string lives inside the
/// `Arc<str>`-backed pool that policy/probe providers
/// share.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Defaults to `0.0`; finite & non-NaN is enforced by
    /// [`crate::SdwanPolicy::validate`].
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
        self.eligible_classes.iter().any(|c| *c == class)
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
    pub fn from_paths<I: IntoIterator<Item = Path>>(paths: I) -> Self {
        let mut by_id: HashMap<PathId, Arc<Path>> = HashMap::new();
        for p in paths {
            by_id.insert(p.id.clone(), Arc::new(p));
        }
        Self { by_id }
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
}
