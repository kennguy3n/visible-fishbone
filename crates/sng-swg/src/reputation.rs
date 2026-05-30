//! Host reputation feed.
//!
//! Where [`crate::category::CategoryProvider`] answers
//! *"what kind of site is this?"*, the reputation
//! provider answers *"how dangerous is this site **right
//! now**?"*. Reputation feeds change minute-to-minute as
//! external threat-intel partners post fresh IOCs; the
//! SWG keeps a hot copy in-process and refreshes it on a
//! cadence.
//!
//! Score range: `0.0..=1.0`. `0.0` is *known-good*,
//! `1.0` is *known-bad*. Implementations that have no
//! opinion return `None` (the orchestrator treats this
//! as "neutral", not "bad").

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

/// Per-host reputation score. Bounded `[0.0, 1.0]`. The
/// constructor clamps anything outside the range so a
/// misbehaving feed can't poison policy evaluation with
/// `NaN` / `Infinity` / negative scores.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ReputationScore(f32);

impl ReputationScore {
    /// Construct a clamped score. `NaN` is treated as
    /// `0.5` (neutral) — the worst-case fallback if a
    /// feed corruption sneaks through.
    #[must_use]
    pub fn new(value: f32) -> Self {
        let v = if value.is_nan() { 0.5 } else { value };
        Self(v.clamp(0.0, 1.0))
    }

    /// Inner f32 in `[0.0, 1.0]`.
    #[must_use]
    pub const fn value(self) -> f32 {
        self.0
    }

    /// Convenience: `true` when the score is at or above
    /// the given threshold.
    #[must_use]
    pub fn at_least(self, threshold: f32) -> bool {
        self.0 >= threshold
    }
}

/// Reputation lookup contract. Implementations look up
/// the current score for a host. Stays sync because the
/// production path expects an in-memory cache (the
/// downloader task runs separately).
pub trait ReputationProvider: Send + Sync + 'static {
    /// Look up the score for `host`. Returns `None` when
    /// the provider has no opinion (no feed entry for
    /// this host).
    fn score_for(&self, host: &str) -> Option<ReputationScore>;
}

/// In-memory provider backed by a host map. Used by the
/// dev / test environment and by production when the
/// reputation downloader task has pulled the feed into
/// the agent. Replaceable via [`Self::replace`].
#[derive(Debug)]
pub struct StaticReputationProvider {
    table: ArcSwap<HashMap<String, ReputationScore>>,
}

impl StaticReputationProvider {
    /// Construct an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    /// Construct a provider seeded with the given map.
    /// Keys are lowercased so callers can pass mixed-case
    /// hosts.
    #[must_use]
    pub fn from_table(initial: HashMap<String, ReputationScore>) -> Self {
        let lowered: HashMap<String, ReputationScore> = initial
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        Self {
            table: ArcSwap::new(Arc::new(lowered)),
        }
    }

    /// Replace the table atomically. In-flight lookups
    /// see the old set until they finish.
    pub fn replace(&self, table: HashMap<String, ReputationScore>) {
        let lowered: HashMap<String, ReputationScore> = table
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        self.table.store(Arc::new(lowered));
    }

    /// Number of entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.load().len()
    }

    /// True if no entries are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.load().is_empty()
    }
}

impl Default for StaticReputationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationProvider for StaticReputationProvider {
    fn score_for(&self, host: &str) -> Option<ReputationScore> {
        let table = self.table.load();
        let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
        // Suffix walking matches the category provider so
        // an entry for `evil.example.com` covers every
        // subdomain.
        let mut candidate: &str = &key;
        loop {
            if let Some(s) = table.get(candidate) {
                return Some(*s);
            }
            match candidate.find('.') {
                Some(i) => {
                    candidate = &candidate[i + 1..];
                    if candidate.is_empty() {
                        return None;
                    }
                }
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn score_clamps_above_one() {
        assert_eq!(ReputationScore::new(2.0).value(), 1.0);
    }

    #[test]
    fn score_clamps_below_zero() {
        assert_eq!(ReputationScore::new(-1.0).value(), 0.0);
    }

    #[test]
    fn score_nan_becomes_neutral() {
        assert_eq!(ReputationScore::new(f32::NAN).value(), 0.5);
    }

    #[test]
    fn score_infinity_clamps_to_one() {
        assert_eq!(ReputationScore::new(f32::INFINITY).value(), 1.0);
    }

    #[test]
    fn score_neg_infinity_clamps_to_zero() {
        assert_eq!(ReputationScore::new(f32::NEG_INFINITY).value(), 0.0);
    }

    #[test]
    fn at_least_threshold_predicate() {
        let s = ReputationScore::new(0.7);
        assert!(s.at_least(0.5));
        assert!(s.at_least(0.7));
        assert!(!s.at_least(0.71));
    }

    fn provider_with(entries: &[(&str, f32)]) -> StaticReputationProvider {
        let mut t = HashMap::new();
        for (k, v) in entries {
            t.insert((*k).to_string(), ReputationScore::new(*v));
        }
        StaticReputationProvider::from_table(t)
    }

    #[test]
    fn empty_provider_returns_none() {
        let p = StaticReputationProvider::new();
        assert_eq!(p.score_for("example.com"), None);
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn exact_host_match_returns_score() {
        let p = provider_with(&[("evil.example.com", 0.95)]);
        let s = p.score_for("evil.example.com").unwrap();
        assert_eq!(s.value(), 0.95);
    }

    #[test]
    fn suffix_match_returns_general_score() {
        let p = provider_with(&[("example.com", 0.2)]);
        let s = p.score_for("www.example.com").unwrap();
        assert_eq!(s.value(), 0.2);
    }

    #[test]
    fn more_specific_entry_overrides_general() {
        let p = provider_with(&[("example.com", 0.2), ("evil.example.com", 0.95)]);
        assert_eq!(
            p.score_for("evil.example.com").map(ReputationScore::value),
            Some(0.95)
        );
        assert_eq!(
            p.score_for("good.example.com").map(ReputationScore::value),
            Some(0.2)
        );
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let p = provider_with(&[("Example.COM", 0.4)]);
        assert_eq!(
            p.score_for("WWW.EXAMPLE.com").map(ReputationScore::value),
            Some(0.4)
        );
    }

    #[test]
    fn unknown_host_returns_none() {
        let p = provider_with(&[("example.com", 0.5)]);
        assert_eq!(p.score_for("other.org"), None);
    }

    #[test]
    fn replace_swaps_table_atomically() {
        let p = StaticReputationProvider::new();
        assert_eq!(p.score_for("example.com"), None);
        let mut t = HashMap::new();
        t.insert("example.com".into(), ReputationScore::new(0.9));
        p.replace(t);
        assert_eq!(
            p.score_for("example.com").map(ReputationScore::value),
            Some(0.9)
        );
    }
}
