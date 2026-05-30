//! URL categorisation.
//!
//! Every observed request is mapped to one [`Category`]
//! before policy evaluates a verdict. The categorisation
//! is the SWG's primary verdict input — operator policy
//! says, in effect, *"block `Malware`, inspect-with-MITM
//! `Phishing`, bypass-TLS `Healthcare`, allow `Business`"*.
//!
//! The crate ships a [`CategoryProvider`] trait so the
//! production deployment can swap in a third-party feed
//! (Webroot / Cisco Talos / Cloudflare Radar / an
//! operator-maintained domain list). For development and
//! tests the in-memory [`StaticCategoryProvider`] holds a
//! [`HashMap<String, Category>`] keyed by host suffix —
//! the lookup is O(host-label-count) and runs lock-free
//! through an [`arc_swap::ArcSwap`] so policy reloads do
//! not block the data path.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// SWG URL category. Closed set — the operator's policy
/// graph maps each variant to a [`crate::policy::Posture`]
/// (allow / inspect / block / bypass-TLS / quarantine).
///
/// The variants are deliberately coarse — operators do
/// not get to invent new categories on the fly. Adding a
/// variant is a policy-schema migration; the global
/// catalogue plus per-tenant overrides ride on top of
/// these as labels, not as new variants.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Confirmed malware distribution or command-and-control.
    Malware,
    /// Phishing / credential-harvesting.
    Phishing,
    /// Generic unwanted: ad networks, cryptominers, p2p.
    Unwanted,
    /// User-facing risky categories: gambling, weapons,
    /// adult, drugs. Operators usually block these.
    Risky,
    /// Sensitive / privacy-protected: healthcare, finance,
    /// legal. Operators usually bypass-TLS to avoid
    /// compliance exposure.
    Sensitive,
    /// Business productivity: cloud office, code hosting,
    /// SaaS apps the operator trusts.
    Business,
    /// Streaming media. Bandwidth-heavy but generally safe.
    Media,
    /// Anything the provider doesn't recognise. Policy
    /// usually says *"inspect with MITM"*.
    Uncategorised,
}

impl Category {
    /// Stable lowercase wire string — matches the
    /// `category` column on telemetry envelopes and the
    /// `category` policy-rule predicate.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Phishing => "phishing",
            Self::Unwanted => "unwanted",
            Self::Risky => "risky",
            Self::Sensitive => "sensitive",
            Self::Business => "business",
            Self::Media => "media",
            Self::Uncategorised => "uncategorised",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A category lookup contract. Implementations look up
/// the category for a parsed host. The trait is **sync**
/// — implementations that need network I/O cache lookups
/// in-process so the data-path call stays non-blocking.
///
/// Returns `None` when the host is genuinely unknown to
/// the provider; the orchestrator treats this as
/// [`Category::Uncategorised`].
pub trait CategoryProvider: Send + Sync + 'static {
    /// Look up the category for `host`. Implementations
    /// MUST be O(log n) or better on the request path.
    fn category_for(&self, host: &str) -> Option<Category>;
}

/// In-memory provider backed by a host-suffix table.
///
/// The table key is a fully-qualified domain (no leading
/// dot); a lookup for `mail.example.com` walks
/// `mail.example.com` → `example.com` → `com` and returns
/// the first match. Suffix walking lets a single entry
/// for `example.com` cover every subdomain without the
/// operator having to enumerate them.
///
/// The internal map sits behind an [`ArcSwap`] so
/// [`Self::replace`] is lock-free; in-flight lookups see
/// the old table until they finish.
#[derive(Debug)]
pub struct StaticCategoryProvider {
    table: ArcSwap<HashMap<String, Category>>,
}

impl StaticCategoryProvider {
    /// Construct an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    /// Construct a provider seeded with the given table.
    /// The keys are lowercased on construction so callers
    /// can pass mixed-case hosts.
    #[must_use]
    pub fn from_table(initial: HashMap<String, Category>) -> Self {
        let lowered: HashMap<String, Category> = initial
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        Self {
            table: ArcSwap::new(Arc::new(lowered)),
        }
    }

    /// Replace the table atomically. In-flight lookups see
    /// the old set until they finish; cheap to call from
    /// a policy-reload task.
    pub fn replace(&self, table: HashMap<String, Category>) {
        let lowered: HashMap<String, Category> = table
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

impl Default for StaticCategoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryProvider for StaticCategoryProvider {
    fn category_for(&self, host: &str) -> Option<Category> {
        let table = self.table.load();
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        // Walk left-to-right by trimming labels off the
        // front. `foo.bar.example.com` → `bar.example.com`
        // → `example.com` → `com`.
        let mut candidate: &str = &host;
        loop {
            if let Some(c) = table.get(candidate) {
                return Some(*c);
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
    fn category_wire_strings_are_stable() {
        assert_eq!(Category::Malware.as_str(), "malware");
        assert_eq!(Category::Phishing.as_str(), "phishing");
        assert_eq!(Category::Unwanted.as_str(), "unwanted");
        assert_eq!(Category::Risky.as_str(), "risky");
        assert_eq!(Category::Sensitive.as_str(), "sensitive");
        assert_eq!(Category::Business.as_str(), "business");
        assert_eq!(Category::Media.as_str(), "media");
        assert_eq!(Category::Uncategorised.as_str(), "uncategorised");
    }

    #[test]
    fn category_roundtrips_through_json() {
        for c in [
            Category::Malware,
            Category::Phishing,
            Category::Unwanted,
            Category::Risky,
            Category::Sensitive,
            Category::Business,
            Category::Media,
            Category::Uncategorised,
        ] {
            let s = serde_json::to_string(&c).unwrap();
            let round: Category = serde_json::from_str(&s).unwrap();
            assert_eq!(c, round);
        }
    }

    fn provider_with(entries: &[(&str, Category)]) -> StaticCategoryProvider {
        let mut t = HashMap::new();
        for (k, v) in entries {
            t.insert((*k).to_string(), *v);
        }
        StaticCategoryProvider::from_table(t)
    }

    #[test]
    fn empty_provider_returns_none() {
        let p = StaticCategoryProvider::new();
        assert_eq!(p.category_for("example.com"), None);
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn exact_host_match_returns_category() {
        let p = provider_with(&[("evil.example.com", Category::Malware)]);
        assert_eq!(p.category_for("evil.example.com"), Some(Category::Malware));
    }

    #[test]
    fn subdomain_match_walks_suffix_table() {
        let p = provider_with(&[("example.com", Category::Business)]);
        assert_eq!(p.category_for("www.example.com"), Some(Category::Business));
        assert_eq!(p.category_for("a.b.example.com"), Some(Category::Business));
    }

    #[test]
    fn more_specific_entry_wins_over_general() {
        let p = provider_with(&[
            ("example.com", Category::Business),
            ("evil.example.com", Category::Malware),
        ]);
        assert_eq!(p.category_for("evil.example.com"), Some(Category::Malware));
        assert_eq!(p.category_for("good.example.com"), Some(Category::Business));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let p = provider_with(&[("Example.COM", Category::Business)]);
        assert_eq!(p.category_for("WWW.EXAMPLE.com"), Some(Category::Business));
    }

    #[test]
    fn trailing_dot_is_ignored() {
        let p = provider_with(&[("example.com", Category::Business)]);
        assert_eq!(p.category_for("example.com."), Some(Category::Business));
    }

    #[test]
    fn unknown_host_returns_none() {
        let p = provider_with(&[("example.com", Category::Business)]);
        assert_eq!(p.category_for("other.org"), None);
    }

    #[test]
    fn empty_host_returns_none() {
        let p = provider_with(&[("example.com", Category::Business)]);
        assert_eq!(p.category_for(""), None);
        assert_eq!(p.category_for("."), None);
    }

    #[test]
    fn replace_swaps_table_atomically() {
        let p = StaticCategoryProvider::new();
        assert_eq!(p.category_for("example.com"), None);
        let mut t = HashMap::new();
        t.insert("example.com".into(), Category::Malware);
        p.replace(t);
        assert_eq!(p.category_for("example.com"), Some(Category::Malware));
        // Second replace clears and changes verdict.
        let mut t2 = HashMap::new();
        t2.insert("example.com".into(), Category::Business);
        p.replace(t2);
        assert_eq!(p.category_for("example.com"), Some(Category::Business));
    }
}
