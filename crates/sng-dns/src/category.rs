//! Category filter: looks up the query name in a multi-category
//! domain database and applies the tenant's per-category
//! disposition (allow / log-and-resolve / block-NXDOMAIN).
//!
//! Category feeds are typically two orders of magnitude larger
//! than reputation feeds (millions of domains across dozens of
//! categories: social, gambling, adult, ads, …). The lookup
//! structure here is therefore a domain-suffix matcher: a query
//! for `news.bbc.co.uk` matches a feed entry of `bbc.co.uk`. The
//! suffix model matches how commercial category DBs publish
//! their data and gives the operator a single line per
//! second-level domain instead of one per FQDN.
//!
//! A query can fall into MULTIPLE categories (e.g. a domain may
//! be in both `news` and `ads`). When multiple matching
//! categories produce different verdicts, the strongest one
//! wins per [`crate::filter::combine_verdicts`] semantics: a
//! single Deny anywhere in the matching set short-circuits.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sng_core::envelope::Verdict;

use crate::filter::{Filter, FilterDecision};
use crate::qtype::RCode;
use crate::query::{DnsQuery, canonicalize_name, domain_suffix_match};

/// Per-category disposition the operator configured for a
/// tenant. `Allow` means "do not short-circuit, do not stamp"
/// (the absence of a hit). `Log` resolves upstream but stamps a
/// `Log` verdict for telemetry. `Block` short-circuits with
/// NXDOMAIN and a `Deny` verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CategoryAction {
    Allow,
    Log,
    Block,
}

impl CategoryAction {
    /// Verdict the action would stamp onto the
    /// [`sng_core::DnsEvent`].
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match self {
            Self::Allow => Verdict::Allow,
            Self::Log => Verdict::Log,
            Self::Block => Verdict::Deny,
        }
    }
}

/// In-memory category database. Built once per feed reload and
/// hot-swapped via [`Category::replace_database`].
///
/// `categories` maps category name → set of canonical domains
/// in that category. `actions` maps category name → operator
/// policy for that category. A category present in
/// `categories` but absent from `actions` is treated as
/// [`CategoryAction::Allow`] so the operator can stage a feed
/// before deciding what to do with each bucket.
#[derive(Clone, Debug, Default)]
pub struct CategoryDb {
    /// `category_name -> set of canonical domains`.
    pub categories: HashMap<String, HashSet<String>>,
    /// `category_name -> tenant policy`.
    pub actions: HashMap<String, CategoryAction>,
}

impl CategoryDb {
    /// Build a database from `(category_name, domain)` pairs and
    /// the policy map. Domain canonicalization is applied here
    /// so the suffix-match path can skip it on every query.
    pub fn build<I, S, T>(domains: I, actions: HashMap<String, CategoryAction>) -> Self
    where
        I: IntoIterator<Item = (S, T)>,
        S: AsRef<str>,
        T: AsRef<str>,
    {
        let mut categories: HashMap<String, HashSet<String>> = HashMap::new();
        for (cat, dom) in domains {
            let name = canonicalize_name(dom.as_ref());
            if name.is_empty() {
                continue;
            }
            categories
                .entry(cat.as_ref().to_string())
                .or_default()
                .insert(name);
        }
        Self {
            categories,
            actions,
        }
    }

    /// All `(category, action)` pairs that match `name` under
    /// domain-suffix semantics. The result is deduplicated by
    /// category (each category is reported at most once even if
    /// multiple feed entries inside it match).
    fn matches(&self, name: &str) -> Vec<(String, CategoryAction)> {
        let mut hits = Vec::new();
        for (cat, set) in &self.categories {
            if set.iter().any(|entry| domain_suffix_match(name, entry)) {
                let action = self
                    .actions
                    .get(cat)
                    .copied()
                    .unwrap_or(CategoryAction::Allow);
                hits.push((cat.clone(), action));
            }
        }
        hits
    }
}

/// Category filter.
pub struct Category {
    db: ArcSwap<CategoryDb>,
}

impl std::fmt::Debug for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.db.load();
        f.debug_struct("Category")
            .field("categories", &snap.categories.len())
            .field("actions", &snap.actions.len())
            .finish()
    }
}

impl Category {
    /// Wrap a [`CategoryDb`] in the hot-swappable filter shell.
    #[must_use]
    pub fn new(db: CategoryDb) -> Self {
        Self {
            db: ArcSwap::from_pointee(db),
        }
    }

    /// Empty category filter. Pass-through until the operator
    /// loads a real DB.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(CategoryDb::default())
    }

    /// Replace the database atomically. In-flight queries see
    /// the previous snapshot; subsequent queries see the new
    /// database.
    pub fn replace_database(&self, db: CategoryDb) {
        self.db.store(Arc::new(db));
    }

    /// Number of categories in the current database.
    #[must_use]
    pub fn category_count(&self) -> usize {
        self.db.load().categories.len()
    }
}

#[async_trait]
impl Filter for Category {
    fn name(&self) -> &'static str {
        "category"
    }

    async fn check(&self, query: &DnsQuery) -> FilterDecision {
        let snapshot = self.db.load();
        let hits = snapshot.matches(&query.name);
        if hits.is_empty() {
            return FilterDecision::Pass;
        }
        // Multiple categories may match. Strongest action wins.
        // A single Block trumps any number of Log / Allow hits;
        // Log trumps Allow.
        let strongest = hits
            .iter()
            .map(|(_, action)| *action)
            .max_by_key(|a| match a {
                CategoryAction::Block => 2,
                CategoryAction::Log => 1,
                CategoryAction::Allow => 0,
            })
            .unwrap_or(CategoryAction::Allow);

        match strongest {
            CategoryAction::Block => FilterDecision::ShortCircuit {
                verdict: Verdict::Deny,
                rcode: RCode::NxDomain,
                synthetic_ip: None,
                reason: std::borrow::Cow::Borrowed("category block"),
            },
            CategoryAction::Log => FilterDecision::Observe {
                verdict: Verdict::Log,
                reason: std::borrow::Cow::Borrowed("category log"),
            },
            CategoryAction::Allow => FilterDecision::Pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{ChainOutcome, FilterChain};
    use crate::qtype::QType;

    fn db_with_policies(policies: &[(&str, CategoryAction)]) -> CategoryDb {
        let domains = [
            ("gambling", "Casino.Example"),
            ("gambling", "bet.example.com"),
            ("ads", "ads.example"),
            ("news", "bbc.co.uk"),
            ("social", "facebook.com"),
        ];
        let actions = policies
            .iter()
            .map(|(c, a)| ((*c).to_string(), *a))
            .collect();
        CategoryDb::build(domains, actions)
    }

    #[tokio::test]
    async fn block_action_short_circuits_with_nxdomain() {
        let db = db_with_policies(&[("gambling", CategoryAction::Block)]);
        let f = Category::new(db);
        let q = DnsQuery::new("casino.example", QType::A);
        match f.check(&q).await {
            FilterDecision::ShortCircuit {
                verdict,
                rcode,
                synthetic_ip,
                ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(rcode, RCode::NxDomain);
                assert_eq!(synthetic_ip, None);
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn suffix_match_covers_subdomains() {
        let db = db_with_policies(&[("news", CategoryAction::Log)]);
        let f = Category::new(db);
        // bbc.co.uk feed entry must match news.bbc.co.uk.
        let q = DnsQuery::new("news.bbc.co.uk", QType::A);
        match f.check(&q).await {
            FilterDecision::Observe { verdict, .. } => {
                assert_eq!(verdict, Verdict::Log);
            }
            other => panic!("expected Observe, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn log_action_returns_observe_not_short_circuit() {
        let db = db_with_policies(&[("ads", CategoryAction::Log)]);
        let f = Category::new(db);
        let q = DnsQuery::new("ads.example", QType::A);
        match f.check(&q).await {
            FilterDecision::Observe { verdict, .. } => {
                assert_eq!(verdict, Verdict::Log);
            }
            other => panic!("expected Observe, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_action_returns_pass() {
        let db = db_with_policies(&[("social", CategoryAction::Allow)]);
        let f = Category::new(db);
        let q = DnsQuery::new("facebook.com", QType::A);
        assert_eq!(f.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn unknown_policy_defaults_to_allow() {
        // The DB has the domain in "gambling" but the operator
        // never set a policy. The filter must NOT block.
        let db = db_with_policies(&[]);
        let f = Category::new(db);
        let q = DnsQuery::new("casino.example", QType::A);
        assert_eq!(f.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn strongest_action_wins_when_multiple_categories_match() {
        // The domain "evil.example" is in BOTH `ads` (Log) and
        // `malware` (Block). Block must win.
        let mut categories: HashMap<String, HashSet<String>> = HashMap::new();
        categories
            .entry("ads".into())
            .or_default()
            .insert("evil.example".into());
        categories
            .entry("malware".into())
            .or_default()
            .insert("evil.example".into());
        let actions: HashMap<String, CategoryAction> = [
            ("ads".to_string(), CategoryAction::Log),
            ("malware".to_string(), CategoryAction::Block),
        ]
        .into_iter()
        .collect();
        let db = CategoryDb {
            categories,
            actions,
        };
        let f = Category::new(db);
        let q = DnsQuery::new("evil.example", QType::A);
        assert!(matches!(
            f.check(&q).await,
            FilterDecision::ShortCircuit { .. }
        ));
    }

    #[tokio::test]
    async fn replace_database_atomically_publishes_new_db() {
        let f = Category::new(CategoryDb::default());
        assert_eq!(f.category_count(), 0);
        let q = DnsQuery::new("casino.example", QType::A);
        assert_eq!(f.check(&q).await, FilterDecision::Pass);
        f.replace_database(db_with_policies(&[("gambling", CategoryAction::Block)]));
        assert!(f.category_count() >= 1);
        assert!(matches!(
            f.check(&q).await,
            FilterDecision::ShortCircuit { .. }
        ));
    }

    #[tokio::test]
    async fn end_to_end_through_filter_chain_block() {
        let db = db_with_policies(&[("gambling", CategoryAction::Block)]);
        let chain = FilterChain::new(vec![Arc::new(Category::new(db))]);
        let q = DnsQuery::new("casino.example", QType::A);
        match chain.evaluate(&q).await {
            ChainOutcome::ShortCircuit { filter, .. } => assert_eq!(filter, "category"),
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn end_to_end_through_filter_chain_observe_resolves() {
        let db = db_with_policies(&[("ads", CategoryAction::Log)]);
        let chain = FilterChain::new(vec![Arc::new(Category::new(db))]);
        let q = DnsQuery::new("ads.example", QType::A);
        match chain.evaluate(&q).await {
            ChainOutcome::ResolveAndObserve { verdict } => assert_eq!(verdict, Verdict::Log),
            other => panic!("expected ResolveAndObserve, got {other:?}"),
        }
    }
}
