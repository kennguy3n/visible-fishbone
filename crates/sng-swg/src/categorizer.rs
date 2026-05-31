//! URL categorisation.
//!
//! The categoriser maps a request (host + path) to a category
//! string the verdict layer interprets as an allow / deny /
//! redirect. Categories are operator-defined dotted strings
//! ("business.saas", "gambling", "social.media",
//! "adult.content") so the same category vocabulary can be
//! reused by the DNS subsystem (`sng-dns`) and the firewall L7
//! AppId table — having a single dotted namespace lets a single
//! dashboard count categorised hits across the three planes
//! without per-subsystem mapping.
//!
//! The pluggable provider trait is [`UrlCategorizer`]. At launch
//! a single implementation ships: [`LocalCategoryDb`], an
//! in-memory lookup backed by a hot-swappable
//! [`arc_swap::ArcSwap`] of `(host, path_prefix) -> category`
//! entries sourced from a signed control-plane bundle. A
//! production deployment can plug a remote provider in behind
//! the same trait surface (the trait is `async` so an HTTPS feed
//! or a managed verdict service slots in without disturbing the
//! ext-authz handler).
//!
//! Lookup semantics:
//!   1. Exact host + path-prefix match wins.
//!   2. Suffix-host (`*.example.com`) + path-prefix match next.
//!   3. Exact host with no path constraint last.
//!   4. No match -> `None`. The verdict layer maps `None` to an
//!      uncategorised allow by default; the manager can override
//!      this with a deny-default policy at install time.
//!
//! Lookups are O(log n) on the prefix tree: entries are bucketed
//! by hostname (longest suffix wins) and each bucket is sorted
//! by path prefix descending so the longest-prefix match wins.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sng_fw::sni_suffix_match;
use std::sync::Arc;

/// Operator-defined category. Stored as an owned string so
/// operator-extension categories are no-allocation on the
/// per-request lookup path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Category(pub String);

impl Category {
    /// Wrap a string slice in a Category. Mostly for tests and
    /// constants.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The wrapped string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One entry in the URL category feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryEntry {
    /// Hostname to match. May start with `*.` to express
    /// "match this suffix". The matcher reuses
    /// [`sng_fw::sni_suffix_match`] so an entry like
    /// `*.gambling.example` matches both `gambling.example` and
    /// `roulette.gambling.example`.
    pub host: String,
    /// Optional path prefix the request path must start with for
    /// the entry to match. None matches every path under the
    /// hostname.
    pub path_prefix: Option<String>,
    /// Category the matched request resolves to.
    pub category: Category,
}

/// Pluggable URL categoriser. The trait is `async` so a remote
/// provider that calls an external feed (Cisco Talos, Cyren,
/// custom in-house) slots in behind the same surface as the
/// local lookup.
#[async_trait]
pub trait UrlCategorizer: Send + Sync + std::fmt::Debug {
    /// Look up the category for a request. Returns `None` when no
    /// entry matches.
    async fn categorize(&self, host: &str, path: &str) -> Option<Category>;
}

/// Local in-memory categoriser. The dataset is held in an
/// [`ArcSwap`] so a control-plane bundle install can swap the
/// table in atomically without taking a write lock on the
/// per-request path.
#[derive(Debug)]
pub struct LocalCategoryDb {
    inner: ArcSwap<CategoryIndex>,
}

#[derive(Debug, Default, Clone)]
struct CategoryIndex {
    // Entries sorted by host-suffix length descending, then by
    // path-prefix length descending. The matcher walks in this
    // order so the most specific (longest host suffix + longest
    // path prefix) entry wins.
    entries: Vec<CategoryEntry>,
}

impl Default for LocalCategoryDb {
    fn default() -> Self {
        Self {
            inner: ArcSwap::from_pointee(CategoryIndex::default()),
        }
    }
}

impl LocalCategoryDb {
    /// Build a new local categoriser preloaded with a set of
    /// entries. The constructor sorts the entries into the
    /// match-walk order so subsequent `categorize_sync` calls
    /// touch only an immutable snapshot.
    #[must_use]
    pub fn new(entries: Vec<CategoryEntry>) -> Self {
        let db = Self::default();
        db.install(entries);
        db
    }

    /// Atomically swap in a new entry set. Returns the number of
    /// entries installed (after sort + dedup) so the manager can
    /// log "installed N categories" without a follow-up
    /// `.iter().count()` walk.
    pub fn install(&self, mut entries: Vec<CategoryEntry>) -> usize {
        // Canonicalise the host field to ASCII lowercase before
        // sort + dedup so two entries the runtime matcher treats
        // as equivalent (`Example.COM` ≡ `example.com`,
        // `*.Chase.COM` ≡ `*.chase.com`) collapse to a single
        // row rather than surviving as semantic duplicates. The
        // `*.` prefix is preserved because it carries the
        // exact-vs-wildcard precedence the secondary sort relies
        // on; only the bytes after the optional `*.` are
        // lowercased. Path prefixes stay case-sensitive — RFC 3986
        // §3.3 treats the path component as case-sensitive, and
        // operators write the literal path their backend serves.
        //
        // Canonicalise the category string to ASCII lowercase for
        // the same reason: the deny-list comparison in
        // `auth.rs:evaluate` already lowercases the category
        // before binary-searching, and the deny-list itself is
        // stored lowercase (sorted + deduped at handler build
        // time — see `ExtAuthzHandlerBuilder::build`). Two feed
        // entries that share host+path but differ only in
        // category casing (`"Adult"` vs `"adult"`) would survive
        // `dedup()` (which keys on `PartialEq` over the whole
        // `CategoryEntry` including category), both walk to the
        // same deny verdict, but the verdict's `reason` field
        // would carry whichever casing won the sort tie-break.
        // That feeds *two* `category = '…'` rows into downstream
        // dashboards for what is logically one category, splitting
        // per-category counts and breaking deny-list audit trails
        // that group by category. Storing the canonical lowercase
        // form means the dedup collapses semantic duplicates and
        // every verdict reason carries the canonical bytes —
        // dashboards see one row per category regardless of feed
        // casing.
        //
        // Without these two normalisations the case-sensitive
        // `dedup` below silently keeps both rows; at lookup time
        // the case-insensitive `host_matches` would walk both,
        // the earlier sort tie-break would win, and an operator-
        // authored override with different casing could be
        // silently shadowed by an industry-default entry of the
        // same suffix. The bypass list applies the same
        // normalisation in `BypassList::new`/`with_extensions`;
        // keeping the two construction paths symmetric means a
        // future control-plane validator that lints the bypass
        // and category feeds together does not see a divergence.
        for e in &mut entries {
            e.host = e.host.to_ascii_lowercase();
            e.category.0 = e.category.0.to_ascii_lowercase();
        }
        entries.sort_by(|a, b| {
            // Primary: descending by stripped-host length
            // (longest suffix first).
            let host_cmp = sort_key(&b.host).cmp(&sort_key(&a.host));
            if host_cmp != std::cmp::Ordering::Equal {
                return host_cmp;
            }
            // Secondary: an exact-host entry beats a wildcard
            // entry of the same stripped length. The module
            // doc promises "exact host wins over `*.host`";
            // sorting wildcard-after-exact in walk order makes
            // the linear scan find the exact entry first when
            // both are present in the index.
            let a_wc = is_wildcard(&a.host);
            let b_wc = is_wildcard(&b.host);
            let wc_cmp = a_wc.cmp(&b_wc);
            if wc_cmp != std::cmp::Ordering::Equal {
                return wc_cmp;
            }
            let bp = b.path_prefix.as_deref().unwrap_or("");
            let ap = a.path_prefix.as_deref().unwrap_or("");
            bp.len().cmp(&ap.len()).then_with(|| ap.cmp(bp))
        });
        // Dedup identical entries — the same suffix and the
        // same category and the same path-prefix from two feeds
        // (industry default + operator extension) collapse to
        // one.
        entries.dedup();
        let n = entries.len();
        self.inner.store(Arc::new(CategoryIndex { entries }));
        n
    }

    /// How many entries are currently installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.load().entries.len()
    }

    /// Whether the categoriser has any entries installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.load().entries.is_empty()
    }

    /// Synchronous lookup. Exposed as a separate entry point
    /// because the local categoriser does no IO and the manager's
    /// in-process fast path does not need an async hop.
    #[must_use]
    pub fn categorize_sync(&self, host: &str, path: &str) -> Option<Category> {
        let snap = self.inner.load();
        for entry in &snap.entries {
            if !host_matches(&entry.host, host) {
                continue;
            }
            if let Some(prefix) = entry.path_prefix.as_deref() {
                if !path.starts_with(prefix) {
                    continue;
                }
            }
            return Some(entry.category.clone());
        }
        None
    }
}

// The local categoriser implements the async trait by delegating
// to the synchronous fast path — no IO involved so blocking the
// runtime is fine.
#[async_trait]
impl UrlCategorizer for LocalCategoryDb {
    async fn categorize(&self, host: &str, path: &str) -> Option<Category> {
        self.categorize_sync(host, path)
    }
}

// A sort key that boils a host pattern down to "longer is more
// specific". `*.foo` and `foo` get equal weight on the length
// axis; [`install`] adds a secondary tie-break that puts the
// exact (non-wildcard) entry before the wildcard so the
// module-doc precedence rules hold.
fn sort_key(host: &str) -> usize {
    host.strip_prefix("*.").unwrap_or(host).len()
}

// Whether the host pattern is a wildcard (`*.foo`) vs an exact
// host (`foo`). Used as a secondary sort key so exact entries
// appear before wildcard entries of the same stripped length.
fn is_wildcard(host: &str) -> bool {
    host.starts_with("*.")
}

// Host comparator. Matches `*.suffix` against any depth of
// subdomain and the apex; exact (non-wildcard) entries match the
// exact hostname. Both forms case-fold via sni_suffix_match.
fn host_matches(entry_host: &str, request_host: &str) -> bool {
    if let Some(suffix) = entry_host.strip_prefix("*.") {
        // *.foo style — permissive match including the apex.
        sni_suffix_match(suffix, request_host)
    } else {
        // Exact match, case-insensitive.
        entry_host.eq_ignore_ascii_case(request_host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn ce(host: &str, path: Option<&str>, cat: &str) -> CategoryEntry {
        CategoryEntry {
            host: host.into(),
            path_prefix: path.map(str::to_owned),
            category: Category::new(cat),
        }
    }

    #[test]
    fn empty_db_returns_none() {
        let db = LocalCategoryDb::default();
        assert_eq!(db.categorize_sync("anywhere.example", "/"), None);
        assert!(db.is_empty());
    }

    #[test]
    fn exact_host_matches() {
        let db = LocalCategoryDb::new(vec![ce("example.com", None, "business.saas")]);
        assert_eq!(
            db.categorize_sync("example.com", "/"),
            Some(Category::new("business.saas"))
        );
        // A subdomain of an exact (non-wildcard) host MUST NOT
        // match — the operator wrote the apex literally because
        // they only meant the apex.
        assert_eq!(db.categorize_sync("api.example.com", "/"), None);
    }

    #[test]
    fn wildcard_host_matches_subdomains_and_apex() {
        let db = LocalCategoryDb::new(vec![ce("*.gambling.example", None, "gambling")]);
        assert_eq!(
            db.categorize_sync("gambling.example", "/"),
            Some(Category::new("gambling")),
            "apex must match"
        );
        assert_eq!(
            db.categorize_sync("roulette.gambling.example", "/"),
            Some(Category::new("gambling")),
            "single-label subdomain must match"
        );
        assert_eq!(
            db.categorize_sync("eu.live.gambling.example", "/"),
            Some(Category::new("gambling")),
            "multi-label subdomain must match (permissive SNI semantics)"
        );
    }

    #[test]
    fn path_prefix_filters_inside_host() {
        // An operator wants to categorise "everything under
        // example.com/admin" as restricted but leave the rest
        // alone. The path-prefix filter must apply *before*
        // the more general host-only entry.
        let db = LocalCategoryDb::new(vec![
            ce("example.com", Some("/admin"), "internal.admin"),
            ce("example.com", None, "business.saas"),
        ]);
        assert_eq!(
            db.categorize_sync("example.com", "/admin/users"),
            Some(Category::new("internal.admin"))
        );
        assert_eq!(
            db.categorize_sync("example.com", "/home"),
            Some(Category::new("business.saas"))
        );
    }

    #[test]
    fn longest_path_prefix_wins_within_host() {
        // Two path-prefix entries for the same host — the more
        // specific (longer) prefix must take precedence.
        let db = LocalCategoryDb::new(vec![
            ce("example.com", Some("/v2/admin"), "internal.admin_v2"),
            ce("example.com", Some("/v2"), "internal.api_v2"),
        ]);
        assert_eq!(
            db.categorize_sync("example.com", "/v2/admin/users"),
            Some(Category::new("internal.admin_v2"))
        );
        assert_eq!(
            db.categorize_sync("example.com", "/v2/users"),
            Some(Category::new("internal.api_v2"))
        );
    }

    #[test]
    fn longest_host_wins_across_entries() {
        // *.internal.bank.com is more specific than *.bank.com;
        // the categoriser must walk in longest-host-first order.
        let db = LocalCategoryDb::new(vec![
            ce("*.bank.com", None, "tls.finance"),
            ce("*.internal.bank.com", None, "tls.internal"),
        ]);
        assert_eq!(
            db.categorize_sync("app.internal.bank.com", "/"),
            Some(Category::new("tls.internal"))
        );
        assert_eq!(
            db.categorize_sync("login.bank.com", "/"),
            Some(Category::new("tls.finance"))
        );
    }

    #[test]
    fn duplicate_entries_collapse() {
        // The control-plane fetch can deliver overlapping
        // sources (industry default + operator extension that
        // re-asserts the same suffix and category). Dedup must
        // collapse those so the matcher walk is not O(N
        // duplicates).
        let db = LocalCategoryDb::new(vec![
            ce("example.com", None, "business.saas"),
            ce("example.com", None, "business.saas"),
        ]);
        assert_eq!(db.len(), 1);
    }

    #[tokio::test]
    async fn async_trait_path_returns_same_category() {
        // The async surface is a thin delegation; lock the
        // contract so a future remote provider that wraps a
        // local cache cannot silently drop the cache fast path.
        let db = LocalCategoryDb::new(vec![ce("example.com", None, "business.saas")]);
        let trait_obj: &dyn UrlCategorizer = &db;
        let cat = trait_obj.categorize("example.com", "/").await;
        assert_eq!(cat, Some(Category::new("business.saas")));
    }

    #[test]
    fn install_atomically_replaces_dataset() {
        // The bundle hot-swap path calls install() on the live
        // categoriser. After install, lookups must see the new
        // dataset; the old one must be inaccessible.
        let db = LocalCategoryDb::new(vec![ce("old.example", None, "old.cat")]);
        let n = db.install(vec![ce("new.example", None, "new.cat")]);
        assert_eq!(n, 1);
        assert_eq!(db.categorize_sync("old.example", "/"), None);
        assert_eq!(
            db.categorize_sync("new.example", "/"),
            Some(Category::new("new.cat"))
        );
    }

    #[test]
    fn case_insensitive_host_match() {
        // Production traffic arrives lowercased after
        // RequestContext::normalize, but a defensive matcher
        // still folds case so a future caller (e.g. a control
        // plane validator) that forgets to normalise doesn't
        // silently miss.
        let db = LocalCategoryDb::new(vec![ce("Example.COM", None, "business.saas")]);
        assert_eq!(
            db.categorize_sync("example.com", "/"),
            Some(Category::new("business.saas"))
        );
    }

    #[test]
    fn install_canonicalizes_host_case_for_dedup() {
        // Regression test: two entries that the runtime matcher
        // treats as equivalent (`Example.COM` ≡ `example.com`)
        // must collapse to a single index row, not survive as
        // semantic duplicates that pollute the longest-prefix
        // walk and inflate bundle-digest churn. Path prefix is
        // case-sensitive by RFC 3986 and is intentionally not
        // folded.
        let db = LocalCategoryDb::new(vec![
            ce("Example.COM", None, "business.saas"),
            ce("example.com", None, "business.saas"),
        ]);
        assert_eq!(db.len(), 1);
        // The collapsed entry stores the canonical (lowercase)
        // host so downstream consumers that iterate the index
        // see matcher-equivalent bytes, not whatever input casing
        // the operator typed.
        assert_eq!(
            db.categorize_sync("example.com", "/"),
            Some(Category::new("business.saas"))
        );
    }

    #[test]
    fn install_canonicalizes_wildcard_host_case_for_dedup() {
        // The wildcard pattern `*.Chase.COM` and `*.chase.com`
        // must also collapse — the `*.` prefix bytes are
        // preserved (they drive the exact-vs-wildcard secondary
        // sort) but the suffix after the wildcard is lowercased.
        let db = LocalCategoryDb::new(vec![
            ce("*.Chase.COM", None, "tls.finance"),
            ce("*.chase.com", None, "tls.finance"),
        ]);
        assert_eq!(db.len(), 1);
        assert_eq!(
            db.categorize_sync("online.chase.com", "/"),
            Some(Category::new("tls.finance"))
        );
    }

    #[test]
    fn install_canonicalizes_category_case_for_dedup() {
        // Regression test: two entries that share host + path
        // but differ only in category casing (`"Adult"` vs
        // `"adult"`) must collapse to a single index row.
        //
        // Before this fix, the case-sensitive `Vec::dedup`
        // (which keys on `PartialEq` over the whole
        // `CategoryEntry`) kept both rows. At lookup time the
        // case-insensitive `host_matches` would walk both, the
        // earlier sort tie-break (input-order preserving stable
        // sort) would win, and the verdict reason field would
        // carry whichever casing happened to land first.
        // Downstream dashboards grouping by `category` then saw
        // *two* rows for what is logically one category,
        // splitting per-category counts and breaking deny-list
        // audit trails that group by category. The
        // `auth.rs:evaluate` deny-list lookup already
        // lowercased the cat before binary-searching the
        // canonical-lowercase deny list, so the deny verdict
        // itself was correct — but the reason string was not.
        let db = LocalCategoryDb::new(vec![
            ce("example.com", None, "Adult"),
            ce("example.com", None, "adult"),
        ]);
        assert_eq!(db.len(), 1);
        // The collapsed row stores the canonical (lowercase)
        // category so every verdict reason carries the same
        // bytes regardless of feed casing.
        assert_eq!(
            db.categorize_sync("example.com", "/"),
            Some(Category::new("adult"))
        );
    }

    #[test]
    fn install_normalizes_category_case_in_verdict_reason() {
        // Even when there is only one entry (no dedup to test),
        // the category casing in the verdict reason must match
        // the canonical (lowercase) form so downstream consumers
        // never see uppercase characters in the `category` field
        // of a deny verdict — that would split per-category
        // counts across casings even if the feed itself is
        // consistent.
        let db = LocalCategoryDb::new(vec![ce("example.com", None, "BUSINESS.SAAS")]);
        assert_eq!(
            db.categorize_sync("example.com", "/"),
            Some(Category::new("business.saas"))
        );
    }
}
