//! TLS interception bypass list.
//!
//! Some destinations are operator-protected: medical-records
//! portals, online banking, government tax sites, … . The SWG must
//! complete the CONNECT to those hosts without acting as a MITM
//! CA, otherwise the client sees a cert-mismatch and the operator
//! gets a support ticket. The decision is keyed off the
//! ClientHello SNI, not the request hostname, because TLS 1.3 ESNI
//! and SNI-encrypted alternatives are still rare enough that SNI
//! is the most reliable signal an Envoy filter chain has before
//! the inner request.
//!
//! Industry-default suffix list ships baked in, covering:
//!
//! * Healthcare — `*.epicportal.com`, `*.mychart.com`, etc.
//! * Banking — `*.chase.com`, `*.bankofamerica.com`, etc.
//! * Government — `*.irs.gov`, `*.hmrc.gov.uk`, etc.
//!
//! The operator can extend or override the defaults at bundle
//! compile time; the defaults are surfaced via [`industry_defaults`]
//! so a control-plane review surface can render exactly what the
//! edge will enforce.
//!
//! Suffix match semantics are intentionally permissive (`*.bank.com`
//! matches both the apex `bank.com` and any depth of subdomain).
//! The implementation re-uses [`sng_fw::sni_suffix_match`] so the
//! firewall's L7 TLS classifier and the SWG's bypass evaluator
//! agree on what "this SNI matches this suffix" means. Diverging
//! semantics in two subsystems would let an operator-written
//! bypass list match in one and miss in the other.

use serde::{Deserialize, Serialize};
use sng_fw::sni_suffix_match;

/// One entry in the bypass list — the suffix to match and the
/// category that produced it (for telemetry drill-down).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BypassEntry {
    /// Suffix that matches the SNI. `*.` prefix is accepted on
    /// input but canonically stripped at construction time —
    /// [`BypassList::new`] and [`BypassList::with_extensions`]
    /// normalise `*.bank.com` to `bank.com` because
    /// [`sni_suffix_match`] treats both forms as equivalent at
    /// runtime. Storing a single canonical form keeps the
    /// merge / dedup paths agreement-by-construction with the
    /// matcher (an operator-authored `*.chase.com` extension
    /// then correctly dedups against the industry-default
    /// `chase.com` entry — see
    /// `with_extensions_normalizes_wildcard_prefix_against_default`).
    pub suffix: String,
    /// Category that owns this suffix. Surfaces in the verdict
    /// reason as `bypass.tls.<category>` so dashboards can break
    /// the bypass rate down per industry vertical.
    pub category: String,
}

/// Bypass evaluator. A new instance is built once per bundle
/// install and then read-only on the hot path. The internal
/// representation keeps entries sorted by suffix length descending
/// so a longer / more specific suffix wins over a shorter / more
/// generic one — useful when the operator bypasses `*.bank.com`
/// but wants to deny TLS interception specifically for
/// `*.internal.bank.com` via a separate category.
#[derive(Clone, Debug, Default)]
pub struct BypassList {
    entries: Vec<BypassEntry>,
}

/// Why a bypass decision was reached. Drives the verdict reason
/// string the SWG emits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BypassReason {
    /// SNI matched an entry. Carries the entry that won so the
    /// caller can form the `bypass.tls.<category>` reason.
    Matched(BypassEntry),
    /// The request had no SNI (plain HTTP CONNECT to an IP, or
    /// the client did not send a SNI extension). Operator-driven
    /// missing-SNI policy in [`crate::manager::SwgManager`]
    /// determines whether this becomes Deny or Allow.
    NoSni,
    /// SNI was present but no entry matched.
    NoMatch,
}

impl BypassReason {
    /// Render the reason as the telemetry-stable string the
    /// verdict emits. The format is the same dotted-category
    /// shape the rest of the crate uses, so dashboards can
    /// group on `reason.starts_with("bypass.")`.
    #[must_use]
    pub fn to_telemetry_string(&self) -> String {
        match self {
            Self::Matched(e) => format!("bypass.{}", e.category),
            Self::NoSni => "bypass.no_sni".to_string(),
            Self::NoMatch => "bypass.no_match".to_string(),
        }
    }
}

/// The bypass evaluator's verdict for a single ClientHello SNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BypassDecision {
    /// Whether the request should bypass TLS interception.
    pub bypass: bool,
    /// Why the decision was reached. Always carried so the
    /// caller can form the verdict reason string regardless of
    /// the outcome.
    pub reason: BypassReason,
}

/// Canonicalise an operator-authored suffix into the form the
/// bypass list stores internally: ASCII-lowercase, leading `*.`
/// stripped. The runtime matcher [`sni_suffix_match`] already
/// normalises both sides this way before comparison, so two
/// input forms that the matcher treats as equivalent
/// (`*.bank.com` ≡ `bank.com`, `Chase.COM` ≡ `chase.com`) must
/// land on the same stored bytes — otherwise the merge / dedup
/// paths in [`BypassList::new`] and [`BypassList::with_extensions`]
/// silently keep duplicates and an operator extension that
/// only differs from a default by `*.` prefix or case fails to
/// override the default's category.
fn canonicalize_suffix(raw: &str) -> String {
    let stripped = raw.strip_prefix("*.").unwrap_or(raw);
    stripped.to_ascii_lowercase()
}

impl BypassList {
    /// Build a bypass list from a sequence of entries.
    ///
    /// The constructor performs three normalisation steps so the
    /// stored representation is matcher-equivalent regardless of
    /// the input form:
    ///
    /// 1. Every suffix is canonicalised to lowercase with the
    ///    leading `*.` stripped (see [`canonicalize_suffix`]).
    ///    The runtime evaluator delegates to [`sni_suffix_match`],
    ///    which is case-insensitive and `*.`-prefix-agnostic;
    ///    storing a single canonical byte string is what makes
    ///    the merge / dedup paths agree with the matcher.
    /// 2. Entries with the same canonicalised suffix are collapsed
    ///    — the **last** occurrence in the input vector wins.
    ///    Two identical (suffix, category) pairs collapse to one;
    ///    a same-suffix / different-category pair collapses to
    ///    the later one. This is the universal
    ///    "operator-override" rule the bypass list applies
    ///    everywhere: callers append the override-source entries
    ///    after the source they want to override, and the
    ///    constructor honours that ordering. [`with_extensions`]
    ///    relies on this contract — it appends operator entries
    ///    after the existing defaults and then calls
    ///    [`Self::new`] to resolve.
    /// 3. The final vector is sorted by suffix length descending
    ///    so the runtime walk hits the longest / most-specific
    ///    suffix first. Ties (same length) are broken by the
    ///    suffix string compared lexicographically so the order
    ///    is fully deterministic.
    ///
    /// # Same-suffix conflict resolution
    ///
    /// The previous implementation only deduped exact
    /// (suffix, category) pairs (`Vec::dedup` keys off
    /// [`PartialEq`] which compares both fields). Two entries
    /// that shared a canonical suffix but differed in category
    /// both survived; at evaluate time the first-in-walk would
    /// win, which — because the secondary sort is lexicographic
    /// on the suffix string and two identical strings tie — was
    /// the *first-in-input* one. That contract differed from
    /// [`Self::with_extensions`] (which is explicit about
    /// last-wins for the operator-override use case) and was a
    /// maintenance hazard: a future direct caller of [`Self::new`]
    /// that assumed the obvious "operator override appended last"
    /// semantics would silently get the opposite. Unifying both
    /// constructors on last-wins eliminates the surface area.
    #[must_use]
    pub fn new(mut entries: Vec<BypassEntry>) -> Self {
        // Canonicalise to lowercase + `*.`-stripped form first so
        // an operator-authored `Chase.COM` or `*.chase.com`
        // collides with the industry-default `chase.com` on the
        // adjacency sort below. Without this the runtime matcher
        // (case-insensitive, `*.`-prefix-agnostic) would see both
        // and the operator's intended override could silently be
        // lost.
        for e in &mut entries {
            e.suffix = canonicalize_suffix(&e.suffix);
        }
        // Stable sort by suffix string so same-suffix entries are
        // adjacent in input order. The `Vec::sort_by`
        // documentation pins this as a stable sort.
        //
        // SORT-STABILITY INVARIANT — DO NOT change `sort_by` to
        // `sort_unstable_by`: the last-wins contract above
        // depends on `Vec::sort_by` being a *stable* sort
        // (documented at <https://doc.rust-lang.org/std/vec/struct.Vec.html#method.sort_by>).
        // With a stable sort, two entries that compare equal
        // (same suffix) keep their relative input order, so the
        // later one lands *after* the earlier one in the sorted
        // vector and the merge loop below replaces the earlier
        // entry with it. An unstable sort would be free to swap
        // them, silently flipping the merge so the *first*-in-
        // input wins — catastrophic for `with_extensions`'s
        // operator-override contract, which calls `Self::new` to
        // do the resolution.
        entries.sort_by(|a, b| a.suffix.cmp(&b.suffix));
        // Walk adjacent same-suffix entries and keep the last one
        // (operator override / later-in-input wins). Identical
        // (suffix, category) pairs collapse trivially — the second
        // replaces the first with byte-identical contents — so the
        // simple-dedup case is still covered without a separate
        // `Vec::dedup` call.
        let mut merged: Vec<BypassEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(last) = merged.last_mut() {
                if last.suffix == entry.suffix {
                    *last = entry;
                    continue;
                }
            }
            merged.push(entry);
        }
        // Final sort: longest-suffix first so the evaluate-time
        // walk finds the most-specific match first.
        merged.sort_by(|a, b| {
            b.suffix
                .len()
                .cmp(&a.suffix.len())
                .then_with(|| a.suffix.cmp(&b.suffix))
        });
        Self { entries: merged }
    }

    /// Construct a bypass list from the baked-in industry
    /// defaults. The caller normally merges these with operator
    /// extensions (`with_extensions`) before installing into the
    /// manager.
    #[must_use]
    pub fn industry_defaults() -> Self {
        Self::new(industry_defaults())
    }

    /// Merge operator-authored extensions on top of the
    /// current list. Operator entries that share a suffix with a
    /// default override the default's category — this is how an
    /// operator demotes a default category they don't recognise
    /// in their environment.
    ///
    /// The override resolution is delegated to [`Self::new`],
    /// which applies last-wins on canonical-suffix collisions.
    /// Operator entries are appended after the existing defaults
    /// in the combined input vector, so the stable adjacency sort
    /// inside [`Self::new`] places the operator entry after the
    /// matching default and the merge loop keeps the operator's
    /// category. Pinned by
    /// `operator_extension_overrides_default_category` and
    /// `with_extensions_normalizes_wildcard_prefix_against_default`.
    #[must_use]
    pub fn with_extensions(mut self, extra: Vec<BypassEntry>) -> Self {
        // Build the combined input vector with defaults first and
        // operator entries second. The override semantics depend
        // entirely on this ordering — [`Self::new`] resolves
        // same-suffix collisions with last-wins, so anything
        // appearing later in the combined vector overrides what
        // came earlier.
        let mut combined = std::mem::take(&mut self.entries);
        combined.extend(extra);
        // [`Self::new`] canonicalises (so input-form variants like
        // `Chase.COM` or `*.chase.com` collide with the
        // industry-default `chase.com` on the merge step),
        // resolves same-suffix collisions with last-wins, and
        // sorts by length-desc for the evaluate-time walk. Letting
        // it do the work means there is exactly one definition of
        // "same-suffix collision" in this module, eliminating the
        // historical asymmetry where the direct [`Self::new`]
        // path used first-wins and the merge path here used
        // last-wins.
        Self::new(combined)
    }

    /// Number of bypass entries. Mostly for telemetry / debug
    /// log lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the bypass list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate the entries in the order the matcher walks them
    /// (longest-suffix first). Used by the control-plane render
    /// surface to display exactly what the edge will enforce.
    pub fn iter(&self) -> impl Iterator<Item = &BypassEntry> {
        self.entries.iter()
    }

    /// Evaluate an SNI against the bypass list. The matcher walks
    /// entries in longest-suffix-first order so the most specific
    /// entry wins.
    #[must_use]
    pub fn evaluate(&self, sni: Option<&str>) -> BypassDecision {
        let Some(sni) = sni else {
            return BypassDecision {
                bypass: false,
                reason: BypassReason::NoSni,
            };
        };
        for entry in &self.entries {
            if sni_suffix_match(&entry.suffix, sni) {
                return BypassDecision {
                    bypass: true,
                    reason: BypassReason::Matched(entry.clone()),
                };
            }
        }
        BypassDecision {
            bypass: false,
            reason: BypassReason::NoMatch,
        }
    }
}

/// The baked-in industry-default bypass list. Conservative — only
/// covers categories where an operator-MITM would have a real
/// regulatory / contractual cost. Operators who explicitly want
/// the inspection path for these categories can override per
/// suffix via [`BypassList::with_extensions`] with their own
/// category labels.
#[must_use]
pub fn industry_defaults() -> Vec<BypassEntry> {
    // Categories deliberately kept narrow:
    //   `tls.healthcare` — HIPAA-covered patient portals.
    //   `tls.finance` — retail and commercial online banking.
    //   `tls.government` — citizen-facing tax / benefits portals.
    //   `tls.identity_provider` — operator-trusted IdPs whose
    //     traffic is itself e2e auth material we do not want to
    //     interpose between client and IdP.
    //
    // Each suffix entry shaves "*." off because the
    // sni_suffix_match helper treats both forms identically.
    let raw: &[(&str, &str)] = &[
        ("mychart.com", "tls.healthcare"),
        ("epicportal.com", "tls.healthcare"),
        ("nhs.uk", "tls.healthcare"),
        ("kaiserpermanente.org", "tls.healthcare"),
        ("chase.com", "tls.finance"),
        ("bankofamerica.com", "tls.finance"),
        ("wellsfargo.com", "tls.finance"),
        ("citi.com", "tls.finance"),
        ("hsbc.com", "tls.finance"),
        ("barclays.co.uk", "tls.finance"),
        ("paypal.com", "tls.finance"),
        ("irs.gov", "tls.government"),
        ("ssa.gov", "tls.government"),
        ("hmrc.gov.uk", "tls.government"),
        ("login.microsoftonline.com", "tls.identity_provider"),
        ("accounts.google.com", "tls.identity_provider"),
        ("login.salesforce.com", "tls.identity_provider"),
        ("okta.com", "tls.identity_provider"),
    ];
    raw.iter()
        .map(|(suffix, category)| BypassEntry {
            suffix: (*suffix).to_string(),
            category: (*category).to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn entry(suffix: &str, cat: &str) -> BypassEntry {
        BypassEntry {
            suffix: suffix.into(),
            category: cat.into(),
        }
    }

    #[test]
    fn empty_list_returns_no_match() {
        let bl = BypassList::default();
        let d = bl.evaluate(Some("bank.com"));
        assert!(!d.bypass);
        assert_eq!(d.reason, BypassReason::NoMatch);
    }

    #[test]
    fn missing_sni_is_distinct_from_no_match() {
        // The manager applies different policy for "no SNI sent"
        // vs "SNI sent but didn't match". The evaluator must
        // surface the distinction so the manager doesn't have to
        // re-derive it.
        let bl = BypassList::new(vec![entry("bank.com", "tls.finance")]);
        let d = bl.evaluate(None);
        assert!(!d.bypass);
        assert_eq!(d.reason, BypassReason::NoSni);
    }

    #[test]
    fn permissive_apex_match_succeeds() {
        // Operator wrote `*.bank.com`; the matcher must accept
        // the bare apex `bank.com` because the SNI bypass list
        // semantics are intentionally permissive (see comment on
        // sng_fw::sni_suffix_match).
        let bl = BypassList::new(vec![entry("*.bank.com", "tls.finance")]);
        let d = bl.evaluate(Some("bank.com"));
        assert!(d.bypass);
        match d.reason {
            BypassReason::Matched(e) => assert_eq!(e.category, "tls.finance"),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn deep_subdomain_match_succeeds() {
        let bl = BypassList::new(vec![entry("bank.com", "tls.finance")]);
        let d = bl.evaluate(Some("login.eu.online.bank.com"));
        assert!(d.bypass);
    }

    #[test]
    fn longest_suffix_wins() {
        // Operator wrote a generic `*.bank.com` bypass plus an
        // override for `*.internal.bank.com` (different category
        // — say they want telemetry on the internal traffic via
        // a different bucket). The matcher must pick the
        // longer / more specific suffix.
        let bl = BypassList::new(vec![
            entry("bank.com", "tls.finance"),
            entry("internal.bank.com", "tls.internal"),
        ]);
        let d = bl.evaluate(Some("app.internal.bank.com"));
        assert!(d.bypass);
        match d.reason {
            BypassReason::Matched(e) => {
                assert_eq!(e.suffix, "internal.bank.com");
                assert_eq!(e.category, "tls.internal");
            }
            other => panic!("expected Matched(internal.bank.com), got {other:?}"),
        }
    }

    #[test]
    fn case_insensitive_match() {
        // Real ClientHello SNIs are usually lowercase but the
        // matcher must not depend on it — case folding is part
        // of sni_suffix_match's contract.
        let bl = BypassList::new(vec![entry("Bank.Com", "tls.finance")]);
        let d = bl.evaluate(Some("LOGIN.bank.com"));
        assert!(d.bypass);
    }

    #[test]
    fn industry_defaults_include_healthcare_finance_government_idp() {
        // Lock in that the baked-in defaults cover the four
        // categories we promise in the module docs. A future
        // refactor that drops one of these would silently
        // regress operator expectations.
        let bl = BypassList::industry_defaults();
        let categories: std::collections::BTreeSet<_> =
            bl.iter().map(|e| e.category.clone()).collect();
        for required in [
            "tls.healthcare",
            "tls.finance",
            "tls.government",
            "tls.identity_provider",
        ] {
            assert!(
                categories.contains(required),
                "industry defaults missing {required}: {categories:?}"
            );
        }
    }

    #[test]
    fn operator_extension_overrides_default_category() {
        // The operator's chase.com listing wins the category — a
        // tenant tagging Chase as "tls.tenant-finance" must see
        // their label in the verdict reason, not the default
        // "tls.finance".
        let bl = BypassList::industry_defaults()
            .with_extensions(vec![entry("chase.com", "tls.tenant-finance")]);
        let d = bl.evaluate(Some("online.chase.com"));
        assert!(d.bypass);
        match d.reason {
            BypassReason::Matched(e) => assert_eq!(e.category, "tls.tenant-finance"),
            other => panic!("expected operator override, got {other:?}"),
        }
    }

    #[test]
    fn with_extensions_normalizes_wildcard_prefix_against_default() {
        // Regression test: an operator who writes `*.chase.com`
        // (a common SNI bypass syntax that mirrors how the
        // defaults are documented in the module-level docs)
        // must collide-and-override the industry default
        // `chase.com` entry rather than land alongside it as a
        // semantically-equivalent duplicate.
        //
        // Before canonicalize_suffix stripped the leading `*.`,
        // the merge dedup was exact-string equality between
        // `*.chase.com` and `chase.com` — so the operator's
        // intended override would be carried as a *second*
        // entry, and `len()` / telemetry would report two
        // semantically-equivalent rows. The length-desc re-sort
        // in `new()` happened to put `*.chase.com` first so the
        // runtime walk picked the operator's category, but the
        // duplicate row stayed in the list, polluting the
        // control-plane review surface and inflating bundle
        // digest churn on no-op operator edits.
        //
        // With canonicalization, both forms land on the same
        // stored bytes (`chase.com`), the dedup loop replaces
        // the default's entry with the operator's, and the
        // merged list has exactly one Chase entry carrying
        // the operator's category.
        let bl = BypassList::industry_defaults()
            .with_extensions(vec![entry("*.chase.com", "tls.tenant-strict")]);
        // Operator's category wins.
        let d = bl.evaluate(Some("online.chase.com"));
        assert!(d.bypass);
        match &d.reason {
            BypassReason::Matched(e) => {
                assert_eq!(e.category, "tls.tenant-strict");
                // And the stored suffix is the canonical
                // stripped form — not the operator's `*.` input.
                assert_eq!(e.suffix, "chase.com");
            }
            other => panic!("expected operator override with `*.` prefix, got {other:?}"),
        }
        // And there is *exactly one* Chase entry in the merged
        // list, not two — the `*.chase.com` operator input did
        // not land alongside the default's `chase.com`.
        let chase_entries: Vec<_> = bl.iter().filter(|e| e.suffix == "chase.com").collect();
        assert_eq!(
            chase_entries.len(),
            1,
            "`*.chase.com` operator input must canonicalize to dedup against default `chase.com`, \
             not coexist as a semantic duplicate: {:?}",
            bl.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn new_strips_wildcard_prefix_to_canonical_form() {
        // The constructor stores suffixes in canonical form
        // (lowercase + `*.` stripped) so consumers that iterate
        // entries see the matcher-equivalent canonical bytes,
        // not whatever input form the operator typed. Two
        // entries that differ only in `*.` prefix collapse to
        // one row.
        let bl = BypassList::new(vec![
            entry("*.bank.com", "tls.finance"),
            entry("bank.com", "tls.finance"),
        ]);
        assert_eq!(bl.len(), 1);
        let only = bl.iter().next().unwrap();
        assert_eq!(only.suffix, "bank.com");
        assert_eq!(only.category, "tls.finance");
    }

    #[test]
    fn duplicate_entries_are_dropped() {
        // Two identical (suffix, category) entries — possible
        // when an operator extends a default that already
        // covers the suffix with the same category — must
        // collapse to a single entry so the matcher walk does
        // not double-process them.
        let bl = BypassList::new(vec![
            entry("bank.com", "tls.finance"),
            entry("bank.com", "tls.finance"),
        ]);
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn new_last_wins_on_same_suffix_different_category() {
        // The constructor unifies same-suffix conflict resolution
        // on last-wins so a direct caller of `BypassList::new`
        // gets the same semantics as `with_extensions`: append the
        // override-source entry after the source to override, and
        // it wins. The previous first-wins behaviour was a
        // maintenance hazard — a direct caller assuming the
        // "obvious" last-wins (operator override appended last)
        // semantics would silently get the opposite, and the rule
        // diverged from `with_extensions` for no good reason.
        //
        // Pin the contract so a future refactor that swaps the
        // adjacency sort for `sort_unstable_by` or that reverts to
        // the old dedup-by-(suffix,category) immediately fails this
        // test rather than silently flipping merge semantics on
        // every direct caller of `Self::new`.
        let bl = BypassList::new(vec![
            entry("bank.com", "tls.finance"),
            entry("bank.com", "tls.tenant-override"),
        ]);
        assert_eq!(bl.len(), 1, "same-suffix entries must collapse");
        let only = bl.iter().next().unwrap();
        assert_eq!(
            only.category, "tls.tenant-override",
            "last-in-input must win on same-suffix conflict"
        );
    }

    #[test]
    fn new_last_wins_across_input_form_variants() {
        // Defence-in-depth: the last-wins contract must hold
        // across input forms that the canonicaliser folds together
        // (case, `*.` prefix). An operator that authors
        // `*.Bank.COM` with their own category after a default
        // `bank.com` must end up with their category — both
        // canonicalisation and last-wins must agree.
        let bl = BypassList::new(vec![
            entry("bank.com", "tls.finance"),
            entry("*.Bank.COM", "tls.tenant-override"),
        ]);
        assert_eq!(bl.len(), 1);
        let only = bl.iter().next().unwrap();
        assert_eq!(only.suffix, "bank.com");
        assert_eq!(only.category, "tls.tenant-override");
    }

    #[test]
    fn evaluation_is_deterministic_across_construction_orders() {
        // The constructor sorts so two BypassList instances
        // built from the same set in different orders evaluate
        // any SNI to byte-identical decisions. The manager
        // depends on this when computing the config digest for
        // the hot-swap dedup path.
        let a = BypassList::new(vec![
            entry("bank.com", "tls.finance"),
            entry("internal.bank.com", "tls.internal"),
        ]);
        let b = BypassList::new(vec![
            entry("internal.bank.com", "tls.internal"),
            entry("bank.com", "tls.finance"),
        ]);
        for sni in [
            "bank.com",
            "internal.bank.com",
            "login.bank.com",
            "other.example",
        ] {
            assert_eq!(a.evaluate(Some(sni)), b.evaluate(Some(sni)), "sni={sni}");
        }
    }
}
