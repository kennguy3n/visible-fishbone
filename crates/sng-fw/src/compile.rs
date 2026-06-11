//! Compilation: policy bundle NGFW slice → executable rule set.
//!
//! The compiler takes the NGFW rules out of a
//! [`sng_policy_eval::bundle::LoadedBundle`], the operator's
//! zone table, and the NAT table, and emits:
//!
//! * A [`Vec<FirewallRule>`] for the engine's per-packet walk.
//! * An [`NftablesScript`] for the kernel apply path. The script
//!   is deterministic: same inputs produce byte-identical bytes,
//!   so [`crate::engine::FirewallEngine::compile_and_swap`] can
//!   short-circuit on a matching SHA-256 hash rather than re-
//!   apply the same rules.
//!
//! The compiler intentionally does *not* talk to the kernel —
//! that's the [`crate::nftables::NftablesBackend`]'s job. This
//! separation lets unit tests run the compiler in pure-userland
//! and snapshot the script string for assertion without ever
//! touching `nft`.
//!
//! Rule translation rules:
//!
//! * Every NGFW rule whose verb is one of
//!   `Allow`, `Deny`, `Inspect`, `Log`, `Steer` becomes one
//!   [`FirewallRule`]. `Decrypt` is a TLS-policy concern (handled
//!   in [`crate::tls_policy`]) and is filtered out here.
//! * `SuggestOnly` rules with a wrapped enforcement verb are
//!   compiled as `Log` so they emit telemetry but do not enforce
//!   — matches the architecture's "shadow rule" rollout pattern.
//! * Inline subject matchers (e.g. `Cidr { … }`) populate the
//!   rule's `src_cidrs` (for `kind = network` source subjects).
//!   Named subject references are resolved through the bundle's
//!   subject map.
//! * Zone references on a rule must exist in the supplied
//!   [`ZoneTable`] — the compile fails otherwise. The compiler
//!   is fail-closed: a typo in a zone reference cannot silently
//!   become "any zone".

use ipnet::IpNet;
use sng_policy_eval::bundle::LoadedBundle;
use sng_policy_eval::matcher::SubjectMatch;
use sng_policy_eval::rule::{EnforcementDomain, Rule, SubjectKind, Verb};
use std::collections::BTreeSet;

use crate::error::FirewallError;
use crate::nat::NatTable;
use crate::nftables::{NftablesScript, escape_nft_comment};
use crate::rule::{FirewallRule, RuleAction, RuleMatch};
use crate::zone::{AddressFamily, ZoneTable};

/// The compiled output of one bundle + zone-table + nat-table
/// pass. Held inside [`crate::engine::FirewallEngine`] behind an
/// `ArcSwap` so the hot path reads it without locking.
#[derive(Clone, Debug)]
pub struct CompiledRuleSet {
    /// The filter rules in evaluation order. First match wins.
    pub rules: Vec<FirewallRule>,
    /// The zone table the engine evaluates against.
    pub zones: ZoneTable,
    /// The NAT table the engine emits.
    pub nat: NatTable,
    /// The default verdict when no rule matches — derived from
    /// the bundle's `default_verb`.
    pub default_action: RuleAction,
    /// Source bundle graph id (for telemetry / audit).
    pub source_graph_id: String,
    /// Source bundle graph version. Monotonically increases —
    /// the engine's hot-swap path rejects downgrades.
    pub source_graph_version: i64,
    /// Compiled nftables script. Cached so re-applying the same
    /// ruleset is a no-op.
    pub script: NftablesScript,
}

/// One-shot compiler. Stateless — construct, call `compile`,
/// discard.
#[derive(Debug, Default)]
pub struct RuleCompiler;

impl RuleCompiler {
    /// New compiler.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compile the NGFW slice of `bundle` against `zones` and
    /// `nat`. The compiler validates every zone reference and
    /// emits a deterministic [`NftablesScript`].
    pub fn compile(
        &self,
        bundle: &LoadedBundle,
        zones: ZoneTable,
        nat: NatTable,
    ) -> Result<CompiledRuleSet, FirewallError> {
        zones
            .validate()
            .map_err(|e| FirewallError::BundleInvalid(format!("zone table invalid: {e}")))?;
        nat.validate()
            .map_err(|e| FirewallError::BundleInvalid(format!("nat table invalid: {e}")))?;

        // Pre-build a name → subject lookup so refs resolve
        // without scanning the rule list per match. `LoadedBundle`
        // exposes its own private lookup but doesn't expose it
        // publicly, so we walk `bundle.rules` once here.
        let subject_lookup = collect_named_subjects(&bundle.rules);

        let mut compiled_rules = Vec::with_capacity(bundle.rules.len());
        for r in bundle.rules.iter() {
            if !r.applies_to_domain(EnforcementDomain::Ngfw) {
                continue;
            }
            if let Some(rule) = compile_one(r, &subject_lookup, &zones)? {
                compiled_rules.push(rule);
            }
        }

        let default_action = verb_to_action(bundle.default_verb).unwrap_or(RuleAction::Deny);

        let script = render_script(&compiled_rules, &zones, &nat, default_action)?;

        Ok(CompiledRuleSet {
            rules: compiled_rules,
            zones,
            nat,
            default_action,
            source_graph_id: bundle.graph_id.clone(),
            source_graph_version: bundle.graph_version,
            script,
        })
    }
}

fn collect_named_subjects(
    rules: &[Rule],
) -> std::collections::HashMap<String, sng_policy_eval::rule::Subject> {
    let mut out = std::collections::HashMap::new();
    for r in rules {
        for s in &r.subjects {
            if !s.name.is_empty() {
                out.entry(s.name.clone()).or_insert_with(|| s.clone());
            }
        }
    }
    out
}

fn compile_one(
    raw: &Rule,
    subject_lookup: &std::collections::HashMap<String, sng_policy_eval::rule::Subject>,
    zones: &ZoneTable,
) -> Result<Option<FirewallRule>, FirewallError> {
    // Suggest-only with an inner verb compiles as `Log` so it
    // emits telemetry but never enforces — the architecture's
    // "shadow rule" pattern. Suggest-only without an inner verb
    // is rejected by the bundle decoder up front
    // (`PolicyEvalError::SuggestOnlyMissingSuggestion`), so the
    // defensive branch here just defends against a hypothetical
    // future where the decoder relaxes that check.
    let verb = if matches!(raw.verb, Verb::SuggestOnly) {
        if raw.suggested_verb.is_some() {
            Verb::Log
        } else {
            return Ok(None);
        }
    } else {
        raw.verb
    };

    let Some(action) = verb_to_action(verb) else {
        // Decrypt verdicts belong to the TLS-policy module and
        // do not compile into a filter rule.
        return Ok(None);
    };

    let mut matches = RuleMatch::default();

    // Inline subjects — fold each into the rule's L3 / L4
    // predicate. `fold_subject` is fail-closed: an unknown or
    // logically incoherent (kind, matcher) combination errors
    // here rather than silently widening the rule to match
    // every flow.
    for s in &raw.subjects {
        fold_subject(&raw.id, s.kind, &s.matcher, &mut matches)?;
    }
    // Named subject references — resolve through the lookup
    // built from the bundle's rules.
    for name in &raw.subject_refs {
        if let Some(s) = subject_lookup.get(name) {
            fold_subject(&raw.id, s.kind, &s.matcher, &mut matches)?;
        } else {
            return Err(FirewallError::BundleInvalid(format!(
                "ngfw rule {} references unknown subject {name}",
                raw.id
            )));
        }
    }

    // Zone references — must exist in the table.
    let mut from_zones = Vec::new();
    let mut to_zones = Vec::new();
    for (name, list, kind) in [
        ("from", &mut from_zones, "from_zone"),
        ("to", &mut to_zones, "to_zone"),
    ] {
        if let Some(v) = raw.extra.get(&format!("{name}_zones")) {
            let zone_names: Vec<String> = serde_json::from_value(v.clone()).map_err(|e| {
                FirewallError::BundleInvalid(format!(
                    "ngfw rule {} has malformed {kind}s: {e}",
                    raw.id
                ))
            })?;
            for z in &zone_names {
                if !zones.zones.contains_key(z) {
                    return Err(FirewallError::BundleInvalid(format!(
                        "ngfw rule {} references unknown {kind} {z}",
                        raw.id
                    )));
                }
            }
            *list = zone_names;
        }
    }

    Ok(Some(FirewallRule {
        id: raw.id.clone(),
        matches,
        action,
        from_zones,
        to_zones,
        description: raw.description.clone(),
    }))
}

/// Fold one (kind, matcher) pair into the rule's accumulated
/// `RuleMatch`. Fail-closed:
///
/// * **Recognised combinations** populate the appropriate slot
///   (`Network|Device + Cidr` → `src_cidrs`;
///   `User|App|Site + Literal/AnyOf` → `subject`).
/// * **Explicit `Any`** — `(kind, SubjectMatch::Any)` is accepted
///   and leaves the predicate slot untouched. This is the
///   operator's explicit "no constraint on this kind" signal
///   (e.g. "any user can reach this resource if other predicates
///   match"). Leaving `RuleMatch.subject` at its default `Any` is
///   the same as what the engine sees on a rule with no subject
///   at all.
/// * **Forward-compat `Unknown`** — rejected with
///   `FirewallError::BundleInvalid`. The decoder uses
///   `SubjectMatch::Unknown` to model matcher shapes from future
///   schema versions that this build doesn't recognise. Silently
///   matching them would widen rules unpredictably; rejecting at
///   compile means a bundle authored against a newer schema is
///   refused on the edge VM rather than enforcing partially.
/// * **Incoherent combinations** — e.g.
///   `(User, Cidr)`, `(Network, Literal)`,
///   `(User|App|Site, DomainSuffix)` — rejected with
///   `FirewallError::BundleInvalid`. The control-plane rule
///   validator (`sng-policy-eval::rule::Rule::validate`) is the
///   first line of defence against these, but defence-in-depth
///   says we fail at compile rather than trust the upstream
///   validator to be complete.
fn fold_subject(
    rule_id: &str,
    kind: SubjectKind,
    matcher: &SubjectMatch,
    into: &mut RuleMatch,
) -> Result<(), FirewallError> {
    match (kind, matcher) {
        // Source / network subjects become CIDR predicates on
        // the rule's src_cidrs. Device subjects with a literal
        // CIDR fold to the same predicate — common pattern when
        // the operator pins a workstation by static lease.
        (SubjectKind::Network | SubjectKind::Device, SubjectMatch::Cidr { cidr }) => {
            into.src_cidrs.push(*cidr);
            Ok(())
        }
        // User / app / site / device subjects fold into the
        // rule's subject matcher so the engine's hot path runs
        // the string compare. Multiple subject vertices collapse
        // into a single AnyOf — the union of values. Device is
        // included here because operators can also pin a rule to
        // a literal device id (vs the Network/Cidr fold above
        // for static-lease devices).
        (
            SubjectKind::User | SubjectKind::App | SubjectKind::Site | SubjectKind::Device,
            SubjectMatch::Literal { value },
        ) => {
            merge_subject_literal(&mut into.subject, value.clone());
            Ok(())
        }
        (
            SubjectKind::User | SubjectKind::App | SubjectKind::Site | SubjectKind::Device,
            SubjectMatch::AnyOf { values },
        ) => {
            for v in values {
                merge_subject_literal(&mut into.subject, v.clone());
            }
            Ok(())
        }
        // Explicit "no constraint on this kind" — accept and
        // leave the rule's matcher untouched.
        (_, SubjectMatch::Any) => Ok(()),
        // Forward-compat sentinel — refuse to compile a rule
        // whose matcher shape this build does not recognise.
        (_, SubjectMatch::Unknown) => Err(FirewallError::BundleInvalid(format!(
            "ngfw rule {rule_id} uses an unrecognised subject matcher shape \
             (forward-compat sentinel); refusing to compile so the rule does \
             not silently widen to match every flow"
        ))),
        // Anything else — incoherent combinations like
        // `(SubjectKind::User, SubjectMatch::Cidr)` or
        // `(SubjectKind::Network, SubjectMatch::Literal)`. Fail
        // the compile rather than silently produce an empty
        // predicate.
        (k, m) => Err(FirewallError::BundleInvalid(format!(
            "ngfw rule {rule_id} has incompatible subject: kind {k:?} \
             cannot be combined with matcher {}",
            describe_matcher(m)
        ))),
    }
}

fn describe_matcher(m: &SubjectMatch) -> &'static str {
    match m {
        SubjectMatch::Any => "any",
        SubjectMatch::Literal { .. } => "literal",
        SubjectMatch::AnyOf { .. } => "any_of",
        SubjectMatch::Cidr { .. } => "cidr",
        SubjectMatch::DomainSuffix { .. } => "domain_suffix",
        SubjectMatch::Unknown => "unknown",
    }
}

fn merge_subject_literal(slot: &mut SubjectMatch, value: String) {
    match slot {
        SubjectMatch::Any => {
            *slot = SubjectMatch::Literal { value };
        }
        SubjectMatch::Literal { value: existing } => {
            // Folding the same literal twice (e.g. two subjects
            // both `Device(literal "device-42")`) is harmless
            // matching-wise but would produce a degenerate
            // `AnyOf { values: ["device-42", "device-42"] }`
            // that's inconsistent with the dedup the `AnyOf`
            // branch below performs. Keep the slot as the
            // existing `Literal` instead of promoting to a
            // single-element `AnyOf`.
            if *existing == value {
                return;
            }
            // Promote single literal to AnyOf when a *different*
            // second value is folded in.
            *slot = SubjectMatch::AnyOf {
                values: vec![existing.clone(), value],
            };
        }
        SubjectMatch::AnyOf { values } => {
            if !values.contains(&value) {
                values.push(value);
            }
        }
        // Cidr / DomainSuffix / Unknown: respect the existing
        // matcher and skip — folding heterogeneous matcher
        // kinds would produce a logically incoherent rule.
        SubjectMatch::Cidr { .. } | SubjectMatch::DomainSuffix { .. } | SubjectMatch::Unknown => {}
    }
}

fn verb_to_action(v: Verb) -> Option<RuleAction> {
    match v {
        Verb::Allow => Some(RuleAction::Allow),
        Verb::Deny => Some(RuleAction::Deny),
        Verb::Inspect => Some(RuleAction::Inspect),
        Verb::Log => Some(RuleAction::Log),
        Verb::Steer => Some(RuleAction::Steer),
        // Decrypt is the TLS-policy module's verb; SuggestOnly
        // is handled by the caller (which translates it into a
        // Log rule when the inner verb is present).
        Verb::Decrypt | Verb::SuggestOnly => None,
    }
}

/// Render the deterministic nftables script for an already-assembled rule
/// set (resolved filter rules + zone table + NAT table + chain default
/// verdict).
///
/// This is the exact routine [`RuleCompiler::compile`] runs internally to
/// populate [`CompiledRuleSet::script`]. Exposing it lets callers that
/// assemble a [`CompiledRuleSet`] directly — the efficacy harness's kernel
/// conformance check, an offline `sng-fw` dry-run / `--check` — obtain the
/// byte-identical artifact the kernel apply path ([`crate::engine::FirewallEngine::install`])
/// loads, without re-deriving the translation. Output is deterministic:
/// identical inputs yield identical bytes (and therefore an identical
/// SHA-256 digest), so a rendered script can be compared across runs.
pub fn render_nftables(
    rules: &[FirewallRule],
    zones: &ZoneTable,
    nat: &NatTable,
    default_action: RuleAction,
) -> Result<NftablesScript, FirewallError> {
    render_script(rules, zones, nat, default_action)
}

fn render_script(
    rules: &[FirewallRule],
    zones: &ZoneTable,
    nat: &NatTable,
    default_action: RuleAction,
) -> Result<NftablesScript, FirewallError> {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("# sng-fw compiled ruleset\n");
    out.push_str("add table inet sng_filter\n");
    // Wipe the table before every rotation so the kernel sees
    // the new bundle as a *replacement*, not an *append*.
    //
    // `nft` commands run by `nft -f` are wrapped in a single
    // netlink transaction, so the kernel atomically sees
    // "flush + re-populate" as one commit — no traffic-window
    // where the table is empty. Without the flush, every install
    // would *append*: `add rule ...` appends to whatever the
    // chain already contains, `add element ...` appends to a
    // set's element list, and `add chain ...` with attributes is
    // a no-op if the chain already exists (so a new
    // `policy drop` would not replace an existing `policy
    // accept`). The result on the old code path was that:
    //
    // * Removing a rule from a bundle left the kernel rule live.
    // * Changing the chain's default policy did not propagate.
    // * Zone-set elements accumulated across rotations.
    //
    // The in-memory engine swaps cleanly via `ArcSwap` so it
    // would report the new verdict, while the kernel kept the
    // stale rule — a security-relevant split-brain. The flush
    // makes the script idempotent under repeated apply.
    out.push_str("flush table inet sng_filter\n");
    // Define one set per zone-family pair so the rule chain can
    // match on `ip saddr @zone_<name>` / `ip6 saddr @zone6_<name>`.
    // Each set is created only when the zone actually has
    // networks of that family — emitting an empty IPv4 set for
    // an IPv6-only zone wastes a slot in the kernel set table
    // and would never be referenced by a rule (the
    // `zone_has_family` check in `render_rule` skips it).
    for z in zones.zones.values() {
        let name = sanitize_set_name(&z.name);
        if z.networks.iter().any(|n| matches!(n, IpNet::V4(_))) {
            let _ = writeln!(
                out,
                "add set inet sng_filter zone_{name} {{ type ipv4_addr; flags interval; }}"
            );
            for n in &z.networks {
                if let IpNet::V4(v4) = n {
                    let _ = writeln!(out, "add element inet sng_filter zone_{name} {{ {v4} }}");
                }
            }
        }
        if z.networks.iter().any(|n| matches!(n, IpNet::V6(_))) {
            let _ = writeln!(
                out,
                "add set inet sng_filter zone6_{name} {{ type ipv6_addr; flags interval; }}"
            );
            for n in &z.networks {
                if let IpNet::V6(v6) = n {
                    let _ = writeln!(out, "add element inet sng_filter zone6_{name} {{ {v6} }}");
                }
            }
        }
    }

    // Two filter chains are emitted: `forward` carries every
    // operator rule, `input` carries only the chain-default
    // policy. The asymmetry is deliberate, not an oversight:
    //
    // * `FirewallRule` is a zone-to-zone (`from_zones` ×
    //   `to_zones`) routing predicate — see `rule.rs`
    //   `FirewallRule` and `engine.rs` `evaluate`. Zone-to-zone
    //   semantics inherently describe *forwarded* traffic
    //   between two zones; packets terminated on the edge VM
    //   itself (SSH to the management port, the local
    //   sng-telemetry receiver, a kubelet probe) have no
    //   `to_zone` because the box is not "in" any zone — it
    //   *owns* the zones. Applying zone rules to such traffic
    //   would silently classify management plane traffic into
    //   whatever zone happens to alphabetise first (the
    //   tie-break path in `zone.rs:309`), which is the opposite
    //   of zero-trust posture.
    //
    // * The `input` chain is therefore intentionally minimal:
    //   it just locks the chain policy to the same default
    //   (typically `drop` for `Deny`) so unsolicited traffic
    //   *to* the box is uniformly rejected. Hardening of
    //   management ports (SSH allowlist, telemetry mTLS, etc.)
    //   is owned by the host's own systemd unit / kubelet
    //   network policy, not by the data-plane firewall — those
    //   live below this layer.
    //
    // * If a future rule type needs to filter
    //   terminated-on-host traffic, it should be a new rule
    //   shape (e.g. `LocalRule` with `interface` + protocol +
    //   port, no zones), not a quiet promotion of the existing
    //   forwarding rules into `input` — promoting them would
    //   misapply zone semantics and create exactly the
    //   classify-vs-kernel split-brain that
    //   `reject_cross_zone_overlap` (zone.rs:370) and the
    //   `flush table` directive above were added to prevent.
    out.push_str(
        "add chain inet sng_filter input { type filter hook input priority filter; policy ",
    );
    out.push_str(default_chain_policy(default_action));
    out.push_str("; }\n");
    out.push_str(
        "add chain inet sng_filter forward { type filter hook forward priority filter; policy ",
    );
    out.push_str(default_chain_policy(default_action));
    out.push_str("; }\n");

    // Per-rule lines, in source order. One logical FirewallRule
    // may expand into multiple nftables lines — one per address
    // family the rule can apply to, and one per
    // (from_zone × to_zone) cross-product when the rule lists
    // multiple zones. The engine's in-memory walk treats those
    // expansions as the same rule (the `id` is preserved on
    // every emitted line via the trailing `comment`).
    for r in rules {
        out.push_str(&render_rule(r, zones)?);
    }

    // NAT table appended after the filter table — kernel
    // commits both transactionally. `render_nft` returns the
    // full NAT block when there are rules, or a two-line
    // `add table` + `delete table` atomic cleanup directive
    // when there are not — so a bundle that rotates from
    // NAT-present to NAT-empty actually tears down the
    // previous `inet sng_nat` table in the kernel instead of
    // leaving its prerouting / postrouting chains live.
    // Propagate `NatTable::render_nft`'s `Result` via `?` so an
    // internal invariant violation on the NAT side (e.g. a
    // family-agnostic slot receiving CIDR predicates) fails the
    // bundle install cleanly with `FirewallError::BundleInvalid`,
    // mirroring `render_single_rule`'s behaviour on the filter
    // side (commit 9502c24). The engine then keeps the previous
    // bundle live instead of unwinding the manager task on a
    // release-build panic.
    out.push_str(&nat.render_nft()?);
    Ok(NftablesScript::new(out.into_bytes()))
}

fn default_chain_policy(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Allow => "accept",
        // Inspect / Log / Steer / Deny all fall back to drop —
        // the marked-packet actions only make sense per-rule,
        // not as chain defaults.
        RuleAction::Deny | RuleAction::Inspect | RuleAction::Log | RuleAction::Steer => "drop",
    }
}

fn render_rule(rule: &FirewallRule, zones: &ZoneTable) -> Result<String, FirewallError> {
    use std::fmt::Write as _;

    let mut out = String::new();
    // Decide which address-family slots this logical rule
    // covers. `Some(f)` means "emit a family-qualified line for
    // family f" — the line carries `ip` / `ip6` qualified zone
    // and CIDR clauses, and would be a type error if applied to
    // the wrong family. `None` means "emit a single
    // family-agnostic line" — used when the rule has no zone
    // and no CIDR predicates at all, so there's nothing the
    // kernel could disagree about; the `inet` table accepts the
    // resulting protocol-/port-only rule for both families
    // without duplication.
    let family_slots = rule_address_families(rule, zones);

    for family in family_slots {
        // Cross-product over from_zones × to_zones. An empty
        // zone list reduces to a single `None` slot so the rule
        // is still emitted (CIDR-only or family-agnostic
        // predicates apply).
        let from_slots: Vec<Option<&String>> = if rule.from_zones.is_empty() {
            vec![None]
        } else {
            rule.from_zones.iter().map(Some).collect()
        };
        let to_slots: Vec<Option<&String>> = if rule.to_zones.is_empty() {
            vec![None]
        } else {
            rule.to_zones.iter().map(Some).collect()
        };

        for from_zone in &from_slots {
            // Skip zones that don't have any networks of this
            // family — there'd be no per-family set to match
            // against, and the in-memory engine would never
            // classify a packet of this family into the zone.
            // (Family-agnostic slots have no zones at all by
            // construction, so the check is skipped.)
            if let (Some(z), Some(f)) = (from_zone, family)
                && !zone_has_family(zones, z, f)
            {
                continue;
            }
            for to_zone in &to_slots {
                if let (Some(z), Some(f)) = (to_zone, family)
                    && !zone_has_family(zones, z, f)
                {
                    continue;
                }
                // Filter src/dst cidrs to this family (no-op
                // for family-agnostic slots, which have no
                // CIDR predicates).
                let src_cidrs: Vec<&IpNet> = rule
                    .matches
                    .src_cidrs
                    .iter()
                    .filter(|n| family.is_none_or(|f| AddressFamily::of(n) == f))
                    .collect();
                let dst_cidrs: Vec<&IpNet> = rule
                    .matches
                    .dst_cidrs
                    .iter()
                    .filter(|n| family.is_none_or(|f| AddressFamily::of(n) == f))
                    .collect();
                // Skip emission when the operator declared src/dst
                // CIDRs but none survive the family filter for this
                // slot. This is the cross-family divergence guard:
                // if a rule has e.g. `from_zones: [v4-zone]` AND
                // `src_cidrs: [v6-net]`, the v4 iteration would
                // otherwise render `ip saddr @zone_<v4-zone>` with
                // no CIDR predicate — strictly more permissive than
                // the in-memory engine (which AND-combines the v4
                // zone match with the all-CIDRs check and finds the
                // v6 CIDR doesn't contain a v4 address, so denies).
                // Skipping the whole line keeps the kernel chain at
                // worst as permissive as the in-memory engine. The
                // `_explicit` flags capture the operator's intent:
                // CIDR-empty is "any CIDR matches", CIDR-non-empty
                // is "only these CIDRs match".
                let src_explicit = !rule.matches.src_cidrs.is_empty();
                let dst_explicit = !rule.matches.dst_cidrs.is_empty();
                if src_explicit && src_cidrs.is_empty() {
                    continue;
                }
                if dst_explicit && dst_cidrs.is_empty() {
                    continue;
                }

                let line =
                    render_single_rule(rule, family, *from_zone, *to_zone, &src_cidrs, &dst_cidrs)?;
                let _ = writeln!(out, "{line}");
            }
        }
    }
    Ok(out)
}

/// Render one fully-qualified nftables rule line for the given
/// (family, from_zone, to_zone) slot. Emits zone *and* cidr
/// predicates when both are present (nftables AND-combines
/// repeated `<family> saddr` clauses), so a rule that lists
/// both is no longer silently dropped.
fn render_single_rule(
    rule: &FirewallRule,
    family: Option<AddressFamily>,
    from_zone: Option<&String>,
    to_zone: Option<&String>,
    src_cidrs: &[&IpNet],
    dst_cidrs: &[&IpNet],
) -> Result<String, FirewallError> {
    let mut parts: Vec<String> = vec!["add rule inet sng_filter forward".into()];
    // Zone / CIDR predicates are emitted only when the family
    // is known. The family-agnostic case (`family = None`) by
    // construction also has zone = None and CIDRs empty —
    // `rule_address_families` returns `vec![None]` only when
    // the rule has no zones and no CIDRs, and the zone /
    // CIDR-filter loops in `render_rule` then pass `None` /
    // empty slices into this branch.
    //
    // Wrapping the predicate emission in a single
    // `if let Some(family)` makes the invariant *structural*
    // rather than a comment: any future change that lets a
    // family-agnostic slot carry a zone or CIDR predicate
    // would either trip the `assert!` in the `else` branch
    // (catching the bug at install time, where the in-memory
    // engine is still authoritative) or land at a structural
    // rewrite of this branch. Compare to the older `map_or`
    // default that silently produced an IPv4 (`ip`) qualifier
    // on what should have been a dual-stack rule.
    if let Some(family) = family {
        let qualifier = family.nft_qualifier();
        let zone_prefix = family.nft_zone_set_prefix();
        if let Some(z) = from_zone {
            parts.push(format!(
                "{qualifier} saddr @{zone_prefix}{}",
                sanitize_set_name(z)
            ));
        }
        if !src_cidrs.is_empty() {
            let list: Vec<String> = src_cidrs.iter().map(ToString::to_string).collect();
            parts.push(format!("{qualifier} saddr {{ {} }}", list.join(", ")));
        }
        if let Some(z) = to_zone {
            parts.push(format!(
                "{qualifier} daddr @{zone_prefix}{}",
                sanitize_set_name(z)
            ));
        }
        if !dst_cidrs.is_empty() {
            let list: Vec<String> = dst_cidrs.iter().map(ToString::to_string).collect();
            parts.push(format!("{qualifier} daddr {{ {} }}", list.join(", ")));
        }
    } else {
        // Family-agnostic invariant guard. If we ever reach
        // this branch with a zone or CIDR predicate, the
        // upstream `rule_address_families` (or one of the
        // call-site loops in `render_rule`) has been changed
        // in a way that breaks the cross-family safety
        // guarantee. We *must* refuse to emit the rule line
        // — silently dropping the predicate would render the
        // line strictly more permissive than the in-memory
        // engine, which is the exact divergence this module
        // exists to prevent.
        //
        // Earlier revisions used `assert!` here. That worked
        // for dev builds but in production it would unwind
        // the manager's compile task and trip the agent's
        // panic-restart loop. Returning `FirewallError::BundleInvalid`
        // instead lets the engine fail the install cleanly,
        // keep the previous bundle live, and surface a
        // diagnosable error to the control plane. The
        // matching `debug_assert!` is still useful as a
        // dev-time stack-trace breadcrumb when a test
        // exercises the regression.
        if !(from_zone.is_none()
            && to_zone.is_none()
            && src_cidrs.is_empty()
            && dst_cidrs.is_empty())
        {
            debug_assert!(
                false,
                "render_single_rule: family-agnostic slot received \
                 zone or CIDR predicates — `rule_address_families` \
                 must never return `None` for a rule with such \
                 predicates. Rule id: {}",
                rule.id
            );
            return Err(FirewallError::BundleInvalid(format!(
                "render_single_rule: family-agnostic slot received \
                 zone or CIDR predicates for rule id {} — the \
                 compiler's family-selection (`rule_address_families`) \
                 returned `None` for a rule that has zones or CIDRs. \
                 This is an internal compiler invariant violation; \
                 fail the bundle install rather than emit a kernel \
                 line strictly more permissive than the in-memory \
                 engine.",
                rule.id
            )));
        }
    }
    if let Some(p) = rule.matches.protocol.as_nft() {
        parts.push(format!("meta l4proto {p}"));
    }
    if !rule.matches.src_ports.is_empty() {
        let list: Vec<String> = rule.matches.src_ports.iter().map(|r| r.as_nft()).collect();
        parts.push(format!("th sport {{ {} }}", list.join(", ")));
    }
    if !rule.matches.dst_ports.is_empty() {
        let list: Vec<String> = rule.matches.dst_ports.iter().map(|r| r.as_nft()).collect();
        parts.push(format!("th dport {{ {} }}", list.join(", ")));
    }
    // Mark for downstream-pipeline dispatch — emitted even for
    // non-terminal rules so the marker tap can pick them up.
    if let Some(mark) = rule.action.meta_mark() {
        parts.push(format!("meta mark set {mark:#x}"));
    }
    // Verdict — ONLY emitted for terminal actions. nftables
    // treats `accept` as terminal in a chain (subsequent rules
    // are skipped), but the in-memory engine treats `Log` as
    // non-terminal and continues walking. Omit the verdict for
    // `Log` so the kernel evaluation falls through to later
    // rules and the two semantics stay aligned.
    if rule.action.is_terminal() {
        parts.push(rule.action.as_nft_verdict().into());
    }
    parts.push(format!("comment \"{}\"", escape_nft_comment(&rule.id)));
    Ok(parts.join(" "))
}

/// Address-family slots this rule needs to be rendered for.
/// A rule that mentions only IPv4 zones / CIDRs emits one IPv4
/// nft line; a rule with mixed predicates emits one nft line
/// per family; an entirely family-agnostic rule (no zones, no
/// cidrs) emits a single line with no `ip` / `ip6` qualifier,
/// rather than two identical lines that the kernel would walk
/// twice for every packet.
fn rule_address_families(rule: &FirewallRule, zones: &ZoneTable) -> Vec<Option<AddressFamily>> {
    let mut families: BTreeSet<AddressFamily> = BTreeSet::new();
    for n in rule
        .matches
        .src_cidrs
        .iter()
        .chain(rule.matches.dst_cidrs.iter())
    {
        families.insert(AddressFamily::of(n));
    }
    for zone_name in rule.from_zones.iter().chain(rule.to_zones.iter()) {
        if let Some(z) = zones.zones.get(zone_name) {
            if z.has_family(AddressFamily::V4) {
                families.insert(AddressFamily::V4);
            }
            if z.has_family(AddressFamily::V6) {
                families.insert(AddressFamily::V6);
            }
        }
    }
    if families.is_empty() {
        // No predicate restricts family — emit a single
        // family-agnostic line. Without zone / CIDR clauses,
        // the `ip` / `ip6` qualifier would have nothing to bind
        // to, so duplicating the line per family would just
        // double the kernel's per-packet work.
        vec![None]
    } else {
        families.into_iter().map(Some).collect()
    }
}

fn zone_has_family(zones: &ZoneTable, name: &str, family: AddressFamily) -> bool {
    zones.zones.get(name).is_some_and(|z| z.has_family(family))
}

/// Map a zone name into an nftables-set-safe identifier.
///
/// nftables set names tolerate a narrower character class than
/// the operator's zone-name convention does (dotted lowercase,
/// like `branch.lan`), so non-alphanumeric / non-underscore
/// characters all collapse to `_`. This conversion can collide
/// (e.g. `branch.lan` and `branch_lan` both → `branch_lan`);
/// the kernel side would silently merge both zones' networks
/// into a single set while the in-memory engine kept them
/// separate by exact name match. `ZoneTable::validate` calls
/// `reject_sanitized_name_collisions` to fail the bundle
/// compile before that divergence can ship.
///
/// Kept `pub(crate)` so the zone-table validator can hash on the
/// exact same transform the compiler will eventually apply.
pub(crate) fn sanitize_set_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{NatRule, NatType};
    use crate::rule::Protocol;
    use crate::zone::{Zone, ZonePolicy};
    use pretty_assertions::assert_eq;
    use sng_policy_eval::matcher::SubjectMatch;
    use sng_policy_eval::rule::Subject as RawSubject;

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    /// Wire-compatible bundle envelope. Lives at module scope
    /// so test helpers can re-use it without tripping clippy's
    /// `items_after_statements` lint.
    #[derive(serde::Serialize)]
    struct Wire<'a> {
        #[serde(rename = "v")]
        v: u8,
        #[serde(rename = "t")]
        t: &'a str,
        #[serde(rename = "g")]
        g: &'a str,
        #[serde(rename = "gv")]
        gv: i64,
        #[serde(rename = "c")]
        c: &'a str,
        #[serde(rename = "d")]
        d: &'a str,
        #[serde(rename = "r", with = "serde_bytes")]
        r: &'a [u8],
        #[serde(rename = "ts")]
        ts: &'a str,
    }

    fn make_bundle_with_rules(rules: &[Rule]) -> LoadedBundle {
        make_bundle(rules, "deny")
    }

    fn make_bundle(rules: &[Rule], default_action: &str) -> LoadedBundle {
        // Construct a wire-compatible bundle envelope and run it
        // through the production decoder. This keeps the compile
        // tests honest: they exercise the same load path
        // production callers use, and we don't have to depend on
        // any private field on `LoadedBundle`.
        let rules_json = serde_json::to_vec(rules).expect("rules serialise");
        let wire = Wire {
            v: 1,
            t: "edge",
            g: "test-graph",
            gv: 1,
            c: "test",
            d: default_action,
            r: &rules_json,
            ts: "2026-01-01T00:00:00Z",
        };
        let body = rmp_serde::to_vec_named(&wire).expect("encode bundle");
        LoadedBundle::from_body(&body, sng_core::policy::BundleTarget::Edge).expect("decode bundle")
    }

    fn ngfw_rule(id: &str, verb: Verb, subjects: Vec<RawSubject>) -> Rule {
        Rule {
            id: id.into(),
            domain: EnforcementDomain::Ngfw,
            verb,
            suggested_verb: None,
            subject_refs: Vec::new(),
            predicate_refs: Vec::new(),
            subjects,
            predicates: Vec::new(),
            targets: Vec::new(),
            description: String::new(),
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn compile_emits_filter_table_header() {
        let zones = ZoneTable::new();
        let nat = NatTable::new();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new().compile(&bundle, zones, nat).unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("add table inet sng_filter"));
        assert!(s.contains("add chain inet sng_filter input"));
        assert!(s.contains("add chain inet sng_filter forward"));
    }

    /// Regression: the rendered script MUST emit `flush table
    /// inet sng_filter` before re-populating the table on every
    /// install. Without it, `add rule ...` / `add element ...`
    /// from successive bundles accumulate in the kernel chain
    /// and the engine / kernel rulesets silently diverge across
    /// rotations.
    #[test]
    fn compile_emits_flush_table_for_filter() {
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(
            s.contains("flush table inet sng_filter"),
            "expected `flush table inet sng_filter` in rendered \
             script; without it, kernel rules accumulate across \
             bundle rotations:\n{s}"
        );
    }

    /// Regression: `flush table` MUST appear after `add table`
    /// (so the table exists when flushed) and BEFORE any
    /// `add chain` / `add set` / `add element` / `add rule`
    /// statements (so the flushed state is the starting point
    /// for the new bundle, not a no-op after population).
    #[test]
    fn compile_flush_table_ordering_precedes_population() {
        let bundle = make_bundle_with_rules(&[ngfw_rule("r", Verb::Deny, vec![])]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        let add_table_idx = s
            .find("add table inet sng_filter\n")
            .expect("add table line present");
        let flush_idx = s
            .find("flush table inet sng_filter\n")
            .expect("flush table line present");
        let chain_input_idx = s
            .find("add chain inet sng_filter input")
            .expect("input chain present");
        let chain_forward_idx = s
            .find("add chain inet sng_filter forward")
            .expect("forward chain present");
        let first_rule_idx = s
            .find("add rule inet sng_filter forward")
            .expect("rule line present");
        assert!(
            add_table_idx < flush_idx,
            "add table must come before flush (script:\n{s})"
        );
        assert!(
            flush_idx < chain_input_idx,
            "flush must come before chain creation (script:\n{s})"
        );
        assert!(
            flush_idx < chain_forward_idx,
            "flush must come before chain creation (script:\n{s})"
        );
        assert!(
            flush_idx < first_rule_idx,
            "flush must come before rule emission (script:\n{s})"
        );
    }

    /// Regression: rendering the same bundle twice must
    /// produce byte-identical scripts. Combined with the
    /// `flush table` guarantee above, this proves the script
    /// is idempotent on the kernel — applying it N times
    /// yields the same chain state as applying it once.
    #[test]
    fn compile_render_is_idempotent_under_repeated_apply() {
        let bundle = make_bundle_with_rules(&[
            ngfw_rule("a", Verb::Allow, vec![]),
            ngfw_rule("b", Verb::Deny, vec![]),
            ngfw_rule("c", Verb::Log, vec![]),
        ]);
        let a = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let b = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert_eq!(
            a.script.as_str().unwrap(),
            b.script.as_str().unwrap(),
            "compiler must render the same bundle byte-identically"
        );
    }

    /// Regression: rotating from a bundle that defines a rule
    /// to a bundle that does NOT define it must produce a
    /// script whose `add rule` count for that id is zero. With
    /// `flush table`, the kernel transactionally drops the
    /// stale rule even though the rendered script never says
    /// `delete rule`.
    #[test]
    fn compile_rotation_drops_removed_rule_via_flush() {
        let v1 = make_bundle_with_rules(&[
            ngfw_rule("keep", Verb::Allow, vec![]),
            ngfw_rule("removed", Verb::Deny, vec![]),
        ]);
        let v2 = make_bundle_with_rules(&[ngfw_rule("keep", Verb::Allow, vec![])]);
        let s1 = RuleCompiler::new()
            .compile(&v1, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s2 = RuleCompiler::new()
            .compile(&v2, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s1_text = s1.script.as_str().unwrap();
        let s2_text = s2.script.as_str().unwrap();
        assert!(s1_text.contains("\"removed\""));
        assert!(!s2_text.contains("\"removed\""));
        // Both scripts must flush; the second script is the
        // authoritative replacement of the first.
        assert!(s1_text.contains("flush table inet sng_filter"));
        assert!(s2_text.contains("flush table inet sng_filter"));
    }

    /// Regression: when a bundle that *had* NAT rules rotates
    /// to a bundle that has *no* NAT rules, the rendered script
    /// must still tear down the `inet sng_nat` table in the
    /// kernel. The previous behaviour was to emit nothing for
    /// the empty-NAT case, which left the prerouting /
    /// postrouting chains live in the kernel and silently kept
    /// DNAT-ing / SNAT-ing traffic according to the old bundle
    /// while the in-memory engine reported "no NAT".
    #[test]
    fn compile_rotation_to_no_nat_tears_down_kernel_table() {
        use crate::nat::{NatRule, NatType};
        use crate::rule::Protocol;

        // v1: bundle with one masquerade rule.
        let mut nat_v1 = NatTable::new();
        nat_v1
            .add(NatRule {
                id: "out".into(),
                src_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
                dst_cidrs: vec![],
                dst_ports: vec![],
                protocol: Protocol::Any,
                iif: String::new(),
                oif: "wan0".into(),
                nat: NatType::Masquerade { port: None },
                description: String::new(),
            })
            .unwrap();
        let v1 = make_bundle_with_rules(&[]);
        let s1 = RuleCompiler::new()
            .compile(&v1, ZoneTable::new(), nat_v1)
            .unwrap();
        let s1_text = s1.script.as_str().unwrap();

        // v2: same control-plane bundle, but NAT table is now
        // empty (operator removed every NAT rule).
        let v2 = make_bundle_with_rules(&[]);
        let s2 = RuleCompiler::new()
            .compile(&v2, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s2_text = s2.script.as_str().unwrap();

        // v1 must install the masquerade rule into sng_nat.
        assert!(
            s1_text.contains("add table inet sng_nat"),
            "v1 must install the NAT table:\n{s1_text}"
        );
        assert!(
            s1_text.contains("masquerade"),
            "v1 must install the masquerade rule:\n{s1_text}"
        );

        // v2 must tear down the NAT table — both `add` (no-op /
        // creates) and `delete` lines must appear, in that
        // order, and no chain / rule declarations must follow.
        assert!(
            s2_text.contains("add table inet sng_nat"),
            "v2 must idempotently `add` the NAT table so the \
             subsequent `delete` works even on a first-ever \
             install:\n{s2_text}"
        );
        assert!(
            s2_text.contains("delete table inet sng_nat"),
            "v2 must `delete` the NAT table so the kernel \
             actually drops the previous bundle's chains and \
             rules:\n{s2_text}"
        );
        let add_idx = s2_text.find("add table inet sng_nat").unwrap();
        let del_idx = s2_text.find("delete table inet sng_nat").unwrap();
        assert!(
            add_idx < del_idx,
            "the cleanup directive ordering must be add-then-delete"
        );
        // The previous masquerade rule must not survive.
        assert!(
            !s2_text.contains("masquerade"),
            "v2 must not carry forward the v1 masquerade rule:\n{s2_text}"
        );
    }

    /// Regression: `render_single_rule` used to `assert!` when
    /// the family-agnostic invariant was violated. In a release
    /// build that panic would unwind the manager's compile task
    /// and trip the agent's panic-restart loop. The corrected
    /// behaviour returns `FirewallError::BundleInvalid` so the
    /// engine fails the install cleanly and keeps the previous
    /// bundle live.
    ///
    /// This test feeds the invariant violation directly into
    /// `render_single_rule` (the upstream `rule_address_families`
    /// would never produce a `None` family for a rule with
    /// zones / CIDRs in practice, but a bug there would manifest
    /// here in production).
    #[test]
    fn render_single_rule_returns_error_on_invariant_violation() {
        // Synthetic family-agnostic slot WITH a CIDR predicate —
        // exactly the divergence the function exists to prevent.
        let rule = FirewallRule {
            id: "broken".into(),
            matches: RuleMatch {
                src_cidrs: vec![cidr("10.0.0.0/8")],
                ..RuleMatch::default()
            },
            action: RuleAction::Deny,
            from_zones: vec![],
            to_zones: vec![],
            description: String::new(),
        };
        let v4_net = cidr("10.0.0.0/8");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            render_single_rule(&rule, None, None, None, &[&v4_net], &[])
        }));
        match result {
            Ok(Err(FirewallError::BundleInvalid(msg))) => {
                assert!(
                    msg.contains("broken"),
                    "error must name the rule that violated the invariant: {msg}"
                );
                assert!(
                    msg.contains("family-agnostic slot"),
                    "error must explain the invariant that was violated: {msg}"
                );
            }
            Ok(Ok(line)) => {
                panic!("invariant violation must NOT silently emit a rule line — got: {line:?}")
            }
            Ok(Err(other)) => {
                panic!("invariant violation must surface as BundleInvalid; got: {other:?}")
            }
            Err(_) => {
                // `debug_assert!` in debug builds catches it as a
                // panic — that's still acceptable behaviour as long
                // as it isn't reachable in production. Convert the
                // panic into the success case so the test passes
                // under both `cargo test` (debug) and `cargo test --release`.
            }
        }
    }

    #[test]
    fn compile_skips_non_ngfw_rules() {
        let bundle = make_bundle_with_rules(&[Rule {
            id: "swg-rule".into(),
            domain: EnforcementDomain::Swg,
            verb: Verb::Allow,
            suggested_verb: None,
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: std::collections::BTreeMap::new(),
        }]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert!(out.rules.is_empty());
    }

    #[test]
    fn compile_skips_decrypt_verb_rules() {
        let bundle = make_bundle_with_rules(&[ngfw_rule("d", Verb::Decrypt, vec![])]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert!(out.rules.is_empty());
    }

    #[test]
    fn compile_suggest_only_with_inner_verb_emits_log_rule() {
        let mut r = ngfw_rule("shadow", Verb::SuggestOnly, vec![]);
        r.suggested_verb = Some(Verb::Deny);
        let bundle = make_bundle_with_rules(&[r]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].action, RuleAction::Log);
    }

    // NOTE: There is no negative test for
    // "SuggestOnly without an inner verb is dropped" because
    // `LoadedBundle::from_body` rejects such bundles up front
    // (`PolicyEvalError::SuggestOnlyMissingSuggestion`). The
    // defensive branch in `compile_one` guards a hypothetical
    // future relaxation only — it is unreachable today.

    #[test]
    fn compile_folds_network_subject_into_src_cidrs() {
        let r = ngfw_rule(
            "net",
            Verb::Allow,
            vec![RawSubject {
                name: String::new(),
                kind: SubjectKind::Network,
                matcher: SubjectMatch::Cidr {
                    cidr: cidr("10.0.0.0/24"),
                },
            }],
        );
        let bundle = make_bundle_with_rules(&[r]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].matches.src_cidrs, vec![cidr("10.0.0.0/24")]);
    }

    #[test]
    fn compile_unknown_subject_ref_fails() {
        let mut r = ngfw_rule("bad", Verb::Allow, vec![]);
        r.subject_refs.push("ghost".into());
        let bundle = make_bundle_with_rules(&[r]);
        let e = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap_err();
        assert!(matches!(e, FirewallError::BundleInvalid(_)));
    }

    #[test]
    fn compile_default_action_falls_back_to_deny() {
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert_eq!(out.default_action, RuleAction::Deny);
    }

    #[test]
    fn compile_emits_per_zone_set_per_ipv4_zone() {
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "branch.lan".into(),
                networks: vec![cidr("10.0.0.0/24")],
                description: String::new(),
            })
            .unwrap();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, zones, NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("add set inet sng_filter zone_branch_lan"));
        assert!(s.contains("add element inet sng_filter zone_branch_lan { 10.0.0.0/24 }"));
    }

    #[test]
    fn compile_emits_ipv6_sets_when_zone_has_ipv6_cidrs() {
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "v6".into(),
                networks: vec![cidr("2001:db8::/32")],
                description: String::new(),
            })
            .unwrap();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, zones, NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("add set inet sng_filter zone6_v6 { type ipv6_addr;"));
        assert!(s.contains("add element inet sng_filter zone6_v6 { 2001:db8::/32 }"));
    }

    #[test]
    fn compile_skips_ipv4_set_for_ipv6_only_zone() {
        // An IPv6-only zone must NOT cause an empty `zone_<name>`
        // ipv4_addr set to be created \u2014 nothing would ever
        // reference it (the v4 rule rendering path skips zones
        // without v4 networks) and it just pollutes the kernel's
        // set table. The mirror v6 set is the one that actually
        // gets used.
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "v6only".into(),
                networks: vec![cidr("2001:db8::/32")],
                description: String::new(),
            })
            .unwrap();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, zones, NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(
            !s.contains("add set inet sng_filter zone_v6only"),
            "v4 set must not be created for v6-only zone: {s}"
        );
        // Spot-check: v6 mirror set is still created.
        assert!(s.contains("add set inet sng_filter zone6_v6only { type ipv6_addr;"));
    }

    #[test]
    fn compile_skips_ipv6_set_for_ipv4_only_zone() {
        // Mirror of the above: a v4-only zone must not cause an
        // empty ipv6_addr set to be created.
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "v4only".into(),
                networks: vec![cidr("10.0.0.0/8")],
                description: String::new(),
            })
            .unwrap();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, zones, NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(
            !s.contains("add set inet sng_filter zone6_v4only"),
            "v6 set must not be created for v4-only zone: {s}"
        );
        assert!(s.contains("add set inet sng_filter zone_v4only { type ipv4_addr;"));
    }

    #[test]
    fn compile_includes_nat_table_when_supplied() {
        let mut nat = NatTable::new();
        nat.add(NatRule {
            id: "snat".into(),
            src_cidrs: vec![cidr("10.0.0.0/8")],
            dst_cidrs: vec![],
            dst_ports: vec![],
            protocol: Protocol::Any,
            iif: String::new(),
            oif: "wan0".into(),
            nat: NatType::Masquerade { port: None },
            description: String::new(),
        })
        .unwrap();
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), nat)
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("add table inet sng_nat"));
        assert!(s.contains("masquerade"));
    }

    #[test]
    fn compile_emits_atomic_nat_teardown_when_no_nat_rules() {
        // Previously this test asserted the script contained
        // *no* NAT-related lines at all when the bundle had no
        // NAT rules. That contract was wrong: it left any
        // previously-installed `inet sng_nat` table live in the
        // kernel, so rotating from a NAT-present bundle to a
        // NAT-empty bundle silently kept DNAT-ing / SNAT-ing
        // traffic according to the old bundle while the
        // in-memory engine reported "no NAT".
        //
        // The new contract: every install must teardown the NAT
        // table atomically via the `add` + `delete` idiom, so
        // the kernel state always matches the in-memory engine
        // regardless of what the previous bundle installed.
        // Chains must NOT appear (this is a teardown, not a
        // re-population), but the two-line cleanup directive
        // must.
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(
            s.contains("add table inet sng_nat"),
            "must emit `add table` for idempotency:\n{s}"
        );
        assert!(
            s.contains("delete table inet sng_nat"),
            "must emit `delete table` to tear down stale state:\n{s}"
        );
        // The kernel does NOT need to traverse empty NAT chains —
        // the `delete table` above removes them all.
        assert!(!s.contains("hook prerouting priority dstnat"), "{s}");
        assert!(!s.contains("hook postrouting priority srcnat"), "{s}");
    }

    #[test]
    fn sanitize_comment_strips_newlines_and_control_chars() {
        // The compiler used to carry a private `sanitize_comment`
        // helper; it now delegates to `nftables::escape_nft_comment`
        // (same function `nat.rs` uses) so the two render paths
        // can't drift out of sync. The end-to-end semantics this
        // test pins down are unchanged.
        assert_eq!(escape_nft_comment("plain"), "plain");
        assert_eq!(escape_nft_comment(r#"with"quotes"#), "with'quotes");
        assert_eq!(escape_nft_comment(r"with\backslash"), "with/backslash");
        // Newlines + carriage returns + tabs + NUL collapse to a
        // single space each — a crafted rule id can't split the
        // emitted `add rule ...` line across multiple lines.
        assert_eq!(escape_nft_comment("a\nb"), "a b");
        assert_eq!(escape_nft_comment("a\r\nb"), "a  b");
        assert_eq!(escape_nft_comment("a\tb"), "a b");
        assert_eq!(escape_nft_comment("a\0b"), "a b");
        // Multi-byte UTF-8 must pass through unchanged.
        assert_eq!(escape_nft_comment("emoji-🦀"), "emoji-🦀");
    }

    #[test]
    fn render_rule_sanitises_newline_in_rule_id() {
        // End-to-end: feed a rule whose `id` contains a newline
        // through `render_rule` and assert the emitted line is
        // single-line. Without sanitisation this would split
        // into two physical lines and `nft -f` would reject it.
        let zones = ZoneTable::new();
        let r = rule_with_zones(
            "evil\nrule",
            &[],
            &[],
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        // `render_rule` always ends each emitted rule with a
        // single trailing newline; the body itself must contain
        // none.
        let trimmed = out.trim_end_matches('\n');
        assert!(
            !trimmed.contains('\n'),
            "rule body contains embedded newline: {out:?}"
        );
        assert!(out.contains(r#"comment "evil rule""#), "{out}");
    }

    #[test]
    fn compile_script_is_deterministic_for_same_inputs() {
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "a".into(),
                networks: vec![cidr("10.0.0.0/24")],
                description: String::new(),
            })
            .unwrap();
        let bundle = make_bundle_with_rules(&[ngfw_rule(
            "r",
            Verb::Allow,
            vec![RawSubject {
                name: String::new(),
                kind: SubjectKind::Network,
                matcher: SubjectMatch::Cidr {
                    cidr: cidr("10.0.0.0/24"),
                },
            }],
        )]);
        let a = RuleCompiler::new()
            .compile(&bundle, zones.clone(), NatTable::new())
            .unwrap();
        let b = RuleCompiler::new()
            .compile(&bundle, zones, NatTable::new())
            .unwrap();
        assert_eq!(a.script.bytes, b.script.bytes);
        assert_eq!(a.script.digest, b.script.digest);
    }

    #[test]
    fn compile_default_action_allow_propagates_to_chain_policy() {
        let bundle = make_bundle(&[], "allow");
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("policy accept;"));
    }

    #[test]
    fn compile_records_source_graph_metadata() {
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        assert_eq!(out.source_graph_id, "test-graph");
        assert_eq!(out.source_graph_version, 1);
    }

    #[test]
    fn compile_includes_chain_policy_in_rendered_script() {
        let bundle = make_bundle_with_rules(&[]);
        let out = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        let s = out.script.as_str().unwrap();
        assert!(s.contains("policy drop;"));
    }

    // Suppress unused-import warning on the in-test helper.
    #[allow(dead_code)]
    fn assert_zone_policy_present(_zp: ZonePolicy) {}

    // -- render_rule behaviour tests -----------------------------
    //
    // These exercise the family-aware, multi-zone, both-zone-and-cidr
    // emitter directly. The bundle-driven `compile_*` tests above
    // cover the integration path; these focus on the rule-rendering
    // surface so a regression in zone / family handling fails a
    // small, targeted test instead of a snapshot-style integration
    // check.

    fn rule_with_zones(
        id: &str,
        from: &[&str],
        to: &[&str],
        action: RuleAction,
        matches: RuleMatch,
    ) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            matches,
            action,
            from_zones: from.iter().map(|s| (*s).to_string()).collect(),
            to_zones: to.iter().map(|s| (*s).to_string()).collect(),
            description: String::new(),
        }
    }

    fn make_zones(entries: &[(&str, &[&str])]) -> ZoneTable {
        let mut zt = ZoneTable::new();
        for (name, cidrs) in entries {
            zt.add_zone(Zone {
                name: (*name).into(),
                networks: cidrs.iter().map(|c| cidr(c)).collect(),
                description: String::new(),
            })
            .unwrap();
        }
        zt
    }

    #[test]
    fn render_rule_log_action_omits_terminal_verdict() {
        // Log is non-terminal in the in-memory engine — the
        // rendered nftables rule MUST NOT emit `accept`
        // otherwise the kernel would short-circuit subsequent
        // rules and diverge from the engine's semantics.
        let zones = make_zones(&[("z", &["10.0.0.0/24"])]);
        let r = rule_with_zones(
            "log-rule",
            &["z"],
            &[],
            RuleAction::Log,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        assert!(out.contains("meta mark set 0x1002"), "{out}");
        assert!(
            !out.contains(" accept "),
            "Log rule must not emit a terminal verdict: {out}"
        );
        // Sanity: a terminal Allow rule on the same zone *does*
        // emit `accept` — confirms the test isn't a false
        // negative.
        let r = rule_with_zones("a", &["z"], &[], RuleAction::Allow, RuleMatch::default());
        assert!(render_rule(&r, &zones).unwrap().contains(" accept "));
    }

    #[test]
    fn render_rule_terminal_actions_emit_their_verdict() {
        let zones = make_zones(&[("z", &["10.0.0.0/24"])]);
        for (action, verdict) in [
            (RuleAction::Allow, " accept "),
            (RuleAction::Deny, " drop "),
            (RuleAction::Inspect, " accept "),
            (RuleAction::Steer, " accept "),
        ] {
            let r = rule_with_zones("r", &["z"], &[], action, RuleMatch::default());
            let s = render_rule(&r, &zones).unwrap();
            assert!(s.contains(verdict), "{action:?} -> {s}");
        }
    }

    #[test]
    fn render_rule_multi_zone_cross_product_emits_one_line_per_pair() {
        // A rule with two from-zones and two to-zones must
        // expand into four nftables lines so the kernel sees
        // every zone combination, not just the first.
        let zones = make_zones(&[
            ("a", &["10.0.0.0/24"]),
            ("b", &["10.1.0.0/24"]),
            ("x", &["10.2.0.0/24"]),
            ("y", &["10.3.0.0/24"]),
        ]);
        let r = rule_with_zones(
            "multi",
            &["a", "b"],
            &["x", "y"],
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "{out}");
        assert!(out.contains("ip saddr @zone_a ip daddr @zone_x"));
        assert!(out.contains("ip saddr @zone_a ip daddr @zone_y"));
        assert!(out.contains("ip saddr @zone_b ip daddr @zone_x"));
        assert!(out.contains("ip saddr @zone_b ip daddr @zone_y"));
    }

    #[test]
    fn render_rule_ipv6_zone_emits_ip6_predicate() {
        // IPv6-only zone must emit `ip6 saddr @zone6_<name>`,
        // not the ipv4 `ip saddr @zone_<name>` form that would
        // never match an ipv6 packet at the kernel.
        let zones = make_zones(&[("v6only", &["2001:db8::/32"])]);
        let r = rule_with_zones(
            "v6",
            &["v6only"],
            &[],
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        assert!(out.contains("ip6 saddr @zone6_v6only"), "{out}");
        assert!(!out.contains("ip saddr @zone_v6only"));
    }

    #[test]
    fn render_rule_dual_family_zone_emits_both_v4_and_v6() {
        // A zone that holds both v4 and v6 networks should
        // produce one rule per family.
        let zones = make_zones(&[("mixed", &["10.0.0.0/24", "2001:db8::/32"])]);
        let r = rule_with_zones(
            "dual",
            &["mixed"],
            &[],
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(out.contains("ip saddr @zone_mixed"));
        assert!(out.contains("ip6 saddr @zone6_mixed"));
    }

    #[test]
    fn render_rule_zone_plus_src_cidr_emits_both_anded() {
        // When the operator sets both `from_zones` and
        // `src_cidrs`, the rule must AND both predicates — the
        // in-memory engine does AND, and dropping the cidr in
        // the rendered nft form would make the kernel rule
        // strictly more permissive than the engine.
        let zones = make_zones(&[("z", &["10.0.0.0/8"])]);
        let mut m = RuleMatch::default();
        m.src_cidrs.push(cidr("10.0.1.0/24"));
        let r = rule_with_zones("both", &["z"], &[], RuleAction::Allow, m);
        let out = render_rule(&r, &zones).unwrap();
        assert!(out.contains("ip saddr @zone_z"), "{out}");
        assert!(out.contains("ip saddr { 10.0.1.0/24 }"), "{out}");
    }

    #[test]
    fn render_rule_v4_zone_with_v6_only_src_cidrs_skips_line() {
        // Cross-family divergence guard. Rule has a v4 zone AND a
        // v6 src_cidr. Previously the v4 iteration would render
        // `ip saddr @zone_v4only` WITHOUT the cidr (filtered out
        // by family) — strictly more permissive than the
        // in-memory engine, which AND-combines the v4 zone match
        // with the v6 CIDR (and finds the v6 CIDR doesn't contain
        // any v4 address, so denies). The fix is to skip the
        // emission when the operator declared CIDRs but none
        // survive the family filter, regardless of whether a
        // zone is present.
        let zones = make_zones(&[("v4only", &["10.0.0.0/8"])]);
        let mut m = RuleMatch::default();
        m.src_cidrs.push(cidr("2001:db8::/32"));
        let r = rule_with_zones("xfam", &["v4only"], &[], RuleAction::Allow, m);
        let out = render_rule(&r, &zones).unwrap();
        assert!(
            out.is_empty(),
            "expected no lines for cross-family rule, got: {out:?}"
        );
    }

    #[test]
    fn render_rule_v6_zone_with_v4_only_src_cidrs_skips_line() {
        // Mirror of the above for the v6-zone + v4-cidr case.
        let zones = make_zones(&[("v6only", &["2001:db8::/32"])]);
        let mut m = RuleMatch::default();
        m.src_cidrs.push(cidr("10.0.0.0/8"));
        let r = rule_with_zones("xfam6", &["v6only"], &[], RuleAction::Allow, m);
        let out = render_rule(&r, &zones).unwrap();
        assert!(
            out.is_empty(),
            "expected no lines for cross-family rule, got: {out:?}"
        );
    }

    #[test]
    fn render_rule_v4_zone_with_v6_only_dst_cidrs_skips_line() {
        // Same guard but for dst_cidrs. The to_zone branch was
        // previously also gated on `to_zone.is_none()`, which
        // missed the same divergence.
        let zones = make_zones(&[("v4only", &["10.0.0.0/8"])]);
        let mut m = RuleMatch::default();
        m.dst_cidrs.push(cidr("2001:db8::/32"));
        let r = rule_with_zones("xfam-dst", &[], &["v4only"], RuleAction::Allow, m);
        let out = render_rule(&r, &zones).unwrap();
        assert!(
            out.is_empty(),
            "expected no lines for cross-family rule, got: {out:?}"
        );
    }

    #[test]
    fn render_rule_mixed_family_zone_with_v6_only_src_cidrs_emits_v6_line_only() {
        // Cross-family divergence guard against a more
        // permissive form of the test above: a zone that holds
        // BOTH families (v4 + v6) combined with a v6-only
        // src_cidr. The v4 iteration must skip (cidr filtered
        // out → can't AND it in, so dropping the whole line is
        // the only divergence-free option). The v6 iteration
        // must emit normally.
        let zones = make_zones(&[("dual", &["10.0.0.0/8", "2001:db8::/32"])]);
        let mut m = RuleMatch::default();
        m.src_cidrs.push(cidr("2001:db8::/32"));
        let r = rule_with_zones("partial-xfam", &["dual"], &[], RuleAction::Allow, m);
        let out = render_rule(&r, &zones).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "{out}");
        assert!(out.contains("ip6 saddr @zone6_dual"), "{out}");
        assert!(out.contains("ip6 saddr { 2001:db8::/32 }"), "{out}");
        assert!(!out.contains("ip saddr @zone_dual"), "{out}");
    }

    #[test]
    fn render_rule_no_zone_no_cidr_emits_single_family_agnostic_rule() {
        // A family-agnostic rule (no zones, no CIDRs) must
        // render exactly once \u2014 without `ip` / `ip6`
        // qualifier. The `inet` table matches the resulting
        // line for both v4 and v6 traffic; emitting two
        // identical copies just doubles the kernel's per-packet
        // walk for no semantic gain.
        let zones = ZoneTable::new();
        let r = rule_with_zones("any", &[], &[], RuleAction::Deny, RuleMatch::default());
        let out = render_rule(&r, &zones).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "{out}");
        assert!(!lines[0].contains("ip saddr"), "{out}");
        assert!(!lines[0].contains("ip6 saddr"), "{out}");
        assert!(!lines[0].contains("ip daddr"), "{out}");
        assert!(!lines[0].contains("ip6 daddr"), "{out}");
    }

    #[test]
    fn render_rule_skips_zone_that_lacks_requested_family() {
        // Rule references a v4-only zone, but a mixed-family
        // sibling zone covers v6. The v6 rendering for the
        // v4-only zone must be skipped (no `zone6_v4only`
        // set exists), and the v4 rendering must still be
        // emitted.
        let zones = make_zones(&[
            ("v4only", &["10.0.0.0/24"]),
            ("mixed", &["10.1.0.0/24", "2001:db8::/32"]),
        ]);
        let r = rule_with_zones(
            "f",
            &["v4only"],
            &["mixed"],
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let out = render_rule(&r, &zones).unwrap();
        assert!(out.contains("ip saddr @zone_v4only ip daddr @zone_mixed"));
        // No v6 rule because v4only has no v6 networks.
        assert!(!out.contains("ip6 saddr @zone6_v4only"));
    }

    // ------------------------------------------------------------
    // fold_subject — fail-closed behaviour for unsupported and
    // logically-incoherent (kind, matcher) combinations.
    // ------------------------------------------------------------
    //
    // The bot's defence-in-depth concern was that the previous
    // catch-all `_ => {}` arm would silently leave
    // `RuleMatch.subject = SubjectMatch::Any`, which is the same
    // shape the engine treats as "no constraint on subject". For
    // a `Verb::Allow` rule, that would expand to allow-all.
    //
    // The new `fold_subject` rejects any combination it doesn't
    // explicitly recognise. These tests pin every accept / reject
    // edge so future schema changes can't silently regress to the
    // permissive behaviour.

    #[test]
    fn fold_subject_rejects_user_with_cidr_matcher() {
        let s = RawSubject {
            name: String::new(),
            kind: SubjectKind::User,
            matcher: SubjectMatch::Cidr {
                cidr: cidr("10.0.0.0/8"),
            },
        };
        let bundle = make_bundle_with_rules(&[ngfw_rule("incoherent", Verb::Allow, vec![s])]);
        let err = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("incoherent") && msg.contains("User") && msg.contains("cidr"),
            "expected incoherent-subject error mentioning rule id, kind, and matcher; got: {msg}"
        );
    }

    #[test]
    fn fold_subject_rejects_network_with_literal_matcher() {
        let s = RawSubject {
            name: String::new(),
            kind: SubjectKind::Network,
            matcher: SubjectMatch::Literal {
                value: "10.0.0.0/8".into(),
            },
        };
        let bundle = make_bundle_with_rules(&[ngfw_rule("bad-net", Verb::Allow, vec![s])]);
        let err = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap_err();
        assert!(
            format!("{err}").contains("Network"),
            "expected error to mention the Network kind: {err}"
        );
    }

    #[test]
    fn fold_subject_rejects_user_with_domain_suffix_matcher() {
        // The exact case the bot flagged: a User subject paired
        // with a DomainSuffix matcher. Previously this silently
        // produced `subject: Any` and the rule would match every
        // user. Now it must fail the compile.
        let s = RawSubject {
            name: String::new(),
            kind: SubjectKind::User,
            matcher: SubjectMatch::DomainSuffix {
                suffix: "example.com".into(),
            },
        };
        let bundle = make_bundle_with_rules(&[ngfw_rule("user-with-domain", Verb::Allow, vec![s])]);
        let err = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("user-with-domain"));
        assert!(msg.contains("User"));
        assert!(msg.contains("domain_suffix"));
    }

    #[test]
    fn fold_subject_rejects_unknown_matcher_for_any_kind() {
        // Forward-compat sentinel: SubjectMatch::Unknown means
        // the decoder saw a matcher shape this build doesn't
        // recognise. Compiling such a rule would silently widen
        // it; the compiler must refuse instead.
        for kind in [
            SubjectKind::User,
            SubjectKind::Network,
            SubjectKind::App,
            SubjectKind::Device,
            SubjectKind::Site,
        ] {
            let s = RawSubject {
                name: String::new(),
                kind,
                matcher: SubjectMatch::Unknown,
            };
            let bundle = make_bundle_with_rules(&[ngfw_rule("u", Verb::Allow, vec![s])]);
            let err = RuleCompiler::new()
                .compile(&bundle, ZoneTable::new(), NatTable::new())
                .unwrap_err();
            assert!(
                format!("{err}").contains("unrecognised"),
                "kind={kind:?} should produce an unrecognised-matcher error; got: {err}"
            );
        }
    }

    #[test]
    fn fold_subject_accepts_explicit_any_matcher_without_constraint() {
        // `SubjectMatch::Any` is the operator's explicit "no
        // constraint" signal. It must compile cleanly and leave
        // the rule's predicate slot at its default (no
        // `subject` filter on the engine's hot path).
        for kind in [
            SubjectKind::User,
            SubjectKind::Network,
            SubjectKind::App,
            SubjectKind::Device,
            SubjectKind::Site,
        ] {
            let s = RawSubject {
                name: String::new(),
                kind,
                matcher: SubjectMatch::Any,
            };
            let bundle = make_bundle_with_rules(&[ngfw_rule("any", Verb::Allow, vec![s])]);
            let compiled = RuleCompiler::new()
                .compile(&bundle, ZoneTable::new(), NatTable::new())
                .unwrap();
            assert_eq!(
                compiled.rules.len(),
                1,
                "Any matcher should compile a single rule for kind {kind:?}"
            );
            assert!(
                matches!(compiled.rules[0].matches.subject, SubjectMatch::Any),
                "Any matcher should leave subject slot at Any for kind {kind:?}"
            );
            assert!(
                compiled.rules[0].matches.src_cidrs.is_empty(),
                "Any matcher should not populate src_cidrs for kind {kind:?}"
            );
        }
    }

    #[test]
    fn fold_subject_accepts_device_literal_subject() {
        // Device subjects with a literal device-id fold into the
        // subject slot the same way User/App/Site do. This is
        // the new behaviour added alongside the fail-closed
        // tightening: previously a `(Device, Literal)` pair fell
        // through the catch-all and silently produced
        // `subject: Any`.
        let s = RawSubject {
            name: String::new(),
            kind: SubjectKind::Device,
            matcher: SubjectMatch::Literal {
                value: "device-42".into(),
            },
        };
        let bundle = make_bundle_with_rules(&[ngfw_rule("d", Verb::Allow, vec![s])]);
        let compiled = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap();
        match &compiled.rules[0].matches.subject {
            SubjectMatch::Literal { value } => assert_eq!(value, "device-42"),
            other => panic!("expected Literal subject for Device; got {other:?}"),
        }
    }

    #[test]
    fn fold_subject_rejects_incoherent_via_named_subject_reference() {
        // Same fail-closed posture must apply when an incoherent
        // matcher is reached through a named subject reference
        // rather than inline. Build a rule that names a subject
        // resolved through the bundle-wide lookup.
        let bad_subject = RawSubject {
            name: "bad-net".into(),
            kind: SubjectKind::Network,
            matcher: SubjectMatch::Literal {
                value: "not-a-cidr".into(),
            },
        };
        let referrer = Rule {
            id: "uses-bad-net".into(),
            domain: EnforcementDomain::Ngfw,
            verb: Verb::Allow,
            suggested_verb: None,
            subject_refs: vec!["bad-net".into()],
            predicate_refs: Vec::new(),
            subjects: Vec::new(),
            predicates: Vec::new(),
            targets: Vec::new(),
            description: String::new(),
            extra: std::collections::BTreeMap::new(),
        };
        let definer = ngfw_rule("defines-bad-net", Verb::Allow, vec![bad_subject]);
        let bundle = make_bundle_with_rules(&[definer, referrer]);
        let err = RuleCompiler::new()
            .compile(&bundle, ZoneTable::new(), NatTable::new())
            .unwrap_err();
        // The error fires on whichever rule is compiled first;
        // both rules reference the same incompatible subject so
        // either id is acceptable, but the message must surface
        // the Network/literal mismatch.
        let msg = format!("{err}");
        assert!(msg.contains("Network"), "{msg}");
        assert!(msg.contains("literal"), "{msg}");
    }
}
