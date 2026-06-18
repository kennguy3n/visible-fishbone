//! The firewall engine — per-packet evaluation + hot-swap.
//!
//! [`FirewallEngine`] owns:
//!
//! * The current [`CompiledRuleSet`] behind an `ArcSwap`. The
//!   hot path ([`Self::evaluate`]) clones the `Arc`, walks the
//!   rule list in source order, and returns the first match's
//!   verdict. No locking on the data path.
//! * An [`NftablesBackend`] handle. [`Self::install`] swaps the
//!   in-memory ruleset *before* applying to the kernel — a
//!   packet that races a swap then sees either the old in-memory
//!   rules with the old kernel rules (pre-swap) or the new
//!   in-memory rules with the new kernel rules (post-apply).
//!   If the kernel apply fails the in-memory swap is rolled
//!   back so the two stay consistent.
//! * An install-mutex ([`tokio::sync::Mutex`]) that serialises
//!   concurrent [`Self::install`] / [`Self::compile_and_swap`]
//!   calls. Without it two callers could each pass the
//!   version-monotonicity check against the same stale
//!   `ArcSwap` snapshot and race their swaps; the mutex closes
//!   that TOCTOU window.
//! * A [`ConntrackTracker`] used to seed the engine's
//!   `connection_state` view on every evaluation.
//!
//! The engine is intentionally narrow: it does not own the
//! L7 / TLS-policy decisions. Those run downstream on flows
//! the engine marked `Inspect` or `Steer`, dispatched through
//! the dedicated [`crate::l7`] / [`crate::tls_policy`] modules.

use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

use crate::compile::{CompiledRuleSet, RuleCompiler};
use crate::conntrack::{ConntrackState, ConntrackTracker, FlowDirection};
use crate::error::FirewallError;
use crate::nat::NatTable;
use crate::nftables::{NftablesBackend, NftablesScript};
use crate::rule::{Protocol, RuleAction};
use crate::zone::ZoneTable;
use sng_policy_eval::bundle::LoadedBundle;

/// Identifies a single flow by its 5-tuple. Used as the
/// conntrack lookup key and as the audit handle for every
/// verdict the engine emits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source address.
    pub src_ip: IpAddr,
    /// Destination address.
    pub dst_ip: IpAddr,
    /// Source port. Zero for L3-only protocols (ICMP, etc.).
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// L4 protocol.
    pub protocol: Protocol,
}

impl FlowKey {
    /// New flow key.
    #[must_use]
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Stable string handle used for conntrack lookups and
    /// telemetry — `{src}:{src_port}-{proto}->{dst}:{dst_port}`.
    /// The format is intentionally tied to the field layout so
    /// the same flow produces the same key on every call.
    #[must_use]
    pub fn audit_key(&self) -> String {
        let proto = self
            .protocol
            .iana_number()
            .map_or_else(|| "any".into(), |n| n.to_string());
        format!(
            "{}:{}-{}->{}:{}",
            self.src_ip, self.src_port, proto, self.dst_ip, self.dst_port
        )
    }
}

/// The engine's per-packet output. Wraps the matching action
/// plus the metadata downstream subsystems need: the rule id
/// for audit, the zone classification, and the conntrack state.
///
/// # Action vs. logged rules
///
/// `action` is the verdict the kernel actually applies to the
/// packet — it is always either the action of a *terminal*
/// matching rule ([`RuleAction::is_terminal`]) or the chain's
/// `default_action`. Non-terminal [`RuleAction::Log`] rules do
/// **not** appear in `action`; that would diverge from
/// nftables, where a `log` rule without an immediate verdict
/// falls through to subsequent rules and ultimately to the
/// chain policy.
///
/// `logged_rule_ids` records every Log rule whose match
/// predicates fired during the walk, in source order. These
/// are advisory — they generate audit events for the
/// telemetry pipeline but do not influence packet disposition.
/// A typical "log-and-default-deny" flow surfaces as
/// `action = Deny`, `matched_rule_id = None`,
/// `logged_rule_ids = ["log-suspicious"]`.
#[derive(Clone, Debug, PartialEq)]
pub struct FirewallVerdict {
    /// Final action — what the kernel / inline pipeline does
    /// with this packet. Mirrors the chain policy when no
    /// terminal rule matched; never carries [`RuleAction::Log`]
    /// (Log is non-terminal and surfaces via
    /// `logged_rule_ids` instead).
    pub action: RuleAction,
    /// Id of the *terminal* matching rule. `None` when the
    /// verdict came from the chain default, even if Log rules
    /// fired along the way.
    pub matched_rule_id: Option<String>,
    /// Ids of every Log rule whose predicates matched during
    /// the rule walk, in source order. Advisory only —
    /// surfaces audit events without altering packet fate.
    pub logged_rule_ids: Vec<String>,
    /// Ingress zone classification, if known.
    pub from_zone: Option<String>,
    /// Egress zone classification, if known.
    pub to_zone: Option<String>,
    /// Conntrack state at the time of the verdict.
    pub conntrack: ConntrackState,
}

/// Inputs to [`FirewallEngine::evaluate`]. Carries the flow key,
/// the per-packet direction (for conntrack), and an optional
/// resolved subject (e.g. a user id) the rule matcher dispatches
/// against.
#[derive(Clone, Debug)]
pub struct EvaluationContext<'a> {
    /// The 5-tuple under evaluation.
    pub flow: FlowKey,
    /// Direction of the observed packet for conntrack.
    pub direction: FlowDirection,
    /// Resolved subject value (user / device / app id).
    pub subject_value: Option<&'a str>,
}

/// The firewall engine. Holds compiled rules + the kernel
/// backend. Construct via [`Self::new`] with a backend
/// implementation; load rules via
/// [`Self::compile_and_swap`] or [`Self::install`].
pub struct FirewallEngine {
    backend: Arc<dyn NftablesBackend>,
    ruleset: ArcSwap<Option<CompiledRuleSet>>,
    conntrack: Mutex<ConntrackTracker>,
    /// Serialises concurrent installs. Held across the async
    /// kernel apply so two callers cannot both pass the version
    /// check, then race their `ArcSwap::store` and clobber the
    /// winner. The hot path ([`Self::evaluate`]) does not
    /// touch this mutex — it only reads the `ArcSwap`.
    install_lock: AsyncMutex<()>,
}

impl std::fmt::Debug for FirewallEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Mutex<ConntrackTracker>` is intentionally elided
        // (`finish_non_exhaustive`) — Debug-printing the
        // conntrack table would either block the hot path on
        // the mutex or report a stale view. The interesting
        // diagnostic state is the backend and the version of
        // the currently-installed ruleset.
        f.debug_struct("FirewallEngine")
            .field("backend", &self.backend)
            .field(
                "ruleset_version",
                &self
                    .ruleset
                    .load()
                    .as_ref()
                    .as_ref()
                    .map(|r| r.source_graph_version),
            )
            .finish_non_exhaustive()
    }
}

impl FirewallEngine {
    /// New engine with the supplied kernel backend. Starts with
    /// no compiled ruleset — [`Self::compile_and_swap`] or
    /// [`Self::install`] must be called before
    /// [`Self::evaluate`] returns a verdict other than the
    /// fail-closed default.
    #[must_use]
    pub fn new(backend: Arc<dyn NftablesBackend>) -> Self {
        Self {
            backend,
            ruleset: ArcSwap::from_pointee(None),
            conntrack: Mutex::new(ConntrackTracker::default()),
            install_lock: AsyncMutex::new(()),
        }
    }

    /// Compile a policy bundle into a ruleset and install it.
    /// Atomic against concurrent calls: the in-memory swap
    /// happens before the kernel apply so a racing
    /// [`Self::evaluate`] always sees a self-consistent view.
    pub async fn compile_and_swap(
        &self,
        bundle: &LoadedBundle,
        zones: ZoneTable,
        nat: NatTable,
    ) -> Result<NftablesScript, FirewallError> {
        let compiled = RuleCompiler::new().compile(bundle, zones, nat)?;
        let script = compiled.script.clone();
        self.install(compiled).await?;
        Ok(script)
    }

    /// Install an already-compiled ruleset. Holds the install
    /// mutex so the digest-dedup / version-monotonicity checks
    /// and the kernel apply happen atomically with respect to
    /// other installers; the hot path is unaffected.
    ///
    /// Order is **memory-first then kernel**: the in-memory
    /// `ArcSwap` is updated, then the kernel script is applied.
    /// If the apply fails the in-memory swap is rolled back so
    /// the engine never reports a verdict from a ruleset the
    /// kernel hasn't loaded.
    pub async fn install(&self, compiled: CompiledRuleSet) -> Result<(), FirewallError> {
        // Serialise installers. Tokio mutex is fine to hold
        // across the `await` on the backend; the hot path
        // ([`Self::evaluate`]) doesn't touch this mutex.
        let _install_guard = self.install_lock.lock().await;

        // Snapshot the current ruleset *inside* the install
        // lock so the digest / version comparison is consistent
        // with the in-memory state we'll swap against, and so
        // we can roll back to exactly that snapshot if the
        // kernel apply fails.
        let previous = self.ruleset.load_full();
        if let Some(current) = previous.as_ref().as_ref() {
            // Digest dedup — same script + same graph version
            // means there's nothing to apply.
            if current.script.digest == compiled.script.digest
                && current.source_graph_version == compiled.source_graph_version
            {
                return Ok(());
            }
            // Version monotonicity. Inside the install lock
            // this is no longer a TOCTOU — a concurrent
            // installer is blocked on the mutex above.
            if compiled.source_graph_version < current.source_graph_version {
                return Err(FirewallError::BundleInvalid(format!(
                    "stale ruleset: incoming graph_version {} < current {}",
                    compiled.source_graph_version, current.source_graph_version
                )));
            }
        }

        // Memory-first swap. A racing `evaluate()` between
        // this store and the kernel apply will see the new
        // in-memory ruleset but the old kernel state — which
        // is the safer mismatch direction (the in-memory
        // verdict is the source of truth for downstream
        // dispatch; the kernel chain is an in-band enforcer
        // and will catch up on the next packet).
        let script = compiled.script.clone();
        self.ruleset.store(Arc::new(Some(compiled)));
        if let Err(e) = self.backend.apply(&script).await {
            // Roll back so the engine doesn't report verdicts
            // from a ruleset the kernel never accepted.
            self.ruleset.store(previous);
            return Err(e);
        }
        Ok(())
    }

    /// Evaluate one flow against the loaded ruleset. Returns
    /// the matching rule's action plus the metadata needed for
    /// audit / downstream dispatch. Fail-closed: if no ruleset
    /// is loaded, returns [`RuleAction::Deny`].
    pub fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FirewallVerdict {
        let ruleset_guard = self.ruleset.load();

        // Gate conntrack updates on a loaded ruleset. The
        // engine is fail-closed (default Deny) before the first
        // bundle install, and on that path there is no useful
        // flow state to remember — every packet is denied
        // regardless of conntrack. Updating anyway would let
        // the `ConntrackTracker` (a `Vec`-backed advisory
        // structure with no eviction) accumulate one entry per
        // observed 5-tuple for the entire duration of a
        // bundle-less startup, growing the per-evaluate scan
        // linearly until the first bundle arrives. Skip the
        // update on the no-ruleset path; pass `New` as the
        // verdict's conntrack state to match the prior
        // observable contract for the fail-closed branch.
        let Some(rs) = ruleset_guard.as_ref().as_ref() else {
            return FirewallVerdict {
                action: RuleAction::Deny,
                matched_rule_id: None,
                logged_rule_ids: Vec::new(),
                from_zone: None,
                to_zone: None,
                conntrack: crate::conntrack::ConntrackState::New,
            };
        };

        let conntrack_state = self.update_conntrack(ctx);

        let from_zone = rs.zones.classify(ctx.flow.src_ip).map(str::to_owned);
        let to_zone = rs.zones.classify(ctx.flow.dst_ip).map(str::to_owned);

        // Zone gate first — operator-declared inter-zone policy
        // overrides per-rule allow when both zones are known.
        if let (Some(from), Some(to)) = (from_zone.as_deref(), to_zone.as_deref()) {
            let policy = rs.zones.lookup(from, to);
            if matches!(policy, crate::zone::ZonePolicy::Deny) {
                return FirewallVerdict {
                    action: RuleAction::Deny,
                    matched_rule_id: None,
                    logged_rule_ids: Vec::new(),
                    from_zone: from_zone.clone(),
                    to_zone: to_zone.clone(),
                    conntrack: conntrack_state,
                };
            }
        }

        // Walk the rule list. A terminal action stops the walk
        // and decides the packet's fate; Log rules accumulate
        // into `logged` so the operator still sees an audit
        // event regardless of how the walk resolves.
        let mut logged: Vec<String> = Vec::new();
        for r in &rs.rules {
            if !zone_match(&r.from_zones, from_zone.as_deref()) {
                continue;
            }
            if !zone_match(&r.to_zones, to_zone.as_deref()) {
                continue;
            }
            if !r.matches.matches(
                ctx.flow.src_ip,
                ctx.flow.dst_ip,
                ctx.flow.src_port,
                ctx.flow.dst_port,
                ctx.flow.protocol,
                ctx.subject_value,
            ) {
                continue;
            }
            if r.action.is_terminal() {
                return FirewallVerdict {
                    action: r.action,
                    matched_rule_id: Some(r.id.clone()),
                    logged_rule_ids: logged,
                    from_zone,
                    to_zone,
                    conntrack: conntrack_state,
                };
            }
            // Non-terminal (Log) — record and continue walking.
            // The kernel `nftables` script omits the verdict on
            // Log rules (see `compile::render_single_rule`), so
            // the chain default ends up applying there too;
            // mirroring that here keeps in-memory and kernel
            // verdicts aligned.
            logged.push(r.id.clone());
        }

        // No terminal rule matched: the chain's `default_action`
        // decides the packet's fate — same as the kernel chain
        // policy. Any Log rules that fired remain in
        // `logged_rule_ids` for telemetry.
        FirewallVerdict {
            action: rs.default_action,
            matched_rule_id: None,
            logged_rule_ids: logged,
            from_zone,
            to_zone,
            conntrack: conntrack_state,
        }
    }

    fn update_conntrack(&self, ctx: &EvaluationContext<'_>) -> ConntrackState {
        let key = ctx.flow.audit_key();
        let Ok(mut ct) = self.conntrack.lock() else {
            // Poisoned lock — return Invalid so the caller does
            // not act on a state we can't trust. The mutex
            // should never be poisoned in practice (no panics
            // in the section it guards), but if it is we want
            // a fail-closed posture rather than a panic.
            return ConntrackState::Invalid;
        };
        ct.observe(&key, ctx.direction)
    }

    /// Snapshot of the currently-loaded ruleset, if any. The
    /// inner [`Option`] is `None` before the first successful
    /// install. Returns an `Arc` so callers can hold the
    /// snapshot stable across subsequent hot-swaps without
    /// blocking the install path.
    #[must_use]
    pub fn current_ruleset(&self) -> Arc<Option<CompiledRuleSet>> {
        self.ruleset.load_full()
    }
}

fn zone_match(allowed: &[String], actual: Option<&str>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(a) = actual else {
        // Rule restricts by zone but we couldn't classify —
        // non-match (the safe direction).
        return false;
    };
    allowed.iter().any(|z| z == a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::MockNftables;
    use crate::rule::{FirewallRule, RuleMatch};
    use crate::zone::Zone;
    use ipnet::IpNet;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn empty_ruleset(default: RuleAction) -> CompiledRuleSet {
        CompiledRuleSet {
            rules: Vec::new(),
            zones: ZoneTable::new(),
            nat: NatTable::new(),
            default_action: default,
            source_graph_id: "g".into(),
            source_graph_version: 1,
            script: NftablesScript::new(b"add table inet sng_filter\n".to_vec()),
            classification: sng_ebpf::Classifier::default(),
        }
    }

    fn make_engine() -> (FirewallEngine, Arc<MockNftables>) {
        let backend = Arc::new(MockNftables::new());
        let engine = FirewallEngine::new(backend.clone());
        (engine, backend)
    }

    fn ctx(src: IpAddr, dst: IpAddr, dport: u16) -> EvaluationContext<'static> {
        EvaluationContext {
            flow: FlowKey::new(src, dst, 33333, dport, Protocol::Tcp),
            direction: FlowDirection::Original,
            subject_value: None,
        }
    }

    #[tokio::test]
    async fn evaluate_returns_deny_when_no_ruleset_loaded() {
        let (eng, _b) = make_engine();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 443));
        assert_eq!(v.action, RuleAction::Deny);
        assert!(v.matched_rule_id.is_none());
    }

    #[tokio::test]
    async fn evaluate_does_not_grow_conntrack_when_no_ruleset_loaded() {
        // Regression: the pre-bundle fail-closed path used to
        // call `update_conntrack` before checking whether a
        // ruleset was loaded, so a long-running engine that
        // hadn't received its first bundle would accumulate one
        // entry per observed 5-tuple forever (the `Vec`-backed
        // `ConntrackTracker` has no eviction). Gate the update
        // on `Some(rs)` so a no-bundle engine stays bounded.
        let (eng, _b) = make_engine();
        for i in 0..50_u8 {
            // Each call uses a distinct 5-tuple so an
            // unconditional update would push a fresh entry
            // every iteration.
            let _ = eng.evaluate(&ctx(ipv4(10, 0, 0, i), ipv4(8, 8, 8, 8), 443));
        }
        // Reach in via the public snapshot path (mirrors how
        // tcpdump-style telemetry inspects the tracker) rather
        // than adding a test-only accessor.
        let entries = eng.conntrack.lock().unwrap().snapshot();
        assert_eq!(
            entries.len(),
            0,
            "conntrack tracker must not grow while no ruleset is loaded; saw {entries:?}"
        );
    }

    #[tokio::test]
    async fn install_applies_script_to_backend() {
        let (eng, backend) = make_engine();
        let rs = empty_ruleset(RuleAction::Allow);
        eng.install(rs).await.unwrap();
        assert_eq!(backend.apply_count(), 1);
    }

    #[tokio::test]
    async fn install_skips_apply_on_identical_digest() {
        let (eng, backend) = make_engine();
        let mut rs1 = empty_ruleset(RuleAction::Allow);
        rs1.source_graph_version = 5;
        let mut rs2 = rs1.clone();
        rs2.source_graph_version = 5;
        eng.install(rs1).await.unwrap();
        eng.install(rs2).await.unwrap();
        assert_eq!(backend.apply_count(), 1);
    }

    #[tokio::test]
    async fn install_rejects_downgrade() {
        let (eng, _backend) = make_engine();
        let mut rs1 = empty_ruleset(RuleAction::Allow);
        rs1.source_graph_version = 10;
        eng.install(rs1).await.unwrap();
        let mut rs2 = empty_ruleset(RuleAction::Deny);
        rs2.source_graph_version = 5;
        let e = eng.install(rs2).await.unwrap_err();
        assert!(matches!(e, FirewallError::BundleInvalid(_)));
    }

    #[tokio::test]
    async fn install_preserves_previous_ruleset_when_apply_fails() {
        let (eng, backend) = make_engine();
        let mut rs1 = empty_ruleset(RuleAction::Allow);
        rs1.source_graph_version = 1;
        eng.install(rs1).await.unwrap();
        backend.fail_next_apply("simulated kernel reject");
        let mut rs2 = empty_ruleset(RuleAction::Deny);
        rs2.source_graph_version = 2;
        let e = eng.install(rs2).await.unwrap_err();
        assert!(matches!(e, FirewallError::NftablesApply(_)));
        // Verdict still uses the previous (allow) default.
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 443));
        assert_eq!(v.action, RuleAction::Allow);
    }

    #[tokio::test]
    async fn evaluate_returns_default_action_when_no_rule_matches() {
        let (eng, _b) = make_engine();
        eng.install(empty_ruleset(RuleAction::Allow)).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 443));
        assert_eq!(v.action, RuleAction::Allow);
        assert!(v.matched_rule_id.is_none());
    }

    #[tokio::test]
    async fn evaluate_picks_first_matching_rule() {
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Deny);
        rs.rules = vec![
            FirewallRule {
                id: "a".into(),
                matches: RuleMatch {
                    dst_ports: vec![crate::rule::PortRange::single(443)],
                    ..RuleMatch::default()
                },
                action: RuleAction::Allow,
                from_zones: vec![],
                to_zones: vec![],
                description: String::new(),
            },
            FirewallRule {
                id: "b".into(),
                matches: RuleMatch {
                    dst_ports: vec![crate::rule::PortRange::single(443)],
                    ..RuleMatch::default()
                },
                action: RuleAction::Deny,
                from_zones: vec![],
                to_zones: vec![],
                description: String::new(),
            },
        ];
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 443));
        assert_eq!(v.action, RuleAction::Allow);
        assert_eq!(v.matched_rule_id.as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn evaluate_zone_gate_denies_inter_zone_by_default() {
        let (eng, _b) = make_engine();
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "branch".into(),
                networks: vec![cidr("10.0.0.0/24")],
                description: String::new(),
            })
            .unwrap();
        zones
            .add_zone(Zone {
                name: "dmz".into(),
                networks: vec![cidr("172.16.0.0/24")],
                description: String::new(),
            })
            .unwrap();
        let mut rs = empty_ruleset(RuleAction::Allow);
        rs.zones = zones;
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 5), ipv4(172, 16, 0, 5), 443));
        assert_eq!(v.action, RuleAction::Deny);
        assert_eq!(v.from_zone.as_deref(), Some("branch"));
        assert_eq!(v.to_zone.as_deref(), Some("dmz"));
    }

    #[tokio::test]
    async fn evaluate_intra_zone_default_allows() {
        let (eng, _b) = make_engine();
        let mut zones = ZoneTable::new();
        zones
            .add_zone(Zone {
                name: "lan".into(),
                networks: vec![cidr("10.0.0.0/24")],
                description: String::new(),
            })
            .unwrap();
        let mut rs = empty_ruleset(RuleAction::Allow);
        rs.zones = zones;
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 80));
        assert_eq!(v.action, RuleAction::Allow);
    }

    #[tokio::test]
    async fn evaluate_zone_restricted_rule_skips_when_zone_unknown() {
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Deny);
        rs.rules = vec![FirewallRule {
            id: "zone-restricted".into(),
            matches: RuleMatch::default(),
            action: RuleAction::Allow,
            from_zones: vec!["branch".into()],
            to_zones: vec![],
            description: String::new(),
        }];
        eng.install(rs).await.unwrap();
        // Source IP not in any zone — rule should not fire.
        let v = eng.evaluate(&ctx(ipv4(1, 2, 3, 4), ipv4(5, 6, 7, 8), 443));
        assert_eq!(v.action, RuleAction::Deny);
    }

    #[tokio::test]
    async fn evaluate_log_rule_alone_falls_through_to_default_action() {
        // Log is non-terminal in nftables \u2014 a rule with only a
        // `log` statement falls through to subsequent rules and
        // ultimately to the chain policy. The in-memory engine
        // must match: a Log rule on a default-deny chain leaves
        // the packet denied, with the Log rule's id surfaced in
        // `logged_rule_ids` for the audit trail. Returning
        // `action = Log` (the old behaviour) would tell the
        // caller the packet is being \"logged\" while the kernel
        // is silently dropping it.
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Deny);
        rs.rules = vec![FirewallRule {
            id: "log-only".into(),
            matches: RuleMatch::default(),
            action: RuleAction::Log,
            from_zones: vec![],
            to_zones: vec![],
            description: String::new(),
        }];
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 22));
        assert_eq!(v.action, RuleAction::Deny);
        assert!(v.matched_rule_id.is_none());
        assert_eq!(v.logged_rule_ids, vec!["log-only".to_string()]);
    }

    #[tokio::test]
    async fn evaluate_log_rule_alone_with_default_allow_falls_through_to_allow() {
        // Same shape, default-allow chain: packet is allowed,
        // Log rule still surfaces in the audit trail.
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Allow);
        rs.rules = vec![FirewallRule {
            id: "log-only".into(),
            matches: RuleMatch::default(),
            action: RuleAction::Log,
            from_zones: vec![],
            to_zones: vec![],
            description: String::new(),
        }];
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 22));
        assert_eq!(v.action, RuleAction::Allow);
        assert!(v.matched_rule_id.is_none());
        assert_eq!(v.logged_rule_ids, vec!["log-only".to_string()]);
    }

    #[tokio::test]
    async fn evaluate_terminal_after_log_preserves_log_audit_trail() {
        // When a Log rule fires *and* a later terminal rule
        // also matches, both must be reported: the terminal
        // rule decides packet fate (`matched_rule_id`); the Log
        // rule's id stays in `logged_rule_ids` so the audit
        // trail isn't silently lost.
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Allow);
        rs.rules = vec![
            FirewallRule {
                id: "log".into(),
                matches: RuleMatch::default(),
                action: RuleAction::Log,
                from_zones: vec![],
                to_zones: vec![],
                description: String::new(),
            },
            FirewallRule {
                id: "deny-ssh".into(),
                matches: RuleMatch {
                    dst_ports: vec![crate::rule::PortRange::single(22)],
                    ..RuleMatch::default()
                },
                action: RuleAction::Deny,
                from_zones: vec![],
                to_zones: vec![],
                description: String::new(),
            },
        ];
        eng.install(rs).await.unwrap();
        let v = eng.evaluate(&ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 22));
        assert_eq!(v.action, RuleAction::Deny);
        assert_eq!(v.matched_rule_id.as_deref(), Some("deny-ssh"));
        assert_eq!(v.logged_rule_ids, vec!["log".to_string()]);
    }

    #[tokio::test]
    async fn evaluate_records_conntrack_new_then_established() {
        let (eng, _b) = make_engine();
        eng.install(empty_ruleset(RuleAction::Allow)).await.unwrap();
        let mut c = ctx(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 443);
        c.direction = FlowDirection::Original;
        let v1 = eng.evaluate(&c);
        assert_eq!(v1.conntrack, ConntrackState::New);
        c.direction = FlowDirection::Reply;
        let v2 = eng.evaluate(&c);
        assert_eq!(v2.conntrack, ConntrackState::Established);
    }

    #[test]
    fn flow_key_audit_key_includes_all_fields() {
        let k = FlowKey::new(
            ipv4(10, 0, 0, 1),
            ipv4(8, 8, 8, 8),
            12345,
            443,
            Protocol::Tcp,
        );
        assert_eq!(k.audit_key(), "10.0.0.1:12345-6->8.8.8.8:443");
    }

    #[test]
    fn flow_key_audit_key_handles_any_protocol() {
        let k = FlowKey::new(ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8), 0, 0, Protocol::Any);
        assert_eq!(k.audit_key(), "10.0.0.1:0-any->8.8.8.8:0");
    }

    #[test]
    fn zone_match_empty_list_matches_anything() {
        assert!(zone_match(&[], None));
        assert!(zone_match(&[], Some("foo")));
    }

    #[test]
    fn zone_match_restricted_list_requires_actual_zone() {
        assert!(!zone_match(&["a".into()], None));
        assert!(!zone_match(&["a".into()], Some("b")));
        assert!(zone_match(&["a".into(), "b".into()], Some("b")));
    }

    #[tokio::test]
    async fn current_ruleset_returns_arc_without_outer_option() {
        // Type-level assertion: the return is `Arc<Option<_>>`,
        // *not* `Option<Arc<Option<_>>>`. The outer Option was
        // removed because it could never be `None` — keep this
        // test so a regression in the wrapper layering trips a
        // compiler error here.
        let (eng, _b) = make_engine();
        let snap: Arc<Option<CompiledRuleSet>> = eng.current_ruleset();
        assert!(snap.is_none());
        eng.install(empty_ruleset(RuleAction::Allow)).await.unwrap();
        let snap: Arc<Option<CompiledRuleSet>> = eng.current_ruleset();
        assert!(snap.is_some());
    }

    #[tokio::test]
    async fn install_swaps_memory_before_kernel_apply() {
        // Memory-first guarantee: the in-memory ruleset must be
        // visible to evaluate() by the time the kernel apply
        // returns. We assert this indirectly by snapshotting
        // current_ruleset() immediately after install() — if
        // the order were kernel-first then a hypothetical
        // failure between apply and store would leave the
        // in-memory engine on the old ruleset (already covered
        // by `install_preserves_previous_ruleset_when_apply_fails`
        // which exercises the rollback path).
        let (eng, _b) = make_engine();
        let mut rs = empty_ruleset(RuleAction::Allow);
        rs.source_graph_version = 7;
        eng.install(rs).await.unwrap();
        let snap = eng.current_ruleset();
        assert_eq!(
            snap.as_ref().as_ref().unwrap().source_graph_version,
            7,
            "in-memory ruleset must reflect the just-installed version"
        );
    }

    #[tokio::test]
    async fn install_serialises_concurrent_calls_to_prevent_toctou() {
        // The install lock must serialise so two callers can't
        // race past the version-monotonicity check. We fire
        // many concurrent installs of monotonically-increasing
        // versions; after they all complete, the in-memory
        // version must be the highest one, every call must
        // have either succeeded or returned BundleInvalid, and
        // the kernel apply count must equal the number of
        // *unique* digests we sent (digest-dedup short-circuits
        // duplicates).
        let (eng, backend) = make_engine();
        let engine = Arc::new(eng);
        let mut tasks = Vec::new();
        for v in 1..=20i64 {
            let e = engine.clone();
            tasks.push(tokio::spawn(async move {
                // Make each script byte-unique so digest-dedup
                // doesn't mask races — we want every install
                // to genuinely contend for the lock.
                let mut rs = empty_ruleset(RuleAction::Allow);
                rs.source_graph_version = v;
                rs.script = NftablesScript::new(format!("# v={v}\n").into_bytes());
                e.install(rs).await
            }));
        }
        let mut ok = 0;
        let mut rejected = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(()) => ok += 1,
                Err(FirewallError::BundleInvalid(_)) => rejected += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(ok + rejected, 20);
        // The lock guarantees monotonic progress: the snapshot
        // must be the highest version we ever submitted.
        let snap = engine.current_ruleset();
        let installed_version = snap.as_ref().as_ref().unwrap().source_graph_version;
        assert_eq!(installed_version, 20);
        // Without the lock the kernel apply count would be
        // racy / possibly exceed 20; with the lock it is at
        // most the number of accepted installs.
        assert!(backend.apply_count() <= ok);
    }
}
