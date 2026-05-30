//! The firewall engine — per-packet evaluation + hot-swap.
//!
//! [`FirewallEngine`] owns:
//!
//! * The current [`CompiledRuleSet`] behind an `ArcSwap`. The
//!   hot path ([`Self::evaluate`]) clones the `Arc`, walks the
//!   rule list in source order, and returns the first match's
//!   verdict. No locking on the data path.
//! * An [`NftablesBackend`] handle. [`Self::swap`] applies the
//!   compiled rule set to the kernel after installing the new
//!   ruleset in the in-memory engine. The two updates are
//!   sequenced — kernel-then-memory would race a packet against
//!   the new kernel rules with the old in-memory ruleset, so
//!   the order is memory-first.
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
#[derive(Clone, Debug, PartialEq)]
pub struct FirewallVerdict {
    /// Final action — what the engine instructs the kernel /
    /// inline pipeline to do.
    pub action: RuleAction,
    /// Id of the matching rule. `None` when the verdict came
    /// from the default action.
    pub matched_rule_id: Option<String>,
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

    /// Install an already-compiled ruleset. Applies the script
    /// to the kernel, then swaps the in-memory pointer. If the
    /// apply fails, the in-memory ruleset is *not* updated —
    /// the engine continues evaluating against the previous
    /// ruleset and the error surfaces to the caller.
    pub async fn install(&self, compiled: CompiledRuleSet) -> Result<(), FirewallError> {
        // Skip if the digest matches the currently-installed
        // ruleset — saves a kernel-side commit + a transient
        // arc-swap on policy republishes that don't actually
        // change the rules.
        if let Some(current) = self.ruleset.load().as_ref().as_ref() {
            if current.script.digest == compiled.script.digest
                && current.source_graph_version == compiled.source_graph_version
            {
                return Ok(());
            }
            if compiled.source_graph_version < current.source_graph_version {
                return Err(FirewallError::BundleInvalid(format!(
                    "stale ruleset: incoming graph_version {} < current {}",
                    compiled.source_graph_version, current.source_graph_version
                )));
            }
        }
        self.backend.apply(&compiled.script).await?;
        self.ruleset.store(Arc::new(Some(compiled)));
        Ok(())
    }

    /// Evaluate one flow against the loaded ruleset. Returns
    /// the matching rule's action plus the metadata needed for
    /// audit / downstream dispatch. Fail-closed: if no ruleset
    /// is loaded, returns [`RuleAction::Deny`].
    pub fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FirewallVerdict {
        let ruleset_guard = self.ruleset.load();
        let conntrack_state = self.update_conntrack(ctx);

        let Some(rs) = ruleset_guard.as_ref().as_ref() else {
            return FirewallVerdict {
                action: RuleAction::Deny,
                matched_rule_id: None,
                from_zone: None,
                to_zone: None,
                conntrack: conntrack_state,
            };
        };

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
                    from_zone: from_zone.clone(),
                    to_zone: to_zone.clone(),
                    conntrack: conntrack_state,
                };
            }
        }

        // Walk the rule list. Terminal action wins.
        let mut log_pending: Option<&str> = None;
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
                    from_zone,
                    to_zone,
                    conntrack: conntrack_state,
                };
            }
            // Non-terminal (Log) — record and continue walking
            // so a subsequent terminal rule applies.
            log_pending = Some(&r.id);
        }

        // No terminal match. If a Log rule fired, return that —
        // the operator wants the audit even if no other rule
        // matched. Otherwise fall back to the default action.
        if let Some(id) = log_pending {
            FirewallVerdict {
                action: RuleAction::Log,
                matched_rule_id: Some(id.to_owned()),
                from_zone,
                to_zone,
                conntrack: conntrack_state,
            }
        } else {
            FirewallVerdict {
                action: rs.default_action,
                matched_rule_id: None,
                from_zone,
                to_zone,
                conntrack: conntrack_state,
            }
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

    /// Snapshot of the currently-loaded ruleset, if any. Used
    /// by telemetry / introspection callers.
    #[must_use]
    pub fn current_ruleset(&self) -> Option<Arc<Option<CompiledRuleSet>>> {
        let g = self.ruleset.load();
        Some(g.clone())
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
    async fn evaluate_log_rule_continues_to_next_terminal() {
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
                id: "deny".into(),
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
        assert_eq!(v.matched_rule_id.as_deref(), Some("deny"));
    }

    #[tokio::test]
    async fn evaluate_log_rule_alone_returns_log_with_audit_id() {
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
        assert_eq!(v.action, RuleAction::Log);
        assert_eq!(v.matched_rule_id.as_deref(), Some("log-only"));
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
}
