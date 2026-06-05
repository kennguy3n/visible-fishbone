//! Data-path decision-throughput comparison: nftables slow path vs
//! eBPF/XDP fast path.
//!
//! The rest of this crate measures *end-to-end* throughput by pushing
//! real frames through a running gateway over `AF_PACKET`. That answers
//! "how fast is the box", but it needs root, a NIC, and a live data
//! plane, so it cannot run in a unit test or on a laptop.
//!
//! This module measures the narrower thing STREAM B actually changes:
//! the **per-packet decision cost** of the two enforcement substrates,
//! in-process and with no privileges. It is an honest apples-to-apples
//! comparison because both paths evaluate the *same* synthetic rule set
//! against the *same* packet stream:
//!
//!   * **nftables (slow path)** — the full [`sng_fw::FirewallEngine`]
//!     evaluate: zone classification, conntrack update, subject gating,
//!     and the ordered rule walk. This is the work the userspace engine
//!     does for every flow the kernel hands up.
//!   * **eBPF/XDP (fast path)** — [`sng_ebpf::XdpRuleSet::evaluate`],
//!     the lean first-match L3/L4 walk an XDP program runs at the ring
//!     buffer, before the packet ever reaches the network stack.
//!
//! The XDP rule set is produced from the compiled rule set with
//! [`sng_fw::compile_hot_path`] — the exact translation the edge ships —
//! so the benchmark cannot drift from production behaviour.
//!
//! The fast path's win is structural (no conntrack mutation, no zone map
//! lookup, no subject string compare, no allocation per verdict), so the
//! measured speedup is a lower bound on the real-world gain: in the
//! kernel, XDP also skips the entire `sk_buff` allocation and network
//! stack traversal that the nftables path pays before it even runs.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use sng_fw::compile::CompiledRuleSet;
use sng_fw::conntrack::FlowDirection;
use sng_fw::engine::{EvaluationContext, FirewallEngine, FlowKey};
use sng_fw::nat::NatTable;
use sng_fw::nftables::{MockNftables, NftablesScript};
use sng_fw::rule::{FirewallRule, Protocol, RuleAction, RuleMatch};
use sng_fw::zone::ZoneTable;
use sng_policy_eval::matcher::SubjectMatch;

/// One side's measured result.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PathResult {
    /// Packets evaluated.
    pub packets: u64,
    /// Wall-clock time spent in the measured evaluate loop.
    pub elapsed: Duration,
}

impl PathResult {
    /// Decisions per second. `0.0` for a zero-duration measurement so a
    /// degenerate (too-fast-to-time) run never divides by zero.
    #[must_use]
    pub fn packets_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.packets as f64 / secs
        }
    }
}

/// The outcome of a [`compare`] run.
#[derive(Clone, Copy, Debug)]
pub struct DataPathComparison {
    /// Number of L3/L4 rules in the synthetic rule set.
    pub rule_count: usize,
    /// nftables full-engine slow path.
    pub nftables: PathResult,
    /// eBPF/XDP fast path.
    pub ebpf: PathResult,
}

impl DataPathComparison {
    /// Fast-path throughput divided by slow-path throughput. `> 1.0`
    /// means the eBPF path evaluates more packets per second. `0.0` if
    /// the slow path was un-measurably fast (guards against a divide by
    /// zero on an idle machine with a coarse clock).
    #[must_use]
    pub fn speedup(&self) -> f64 {
        let slow = self.nftables.packets_per_sec();
        if slow <= 0.0 {
            0.0
        } else {
            self.ebpf.packets_per_sec() / slow
        }
    }
}

/// Build a synthetic rule set of `rule_count` hot-path-eligible L3/L4
/// allow rules over distinct `10.x.y.0/24` destinations, terminating in
/// a default `Deny`. Every rule is pure L3/L4 (no subject gate, no zone
/// filter), so the entire set is eligible for XDP offload and the two
/// paths are guaranteed to agree on every verdict.
#[must_use]
pub fn build_synthetic_ruleset(rule_count: usize) -> CompiledRuleSet {
    let rules = (0..rule_count)
        .map(|i| {
            // Spread destinations across 10.<hi>.<lo>.0/24 so each rule
            // matches a disjoint /24 and only one rule can fire per flow.
            let hi = u8::try_from((i >> 8) & 0xff).unwrap_or(0);
            let lo = u8::try_from(i & 0xff).unwrap_or(0);
            let dst: IpNet = IpNet::new(IpAddr::V4(Ipv4Addr::new(10, hi, lo, 0)), 24)
                .expect("valid /24");
            FirewallRule {
                id: format!("rule-{i}"),
                matches: RuleMatch {
                    src_cidrs: Vec::new(),
                    dst_cidrs: vec![dst],
                    src_ports: Vec::new(),
                    dst_ports: Vec::new(),
                    protocol: Protocol::Tcp,
                    subject: SubjectMatch::Any,
                },
                action: RuleAction::Allow,
                from_zones: Vec::new(),
                to_zones: Vec::new(),
                description: String::new(),
            }
        })
        .collect();
    CompiledRuleSet {
        rules,
        zones: ZoneTable::default(),
        nat: NatTable::default(),
        default_action: RuleAction::Deny,
        source_graph_id: "bench-datapath".to_owned(),
        source_graph_version: 1,
        script: NftablesScript::new(Vec::new()),
    }
}

/// The size of the synthetic concurrent-flow pool. A real edge tracks a
/// bounded set of live flows, not a fresh 5-tuple per packet; capping the
/// pool keeps the slow path's conntrack table (a `Vec`-backed advisory
/// structure) at a realistic steady-state size instead of growing it
/// unbounded, which would turn the benchmark into an O(n²) artefact of
/// the test rather than a measure of per-packet decision cost.
pub const FLOW_POOL: usize = 1024;

/// Build a pool of up to [`FLOW_POOL`] distinct synthetic TCP flows, then
/// stream `packet_count` packets by cycling through that pool. Most flows
/// target the rule set's `/24`s (so they hit a rule); every
/// `miss_every`-th *pool slot* targets `203.0.113.0` (TEST-NET-3, matched
/// by no rule) so the default-action path is exercised too. `rule_count`
/// must be the same value passed to [`build_synthetic_ruleset`].
#[must_use]
pub fn build_flows(packet_count: usize, rule_count: usize, miss_every: usize) -> Vec<FlowKey> {
    let rule_count = rule_count.max(1);
    let miss_every = miss_every.max(1);
    let pool_len = packet_count.clamp(1, FLOW_POOL);

    // Construct the distinct-flow pool once.
    let pool: Vec<FlowKey> = (0..pool_len)
        .map(|slot| {
            let dst = if slot % miss_every == 0 {
                // Matches no rule → exercises the default Deny / catch-all.
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
            } else {
                let idx = slot % rule_count;
                let hi = u8::try_from((idx >> 8) & 0xff).unwrap_or(0);
                let lo = u8::try_from(idx & 0xff).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::new(10, hi, lo, 7))
            };
            FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                dst,
                40000 + u16::try_from(slot % u16::MAX as usize).unwrap_or(0),
                443,
                Protocol::Tcp,
            )
        })
        .collect();

    // Stream packet_count packets by cycling the pool.
    (0..packet_count).map(|i| pool[i % pool_len].clone()).collect()
}

/// Run the comparison: build a `rule_count`-rule set, install it into a
/// [`FirewallEngine`] (mock kernel backend) and translate it to an
/// [`XdpRuleSet`], then evaluate `packet_count` synthetic flows through
/// each path and time the loops.
///
/// # Panics
///
/// Panics if the one-time `FirewallEngine::install` fails — that only
/// happens on a malformed rule set, which `build_synthetic_ruleset`
/// never produces, so a panic here is a benchmark bug, not a runtime
/// condition.
#[must_use]
pub fn compare(rule_count: usize, packet_count: usize) -> DataPathComparison {
    let compiled = build_synthetic_ruleset(rule_count);
    let flows = build_flows(packet_count, rule_count, 8);

    // --- eBPF/XDP fast path: the exact production translation. ---
    let xdp = sng_fw::compile_hot_path(&compiled);

    // --- nftables slow path: the full engine, ruleset installed. ---
    let engine = FirewallEngine::new(std::sync::Arc::new(MockNftables::new()));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    rt.block_on(engine.install(compiled))
        .expect("install synthetic ruleset");

    // Measure the slow path.
    let nft_start = Instant::now();
    let mut nft_sink = 0u64;
    for flow in &flows {
        let ctx = EvaluationContext {
            flow: flow.clone(),
            direction: FlowDirection::Original,
            subject_value: None,
        };
        let verdict = engine.evaluate(&ctx);
        nft_sink = nft_sink.wrapping_add(verdict.action as u64);
    }
    let nft_elapsed = nft_start.elapsed();

    // Measure the fast path.
    let xdp_start = Instant::now();
    let mut xdp_sink = 0u64;
    for flow in &flows {
        let src_port = flow.src_port;
        let proto = flow.protocol.iana_number().unwrap_or(6);
        let decision = xdp.evaluate(flow.src_ip, flow.dst_ip, src_port, flow.dst_port, proto);
        xdp_sink = xdp_sink.wrapping_add(decision.action as u64);
    }
    let xdp_elapsed = xdp_start.elapsed();

    // Touch the sinks so the optimizer cannot delete either loop.
    std::hint::black_box((nft_sink, xdp_sink));

    DataPathComparison {
        rule_count,
        nftables: PathResult {
            packets: flows.len() as u64,
            elapsed: nft_elapsed,
        },
        ebpf: PathResult {
            packets: flows.len() as u64,
            elapsed: xdp_elapsed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_ebpf::XdpRuleAction;

    #[test]
    fn synthetic_ruleset_is_fully_hot_path_eligible() {
        let compiled = build_synthetic_ruleset(64);
        let xdp = sng_fw::compile_hot_path(&compiled);
        // Every rule translated (none truncated the chain) and the
        // default Deny was accelerated to a drop catch-all.
        assert_eq!(xdp.len(), 64);
        assert_eq!(xdp.default_action(), XdpRuleAction::Drop);
    }

    #[test]
    fn both_paths_agree_on_every_synthetic_flow() {
        let rule_count = 32;
        let compiled = build_synthetic_ruleset(rule_count);
        let xdp = sng_fw::compile_hot_path(&compiled);

        let engine = FirewallEngine::new(std::sync::Arc::new(MockNftables::new()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(engine.install(compiled)).unwrap();

        for flow in build_flows(500, rule_count, 8) {
            let ctx = EvaluationContext {
                flow: flow.clone(),
                direction: FlowDirection::Original,
                subject_value: None,
            };
            let nft = engine.evaluate(&ctx).action;
            let proto = flow.protocol.iana_number().unwrap_or(6);
            let xdp_action =
                xdp.evaluate(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto)
                    .action;
            // The two substrates must reach the same allow/deny verdict
            // for every L3/L4 flow — that is the correctness contract the
            // offload relies on.
            let nft_allow = nft == RuleAction::Allow;
            let xdp_allow = xdp_action == XdpRuleAction::Pass;
            assert_eq!(
                nft_allow, xdp_allow,
                "verdict mismatch for {flow:?}: nft={nft:?} xdp={xdp_action:?}"
            );
        }
    }

    #[test]
    fn compare_runs_and_reports_positive_throughput() {
        let cmp = compare(16, 5_000);
        assert_eq!(cmp.rule_count, 16);
        assert_eq!(cmp.nftables.packets, 5_000);
        assert_eq!(cmp.ebpf.packets, 5_000);
        // Both paths must have evaluated something at a measurable rate.
        assert!(cmp.nftables.packets_per_sec() > 0.0);
        assert!(cmp.ebpf.packets_per_sec() > 0.0);
        // The speedup is reported as a finite, positive ratio. We do not
        // assert a hard threshold (CI runners vary wildly), only that the
        // measurement is well-formed; the binary prints the live number.
        let speedup = cmp.speedup();
        assert!(speedup.is_finite());
        assert!(speedup > 0.0);
    }

    #[test]
    fn packets_per_sec_is_zero_for_zero_duration() {
        let r = PathResult {
            packets: 100,
            elapsed: Duration::ZERO,
        };
        // Exactly zero by construction (zero duration short-circuits);
        // `<= 0.0` sidesteps the float-equality lint while still pinning
        // the documented contract.
        assert!(r.packets_per_sec() <= 0.0);
    }
}
