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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use aho_corasick::AhoCorasick;
use ipnet::IpNet;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use sng_ebpf::ddos::{PROTO_TCP, tcp_flags};
use sng_ebpf::{DdosConfig, DdosMitigator, DropReason, PacketMeta, RateLimit, XdpRuleAction};
use sng_fw::compile::CompiledRuleSet;
use sng_fw::conntrack::FlowDirection;
use sng_fw::engine::{EvaluationContext, FirewallEngine, FlowKey};
use sng_fw::l7::default_traffic_class;
use sng_fw::nat::NatTable;
use sng_fw::nftables::{MockNftables, NftablesScript};
use sng_fw::rule::{FirewallRule, Protocol, RuleAction, RuleMatch};
use sng_fw::zone::ZoneTable;
use sng_fw::{AppIdentifier, SniExtractor, TlsDecision, TlsPolicy, TrafficClass, sni_suffix_match};
use sng_policy_eval::matcher::SubjectMatch;

use crate::business_report::TrafficMix;

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
///
/// `rule_count` must be `<= 65_536`: the `10.<hi>.<lo>.0/24` encoding has
/// only 16 bits of room, so larger counts wrap the high byte and produce
/// colliding (non-disjoint) `/24`s, which would break the one-rule-per-flow
/// invariant the comparison relies on. The benchmark's realistic range is
/// hundreds-to-thousands of rules, well inside this bound; the
/// `debug_assert!` catches misuse loudly rather than silently overlapping.
#[must_use]
pub fn build_synthetic_ruleset(rule_count: usize) -> CompiledRuleSet {
    debug_assert!(
        rule_count <= 0x1_0000,
        "build_synthetic_ruleset: rule_count {rule_count} exceeds the 65536 \
         disjoint /24s the 10.<hi>.<lo>.0 encoding can represent"
    );
    let rules = (0..rule_count)
        .map(|i| {
            // Spread destinations across 10.<hi>.<lo>.0/24 so each rule
            // matches a disjoint /24 and only one rule can fire per flow.
            let hi = u8::try_from((i >> 8) & 0xff).unwrap_or(0);
            let lo = u8::try_from(i & 0xff).unwrap_or(0);
            let dst: IpNet =
                IpNet::new(IpAddr::V4(Ipv4Addr::new(10, hi, lo, 0)), 24).expect("valid /24");
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
    // Hit flows are addressed `10.<hi>.<lo>.7` from `idx % rule_count`, the
    // same 16-bit encoding as `build_synthetic_ruleset`; counts above 65_536
    // collide and a "hit" flow could land on the wrong rule's /24. Guard the
    // shared invariant (see `build_synthetic_ruleset`).
    debug_assert!(
        rule_count <= 0x1_0000,
        "build_flows: rule_count {rule_count} exceeds the 65536 disjoint /24s \
         the 10.<hi>.<lo>.0 encoding can represent"
    );
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
    (0..packet_count)
        .map(|i| pool[i % pool_len].clone())
        .collect()
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

/// Measured result of an XDP DDoS-mitigation scenario.
#[derive(Clone, Copy, Debug)]
pub struct DdosBenchResult {
    /// Packets pushed through [`DdosMitigator::evaluate`].
    pub packets: u64,
    /// Packets the mitigation dropped.
    pub dropped: u64,
    /// Wall-clock time spent in the measured evaluate loop.
    pub elapsed: Duration,
}

impl DdosBenchResult {
    /// Packets evaluated per second — the XDP drop-decision throughput.
    /// `0.0` for a zero-duration measurement so a degenerate run never
    /// divides by zero.
    #[must_use]
    pub fn packets_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.packets as f64 / secs
        }
    }

    /// Fraction of evaluated packets that were dropped, in `0.0..=1.0`.
    #[must_use]
    pub fn drop_ratio(&self) -> f64 {
        if self.packets == 0 {
            0.0
        } else {
            self.dropped as f64 / self.packets as f64
        }
    }
}

/// Number of distinct spoofed sources a synthetic SYN flood cycles
/// through. Real volumetric floods spray randomised/spoofed source IPs;
/// cycling a bounded pool keeps the per-source token buckets at a
/// realistic steady-state population instead of inflating the tracking
/// map without bound.
pub const FLOOD_SOURCES: usize = 4096;

fn flood_source(slot: usize) -> IpAddr {
    // 100.64.0.0/10 (CGNAT space) gives 4 M addresses without colliding
    // with the benchmark's other fixtures.
    let slot = u32::try_from(slot & 0x003f_ffff).unwrap_or(0);
    let base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    IpAddr::V4(Ipv4Addr::from(base + slot))
}

fn syn_packet(src: IpAddr) -> PacketMeta {
    PacketMeta {
        src_ip: src,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 40000,
        dst_port: 443,
        protocol: PROTO_TCP,
        tcp_flags: tcp_flags::SYN,
        len: 64,
    }
}

/// Benchmark the XDP SYN-flood drop rate: stream `packet_count` SYNs from
/// a [`FLOOD_SOURCES`]-wide spoofed-source pool through a
/// [`DdosMitigator`] whose per-source budget has already been saturated,
/// so the loop measures the steady-state cost of the *drop* decision —
/// the number the Step-3 target (`> 10M pps`) is about.
///
/// The buckets are pre-drained with a warm-up pass at `t=0`; the measured
/// pass also runs at `t=0` so no refill credits accrue and every measured
/// packet exercises the drop path.
#[must_use]
pub fn bench_syn_flood_drop_rate(packet_count: usize) -> DdosBenchResult {
    // Small per-source budget so the warm-up drains it cheaply; GeoIP is
    // empty (no country block) so the measured cost is purely the
    // per-source token-bucket lookup + drop.
    const SYN_BURST: u64 = 64;
    let config = DdosConfig {
        syn: Some(RateLimit::new(SYN_BURST, SYN_BURST).expect("valid syn budget")),
        ..DdosConfig::default()
    };
    let mut mitigator = DdosMitigator::with_capacity(config, FLOOD_SOURCES * 2);

    // Pre-build the packet stream so address construction is not timed.
    let packets: Vec<PacketMeta> = (0..packet_count)
        .map(|i| syn_packet(flood_source(i % FLOOD_SOURCES)))
        .collect();

    // Warm-up: fully drain EVERY source's bucket at t=0 by spending its
    // entire burst budget, independent of `packet_count`. Draining via the
    // measured stream would leave buckets partially full whenever
    // `packet_count` is small relative to `FLOOD_SOURCES * SYN_BURST`
    // (e.g. a quick 100-packet smoke run), so the measured pass would see
    // admits and under-report the drop rate. Draining per source makes the
    // measured pass observe empty buckets and drop every packet regardless
    // of how many packets are measured.
    for slot in 0..FLOOD_SOURCES {
        let warmup = syn_packet(flood_source(slot));
        for _ in 0..SYN_BURST {
            let _ = mitigator.evaluate(&warmup, 0);
        }
    }

    let start = Instant::now();
    let mut dropped = 0u64;
    let mut sink = 0u64;
    for p in &packets {
        let verdict = mitigator.evaluate(p, 0);
        if verdict.reason == DropReason::SynFlood {
            dropped += 1;
        }
        sink = sink.wrapping_add(verdict.action as u64);
    }
    let elapsed = start.elapsed();
    std::hint::black_box(sink);

    DdosBenchResult {
        packets: packets.len() as u64,
        dropped,
        elapsed,
    }
}

// ---------------------------------------------------------------------------
// Forwarding-mode sweep
//
// The `compare` benchmark above answers one narrow question — the raw
// L3/L4 decision cost of the two substrates. A published SKU datasheet
// needs more: the per-packet cost at every *inspection depth* the gateway
// actually runs, decomposed by traffic class, on the shipping (XDP) data
// path. This section drives that, end-to-end, with real enforcement code:
//
//   * forwarding decision   — `XdpRuleSet::evaluate` (fast path) or the
//     full `FirewallEngine` (slow path), the same nftables-vs-XDP toggle
//     `compare` measures;
//   * L7 identification     — `AppIdentifier`/`SignatureScanner` over a
//     real first-packet payload, then `default_traffic_class`;
//   * URL categorisation    — the production `sni_suffix_match` matcher
//     over a category list (the SWG's local-DB lookup);
//   * IPS/DLP content scan  — a real Aho-Corasick multi-pattern scan over
//     the (decrypted) payload, the MPM core of a signature engine;
//   * malware lookup        — a real SHA-256 over the payload, matched
//     against a hash set (the AV reputation check);
//   * TLS decrypt           — `SniExtractor` + `TlsPolicy::decide`, then a
//     real AES-256-GCM record open via `ring` (the edge's rustls crypto
//     provider), then a content scan of the cleartext.
//
// Nothing here is stubbed: every stage runs the same code the data plane
// runs, so the published numbers are measurements, not estimates.

/// The inspection depth a forwarding measurement applies. The variants
/// are cumulative — each does everything the shallower one does, plus its
/// own stage — so a sweep across all four shows the marginal cost of each
/// layer of the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardingMode {
    /// Pure L3/L4 forwarding verdict — no stateful NGFW, no L7.
    RawL3,
    /// Stateful NGFW verdict (zones, conntrack, subject gate, rule walk).
    NgfwVerdict,
    /// NGFW + L7 inspection (app-id, URL category, IPS/DLP, malware) on
    /// inspect-eligible flows. No TLS decryption (cleartext / metadata).
    FullStack,
    /// Full stack plus TLS interception: SNI extraction, the decrypt-vs-
    /// bypass decision, and AES-256-GCM record decryption + a content
    /// scan of the cleartext, on `inspect_full` flows.
    FullStackTlsDecrypt,
}

impl ForwardingMode {
    /// Every mode in increasing inspection depth.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::RawL3,
            Self::NgfwVerdict,
            Self::FullStack,
            Self::FullStackTlsDecrypt,
        ]
    }

    /// Stable kebab-case label used in reports, filenames, and markdown.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RawL3 => "raw-l3",
            Self::NgfwVerdict => "ngfw-verdict",
            Self::FullStack => "full-stack",
            Self::FullStackTlsDecrypt => "full-stack-tls",
        }
    }

    /// Cumulative depth, `0..=3`. Higher means more stages run.
    #[must_use]
    pub const fn depth(self) -> u8 {
        match self {
            Self::RawL3 => 0,
            Self::NgfwVerdict => 1,
            Self::FullStack => 2,
            Self::FullStackTlsDecrypt => 3,
        }
    }
}

/// Which substrate computes the forwarding decision — the nftables-vs-XDP
/// toggle. On the fast path a `Drop` verdict terminates the packet before
/// any userspace work; on the slow path every packet pays the full engine
/// walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Full `FirewallEngine` userspace evaluate (the slow path).
    Nftables,
    /// `XdpRuleSet` lean L3/L4 evaluate (the WS1 fast path).
    Xdp,
}

impl Backend {
    /// Both substrates.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::Nftables, Self::Xdp]
    }

    /// Stable lowercase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Xdp => "xdp",
        }
    }
}

/// One measured `(mode, backend)` forwarding loop.
#[derive(Clone, Copy, Debug)]
pub struct ForwardingResult {
    /// Inspection depth measured.
    pub mode: ForwardingMode,
    /// Forwarding substrate measured.
    pub backend: Backend,
    /// Packets pushed through the pipeline.
    pub packets: u64,
    /// Wall-clock time spent in the measured loop.
    pub elapsed: Duration,
    /// Median per-packet service time (ns), from batched sampling.
    pub p50_ns: u64,
    /// 99th-percentile per-packet service time (ns).
    pub p99_ns: u64,
}

impl ForwardingResult {
    /// Packets evaluated per second. `0.0` for a zero-duration run.
    #[must_use]
    pub fn packets_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.packets as f64 / secs
        }
    }

    /// Mean per-packet service time in nanoseconds. `0.0` for an empty
    /// run. This is the value the regression gate normalises on, since a
    /// ratio of two service times is hardware-invariant.
    #[must_use]
    pub fn ns_per_packet(&self) -> f64 {
        if self.packets == 0 {
            0.0
        } else {
            self.elapsed.as_nanos() as f64 / self.packets as f64
        }
    }

    /// Throughput in Gbps for a given representative frame size.
    #[must_use]
    pub fn gbps(&self, packet_bytes: u32) -> f64 {
        self.packets_per_sec() * f64::from(packet_bytes) * 8.0 / 1e9
    }
}

/// Per-traffic-class result under the full pipeline on the fast path.
#[derive(Clone, Copy, Debug)]
pub struct ClassForwardingResult {
    /// The class measured.
    pub class: TrafficClass,
    /// Packets pushed (all of this class).
    pub packets: u64,
    /// Wall-clock time for the loop.
    pub elapsed: Duration,
    /// Median per-packet service time (ns).
    pub p50_ns: u64,
    /// 99th-percentile per-packet service time (ns).
    pub p99_ns: u64,
}

impl ClassForwardingResult {
    /// Packets per second for this class. `0.0` for a zero-duration run.
    #[must_use]
    pub fn packets_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.packets as f64 / secs
        }
    }

    /// Throughput in Gbps for a representative frame size.
    #[must_use]
    pub fn gbps(&self, packet_bytes: u32) -> f64 {
        self.packets_per_sec() * f64::from(packet_bytes) * 8.0 / 1e9
    }
}

/// The full output of a [`ForwardingHarness::sweep`].
#[derive(Clone, Debug)]
pub struct ForwardingSweep {
    /// Rule count of the synthetic policy walked.
    pub rule_count: usize,
    /// Per-`(mode, backend)` results, in `mode × backend` order.
    pub results: Vec<ForwardingResult>,
    /// Per-traffic-class results under the full pipeline, fast path.
    pub per_class: Vec<ClassForwardingResult>,
}

impl ForwardingSweep {
    /// Look up a measured `(mode, backend)` result.
    #[must_use]
    pub fn get(&self, mode: ForwardingMode, backend: Backend) -> Option<&ForwardingResult> {
        self.results
            .iter()
            .find(|r| r.mode == mode && r.backend == backend)
    }
}

/// Batch size for per-packet latency sampling. A single `Instant::now()`
/// pair brackets `LATENCY_BATCH` packets and the elapsed time is divided
/// by the batch size, so the ~20 ns timer overhead is amortised to a
/// fraction of a nanosecond per packet — small against even the leanest
/// (raw-L3) decision — while still yielding a real service-time
/// distribution rather than a single mean.
const LATENCY_BATCH: usize = 64;

/// One synthetic flow: a 5-tuple plus the L7 fixtures the inspection
/// stages consume. Built once into a pool and cycled, so neither address
/// construction nor record sealing is timed.
#[derive(Clone, Debug)]
struct SynFlow {
    flow: FlowKey,
    proto: u8,
    class: TrafficClass,
    /// First-packet payload for app-id / signature scan.
    payload: Vec<u8>,
    /// SNI / Host for URL categorisation.
    host: String,
    /// A real TLS ClientHello carrying `host` as SNI.
    client_hello: Vec<u8>,
    /// Single-use nonce for the sealed record.
    nonce: [u8; NONCE_LEN],
    /// An AES-256-GCM-sealed application record (ciphertext + tag) the
    /// decrypt stage opens.
    sealed: Vec<u8>,
}

/// Reusable enforcement state for the forwarding sweep: the two
/// substrates plus every real inspector a packet flows through. Built
/// once from a rule count, then `sweep`d across modes and backends.
pub struct ForwardingHarness {
    rule_count: usize,
    engine: FirewallEngine,
    xdp: sng_ebpf::XdpRuleSet,
    appid: AppIdentifier,
    sni: SniExtractor,
    tls: TlsPolicy,
    aead: LessSafeKey,
    /// IPS/DLP multi-pattern matcher (Aho-Corasick MPM).
    ips: AhoCorasick,
    /// URL category suffixes paired with their category label.
    categories: Vec<(String, &'static str)>,
    /// Known-bad payload digests (the AV reputation set).
    malware: HashSet<[u8; 32]>,
}

impl std::fmt::Debug for ForwardingHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardingHarness")
            .field("rule_count", &self.rule_count)
            .field("categories", &self.categories.len())
            .field("malware_signatures", &self.malware.len())
            .finish_non_exhaustive()
    }
}

/// Representative application-record size sealed per flow (bytes). A full
/// MTU frame's worth of payload, so the AEAD-open and content-scan costs
/// reflect a real record rather than a token.
const RECORD_BYTES: usize = 1400;

/// Base of the synthetic ephemeral source-port window. Flows vary their
/// source port by slot within `[EPHEMERAL_BASE, EPHEMERAL_BASE + EPHEMERAL_SPAN)`
/// — inside the IANA ephemeral range and chosen so `base + offset` can never
/// overflow `u16` regardless of pool size.
const EPHEMERAL_BASE: u16 = 40_000;
/// Width of the ephemeral source-port window (see [`EPHEMERAL_BASE`]).
const EPHEMERAL_SPAN: u16 = 20_000;

impl ForwardingHarness {
    /// Build the harness: install a `rule_count`-rule synthetic policy
    /// into both substrates and construct every inspector once.
    ///
    /// # Panics
    /// Panics if the one-time `FirewallEngine::install` fails — that only
    /// happens on a malformed rule set, which `build_synthetic_ruleset`
    /// never produces, so a panic here is a benchmark bug.
    #[must_use]
    pub fn new(rule_count: usize) -> Self {
        let compiled = build_synthetic_ruleset(rule_count);
        let xdp = sng_fw::compile_hot_path(&compiled);
        let engine = FirewallEngine::new(std::sync::Arc::new(MockNftables::new()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        rt.block_on(engine.install(compiled))
            .expect("install synthetic ruleset");

        // AES-256-GCM with a fixed bench key. `LessSafeKey` lets us pin
        // the nonce per record (we seal once, open many times against the
        // same nonce in the loop) — appropriate for a benchmark, never
        // for production, where rustls manages nonces.
        let key_bytes = [0x42u8; 32];
        let aead =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).expect("valid AES-256 key"));

        let ips = AhoCorasick::new(ips_signature_set()).expect("valid IPS pattern set");

        Self {
            rule_count,
            engine,
            xdp,
            appid: AppIdentifier::new(),
            sni: SniExtractor::new(),
            tls: TlsPolicy::default_policy(),
            aead,
            ips,
            categories: category_db(),
            malware: malware_signature_set(),
        }
    }

    /// Rule count of the installed synthetic policy.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Run the full sweep for a SKU's traffic `mix` at `sample_packets`
    /// packets per measurement: every `(mode, backend)` pair, plus a
    /// per-traffic-class decomposition under the full pipeline on the
    /// fast path.
    #[must_use]
    pub fn sweep(&self, mix: &TrafficMix, sample_packets: usize) -> ForwardingSweep {
        let sample_packets = sample_packets.max(1);
        let pool = self.build_flow_pool(mix, sample_packets.min(FLOW_POOL));

        let mut results = Vec::with_capacity(ForwardingMode::all().len() * Backend::all().len());
        for mode in ForwardingMode::all() {
            for backend in Backend::all() {
                results.push(self.measure(&pool, sample_packets, mode, backend));
            }
        }

        let mut per_class = Vec::with_capacity(TrafficClass::all().len());
        for class in TrafficClass::all() {
            let class_pool = self.build_class_pool(class, FLOW_POOL.min(sample_packets));
            let r = self.measure(
                &class_pool,
                sample_packets,
                ForwardingMode::FullStackTlsDecrypt,
                Backend::Xdp,
            );
            per_class.push(ClassForwardingResult {
                class,
                packets: r.packets,
                elapsed: r.elapsed,
                p50_ns: r.p50_ns,
                p99_ns: r.p99_ns,
            });
        }

        ForwardingSweep {
            rule_count: self.rule_count,
            results,
            per_class,
        }
    }

    /// Measure a single `(mode, backend)` forwarding loop over a freshly
    /// built mixed flow pool — the one-stream unit the multi-queue harness
    /// fans out across worker threads.
    ///
    /// This is exactly one `(mode, backend)` cell of [`Self::sweep`],
    /// exposed so a caller can drive it on its own thread/core to model an
    /// independent NIC receive (RSS) queue. Each caller owns a distinct
    /// `ForwardingHarness` (its own engine, conntrack, and flow pool), so N
    /// of them running concurrently model N queues with no shared mutable
    /// state — the aggregate is then bounded only by the host's real core
    /// count and memory bandwidth, which is the line-rate ceiling the
    /// single-stream floor cannot see.
    #[must_use]
    pub fn measure_stream(
        &self,
        mix: &TrafficMix,
        sample_packets: usize,
        mode: ForwardingMode,
        backend: Backend,
    ) -> ForwardingResult {
        let sample_packets = sample_packets.max(1);
        let pool = self.build_flow_pool(mix, sample_packets.min(FLOW_POOL));
        self.measure(&pool, sample_packets, mode, backend)
    }

    /// Measure one `(mode, backend)` loop over `sample_packets` packets
    /// cycled from `pool`, then a second batched pass for the latency
    /// distribution.
    fn measure(
        &self,
        pool: &[SynFlow],
        sample_packets: usize,
        mode: ForwardingMode,
        backend: Backend,
    ) -> ForwardingResult {
        debug_assert!(!pool.is_empty(), "flow pool must be non-empty");
        let mut scratch: Vec<u8> = Vec::with_capacity(RECORD_BYTES + 16);

        // Throughput pass: time the whole loop.
        let start = Instant::now();
        let mut sink = 0u64;
        for i in 0..sample_packets {
            let f = &pool[i % pool.len()];
            sink = sink.wrapping_add(self.process_one(f, mode, backend, &mut scratch));
        }
        let elapsed = start.elapsed();
        std::hint::black_box(sink);

        // Latency pass: bracket batches of LATENCY_BATCH packets and
        // record the per-packet service time so the distribution has
        // negligible timer bias.
        let mut hist = crate::measurement::LatencyHistogram::new(50_000_000, 3);
        let mut sink2 = 0u64;
        let mut i = 0usize;
        while i < sample_packets {
            let batch = LATENCY_BATCH.min(sample_packets - i);
            let b_start = Instant::now();
            for j in 0..batch {
                let f = &pool[(i + j) % pool.len()];
                sink2 = sink2.wrapping_add(self.process_one(f, mode, backend, &mut scratch));
            }
            let b_ns = b_start.elapsed().as_nanos() as u64;
            let per_packet = b_ns / batch as u64;
            hist.record_n(per_packet, batch as u64);
            i += batch;
        }
        std::hint::black_box(sink2);

        ForwardingResult {
            mode,
            backend,
            packets: sample_packets as u64,
            elapsed,
            p50_ns: hist.p50().unwrap_or(0),
            p99_ns: hist.p99().unwrap_or(0),
        }
    }

    /// Push one packet through the pipeline for `(mode, backend)`. Returns
    /// a value derived from every stage's output so the optimizer cannot
    /// elide the work. This is the single source of truth for "what does
    /// a packet cost"; both the throughput and latency passes call it.
    #[inline]
    fn process_one(
        &self,
        f: &SynFlow,
        mode: ForwardingMode,
        backend: Backend,
        scratch: &mut Vec<u8>,
    ) -> u64 {
        let mut sink = 0u64;

        // --- Stage A: forwarding decision. ---
        if backend == Backend::Xdp {
            let d = self.xdp.evaluate(
                f.flow.src_ip,
                f.flow.dst_ip,
                f.flow.src_port,
                f.flow.dst_port,
                f.proto,
            );
            sink = sink.wrapping_add(d.action as u64);
            if d.action == XdpRuleAction::Drop {
                // Blocked at the ring buffer — no userspace work at all.
                return sink;
            }
        }
        // The stateful userspace NGFW verdict runs for every packet on the
        // slow path, and for fast-path packets whenever the mode needs
        // more than the lean L3/L4 decision. This is exactly the hybrid a
        // real XDP-offloaded edge runs: XDP early-drops, userspace decides
        // the rest.
        if backend == Backend::Nftables || mode != ForwardingMode::RawL3 {
            let ctx = EvaluationContext {
                flow: f.flow.clone(),
                direction: FlowDirection::Original,
                subject_value: None,
            };
            let verdict = self.engine.evaluate(&ctx);
            sink = sink.wrapping_add(verdict.action as u64);
            if verdict.action != RuleAction::Allow {
                return sink;
            }
        }
        if mode.depth() <= ForwardingMode::NgfwVerdict.depth() {
            return sink;
        }

        // --- Stage B: full-stack L7 inspection (inspect-eligible flows). ---
        let inspect = matches!(
            f.class,
            TrafficClass::InspectLite | TrafficClass::InspectFull
        );
        if inspect {
            let proto = self.appid.identify(&f.payload);
            let tc = default_traffic_class(proto);
            sink = sink.wrapping_add(proto.as_str().len() as u64);
            sink = sink.wrapping_add(tc.as_str().len() as u64);
            sink = sink.wrapping_add(self.categorize(&f.host));
            sink = sink.wrapping_add(self.scan(&f.payload));
            sink = sink.wrapping_add(u64::from(self.malware_hit(&f.payload)));
        }

        // --- Stage C: TLS decrypt (full-inspect flows only). ---
        if mode == ForwardingMode::FullStackTlsDecrypt && f.class == TrafficClass::InspectFull {
            let sni = self.sni.extract(&f.client_hello).ok().flatten();
            if self.tls.decide(sni.as_deref()).decision() == TlsDecision::Decrypt
                && let Some(plaintext) = self.open_record(f, scratch)
            {
                sink = sink.wrapping_add(self.scan(plaintext));
                sink = sink.wrapping_add(u64::from(self.malware_hit(plaintext)));
            }
        }

        // A private tunnel is decapsulated (overlay AEAD) but not content-
        // inspected once the full stack is engaged.
        if f.class == TrafficClass::TunnelPrivate
            && mode.depth() >= ForwardingMode::FullStack.depth()
            && let Some(plaintext) = self.open_record(f, scratch)
        {
            sink = sink.wrapping_add(plaintext.len() as u64);
        }

        sink
    }

    /// Copy the flow's sealed record into `scratch` and open it in place
    /// with AES-256-GCM, returning the cleartext slice (or `None` if the
    /// tag failed — never expected for our own sealed records).
    fn open_record<'s>(&self, f: &SynFlow, scratch: &'s mut Vec<u8>) -> Option<&'s [u8]> {
        scratch.clear();
        scratch.extend_from_slice(&f.sealed);
        self.aead
            .open_in_place(Nonce::assume_unique_for_key(f.nonce), Aad::empty(), scratch)
            .ok()
            .map(|pt| &*pt)
    }

    /// Linear suffix-match over the category DB (the SWG local-DB lookup).
    /// Returns the matched category's length, or 0 on no match — a value
    /// to keep the call live, not a verdict.
    fn categorize(&self, host: &str) -> u64 {
        for (suffix, category) in &self.categories {
            if sni_suffix_match(suffix, host) {
                return category.len() as u64;
            }
        }
        0
    }

    /// Aho-Corasick multi-pattern scan; returns the match count.
    fn scan(&self, data: &[u8]) -> u64 {
        self.ips.find_iter(data).count() as u64
    }

    /// SHA-256 the payload and test the digest against the AV set.
    fn malware_hit(&self, data: &[u8]) -> bool {
        let d = digest(&SHA256, data);
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        self.malware.contains(&h)
    }

    /// Build a mixed flow pool whose class proportions match `mix`. Class
    /// assignment is deterministic by slot position so the proportions —
    /// and therefore the measurement — are reproducible.
    fn build_flow_pool(&self, mix: &TrafficMix, pool_len: usize) -> Vec<SynFlow> {
        let pool_len = pool_len.max(1);
        let weights = mix.normalized();
        (0..pool_len)
            .map(|slot| {
                let pos = (slot as f64 + 0.5) / pool_len as f64;
                let class = pick_class(&weights, pos);
                self.make_flow(slot, class)
            })
            .collect()
    }

    /// Build a homogeneous pool of a single class for the per-class
    /// breakdown.
    fn build_class_pool(&self, class: TrafficClass, pool_len: usize) -> Vec<SynFlow> {
        let pool_len = pool_len.max(1);
        (0..pool_len)
            .map(|slot| self.make_flow(slot, class))
            .collect()
    }

    /// Construct one synthetic flow of `class`, sealing its application
    /// record so the decrypt stage has real ciphertext to open.
    fn make_flow(&self, slot: usize, class: TrafficClass) -> SynFlow {
        let rule_count = self.rule_count.max(1);
        // Blocked flows target TEST-NET-3 (matched by no rule → default
        // Deny → XDP drop); every other class hits an allow rule's /24.
        let dst = if class == TrafficClass::Block {
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, (slot % 254 + 1) as u8))
        } else {
            let idx = slot % rule_count;
            let hi = u8::try_from((idx >> 8) & 0xff).unwrap_or(0);
            let lo = u8::try_from(idx & 0xff).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::new(10, hi, lo, 7))
        };
        // Vary the ephemeral source port per slot so flows stay distinct
        // (the 5-tuple feeds the XDP hash and the conntrack key). Confine it
        // to a fixed window inside the IANA ephemeral range so `base + offset`
        // can never overflow u16 no matter how large the pool grows — the
        // offset is bounded by the span, so the sum stays < 60000.
        let src_port = EPHEMERAL_BASE + u16::try_from(slot % EPHEMERAL_SPAN as usize).unwrap_or(0);
        let flow = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            dst,
            src_port,
            443,
            Protocol::Tcp,
        );

        let host = host_for_class(class, slot);
        let payload = payload_for_class(class, &host);
        let client_hello = tls_client_hello_with_sni(&host);

        // Seal a representative application record. The nonce is derived
        // from the slot so it is unique within the pool.
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&(slot as u64).to_be_bytes());
        let record = synthetic_record(slot, RECORD_BYTES);
        let mut sealed = record;
        self.aead
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut sealed,
            )
            .expect("seal record");

        SynFlow {
            flow,
            proto: 6,
            class,
            payload,
            host,
            client_hello,
            nonce,
            sealed,
        }
    }
}

/// Pick a class from normalised `(class, fraction)` weights given a
/// position in `0.0..1.0` (cumulative-distribution lookup).
fn pick_class(weights: &[(TrafficClass, f64); 6], pos: f64) -> TrafficClass {
    let mut acc = 0.0;
    for (class, frac) in weights {
        acc += *frac;
        if pos < acc {
            return *class;
        }
    }
    // Floating-point slack at the tail: fall back to the last class.
    weights[weights.len() - 1].0
}

/// SNI / Host fixture for a class. Inspect-eligible classes use domains
/// the category DB recognises so the SWG lookup does real work.
fn host_for_class(class: TrafficClass, slot: usize) -> String {
    match class {
        TrafficClass::TrustedDirect => "dns.trusted-cdn.example".to_owned(),
        TrafficClass::TrustedMediaBypass => "media.trusted-cdn.example".to_owned(),
        TrafficClass::InspectLite => format!("svc{:03}.saas.example", slot % 1000),
        TrafficClass::InspectFull => format!("app{:03}.webmail.example", slot % 1000),
        TrafficClass::TunnelPrivate => "gw.tenant-private.example".to_owned(),
        TrafficClass::Block => "known-bad.malware.example".to_owned(),
    }
}

/// First-packet L7 payload fixture for a class.
fn payload_for_class(class: TrafficClass, host: &str) -> Vec<u8> {
    match class {
        // A real DNS query header + question.
        TrafficClass::TrustedDirect => dns_query(host),
        // A TLS application-data record header (post-handshake media).
        TrafficClass::TrustedMediaBypass | TrafficClass::TunnelPrivate => {
            vec![0x17, 0x03, 0x03, 0x05, 0xdc]
        }
        // A plain HTTP request line.
        TrafficClass::InspectLite => {
            format!("GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
        }
        // A TLS ClientHello (the decrypt path re-parses the full hello).
        TrafficClass::InspectFull => tls_client_hello_with_sni(host),
        TrafficClass::Block => b"GET /malware.exe HTTP/1.1\r\n\r\n".to_vec(),
    }
}

/// A minimal but valid DNS query (header + one A question for `host`),
/// recognised by `SignatureScanner::is_dns`.
fn dns_query(host: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + host.len() + 6);
    p.extend_from_slice(&[0x12, 0x34]); // id
    p.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD
    p.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    p.extend_from_slice(&[0x00, 0x00]); // ancount
    p.extend_from_slice(&[0x00, 0x00]); // nscount
    p.extend_from_slice(&[0x00, 0x00]); // arcount
    for label in host.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00); // root label
    p.extend_from_slice(&[0x00, 0x01]); // qtype A
    p.extend_from_slice(&[0x00, 0x01]); // qclass IN
    p
}

/// Hand-crafted minimal TLS 1.2 ClientHello carrying one SNI extension —
/// the same wire layout `SniExtractor::extract` parses in production.
fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
    let mut hello = Vec::<u8>::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    hello.extend_from_slice(&[0u8; 32]); // random
    hello.push(0); // session_id_length
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]); // cipher_suites
    hello.extend_from_slice(&[0x01, 0x00]); // compression_methods
    let ext_offset = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder
    let ext_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // ext type 0 (SNI)
    let sni_len_offset = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // ext length placeholder
    let sni_data_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // ServerNameList length placeholder
    hello.push(0x00); // name_type host_name
    let name_bytes = host.as_bytes();
    hello.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(name_bytes);
    let sni_data_end = hello.len();
    let server_name_list_len = (sni_data_end - sni_data_start - 2) as u16;
    hello[sni_data_start..sni_data_start + 2].copy_from_slice(&server_name_list_len.to_be_bytes());
    let sni_total_len = (sni_data_end - sni_data_start) as u16;
    hello[sni_len_offset..sni_len_offset + 2].copy_from_slice(&sni_total_len.to_be_bytes());
    let ext_total = (hello.len() - ext_start) as u16;
    hello[ext_offset..ext_offset + 2].copy_from_slice(&ext_total.to_be_bytes());

    let hs_len = hello.len() as u32;
    let mut record = Vec::<u8>::with_capacity(9 + hello.len());
    record.push(0x16); // handshake content type
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&((4 + hello.len()) as u16).to_be_bytes());
    record.push(0x01); // ClientHello
    record.push(((hs_len >> 16) & 0xFF) as u8);
    record.push(((hs_len >> 8) & 0xFF) as u8);
    record.push((hs_len & 0xFF) as u8);
    record.extend_from_slice(&hello);
    record
}

/// A representative application record: mostly benign filler with the odd
/// embedded token, so the content scan does real matching work over real
/// bytes. Deterministic in `seed` for reproducibility.
fn synthetic_record(seed: usize, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let filler = b"GET /resource HTTP/1.1 200 OK content payload segment ";
    while buf.len() < len {
        buf.extend_from_slice(filler);
    }
    buf.truncate(len);
    // Sprinkle a couple of scanner tokens at seed-dependent offsets so a
    // share of records produce matches (an IPS hot path is rarely empty).
    if len > 64 {
        let token = b"UNION SELECT";
        let off = seed % (len - token.len());
        buf[off..off + token.len()].copy_from_slice(token);
    }
    buf
}

/// The IPS/DLP signature set fed to the Aho-Corasick MPM. A blend of real
/// exploit/DLP tokens and a generated long tail, sized to a few hundred
/// patterns so the automaton — and its scan cost — is representative of a
/// signature engine rather than a toy.
fn ips_signature_set() -> Vec<String> {
    let mut set: Vec<String> = [
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        "<script>",
        "eval(",
        "UNION SELECT",
        "SELECT * FROM",
        "DROP TABLE",
        "../../../",
        "%2e%2e%2f",
        "password=",
        "passwd",
        "BEGIN RSA PRIVATE KEY",
        "AWS_SECRET_ACCESS_KEY",
        "xp_cmdshell",
        "base64_decode",
        "wget http",
        "curl http",
        "nc -e",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // Long tail of synthetic signatures (CVE-style content hooks) so the
    // MPM has the breadth of a real ruleset.
    for i in 0..236 {
        set.push(format!("SIG-{i:04}-MALWARE-CONTENT"));
    }
    set
}

/// The URL category DB consulted by the SWG lookup. A blend of named
/// categories and a generated tail of tracker/ad domains.
fn category_db() -> Vec<(String, &'static str)> {
    let mut db: Vec<(String, &'static str)> = vec![
        ("webmail.example".to_owned(), "webmail"),
        ("saas.example".to_owned(), "business"),
        ("trusted-cdn.example".to_owned(), "content-delivery"),
        ("malware.example".to_owned(), "malware"),
        ("tenant-private.example".to_owned(), "private"),
        ("social.example".to_owned(), "social-media"),
        ("finance.example".to_owned(), "finance"),
    ];
    for i in 0..200 {
        db.push((format!("t{i:03}.tracker.example"), "tracking"));
    }
    db
}

/// The AV reputation set: digests of a handful of known-bad payloads.
/// Populated with the digest of the `Block`-class fixture so the lookup
/// has real hits, not just misses.
fn malware_signature_set() -> HashSet<[u8; 32]> {
    let mut set = HashSet::new();
    for sample in [
        b"GET /malware.exe HTTP/1.1\r\n\r\n".as_slice(),
        b"MZ\x90\x00\x03\x00\x00\x00".as_slice(),
    ] {
        let d = digest(&SHA256, sample);
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        set.insert(h);
    }
    set
}

/// Convenience entry point: build a harness and run the forwarding sweep
/// for a `mix` at `rule_count` rules and `sample_packets` packets.
#[must_use]
pub fn bench_forwarding(
    rule_count: usize,
    sample_packets: usize,
    mix: &TrafficMix,
) -> ForwardingSweep {
    ForwardingHarness::new(rule_count).sweep(mix, sample_packets)
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
            let xdp_action = xdp
                .evaluate(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    proto,
                )
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
    fn syn_flood_bench_drops_saturated_sources() {
        // The warm-up spends every source's full burst budget, so the
        // measured pass at t=0 sees empty buckets and drops every packet.
        let pkts = FLOOD_SOURCES * 100;
        let r = bench_syn_flood_drop_rate(pkts);
        assert_eq!(r.packets, pkts as u64);
        assert_eq!(r.dropped, r.packets, "all post-warm-up SYNs are dropped");
        assert!((r.drop_ratio() - 1.0).abs() < f64::EPSILON);
        assert!(r.packets_per_sec() > 0.0);
    }

    #[test]
    fn syn_flood_bench_drops_all_even_for_small_packet_count() {
        // Regression: with a small packet_count (far fewer than
        // FLOOD_SOURCES * burst), the old stream-driven warm-up left most
        // buckets full and the measured pass under-reported the drop rate.
        // The per-source warm-up drains every bucket regardless, so even a
        // 100-packet smoke run drops 100%.
        for pkts in [1usize, 100, FLOOD_SOURCES] {
            let r = bench_syn_flood_drop_rate(pkts);
            assert_eq!(r.packets, pkts as u64);
            assert_eq!(
                r.dropped, r.packets,
                "every measured SYN is dropped for packet_count = {pkts}"
            );
            assert!((r.drop_ratio() - 1.0).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn syn_flood_bench_drop_ratio_is_zero_for_empty_run() {
        let r = DdosBenchResult {
            packets: 0,
            dropped: 0,
            elapsed: Duration::from_millis(1),
        };
        assert!(r.drop_ratio() <= 0.0);
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

    #[test]
    fn forwarding_sweep_covers_every_mode_backend_and_class() {
        let harness = ForwardingHarness::new(32);
        let sweep = harness.sweep(&TrafficMix::default(), 4_000);

        // Every (mode, backend) combination is measured exactly once.
        assert_eq!(
            sweep.results.len(),
            ForwardingMode::all().len() * Backend::all().len()
        );
        for mode in ForwardingMode::all() {
            for backend in Backend::all() {
                let r = sweep
                    .get(mode, backend)
                    .expect("every (mode, backend) point is present");
                assert_eq!(r.packets, 4_000, "{mode:?}/{backend:?} pushed all packets");
                assert!(
                    r.packets_per_sec() > 0.0,
                    "{mode:?}/{backend:?} has positive throughput"
                );
                assert!(
                    r.p99_ns >= r.p50_ns,
                    "{mode:?}/{backend:?} p99 {} >= p50 {}",
                    r.p99_ns,
                    r.p50_ns
                );
                assert!(r.gbps(1500) > 0.0);
            }
        }

        // The per-class breakdown carries one entry per taxonomy class, in
        // canonical order, each having pushed the full sample.
        assert_eq!(sweep.per_class.len(), TrafficClass::all().len());
        for (entry, class) in sweep.per_class.iter().zip(TrafficClass::all()) {
            assert_eq!(entry.class, class);
            assert_eq!(entry.packets, 4_000);
            assert!(entry.packets_per_sec() > 0.0);
            assert!(entry.p99_ns >= entry.p50_ns);
        }
    }

    #[test]
    fn deeper_inspection_costs_at_least_as_much_as_raw_l3() {
        // The cumulative pipeline can only add work, so on the same
        // substrate a deeper mode must not be *cheaper* per packet than
        // raw-L3 by more than measurement noise. We assert the robust
        // direction (full-stack+TLS ns/pkt >= raw-L3) with a generous
        // tolerance so the test is not flaky on a loaded CI runner.
        let harness = ForwardingHarness::new(64);
        let sweep = harness.sweep(&TrafficMix::default(), 8_000);
        let raw = sweep
            .get(ForwardingMode::RawL3, Backend::Xdp)
            .unwrap()
            .packets_per_sec();
        let full = sweep
            .get(ForwardingMode::FullStackTlsDecrypt, Backend::Xdp)
            .unwrap()
            .packets_per_sec();
        // Full stack is never dramatically *faster* than raw forwarding.
        assert!(
            full <= raw * 2.0,
            "full-stack pps {full} implausibly exceeds raw-L3 pps {raw}"
        );
    }
}
