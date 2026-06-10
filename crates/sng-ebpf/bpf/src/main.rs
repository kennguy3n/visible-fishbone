//! SNG eBPF/XDP fast-path data plane (kernel side).
//!
//! Two programs share one object and one set of maps:
//!
//! * [`sng_xdp_classify`] — the XDP ingress hook. Per packet it parses
//!   the L3/L4 5-tuple, consults the policy-verdict cache for a recent
//!   decision, and on a miss runs GeoIP country blocking, per-source
//!   SYN/UDP flood rate limiting, traffic classification, and the
//!   hot-path firewall, then records per-flow state and caches the
//!   verdict. Anything it cannot parse (non-IP, truncated) is passed to
//!   the normal kernel stack — XDP is an accelerator in front of
//!   nftables, never a black hole.
//! * [`sng_tc_egress`] — the TC `clsact` egress hook. It resolves the
//!   flow's class tag (written by the ingress program) and steers the
//!   packet onto the right underlay via the per-class steering table.
//!
//! All map layouts and names are the kernel mirror of the userspace
//! contract; see [`contract`]. The userspace loader
//! (`crates/sng-ebpf/src/loader.rs`) fills these maps.

#![no_std]
#![no_main]

mod contract;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::{bpf_ktime_get_ns, bpf_redirect},
    macros::{classifier, map, xdp},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, ProgramArray},
    programs::{TcContext, XdpContext},
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use contract::*;

// ---- Maps (names + capacities match the userspace contract) ----

#[map(name = "sng_fw_rules")]
static SNG_FW_RULES: Array<WireRule> = Array::with_max_entries(MAX_FW_RULES, 0);
#[map(name = "sng_fw_meta")]
static SNG_FW_META: Array<WireRuleSetMeta> = Array::with_max_entries(1, 0);
#[map(name = "sng_class_rules")]
static SNG_CLASS_RULES: Array<WireClassRule> = Array::with_max_entries(MAX_CLASS_RULES, 0);
#[map(name = "sng_class_meta")]
static SNG_CLASS_META: Array<WireClassMeta> = Array::with_max_entries(1, 0);
#[map(name = "sng_steering")]
static SNG_STEERING: Array<WireSteeringTarget> = Array::with_max_entries(STEERING_SLOTS, 0);
#[map(name = "sng_ddos_cfg")]
static SNG_DDOS_CFG: Array<WireDdosConfig> = Array::with_max_entries(1, 0);
#[map(name = "sng_geoip_v4")]
static SNG_GEOIP_V4: LpmTrie<[u8; 4], WireCountry> =
    LpmTrie::with_max_entries(MAX_GEOIP_ENTRIES, 0);
#[map(name = "sng_geoip_v6")]
static SNG_GEOIP_V6: LpmTrie<[u8; 16], WireCountry> =
    LpmTrie::with_max_entries(MAX_GEOIP_ENTRIES, 0);
#[map(name = "sng_geo_block")]
static SNG_GEO_BLOCK: HashMap<WireCountry, u8> =
    HashMap::with_max_entries(MAX_BLOCKED_COUNTRIES, 0);
#[map(name = "sng_flow_state")]
static SNG_FLOW_STATE: LruHashMap<FlowKey, FlowState> = LruHashMap::with_max_entries(MAX_FLOWS, 0);
// PoP-shared policy verdict cache: one fixed-capacity LRU keyed by the
// `FlowKey` 5-tuple (no tenant field) for every tenant on the edge. Keep
// `MAX_FLOWS` a tenant-count-independent constant — see `contract::MAX_FLOWS`.
#[map(name = "sng_verdict_cache")]
static SNG_VERDICT_CACHE: LruHashMap<FlowKey, VerdictCacheEntry> =
    LruHashMap::with_max_entries(MAX_FLOWS, 0);
#[map(name = "sng_syn_buckets")]
static SNG_SYN_BUCKETS: LruHashMap<[u8; 16], TokenBucketState> =
    LruHashMap::with_max_entries(MAX_SOURCES, 0);
#[map(name = "sng_udp_buckets")]
static SNG_UDP_BUCKETS: LruHashMap<[u8; 16], TokenBucketState> =
    LruHashMap::with_max_entries(MAX_SOURCES, 0);

// ---- Tail-call pipeline (split to stay under the verifier jump limit) ----
//
// The XDP fast path is split into chained programs so that no single
// program's verification exceeds the kernel's `BPF_COMPLEXITY_LIMIT_JMP_SEQ`
// (8192 jumps on 5.15). The 1024-entry linear rule scans (classify and
// firewall) are the dominant source of jumps, so they live in their own
// programs and the verifier proves each independently:
//
//   sng_xdp_classify (entry)   -- parse + verdict cache + GeoIP + rate limit
//        | tail_call(SNG_TAIL_CLASSIFY_0)
//   sng_xdp_stage_classify     -- class rules [0, CLASS_CHUNK)
//        | tail_call(SNG_TAIL_CLASSIFY_1)
//   sng_xdp_stage_classify_1   -- class rules [CLASS_CHUNK, 2*CLASS_CHUNK)
//        | tail_call(SNG_TAIL_FIREWALL_0)
//   sng_xdp_stage_firewall     -- firewall rules [0*FW_CHUNK, 1*FW_CHUNK)
//        | tail_call(SNG_TAIL_FIREWALL_1)
//   sng_xdp_stage_firewall_1..6 -- firewall rules [k*FW_CHUNK, (k+1)*FW_CHUNK)
//        | tail_call(SNG_TAIL_FIREWALL_{k+1})
//   sng_xdp_stage_firewall_7   -- firewall rules [7*FW_CHUNK, MAX) (terminal)
//        | tail_call(SNG_TAIL_APPLY)        on match / default
//   sng_xdp_stage_apply        -- cache + account the resolved verdict once
//
// Both linear scans are split into fixed, compile-time-constant index ranges
// (chunks). A rule's nested CIDR/port matching dominates the jump count, so
// each scan is sized so its verified jump sequence stays under the 8192-jump
// cap *and* LLVM keeps it a real loop (a chunk small enough to fully unroll
// instead explodes the verifier's state count past the 1M-insn limit).
// Empirically on 5.15: firewall verifies at FW_CHUNK=128 (8 programs cover
// 1024 rules), classification at CLASS_CHUNK=512 (2 programs). Both leave
// margin on either side of the unroll/jump boundaries. Constant ranges are
// essential: a *runtime* cursor makes the rule index symbolic, which
// collapses the verifier's state pruning and blows the 1M-insn limit.
// First-match-wins ordering is preserved because the chunks scan strictly
// increasing index ranges in sequence. The worst-case chain (a packet that
// matches no rule) is entry + 2 classify + 8 firewall + apply = 11 tail
// calls, well under the kernel's 33-deep tail-call cap.
//
// A tail call replaces (does not return into) the current program and resets
// the BPF stack, so cross-stage state travels through the per-CPU scratch
// slot below — XDP runs each packet to completion on one CPU without
// preemption, so a single-entry per-CPU array is a safe hand-off buffer.
// If a tail call fails (the jump table is not yet populated by the loader),
// control falls through to `XDP_PASS`: fail-open to nftables, never a drop.

/// Jump-table indices for the tail-call pipeline. The userspace loader
/// (`AyaLoader::attach_xdp`) populates `sng_xdp_progs` at these indices.
const SNG_TAIL_CLASSIFY_0: u32 = 0;
const SNG_TAIL_CLASSIFY_1: u32 = 1;
const SNG_TAIL_FIREWALL_0: u32 = 2;
const SNG_TAIL_FIREWALL_1: u32 = 3;
const SNG_TAIL_FIREWALL_2: u32 = 4;
const SNG_TAIL_FIREWALL_3: u32 = 5;
const SNG_TAIL_FIREWALL_4: u32 = 6;
const SNG_TAIL_FIREWALL_5: u32 = 7;
const SNG_TAIL_FIREWALL_6: u32 = 8;
const SNG_TAIL_FIREWALL_7: u32 = 9;
/// Terminal stage: applies (caches + accounts) the resolved verdict once.
const SNG_TAIL_APPLY: u32 = 10;
/// Number of populated jump-table slots (the loader fills exactly these).
pub const SNG_XDP_PROG_SLOTS: u32 = 11;

/// Firewall rules scanned per program (a compile-time-constant index range).
/// At ~35 verifier jumps per rule (4 CIDRs + 4 ports per `WireRule`) a
/// 128-rule chunk lands near ~4500 jumps, under the 8192 cap, and stays a
/// real loop (LLVM only unrolls — and explodes the verifier state count —
/// above ~160). `MAX_FW_RULES / FW_CHUNK` = 1024 / 128 = 8 chunks cover the
/// whole array, within the kernel's 33-deep tail-call cap.
const FW_CHUNK: u32 = 128;

/// Class rules scanned per program. The class matcher is far cheaper than
/// the firewall matcher (one prefix + one port compare), so 512 rules per
/// program stays well under the jump cap and rolled; 2 chunks cover 1024.
const CLASS_CHUNK: u32 = 512;

#[map(name = "sng_xdp_progs")]
static SNG_XDP_PROGS: ProgramArray = ProgramArray::with_max_entries(SNG_XDP_PROG_SLOTS, 0);

/// Per-CPU hand-off buffer carrying the parsed flow context across the
/// tail-call boundary. Kernel-owned and internal to this object — it has
/// no userspace mirror and is never read by the control plane.
#[map(name = "sng_xdp_scratch")]
static SNG_XDP_SCRATCH: PerCpuArray<XdpScratch> = PerCpuArray::with_max_entries(1, 0);

/// Cross-stage state for the tail-call pipeline. `class` is written by the
/// classification stage and read by the firewall stage; the rest is set by
/// the entry stage. Layout is internal (no wire contract), but kept
/// `#[repr(C)]` so its size/alignment are stable across stages.
#[repr(C)]
#[derive(Copy, Clone)]
struct XdpScratch {
    key: FlowKey,
    now: u64,
    bytes: u32,
    class: u8,
    /// Verdict resolved by a firewall chunk, consumed by the apply stage.
    action: u8,
    pad: [u8; 2],
}

/// How long a cached verdict stays valid (5 s). A flush from the control
/// plane on a policy change is the primary invalidation; this TTL bounds
/// staleness if a flush is ever missed.
const VERDICT_TTL_NS: u64 = 5_000_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// `BPF_ANY` — insert-or-update for map writes.
const BPF_ANY: u64 = 0;

// ===================== XDP ingress program =====================

/// Stage 0 / entry: parse the packet, serve a cached verdict, and apply
/// the GeoIP block and per-source rate limits. On a miss it stashes the
/// flow context in the per-CPU scratch slot and tail-calls the classify
/// stage; the remaining 1024-entry rule scans live in the chained
/// programs so each stays under the verifier jump limit.
#[xdp]
pub fn sng_xdp_classify(ctx: XdpContext) -> u32 {
    // Fail-open to the kernel stack: a packet the fast path cannot parse
    // or classify is handed up to nftables, never silently dropped.
    try_classify(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_classify(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some(parsed) = parse_flow(data, data_end) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let key = parsed.key;
    let now = unsafe { bpf_ktime_get_ns() };

    // Fast path: a fresh cached verdict short-circuits the whole pipeline.
    if let Some(entry) = unsafe { SNG_VERDICT_CACHE.get(&key) } {
        if now.saturating_sub(entry.inserted_ns) <= VERDICT_TTL_NS {
            let action = u32::from(entry.action);
            account_flow(&key, parsed.bytes, entry.action, entry.traffic_class, now);
            return Ok(xdp_action_or_pass(action));
        }
    }

    let cfg = SNG_DDOS_CFG.get(0);

    // GeoIP country blocking on the source address.
    if let Some(cfg) = cfg {
        if cfg.geoip_enabled == PRESENT && geoip_blocked(&key) {
            return Ok(finish(&key, parsed.bytes, ACTION_DROP, CLASS_BLOCK, now));
        }
    }

    // Per-source SYN / UDP flood rate limiting.
    if let Some(cfg) = cfg {
        if !rate_limit_admits(cfg, &parsed, now) {
            return Ok(finish(&key, parsed.bytes, ACTION_DROP, CLASS_BLOCK, now));
        }
    }

    // Hand the flow to the classification stage. Stash the context in the
    // per-CPU scratch slot (the stack does not survive a tail call), then
    // jump. `tail_call` does not return on success; on failure (jump table
    // not yet populated) fall open to the kernel stack.
    let Some(scratch) = SNG_XDP_SCRATCH.get_ptr_mut(0) else {
        return Ok(xdp_action::XDP_PASS);
    };
    unsafe {
        (*scratch).key = key;
        (*scratch).now = now;
        (*scratch).bytes = parsed.bytes;
        (*scratch).class = 0;
        (*scratch).action = ACTION_PASS;
        (*scratch).pad = [0; 2];
    }
    let _ = unsafe { SNG_XDP_PROGS.tail_call(ctx, SNG_TAIL_CLASSIFY_0) };
    Ok(xdp_action::XDP_PASS)
}

/// Stage 1 (chunk 0): traffic classification over class rules
/// `[0, CLASS_CHUNK)` (longest-prefix-first array walk). A `CLASS_BLOCK`
/// tier drops here; a match records the class in scratch and tail-calls the
/// firewall stage; no match tail-calls the next classification chunk.
#[xdp]
pub fn sng_xdp_stage_classify(ctx: XdpContext) -> u32 {
    run_classify_chunk(&ctx, 0, SNG_TAIL_CLASSIFY_1).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 1 (chunk 1, terminal): class rules `[CLASS_CHUNK, 2*CLASS_CHUNK)`.
/// On no match it resolves the fallback class before the firewall stage.
#[xdp]
pub fn sng_xdp_stage_classify_1(ctx: XdpContext) -> u32 {
    run_classify_chunk(&ctx, CLASS_CHUNK, SNG_TAIL_TERMINAL).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 0): hot-path firewall over rules `[0, FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 0, SNG_TAIL_FIREWALL_1).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 1): firewall over rules `[FW_CHUNK, 2*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_1(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, FW_CHUNK, SNG_TAIL_FIREWALL_2).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 2): firewall over rules `[2*FW_CHUNK, 3*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_2(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 2 * FW_CHUNK, SNG_TAIL_FIREWALL_3).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 3): firewall over rules `[3*FW_CHUNK, 4*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_3(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 3 * FW_CHUNK, SNG_TAIL_FIREWALL_4).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 4): firewall over rules `[4*FW_CHUNK, 5*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_4(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 4 * FW_CHUNK, SNG_TAIL_FIREWALL_5).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 5): firewall over rules `[5*FW_CHUNK, 6*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_5(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 5 * FW_CHUNK, SNG_TAIL_FIREWALL_6).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 6): firewall over rules `[6*FW_CHUNK, 7*FW_CHUNK)`.
#[xdp]
pub fn sng_xdp_stage_firewall_6(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 6 * FW_CHUNK, SNG_TAIL_FIREWALL_7).unwrap_or(xdp_action::XDP_PASS)
}

/// Stage 2 (chunk 7, terminal): firewall over rules `[7*FW_CHUNK, MAX)`.
#[xdp]
pub fn sng_xdp_stage_firewall_7(ctx: XdpContext) -> u32 {
    run_firewall_chunk(&ctx, 7 * FW_CHUNK, SNG_TAIL_TERMINAL).unwrap_or(xdp_action::XDP_PASS)
}

/// Terminal stage: cache + account the verdict a firewall chunk resolved.
///
/// Splitting this out of the chunk programs is what keeps each chunk
/// verifiable: the verdict continuation (`finish` — two map inserts and a
/// lookup) is heavy, and applying it inside a chunk made the verifier
/// re-explore it once per loop-exit state, exploding the instruction count.
/// Here it is reached on a single path and verified exactly once.
#[xdp]
pub fn sng_xdp_stage_apply(ctx: XdpContext) -> u32 {
    try_stage_apply(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_stage_apply(_ctx: &XdpContext) -> Result<u32, ()> {
    let scratch = SNG_XDP_SCRATCH.get(0).ok_or(())?;
    Ok(finish(
        &scratch.key,
        scratch.bytes,
        scratch.action,
        scratch.class,
        scratch.now,
    ))
}

/// Sentinel "next" index meaning "no further chunk": the current chunk is
/// terminal, so on no match it resolves the default action instead of
/// tail-calling. It is never registered in the jump table.
const SNG_TAIL_TERMINAL: u32 = u32::MAX;

/// Scan firewall rules in the chunk `[lo, lo + FW_CHUNK)` (first-match-wins).
/// `lo` is a compile-time constant at every call site, so the loop bound is
/// constant for the verifier. On a match this caches and accounts the
/// verdict (terminal). On no match it tail-calls `next_tail` to scan the
/// following chunk; the terminal chunk (`next_tail == SNG_TAIL_TERMINAL`, or
/// a chunk that already covers the whole installed ruleset) instead applies
/// the configured default action.
#[inline(always)]
fn run_firewall_chunk(ctx: &XdpContext, lo: u32, next_tail: u32) -> Result<u32, ()> {
    let scratch = SNG_XDP_SCRATCH.get(0).ok_or(())?;
    let key = scratch.key;
    let (count, default) = fw_meta();

    // First-match-wins scan with an *early exit* on the matching rule, exactly
    // like `classify`. The match arm stashes the verdict and tail-calls the
    // apply stage immediately, so the program terminates at the match — nothing
    // is carried past it. An earlier version instead accumulated the result in a
    // `matched: Option<u8>` and applied it after the loop; carrying that live
    // value across every iteration (plus the post-loop continuation) fanned the
    // verifier's state count out to ~18k and blew the 1M-insn analysis limit
    // even at 24 rules. With the early exit each iteration has just two
    // successors — match→terminal-tail-call and no-match→next index — so the
    // scan stays a small, prunable loop and is bounded by its jump count
    // (~35/rule at 4 CIDRs + 4 ports) rather than by state explosion. The bound
    // carries the symbolic `count` so the loop stops at the installed rule
    // count, while `hi` (a verifier-known constant) bounds the worst case.
    //
    // FW_CHUNK is deliberately large enough (128) that LLVM does *not* fully
    // unroll the body: too small a constant trip count makes the optimizer
    // inline every rule, fanning the verifier's state count past the 1M-insn
    // limit, whereas the rolled loop stays a small prunable cycle. The chunk
    // size therefore sits in the window above the unroll threshold and below
    // the 8192-jump cap — see the module header for the measured boundaries.
    let hi = lo + FW_CHUNK;
    let mut i = lo;
    while i < hi && i < count {
        if let Some(rule) = SNG_FW_RULES.get(i) {
            if fw_rule_matches(rule, &key) {
                stash_action_and_apply(ctx, rule_to_action(rule.action));
                return Ok(xdp_action::XDP_PASS);
            }
        }
        i += 1;
    }

    // No match in this chunk. If a populated later chunk exists, continue the
    // scan there; the verdict continuation lives in its own terminal program
    // (`sng_xdp_stage_apply`).
    if next_tail != SNG_TAIL_TERMINAL && hi < count && hi < MAX_FW_RULES {
        let _ = unsafe { SNG_XDP_PROGS.tail_call(ctx, next_tail) };
        // Tail-call failed (jump table not populated) → fail open.
        return Ok(xdp_action::XDP_PASS);
    }

    // Terminal chunk with no match → apply the configured default action.
    stash_action_and_apply(ctx, rule_to_action(default));
    Ok(xdp_action::XDP_PASS)
}

/// Stash the resolved verdict in per-CPU scratch and tail-call the apply
/// stage, which caches + accounts it on a single path. On tail-call failure
/// the caller falls through to a fail-open `XDP_PASS`.
#[inline(always)]
fn stash_action_and_apply(ctx: &XdpContext, action: u8) {
    if let Some(s) = SNG_XDP_SCRATCH.get_ptr_mut(0) {
        unsafe { (*s).action = action };
    }
    let _ = unsafe { SNG_XDP_PROGS.tail_call(ctx, SNG_TAIL_APPLY) };
}

/// Resolve, cache, and account a fresh verdict, returning the XDP action.
fn finish(key: &FlowKey, bytes: u32, action: u8, class: u8, now: u64) -> u32 {
    let entry = VerdictCacheEntry {
        action,
        traffic_class: class,
        pad: [0; 6],
        inserted_ns: now,
    };
    let _ = SNG_VERDICT_CACHE.insert(key, &entry, BPF_ANY);
    account_flow(key, bytes, action, class, now);
    xdp_action_or_pass(u32::from(action))
}

/// Map a stored action discriminant to a kernel `xdp_action`, defaulting
/// to `XDP_PASS` for any value outside the known set.
fn xdp_action_or_pass(action: u32) -> u32 {
    match action {
        a if a == u32::from(ACTION_DROP) => xdp_action::XDP_DROP,
        a if a == u32::from(ACTION_ABORTED) => xdp_action::XDP_ABORTED,
        _ => xdp_action::XDP_PASS,
    }
}

/// Update (or create) the per-flow state record.
fn account_flow(key: &FlowKey, bytes: u32, action: u8, class: u8, now: u64) {
    if let Some(state) = unsafe { SNG_FLOW_STATE.get(key) } {
        let mut updated = *state;
        updated.last_seen_ns = now;
        updated.packets = updated.packets.saturating_add(1);
        updated.bytes = updated.bytes.saturating_add(u64::from(bytes));
        updated.action = action;
        updated.traffic_class = class;
        let _ = SNG_FLOW_STATE.insert(key, &updated, BPF_ANY);
    } else {
        let state = FlowState {
            last_seen_ns: now,
            first_seen_ns: now,
            packets: 1,
            bytes: u64::from(bytes),
            action,
            traffic_class: class,
            l4_protocol: key.protocol,
            anomaly_flags: 0,
            pad: [0; 4],
        };
        let _ = SNG_FLOW_STATE.insert(key, &state, BPF_ANY);
    }
}

/// True if the flow's source address resolves to a blocked country.
fn geoip_blocked(key: &FlowKey) -> bool {
    let country = if key.family == FAMILY_V4 {
        let mut data = [0u8; 4];
        data.copy_from_slice(&key.src[..4]);
        SNG_GEOIP_V4.get(&Key::new(32, data)).copied()
    } else {
        SNG_GEOIP_V6.get(&Key::new(128, key.src)).copied()
    };
    match country {
        Some(country) => unsafe { SNG_GEO_BLOCK.get(&country).is_some() },
        None => false,
    }
}

/// Apply the relevant per-source token bucket; returns `false` to drop.
fn rate_limit_admits(cfg: &WireDdosConfig, parsed: &Parsed, now: u64) -> bool {
    if parsed.is_tcp_syn && cfg.syn_enabled == PRESENT {
        return bucket_admit(
            &SNG_SYN_BUCKETS,
            &parsed.key.src,
            cfg.syn_capacity,
            cfg.syn_refill_per_sec,
            now,
        );
    }
    if parsed.key.protocol == PROTO_UDP && cfg.udp_enabled == PRESENT {
        return bucket_admit(
            &SNG_UDP_BUCKETS,
            &parsed.key.src,
            cfg.udp_capacity,
            cfg.udp_refill_per_sec,
            now,
        );
    }
    true
}

/// Token-bucket admission for one source. Mirrors the userspace
/// `ddos::TokenBucket` (scaled-integer, no floating point); the clock only
/// advances on a whole-token refill so sub-token time is not lost.
//
// The refill block is gated on `refill_per_sec > 0`, so the subsequent
// `NANOS_PER_SEC / refill_per_sec` can never divide by zero. `checked_div`
// (as clippy suggests) would force an `Option` and an extra branch on a
// path that is provably safe, so the explicit guard is kept deliberately.
#[allow(clippy::manual_checked_ops)]
fn bucket_admit(
    map: &LruHashMap<[u8; 16], TokenBucketState>,
    src: &[u8; 16],
    capacity: u64,
    refill_per_sec: u64,
    now: u64,
) -> bool {
    if capacity == 0 {
        return false;
    }
    let mut bucket = match unsafe { map.get(src) } {
        Some(b) => *b,
        None => TokenBucketState {
            tokens: capacity,
            last_refill_ns: now,
        },
    };

    if refill_per_sec > 0 {
        // Nanoseconds of elapsed time that accrue one token. Crucially this
        // divides the *constant* numerator by the *runtime* `refill_per_sec`,
        // which the BPF backend lowers to a native 64-bit divide. Dividing
        // by a compile-time constant (e.g. `elapsed / 1_000_000_000`) would
        // instead be optimised into a 64×64→128 magic-number multiply that
        // calls the unsupported `__multi3` libcall and fails to link.
        // `refill_per_sec >= 1`, so the quotient is in `[1, 1e9]`.
        let ns_per_token = NANOS_PER_SEC / refill_per_sec;
        let ns_per_token = if ns_per_token == 0 { 1 } else { ns_per_token };

        let elapsed = now.saturating_sub(bucket.last_refill_ns);
        // runtime / runtime -> native BPF divide.
        let added = elapsed / ns_per_token;
        if added > 0 {
            bucket.tokens = min_u64(bucket.tokens.saturating_add(added), capacity);
            // Advance the clock only by the time actually consumed by the
            // whole tokens we granted, so sub-token remainder carries over.
            // `added == elapsed / ns_per_token`, so `added * ns_per_token`
            // is always `<= elapsed` and cannot overflow — a plain 64-bit
            // multiply (native BPF). We must NOT add an overflow guard such
            // as `a > u64::MAX / b`: LLVM's InstCombine rewrites that idiom
            // into a `umul.with.overflow` that lowers to the unsupported
            // 128-bit `__multi3` libcall.
            let consumed = added * ns_per_token;
            bucket.last_refill_ns = bucket.last_refill_ns.saturating_add(consumed);
        }
    } else if now > bucket.last_refill_ns {
        bucket.last_refill_ns = now;
    }

    let admitted = if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        false
    };
    let _ = map.insert(src, &bucket, BPF_ANY);
    admitted
}

/// Read the classification metadata: `(rule_count, fallback_class)`. With
/// no classifier installed the data path fails closed (`CLASS_BLOCK`, a
/// drop), matching the userspace default.
fn class_meta() -> (u32, u8) {
    match SNG_CLASS_META.get(0) {
        Some(m) => (m.count, m.fallback_class),
        None => (0, CLASS_BLOCK),
    }
}

/// Scan the classification array in the chunk `[lo, lo + CLASS_CHUNK)`
/// (already longest-prefix-first, so first-match-wins is most-specific
/// first). On a match resolve the tier; on no match tail-call `next_tail`
/// to scan the next chunk, or — for the terminal chunk — resolve the
/// configured fallback tier. Mirrors `run_firewall_chunk`: the constant
/// range keeps the loop rolled and its jump sequence bounded.
#[inline(always)]
fn run_classify_chunk(ctx: &XdpContext, lo: u32, next_tail: u32) -> Result<u32, ()> {
    let scratch = SNG_XDP_SCRATCH.get(0).ok_or(())?;
    let key = scratch.key;
    let bytes = scratch.bytes;
    let now = scratch.now;
    let (count, fallback) = class_meta();

    let hi = lo + CLASS_CHUNK;
    let mut i = lo;
    while i < hi && i < count {
        if let Some(rule) = SNG_CLASS_RULES.get(i) {
            if class_rule_matches(rule, &key) {
                return Ok(resolve_class_and_advance(ctx, &key, bytes, now, rule.class));
            }
        }
        i += 1;
    }

    // No match in this chunk. If a populated later chunk exists, continue
    // the scan there; otherwise this chunk is terminal.
    if next_tail != SNG_TAIL_TERMINAL && hi < count && hi < MAX_CLASS_RULES {
        let _ = unsafe { SNG_XDP_PROGS.tail_call(ctx, next_tail) };
        return Ok(xdp_action::XDP_PASS);
    }
    Ok(resolve_class_and_advance(ctx, &key, bytes, now, fallback))
}

/// Resolve a classification tier: a `CLASS_BLOCK` tier drops via `finish`;
/// any other tier is recorded in scratch and control tail-calls the first
/// firewall chunk. On tail-call failure the caller falls open to `XDP_PASS`.
#[inline(always)]
fn resolve_class_and_advance(
    ctx: &XdpContext,
    key: &FlowKey,
    bytes: u32,
    now: u64,
    class: u8,
) -> u32 {
    if class == CLASS_BLOCK {
        return finish(key, bytes, ACTION_DROP, class, now);
    }
    if let Some(s) = SNG_XDP_SCRATCH.get_ptr_mut(0) {
        unsafe { (*s).class = class };
    }
    let _ = unsafe { SNG_XDP_PROGS.tail_call(ctx, SNG_TAIL_FIREWALL_0) };
    xdp_action::XDP_PASS
}

fn class_rule_matches(rule: &WireClassRule, key: &FlowKey) -> bool {
    if rule.family != key.family {
        return false;
    }
    let len_bytes = if key.family == FAMILY_V4 { 4 } else { 16 };
    if !prefix_match(&key.dst, &rule.dst, rule.prefix_len, len_bytes) {
        return false;
    }
    if rule.port_present == PRESENT && rule.dst_port != key.dst_port {
        return false;
    }
    true
}

/// Read the firewall ruleset metadata: `(rule_count, default_action)`.
/// With no ruleset installed the data path fails closed (`RULE_DROP`),
/// matching the userspace `XdpRuleSet::default`.
fn fw_meta() -> (u32, u8) {
    match SNG_FW_META.get(0) {
        Some(m) => (m.count, m.default_action),
        None => (0, RULE_DROP),
    }
}

fn rule_to_action(rule_action: u8) -> u8 {
    if rule_action == RULE_DROP {
        ACTION_DROP
    } else {
        ACTION_PASS
    }
}

/// `#[inline(never)]` keeps the per-rule match as a real BPF-to-BPF call.
/// LLVM will not fully unroll a loop whose body contains a call, so the
/// firewall scan stays a real loop even at a small `FW_CHUNK`. That is what
/// lets each chunk scan few enough rules to keep its verified jump sequence
/// under the kernel's 8192-jump cap (an unrolled scan instead explodes the
/// verifier's state count).
#[inline(never)]
fn fw_rule_matches(rule: &WireRule, key: &FlowKey) -> bool {
    let len_bytes = if key.family == FAMILY_V4 { 4 } else { 16 };
    if rule.protocol_present == PRESENT && rule.protocol != key.protocol {
        return false;
    }
    if !cidr_list_matches(
        &rule.src_cidrs,
        rule.n_src_cidrs,
        &key.src,
        key.family,
        len_bytes,
    ) {
        return false;
    }
    if !cidr_list_matches(
        &rule.dst_cidrs,
        rule.n_dst_cidrs,
        &key.dst,
        key.family,
        len_bytes,
    ) {
        return false;
    }
    if !port_list_matches(&rule.src_ports, rule.n_src_ports, key.src_port) {
        return false;
    }
    if !port_list_matches(&rule.dst_ports, rule.n_dst_ports, key.dst_port) {
        return false;
    }
    true
}

/// An empty list matches anything; otherwise the address must match at
/// least one same-family CIDR.
///
/// `n` is clamped to `MAX_CIDRS_PER_RULE` up front so the scan loop carries
/// a single bound (`i < n`) instead of two (`i < MAX && i < n`). The clamp
/// keeps the bound a verifier-known constant ceiling, halving the
/// loop-control branches — material because this runs twice per rule across
/// the firewall scan and the per-rule jump count is what gates each chunk
/// under the 8192-jump verifier limit.
fn cidr_list_matches(
    cidrs: &[WireCidr; MAX_CIDRS_PER_RULE],
    n: u8,
    addr: &[u8; 16],
    family: u8,
    len_bytes: usize,
) -> bool {
    if n == 0 {
        return true;
    }
    let count = if (n as usize) < MAX_CIDRS_PER_RULE {
        n as usize
    } else {
        MAX_CIDRS_PER_RULE
    };
    // Accumulate into `hit` instead of returning early on the first match.
    // An early `return true` creates a distinct function exit per match
    // position, and because this runs inside the firewall scan loop the
    // verifier explores those exits multiplicatively across rules, exploding
    // the analysed instruction count. Folding every iteration into a single
    // boolean keeps one exit, so the enclosing scan stays prunable.
    let mut hit = false;
    let mut i = 0usize;
    while i < count {
        let c = &cidrs[i];
        if c.family == family && prefix_match(addr, &c.addr, c.prefix_len, len_bytes) {
            hit = true;
        }
        i += 1;
    }
    hit
}

/// An empty list matches any port; otherwise the port must fall in a range.
/// `n` is clamped to `MAX_PORTS_PER_RULE` up front for the same single-bound
/// loop-control reason as [`cidr_list_matches`].
fn port_list_matches(ports: &[WirePortRange; MAX_PORTS_PER_RULE], n: u8, port: u16) -> bool {
    if n == 0 {
        return true;
    }
    let count = if (n as usize) < MAX_PORTS_PER_RULE {
        n as usize
    } else {
        MAX_PORTS_PER_RULE
    };
    // Accumulator form (no early return) for the same reason as
    // [`cidr_list_matches`]: a single exit keeps the firewall scan prunable.
    let mut hit = false;
    let mut i = 0usize;
    while i < count {
        let r = &ports[i];
        if port >= r.from && port <= r.to {
            hit = true;
        }
        i += 1;
    }
    hit
}

/// Longest-prefix bitwise compare of `addr` against `net` over the leading
/// `prefix_len` bits, clamped to the address-family width `len_bytes`
/// (4 for v4, 16 for v6).
///
/// Implemented with at most two 64-bit masked compares rather than a
/// per-byte loop. The byte loop iterated a *symbolic* count (`prefix_len`
/// from a map) and applied a symbolic mask shift, which the verifier tracks
/// imprecisely — across a long rule scan that imprecision defeats state
/// pruning and explodes the verifier's processed-instruction count. The
/// word form has no data-dependent inner loop, so each call collapses to a
/// handful of fixed instructions and the verifier prunes the scan cleanly.
/// Addresses are in network byte order, so `from_be_bytes` yields a value
/// whose most-significant bits are the leading address bits; masking the top
/// `prefix_len` bits is the prefix compare.
#[inline(always)]
fn prefix_match(addr: &[u8; 16], net: &[u8; 16], prefix_len: u8, len_bytes: usize) -> bool {
    let max_bits = (len_bytes as u32) * 8;
    let bits = if (prefix_len as u32) < max_bits {
        prefix_len as u32
    } else {
        max_bits
    };
    if bits == 0 {
        return true;
    }

    let a_hi = u64::from_be_bytes([
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
    ]);
    let n_hi = u64::from_be_bytes([
        net[0], net[1], net[2], net[3], net[4], net[5], net[6], net[7],
    ]);

    if bits <= 64 {
        let mask = if bits == 64 {
            u64::MAX
        } else {
            u64::MAX << (64 - bits)
        };
        return (a_hi ^ n_hi) & mask == 0;
    }

    if a_hi != n_hi {
        return false;
    }

    let a_lo = u64::from_be_bytes([
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
    ]);
    let n_lo = u64::from_be_bytes([
        net[8], net[9], net[10], net[11], net[12], net[13], net[14], net[15],
    ]);
    let lo_bits = bits - 64;
    let mask = if lo_bits == 64 {
        u64::MAX
    } else {
        u64::MAX << (64 - lo_bits)
    };
    (a_lo ^ n_lo) & mask == 0
}

// ===================== TC egress steering program =====================

#[classifier]
pub fn sng_tc_egress(ctx: TcContext) -> i32 {
    let mut ctx = ctx;
    try_steer(&mut ctx).unwrap_or(TC_ACT_OK)
}

fn try_steer(ctx: &mut TcContext) -> Result<i32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some(parsed) = parse_flow(data, data_end) else {
        return Ok(TC_ACT_OK);
    };

    // The class was tagged by the ingress program. Egress packets of a
    // flow may carry the reverse 5-tuple, so try both orientations.
    let class = match unsafe { SNG_FLOW_STATE.get(&parsed.key) } {
        Some(state) => state.traffic_class,
        None => {
            let reversed = reverse_key(&parsed.key);
            match unsafe { SNG_FLOW_STATE.get(&reversed) } {
                Some(state) => state.traffic_class,
                None => return Ok(TC_ACT_OK),
            }
        }
    };

    let Some(target) = SNG_STEERING.get(u32::from(class)) else {
        return Ok(TC_ACT_OK);
    };
    let target = *target;

    match target.action {
        a if a == STEER_DROP => Ok(TC_ACT_SHOT),
        a if a == STEER_MARK => {
            ctx.set_mark(target.mark);
            Ok(TC_ACT_OK)
        }
        a if a == STEER_REDIRECT => {
            if target.mark != 0 {
                ctx.set_mark(target.mark);
            }
            // `bpf_redirect` returns TC_ACT_REDIRECT on success; on a bad
            // ifindex fall back to the default route rather than dropping.
            let ret = unsafe { bpf_redirect(target.ifindex, 0) } as i32;
            if ret == TC_ACT_REDIRECT {
                Ok(ret)
            } else {
                Ok(TC_ACT_OK)
            }
        }
        _ => Ok(TC_ACT_OK),
    }
}

fn reverse_key(key: &FlowKey) -> FlowKey {
    FlowKey {
        src: key.dst,
        dst: key.src,
        src_port: key.dst_port,
        dst_port: key.src_port,
        protocol: key.protocol,
        family: key.family,
        pad: [0; 2],
    }
}

// ===================== Shared packet parsing =====================

/// The parsed result of one packet: its flow key, whether it is a bare
/// TCP SYN (connection-open, the SYN-flood signal), and its L3 byte count.
struct Parsed {
    key: FlowKey,
    is_tcp_syn: bool,
    bytes: u32,
}

/// Parse Ethernet → IPv4/IPv6 → TCP/UDP into a [`Parsed`]. Returns `None`
/// for non-IP or truncated packets (the caller passes them through).
///
/// `#[inline(always)]` is load-bearing: returning `Option<Parsed>` across a
/// BPF-to-BPF call boundary makes the kernel verifier reject the program on
/// the `None` paths (the struct-return stack slot is only partially
/// initialised, so the caller's read of it is flagged as an uninitialised
/// stack read). Inlining folds the parse into the caller's frame, letting
/// the verifier track each field's initialisation per path.
#[inline(always)]
fn parse_flow(data: usize, data_end: usize) -> Option<Parsed> {
    let eth: *const EthHdr = ptr_at(data, data_end, 0)?;
    let ether_type = unsafe { (*eth).ether_type };

    let mut key = FlowKey {
        src: [0; 16],
        dst: [0; 16],
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        family: 0,
        pad: [0; 2],
    };

    let (l4_off, proto, bytes) = if ether_type == EtherType::Ipv4 as u16 {
        let ip: *const Ipv4Hdr = ptr_at(data, data_end, EthHdr::LEN)?;
        let src = unsafe { (*ip).src_addr };
        let dst = unsafe { (*ip).dst_addr };
        copy4(&mut key.src, &src);
        copy4(&mut key.dst, &dst);
        key.family = FAMILY_V4;
        let proto = unsafe { (*ip).proto };
        let total = u16::from_be_bytes(unsafe { (*ip).tot_len });
        // Honour the IHL field rather than assuming the 20-byte minimum:
        // an IPv4 header carries up to 40 bytes of options (IHL 5..=15, in
        // 32-bit words). Reading L4 at a fixed offset would pull garbage
        // ports / SYN flags out of an options-bearing packet — an evasion
        // vector against port-keyed rules. A header below the 20-byte
        // minimum is malformed; fail open to the kernel stack. `l4_off`
        // stays bounded (<= 14 + 60) and every L4 read is range-checked by
        // `ptr_at`.
        let ihl_bytes = unsafe { (*ip).ihl() } as usize * 4;
        if ihl_bytes < Ipv4Hdr::LEN {
            return None;
        }
        (EthHdr::LEN + ihl_bytes, proto, u32::from(total))
    } else if ether_type == EtherType::Ipv6 as u16 {
        let ip: *const Ipv6Hdr = ptr_at(data, data_end, EthHdr::LEN)?;
        key.src = unsafe { (*ip).src_addr };
        key.dst = unsafe { (*ip).dst_addr };
        key.family = FAMILY_V6;
        let first_proto = unsafe { (*ip).next_hdr };
        let payload = u16::from_be_bytes(unsafe { (*ip).payload_len });
        // `next_hdr` is the real L4 protocol only when no extension headers
        // are present. A Hop-by-Hop / Routing / Dest-Options / Mobility /
        // Fragment header instead chains to the true L4 at a variable
        // offset; reading L4 at the fixed 40-byte offset would mis-key ports
        // (they stay 0), letting an attacker prepend an extension header to
        // slip past port-keyed rules and SYN/UDP rate limiting on the fast
        // path. Walk the chain (bounded by `MAX_IPV6_EXT_HDRS` for the
        // verifier) to the real L4 header. Anything we cannot resolve —
        // ESP/AH (encrypted/authenticated, no readable L4), a non-first
        // fragment (no L4 in this packet), or a chain longer than the cap —
        // fails open to the kernel stack (same semantics as a short IPv4
        // IHL), where nftables parses the chain and enforces correctly.
        let (l4_off, proto) =
            resolve_ipv6_l4(data, data_end, EthHdr::LEN + Ipv6Hdr::LEN, first_proto)?;
        (l4_off, proto, u32::from(payload) + Ipv6Hdr::LEN as u32)
    } else {
        return None;
    };

    key.protocol = proto;
    let mut is_tcp_syn = false;
    if proto == PROTO_TCP {
        let tcp: *const TcpHdr = ptr_at(data, data_end, l4_off)?;
        key.src_port = u16::from_be_bytes(unsafe { (*tcp).source });
        key.dst_port = u16::from_be_bytes(unsafe { (*tcp).dest });
        // A connection-open SYN (SYN set, ACK clear) is the flood signal.
        is_tcp_syn = unsafe { (*tcp).syn() != 0 && (*tcp).ack() == 0 };
    } else if proto == PROTO_UDP {
        let udp: *const UdpHdr = ptr_at(data, data_end, l4_off)?;
        key.src_port = u16::from_be_bytes(unsafe { (*udp).src });
        key.dst_port = u16::from_be_bytes(unsafe { (*udp).dst });
    }

    Some(Parsed {
        key,
        is_tcp_syn,
        bytes,
    })
}

/// The first two bytes shared by every "generic" IPv6 extension header
/// (Hop-by-Hop, Routing, Destination Options, Mobility): a next-header byte
/// and a length in 8-byte units (excluding the first 8 bytes).
#[repr(C)]
struct Ipv6ExtHdr {
    next_hdr: u8,
    hdr_ext_len: u8,
}

/// The IPv6 Fragment header (RFC 8200 §4.5), fixed at 8 bytes. `frag_off`
/// holds a 13-bit fragment offset (in 8-byte units) in its top bits, with
/// the low 3 bits holding reserved bits and the More-Fragments flag. The
/// `reserved` / `ident` fields are unread by the fast path but are kept so
/// the struct is a faithful, `#[repr(C)]`-correct 8-byte mirror of the wire
/// layout (the parser advances a fixed 8 bytes past it).
#[repr(C)]
#[allow(dead_code)]
struct Ipv6FragHdr {
    next_hdr: u8,
    reserved: u8,
    frag_off: [u8; 2],
    ident: [u8; 4],
}

/// True if `next_hdr` is an IPv6 extension header (rather than the real L4
/// protocol). These chain to the true L4 at a variable offset; the fast
/// path walks them in [`resolve_ipv6_l4`]. Covers Hop-by-Hop, Routing,
/// Fragment, ESP, Authentication, Destination Options and Mobility —
/// RFC 8200 §4 plus AH/ESP.
#[inline(always)]
const fn is_ipv6_ext_hdr(next_hdr: u8) -> bool {
    matches!(
        next_hdr,
        IPPROTO_HOPOPTS
            | IPPROTO_ROUTING
            | IPPROTO_FRAGMENT
            | IPPROTO_ESP
            | IPPROTO_AH
            | IPPROTO_DSTOPTS
            | IPPROTO_MOBILITY
    )
}

/// Walk the IPv6 extension-header chain starting at `start_off` (the byte
/// just past the 40-byte fixed header) with initial next-header `first_proto`,
/// returning the `(l4_offset, l4_protocol)` of the real upper-layer header.
///
/// Returns `None` (caller fails open to nftables) when the chain cannot be
/// resolved on the fast path:
/// * ESP/AH — payload is encrypted/authenticated, L4 ports are unreadable;
/// * a non-first Fragment — this packet carries no L4 header;
/// * a chain longer than [`MAX_IPV6_EXT_HDRS`] — pathological / hostile;
/// * any truncated read (bounds-checked by [`ptr_at`]).
///
/// The loop is bounded by a compile-time constant so the BPF verifier can
/// prove termination, and every packet access is range-checked, so `off`
/// never reads past `data_end`. This mirrors the host-tested reference
/// `ipv6_l4_offset` in `crates/sng-ebpf/src/wire.rs`.
#[inline(always)]
fn resolve_ipv6_l4(
    data: usize,
    data_end: usize,
    start_off: usize,
    first_proto: u8,
) -> Option<(usize, u8)> {
    let mut proto = first_proto;
    let mut off = start_off;
    for _ in 0..MAX_IPV6_EXT_HDRS {
        if !is_ipv6_ext_hdr(proto) {
            // `proto` is the real upper-layer protocol (TCP/UDP/ICMPv6/...).
            return Some((off, proto));
        }
        // Encrypted (ESP) or authenticated (AH) payloads have no L4 we can
        // read on the fast path; hand them to nftables.
        if proto == IPPROTO_ESP || proto == IPPROTO_AH {
            return None;
        }
        if proto == IPPROTO_FRAGMENT {
            let fh: *const Ipv6FragHdr = ptr_at(data, data_end, off)?;
            // Fragment offset lives in the top 13 bits of the big-endian
            // field; a non-zero offset means this is not the first fragment,
            // so the L4 header is in another packet — fail open.
            let frag_off = u16::from_be_bytes(unsafe { (*fh).frag_off }) >> 3;
            if frag_off != 0 {
                return None;
            }
            proto = unsafe { (*fh).next_hdr };
            off = off.checked_add(8)?;
        } else {
            // Generic ext header: total length is (hdr_ext_len + 1) * 8 bytes.
            let eh: *const Ipv6ExtHdr = ptr_at(data, data_end, off)?;
            let hdr_len = (unsafe { (*eh).hdr_ext_len } as usize + 1) * 8;
            proto = unsafe { (*eh).next_hdr };
            off = off.checked_add(hdr_len)?;
        }
    }
    // Ran out of iterations and still on an extension header → too long.
    None
}

/// Bounds-checked pointer into the packet at `offset`, valid for `T`.
#[inline(always)]
fn ptr_at<T>(data: usize, data_end: usize, offset: usize) -> Option<*const T> {
    let len = mem::size_of::<T>();
    let start = data.checked_add(offset)?;
    let end = start.checked_add(len)?;
    if end > data_end {
        return None;
    }
    Some(start as *const T)
}

#[inline(always)]
fn copy4(dst: &mut [u8; 16], src: &[u8; 4]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

#[inline(always)]
fn min_u64(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF has no unwinding; a panic cannot occur on the verified paths
    // above (every map/packet access is checked), but a handler is
    // mandatory for `no_std`.
    loop {}
}
