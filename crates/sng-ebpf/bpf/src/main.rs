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
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, LruHashMap},
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
static SNG_GEOIP_V4: LpmTrie<[u8; 4], WireCountry> = LpmTrie::with_max_entries(MAX_GEOIP_ENTRIES, 0);
#[map(name = "sng_geoip_v6")]
static SNG_GEOIP_V6: LpmTrie<[u8; 16], WireCountry> =
    LpmTrie::with_max_entries(MAX_GEOIP_ENTRIES, 0);
#[map(name = "sng_geo_block")]
static SNG_GEO_BLOCK: HashMap<WireCountry, u8> = HashMap::with_max_entries(MAX_BLOCKED_COUNTRIES, 0);
#[map(name = "sng_flow_state")]
static SNG_FLOW_STATE: LruHashMap<FlowKey, FlowState> = LruHashMap::with_max_entries(MAX_FLOWS, 0);
#[map(name = "sng_verdict_cache")]
static SNG_VERDICT_CACHE: LruHashMap<FlowKey, VerdictCacheEntry> =
    LruHashMap::with_max_entries(MAX_FLOWS, 0);
#[map(name = "sng_syn_buckets")]
static SNG_SYN_BUCKETS: LruHashMap<[u8; 16], TokenBucketState> =
    LruHashMap::with_max_entries(MAX_SOURCES, 0);
#[map(name = "sng_udp_buckets")]
static SNG_UDP_BUCKETS: LruHashMap<[u8; 16], TokenBucketState> =
    LruHashMap::with_max_entries(MAX_SOURCES, 0);

/// How long a cached verdict stays valid (5 s). A flush from the control
/// plane on a policy change is the primary invalidation; this TTL bounds
/// staleness if a flush is ever missed.
const VERDICT_TTL_NS: u64 = 5_000_000_000;

/// `BPF_ANY` — insert-or-update for map writes.
const BPF_ANY: u64 = 0;

// ===================== XDP ingress program =====================

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

    // Traffic classification (longest-prefix-first array walk).
    let class = classify(&key);
    if class == CLASS_BLOCK {
        return Ok(finish(&key, parsed.bytes, ACTION_DROP, class, now));
    }

    // Hot-path firewall (first-match-wins; default on no match).
    let action = firewall_action(&key);
    Ok(finish(&key, parsed.bytes, action, class, now))
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
        updated.bytes = updated.bytes.saturating_add(bytes);
        updated.action = action;
        updated.traffic_class = class;
        let _ = SNG_FLOW_STATE.insert(key, &updated, BPF_ANY);
    } else {
        let state = FlowState {
            last_seen_ns: now,
            first_seen_ns: now,
            packets: 1,
            bytes,
            action,
            traffic_class: class,
            l4_protocol: key.protocol,
            anomaly_flags: 0,
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
        return bucket_admit(&SNG_SYN_BUCKETS, &parsed.key.src, cfg.syn_capacity, cfg.syn_refill_per_sec, now);
    }
    if parsed.key.protocol == PROTO_UDP && cfg.udp_enabled == PRESENT {
        return bucket_admit(&SNG_UDP_BUCKETS, &parsed.key.src, cfg.udp_capacity, cfg.udp_refill_per_sec, now);
    }
    true
}

/// Token-bucket admission for one source. Mirrors the userspace
/// `ddos::TokenBucket` (scaled-integer, no floating point); the clock only
/// advances on a whole-token refill so sub-token time is not lost.
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
        let elapsed = now.saturating_sub(bucket.last_refill_ns);
        let secs = elapsed / 1_000_000_000;
        let rem = elapsed % 1_000_000_000;
        // Split the multiply across whole/fractional seconds to keep the
        // intermediate products inside u64.
        let added = secs
            .saturating_mul(refill_per_sec)
            .saturating_add(rem.saturating_mul(refill_per_sec) / 1_000_000_000);
        if added > 0 {
            bucket.tokens = min_u64(bucket.tokens.saturating_add(added), capacity);
            bucket.last_refill_ns = now;
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

/// Walk the classification array (already longest-prefix-first) and
/// return the first matching tier, or the configured fallback.
fn classify(key: &FlowKey) -> u8 {
    let meta = SNG_CLASS_META.get(0);
    let (count, fallback) = match meta {
        Some(m) => (m.count, m.fallback_class),
        None => return CLASS_BLOCK,
    };
    let mut i: u32 = 0;
    while i < count && i < MAX_CLASS_RULES {
        if let Some(rule) = SNG_CLASS_RULES.get(i) {
            if class_rule_matches(rule, key) {
                return rule.class;
            }
        }
        i += 1;
    }
    fallback
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

/// Walk the firewall array first-match-wins; fall back to the default.
fn firewall_action(key: &FlowKey) -> u8 {
    let meta = SNG_FW_META.get(0);
    let (count, default) = match meta {
        Some(m) => (m.count, m.default_action),
        // No ruleset installed: fail closed, matching the userspace
        // `XdpRuleSet::default`.
        None => return rule_to_action(RULE_DROP),
    };
    let mut i: u32 = 0;
    while i < count && i < MAX_FW_RULES {
        if let Some(rule) = SNG_FW_RULES.get(i) {
            if fw_rule_matches(rule, key) {
                return rule_to_action(rule.action);
            }
        }
        i += 1;
    }
    rule_to_action(default)
}

fn rule_to_action(rule_action: u8) -> u8 {
    if rule_action == RULE_DROP {
        ACTION_DROP
    } else {
        ACTION_PASS
    }
}

fn fw_rule_matches(rule: &WireRule, key: &FlowKey) -> bool {
    let len_bytes = if key.family == FAMILY_V4 { 4 } else { 16 };
    if rule.protocol_present == PRESENT && rule.protocol != key.protocol {
        return false;
    }
    if !cidr_list_matches(&rule.src_cidrs, rule.n_src_cidrs, &key.src, key.family, len_bytes) {
        return false;
    }
    if !cidr_list_matches(&rule.dst_cidrs, rule.n_dst_cidrs, &key.dst, key.family, len_bytes) {
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
    let mut i = 0usize;
    while i < MAX_CIDRS_PER_RULE && i < n as usize {
        let c = &cidrs[i];
        if c.family == family && prefix_match(addr, &c.addr, c.prefix_len, len_bytes) {
            return true;
        }
        i += 1;
    }
    false
}

/// An empty list matches any port; otherwise the port must fall in a range.
fn port_list_matches(ports: &[WirePortRange; MAX_PORTS_PER_RULE], n: u8, port: u16) -> bool {
    if n == 0 {
        return true;
    }
    let mut i = 0usize;
    while i < MAX_PORTS_PER_RULE && i < n as usize {
        let r = &ports[i];
        if port >= r.from && port <= r.to {
            return true;
        }
        i += 1;
    }
    false
}

/// Longest-prefix bitwise compare of `addr` against `net` over
/// `prefix_len` bits, bounded to `len_bytes` (4 for v4, 16 for v6).
fn prefix_match(addr: &[u8; 16], net: &[u8; 16], prefix_len: u8, len_bytes: usize) -> bool {
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    let mut i = 0usize;
    while i < full && i < len_bytes && i < 16 {
        if addr[i] != net[i] {
            return false;
        }
        i += 1;
    }
    if rem > 0 && full < len_bytes && full < 16 {
        let mask = 0xffu8 << (8 - rem);
        if (addr[full] ^ net[full]) & mask != 0 {
            return false;
        }
    }
    true
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
        (EthHdr::LEN + Ipv4Hdr::LEN, proto, u32::from(total))
    } else if ether_type == EtherType::Ipv6 as u16 {
        let ip: *const Ipv6Hdr = ptr_at(data, data_end, EthHdr::LEN)?;
        key.src = unsafe { (*ip).src_addr };
        key.dst = unsafe { (*ip).dst_addr };
        key.family = FAMILY_V6;
        let proto = unsafe { (*ip).next_hdr };
        let payload = u16::from_be_bytes(unsafe { (*ip).payload_len });
        (
            EthHdr::LEN + Ipv6Hdr::LEN,
            proto,
            u32::from(payload) + Ipv6Hdr::LEN as u32,
        )
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

fn copy4(dst: &mut [u8; 16], src: &[u8; 4]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

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
