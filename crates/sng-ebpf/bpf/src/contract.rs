//! Kernel-side mirror of the map contract.
//!
//! Every `#[repr(C)]` type and every map-name / capacity constant here is
//! the byte-for-byte counterpart of the userspace definitions in
//! `crates/sng-ebpf/src/wire.rs` and `crates/sng-ebpf/src/maps.rs`. The
//! userspace loader marshals policy into these layouts and writes them
//! into the maps this object declares; the programs below read them back.
//!
//! The two halves cannot share a crate (this one is `no_std` for a BPF
//! target; `sng-ebpf` is a `std` crate with `aya`, `ipnet`, and
//! `sng-core` dependencies), so the definitions are duplicated by design.
//! The userspace side pins the sizes in `wire::tests::
//! wire_layouts_are_padded_and_aligned`; if you change a layout there,
//! change it here and bump both. Field order, padding, and `#[repr(C)]`
//! must match exactly.

#![allow(dead_code)]

// ---- Map names (must equal `crate::wire::MAP_*` on the userspace side) ----

pub const MAP_FW_RULES: &str = "sng_fw_rules";
pub const MAP_FW_META: &str = "sng_fw_meta";
pub const MAP_CLASS_RULES: &str = "sng_class_rules";
pub const MAP_CLASS_META: &str = "sng_class_meta";
pub const MAP_STEERING: &str = "sng_steering";
pub const MAP_DDOS_CONFIG: &str = "sng_ddos_cfg";
pub const MAP_GEOIP_V4: &str = "sng_geoip_v4";
pub const MAP_GEOIP_V6: &str = "sng_geoip_v6";
pub const MAP_GEO_BLOCK: &str = "sng_geo_block";
pub const MAP_FLOW_STATE: &str = "sng_flow_state";
pub const MAP_CONNTRACK: &str = "sng_conntrack";
pub const MAP_VERDICT_CACHE: &str = "sng_verdict_cache";
/// Kernel-owned per-source SYN token buckets (not written by userspace).
pub const MAP_SYN_BUCKETS: &str = "sng_syn_buckets";
/// Kernel-owned per-source UDP token buckets (not written by userspace).
pub const MAP_UDP_BUCKETS: &str = "sng_udp_buckets";
/// Tail-call jump table for the split XDP pipeline. The userspace loader
/// populates it with the FDs of the `sng_xdp_stage_*` programs after load.
pub const MAP_XDP_PROGS: &str = "sng_xdp_progs";
/// Kernel-owned per-CPU scratch buffer that carries the parsed flow
/// context across the tail-call boundary (not written by userspace).
pub const MAP_XDP_SCRATCH: &str = "sng_xdp_scratch";

// ---- Capacities (mirror `crate::wire::MAX_*`) ----

pub const MAX_FW_RULES: u32 = 1024;
pub const MAX_CLASS_RULES: u32 = 1024;
pub const MAX_CIDRS_PER_RULE: usize = 4;
pub const MAX_PORTS_PER_RULE: usize = 4;
pub const STEERING_SLOTS: u32 = 6;
/// Per-family GeoIP trie capacity and per-source bucket / flow-table
/// capacities. These bound kernel memory; tune with the deployment.
pub const MAX_GEOIP_ENTRIES: u32 = 1 << 16;
pub const MAX_BLOCKED_COUNTRIES: u32 = 512;
/// Capacity of the flow-keyed `LRU_HASH` fast-path tables: per-flow state
/// (`sng_flow_state`) and **the policy verdict cache** (`sng_verdict_cache`)
/// — the two maps declared `with_max_entries(MAX_FLOWS, …)` in `main.rs`.
///
/// This is a single **PoP-wide** ceiling on concurrent flows, shared by
/// every tenant on the edge, **not** a per-tenant allocation — the cache
/// is keyed by the `FlowKey` 5-tuple (no tenant field), so all tenants
/// share one fixed-size LRU and the kernel reclaims the least-recently-used
/// flow under pressure. It MUST remain a compile-time constant that does
/// not reference any tenant count: scaling it per tenant
/// (`PER_TENANT * n_tenants`) would, at ~5000 SME tenants per PoP, blow up
/// locked kernel memory and decay the hit-rate. Mirrors
/// `crate::wire::MAX_FLOWS` on the userspace side; keep the two in lockstep.
pub const MAX_FLOWS: u32 = 1 << 20;
/// Per-source rate-limit `LRU_HASH` capacity — likewise PoP-wide, never
/// per-tenant. Mirrors `crate::wire::MAX_SOURCES`.
pub const MAX_SOURCES: u32 = 1 << 20;

// Lock the PoP-shared capacities at compile time: non-zero (the verifier
// rejects a zero-capacity map) and pinned to the value the userspace
// mirror (`crate::wire::MAX_FLOWS` / `MAX_SOURCES`) also asserts. A future
// edit that zeroes or per-tenant-scales either constant fails the BPF
// build here, in lockstep with the userspace regression test.
const _: () = assert!(MAX_FLOWS == 1 << 20);
const _: () = assert!(MAX_SOURCES == 1 << 20);

// ---- Address family discriminants (mirror `crate::maps::family`) ----

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

// ---- L4 protocol numbers ----

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// ---- IPv6 extension-header "next header" numbers (RFC 8200 §4) ----
//
// These appear in the IPv6 fixed header's `next_hdr` (or a preceding
// extension header's `next_hdr`) in place of the real L4 protocol. The
// fast-path parser walks the skippable ones to reach the true L4 header;
// see `parse_flow` in `main.rs`.
pub const IPPROTO_HOPOPTS: u8 = 0; // Hop-by-Hop Options
pub const IPPROTO_ROUTING: u8 = 43; // Routing
pub const IPPROTO_FRAGMENT: u8 = 44; // Fragment
pub const IPPROTO_ESP: u8 = 50; // Encapsulating Security Payload
pub const IPPROTO_AH: u8 = 51; // Authentication Header
pub const IPPROTO_DSTOPTS: u8 = 60; // Destination Options
pub const IPPROTO_MOBILITY: u8 = 135; // Mobility (RFC 6275)

/// Upper bound on the IPv6 extension-header chain the fast path will walk
/// before failing open. RFC 8200 allows an arbitrarily long chain, but a
/// fixed cap is required for the BPF verifier (bounded loop) and is far
/// beyond any legitimate packet; a longer chain is treated as unparseable
/// and handed to the slow path.
pub const MAX_IPV6_EXT_HDRS: usize = 8;

// ---- Action / flag discriminants ----

/// `XdpRuleAction` discriminants (mirror `crate::firewall`).
pub const RULE_PASS: u8 = 0;
pub const RULE_DROP: u8 = 1;

/// `SteeringAction` discriminants (mirror `crate::tc`).
pub const STEER_PASS: u8 = 0;
pub const STEER_MARK: u8 = 1;
pub const STEER_REDIRECT: u8 = 2;
pub const STEER_DROP: u8 = 3;

/// `XdpAction` discriminants — identical to the kernel `xdp_action`
/// values (mirror `crate::class::XdpAction`).
pub const ACTION_ABORTED: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_PASS: u8 = 2;

/// `TrafficClass` discriminant for `block` — the only tier the data path
/// branches on by value (mirror `crate::wire::class_to_u8`).
pub const CLASS_BLOCK: u8 = 5;

/// Generic present/absent flag value used across the wire layouts.
pub const PRESENT: u8 = 1;

// ---- Wire layouts (mirror `crate::wire` / `crate::maps`) ----

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireCidr {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub family: u8,
    pub pad: [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WirePortRange {
    pub from: u16,
    pub to: u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireRule {
    pub src_cidrs: [WireCidr; MAX_CIDRS_PER_RULE],
    pub dst_cidrs: [WireCidr; MAX_CIDRS_PER_RULE],
    pub src_ports: [WirePortRange; MAX_PORTS_PER_RULE],
    pub dst_ports: [WirePortRange; MAX_PORTS_PER_RULE],
    pub n_src_cidrs: u8,
    pub n_dst_cidrs: u8,
    pub n_src_ports: u8,
    pub n_dst_ports: u8,
    pub protocol: u8,
    pub protocol_present: u8,
    pub action: u8,
    pub pad: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireRuleSetMeta {
    pub count: u32,
    pub default_action: u8,
    pub pad: [u8; 3],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireClassRule {
    pub dst: [u8; 16],
    pub prefix_len: u8,
    pub family: u8,
    pub port_present: u8,
    pub class: u8,
    pub dst_port: u16,
    pub pad: [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireClassMeta {
    pub count: u32,
    pub fallback_class: u8,
    pub pad: [u8; 3],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireSteeringTarget {
    pub action: u8,
    pub pad: [u8; 3],
    pub ifindex: u32,
    pub mark: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireDdosConfig {
    pub syn_capacity: u64,
    pub syn_refill_per_sec: u64,
    pub udp_capacity: u64,
    pub udp_refill_per_sec: u64,
    pub syn_enabled: u8,
    pub udp_enabled: u8,
    pub geoip_enabled: u8,
    pub pad: [u8; 5],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WireCountry {
    pub code: [u8; 2],
    pub pad: [u8; 2],
}

/// Per-flow 5-tuple key (mirror `crate::maps::FlowKey`).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FlowKey {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub family: u8,
    pub pad: [u8; 2],
}

/// Per-flow state (mirror `crate::maps::FlowState`).
///
/// `packets`/`bytes` are `u64` and a trailing `pad` rounds the struct to
/// its 8-byte alignment, so the layout is byte-for-byte the userspace
/// definition (40 bytes). `u32` counters would both shrink the struct to
/// 32 bytes — garbling every field userspace reads past the counters —
/// and saturate at ~4 GB / ~4 G packets on a long-lived flow.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FlowState {
    pub last_seen_ns: u64,
    pub first_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub action: u8,
    pub traffic_class: u8,
    pub l4_protocol: u8,
    pub anomaly_flags: u8,
    pub pad: [u8; 4],
}

/// Cached policy verdict (mirror `crate::maps::VerdictCacheEntry`).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct VerdictCacheEntry {
    pub action: u8,
    pub traffic_class: u8,
    pub pad: [u8; 6],
    pub inserted_ns: u64,
}

/// Per-source token bucket — kernel-owned DDoS counter state. Not part of
/// the userspace contract; lives only in this object.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TokenBucketState {
    pub tokens: u64,
    pub last_refill_ns: u64,
}
