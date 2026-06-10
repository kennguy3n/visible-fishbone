//! Kernel ⇄ userspace map-contract: names, `#[repr(C)]` wire layouts, and
//! the pure marshalling that turns the userspace policy models into the
//! byte buffers the BPF maps hold.
//!
//! The [`crate::loader::AyaLoader`] writes these wire types into the
//! kernel maps; the `no_std` BPF object in `crates/sng-ebpf/bpf/` reads
//! the *same* `#[repr(C)]` definitions on its side. Keeping the layouts,
//! the map names, and the fixed capacities in one module is what lets the
//! two halves agree without a shared crate — change a layout here and the
//! BPF program (which re-declares the identical structs) must change in
//! lock-step.
//!
//! Everything in this module is plain data and pure functions, so it
//! compiles and unit-tests on any target with no eBPF toolchain. The
//! `aya::Pod` impls that let `aya` copy these structs into a map are the
//! only feature-gated part (`xdp`), since `aya` is a Linux-only optional
//! dependency.
//!
//! ## Why fixed-capacity arrays for rules and classification
//!
//! The XDP verifier requires bounded loops, so the firewall ruleset and
//! the classification table are `BPF_MAP_TYPE_ARRAY`s the kernel walks
//! linearly up to a compile-time bound ([`MAX_FW_RULES`] /
//! [`MAX_CLASS_RULES`]). A `*_meta` array of one element carries the live
//! entry count and the fallback/default so the kernel reads only the
//! populated prefix. The GeoIP database, by contrast, is far too large
//! for a linear scan and is keyed by IP prefix, so it uses an
//! `LPM_TRIE` (split per address family, the conventional dual-stack
//! layout) — see [`crate::loader`].
//!
//! ## Fail-safe on overflow
//!
//! A ruleset or classification table larger than the map capacity, or a
//! single rule with more CIDR/port predicates than a [`WireRule`] slot
//! holds, is rejected with [`EbpfError::RuleInvalid`] rather than
//! silently truncated. The data path stays authoritative on nftables for
//! that bundle instead of enforcing a partial policy.

use crate::class::Classifier;
use crate::ddos::{CountryCode, DdosConfig};
use crate::error::EbpfError;
use crate::firewall::{XdpRuleAction, XdpRuleSet};
use crate::maps::family;
use crate::tc::{EgressSteeringTable, SteeringTarget};

use ipnet::IpNet;
use sng_core::TrafficClass;

/// Name of the hot-path firewall rule array (`ARRAY<u32, WireRule>`).
pub const MAP_FW_RULES: &str = "sng_fw_rules";
/// Name of the firewall metadata array (`ARRAY<u32, WireRuleSetMeta>`, 1 entry).
pub const MAP_FW_META: &str = "sng_fw_meta";
/// Name of the classification rule array (`ARRAY<u32, WireClassRule>`).
pub const MAP_CLASS_RULES: &str = "sng_class_rules";
/// Name of the classification metadata array (`ARRAY<u32, WireClassMeta>`, 1 entry).
pub const MAP_CLASS_META: &str = "sng_class_meta";
/// Name of the per-traffic-class egress steering array (`ARRAY<u32, WireSteeringTarget>`, 6 entries).
pub const MAP_STEERING: &str = "sng_steering";
/// Name of the DDoS rate-limit / GeoIP config array (`ARRAY<u32, WireDdosConfig>`, 1 entry).
pub const MAP_DDOS_CONFIG: &str = "sng_ddos_cfg";
/// Name of the IPv4 GeoIP database (`LPM_TRIE<[u8;4], WireCountry>`).
pub const MAP_GEOIP_V4: &str = "sng_geoip_v4";
/// Name of the IPv6 GeoIP database (`LPM_TRIE<[u8;16], WireCountry>`).
pub const MAP_GEOIP_V6: &str = "sng_geoip_v6";
/// Name of the blocked-country set (`HASH<WireCountry, u8>`).
pub const MAP_GEO_BLOCK: &str = "sng_geo_block";
/// Name of the per-flow state map (`LRU_HASH<FlowKey, FlowState>`), owned
/// by the kernel data path and observed by userspace telemetry.
pub const MAP_FLOW_STATE: &str = "sng_flow_state";
/// Name of the XDP conntrack shadow (`LRU_HASH<FlowKey, ConntrackEntry>`).
pub const MAP_CONNTRACK: &str = "sng_conntrack";
/// Name of the policy-verdict cache (`LRU_HASH<FlowKey, VerdictCacheEntry>`).
/// Flushed by the control plane whenever the rules or classification
/// change so a repeat packet is re-evaluated against the new policy.
pub const MAP_VERDICT_CACHE: &str = "sng_verdict_cache";

/// Maximum hot-path firewall rules the XDP array holds.
pub const MAX_FW_RULES: usize = 1024;
/// Maximum classification entries the XDP array holds.
pub const MAX_CLASS_RULES: usize = 1024;
/// Maximum source/destination CIDR predicates a single *wire* [`WireRule`]
/// carries. This is the kernel contract: keeping it at 4 (vs. 8) roughly
/// halves the per-rule verifier jump cost so a firewall chunk program
/// verifies on Linux 5.15 (see `sng-ebpf-bpf` module header). A richer
/// logical rule (up to [`LOGICAL_MAX_CIDRS_PER_RULE`]) is preserved by
/// splitting it across several contiguous wire rules during marshalling.
pub const MAX_CIDRS_PER_RULE: usize = 4;
/// Maximum source/destination port ranges a single *wire* [`WireRule`]
/// carries. See [`MAX_CIDRS_PER_RULE`] for why this is 4, not 8.
pub const MAX_PORTS_PER_RULE: usize = 4;
/// Maximum CIDR predicates per *logical* [`crate::firewall::XdpRule`] and
/// direction that marshalling accepts. A logical rule wider than the wire
/// cap ([`MAX_CIDRS_PER_RULE`]) is split into several wire rules whose
/// union matches identically (the matcher OR-s within a field); this is the
/// user-facing per-direction CIDR capacity.
pub const LOGICAL_MAX_CIDRS_PER_RULE: usize = 8;
/// Maximum port ranges per *logical* [`crate::firewall::XdpRule`] and
/// direction that marshalling accepts. See [`LOGICAL_MAX_CIDRS_PER_RULE`].
pub const LOGICAL_MAX_PORTS_PER_RULE: usize = 8;
/// The six steering tiers — the fixed length of the steering array.
pub const STEERING_SLOTS: usize = 6;

/// Sentinel [`WireRule::protocol_present`] / generic "absent" flag value.
const ABSENT: u8 = 0;
/// Generic "present" flag value.
const PRESENT: u8 = 1;

/// A single CIDR predicate in network-byte-order, family-tagged.
///
/// IPv4 networks occupy the first four bytes of `addr` with the rest
/// zero (matching [`crate::maps::FlowKey`]); IPv6 uses all sixteen.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireCidr {
    /// Network address bytes (network order).
    pub addr: [u8; 16],
    /// Prefix length in bits (`0..=32` for v4, `0..=128` for v6).
    pub prefix_len: u8,
    /// Address family — [`family::V4`] or [`family::V6`].
    pub family: u8,
    /// Explicit padding to a 4-byte boundary. Always zero.
    pad: [u8; 2],
}

/// An inclusive L4 port range. `from == to` is a single port.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WirePortRange {
    /// Lower bound, inclusive.
    pub from: u16,
    /// Upper bound, inclusive.
    pub to: u16,
}

/// One compiled hot-path firewall rule in its fixed-size kernel layout.
///
/// Variable-length predicate lists are flattened into fixed slots with a
/// companion count (`n_*`); the kernel walks `0..n_*`. An empty field
/// (`n_* == 0`) means "any", matching [`crate::firewall::XdpRule`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct WireRule {
    /// Source CIDR predicates; `n_src_cidrs` are live.
    pub src_cidrs: [WireCidr; MAX_CIDRS_PER_RULE],
    /// Destination CIDR predicates; `n_dst_cidrs` are live.
    pub dst_cidrs: [WireCidr; MAX_CIDRS_PER_RULE],
    /// Source port ranges; `n_src_ports` are live.
    pub src_ports: [WirePortRange; MAX_PORTS_PER_RULE],
    /// Destination port ranges; `n_dst_ports` are live.
    pub dst_ports: [WirePortRange; MAX_PORTS_PER_RULE],
    /// Number of live source CIDRs.
    pub n_src_cidrs: u8,
    /// Number of live destination CIDRs.
    pub n_dst_cidrs: u8,
    /// Number of live source port ranges.
    pub n_src_ports: u8,
    /// Number of live destination port ranges.
    pub n_dst_ports: u8,
    /// IANA L4 protocol number, significant only when `protocol_present`.
    pub protocol: u8,
    /// `1` if `protocol` constrains the match, `0` for "any protocol".
    pub protocol_present: u8,
    /// Verdict on match — [`XdpRuleAction`] discriminant (0 pass, 1 drop).
    pub action: u8,
    /// Explicit padding. Always zero.
    pad: u8,
}

impl Default for WireRule {
    fn default() -> Self {
        Self {
            src_cidrs: [WireCidr::default(); MAX_CIDRS_PER_RULE],
            dst_cidrs: [WireCidr::default(); MAX_CIDRS_PER_RULE],
            src_ports: [WirePortRange::default(); MAX_PORTS_PER_RULE],
            dst_ports: [WirePortRange::default(); MAX_PORTS_PER_RULE],
            n_src_cidrs: 0,
            n_dst_cidrs: 0,
            n_src_ports: 0,
            n_dst_ports: 0,
            protocol: 0,
            protocol_present: ABSENT,
            action: XdpRuleAction::Drop as u8,
            pad: 0,
        }
    }
}

/// Metadata for the firewall rule array — the single `*_meta` entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireRuleSetMeta {
    /// Number of live rules in [`MAP_FW_RULES`] (`0..=MAX_FW_RULES`).
    pub count: u32,
    /// Action when no rule matches — [`XdpRuleAction`] discriminant.
    pub default_action: u8,
    /// Explicit padding. Always zero.
    pad: [u8; 3],
}

/// One classification entry: a destination prefix (and optional port)
/// mapped to a traffic-class tier. Ordered longest-prefix-first by the
/// marshaller so the kernel's first match is the most specific.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireClassRule {
    /// Destination network bytes (network order).
    pub dst: [u8; 16],
    /// Destination prefix length in bits.
    pub prefix_len: u8,
    /// Address family — [`family::V4`] or [`family::V6`].
    pub family: u8,
    /// `1` if `dst_port` constrains the match, `0` for "any port".
    pub port_present: u8,
    /// Traffic-class tier — [`class_to_u8`] discriminant (`0..=5`).
    pub class: u8,
    /// Destination port, significant only when `port_present`.
    pub dst_port: u16,
    /// Explicit padding. Always zero.
    pad: [u8; 2],
}

/// Metadata for the classification array — the single `*_meta` entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireClassMeta {
    /// Number of live entries in [`MAP_CLASS_RULES`].
    pub count: u32,
    /// Fallback tier when no entry matches — [`class_to_u8`] discriminant.
    pub fallback_class: u8,
    /// Explicit padding. Always zero.
    pad: [u8; 3],
}

/// A resolved egress target in its kernel layout. Mirrors
/// [`SteeringTarget`] with the action as a raw `u8` (no enum, so any
/// bit pattern read back from the map is well-defined).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireSteeringTarget {
    /// [`crate::tc::SteeringAction`] discriminant (0 pass, 1 mark, 2 redirect, 3 drop).
    pub action: u8,
    /// Explicit padding to align `ifindex`. Always zero.
    pad: [u8; 3],
    /// Egress interface index for a redirect; zero otherwise.
    pub ifindex: u32,
    /// `skb` mark for a mark/redirect; zero otherwise.
    pub mark: u32,
}

/// The DDoS rate-limit budgets plus GeoIP-enable flag — the single
/// [`MAP_DDOS_CONFIG`] entry. The GeoIP database and blocklist live in
/// their own maps; this struct only carries the scalar config.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct WireDdosConfig {
    /// SYN-flood bucket capacity (burst), significant when `syn_enabled`.
    pub syn_capacity: u64,
    /// SYN-flood sustained refill (packets/sec).
    pub syn_refill_per_sec: u64,
    /// UDP-flood bucket capacity (burst), significant when `udp_enabled`.
    pub udp_capacity: u64,
    /// UDP-flood sustained refill (packets/sec).
    pub udp_refill_per_sec: u64,
    /// `1` if SYN-flood mitigation is active.
    pub syn_enabled: u8,
    /// `1` if UDP-flood mitigation is active.
    pub udp_enabled: u8,
    /// `1` if the country blocklist is non-empty (GeoIP enforcement on).
    pub geoip_enabled: u8,
    /// Explicit padding. Always zero.
    pad: [u8; 5],
}

/// A country code in its map layout. The two significant bytes are the
/// ISO-3166-1 alpha-2 code; padding keeps the key 4-byte aligned.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WireCountry {
    /// ISO-3166-1 alpha-2 code (e.g. `*b"US"`).
    pub code: [u8; 2],
    /// Explicit padding. Always zero.
    pad: [u8; 2],
}

impl WireCountry {
    /// Wrap a raw 2-byte country code.
    #[must_use]
    pub const fn new(code: CountryCode) -> Self {
        Self { code, pad: [0; 2] }
    }
}

/// A GeoIP database entry decomposed for an `LPM_TRIE`: the prefix
/// length, the family-appropriate key bytes, and the country value. The
/// `addr_v4` / `addr_v6` split mirrors the two per-family trie maps.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WireGeoEntry {
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Address family — [`family::V4`] or [`family::V6`].
    pub family: u8,
    /// Full 16-byte network address (v4 in the first four bytes).
    pub addr: [u8; 16],
    /// Resolved country.
    pub country: WireCountry,
}

impl WireGeoEntry {
    /// The IPv4 LPM key data (first four address bytes), or `None` for v6.
    #[must_use]
    pub fn key_v4(&self) -> Option<[u8; 4]> {
        (self.family == family::V4).then(|| {
            let mut k = [0u8; 4];
            k.copy_from_slice(&self.addr[..4]);
            k
        })
    }

    /// The IPv6 LPM key data, or `None` for v4.
    #[must_use]
    pub fn key_v6(&self) -> Option<[u8; 16]> {
        (self.family == family::V6).then_some(self.addr)
    }
}

/// The fully-marshalled DDoS configuration ready to write into the maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarshalledDdos {
    /// Scalar config for [`MAP_DDOS_CONFIG`].
    pub config: WireDdosConfig,
    /// GeoIP database entries (both families) for the LPM tries.
    pub geoip: Vec<WireGeoEntry>,
    /// Blocked country codes for [`MAP_GEO_BLOCK`].
    pub blocked: Vec<WireCountry>,
}

/// Stable `u8` discriminant for a [`TrafficClass`] — its index in
/// [`TrafficClass::all`]. Written as an exhaustive match so adding a
/// variant is a compile error here (and in [`crate::tc`]) rather than a
/// silent misencoding on the data path.
#[must_use]
pub const fn class_to_u8(class: TrafficClass) -> u8 {
    match class {
        TrafficClass::TrustedDirect => 0,
        TrafficClass::TrustedMediaBypass => 1,
        TrafficClass::InspectLite => 2,
        TrafficClass::InspectFull => 3,
        TrafficClass::TunnelPrivate => 4,
        TrafficClass::Block => 5,
    }
}

/// Decompose an [`IpNet`] into `(family, prefix_len, 16-byte addr)`.
fn ipnet_parts(net: IpNet) -> (u8, u8, [u8; 16]) {
    match net {
        IpNet::V4(n) => {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&n.network().octets());
            (family::V4, n.prefix_len(), addr)
        }
        IpNet::V6(n) => (family::V6, n.prefix_len(), n.network().octets()),
    }
}

impl WireCidr {
    fn from_net(net: IpNet) -> Self {
        let (family, prefix_len, addr) = ipnet_parts(net);
        Self {
            addr,
            prefix_len,
            family,
            pad: [0; 2],
        }
    }
}

/// Marshal a hot-path ruleset into the kernel array layout plus its
/// metadata entry.
///
/// A logical [`crate::firewall::XdpRule`] may carry up to
/// [`LOGICAL_MAX_CIDRS_PER_RULE`] CIDRs / [`LOGICAL_MAX_PORTS_PER_RULE`]
/// ports per direction, but a *wire* [`WireRule`] holds only
/// [`MAX_CIDRS_PER_RULE`] / [`MAX_PORTS_PER_RULE`] (the kernel verifier
/// contract). A rule wider than the wire cap is split into several
/// contiguous wire rules via [`expand_rule`]; their union matches exactly
/// what the logical rule does, and first-match-wins ordering is preserved
/// because all of a rule's wire rows are emitted together and share its
/// action. The expanded total must still fit [`MAX_FW_RULES`].
///
/// # Errors
///
/// Returns [`EbpfError::RuleInvalid`] if a rule carries more than
/// [`LOGICAL_MAX_CIDRS_PER_RULE`] CIDRs or [`LOGICAL_MAX_PORTS_PER_RULE`]
/// ports per direction, if the expanded wire ruleset exceeds
/// [`MAX_FW_RULES`], or if a member rule fails its own validation.
/// Marshalling validates first, so a returned `Ok` is byte-for-byte
/// installable.
pub fn marshal_rules(set: &XdpRuleSet) -> Result<(Vec<WireRule>, WireRuleSetMeta), EbpfError> {
    set.validate()?;
    let mut out: Vec<WireRule> = Vec::with_capacity(set.len());
    for rule in set.rules() {
        let expanded = expand_rule(rule)?;
        if out.len() + expanded.len() > MAX_FW_RULES {
            return Err(EbpfError::RuleInvalid(format!(
                "hot-path ruleset expands to more than {MAX_FW_RULES} wire rules at \
                 rule {:?}: a rule with many CIDR/port predicates splits into several \
                 wire rules (the kernel holds {MAX_CIDRS_PER_RULE} CIDRs / \
                 {MAX_PORTS_PER_RULE} ports each); reduce predicates or rule count",
                rule.id
            )));
        }
        out.extend(expanded);
    }
    let meta = WireRuleSetMeta {
        count: count_u32(out.len()),
        default_action: set.default_action() as u8,
        pad: [0; 3],
    };
    Ok((out, meta))
}

/// Expand one logical rule into the contiguous run of wire rules whose union
/// matches the same packets.
///
/// The matcher OR-s the values within a predicate field (an empty field is
/// "any") and AND-s across fields. Splitting each field into wire-sized
/// groups and emitting the cross-product of those groups preserves the match
/// set exactly, because AND distributes over OR:
///
/// ```text
/// (a0|a1|a2|a3|a4) & (b0|b1) ==  (a0|a1|a2|a3)&(b0|b1)  |  (a4)&(b0|b1)
/// ```
///
/// Each emitted wire rule carries the original rule's protocol and action, so
/// whichever row fires first yields the verdict the logical rule would. The
/// rows are contiguous, so first-match-wins ordering against *other* rules is
/// unchanged.
fn expand_rule(rule: &crate::firewall::XdpRule) -> Result<Vec<WireRule>, EbpfError> {
    rule.validate()?;
    let src_cidr_groups = chunk_field(
        &rule.src_cidrs,
        MAX_CIDRS_PER_RULE,
        LOGICAL_MAX_CIDRS_PER_RULE,
        &rule.id,
        "source CIDRs",
    )?;
    let dst_cidr_groups = chunk_field(
        &rule.dst_cidrs,
        MAX_CIDRS_PER_RULE,
        LOGICAL_MAX_CIDRS_PER_RULE,
        &rule.id,
        "destination CIDRs",
    )?;
    let src_port_groups = chunk_field(
        &rule.src_ports,
        MAX_PORTS_PER_RULE,
        LOGICAL_MAX_PORTS_PER_RULE,
        &rule.id,
        "source ports",
    )?;
    let dst_port_groups = chunk_field(
        &rule.dst_ports,
        MAX_PORTS_PER_RULE,
        LOGICAL_MAX_PORTS_PER_RULE,
        &rule.id,
        "destination ports",
    )?;

    let protocol = rule.protocol.unwrap_or(0);
    let protocol_present = if rule.protocol.is_some() {
        PRESENT
    } else {
        ABSENT
    };
    let action = rule.action as u8;

    let mut wires = Vec::with_capacity(
        src_cidr_groups.len()
            * dst_cidr_groups.len()
            * src_port_groups.len()
            * dst_port_groups.len(),
    );
    for sc in &src_cidr_groups {
        for dc in &dst_cidr_groups {
            for sp in &src_port_groups {
                for dp in &dst_port_groups {
                    let mut wire = WireRule {
                        n_src_cidrs: group_len(sc),
                        n_dst_cidrs: group_len(dc),
                        n_src_ports: group_len(sp),
                        n_dst_ports: group_len(dp),
                        protocol,
                        protocol_present,
                        action,
                        ..WireRule::default()
                    };
                    for (slot, net) in wire.src_cidrs.iter_mut().zip(sc) {
                        *slot = WireCidr::from_net(*net);
                    }
                    for (slot, net) in wire.dst_cidrs.iter_mut().zip(dc) {
                        *slot = WireCidr::from_net(*net);
                    }
                    for (slot, range) in wire.src_ports.iter_mut().zip(sp) {
                        *slot = WirePortRange {
                            from: range.from,
                            to: range.to,
                        };
                    }
                    for (slot, range) in wire.dst_ports.iter_mut().zip(dp) {
                        *slot = WirePortRange {
                            from: range.from,
                            to: range.to,
                        };
                    }
                    wires.push(wire);
                }
            }
        }
    }
    Ok(wires)
}

/// Split a logical predicate list into wire-sized groups of at most
/// `wire_max` elements each (the [`WireRule`] slot count for this field). An
/// empty list ("any") yields a single empty group — a wildcard wire field —
/// so the cross-product in [`expand_rule`] still emits one row. Rejects a
/// list longer than `logical_max`, the user-facing per-direction capacity.
fn chunk_field<T: Clone>(
    items: &[T],
    wire_max: usize,
    logical_max: usize,
    id: &str,
    what: &str,
) -> Result<Vec<Vec<T>>, EbpfError> {
    if items.len() > logical_max {
        return Err(EbpfError::RuleInvalid(format!(
            "rule {id:?} has {} {what}, exceeding the per-rule capacity of {logical_max}",
            items.len()
        )));
    }
    if items.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    Ok(items.chunks(wire_max).map(<[T]>::to_vec).collect())
}

/// Live-element count of a wire group. A group never exceeds the wire cap
/// (a low single-digit constant), so it always fits a `u8`; saturate rather
/// than panic to keep marshalling total.
fn group_len<T>(group: &[T]) -> u8 {
    u8::try_from(group.len()).unwrap_or(u8::MAX)
}

/// Convert a slice length already bounded by the map capacity (a low
/// four-figure constant) into the `u32` count the metadata entry holds.
/// Saturating rather than panicking keeps marshalling total.
fn count_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// Marshal a classifier into the kernel array layout plus its metadata.
/// Entry order is preserved from [`Classifier::rules`] (longest-prefix
/// first), so the kernel's first match is the most specific.
///
/// # Errors
///
/// Returns [`EbpfError::RuleInvalid`] if the classifier holds more than
/// [`MAX_CLASS_RULES`] entries.
pub fn marshal_classification(
    classifier: &Classifier,
) -> Result<(Vec<WireClassRule>, WireClassMeta), EbpfError> {
    if classifier.len() > MAX_CLASS_RULES {
        return Err(EbpfError::RuleInvalid(format!(
            "classification table has {} entries, exceeding the XDP capacity of {MAX_CLASS_RULES}",
            classifier.len()
        )));
    }
    let out: Vec<WireClassRule> = classifier
        .rules()
        .iter()
        .map(|rule| {
            let (family, prefix_len, dst) = ipnet_parts(rule.dst);
            WireClassRule {
                dst,
                prefix_len,
                family,
                port_present: if rule.dst_port.is_some() {
                    PRESENT
                } else {
                    ABSENT
                },
                class: class_to_u8(rule.class),
                dst_port: rule.dst_port.unwrap_or(0),
                pad: [0; 2],
            }
        })
        .collect();
    let meta = WireClassMeta {
        count: count_u32(out.len()),
        fallback_class: class_to_u8(classifier.fallback()),
        pad: [0; 3],
    };
    Ok((out, meta))
}

/// Marshal the steering table into the fixed six-slot kernel array, in
/// [`TrafficClass::all`] order (the index the TC program keys on).
#[must_use]
pub fn marshal_steering(table: &EgressSteeringTable) -> [WireSteeringTarget; STEERING_SLOTS] {
    let mut out = [WireSteeringTarget::default(); STEERING_SLOTS];
    for (slot, target) in out.iter_mut().zip(table.targets()) {
        *slot = wire_steering_target(*target);
    }
    out
}

fn wire_steering_target(target: SteeringTarget) -> WireSteeringTarget {
    WireSteeringTarget {
        action: target.action as u8,
        pad: [0; 3],
        ifindex: target.ifindex,
        mark: target.mark,
    }
}

/// Marshal a DDoS configuration into its scalar config plus the GeoIP
/// database and blocklist entries.
///
/// # Errors
///
/// Returns [`EbpfError::RuleInvalid`] if the configuration fails its own
/// validation (e.g. a non-empty blocklist with an empty database).
pub fn marshal_ddos(config: &DdosConfig) -> Result<MarshalledDdos, EbpfError> {
    config.validate()?;
    let wire = WireDdosConfig {
        syn_capacity: config.syn.map_or(0, |l| l.capacity),
        syn_refill_per_sec: config.syn.map_or(0, |l| l.refill_per_sec),
        udp_capacity: config.udp.map_or(0, |l| l.capacity),
        udp_refill_per_sec: config.udp.map_or(0, |l| l.refill_per_sec),
        syn_enabled: if config.syn.is_some() {
            PRESENT
        } else {
            ABSENT
        },
        udp_enabled: if config.udp.is_some() {
            PRESENT
        } else {
            ABSENT
        },
        geoip_enabled: if config.blocklist.is_empty() {
            ABSENT
        } else {
            PRESENT
        },
        pad: [0; 5],
    };
    let geoip = config
        .geoip
        .entries()
        .iter()
        .map(|entry| {
            let (family, prefix_len, addr) = ipnet_parts(entry.net);
            WireGeoEntry {
                prefix_len,
                family,
                addr,
                country: WireCountry::new(entry.country),
            }
        })
        .collect();
    let blocked = config.blocklist.codes().map(WireCountry::new).collect();
    Ok(MarshalledDdos {
        config: wire,
        geoip,
        blocked,
    })
}

#[cfg(feature = "xdp")]
mod pod {
    use super::{
        WireCidr, WireClassMeta, WireClassRule, WireCountry, WireDdosConfig, WirePortRange,
        WireRule, WireRuleSetMeta, WireSteeringTarget,
    };
    use crate::maps::{FlowKey, VerdictCacheEntry};

    /// `aya::Pod` is an `unsafe` marker the workspace's
    /// `unsafe_code = "deny"` posture flags; this macro keeps the
    /// `#[allow(unsafe_code)]` opt-in (and the shared safety argument) in
    /// one auditable place rather than scattering it per type.
    ///
    /// SAFETY: every type listed is `#[repr(C)]`, `Copy`, and composed
    /// solely of integers, byte arrays, and other `Pod` fields (including
    /// explicit zeroed padding), so every byte is initialised and any bit
    /// pattern read back from a kernel map is a valid value — exactly the
    /// contract `aya::Pod` requires.
    macro_rules! impl_pod {
        ($($ty:ty),+ $(,)?) => {$(
            #[allow(unsafe_code)]
            unsafe impl aya::Pod for $ty {}
        )+};
    }

    impl_pod!(
        WireCidr,
        WirePortRange,
        WireRule,
        WireRuleSetMeta,
        WireClassRule,
        WireClassMeta,
        WireSteeringTarget,
        WireDdosConfig,
        WireCountry,
        // The per-flow key and cached verdict are read back from the
        // kernel maps when the loader flushes the verdict cache on a
        // policy change, so they too must be `Pod`. Both are `#[repr(C)]`
        // with explicit padding in `crate::maps`.
        FlowKey,
        VerdictCacheEntry,
    );
}

// ===================== IPv6 extension-header walk (host reference) ====
//
// The BPF data path resolves the true L4 header of an IPv6 packet by
// walking the extension-header chain (`resolve_ipv6_l4` in
// `bpf/src/main.rs`). That code is `no_std`/`no_main` and only runs inside
// the kernel, so it cannot be unit-tested on the host. The module below is
// a byte-for-byte mirror of that walk — same constants, same bounded
// iteration count, same fail-open conditions — so its host tests pin the
// wire-level behaviour of the kernel parser. Any change to one must be
// mirrored in the other (the two are intentionally identical). It is
// compiled only under `cfg(test)` since it exists purely as a host oracle.
#[cfg(test)]
mod ipv6_ext_ref {
    /// IPv6 "next header" numbers (RFC 8200 §4) the fast path understands.
    /// Mirror the identically-named constants in `bpf/src/contract.rs`.
    pub(super) const IPPROTO_HOPOPTS: u8 = 0;
    pub(super) const IPPROTO_ROUTING: u8 = 43;
    pub(super) const IPPROTO_FRAGMENT: u8 = 44;
    pub(super) const IPPROTO_ESP: u8 = 50;
    pub(super) const IPPROTO_AH: u8 = 51;
    pub(super) const IPPROTO_DSTOPTS: u8 = 60;
    pub(super) const IPPROTO_MOBILITY: u8 = 135;

    /// Upper bound on the chain length the fast path walks before failing
    /// open. Mirrors `MAX_IPV6_EXT_HDRS` in `bpf/src/contract.rs`.
    pub(super) const MAX_IPV6_EXT_HDRS: usize = 8;

    /// True if `next_hdr` is an IPv6 extension header rather than a real L4
    /// protocol. Mirrors `is_ipv6_ext_hdr` in `bpf/src/main.rs`.
    pub(super) const fn is_ipv6_ext_hdr(next_hdr: u8) -> bool {
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

    /// Host reference for the BPF `resolve_ipv6_l4` walk. Given `ext` (the
    /// packet bytes starting immediately after the 40-byte IPv6 fixed
    /// header) and the fixed header's `next_hdr`, returns `(offset,
    /// l4_protocol)` of the real upper-layer header — where `offset` is
    /// measured from the start of `ext` — or `None` when the chain cannot
    /// be resolved on the fast path:
    ///
    /// * ESP/AH — payload is encrypted/authenticated, ports are unreadable;
    /// * a non-first Fragment — this packet carries no L4 header;
    /// * a chain longer than [`MAX_IPV6_EXT_HDRS`] — pathological / hostile;
    /// * a truncated read — `ext` ends mid extension header.
    ///
    /// The loop is bounded by the same compile-time constant as the kernel
    /// walk, and every slice read is bounds-checked (`get`), so the function
    /// is total. A generic extension header only requires its first two
    /// bytes to be present (matching the kernel's `ptr_at::<Ipv6ExtHdr>`);
    /// the bytes it skips over and the eventual L4 header are bounds-checked
    /// by the caller (in the kernel, the subsequent `ptr_at` for the
    /// TCP/UDP header).
    pub(super) fn ipv6_l4_offset(ext: &[u8], first_proto: u8) -> Option<(usize, u8)> {
        let mut proto = first_proto;
        let mut off = 0usize;
        for _ in 0..MAX_IPV6_EXT_HDRS {
            if !is_ipv6_ext_hdr(proto) {
                return Some((off, proto));
            }
            if proto == IPPROTO_ESP || proto == IPPROTO_AH {
                return None;
            }
            if proto == IPPROTO_FRAGMENT {
                // Fragment header is a fixed 8 bytes; the 13-bit fragment
                // offset is the top bits of the big-endian field at 2..4.
                let fh = ext.get(off..off + 8)?;
                let frag_off = u16::from_be_bytes([fh[2], fh[3]]) >> 3;
                if frag_off != 0 {
                    return None;
                }
                proto = fh[0];
                off = off.checked_add(8)?;
            } else {
                // Generic ext header: total length is (hdr_ext_len + 1) * 8.
                let eh = ext.get(off..off + 2)?;
                let hdr_len = (eh[1] as usize + 1) * 8;
                proto = eh[0];
                off = off.checked_add(hdr_len)?;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ipv6_ext_ref::*;
    use super::*;
    use crate::class::ClassRule;
    use crate::ddos::{GeoIpBlocklist, GeoIpEntry, GeoIpTable, RateLimit};
    use crate::firewall::{PortRange, XdpRule};
    use pretty_assertions::assert_eq;
    use std::mem::size_of;
    use std::net::IpAddr;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn class_discriminants_match_all_ordering() {
        for (idx, class) in TrafficClass::all().into_iter().enumerate() {
            assert_eq!(class_to_u8(class) as usize, idx);
        }
    }

    #[test]
    fn wire_layouts_are_padded_and_aligned() {
        // The kernel re-declares these structs; their size must be stable
        // and free of compiler-inserted padding (every byte accounted for
        // by an explicit field), so a `repr(C)` mismatch is caught here.
        assert_eq!(size_of::<WireCidr>(), 20);
        assert_eq!(size_of::<WirePortRange>(), 4);
        assert_eq!(size_of::<WireRuleSetMeta>(), 8);
        assert_eq!(size_of::<WireClassRule>(), 24);
        assert_eq!(size_of::<WireClassMeta>(), 8);
        assert_eq!(size_of::<WireSteeringTarget>(), 12);
        assert_eq!(size_of::<WireDdosConfig>(), 40);
        assert_eq!(size_of::<WireCountry>(), 4);
        // The largest and most complex wire type; pin it so a stray field
        // or padding change is caught (the kernel re-declares it identically).
        // 4*20 (src_cidrs) + 4*20 (dst_cidrs) + 4*4 (src_ports) + 4*4
        // (dst_ports) + 8 trailing u8 fields = 200 bytes at the 4/4 wire cap.
        assert_eq!(size_of::<WireRule>(), 200);
        // `FlowState` and `VerdictCacheEntry` are read back from the kernel
        // maps verbatim, so their layout is part of the same contract and the
        // kernel mirror (`bpf/src/contract.rs`) must match byte-for-byte.
        assert_eq!(size_of::<crate::maps::FlowState>(), 40);
        assert_eq!(size_of::<crate::maps::VerdictCacheEntry>(), 16);
        assert_eq!(size_of::<crate::maps::FlowKey>(), 40);
    }

    #[test]
    fn marshal_rules_preserves_order_predicates_and_meta() {
        let rule = XdpRule {
            id: "r1".into(),
            src_cidrs: vec![net("10.0.0.0/8")],
            dst_cidrs: vec![net("192.168.1.0/24"), net("2001:db8::/32")],
            src_ports: vec![PortRange::new(1024, 2048).unwrap()],
            dst_ports: vec![PortRange::single(443)],
            protocol: Some(6),
            action: XdpRuleAction::Pass,
        };
        let set = XdpRuleSet::new(vec![rule], XdpRuleAction::Drop);
        let (wire, meta) = marshal_rules(&set).unwrap();

        assert_eq!(meta.count, 1);
        assert_eq!(meta.default_action, XdpRuleAction::Drop as u8);

        let w = wire[0];
        assert_eq!(w.action, XdpRuleAction::Pass as u8);
        assert_eq!(w.protocol_present, PRESENT);
        assert_eq!(w.protocol, 6);
        assert_eq!(w.n_src_cidrs, 1);
        assert_eq!(w.n_dst_cidrs, 2);
        assert_eq!(w.n_src_ports, 1);
        assert_eq!(w.n_dst_ports, 1);

        // IPv4 source CIDR: first four bytes significant, family tagged.
        assert_eq!(w.src_cidrs[0].family, family::V4);
        assert_eq!(w.src_cidrs[0].prefix_len, 8);
        assert_eq!(&w.src_cidrs[0].addr[..4], &[10, 0, 0, 0]);
        // IPv6 destination CIDR carried in the second slot.
        assert_eq!(w.dst_cidrs[1].family, family::V6);
        assert_eq!(w.dst_cidrs[1].prefix_len, 32);
        // Unused slots stay zeroed.
        assert_eq!(w.src_cidrs[1], WireCidr::default());
        assert_eq!(w.src_ports[0].from, 1024);
        assert_eq!(w.src_ports[0].to, 2048);
        assert_eq!(w.dst_ports[0].from, 443);
        assert_eq!(w.dst_ports[0].to, 443);
    }

    #[test]
    fn marshal_rule_without_protocol_clears_flag() {
        let set = XdpRuleSet::new(
            vec![XdpRule::catch_all("default", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        let (wire, _) = marshal_rules(&set).unwrap();
        assert_eq!(wire[0].protocol_present, ABSENT);
        assert_eq!(wire[0].protocol, 0);
        assert_eq!(wire[0].n_src_cidrs, 0);
    }

    #[test]
    fn marshal_rules_rejects_more_than_logical_cidrs() {
        // A list within the logical cap now *splits* rather than erroring; a
        // list beyond it is still rejected. Build LOGICAL_MAX + 1 CIDRs.
        let rule = XdpRule {
            id: "huge".into(),
            src_cidrs: (0..=LOGICAL_MAX_CIDRS_PER_RULE)
                .map(|i| net(&format!("10.{i}.0.0/16")))
                .collect(),
            dst_cidrs: vec![],
            src_ports: vec![],
            dst_ports: vec![],
            protocol: None,
            action: XdpRuleAction::Pass,
        };
        let set = XdpRuleSet::new(vec![rule], XdpRuleAction::Drop);
        let err = marshal_rules(&set).unwrap_err();
        assert!(matches!(err, EbpfError::RuleInvalid(_)), "got {err:?}");
    }

    #[test]
    fn marshal_rules_keeps_wire_cap_within_a_single_wire_rule() {
        // Exactly the wire cap in every field stays one wire rule (no split).
        let rule = XdpRule {
            id: "exact".into(),
            src_cidrs: (0..MAX_CIDRS_PER_RULE)
                .map(|i| net(&format!("10.{i}.0.0/16")))
                .collect(),
            dst_cidrs: (0..MAX_CIDRS_PER_RULE)
                .map(|i| net(&format!("192.168.{i}.0/24")))
                .collect(),
            src_ports: (0..MAX_PORTS_PER_RULE)
                .map(|i| PortRange::single(1000 + i as u16))
                .collect(),
            dst_ports: (0..MAX_PORTS_PER_RULE)
                .map(|i| PortRange::single(2000 + i as u16))
                .collect(),
            protocol: Some(6),
            action: XdpRuleAction::Pass,
        };
        let set = XdpRuleSet::new(vec![rule], XdpRuleAction::Drop);
        let (wire, meta) = marshal_rules(&set).unwrap();
        assert_eq!(wire.len(), 1);
        assert_eq!(meta.count, 1);
        assert_eq!(wire[0].n_src_cidrs as usize, MAX_CIDRS_PER_RULE);
        assert_eq!(wire[0].n_dst_ports as usize, MAX_PORTS_PER_RULE);
    }

    #[test]
    fn marshal_rules_splits_wide_rule_into_contiguous_cross_product() {
        // 5 src CIDRs (-> 2 groups: 4 + 1) x 6 dst ports (-> 2 groups: 4 + 2)
        // = 4 contiguous wire rules, each carrying the rule's action.
        let rule = XdpRule {
            id: "wide".into(),
            src_cidrs: (0..5).map(|i| net(&format!("10.{i}.0.0/16"))).collect(),
            dst_cidrs: vec![],
            src_ports: vec![],
            dst_ports: (0..6).map(|i| PortRange::single(8000 + i)).collect(),
            protocol: Some(6),
            action: XdpRuleAction::Pass,
        };
        let set = XdpRuleSet::new(vec![rule], XdpRuleAction::Drop);
        let (wire, meta) = marshal_rules(&set).unwrap();
        assert_eq!(wire.len(), 4, "ceil(5/4)=2 x ceil(6/4)=2");
        assert_eq!(meta.count, 4);
        for w in &wire {
            assert_eq!(w.action, XdpRuleAction::Pass as u8);
            assert_eq!(w.protocol_present, PRESENT);
            assert_eq!(w.protocol, 6);
            // dst_cidrs is "any" in every row; no group exceeds the wire cap.
            assert_eq!(w.n_dst_cidrs, 0);
            assert!(w.n_src_cidrs as usize <= MAX_CIDRS_PER_RULE);
            assert!(w.n_dst_ports as usize <= MAX_PORTS_PER_RULE);
        }
        // Every src CIDR group is covered across the rows (4 then 1).
        let total_src: usize = [wire[0].n_src_cidrs, wire[2].n_src_cidrs]
            .iter()
            .map(|&n| n as usize)
            .sum();
        assert_eq!(total_src, 5);
    }

    /// Reference matcher over a marshalled `WireRule`, mirroring the kernel:
    /// OR within each populated field, AND across fields, empty field = any.
    fn wire_matches(
        w: &WireRule,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        proto: u8,
    ) -> bool {
        if w.protocol_present == PRESENT && w.protocol != proto {
            return false;
        }
        let cidr_hit = |c: &WireCidr, ip: IpAddr| -> bool {
            let net = if c.family == family::V4 {
                let mut o = [0u8; 4];
                o.copy_from_slice(&c.addr[..4]);
                IpNet::new(IpAddr::from(o), c.prefix_len).unwrap()
            } else {
                IpNet::new(IpAddr::from(c.addr), c.prefix_len).unwrap()
            };
            net.contains(&ip)
        };
        if w.n_src_cidrs > 0
            && !w.src_cidrs[..w.n_src_cidrs as usize]
                .iter()
                .any(|c| cidr_hit(c, src))
        {
            return false;
        }
        if w.n_dst_cidrs > 0
            && !w.dst_cidrs[..w.n_dst_cidrs as usize]
                .iter()
                .any(|c| cidr_hit(c, dst))
        {
            return false;
        }
        if w.n_src_ports > 0
            && !w.src_ports[..w.n_src_ports as usize]
                .iter()
                .any(|p| sport >= p.from && sport <= p.to)
        {
            return false;
        }
        if w.n_dst_ports > 0
            && !w.dst_ports[..w.n_dst_ports as usize]
                .iter()
                .any(|p| dport >= p.from && dport <= p.to)
        {
            return false;
        }
        true
    }

    #[test]
    fn expand_rule_union_matches_logical_rule_exactly() {
        // A maximally wide rule (8 src CIDRs, 8 dst CIDRs, 8 src ports, 8 dst
        // ports) splits into 2*2*2*2 = 16 wire rules. For a battery of probe
        // packets, "the logical rule matches" must equal "some wire row
        // matches" — the equivalence the split relies on.
        let rule = XdpRule {
            id: "max".into(),
            src_cidrs: (0..8).map(|i| net(&format!("10.{i}.0.0/16"))).collect(),
            dst_cidrs: (0..8)
                .map(|i| net(&format!("192.168.{i}.0/24")))
                .collect(),
            src_ports: (0..8).map(|i| PortRange::single(1000 + i)).collect(),
            dst_ports: (0..8).map(|i| PortRange::single(2000 + i)).collect(),
            protocol: Some(6),
            action: XdpRuleAction::Pass,
        };
        let set = XdpRuleSet::new(vec![rule.clone()], XdpRuleAction::Drop);
        let (wire, _) = marshal_rules(&set).unwrap();
        assert_eq!(wire.len(), 16);

        // Probe a grid that straddles in- and out-of-set values on every axis.
        let src_ips = [
            "10.0.5.5", "10.7.9.9", "10.8.1.1", "11.0.0.1", "192.168.0.5",
        ];
        let dst_ips = [
            "192.168.0.9", "192.168.7.9", "192.168.8.9", "10.0.0.9", "8.8.8.8",
        ];
        let ports = [999u16, 1000, 1007, 1008, 2000, 2007, 2008, 4000];
        let protos = [6u8, 17];
        for s in src_ips {
            for d in dst_ips {
                for &sp in &ports {
                    for &dp in &ports {
                        for &pr in &protos {
                            let src: IpAddr = s.parse().unwrap();
                            let dst: IpAddr = d.parse().unwrap();
                            let logical = rule.matches(src, dst, sp, dp, pr);
                            let union = wire.iter().any(|w| wire_matches(w, src, dst, sp, dp, pr));
                            assert_eq!(
                                logical, union,
                                "mismatch for {src} {dst} {sp} {dp} proto {pr}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn marshal_rules_split_preserves_first_match_ordering() {
        // Two overlapping logical rules: a wide PASS that splits, then a DROP
        // catch-all. A packet the first rule matches must resolve via one of
        // the first rule's (contiguous, earlier) rows, not the catch-all.
        let pass = XdpRule {
            id: "pass".into(),
            src_cidrs: (0..5).map(|i| net(&format!("10.{i}.0.0/16"))).collect(),
            dst_cidrs: vec![],
            src_ports: vec![],
            dst_ports: vec![],
            protocol: None,
            action: XdpRuleAction::Pass,
        };
        let drop = XdpRule::catch_all("drop-all", XdpRuleAction::Drop);
        let set = XdpRuleSet::new(vec![pass, drop], XdpRuleAction::Drop);
        let (wire, _) = marshal_rules(&set).unwrap();
        // 2 PASS rows (ceil(5/4)) followed by 1 DROP row.
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[0].action, XdpRuleAction::Pass as u8);
        assert_eq!(wire[1].action, XdpRuleAction::Pass as u8);
        assert_eq!(wire[2].action, XdpRuleAction::Drop as u8);

        // A packet from 10.4.x (only in the PASS rule's second group) hits a
        // PASS row before the DROP catch-all.
        let src: IpAddr = "10.4.0.1".parse().unwrap();
        let dst: IpAddr = "8.8.8.8".parse().unwrap();
        let first = wire
            .iter()
            .find(|w| wire_matches(w, src, dst, 1234, 443, 6))
            .expect("a row matches");
        assert_eq!(first.action, XdpRuleAction::Pass as u8);
    }

    #[test]
    fn marshal_rules_rejects_overflow_after_expansion() {
        // Each rule splits into 16 wire rows; enough of them overflow the
        // 1024 wire-rule budget even though the logical count is far smaller.
        let wide = || XdpRule {
            id: "w".into(),
            src_cidrs: (0..8).map(|i| net(&format!("10.{i}.0.0/16"))).collect(),
            dst_cidrs: (0..8)
                .map(|i| net(&format!("192.168.{i}.0/24")))
                .collect(),
            src_ports: (0..8).map(|i| PortRange::single(1000 + i)).collect(),
            dst_ports: (0..8).map(|i| PortRange::single(2000 + i)).collect(),
            protocol: Some(6),
            action: XdpRuleAction::Pass,
        };
        // 65 rules * 16 rows = 1040 > 1024.
        let rules: Vec<_> = (0..65).map(|_| wide()).collect();
        let set = XdpRuleSet::new(rules, XdpRuleAction::Drop);
        let err = marshal_rules(&set).unwrap_err();
        assert!(matches!(err, EbpfError::RuleInvalid(_)), "got {err:?}");
    }

    #[test]
    fn marshal_rules_rejects_invalid_member() {
        let set = XdpRuleSet::new(
            vec![XdpRule::catch_all("", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        assert!(matches!(
            marshal_rules(&set).unwrap_err(),
            EbpfError::RuleInvalid(_)
        ));
    }

    #[test]
    fn marshal_classification_preserves_longest_prefix_order() {
        let classifier = Classifier::new(vec![
            ClassRule::new(net("10.0.0.0/8"), None, TrafficClass::TrustedDirect),
            ClassRule::new(net("10.1.2.0/24"), Some(443), TrafficClass::Block),
        ]);
        let (wire, meta) = marshal_classification(&classifier).unwrap();
        assert_eq!(meta.count, 2);
        assert_eq!(
            meta.fallback_class,
            class_to_u8(TrafficClass::default_conservative())
        );
        // Longest prefix (/24) must come first.
        assert_eq!(wire[0].prefix_len, 24);
        assert_eq!(wire[0].port_present, PRESENT);
        assert_eq!(wire[0].dst_port, 443);
        assert_eq!(wire[0].class, class_to_u8(TrafficClass::Block));
        assert_eq!(wire[1].prefix_len, 8);
        assert_eq!(wire[1].port_present, ABSENT);
    }

    #[test]
    fn marshal_steering_orders_by_class_index() {
        let mut table = EgressSteeringTable::new();
        table.set(
            TrafficClass::TunnelPrivate,
            SteeringTarget::redirect(7, 0x55),
        );
        let wire = marshal_steering(&table);
        // TunnelPrivate is index 4.
        assert_eq!(wire[4].action, crate::tc::SteeringAction::Redirect as u8);
        assert_eq!(wire[4].ifindex, 7);
        assert_eq!(wire[4].mark, 0x55);
        // Block (index 5) drops by default.
        assert_eq!(wire[5].action, crate::tc::SteeringAction::Drop as u8);
    }

    #[test]
    fn marshal_ddos_splits_config_database_and_blocklist() {
        let config = DdosConfig {
            syn: Some(RateLimit::new(100, 50).unwrap()),
            udp: None,
            geoip: GeoIpTable::new(vec![
                GeoIpEntry::new(net("1.0.0.0/8"), *b"CN"),
                GeoIpEntry::new(net("2001:db8::/32"), *b"RU"),
            ]),
            blocklist: GeoIpBlocklist::new([*b"CN"]),
        };
        let marshalled = marshal_ddos(&config).unwrap();
        assert_eq!(marshalled.config.syn_enabled, PRESENT);
        assert_eq!(marshalled.config.syn_capacity, 100);
        assert_eq!(marshalled.config.syn_refill_per_sec, 50);
        assert_eq!(marshalled.config.udp_enabled, ABSENT);
        assert_eq!(marshalled.config.geoip_enabled, PRESENT);
        assert_eq!(marshalled.geoip.len(), 2);
        assert_eq!(marshalled.blocked, vec![WireCountry::new(*b"CN")]);

        let v4 = marshalled
            .geoip
            .iter()
            .find(|e| e.family == family::V4)
            .unwrap();
        assert_eq!(v4.key_v4(), Some([1, 0, 0, 0]));
        assert_eq!(v4.key_v6(), None);
        let v6 = marshalled
            .geoip
            .iter()
            .find(|e| e.family == family::V6)
            .unwrap();
        assert_eq!(v6.key_v6().unwrap()[..4], [0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(v6.key_v4(), None);
    }

    #[test]
    fn marshal_ddos_rejects_blocklist_without_database() {
        let config = DdosConfig {
            blocklist: GeoIpBlocklist::new([*b"CN"]),
            ..DdosConfig::default()
        };
        assert!(matches!(
            marshal_ddos(&config).unwrap_err(),
            EbpfError::RuleInvalid(_)
        ));
    }

    // ---- IPv6 extension-header walk (mirrors bpf `resolve_ipv6_l4`) ----

    const PROTO_TCP: u8 = 6;
    const PROTO_UDP: u8 = 17;

    /// One 8-byte generic extension header `[next_hdr, hdr_ext_len=0, 0;6]`.
    fn ext8(next_hdr: u8) -> [u8; 8] {
        [next_hdr, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn ipv6_walk_no_ext_headers_returns_l4_at_zero() {
        // `next_hdr` already the real L4: offset 0, protocol unchanged.
        assert_eq!(ipv6_l4_offset(&[], PROTO_TCP), Some((0, PROTO_TCP)));
        assert_eq!(ipv6_l4_offset(&[], PROTO_UDP), Some((0, PROTO_UDP)));
    }

    #[test]
    fn ipv6_walk_single_hop_by_hop_to_tcp() {
        // Hop-by-Hop (8 bytes) chaining to TCP → L4 at offset 8.
        let ext = ext8(PROTO_TCP);
        assert_eq!(
            ipv6_l4_offset(&ext, IPPROTO_HOPOPTS),
            Some((8, PROTO_TCP))
        );
    }

    #[test]
    fn ipv6_walk_chained_hopopts_routing_to_udp() {
        // Hop-by-Hop → Routing → UDP: two 8-byte headers, L4 at offset 16.
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext8(IPPROTO_ROUTING));
        ext.extend_from_slice(&ext8(PROTO_UDP));
        assert_eq!(
            ipv6_l4_offset(&ext, IPPROTO_HOPOPTS),
            Some((16, PROTO_UDP))
        );
    }

    #[test]
    fn ipv6_walk_variable_length_dstopts() {
        // Destination-Options with hdr_ext_len=1 → (1+1)*8 = 16 bytes.
        let mut ext = vec![PROTO_TCP, 1, 0, 0, 0, 0, 0, 0];
        ext.extend_from_slice(&[0u8; 8]); // remainder of the 16-byte header
        assert_eq!(
            ipv6_l4_offset(&ext, IPPROTO_DSTOPTS),
            Some((16, PROTO_TCP))
        );
    }

    #[test]
    fn ipv6_walk_first_fragment_resolves_l4() {
        // Fragment header, fragment offset 0 (first fragment) → TCP at 8.
        let frag = [PROTO_TCP, 0, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            ipv6_l4_offset(&frag, IPPROTO_FRAGMENT),
            Some((8, PROTO_TCP))
        );
    }

    #[test]
    fn ipv6_walk_non_first_fragment_fails_open() {
        // Fragment offset non-zero (top 13 bits): no L4 in this packet.
        // 0x0008 big-endian → frag_off field; >> 3 = 1 (non-first).
        let frag = [PROTO_TCP, 0, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(ipv6_l4_offset(&frag, IPPROTO_FRAGMENT), None);
    }

    #[test]
    fn ipv6_walk_esp_and_ah_fail_open() {
        // Encrypted / authenticated payloads have no readable L4.
        assert_eq!(ipv6_l4_offset(&ext8(PROTO_TCP), IPPROTO_ESP), None);
        assert_eq!(ipv6_l4_offset(&ext8(PROTO_TCP), IPPROTO_AH), None);
    }

    #[test]
    fn ipv6_walk_truncated_header_fails_open() {
        // `next_hdr` says Hop-by-Hop but only one byte is present.
        assert_eq!(ipv6_l4_offset(&[IPPROTO_HOPOPTS], IPPROTO_HOPOPTS), None);
        // Fragment claimed but fewer than 8 bytes present.
        assert_eq!(
            ipv6_l4_offset(&[PROTO_TCP, 0, 0, 0], IPPROTO_FRAGMENT),
            None
        );
    }

    #[test]
    fn ipv6_walk_overlong_chain_fails_open() {
        // MAX_IPV6_EXT_HDRS Dest-Options headers each chaining to another
        // Dest-Options: the bounded walk exhausts its iterations while still
        // on an extension header (the trailing TCP header is never reached),
        // so it fails open.
        let mut ext = Vec::new();
        for _ in 0..MAX_IPV6_EXT_HDRS {
            ext.extend_from_slice(&ext8(IPPROTO_DSTOPTS));
        }
        ext.extend_from_slice(&ext8(PROTO_TCP));
        assert_eq!(ipv6_l4_offset(&ext, IPPROTO_DSTOPTS), None);
    }

    #[test]
    fn ipv6_walk_max_length_chain_resolves() {
        // The longest chain that still resolves: MAX_IPV6_EXT_HDRS-1 leading
        // Dest-Options headers, the last of which chains to TCP. L4 is then
        // detected at the top of the final (8th) bounded iteration.
        let mut ext = Vec::new();
        for _ in 0..(MAX_IPV6_EXT_HDRS - 2) {
            ext.extend_from_slice(&ext8(IPPROTO_DSTOPTS));
        }
        ext.extend_from_slice(&ext8(PROTO_TCP));
        let expected_off = (MAX_IPV6_EXT_HDRS - 1) * 8;
        assert_eq!(
            ipv6_l4_offset(&ext, IPPROTO_DSTOPTS),
            Some((expected_off, PROTO_TCP))
        );
    }
}
