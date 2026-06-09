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
/// Maximum source/destination CIDR predicates a single [`WireRule`] carries.
pub const MAX_CIDRS_PER_RULE: usize = 8;
/// Maximum source/destination port ranges a single [`WireRule`] carries.
pub const MAX_PORTS_PER_RULE: usize = 8;
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
/// # Errors
///
/// Returns [`EbpfError::RuleInvalid`] if the set is larger than
/// [`MAX_FW_RULES`], if any rule carries more than [`MAX_CIDRS_PER_RULE`]
/// CIDRs or [`MAX_PORTS_PER_RULE`] port ranges per direction, or if a
/// member rule fails its own validation. Marshalling validates first, so
/// a returned `Ok` is byte-for-byte installable.
pub fn marshal_rules(set: &XdpRuleSet) -> Result<(Vec<WireRule>, WireRuleSetMeta), EbpfError> {
    set.validate()?;
    if set.len() > MAX_FW_RULES {
        return Err(EbpfError::RuleInvalid(format!(
            "hot-path ruleset has {} rules, exceeding the XDP capacity of {MAX_FW_RULES}",
            set.len()
        )));
    }
    let mut out = Vec::with_capacity(set.len());
    for rule in set.rules() {
        out.push(marshal_rule(rule)?);
    }
    let meta = WireRuleSetMeta {
        count: count_u32(out.len()),
        default_action: set.default_action() as u8,
        pad: [0; 3],
    };
    Ok((out, meta))
}

fn marshal_rule(rule: &crate::firewall::XdpRule) -> Result<WireRule, EbpfError> {
    let n_src_cidrs = checked_len(
        rule.src_cidrs.len(),
        MAX_CIDRS_PER_RULE,
        &rule.id,
        "source CIDRs",
    )?;
    let n_dst_cidrs = checked_len(
        rule.dst_cidrs.len(),
        MAX_CIDRS_PER_RULE,
        &rule.id,
        "destination CIDRs",
    )?;
    let n_src_ports = checked_len(
        rule.src_ports.len(),
        MAX_PORTS_PER_RULE,
        &rule.id,
        "source ports",
    )?;
    let n_dst_ports = checked_len(
        rule.dst_ports.len(),
        MAX_PORTS_PER_RULE,
        &rule.id,
        "destination ports",
    )?;

    let mut wire = WireRule {
        n_src_cidrs,
        n_dst_cidrs,
        n_src_ports,
        n_dst_ports,
        protocol: rule.protocol.unwrap_or(0),
        protocol_present: if rule.protocol.is_some() {
            PRESENT
        } else {
            ABSENT
        },
        action: rule.action as u8,
        ..WireRule::default()
    };
    for (slot, net) in wire.src_cidrs.iter_mut().zip(&rule.src_cidrs) {
        *slot = WireCidr::from_net(*net);
    }
    for (slot, net) in wire.dst_cidrs.iter_mut().zip(&rule.dst_cidrs) {
        *slot = WireCidr::from_net(*net);
    }
    for (slot, range) in wire.src_ports.iter_mut().zip(&rule.src_ports) {
        *slot = WirePortRange {
            from: range.from,
            to: range.to,
        };
    }
    for (slot, range) in wire.dst_ports.iter_mut().zip(&rule.dst_ports) {
        *slot = WirePortRange {
            from: range.from,
            to: range.to,
        };
    }
    Ok(wire)
}

fn checked_len(len: usize, max: usize, id: &str, what: &str) -> Result<u8, EbpfError> {
    if len > max {
        return Err(EbpfError::RuleInvalid(format!(
            "rule {id:?} has {len} {what}, exceeding the XDP per-rule capacity of {max}"
        )));
    }
    // `max` is a per-rule capacity constant well under `u8::MAX`, so the
    // bound check above guarantees this conversion; saturate rather than
    // panic to keep the data path total even if a future `max` grows.
    Ok(u8::try_from(len).unwrap_or(u8::MAX))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::ClassRule;
    use crate::ddos::{GeoIpBlocklist, GeoIpEntry, GeoIpTable, RateLimit};
    use crate::firewall::{PortRange, XdpRule};
    use pretty_assertions::assert_eq;
    use std::mem::size_of;

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
        assert_eq!(size_of::<WireRule>(), 392);
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
    fn marshal_rules_rejects_too_many_cidrs() {
        let rule = XdpRule {
            id: "huge".into(),
            src_cidrs: (0..=MAX_CIDRS_PER_RULE)
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
}
