//! eBPF map key / value layouts and the userspace verdict cache.
//!
//! XDP fast-path state lives in BPF maps keyed by a fixed-size flow
//! tuple. The kernel side and the userspace control plane must agree on
//! the byte layout of every key and value, so the shared types here are
//! `#[repr(C)]` with explicit padding — the same struct definition is
//! what a `no_std` BPF program would `#[repr(C)]` on its side.
//!
//! Three maps back the fast path:
//!
//! * **per-flow state** ([`FlowState`]) — last-seen timestamp + counters
//!   for an active flow, keyed by [`FlowKey`].
//! * **connection tracking** ([`ConntrackEntry`]) — the XDP-side
//!   conntrack shadow used to fast-accept established flows without
//!   re-walking the rule list.
//! * **policy verdict cache** ([`VerdictCacheEntry`]) — the cached
//!   classification + firewall verdict for a flow so a repeat packet
//!   skips classification entirely.
//!
//! [`PolicyVerdictCache`] is the userspace model of that third map: a
//! TTL-evicting table the control plane uses directly when running
//! without a kernel loader, and which mirrors what the kernel `LRU_HASH`
//! holds when one is attached.

use std::collections::HashMap;
use std::net::IpAddr;

/// Address family discriminant stored alongside the 16-byte address so a
/// v4 flow and its v6-mapped form are never conflated.
pub mod family {
    /// IPv4 — the low 4 bytes of [`super::FlowKey::addr`] arrays hold the
    /// octets, the remaining 12 are zero.
    pub const V4: u8 = 4;
    /// IPv6 — all 16 bytes are significant.
    pub const V6: u8 = 6;
}

/// Fixed-size flow identifier — the key for every XDP fast-path map.
///
/// Addresses are stored as 16 raw bytes (network order) with a `family`
/// discriminant so the same key type covers IPv4 and IPv6 without a
/// non-`repr(C)` enum. The trailing padding is always zero so the
/// derived `Hash` / `Eq` are stable across the userspace ⇄ kernel
/// boundary.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FlowKey {
    /// Source address bytes (network order). For IPv4 only the first 4
    /// bytes are significant.
    pub src: [u8; 16],
    /// Destination address bytes (network order).
    pub dst: [u8; 16],
    /// Source port (host order). Zero for L3-only protocols.
    pub src_port: u16,
    /// Destination port (host order).
    pub dst_port: u16,
    /// IANA L4 protocol number (6 = TCP, 17 = UDP, …).
    pub protocol: u8,
    /// Address family — [`family::V4`] or [`family::V6`].
    pub family: u8,
    /// Explicit padding to a 4-byte boundary. Always zero.
    pad: [u8; 2],
}

impl FlowKey {
    /// Build a key from a resolved 5-tuple.
    #[must_use]
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        let (src, src_fam) = addr_bytes(src_ip);
        let (dst, dst_fam) = addr_bytes(dst_ip);
        // A single `family` discriminant covers both endpoints, so the key
        // is only well-formed for a same-family flow. Mixed-family 5-tuples
        // are unroutable — no IP stack (and so no kernel XDP hook) produces
        // one — and folding them into one key would mislabel the dst bytes.
        // Assert the invariant in debug builds; release keeps the source
        // family (matching the kernel side, which only sees same-family
        // flows) rather than panicking on the data path.
        debug_assert_eq!(
            src_fam, dst_fam,
            "FlowKey requires src and dst to share an address family"
        );
        Self {
            src,
            dst,
            src_port,
            dst_port,
            protocol,
            family: src_fam,
            pad: [0; 2],
        }
    }
}

/// Normalise an [`IpAddr`] to the fixed 16-byte representation plus its
/// family discriminant.
fn addr_bytes(ip: IpAddr) -> ([u8; 16], u8) {
    match ip {
        IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&v4.octets());
            (out, family::V4)
        }
        IpAddr::V6(v6) => (v6.octets(), family::V6),
    }
}

/// Per-flow state value — the kernel updates this on every packet of an
/// active flow; userspace reads it for telemetry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FlowState {
    /// Monotonic nanosecond timestamp of the last packet seen on this
    /// flow (kernel `bpf_ktime_get_ns`). Userspace uses it to age flows.
    pub last_seen_ns: u64,
    /// Packets observed on this flow since the entry was created.
    pub packets: u64,
    /// Bytes observed on this flow since the entry was created.
    pub bytes: u64,
    /// Cached [`crate::class::XdpAction`] discriminant applied to this
    /// flow (so a repeat packet does not re-run the rule walk).
    pub action: u8,
    /// Cached [`sng_core::TrafficClass`] discriminant for this flow.
    pub traffic_class: u8,
    /// Explicit padding. Always zero.
    pad: [u8; 6],
}

/// XDP-side connection-tracking state. Deliberately coarser than the
/// userspace [`sng_fw::conntrack`] model: the fast path only needs to
/// know whether a flow is already established (fast-accept) or still
/// being evaluated.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ConntrackState {
    /// First packet of a flow the fast path has not yet classified.
    #[default]
    New = 0,
    /// Bidirectional traffic observed — the flow is established and the
    /// fast path may accept subsequent packets without a full walk.
    Established = 1,
    /// A flow related to an established one (e.g. an expected data
    /// channel). Treated like [`Self::Established`] for fast-accept.
    Related = 2,
    /// The flow violated an invariant (e.g. out-of-window) and must be
    /// punted to the slow path for re-evaluation.
    Invalid = 3,
}

/// A connection-tracking map entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ConntrackEntry {
    /// Conntrack state discriminant.
    pub state: u8,
    /// Explicit padding.
    pad: [u8; 7],
    /// Monotonic nanosecond expiry — the kernel side evicts the entry
    /// once `bpf_ktime_get_ns()` passes this value.
    pub expires_ns: u64,
}

impl ConntrackEntry {
    /// Build an entry in the given state expiring at `expires_ns`.
    #[must_use]
    pub fn new(state: ConntrackState, expires_ns: u64) -> Self {
        Self {
            state: state as u8,
            pad: [0; 7],
            expires_ns,
        }
    }

    /// True iff a packet observed at `now_ns` may be fast-accepted on
    /// this entry (established or related, and not yet expired).
    #[must_use]
    pub const fn fast_acceptable(&self, now_ns: u64) -> bool {
        if now_ns >= self.expires_ns {
            return false;
        }
        self.state == ConntrackState::Established as u8
            || self.state == ConntrackState::Related as u8
    }
}

/// A policy-verdict-cache entry — the cached firewall + classification
/// decision for a flow.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct VerdictCacheEntry {
    /// Cached [`crate::class::XdpAction`] discriminant.
    pub action: u8,
    /// Cached [`sng_core::TrafficClass`] discriminant.
    pub traffic_class: u8,
    /// Explicit padding.
    pad: [u8; 6],
    /// Monotonic nanosecond insertion time. Combined with the cache's
    /// configured TTL to decide eviction.
    pub inserted_ns: u64,
}

impl VerdictCacheEntry {
    /// New entry inserted at `inserted_ns`.
    #[must_use]
    pub fn new(action: u8, traffic_class: u8, inserted_ns: u64) -> Self {
        Self {
            action,
            traffic_class,
            pad: [0; 6],
            inserted_ns,
        }
    }
}

/// Userspace model of the policy-verdict-cache BPF map: a TTL-evicting
/// `FlowKey -> VerdictCacheEntry` table.
///
/// When the control plane runs without a kernel loader this *is* the
/// verdict cache; when a loader is attached it mirrors the kernel
/// `LRU_HASH` so userspace telemetry and tests see the same eviction
/// behaviour. Eviction is lazy (checked on read) plus an explicit
/// [`Self::evict_expired`] sweep, matching how a kernel `LRU_HASH`
/// reclaims on insert pressure.
#[derive(Debug)]
pub struct PolicyVerdictCache {
    entries: HashMap<FlowKey, VerdictCacheEntry>,
    ttl_ns: u64,
    capacity: usize,
}

impl PolicyVerdictCache {
    /// New cache holding at most `capacity` entries, each valid for
    /// `ttl_ns` nanoseconds after insertion.
    #[must_use]
    pub fn new(capacity: usize, ttl_ns: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_ns,
            capacity,
        }
    }

    /// Number of live (not-yet-swept) entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace the verdict for `key`. Returns `false` without
    /// inserting if the cache is at capacity and `key` is not already
    /// present (mirrors a kernel `LRU_HASH` that would evict the
    /// least-recently-used entry — userspace callers re-derive the
    /// verdict on the next packet rather than guess an LRU victim).
    pub fn insert(&mut self, key: FlowKey, entry: VerdictCacheEntry) -> bool {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key, entry);
        true
    }

    /// Look up the cached verdict for `key`, treating an entry older than
    /// the TTL (relative to `now_ns`) as a miss and removing it.
    pub fn get(&mut self, key: &FlowKey, now_ns: u64) -> Option<VerdictCacheEntry> {
        let expired = self
            .entries
            .get(key)
            .is_some_and(|e| now_ns.saturating_sub(e.inserted_ns) >= self.ttl_ns);
        if expired {
            self.entries.remove(key);
            return None;
        }
        self.entries.get(key).copied()
    }

    /// Sweep every entry whose TTL has elapsed as of `now_ns`. Returns
    /// the number evicted.
    pub fn evict_expired(&mut self, now_ns: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now_ns.saturating_sub(e.inserted_ns) < self.ttl_ns);
        before - self.entries.len()
    }

    /// Drop every entry. Used on a ruleset hot-swap, where every cached
    /// verdict is stale against the new rules.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn flow_key_v4_maps_into_low_four_bytes_with_family() {
        let k = FlowKey::new(v4(10, 0, 0, 1), v4(8, 8, 8, 8), 1234, 53, 17);
        assert_eq!(k.family, family::V4);
        assert_eq!(&k.src[..4], &[10, 0, 0, 1]);
        assert_eq!(&k.src[4..], &[0u8; 12]);
        assert_eq!(&k.dst[..4], &[8, 8, 8, 8]);
        assert_eq!(k.protocol, 17);
        assert_eq!(k.pad, [0, 0]);
    }

    #[test]
    fn flow_key_v6_keeps_all_sixteen_bytes() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let k = FlowKey::new(ip, ip, 443, 443, 6);
        assert_eq!(k.family, family::V6);
        assert_eq!(k.src, ip_octets(ip));
    }

    fn ip_octets(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(_) => unreachable!(),
        }
    }

    #[test]
    fn v4_and_v6_mapped_keys_are_distinct() {
        let v4_key = FlowKey::new(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 1, 2, 6);
        let mapped = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        let v6_key = FlowKey::new(mapped, mapped, 1, 2, 6);
        assert_ne!(v4_key, v6_key);
    }

    #[test]
    fn conntrack_fast_accept_requires_established_and_unexpired() {
        let est = ConntrackEntry::new(ConntrackState::Established, 100);
        assert!(est.fast_acceptable(50));
        assert!(!est.fast_acceptable(100));
        assert!(!est.fast_acceptable(150));

        let new = ConntrackEntry::new(ConntrackState::New, 100);
        assert!(!new.fast_acceptable(50));

        let invalid = ConntrackEntry::new(ConntrackState::Invalid, 100);
        assert!(!invalid.fast_acceptable(50));
    }

    #[test]
    fn verdict_cache_hit_then_ttl_miss() {
        let mut cache = PolicyVerdictCache::new(8, 1000);
        let key = FlowKey::new(v4(10, 0, 0, 1), v4(1, 1, 1, 1), 5000, 443, 6);
        assert!(cache.insert(key, VerdictCacheEntry::new(2, 0, 100)));
        // Within TTL → hit.
        assert!(cache.get(&key, 500).is_some());
        // Past TTL → miss, and the entry is removed.
        assert!(cache.get(&key, 1100).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn verdict_cache_respects_capacity() {
        let mut cache = PolicyVerdictCache::new(1, 1000);
        let k1 = FlowKey::new(v4(10, 0, 0, 1), v4(1, 1, 1, 1), 1, 443, 6);
        let k2 = FlowKey::new(v4(10, 0, 0, 2), v4(1, 1, 1, 1), 2, 443, 6);
        assert!(cache.insert(k1, VerdictCacheEntry::new(2, 0, 0)));
        // At capacity and k2 is new → refused.
        assert!(!cache.insert(k2, VerdictCacheEntry::new(1, 5, 0)));
        // Replacing an existing key is always allowed.
        assert!(cache.insert(k1, VerdictCacheEntry::new(1, 5, 0)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evict_expired_sweeps_only_stale_entries() {
        let mut cache = PolicyVerdictCache::new(8, 1000);
        let fresh = FlowKey::new(v4(10, 0, 0, 1), v4(1, 1, 1, 1), 1, 443, 6);
        let stale = FlowKey::new(v4(10, 0, 0, 2), v4(1, 1, 1, 1), 2, 443, 6);
        cache.insert(fresh, VerdictCacheEntry::new(2, 0, 900));
        cache.insert(stale, VerdictCacheEntry::new(2, 0, 100));
        let evicted = cache.evict_expired(1200);
        assert_eq!(evicted, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&fresh, 1200).is_some());
    }
}
