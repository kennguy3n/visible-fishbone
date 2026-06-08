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

/// Per-flow anomaly flags carried in [`FlowState::anomaly_flags`].
///
/// A bitset rather than an enum so a single flow can accumulate more
/// than one anomaly across its lifetime; the kernel side sets a bit with
/// a `|=` on the per-flow map value, which is a single-instruction update
/// in BPF.
pub mod anomaly {
    /// No anomaly observed.
    pub const NONE: u8 = 0;
    /// The flow's L4 protocol changed after the entry was created — a
    /// packet arrived on the same 5-tuple slot carrying a different IANA
    /// protocol number than the one the flow was first seen with. Set by
    /// [`super::FlowState::observe`]; surfaced to the slow path so it can
    /// punt the flow for re-evaluation instead of trusting a cached
    /// verdict that was computed for the original protocol.
    pub const PROTOCOL_CHANGE: u8 = 1 << 0;
}

/// Per-flow state value — the kernel updates this on every packet of an
/// active flow; userspace reads it for telemetry, bandwidth monitoring,
/// long-lived-connection detection, and protocol-anomaly flagging.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FlowState {
    /// Monotonic nanosecond timestamp of the last packet seen on this
    /// flow (kernel `bpf_ktime_get_ns`). Userspace uses it to age flows.
    pub last_seen_ns: u64,
    /// Monotonic nanosecond timestamp of the first packet seen on this
    /// flow (when the entry was created). Combined with `last_seen_ns`
    /// it yields the flow's duration for long-lived-connection
    /// detection.
    pub first_seen_ns: u64,
    /// Packets observed on this flow since the entry was created.
    pub packets: u64,
    /// Bytes observed on this flow since the entry was created — the
    /// per-flow byte counter that backs bandwidth monitoring.
    pub bytes: u64,
    /// Cached [`crate::class::XdpAction`] discriminant applied to this
    /// flow (so a repeat packet does not re-run the rule walk).
    pub action: u8,
    /// Cached [`sng_core::TrafficClass`] discriminant for this flow.
    pub traffic_class: u8,
    /// IANA L4 protocol number this flow was first observed with (6 =
    /// TCP, 17 = UDP, …). Zero until the first [`Self::observe`] sets it.
    pub l4_protocol: u8,
    /// Accumulated [`anomaly`] flags for this flow.
    pub anomaly_flags: u8,
    /// Explicit padding to an 8-byte boundary. Always zero.
    pad: [u8; 4],
}

impl FlowState {
    /// Create the per-flow state for the first packet of a flow seen at
    /// `now_ns` carrying L4 `protocol`, with zeroed counters.
    #[must_use]
    pub fn new(now_ns: u64, protocol: u8) -> Self {
        Self {
            last_seen_ns: now_ns,
            first_seen_ns: now_ns,
            packets: 0,
            bytes: 0,
            action: 0,
            traffic_class: 0,
            l4_protocol: protocol,
            anomaly_flags: anomaly::NONE,
            pad: [0; 4],
        }
    }

    /// Account a packet of `bytes` bytes carrying L4 `protocol`, observed
    /// at `now_ns`.
    ///
    /// Updates the last-seen timestamp and the packet / byte counters,
    /// and — the protocol-anomaly check — sets
    /// [`anomaly::PROTOCOL_CHANGE`] if this packet's protocol differs
    /// from the one the flow was created with.
    ///
    /// A pristine, default-constructed map slot carries no protocol
    /// baseline (`l4_protocol == 0`); its first observation adopts that
    /// packet's protocol and creation time as the flow baseline instead
    /// of flagging a spurious anomaly, so a flow created via [`Default`]
    /// (e.g. a freshly-zeroed kernel map value) folds its first packet's
    /// metadata in cleanly. A slot built with [`Self::new`] always carries
    /// a non-zero protocol, so this branch never rewrites its
    /// `first_seen_ns` — the baseline no longer keys off a zero timestamp
    /// as a sentinel, which previously collided with `new(0, _)`.
    ///
    /// Counters saturate rather than wrap, and `last_seen_ns` never moves
    /// backwards, so a non-monotonic clock reading cannot corrupt the
    /// duration computation.
    pub fn observe(&mut self, now_ns: u64, bytes: u64, protocol: u8) {
        if self.l4_protocol == 0 {
            // Pristine slot: adopt this packet as the flow's baseline.
            self.l4_protocol = protocol;
            if self.packets == 0 {
                self.first_seen_ns = now_ns;
            }
        } else if protocol != 0 && protocol != self.l4_protocol {
            self.anomaly_flags |= anomaly::PROTOCOL_CHANGE;
        }
        self.last_seen_ns = self.last_seen_ns.max(now_ns);
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Flow duration in nanoseconds (`last_seen_ns - first_seen_ns`).
    /// Saturating, so a clock anomaly yields `0` rather than a wrapped
    /// value.
    #[must_use]
    pub const fn duration_ns(&self) -> u64 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns)
    }

    /// True iff the flow has been alive for at least `threshold_ns` —
    /// the long-lived-connection signal.
    #[must_use]
    pub const fn is_long_lived(&self, threshold_ns: u64) -> bool {
        self.duration_ns() >= threshold_ns
    }

    /// Mean throughput in bytes per second over the flow's lifetime, for
    /// bandwidth monitoring. Returns `0` for a zero-duration flow (a
    /// single packet, or sub-nanosecond span) rather than dividing by
    /// zero. Integer math throughout — BPF has no floating point.
    #[must_use]
    pub fn bytes_per_sec(&self) -> u64 {
        let dur = self.duration_ns();
        if dur == 0 {
            return 0;
        }
        let bps = u128::from(self.bytes) * 1_000_000_000 / u128::from(dur);
        u64::try_from(bps).unwrap_or(u64::MAX)
    }

    /// True iff any anomaly flag is set on this flow.
    #[must_use]
    pub const fn has_anomaly(&self) -> bool {
        self.anomaly_flags != anomaly::NONE
    }

    /// True iff the protocol-change anomaly is flagged on this flow.
    #[must_use]
    pub const fn has_protocol_change(&self) -> bool {
        self.anomaly_flags & anomaly::PROTOCOL_CHANGE != 0
    }
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
    fn flow_state_observe_counts_bytes_packets_and_duration() {
        let mut fs = FlowState::new(1_000, 6);
        assert_eq!(fs.packets, 0);
        assert_eq!(fs.l4_protocol, 6);

        fs.observe(2_000, 100, 6);
        fs.observe(3_000, 200, 6);
        assert_eq!(fs.packets, 2);
        assert_eq!(fs.bytes, 300);
        // first_seen at construction, last_seen advanced by the latest packet.
        assert_eq!(fs.first_seen_ns, 1_000);
        assert_eq!(fs.last_seen_ns, 3_000);
        assert_eq!(fs.duration_ns(), 2_000);
        assert!(!fs.has_anomaly());
    }

    #[test]
    fn flow_state_default_adopts_first_observed_protocol() {
        // A default-constructed entry has protocol 0; the first observe
        // records the protocol rather than flagging an anomaly.
        let mut fs = FlowState::default();
        fs.observe(500, 64, 17);
        assert_eq!(fs.l4_protocol, 17);
        assert_eq!(fs.first_seen_ns, 500);
        assert!(!fs.has_anomaly());
    }

    #[test]
    fn flow_state_flags_protocol_change_mid_stream() {
        let mut fs = FlowState::new(0, 6);
        fs.observe(10, 40, 6); // same protocol — fine
        assert!(!fs.has_protocol_change());
        fs.observe(20, 40, 17); // TCP flow suddenly carrying UDP
        assert!(fs.has_anomaly());
        assert!(fs.has_protocol_change());
        // The baseline protocol is retained; the change is recorded via
        // the flag, not by overwriting `l4_protocol`.
        assert_eq!(fs.l4_protocol, 6);
    }

    #[test]
    fn flow_state_new_at_epoch_zero_keeps_creation_time() {
        // Regression: a flow created at timestamp 0 (a degenerate but
        // representable epoch) carries a real protocol, so a later
        // observation must NOT rewrite first_seen_ns. The baseline keys
        // off the zero protocol of a pristine slot, not a zero timestamp,
        // so new(0, _) is unambiguous.
        let mut fs = FlowState::new(0, 6);
        assert_eq!(fs.first_seen_ns, 0);
        fs.observe(1_000, 100, 6);
        fs.observe(2_000, 100, 6);
        // first_seen stays at the creation time (0), not the first observe.
        assert_eq!(fs.first_seen_ns, 0);
        assert_eq!(fs.last_seen_ns, 2_000);
        assert_eq!(fs.duration_ns(), 2_000);
        assert!(!fs.has_anomaly());
    }

    #[test]
    fn flow_state_long_lived_detection_and_bandwidth() {
        // Anchor at a realistic monotonic epoch (bpf_ktime_get_ns is
        // nanoseconds since boot, never zero at runtime).
        let t0 = 1_000_000_000;
        let mut fs = FlowState::new(t0, 6);
        // 10 MB over 2 seconds → 5 MB/s.
        fs.observe(t0 + 2_000_000_000, 10_000_000, 6);
        assert_eq!(fs.duration_ns(), 2_000_000_000);
        assert!(fs.is_long_lived(1_000_000_000));
        assert!(!fs.is_long_lived(3_000_000_000));
        assert_eq!(fs.bytes_per_sec(), 5_000_000);
    }

    #[test]
    fn flow_state_bandwidth_zero_for_single_packet() {
        let mut fs = FlowState::new(42, 6);
        fs.observe(42, 1_500, 6);
        assert_eq!(fs.duration_ns(), 0);
        // Zero-duration flow reports 0 rather than dividing by zero.
        assert_eq!(fs.bytes_per_sec(), 0);
    }

    #[test]
    fn flow_state_last_seen_never_moves_backwards() {
        let mut fs = FlowState::new(1_000, 6);
        fs.observe(5_000, 10, 6);
        // A stale / reordered packet timestamped earlier must not rewind
        // last_seen and corrupt the duration.
        fs.observe(2_000, 10, 6);
        assert_eq!(fs.last_seen_ns, 5_000);
        assert_eq!(fs.duration_ns(), 4_000);
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
