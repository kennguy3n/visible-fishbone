//! XDP-level DDoS mitigation: SYN-flood and UDP-flood rate limiting and
//! GeoIP country blocking.
//!
//! These are the cheapest enforcement decisions the gateway makes — they
//! run in the XDP ingress program at the earliest kernel hook, before a
//! packet is ever turned into an `sk_buff` or walked by the firewall
//! rule set, so a volumetric flood is dropped at line rate without
//! spending stack, conntrack, or rule-evaluation budget on it.
//!
//! Three mitigations compose into one [`DdosMitigator::evaluate`] verdict:
//!
//! * **SYN-flood** — a per-source-IP token-bucket rate limiter over TCP
//!   SYN packets (the initial SYN, not SYN-ACK). A source that opens
//!   connections faster than its sustained budget is dropped once its
//!   burst allowance is spent.
//! * **UDP-flood** — the same token-bucket limiter applied to UDP
//!   datagrams per source IP, with its own (typically higher) budget.
//! * **GeoIP blocking** — a longest-prefix IP→country table (the GeoIP
//!   database loaded into a BPF LPM map) plus a per-tenant set of blocked
//!   ISO-3166-1 alpha-2 country codes. A packet from a blocked country is
//!   dropped before the rate limiters even run.
//!
//! # No floating point
//!
//! Everything here is integer math. The kernel-side BPF program cannot
//! use floating point, so the token bucket refills with scaled-integer
//! nanosecond arithmetic ([`TokenBucket::refill`]) rather than the
//! `f64` accounting the userspace `sng_swg` rate limiter uses. The
//! refill is *remainder-preserving*: it advances the bucket clock only by
//! the time it actually converted into whole tokens, so a limiter polled
//! far faster than its refill rate never starves (the classic
//! integer-rate-limiter bug where every poll floors the sub-token refill
//! to zero and advances the clock anyway).
//!
//! # Userspace model ⇄ kernel maps
//!
//! Like [`crate::maps::PolicyVerdictCache`], the per-source-IP limiter
//! tables here are the userspace model of kernel `LRU_HASH` maps: when no
//! kernel loader is attached this *is* the limiter, and when one is
//! attached it mirrors the per-CPU map state. The map mutates on every
//! packet, so the hot-path methods take `&mut self` (a kernel per-CPU map
//! is lock-free per CPU); a shared control-plane handle wraps the
//! mitigator behind its own lock.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::class::XdpAction;
use crate::error::EbpfError;

/// IANA L4 protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IANA L4 protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

/// TCP control-flag bit masks (the relevant subset).
pub mod tcp_flags {
    /// SYN — connection-open request.
    pub const SYN: u8 = 0x02;
    /// ACK — acknowledgement.
    pub const ACK: u8 = 0x10;
}

/// One nanosecond per second — the fixed-point scale the integer token
/// bucket refills against (`bpf_ktime_get_ns` is nanosecond-resolution).
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// A 16-byte (4-octet IPv4 + zero fill, or full IPv6) network-order
/// source-address key for the per-source-IP limiter maps. ISO-3166-1
/// alpha-2 country codes use a separate 2-byte representation.
pub type CountryCode = [u8; 2];

/// Sustained-rate + burst budget for one token-bucket limiter.
///
/// `capacity` is the maximum burst (tokens the bucket can hold at once);
/// `refill_per_sec` is the sustained packets-per-second the source is
/// allowed once the burst is spent. A `refill_per_sec` of zero is a hard
/// cap of `capacity` packets with no replenishment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RateLimit {
    /// Maximum burst — the bucket's token capacity.
    pub capacity: u64,
    /// Sustained refill rate in tokens (packets) per second.
    pub refill_per_sec: u64,
}

impl RateLimit {
    /// New limit with an explicit burst capacity and sustained rate.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::RuleInvalid`] if `capacity` is zero — a
    /// zero-capacity bucket would drop every packet including the first,
    /// which is never the intended configuration.
    pub fn new(capacity: u64, refill_per_sec: u64) -> Result<Self, EbpfError> {
        if capacity == 0 {
            return Err(EbpfError::RuleInvalid(
                "ddos rate limit capacity must be > 0".into(),
            ));
        }
        Ok(Self {
            capacity,
            refill_per_sec,
        })
    }
}

/// A single integer token bucket — the per-source map *value*.
///
/// `#[repr(C)]` with no padding (two `u64`s) so it is byte-identical to
/// what the kernel side stores in its per-source `LRU_HASH`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TokenBucket {
    /// Whole tokens currently available.
    pub tokens: u64,
    /// Monotonic nanosecond timestamp the bucket was last refilled to.
    /// Advances only by the span already converted into whole tokens, so
    /// the sub-token remainder is preserved across refills.
    pub last_refill_ns: u64,
}

impl TokenBucket {
    /// A full bucket as of `now_ns`.
    #[must_use]
    pub const fn full(limit: RateLimit, now_ns: u64) -> Self {
        Self {
            tokens: limit.capacity,
            last_refill_ns: now_ns,
        }
    }

    /// Refill the bucket up to `now_ns` under `limit`, clamping to
    /// capacity. Remainder-preserving: `last_refill_ns` advances only by
    /// the time that produced whole tokens, so repeated sub-token refills
    /// accumulate instead of being floored away.
    pub fn refill(&mut self, limit: RateLimit, now_ns: u64) {
        if limit.refill_per_sec == 0 {
            // No replenishment — a pure hard cap. Still advance the clock
            // so a later non-zero reconfigure does not back-credit.
            self.last_refill_ns = self.last_refill_ns.max(now_ns);
            return;
        }
        let elapsed = u128::from(now_ns.saturating_sub(self.last_refill_ns));
        if elapsed == 0 {
            return;
        }
        let rate = u128::from(limit.refill_per_sec);
        let added = elapsed * rate / NANOS_PER_SEC;
        if added == 0 {
            return;
        }
        let added = u64::try_from(added).unwrap_or(u64::MAX);
        self.tokens = self.tokens.saturating_add(added).min(limit.capacity);
        // Advance the clock by the span that produced the `added` whole
        // tokens — NOT by the full `elapsed`. This is the remainder-
        // preserving guarantee: the sub-token tail of `elapsed` (the part
        // that did not yet amount to a whole token) is left uncredited on
        // the clock so it accumulates into the next refill instead of
        // being floored away. The capacity clamp above is independent: if
        // the bucket saturates, the surplus tokens are intentionally
        // dropped (a full bucket cannot bank time), which is standard
        // token-bucket behaviour.
        let consumed_ns = u128::from(added) * NANOS_PER_SEC / rate;
        let consumed_ns = u64::try_from(consumed_ns).unwrap_or(u64::MAX);
        self.last_refill_ns = self.last_refill_ns.saturating_add(consumed_ns);
    }

    /// Refill to `now_ns`, then try to consume one token. Returns `true`
    /// (admitted) if a token was available, `false` (drop) otherwise.
    pub fn try_consume(&mut self, limit: RateLimit, now_ns: u64) -> bool {
        self.refill(limit, now_ns);
        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// True iff the bucket is full as of its last refill — an idle
    /// source carrying no rate-limit state worth retaining.
    #[must_use]
    const fn is_full(&self, limit: RateLimit) -> bool {
        self.tokens >= limit.capacity
    }
}

/// A tracked per-source entry: the kernel-compatible [`TokenBucket`] plus
/// the userspace-only last-access timestamp that orders LRU eviction.
///
/// A kernel `LRU_HASH` keeps recency ordering in the map's own internal
/// metadata, not in the stored value, so `last_seen_ns` lives here in a
/// userspace-only wrapper rather than inside [`TokenBucket`] — the
/// `#[repr(C)]` byte layout shared with the kernel map value is therefore
/// left unchanged.
#[derive(Copy, Clone, Debug)]
struct TrackedBucket {
    bucket: TokenBucket,
    /// Monotonic timestamp of the most recent `admit` that touched this
    /// entry; the LRU key for on-pressure eviction.
    last_seen_ns: u64,
}

/// Per-source-IP token-bucket rate limiter — the userspace model of a
/// kernel `LRU_HASH<src_ip, TokenBucket>`.
///
/// Bounded by `max_tracked`, and faithful to the kernel `LRU_HASH` it
/// models: when the table is full and a new source arrives, genuinely
/// idle (fully-refilled) sources are pruned first — the cheap, common
/// case — and if every tracked source is still active the single
/// least-recently-used entry is evicted to make room. The table is thus
/// always bounded and the limiter keeps enforcing under a
/// high-source-diversity flood, instead of failing open (which would let
/// an attacker rotating spoofed source IPs past `max_tracked` bypass rate
/// limiting entirely). An evicted source simply reappears as a fresh full
/// bucket on its next packet — at most one extra burst, exactly as the
/// kernel map behaves.
#[derive(Debug)]
pub struct SourceRateLimiter {
    buckets: HashMap<IpAddr, TrackedBucket>,
    limit: RateLimit,
    max_tracked: usize,
}

impl SourceRateLimiter {
    /// New limiter with the given budget, tracking at most `max_tracked`
    /// distinct source IPs.
    #[must_use]
    pub fn new(limit: RateLimit, max_tracked: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            limit,
            max_tracked: max_tracked.max(1),
        }
    }

    /// Number of source IPs currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// The configured budget.
    #[must_use]
    pub const fn limit(&self) -> RateLimit {
        self.limit
    }

    /// Admit (or drop) one packet from `src` at `now_ns`. `true` =
    /// within budget (XDP passes), `false` = over budget (XDP drops).
    pub fn admit(&mut self, src: IpAddr, now_ns: u64) -> bool {
        if let Some(entry) = self.buckets.get_mut(&src) {
            // Touch the LRU timestamp (monotonically) and account the packet.
            entry.last_seen_ns = entry.last_seen_ns.max(now_ns);
            return entry.bucket.try_consume(self.limit, now_ns);
        }
        // New source. Bound the table before inserting so it can never
        // exceed `max_tracked`: prune idle sources first, and if every
        // tracked source is still active evict the least-recently-used
        // one. This always frees a slot, so the limiter keeps enforcing
        // rather than failing open.
        if self.buckets.len() >= self.max_tracked && !self.prune_idle(now_ns) {
            self.evict_lru();
        }
        // First packet from a fresh source: a full bucket, minus this one.
        let mut bucket = TokenBucket::full(self.limit, now_ns);
        let admitted = bucket.try_consume(self.limit, now_ns);
        self.buckets.insert(
            src,
            TrackedBucket {
                bucket,
                last_seen_ns: now_ns,
            },
        );
        admitted
    }

    /// Drop every tracked source that has refilled to full as of
    /// `now_ns` (idle senders). Returns `true` if at least one entry was
    /// freed. Used both as the cheap first stage of on-pressure eviction
    /// and as an explicit maintenance sweep.
    pub fn prune_idle(&mut self, now_ns: u64) -> bool {
        let limit = self.limit;
        let before = self.buckets.len();
        self.buckets.retain(|_, e| {
            e.bucket.refill(limit, now_ns);
            !e.bucket.is_full(limit)
        });
        self.buckets.len() < before
    }

    /// Evict the single least-recently-used source (smallest
    /// `last_seen_ns`), guaranteeing a free slot when no idle source can
    /// be pruned. A no-op on an empty table.
    ///
    /// `O(n)` scan, like [`Self::prune_idle`]: the kernel `LRU_HASH`
    /// maintains an intrusive LRU list for `O(1)` eviction, but the
    /// userspace mirror — which is not the production hot path — trades
    /// that for simplicity. The eviction faithfully matches the kernel:
    /// the stalest source is dropped and reappears as a fresh bucket if it
    /// sends again.
    fn evict_lru(&mut self) {
        if let Some(victim) = self
            .buckets
            .iter()
            .min_by_key(|(_, e)| e.last_seen_ns)
            .map(|(&ip, _)| ip)
        {
            self.buckets.remove(&victim);
        }
    }

    /// Drop all tracked state. Used on a policy reconfigure.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

/// One GeoIP database entry: a network mapped to its country.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GeoIpEntry {
    /// The network this entry covers.
    pub net: IpNet,
    /// ISO-3166-1 alpha-2 country code (e.g. `*b"US"`).
    pub country: CountryCode,
}

impl GeoIpEntry {
    /// New entry mapping `net` to `country`.
    #[must_use]
    pub const fn new(net: IpNet, country: CountryCode) -> Self {
        Self { net, country }
    }
}

/// The GeoIP database — a longest-prefix IP→country table.
///
/// Models the kernel `BPF_MAP_TYPE_LPM_TRIE` the loader fills from the
/// MaxMind-style database. Lookups are longest-prefix-first (a `/32`
/// host override beats a `/8` country block), exactly like
/// [`crate::class::Classifier`].
#[derive(Clone, Debug, Default)]
pub struct GeoIpTable {
    entries: Vec<GeoIpEntry>,
}

impl GeoIpTable {
    /// Build a table from `entries`, sorting longest-prefix-first so the
    /// most specific network wins a lookup.
    #[must_use]
    pub fn new(mut entries: Vec<GeoIpEntry>) -> Self {
        entries.sort_by_key(|e| std::cmp::Reverse(e.net.prefix_len()));
        Self { entries }
    }

    /// Number of database entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve `ip` to its country code, or `None` if no entry covers it.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        self.entries
            .iter()
            .find(|e| e.net.contains(&ip))
            .map(|e| e.country)
    }
}

/// A per-tenant set of blocked country codes.
///
/// Models the kernel `HASH<CountryCode, u8>` the loader fills per tenant.
/// An empty blocklist blocks nothing, so GeoIP enforcement is a no-op
/// until a tenant configures countries to drop.
#[derive(Clone, Debug, Default)]
pub struct GeoIpBlocklist {
    blocked: BTreeSet<CountryCode>,
}

impl GeoIpBlocklist {
    /// New blocklist from an iterator of country codes.
    #[must_use]
    pub fn new(codes: impl IntoIterator<Item = CountryCode>) -> Self {
        Self {
            blocked: codes.into_iter().collect(),
        }
    }

    /// Add a country to the blocklist.
    pub fn block(&mut self, country: CountryCode) {
        self.blocked.insert(country);
    }

    /// True iff `country` is blocked.
    #[must_use]
    pub fn is_blocked(&self, country: CountryCode) -> bool {
        self.blocked.contains(&country)
    }

    /// Number of blocked countries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// True iff no country is blocked (GeoIP enforcement is a no-op).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// The installable DDoS-mitigation configuration: the rate-limit budgets
/// and the GeoIP database + per-tenant blocklist.
///
/// This is the immutable policy the control plane pushes into the kernel
/// maps via [`crate::loader::ProgramLoader::update_ddos`]; the live
/// per-source counters are kernel map state and are *not* part of the
/// config.
#[derive(Clone, Debug, Default)]
pub struct DdosConfig {
    /// SYN-flood budget (per source IP). `None` disables SYN-flood
    /// mitigation.
    pub syn: Option<RateLimit>,
    /// UDP-flood budget (per source IP). `None` disables UDP-flood
    /// mitigation.
    pub udp: Option<RateLimit>,
    /// GeoIP database (IP→country).
    pub geoip: GeoIpTable,
    /// Per-tenant blocked country codes.
    pub blocklist: GeoIpBlocklist,
}

impl DdosConfig {
    /// Validate the configuration: both rate limits (when present) must
    /// have a non-zero capacity, and a non-empty blocklist requires a
    /// non-empty GeoIP database (blocking by country is meaningless
    /// without a database to resolve the country from).
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::RuleInvalid`] describing the first violation.
    pub fn validate(&self) -> Result<(), EbpfError> {
        for (name, lim) in [("syn", self.syn), ("udp", self.udp)] {
            if let Some(lim) = lim
                && lim.capacity == 0
            {
                return Err(EbpfError::RuleInvalid(format!(
                    "ddos {name} rate limit capacity must be > 0"
                )));
            }
        }
        if !self.blocklist.is_empty() && self.geoip.is_empty() {
            return Err(EbpfError::RuleInvalid(
                "ddos geoip blocklist is non-empty but the geoip database is empty".into(),
            ));
        }
        Ok(())
    }
}

/// The reason the mitigator reached its verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DropReason {
    /// Not dropped by DDoS mitigation — handed to the next fast-path
    /// stage (classification / firewall).
    Allowed = 0,
    /// Dropped: source exceeded its SYN-flood budget.
    SynFlood = 1,
    /// Dropped: source exceeded its UDP-flood budget.
    UdpFlood = 2,
    /// Dropped: source resolves to a blocked country.
    GeoBlocked = 3,
}

/// The mitigator's per-packet verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DdosVerdict {
    /// The XDP action to take.
    pub action: XdpAction,
    /// Why the action was chosen.
    pub reason: DropReason,
}

impl DdosVerdict {
    /// True iff the packet was dropped by DDoS mitigation.
    #[must_use]
    pub fn is_drop(&self) -> bool {
        self.reason != DropReason::Allowed
    }
}

/// Point-in-time DDoS-mitigation counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DdosStats {
    /// Packets allowed through DDoS mitigation.
    pub passed: u64,
    /// Packets dropped as SYN flood.
    pub syn_dropped: u64,
    /// Packets dropped as UDP flood.
    pub udp_dropped: u64,
    /// Packets dropped by GeoIP country block.
    pub geo_dropped: u64,
}

impl DdosStats {
    /// Total packets dropped across all three mitigations.
    #[must_use]
    pub const fn total_dropped(&self) -> u64 {
        self.syn_dropped
            .saturating_add(self.udp_dropped)
            .saturating_add(self.geo_dropped)
    }

    /// Total packets evaluated (passed + dropped).
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.passed.saturating_add(self.total_dropped())
    }
}

/// The L3/L4 packet metadata the XDP program extracts and hands to the
/// mitigator — the minimal header fields the DDoS decisions need.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source port (host order; `0` for L3-only protocols).
    pub src_port: u16,
    /// Destination port (host order).
    pub dst_port: u16,
    /// IANA L4 protocol number.
    pub protocol: u8,
    /// TCP control flags ([`tcp_flags`]). Ignored for non-TCP.
    pub tcp_flags: u8,
    /// On-wire packet length in bytes.
    pub len: u64,
}

impl PacketMeta {
    /// True iff this is an initial TCP SYN (SYN set, ACK clear) — the
    /// packet a SYN flood is built from. A SYN-ACK (both set) is part of
    /// an accepted handshake and is not rate-limited as a flood.
    #[must_use]
    pub const fn is_tcp_syn(&self) -> bool {
        self.protocol == PROTO_TCP
            && (self.tcp_flags & tcp_flags::SYN != 0)
            && (self.tcp_flags & tcp_flags::ACK == 0)
    }

    /// True iff this is a UDP datagram.
    #[must_use]
    pub const fn is_udp(&self) -> bool {
        self.protocol == PROTO_UDP
    }
}

/// The XDP-level DDoS mitigator: GeoIP block + SYN/UDP flood rate
/// limiting, composed into a single per-packet verdict.
///
/// Built from a [`DdosConfig`]; owns the live per-source limiter tables
/// and the running [`DdosStats`]. Per-packet [`Self::evaluate`] takes
/// `&mut self` because each call mutates a limiter bucket — the same
/// `&mut`-on-the-hot-path shape [`crate::maps::PolicyVerdictCache`] uses.
#[derive(Debug)]
pub struct DdosMitigator {
    geoip: GeoIpTable,
    blocklist: GeoIpBlocklist,
    syn: Option<SourceRateLimiter>,
    udp: Option<SourceRateLimiter>,
    stats: DdosStats,
}

impl DdosMitigator {
    /// Default per-limiter source-table bound (distinct source IPs
    /// tracked before idle-eviction kicks in). Matches the order of
    /// magnitude of a kernel `LRU_HASH` sized for an edge under attack.
    pub const DEFAULT_MAX_TRACKED: usize = 1 << 20;

    /// Build a mitigator from `config`, sizing each enabled limiter's
    /// source table to [`Self::DEFAULT_MAX_TRACKED`].
    #[must_use]
    pub fn new(config: DdosConfig) -> Self {
        Self::with_capacity(config, Self::DEFAULT_MAX_TRACKED)
    }

    /// Build a mitigator from `config` with an explicit per-limiter
    /// source-table bound.
    ///
    /// `config` is expected to satisfy [`DdosConfig::validate`]. Because
    /// [`RateLimit`] is `#[repr(C)]` for byte-compatibility with the
    /// kernel map value its fields are public, so a caller *can* bypass
    /// [`RateLimit::new`] and hand-build an invalid limit (e.g. zero
    /// capacity, which would drop every packet). Production construction
    /// always flows through the control plane, which validates before
    /// install; this constructor adds a debug-build assertion so such a
    /// misconfiguration trips loudly in tests rather than silently
    /// black-holing traffic. The assertion compiles out of release
    /// builds, so it costs nothing on the fast path.
    #[must_use]
    pub fn with_capacity(config: DdosConfig, max_tracked: usize) -> Self {
        debug_assert!(
            config.validate().is_ok(),
            "DdosMitigator built from an invalid DdosConfig; \
             construct rate limits via RateLimit::new and call \
             DdosConfig::validate before installing"
        );
        Self {
            geoip: config.geoip,
            blocklist: config.blocklist,
            syn: config.syn.map(|l| SourceRateLimiter::new(l, max_tracked)),
            udp: config.udp.map(|l| SourceRateLimiter::new(l, max_tracked)),
            stats: DdosStats::default(),
        }
    }

    /// Current counters.
    #[must_use]
    pub const fn stats(&self) -> DdosStats {
        self.stats
    }

    /// Number of source IPs the SYN limiter is tracking (`0` if SYN-flood
    /// mitigation is disabled).
    #[must_use]
    pub fn syn_tracked(&self) -> usize {
        self.syn.as_ref().map_or(0, SourceRateLimiter::tracked)
    }

    /// Number of source IPs the UDP limiter is tracking (`0` if UDP-flood
    /// mitigation is disabled).
    #[must_use]
    pub fn udp_tracked(&self) -> usize {
        self.udp.as_ref().map_or(0, SourceRateLimiter::tracked)
    }

    /// Evaluate one packet observed at `now_ns`, returning its verdict
    /// and updating the counters.
    ///
    /// Decision order, cheapest-first: GeoIP block (a single LPM lookup,
    /// no per-source state) → SYN-flood (TCP initial SYN only) →
    /// UDP-flood. A packet that no mitigation drops is `Allowed` and
    /// continues to classification / firewall.
    pub fn evaluate(&mut self, meta: &PacketMeta, now_ns: u64) -> DdosVerdict {
        // 1. GeoIP — drop before spending any per-source state.
        if !self.blocklist.is_empty()
            && let Some(country) = self.geoip.lookup(meta.src_ip)
            && self.blocklist.is_blocked(country)
        {
            self.stats.geo_dropped = self.stats.geo_dropped.saturating_add(1);
            return DdosVerdict {
                action: XdpAction::Drop,
                reason: DropReason::GeoBlocked,
            };
        }

        // 2. SYN flood — only the initial SYN of a TCP handshake.
        if meta.is_tcp_syn()
            && let Some(limiter) = self.syn.as_mut()
            && !limiter.admit(meta.src_ip, now_ns)
        {
            self.stats.syn_dropped = self.stats.syn_dropped.saturating_add(1);
            return DdosVerdict {
                action: XdpAction::Drop,
                reason: DropReason::SynFlood,
            };
        }

        // 3. UDP flood.
        if meta.is_udp()
            && let Some(limiter) = self.udp.as_mut()
            && !limiter.admit(meta.src_ip, now_ns)
        {
            self.stats.udp_dropped = self.stats.udp_dropped.saturating_add(1);
            return DdosVerdict {
                action: XdpAction::Drop,
                reason: DropReason::UdpFlood,
            };
        }

        self.stats.passed = self.stats.passed.saturating_add(1);
        DdosVerdict {
            action: XdpAction::Pass,
            reason: DropReason::Allowed,
        }
    }

    /// Prune idle (fully-refilled) sources from both limiter tables as of
    /// `now_ns`. The maintenance sweep an edge runs periodically to bound
    /// limiter memory between bursts.
    pub fn prune_idle(&mut self, now_ns: u64) {
        if let Some(l) = self.syn.as_mut() {
            l.prune_idle(now_ns);
        }
        if let Some(l) = self.udp.as_mut() {
            l.prune_idle(now_ns);
        }
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

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    const SEC: u64 = 1_000_000_000;

    fn syn(src: IpAddr) -> PacketMeta {
        PacketMeta {
            src_ip: src,
            dst_ip: v4(10, 0, 0, 1),
            src_port: 40000,
            dst_port: 443,
            protocol: PROTO_TCP,
            tcp_flags: tcp_flags::SYN,
            len: 64,
        }
    }

    fn udp(src: IpAddr) -> PacketMeta {
        PacketMeta {
            src_ip: src,
            dst_ip: v4(10, 0, 0, 1),
            src_port: 40000,
            dst_port: 53,
            protocol: PROTO_UDP,
            tcp_flags: 0,
            len: 512,
        }
    }

    // --- TokenBucket ------------------------------------------------------

    #[test]
    fn token_bucket_consumes_capacity_then_drops() {
        let limit = RateLimit::new(3, 0).unwrap();
        let mut b = TokenBucket::full(limit, 0);
        assert!(b.try_consume(limit, 0));
        assert!(b.try_consume(limit, 0));
        assert!(b.try_consume(limit, 0));
        // Capacity spent, no refill configured → drop.
        assert!(!b.try_consume(limit, 0));
    }

    #[test]
    fn token_bucket_refills_at_configured_rate() {
        let limit = RateLimit::new(10, 100).unwrap(); // 100 tokens/sec
        let mut b = TokenBucket::full(limit, 0);
        for _ in 0..10 {
            assert!(b.try_consume(limit, 0));
        }
        assert!(!b.try_consume(limit, 0));
        // After 50 ms at 100/s → 5 tokens back.
        let t = SEC / 20;
        b.refill(limit, t);
        assert_eq!(b.tokens, 5);
    }

    #[test]
    fn token_bucket_clamps_to_capacity() {
        let limit = RateLimit::new(10, 1000).unwrap();
        let mut b = TokenBucket {
            tokens: 0,
            last_refill_ns: 0,
        };
        // A full second at 1000/s would add 1000, clamp to capacity 10.
        b.refill(limit, SEC);
        assert_eq!(b.tokens, 10);
    }

    #[test]
    fn token_bucket_high_frequency_poll_does_not_starve() {
        // The integer-rate-limiter trap: poll far faster than the refill
        // rate. A naive implementation floors each sub-token refill to 0
        // and advances the clock, so the bucket never refills. The
        // remainder-preserving refill must still accrue tokens.
        let limit = RateLimit::new(1, 10).unwrap(); // 10 tokens/sec
        let mut b = TokenBucket::full(limit, 0);
        assert!(b.try_consume(limit, 0)); // spend the one token
        // Poll every 1 ms for 200 ms. 10/s → a token every 100 ms, so we
        // expect ~2 tokens to become available over the window.
        let mut granted = 0;
        for ms in 1..=200 {
            if b.try_consume(limit, ms * (SEC / 1000)) {
                granted += 1;
            }
        }
        assert_eq!(granted, 2, "expected 2 refilled tokens over 200ms at 10/s");
    }

    // --- SourceRateLimiter ------------------------------------------------

    #[test]
    fn source_limiter_is_per_source() {
        let mut rl = SourceRateLimiter::new(RateLimit::new(2, 0).unwrap(), 1024);
        let a = v4(1, 1, 1, 1);
        let b = v4(2, 2, 2, 2);
        // Source A spends its 2-token budget.
        assert!(rl.admit(a, 0));
        assert!(rl.admit(a, 0));
        assert!(!rl.admit(a, 0));
        // Source B is unaffected — independent bucket.
        assert!(rl.admit(b, 0));
        assert!(rl.admit(b, 0));
        assert!(!rl.admit(b, 0));
        assert_eq!(rl.tracked(), 2);
    }

    #[test]
    fn source_limiter_prunes_idle_buckets_under_pressure() {
        // max_tracked = 1. First source goes idle (refills to full), then
        // a second source must be admittable by evicting the idle one.
        let mut rl = SourceRateLimiter::new(RateLimit::new(1, 1000).unwrap(), 1);
        let a = v4(1, 1, 1, 1);
        let b = v4(2, 2, 2, 2);
        assert!(rl.admit(a, 0));
        assert_eq!(rl.tracked(), 1);
        // Much later, A has refilled to full (idle). B arrives; A is pruned.
        assert!(rl.admit(b, 10 * SEC));
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn source_limiter_evicts_lru_instead_of_failing_open() {
        // Zero refill so no tracked source ever goes idle — the exact case
        // the old code failed open on. max_tracked = 2, both slots active.
        let mut rl = SourceRateLimiter::new(RateLimit::new(5, 0).unwrap(), 2);
        let a = v4(1, 1, 1, 1);
        let b = v4(2, 2, 2, 2);
        let c = v4(3, 3, 3, 3);
        assert!(rl.admit(a, 1)); // A active, last_seen = 1
        assert!(rl.admit(b, 2)); // B active, last_seen = 2
        assert_eq!(rl.tracked(), 2);
        // C arrives at t = 3. No idle source to prune, so the LRU entry
        // (A, last_seen = 1) is evicted — NOT fail-open. The table stays
        // bounded and C is tracked.
        assert!(rl.admit(c, 3));
        assert_eq!(rl.tracked(), 2);
        // B was untouched and is still tracked with its drained-by-one
        // budget, so the limiter keeps enforcing it: 4 tokens remain, then
        // the 5th packet is dropped (no fail-open leak).
        assert!(rl.admit(b, 4));
        assert!(rl.admit(b, 5));
        assert!(rl.admit(b, 6));
        assert!(rl.admit(b, 7));
        assert!(!rl.admit(b, 8));
        assert_eq!(rl.tracked(), 2);
    }

    #[test]
    fn source_limiter_stays_bounded_and_enforcing_under_zero_refill_flood() {
        // Pure hard cap (no refill), tiny table. Several distinct sources
        // each send a 4-packet burst. The table must stay bounded at
        // max_tracked and every source must stay capped at its 2-token
        // burst — the old fail-open path admitted all 4 of a "new"
        // source's packets untracked once the table saturated.
        let mut rl = SourceRateLimiter::new(RateLimit::new(2, 0).unwrap(), 2);
        let srcs = [
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            v4(3, 3, 3, 3),
            v4(4, 4, 4, 4),
        ];
        let mut now = 0u64;
        for &s in &srcs {
            let mut admitted = 0;
            for _ in 0..4 {
                now += 1;
                if rl.admit(s, now) {
                    admitted += 1;
                }
            }
            // A source stays the most-recently-used entry while it is being
            // hammered, so it is never evicted mid-burst and is capped at
            // exactly its 2-token budget — never the 4 the old fail-open
            // path would have leaked.
            assert_eq!(
                admitted, 2,
                "source must stay rate-limited under saturation"
            );
            assert!(rl.tracked() <= 2, "table must stay bounded at max_tracked");
        }
    }

    // --- GeoIP ------------------------------------------------------------

    #[test]
    fn geoip_longest_prefix_wins() {
        let table = GeoIpTable::new(vec![
            GeoIpEntry::new(net("1.0.0.0/8"), *b"CN"),
            GeoIpEntry::new(net("1.2.3.0/24"), *b"US"), // carve-out
        ]);
        assert_eq!(table.lookup(v4(1, 9, 9, 9)), Some(*b"CN"));
        assert_eq!(table.lookup(v4(1, 2, 3, 4)), Some(*b"US"));
        assert_eq!(table.lookup(v4(8, 8, 8, 8)), None);
    }

    #[test]
    fn geoip_blocklist_membership() {
        let mut bl = GeoIpBlocklist::new([*b"CN", *b"RU"]);
        assert!(bl.is_blocked(*b"CN"));
        assert!(!bl.is_blocked(*b"US"));
        bl.block(*b"KP");
        assert!(bl.is_blocked(*b"KP"));
        assert_eq!(bl.len(), 3);
    }

    // --- DdosConfig validation -------------------------------------------

    #[test]
    fn config_validate_rejects_blocklist_without_database() {
        let cfg = DdosConfig {
            blocklist: GeoIpBlocklist::new([*b"CN"]),
            ..DdosConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_well_formed() {
        let cfg = DdosConfig {
            syn: Some(RateLimit::new(100, 50).unwrap()),
            udp: Some(RateLimit::new(1000, 500).unwrap()),
            geoip: GeoIpTable::new(vec![GeoIpEntry::new(net("1.0.0.0/8"), *b"CN")]),
            blocklist: GeoIpBlocklist::new([*b"CN"]),
        };
        assert!(cfg.validate().is_ok());
    }

    // --- DdosMitigator ----------------------------------------------------

    fn mitigator() -> DdosMitigator {
        DdosMitigator::new(DdosConfig {
            syn: Some(RateLimit::new(3, 0).unwrap()),
            udp: Some(RateLimit::new(2, 0).unwrap()),
            geoip: GeoIpTable::new(vec![GeoIpEntry::new(net("203.0.113.0/24"), *b"CN")]),
            blocklist: GeoIpBlocklist::new([*b"CN"]),
        })
    }

    #[test]
    fn mitigator_drops_syn_flood_past_budget() {
        let mut m = mitigator();
        let src = v4(198, 51, 100, 7);
        // 3-token budget: first 3 SYNs pass, the 4th is a flood drop.
        for _ in 0..3 {
            let v = m.evaluate(&syn(src), 0);
            assert_eq!(v.reason, DropReason::Allowed);
        }
        let v = m.evaluate(&syn(src), 0);
        assert_eq!(v.action, XdpAction::Drop);
        assert_eq!(v.reason, DropReason::SynFlood);
        assert_eq!(m.stats().syn_dropped, 1);
        assert_eq!(m.stats().passed, 3);
    }

    #[test]
    fn mitigator_drops_udp_flood_past_budget() {
        let mut m = mitigator();
        let src = v4(198, 51, 100, 8);
        assert_eq!(m.evaluate(&udp(src), 0).reason, DropReason::Allowed);
        assert_eq!(m.evaluate(&udp(src), 0).reason, DropReason::Allowed);
        let v = m.evaluate(&udp(src), 0);
        assert_eq!(v.action, XdpAction::Drop);
        assert_eq!(v.reason, DropReason::UdpFlood);
        assert_eq!(m.stats().udp_dropped, 1);
    }

    #[test]
    fn mitigator_geo_blocks_before_rate_limiting() {
        let mut m = mitigator();
        // 203.0.113.5 → CN, which is blocked.
        let blocked = v4(203, 0, 113, 5);
        let v = m.evaluate(&syn(blocked), 0);
        assert_eq!(v.action, XdpAction::Drop);
        assert_eq!(v.reason, DropReason::GeoBlocked);
        assert_eq!(m.stats().geo_dropped, 1);
        // GeoIP fired first, so no SYN budget was spent.
        assert_eq!(m.syn_tracked(), 0);
    }

    #[test]
    fn mitigator_passes_syn_ack_without_rate_limiting() {
        let mut m = mitigator();
        let src = v4(198, 51, 100, 9);
        let mut p = syn(src);
        p.tcp_flags = tcp_flags::SYN | tcp_flags::ACK; // SYN-ACK, not a flood
        // Far more than the 3-SYN budget — none are treated as floods.
        for _ in 0..10 {
            assert_eq!(m.evaluate(&p, 0).reason, DropReason::Allowed);
        }
        assert_eq!(m.stats().syn_dropped, 0);
        assert_eq!(m.syn_tracked(), 0);
    }

    #[test]
    fn mitigator_disabled_limiters_pass_everything() {
        let mut m = DdosMitigator::new(DdosConfig::default());
        let src = v4(198, 51, 100, 10);
        for _ in 0..100 {
            assert_eq!(m.evaluate(&syn(src), 0).reason, DropReason::Allowed);
            assert_eq!(m.evaluate(&udp(src), 0).reason, DropReason::Allowed);
        }
        assert_eq!(m.stats().total_dropped(), 0);
        assert_eq!(m.stats().passed, 200);
    }

    #[test]
    fn mitigator_ipv6_source_is_rate_limited() {
        let mut m = mitigator();
        let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        for _ in 0..3 {
            assert_eq!(m.evaluate(&syn(src), 0).reason, DropReason::Allowed);
        }
        assert_eq!(m.evaluate(&syn(src), 0).reason, DropReason::SynFlood);
    }

    #[test]
    fn stats_total_accounting() {
        let s = DdosStats {
            passed: 10,
            syn_dropped: 2,
            udp_dropped: 3,
            geo_dropped: 1,
        };
        assert_eq!(s.total_dropped(), 6);
        assert_eq!(s.total(), 16);
    }
}
