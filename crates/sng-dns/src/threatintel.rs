//! Threat-intelligence sinkhole backed by a Bloom filter.
//!
//! [`crate::sinkhole`] holds an exact [`std::collections::HashSet`]
//! of operator-curated bad domains — perfect when the list is in
//! the thousands. Commercial threat-intel feeds, by contrast, ship
//! *millions* of indicators (the DGA / fast-flux domains malware
//! families burn through daily). Holding 10M+ canonical names in a
//! HashSet costs hundreds of MB of resident memory per edge — on a
//! fleet of constrained appliances that is the difference between
//! "fits" and "OOM".
//!
//! A Bloom filter trades a small, *bounded* false-positive rate for
//! O(1)-per-entry memory (≈1.2 bytes/entry at a 1% FPR, ≈1.8 at
//! 0.1%): a 10M-domain feed fits in ~18 MB instead of ~600 MB. The
//! tradeoff is that a Bloom filter can report a name as present when
//! it is not (a false positive) — never the reverse. A false
//! positive here would sinkhole a legitimate domain, so we pair the
//! filter with an explicit *allowlist* the operator can populate
//! with business-critical names; an allowlisted name (or any of its
//! parents) is never sinkholed regardless of a Bloom hit. This is
//! the standard "fast probabilistic membership + authoritative
//! override" shape used by production DNS firewalls.
//!
//! The Bloom filter is built once from a verified, Ed25519-signed
//! feed bundle (same trust model as the IPS / policy bundles) and
//! published into the [`crate::filter::FilterChain`] via
//! [`arc_swap::ArcSwap`] on reload — identical to every other feed.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use sng_core::envelope::Verdict;

use crate::filter::{Filter, FilterDecision};
use crate::qtype::QType;
use crate::query::{DnsQuery, canonicalize_name};

/// 64-bit FNV-1a offset basis / prime (RFC-style constants).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit FNV-1a hash with a caller-supplied seed mixed into the
/// initial state. Two different seeds give two independent hash
/// functions, which is all the Kirsch–Mitzenmacher double-hashing
/// scheme below needs to synthesise `k` indices.
fn fnv1a_seeded(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = FNV_OFFSET ^ seed;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// A classic Bloom filter over UTF-8 strings.
///
/// Bit storage is a `Vec<u64>` word array; `num_bits` is the true
/// bit capacity `m` and may be less than `words.len() * 64`. The
/// `k` indices for a key are produced by double hashing
/// `g_i = h1 + i*h2` (Kirsch & Mitzenmacher, 2006), which gives the
/// same asymptotic FPR as `k` independent hashes while computing
/// only two.
#[derive(Clone, Debug)]
pub struct BloomFilter {
    words: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
    inserted: u64,
}

impl BloomFilter {
    /// Build an empty filter sized for `expected_items` entries at a
    /// target false-positive rate `fpr` (clamped to a sane
    /// `(0, 0.5]`). Uses the standard optimal sizing:
    ///
    /// ```text
    /// m = ceil(-n ln p / (ln 2)^2)   k = round((m/n) ln 2)
    /// ```
    ///
    /// `expected_items` is floored to 1 so an empty feed still
    /// yields a usable (tiny) filter rather than a zero-length one.
    // Sizing math is deliberately floating-point: `n`/`m`/`k` are
    // bounded (feed sizes ≤ low billions, k clamped to 32) so the
    // precision/truncation/sign casts below are safe — the results
    // are floored/clamped into small integer ranges right after.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    #[must_use]
    pub fn with_capacity(expected_items: usize, fpr: f64) -> Self {
        let n = expected_items.max(1) as f64;
        let p = fpr.clamp(f64::MIN_POSITIVE, 0.5);
        let ln2 = std::f64::consts::LN_2;
        let m = (-n * p.ln() / (ln2 * ln2)).ceil();
        // Guard against degenerate sizes; at least one 64-bit word.
        let num_bits = (m as u64).max(64);
        let k = ((m / n) * ln2).round();
        let num_hashes = (k as u32).clamp(1, 32);
        let words = vec![0u64; num_bits.div_ceil(64) as usize];
        Self {
            words,
            num_bits,
            num_hashes,
            inserted: 0,
        }
    }

    /// The two base hashes for a key. `h2` is forced odd so it is
    /// coprime with the power-of-two-ish word stride and never
    /// collapses the `g_i` sequence to a single index.
    fn base_hashes(key: &str) -> (u64, u64) {
        let bytes = key.as_bytes();
        let h1 = fnv1a_seeded(bytes, 0);
        let h2 = fnv1a_seeded(bytes, 0x9e37_79b9_7f4a_7c15) | 1;
        (h1, h2)
    }

    /// Set the `k` bits for `key`.
    pub fn insert(&mut self, key: &str) {
        let (h1, h2) = Self::base_hashes(key);
        for i in 0..u64::from(self.num_hashes) {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.num_bits;
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            self.words[word] |= 1u64 << bit;
        }
        self.inserted += 1;
    }

    /// Test membership. `false` is definitive (the key was never
    /// inserted); `true` means "probably present" with the filter's
    /// configured false-positive probability.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        let (h1, h2) = Self::base_hashes(key);
        for i in 0..u64::from(self.num_hashes) {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.num_bits;
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            if self.words[word] & (1u64 << bit) == 0 {
                return false;
            }
        }
        true
    }

    /// Number of keys inserted so far.
    #[must_use]
    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    /// Bit capacity `m`.
    #[must_use]
    pub fn num_bits(&self) -> u64 {
        self.num_bits
    }

    /// Number of hash functions `k`.
    #[must_use]
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Current expected false-positive probability given how many
    /// items have actually been inserted:
    /// `(1 - e^{-k·n/m})^k`. Useful for telemetry / capacity alarms
    /// (an overfilled filter silently degrades its FPR).
    // `inserted`/`num_bits` fit comfortably in an f64 mantissa for
    // any realistic feed; this is a diagnostic estimate, not an
    // exact count, so precision loss is immaterial.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn estimated_fpr(&self) -> f64 {
        let k = f64::from(self.num_hashes);
        let n = self.inserted as f64;
        let m = self.num_bits as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

/// Threat-intel sinkhole: a [`BloomFilter`] of known-bad domains
/// plus an authoritative allowlist that overrides false positives,
/// plus the two sink addresses synthesized answers point at.
#[derive(Clone, Debug)]
pub struct ThreatIntelSinkhole {
    bloom: BloomFilter,
    /// Canonical names that must never be sinkholed even on a Bloom
    /// hit (business-critical infra). Matched with suffix semantics
    /// so allowlisting `example.com` also protects `api.example.com`.
    allow: HashSet<String>,
    sink_v4: Ipv4Addr,
    sink_v6: Ipv6Addr,
}

impl ThreatIntelSinkhole {
    /// Build from an iterator of known-bad domains. `expected_items`
    /// sizes the Bloom filter; pass the feed length (or an estimate)
    /// so the FPR target is met. `allow` is the override list.
    #[must_use]
    pub fn build(
        bad_domains: impl IntoIterator<Item = String>,
        allow: impl IntoIterator<Item = String>,
        expected_items: usize,
        fpr: f64,
        sink_v4: Ipv4Addr,
        sink_v6: Ipv6Addr,
    ) -> Self {
        let mut bloom = BloomFilter::with_capacity(expected_items, fpr);
        for d in bad_domains {
            let c = canonicalize_name(&d);
            if !c.is_empty() {
                bloom.insert(&c);
            }
        }
        let allow = allow
            .into_iter()
            .map(|n| canonicalize_name(&n))
            .filter(|n| !n.is_empty())
            .collect();
        Self {
            bloom,
            allow,
            sink_v4,
            sink_v6,
        }
    }

    /// Whether `canonical` (or any parent suffix) is allowlisted.
    fn allowlisted(&self, canonical: &str) -> bool {
        Self::suffix_hit(canonical, |s| self.allow.contains(s))
    }

    /// Whether `canonical` (or any parent suffix) is in the bad-domain
    /// Bloom filter.
    #[must_use]
    pub fn matches(&self, canonical: &str) -> bool {
        Self::suffix_hit(canonical, |s| self.bloom.contains(s))
    }

    /// Walk the labels from most specific to least specific, calling
    /// `probe` on each suffix and returning true on the first hit.
    /// Bounded by the label count (≤127, RFC 1035 §2.3.4).
    fn suffix_hit(canonical: &str, probe: impl Fn(&str) -> bool) -> bool {
        let mut current = canonical;
        loop {
            if probe(current) {
                return true;
            }
            match current.find('.') {
                Some(idx) => current = &current[idx + 1..],
                None => return false,
            }
        }
    }

    fn sink_for(&self, qtype: QType) -> Option<IpAddr> {
        match qtype {
            QType::A => Some(IpAddr::V4(self.sink_v4)),
            QType::Aaaa => Some(IpAddr::V6(self.sink_v6)),
            // For non-address qtypes we synthesize NOERROR/no-answer,
            // matching crate::sinkhole: the endpoint sees the name as
            // existing but with no record of the requested type.
            _ => None,
        }
    }

    /// Reference to the underlying Bloom filter (telemetry / sizing).
    #[must_use]
    pub fn bloom(&self) -> &BloomFilter {
        &self.bloom
    }
}

#[async_trait]
impl Filter for ThreatIntelSinkhole {
    fn name(&self) -> &'static str {
        "threatintel"
    }

    async fn check(&self, query: &DnsQuery) -> FilterDecision {
        // Allowlist wins: never sinkhole a business-critical name on a
        // Bloom false positive.
        if self.allowlisted(&query.name) {
            return FilterDecision::Pass;
        }
        if !self.matches(&query.name) {
            return FilterDecision::Pass;
        }
        tracing::info!(
            target: "sng_dns::threatintel",
            qname = %query.name,
            qtype = %query.qtype.as_str(),
            "threat-intel sinkhole hit"
        );
        FilterDecision::ShortCircuit {
            verdict: Verdict::Deny,
            rcode: crate::qtype::RCode::NoError,
            synthetic_ip: self.sink_for(query.qtype),
            reason: "threat-intel sinkhole match".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{ChainOutcome, FilterChain};
    use std::sync::Arc;

    #[test]
    fn bloom_membership_no_false_negatives() {
        let mut b = BloomFilter::with_capacity(1000, 0.01);
        for i in 0..1000 {
            b.insert(&format!("bad{i}.example"));
        }
        // Every inserted key MUST be reported present (no false negs).
        for i in 0..1000 {
            assert!(
                b.contains(&format!("bad{i}.example")),
                "false negative at {i}"
            );
        }
        assert_eq!(b.inserted(), 1000);
    }

    #[test]
    fn bloom_fpr_is_bounded() {
        // Build at 1% target, probe 20k absent keys, assert the
        // observed FPR is within a generous multiple of the target
        // (sizing math + double hashing should keep it well under 3%).
        let n = 5000;
        let mut b = BloomFilter::with_capacity(n, 0.01);
        for i in 0..n {
            b.insert(&format!("present-{i}"));
        }
        let trials = 20_000;
        let mut fp = 0;
        for i in 0..trials {
            if b.contains(&format!("absent-{i}")) {
                fp += 1;
            }
        }
        let observed = f64::from(fp) / f64::from(trials);
        assert!(observed < 0.03, "observed FPR {observed} exceeds 3%");
    }

    #[test]
    fn sizing_scales_with_capacity_and_fpr() {
        let small = BloomFilter::with_capacity(1000, 0.01);
        let lower_fpr = BloomFilter::with_capacity(1000, 0.0001);
        // Tighter FPR ⇒ more bits and more hash functions.
        assert!(lower_fpr.num_bits() > small.num_bits());
        assert!(lower_fpr.num_hashes() >= small.num_hashes());
        assert!(small.num_hashes() >= 1);
    }

    #[test]
    fn empty_capacity_still_valid() {
        let b = BloomFilter::with_capacity(0, 0.01);
        assert!(b.num_bits() >= 64);
        assert!(!b.contains("anything"));
    }

    fn ti() -> ThreatIntelSinkhole {
        ThreatIntelSinkhole::build(
            ["Evil.Example.".into(), "malware.test".into()],
            ["safe.evil.example".into()],
            1000,
            0.001,
            Ipv4Addr::new(10, 0, 0, 1),
            "fc00::1".parse().unwrap(),
        )
    }

    #[test]
    fn canonicalizes_and_suffix_matches() {
        let s = ti();
        assert!(s.matches("evil.example"));
        assert!(s.matches("c2.evil.example"));
        assert!(s.matches("malware.test"));
    }

    #[tokio::test]
    async fn allowlist_overrides_bloom_hit() {
        let s = ti();
        // safe.evil.example is allowlisted even though evil.example
        // is in the bad set -> must Pass, not sinkhole.
        let q = DnsQuery::new("safe.evil.example", QType::A);
        assert_eq!(s.check(&q).await, FilterDecision::Pass);
        // A child of the allowlisted name is also protected.
        let q2 = DnsQuery::new("deep.safe.evil.example", QType::A);
        assert_eq!(s.check(&q2).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn a_query_sinkholes_to_v4() {
        let s = ti();
        let q = DnsQuery::new("c2.evil.example", QType::A);
        match s.check(&q).await {
            FilterDecision::ShortCircuit {
                verdict,
                synthetic_ip,
                ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(synthetic_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn txt_query_sinkholes_to_no_answer() {
        let s = ti();
        let q = DnsQuery::new("malware.test", QType::Txt);
        match s.check(&q).await {
            FilterDecision::ShortCircuit { synthetic_ip, .. } => {
                assert_eq!(synthetic_ip, None);
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clean_name_passes() {
        let s = ti();
        let q = DnsQuery::new("good.example", QType::A);
        assert_eq!(s.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn integrates_into_filter_chain() {
        let chain = FilterChain::new(vec![Arc::new(ti()) as Arc<dyn Filter>]);
        let out = chain
            .evaluate(&DnsQuery::new("evil.example", QType::A))
            .await;
        match out {
            ChainOutcome::ShortCircuit {
                verdict, filter, ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(filter, "threatintel");
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }
}
