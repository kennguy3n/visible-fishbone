//! Scalable nearest-fingerprint search over 64-bit SimHash codes.
//!
//! The document-fingerprint detector compares an event's SimHash
//! ([`crate::classifier::simhash`]) against a registry of known
//! sensitive-document fingerprints and fires when one is within a
//! Hamming-distance threshold (a near-duplicate). A linear scan over
//! the registry is `O(N)` per event; with a large per-tenant registry
//! that cost lands on the inspection hot path for every clipboard,
//! file-write, and upload event.
//!
//! [`FingerprintIndex`] replaces the linear scan with **multi-index
//! hashing** (MIH): each 64-bit code is split into `m` disjoint
//! substrings, and a hash table is kept per substring position. To
//! find every code within Hamming distance `r` of a query, it suffices
//! to search each substring table within radius `r' = ⌊r/m⌋ — by the
//! pigeonhole principle, any code within total distance `r` must agree
//! with the query on at least one substring to within `r'` bits
//! (otherwise the `m` substrings would contribute more than
//! `m·(r'+1) > r` differing bits). Candidates gathered from the
//! substring tables are then verified by their exact full-width Hamming
//! distance, so the result is **exact**: no false positives and no
//! false negatives versus the brute-force scan.
//!
//! ## Scaling characteristics
//!
//! Candidate generation probes `m · Σ_{k=0}^{r'} C(w, k)` table slots
//! (`w = 64/m` bits per substring), a constant **independent of the
//! registry size `N`**. With the defaults (`m = 4`, so `w = 16`, and
//! the engine's `r = 12` ⇒ `r' = 3`) that is `4 · 697 ≈ 2.8k` probes,
//! after which only the (small) candidate set is distance-checked.
//! For a tiny registry the constant probe cost can exceed an `O(N)`
//! scan, so the index transparently falls back to a linear scan below
//! [`LINEAR_FALLBACK_LEN`]; the answer is identical either way.
//!
//! ## Redaction invariant
//!
//! The index stores only 64-bit hashes and opaque rule ids — never any
//! document content. A SimHash is a lossy, irreversible fingerprint, so
//! the registry cannot reconstruct the documents it protects.

use std::collections::HashMap;

/// Number of substrings each 64-bit code is split into for the
/// multi-index. Must divide 64. Four 16-bit substrings give a good
/// balance between probe count and candidate selectivity for the
/// engine's distance-12 threshold.
pub const DEFAULT_SUBSTRINGS: u32 = 4;

/// Registry sizes at or below this use a direct linear scan instead of
/// the multi-index: with so few codes the `O(N)` scan is cheaper than
/// the index's (registry-size-independent) probe constant, and it
/// returns the identical exact result.
pub const LINEAR_FALLBACK_LEN: usize = 1024;

/// A registry entry within the query radius: its registration id and
/// its exact Hamming distance from the query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbor {
    /// Registration id, as returned by [`FingerprintIndex::register`]
    /// (a dense 0-based index in registration order).
    pub id: u32,
    /// Exact Hamming distance (`0..=64`) between the query and this
    /// entry's code.
    pub distance: u32,
}

/// An exact nearest-neighbour index over 64-bit SimHash fingerprints,
/// backed by multi-index hashing (see the module docs).
#[derive(Clone, Debug)]
pub struct FingerprintIndex {
    /// Every registered code, indexed by registration id.
    codes: Vec<u64>,
    /// Number of substrings (`m`); `64 % substrings == 0`.
    substrings: u32,
    /// Bits per substring (`64 / substrings`).
    width: u32,
    /// Per-substring map from the substring's value to the ids of every
    /// code carrying that value in that position.
    tables: Vec<HashMap<u64, Vec<u32>>>,
}

impl Default for FingerprintIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintIndex {
    /// A new empty index with [`DEFAULT_SUBSTRINGS`] substrings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_substrings(DEFAULT_SUBSTRINGS)
    }

    /// A new empty index splitting each code into `substrings` parts.
    ///
    /// # Panics
    /// Panics if `substrings` is zero or does not divide 64 — both are
    /// build-time configuration errors, not runtime input.
    #[must_use]
    pub fn with_substrings(substrings: u32) -> Self {
        assert!(
            substrings != 0 && 64 % substrings == 0,
            "substring count must be a non-zero divisor of 64, got {substrings}"
        );
        Self {
            codes: Vec::new(),
            substrings,
            width: 64 / substrings,
            tables: (0..substrings).map(|_| HashMap::new()).collect(),
        }
    }

    /// Number of registered fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Whether the index holds no fingerprints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// The substring value of `code` at substring position `i`.
    fn substring(&self, code: u64, i: u32) -> u64 {
        let shift = i * self.width;
        let mask = if self.width == 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        (code >> shift) & mask
    }

    /// Register a single fingerprint, returning its registration id.
    /// Duplicate codes are allowed; each registration is a distinct id.
    pub fn register(&mut self, code: u64) -> u32 {
        // Registration ids are `u32`; a registry would need >4 billion
        // fingerprints to overflow (far beyond any realistic policy or
        // tenant dataset), so saturating is a safe degenerate bound that
        // matches the crate's `try_from(..).unwrap_or` convention.
        let id = u32::try_from(self.codes.len()).unwrap_or(u32::MAX);
        for i in 0..self.substrings {
            let key = self.substring(code, i);
            self.tables[i as usize].entry(key).or_default().push(id);
        }
        self.codes.push(code);
        id
    }

    /// Bulk-register `codes`, returning the id assigned to each in
    /// order. Equivalent to calling [`Self::register`] for each code but
    /// reserves capacity up front for a large batch.
    pub fn register_bulk<I>(&mut self, codes: I) -> Vec<u32>
    where
        I: IntoIterator<Item = u64>,
    {
        let iter = codes.into_iter();
        let (lower, _) = iter.size_hint();
        self.codes.reserve(lower);
        iter.map(|code| self.register(code)).collect()
    }

    /// The code registered under `id`, or `None` if out of range.
    #[must_use]
    pub fn code(&self, id: u32) -> Option<u64> {
        self.codes.get(id as usize).copied()
    }

    /// Every registered fingerprint within Hamming distance
    /// `max_distance` of `query`, each with its exact distance. The
    /// result is exact (identical to a brute-force scan); order is
    /// unspecified.
    #[must_use]
    pub fn query_within(&self, query: u64, max_distance: u32) -> Vec<Neighbor> {
        let mut out = Vec::new();
        if self.codes.is_empty() {
            return out;
        }

        // Small registry: the linear scan beats the index's fixed probe
        // cost and yields the same exact answer.
        if self.codes.len() <= LINEAR_FALLBACK_LEN {
            for (idx, &code) in self.codes.iter().enumerate() {
                let distance = (code ^ query).count_ones();
                if distance <= max_distance {
                    out.push(Neighbor {
                        id: u32::try_from(idx).unwrap_or(u32::MAX),
                        distance,
                    });
                }
            }
            return out;
        }

        // Multi-index search: per-substring radius is ⌊max_distance/m⌋.
        let sub_radius = max_distance / self.substrings;
        // Track ids already distance-checked so a candidate surfaced via
        // several substrings is verified at most once.
        let mut seen = vec![false; self.codes.len()];
        for i in 0..self.substrings {
            let q_sub = self.substring(query, i);
            let table = &self.tables[i as usize];
            enumerate_flips(self.width, sub_radius, |flip| {
                let Some(ids) = table.get(&(q_sub ^ flip)) else {
                    return;
                };
                for &id in ids {
                    let slot = &mut seen[id as usize];
                    if *slot {
                        continue;
                    }
                    *slot = true;
                    let distance = (self.codes[id as usize] ^ query).count_ones();
                    if distance <= max_distance {
                        out.push(Neighbor { id, distance });
                    }
                }
            });
        }
        out
    }

    /// The single nearest fingerprint within `max_distance` of `query`,
    /// or `None` if none is in range. Ties are broken by lowest id.
    #[must_use]
    pub fn nearest(&self, query: u64, max_distance: u32) -> Option<Neighbor> {
        self.query_within(query, max_distance)
            .into_iter()
            .min_by(|a, b| a.distance.cmp(&b.distance).then(a.id.cmp(&b.id)))
    }

    /// Whether any fingerprint is within `max_distance` of `query`.
    #[must_use]
    pub fn contains_within(&self, query: u64, max_distance: u32) -> bool {
        // A short-circuiting variant of the search: for the linear case
        // we can stop at the first hit; for the index case we reuse the
        // (already cheap) full query.
        if self.codes.len() <= LINEAR_FALLBACK_LEN {
            return self
                .codes
                .iter()
                .any(|&code| (code ^ query).count_ones() <= max_distance);
        }
        !self.query_within(query, max_distance).is_empty()
    }
}

/// Invoke `emit` once with every `width`-bit mask whose population
/// count is at most `radius` — i.e. every combination of up to `radius`
/// bit positions in `[0, width)`, including the empty (zero) mask. The
/// caller XORs each mask into a substring value to enumerate that
/// substring's Hamming-`radius` neighbourhood.
fn enumerate_flips(width: u32, radius: u32, mut emit: impl FnMut(u64)) {
    // k = 0: the value itself, no bits flipped.
    emit(0);
    let max_k = radius.min(width);
    for k in 1..=max_k {
        // Iterate combinations c[0] < c[1] < … < c[k-1] over [0, width)
        // in lexicographic order.
        let mut c: Vec<u32> = (0..k).collect();
        loop {
            let mut mask = 0u64;
            for &p in &c {
                mask |= 1u64 << p;
            }
            emit(mask);

            // Advance to the next combination: find the rightmost index
            // that can still be incremented (kept entirely in `u32` so
            // there is no signed-index cast). `i == k` is the
            // "none found" sentinel.
            let mut i = k;
            let mut found = false;
            while i > 0 {
                i -= 1;
                if c[i as usize] != width - k + i {
                    found = true;
                    break;
                }
            }
            if !found {
                break;
            }
            c[i as usize] += 1;
            let mut j = i + 1;
            while j < k {
                c[j as usize] = c[(j - 1) as usize] + 1;
                j += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic SplitMix64 PRNG so the at-scale tests are
    /// reproducible without pulling in an RNG dependency.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// Flip exactly `n` distinct bits of `code`, chosen by `rng`.
    fn flip_n_bits(mut code: u64, n: u32, rng: &mut SplitMix64) -> u64 {
        let mut flipped = 0u64;
        let mut count = 0;
        while count < n {
            let bit = (rng.next() % 64) as u32;
            if flipped & (1u64 << bit) == 0 {
                flipped |= 1u64 << bit;
                code ^= 1u64 << bit;
                count += 1;
            }
        }
        code
    }

    fn brute_force(codes: &[u64], query: u64, max_distance: u32) -> Vec<u32> {
        let mut ids: Vec<u32> = codes
            .iter()
            .enumerate()
            .filter(|&(_, &c)| (c ^ query).count_ones() <= max_distance)
            .map(|(i, _)| i as u32)
            .collect();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn enumerate_flips_counts_match_binomial() {
        // For width 16, radius 3: 1 + 16 + 120 + 560 = 697 masks, all
        // distinct, each with popcount <= 3.
        let mut seen = std::collections::HashSet::new();
        enumerate_flips(16, 3, |m| {
            assert!(m.count_ones() <= 3);
            assert!(seen.insert(m), "duplicate mask {m:#x}");
        });
        assert_eq!(seen.len(), 1 + 16 + 120 + 560);
    }

    #[test]
    fn empty_index_returns_nothing() {
        let idx = FingerprintIndex::new();
        assert!(idx.is_empty());
        assert!(idx.query_within(0, 12).is_empty());
        assert_eq!(idx.nearest(0, 12), None);
        assert!(!idx.contains_within(0, 12));
    }

    #[test]
    fn linear_path_exact_for_small_registry() {
        let mut idx = FingerprintIndex::new();
        let codes = [0u64, 0xFFFF_FFFF_FFFF_FFFF, 0x00FF_00FF_00FF_00FF, 1, 3, 7];
        idx.register_bulk(codes);
        assert!(idx.len() <= LINEAR_FALLBACK_LEN);
        for query in [0u64, 1, 0xFF, 0xFFFF_FFFF_FFFF_FFFF, 12345] {
            for r in [0u32, 1, 8, 12, 32] {
                let mut got: Vec<u32> = idx
                    .query_within(query, r)
                    .into_iter()
                    .map(|n| n.id)
                    .collect();
                got.sort_unstable();
                assert_eq!(got, brute_force(&codes, query, r), "query={query:#x} r={r}");
            }
        }
    }

    #[test]
    fn index_path_matches_brute_force_at_scale() {
        // Above LINEAR_FALLBACK_LEN so the multi-index path is taken.
        let mut rng = SplitMix64(0x1234_5678_9ABC_DEF0);
        let codes: Vec<u64> = (0..5000).map(|_| rng.next()).collect();
        let mut idx = FingerprintIndex::new();
        idx.register_bulk(codes.iter().copied());
        assert!(idx.len() > LINEAR_FALLBACK_LEN);

        for _ in 0..200 {
            let query = rng.next();
            for r in [0u32, 4, 8, 12] {
                let mut got: Vec<u32> = idx
                    .query_within(query, r)
                    .into_iter()
                    .map(|n| n.id)
                    .collect();
                got.sort_unstable();
                assert_eq!(got, brute_force(&codes, query, r), "query={query:#x} r={r}");
            }
        }
    }

    #[test]
    fn near_duplicates_found_exact_duplicates_too() {
        let mut rng = SplitMix64(0xDEAD_BEEF_CAFE_F00D);
        let mut codes: Vec<u64> = (0..3000).map(|_| rng.next()).collect();
        // Append a known base plus controlled near/non-near neighbours.
        let base = 0xA5A5_5A5A_0F0F_F0F0;
        codes.push(base);
        let mut idx = FingerprintIndex::new();
        idx.register_bulk(codes.iter().copied());

        // Exact duplicate of the base → distance 0, must be found.
        let dup = idx.nearest(base, 12).expect("exact match");
        assert_eq!(dup.distance, 0);

        // A query 11 bits away (<= 12) must surface the base.
        let near = flip_n_bits(base, 11, &mut rng);
        assert!(
            idx.query_within(near, 12)
                .iter()
                .any(|n| codes[n.id as usize] == base),
            "11-bit near-duplicate must match at radius 12"
        );

        // Cross-check the whole result set against brute force for the
        // near query.
        let mut got: Vec<u32> = idx
            .query_within(near, 12)
            .into_iter()
            .map(|n| n.id)
            .collect();
        got.sort_unstable();
        assert_eq!(got, brute_force(&codes, near, 12));
    }

    #[test]
    fn nearest_returns_minimum_distance() {
        let mut idx = FingerprintIndex::with_substrings(8);
        // Distances from query 0: 1, 2, 3 bits set respectively.
        idx.register(0b0001);
        idx.register(0b0011);
        idx.register(0b0111);
        let n = idx.nearest(0, 12).expect("in range");
        assert_eq!(n.distance, 1);
        assert_eq!(n.id, 0);
    }

    #[test]
    fn substring_counts_all_agree() {
        // Each substring count must yield the identical exact result on
        // the multi-index path. (Counts below 4 leave a per-substring
        // radius wide enough that flip enumeration is needlessly large
        // for the engine's distance-12 threshold, so they are not used
        // in practice; 4..=64 all keep enumeration small.)
        let mut rng = SplitMix64(7);
        let codes: Vec<u64> = (0..2000).map(|_| rng.next()).collect();
        let query = rng.next();
        let expected = brute_force(&codes, query, 12);
        for m in [4u32, 8, 16, 32, 64] {
            let mut idx = FingerprintIndex::with_substrings(m);
            idx.register_bulk(codes.iter().copied());
            let mut got: Vec<u32> = idx
                .query_within(query, 12)
                .into_iter()
                .map(|n| n.id)
                .collect();
            got.sort_unstable();
            assert_eq!(got, expected, "substrings={m}");
        }
    }
}
