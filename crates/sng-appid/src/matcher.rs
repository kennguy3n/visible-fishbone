//! Bounded-time application matcher compiled from a [`Catalog`].
//!
//! # Design / cost characteristics
//! The matcher pre-compiles the catalog into hash structures so a
//! single identification does a bounded, input-independent amount of
//! work — there is no regex and no backtracking, so adversarial input
//! cannot trigger super-linear blow-up (a hard requirement for a
//! no-ops SaaS fronting 5,000 tenants).
//!
//! Per identification the matcher does at most:
//! - `O(labels)` hash lookups for SNI and for Host, with `labels`
//!   capped at [`MAX_HOST_LABELS`] (longest-suffix wins per app);
//! - one hash lookup for JA3;
//! - a linear scan of the (small, fixed) byte-probe table;
//! - one pass over the handful of candidate apps to apply port /
//!   transport modifiers and pick the best.
//!
//! Memory is bounded by the catalog size; nothing is allocated per
//! connection beyond a single lowercased copy of the host name and a
//! small candidate map.

use std::collections::{HashMap, HashSet};

use crate::catalog::Catalog;
use crate::features::{AppMatch, ConnFeatures, MAX_HOST_LABELS, MAX_PROBE_BYTES, Transport};
use crate::signature::normalise_host;

/// DNS names are at most 255 bytes; a longer "host" is bogus and is
/// ignored so the matcher never scans an unbounded string.
const MAX_HOST_NAME_LEN: usize = 255;

/// Added when a host suffix matches the *entire* observed name (an
/// exact host match is more specific than a parent-domain suffix).
const EXACT_BONUS: i32 = 5;

/// Added to an app that is already a candidate (via host/SNI/bytes)
/// when its JA3 fingerprint also matches — corroboration.
const JA3_BONUS: i32 = 5;

/// Confidence assigned to an app matched *only* by JA3. JA3 hashes
/// collide across apps, so on its own it is a weak signal.
const JA3_ONLY_CONFIDENCE: i32 = 40;

/// Small reward when the observed port is one the app is known to use.
const PORT_MATCH_BONUS: i32 = 2;

/// Small penalty when the app declares ports and the observed port is
/// not among them (a hint, never disqualifying).
const PORT_MISMATCH_PENALTY: i32 = 5;

/// Penalty when the observed transport disagrees with the app's
/// declared transport (a hint, never disqualifying).
const TRANSPORT_MISMATCH_PENALTY: i32 = 10;

/// Compact, match-time projection of an [`crate::signature::AppSignature`].
#[derive(Debug, Clone)]
struct AppMeta {
    app_id: String,
    category: String,
    confidence: u8,
    transport: Transport,
    ports: Vec<u16>,
}

/// A pre-compiled, bounded-time application matcher.
#[derive(Debug, Clone, Default)]
pub struct Matcher {
    apps: Vec<AppMeta>,
    /// Host suffix (lowercase, dotted) -> indices of apps claiming it.
    /// Shared by SNI and HTTP Host lookups (both are host names).
    host_suffix_map: HashMap<String, Vec<usize>>,
    /// JA3 hash (lowercase hex) -> indices of apps hinting at it.
    ja3_map: HashMap<String, Vec<usize>>,
    /// (leading-byte probe, app index) pairs; small and fixed.
    byte_prefixes: Vec<(Vec<u8>, usize)>,
}

impl Matcher {
    /// Compiles a matcher from a validated catalog.
    #[must_use]
    pub fn from_catalog(catalog: &Catalog) -> Self {
        let sigs = catalog.signatures();
        let mut apps = Vec::with_capacity(sigs.len());
        let mut host_suffix_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut ja3_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut byte_prefixes: Vec<(Vec<u8>, usize)> = Vec::new();

        for (idx, sig) in sigs.iter().enumerate() {
            for suffix in sig.sni_suffixes.iter().chain(sig.host_suffixes.iter()) {
                let bucket = host_suffix_map.entry(suffix.clone()).or_default();
                if !bucket.contains(&idx) {
                    bucket.push(idx);
                }
            }
            for ja3 in &sig.ja3 {
                ja3_map.entry(ja3.clone()).or_default().push(idx);
            }
            for probe in &sig.byte_prefixes {
                byte_prefixes.push((probe.clone(), idx));
            }
            apps.push(AppMeta {
                app_id: sig.app_id.clone(),
                category: sig.category.clone(),
                confidence: sig.confidence,
                transport: sig.transport,
                ports: sig.ports.clone(),
            });
        }

        Self {
            apps,
            host_suffix_map,
            ja3_map,
            byte_prefixes,
        }
    }

    /// Returns the process-wide matcher compiled from the embedded
    /// baseline catalog. Compiled lazily on first use.
    #[must_use]
    pub fn builtin() -> &'static Matcher {
        use std::sync::OnceLock;
        static BUILTIN: OnceLock<Matcher> = OnceLock::new();
        BUILTIN.get_or_init(|| Self::from_catalog(Catalog::builtin()))
    }

    /// Number of applications the matcher knows about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    /// Whether the matcher knows about no applications.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Identifies the application for a set of connection features,
    /// returning the single best match or `None` if nothing matched
    /// with non-zero confidence.
    ///
    /// Runs in bounded time regardless of input (see the module-level
    /// cost notes) and never panics on adversarial input.
    #[must_use]
    pub fn identify(&self, feat: &ConnFeatures<'_>) -> Option<AppMatch> {
        let mut scores: HashMap<usize, i32> = HashMap::new();

        // Strong host signals: longest-suffix match on SNI and Host.
        if let Some(sni) = feat.sni {
            self.accumulate_host(sni, &mut scores);
        }
        if let Some(host) = feat.host {
            self.accumulate_host(host, &mut scores);
        }

        // Byte-probe protocols (SSH, RDP, SMB, BitTorrent, …).
        if let Some(first_bytes) = feat.first_bytes {
            let probe = &first_bytes[..first_bytes.len().min(MAX_PROBE_BYTES)];
            for (prefix, idx) in &self.byte_prefixes {
                if probe.starts_with(prefix) {
                    upsert_max(&mut scores, *idx, i32::from(self.apps[*idx].confidence));
                }
            }
        }

        // JA3: corroborates an existing candidate, otherwise a weak
        // standalone signal.
        if let Some(ja3) = feat.ja3 {
            let ja3 = ja3.trim().to_ascii_lowercase();
            if let Some(bucket) = self.ja3_map.get(&ja3) {
                for &idx in bucket {
                    scores
                        .entry(idx)
                        .and_modify(|s| *s += JA3_BONUS)
                        .or_insert(JA3_ONLY_CONFIDENCE);
                }
            }
        }

        if scores.is_empty() {
            return None;
        }

        // Port / transport hints nudge candidates without disqualifying.
        for (idx, score) in &mut scores {
            let meta = &self.apps[*idx];
            if let Some(transport) = feat.transport
                && transport != meta.transport
            {
                *score -= TRANSPORT_MISMATCH_PENALTY;
            }
            if let Some(port) = feat.port
                && !meta.ports.is_empty()
            {
                if meta.ports.contains(&port) {
                    *score += PORT_MATCH_BONUS;
                } else {
                    *score -= PORT_MISMATCH_PENALTY;
                }
            }
        }

        self.best(&scores)
    }

    /// Walks the suffixes of `host` from longest to shortest, recording
    /// each candidate app at its single longest (most specific)
    /// matching suffix. Updates `scores` keeping the max per app.
    fn accumulate_host(&self, host: &str, scores: &mut HashMap<usize, i32>) {
        let host = normalise_host(host);
        if host.is_empty() || host.len() > MAX_HOST_NAME_LEN {
            return;
        }

        // Byte offsets at which each progressively shorter suffix
        // begins: 0 (full name), then just after each dot.
        let mut offsets: Vec<usize> = Vec::with_capacity(MAX_HOST_LABELS);
        offsets.push(0);
        for (pos, _) in host.match_indices('.') {
            offsets.push(pos + 1);
        }
        // Keep only suffixes with at most MAX_HOST_LABELS labels.
        let start = offsets.len().saturating_sub(MAX_HOST_LABELS);

        let mut seen: HashSet<usize> = HashSet::new();
        for &offset in offsets.iter().skip(start) {
            let Some(suffix) = host.get(offset..) else {
                continue;
            };
            let is_exact = offset == 0;
            if let Some(bucket) = self.host_suffix_map.get(suffix) {
                for &idx in bucket {
                    // First time we see an app is at its longest suffix.
                    if seen.insert(idx) {
                        let mut base = i32::from(self.apps[idx].confidence);
                        if is_exact {
                            base += EXACT_BONUS;
                        }
                        upsert_max(scores, idx, base);
                    }
                }
            }
        }
    }

    /// Picks the highest-scoring candidate, breaking ties by ascending
    /// `app_id` for determinism. Returns `None` if the best clamps to
    /// zero confidence.
    fn best(&self, scores: &HashMap<usize, i32>) -> Option<AppMatch> {
        let mut best: Option<(usize, i32)> = None;
        for (&idx, &score) in scores {
            match best {
                None => best = Some((idx, score)),
                Some((best_idx, best_score)) => {
                    let better = score > best_score
                        || (score == best_score
                            && self.apps[idx].app_id < self.apps[best_idx].app_id);
                    if better {
                        best = Some((idx, score));
                    }
                }
            }
        }

        let (idx, score) = best?;
        let confidence = u8::try_from(score.clamp(0, 100)).unwrap_or(0);
        if confidence == 0 {
            return None;
        }
        let meta = &self.apps[idx];
        Some(AppMatch {
            app_id: meta.app_id.clone(),
            category: meta.category.clone(),
            confidence,
        })
    }
}

/// Inserts `val` for `idx`, or keeps the larger of the existing and new
/// value.
fn upsert_max(scores: &mut HashMap<usize, i32>, idx: usize, val: i32) {
    scores
        .entry(idx)
        .and_modify(|s| {
            if val > *s {
                *s = val;
            }
        })
        .or_insert(val);
}
