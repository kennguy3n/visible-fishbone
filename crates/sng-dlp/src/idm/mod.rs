// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `idm` — Indexed Document Matching for endpoint DLP.
//!
//! IDM detects *partial or derivative copies of whole protected
//! documents*. Where the existing SimHash fingerprint
//! ([`crate::fingerprint`]) answers "is this blob a near-duplicate of
//! one registered blob?" with a single fuzzy 64-bit code, IDM answers
//! the complementary question Netskope-class DLP also covers: "does
//! this inspected content *contain* a passage lifted from one of my
//! protected documents, even after edits, reordering, or being pasted
//! into a larger file?".
//!
//! # Algorithm
//!
//! The module uses the classic **k-shingling + winnowing** scheme
//! (Schleimer, Wilkerson & Aiken, 2003 — the technique behind MOSS),
//! adapted to reuse this crate's fingerprint conventions:
//!
//! 1. **Tokenize** the text with the same script-aware rule the
//!    SimHash path uses (whitespace tokens for space-delimited
//!    scripts; CJK bigrams; Thai trigrams), so IDM and SimHash agree
//!    on what a "token" is.
//! 2. **Shingle** into overlapping windows of `shingle_size` tokens
//!    joined by a single space.
//! 3. **Hash** each shingle to a 64-bit code with the crate-standard
//!    primitive: SHA-256 truncated to the leading 8 bytes, big-endian
//!    (identical to [`crate::classifier::simhash`]'s per-token hash).
//! 4. **Winnow**: slide a window of `window` consecutive shingle
//!    hashes and keep the minimum in each window (rightmost on ties).
//!    Winnowing guarantees that any shared passage of at least
//!    `window + shingle_size - 1` tokens contributes at least one
//!    common fingerprint, while bounding the fingerprint density to
//!    roughly `2 / (window + 1)` of the shingles.
//! 5. **Cap**: keep at most `max_fingerprints` per document (the
//!    numerically smallest, a stable bottom-`k` sample) so a single
//!    protected document can never blow the per-tenant memory budget.
//!
//! The resulting `Vec<u64>` is the document's fingerprint set — the
//! only thing ever persisted or distributed. The raw document is
//! never stored (see the control-plane service `internal/service/
//! dlpidm`, which computes the identical fingerprints in Go and keeps
//! only the hashes).
//!
//! # Matching
//!
//! [`IdmIndex`] holds an inverted index `fingerprint -> [document]`.
//! A query shingles + winnows the inspected content the same way and,
//! for each protected document, computes **containment** — the
//! fraction of that document's fingerprints present in the inspected
//! content. A document is reported when its containment is at least
//! the configured threshold. Containment (asymmetric) is the right
//! score for "small protected doc embedded in a large inspected
//! stream"; Jaccard would be diluted by the size mismatch.
//!
//! # Bounded cost (no-ops SaaS, 5,000 SME tenants)
//!
//! Every entry point is bounded with no tenant tuning required:
//!
//! * Document and query content are truncated to `max_scan_bytes`
//!   (default 1 MiB) before shingling, so worst-case work is linear
//!   in a fixed cap, not in attacker-controlled input size.
//! * Per-document fingerprints are capped (`max_fingerprints`,
//!   default 2048 → 16 KiB of `u64`).
//! * Index memory is `O(total fingerprints)`; the inverted index
//!   never stores document text.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Default shingle width in tokens. Five-token shingles are long
/// enough that incidental phrase collisions between unrelated
/// documents are rare, yet short enough to survive light editing of a
/// copied passage.
pub const DEFAULT_SHINGLE_SIZE: usize = 5;

/// Default winnowing window. With [`DEFAULT_SHINGLE_SIZE`] this
/// guarantees detection of any shared run of `8 + 5 - 1 = 12` or more
/// tokens.
pub const DEFAULT_WINNOW_WINDOW: usize = 8;

/// Default per-document fingerprint cap. 2048 × 8 bytes = 16 KiB per
/// protected document, the stable bottom-`k` smallest fingerprints.
pub const DEFAULT_MAX_FINGERPRINTS: usize = 2048;

/// Default similarity (containment) threshold for reporting a match.
/// Reuses the crate-wide fingerprint threshold so IDM and the SimHash
/// near-duplicate path agree on "how similar is similar enough".
pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = crate::classifier::FINGERPRINT_SIMILARITY_THRESHOLD;

/// Default byte cap applied to document and query content before
/// shingling. Mirrors the classifier's scan cap so an image, a paste,
/// and a protected-document upload are all bounded identically.
pub const DEFAULT_MAX_SCAN_BYTES: usize = crate::classifier::DEFAULT_MAX_SCAN_BYTES;

/// Parameters controlling fingerprint generation. The defaults are
/// the no-ops values; tenants never tune these. They are exposed so
/// the control plane can pin the exact values it used to compute a
/// stored set (forward-compatibility if a future bundle revises the
/// defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintParams {
    /// Number of tokens per shingle (k). Clamped to at least 1.
    pub shingle_size: usize,
    /// Winnowing window width over shingle hashes. Clamped to at
    /// least 1.
    pub window: usize,
    /// Maximum fingerprints kept per document. Clamped to at least 1.
    pub max_fingerprints: usize,
    /// Byte cap applied to content before shingling.
    pub max_scan_bytes: usize,
}

impl Default for FingerprintParams {
    fn default() -> Self {
        Self {
            shingle_size: DEFAULT_SHINGLE_SIZE,
            window: DEFAULT_WINNOW_WINDOW,
            max_fingerprints: DEFAULT_MAX_FINGERPRINTS,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        }
    }
}

impl FingerprintParams {
    /// Returns the parameters with every field clamped into its valid
    /// range. Calling this is idempotent and cheap; all entry points
    /// apply it so a misconfigured bundle can never produce a panic
    /// (zero window, zero shingle size) or an unbounded run.
    #[must_use]
    fn sanitized(self) -> Self {
        Self {
            shingle_size: self.shingle_size.max(1),
            window: self.window.max(1),
            max_fingerprints: self.max_fingerprints.max(1),
            max_scan_bytes: self.max_scan_bytes.max(1),
        }
    }
}

/// Compute the fingerprint set of a protected document.
///
/// The returned vector is **sorted ascending, de-duplicated, and
/// capped** to `params.max_fingerprints`. This canonical form is what
/// the control plane persists and distributes, and is byte-for-byte
/// reproducible across the Rust edge and the Go control plane (see the
/// parity golden vector in the tests and in `internal/service/
/// dlpidm`).
#[must_use]
pub fn fingerprint_document(text: &str, params: &FingerprintParams) -> Vec<u64> {
    let params = params.sanitized();
    let scanned = truncate_on_char_boundary(text, params.max_scan_bytes);
    let tokens = tokenize(scanned);
    let shingle_hashes = shingle_hashes(&tokens, params.shingle_size);
    let winnowed = winnow(&shingle_hashes, params.window);
    finalize(winnowed, params.max_fingerprints)
}

/// One protected document registered in an [`IdmIndex`].
#[derive(Debug, Clone)]
pub struct IndexedDocument {
    /// Opaque identifier (the control plane uses the fingerprint-set
    /// row id; tests use a human-readable label). Echoed back in
    /// [`IdmMatch::document_id`].
    pub id: String,
    /// The document's canonical fingerprint set (as produced by
    /// [`fingerprint_document`]). Need not be sorted; the index
    /// de-duplicates on insert.
    pub fingerprints: Vec<u64>,
}

/// A reported partial/derivative-copy match.
#[derive(Debug, Clone, PartialEq)]
pub struct IdmMatch {
    /// Identifier of the protected document that was (partially)
    /// found in the inspected content.
    pub document_id: String,
    /// Fraction in `[0, 1]` of the protected document's fingerprints
    /// present in the inspected content.
    pub containment: f64,
    /// Number of the document's fingerprints found in the query.
    pub matched_fingerprints: usize,
    /// Total fingerprints in the protected document (the containment
    /// denominator).
    pub document_fingerprints: usize,
}

/// An inverted index over protected-document fingerprints supporting
/// bounded containment queries.
///
/// Build once from a tenant's distributed fingerprint sets, then query
/// repeatedly on the inspection hot path. The index stores only
/// `u64` fingerprints and per-document counts — never document text.
#[derive(Debug, Clone)]
pub struct IdmIndex {
    /// `fingerprint -> sorted, de-duplicated document indices`.
    postings: HashMap<u64, Vec<u32>>,
    /// Per-document id and fingerprint count, indexed by the `u32`
    /// used in `postings`.
    documents: Vec<DocumentEntry>,
    /// Containment threshold at or above which a document is reported.
    threshold: f64,
}

#[derive(Debug, Clone)]
struct DocumentEntry {
    id: String,
    fingerprint_count: usize,
}

impl IdmIndex {
    /// Create an empty index with the given containment threshold.
    /// The threshold is clamped to `[0, 1]`.
    #[must_use]
    pub fn new(threshold: f64) -> Self {
        Self {
            postings: HashMap::new(),
            documents: Vec::new(),
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Build an index from a set of protected documents.
    pub fn build<I>(documents: I, threshold: f64) -> Self
    where
        I: IntoIterator<Item = IndexedDocument>,
    {
        let mut index = Self::new(threshold);
        for document in documents {
            index.add_document(document);
        }
        index
    }

    /// Number of protected documents registered.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    /// Number of distinct fingerprints in the inverted index.
    #[must_use]
    pub fn fingerprint_count(&self) -> usize {
        self.postings.len()
    }

    /// True when no documents are registered (the common, off-hot-path
    /// case for a tenant with no protected-document sets).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Register one protected document. The fingerprint set is
    /// de-duplicated; documents with no fingerprints are still
    /// recorded (they simply never match).
    pub fn add_document(&mut self, document: IndexedDocument) {
        // `u32` document ids keep the postings compact. A tenant that
        // somehow exceeds 4 billion protected documents is far outside
        // the SME envelope; guard rather than wrap.
        let Ok(doc_id) = u32::try_from(self.documents.len()) else {
            return;
        };
        let mut fingerprints = document.fingerprints;
        fingerprints.sort_unstable();
        fingerprints.dedup();
        let fingerprint_count = fingerprints.len();
        for fingerprint in fingerprints {
            let docs = self.postings.entry(fingerprint).or_default();
            // Fingerprints within a document are unique here, so the
            // id is never already present for this fingerprint.
            docs.push(doc_id);
        }
        self.documents.push(DocumentEntry {
            id: document.id,
            fingerprint_count,
        });
    }

    /// Query the index with inspected content, returning every
    /// protected document whose containment meets the threshold.
    ///
    /// Results are sorted by descending containment, then by document
    /// id, for deterministic output. Bounded by `params.max_scan_bytes`.
    #[must_use]
    pub fn query(&self, text: &str, params: &FingerprintParams) -> Vec<IdmMatch> {
        if self.documents.is_empty() {
            return Vec::new();
        }
        let params = params.sanitized();
        let scanned = truncate_on_char_boundary(text, params.max_scan_bytes);
        let tokens = tokenize(scanned);
        let shingle_hashes = shingle_hashes(&tokens, params.shingle_size);
        let mut query_fingerprints = winnow(&shingle_hashes, params.window);
        query_fingerprints.sort_unstable();
        query_fingerprints.dedup();

        // Tally, per document, how many of ITS fingerprints appear in
        // the query. Query fingerprints are distinct and each posting
        // list holds distinct document ids, so a simple increment can
        // never double-count a (document, fingerprint) pair.
        let mut matched = vec![0usize; self.documents.len()];
        for fingerprint in &query_fingerprints {
            if let Some(docs) = self.postings.get(fingerprint) {
                for &doc_id in docs {
                    if let Some(slot) = matched.get_mut(doc_id as usize) {
                        *slot += 1;
                    }
                }
            }
        }

        let mut results = Vec::new();
        for (idx, entry) in self.documents.iter().enumerate() {
            let count = matched.get(idx).copied().unwrap_or(0);
            if count == 0 || entry.fingerprint_count == 0 {
                continue;
            }
            let containment = containment_ratio(count, entry.fingerprint_count);
            if containment >= self.threshold {
                results.push(IdmMatch {
                    document_id: entry.id.clone(),
                    containment,
                    matched_fingerprints: count,
                    document_fingerprints: entry.fingerprint_count,
                });
            }
        }
        results.sort_by(|a, b| {
            b.containment
                .partial_cmp(&a.containment)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.document_id.cmp(&b.document_id))
        });
        results
    }
}

/// Containment ratio `matched / total`. Both operands are bounded by
/// `max_fingerprints` (a few thousand at most), far below `2^53`, so the `f64`
/// conversion is exact — the allow simply documents that the cast is deliberate
/// and lossless for the values this code can ever produce.
#[allow(clippy::cast_precision_loss)]
fn containment_ratio(matched: usize, total: usize) -> f64 {
    matched as f64 / total as f64
}

// --- Fingerprint primitives ------------------------------------------------

/// Truncate `text` to at most `max_bytes`, never splitting a UTF-8
/// character. Returns a sub-slice (no allocation).
fn truncate_on_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    // SAFETY-free: `end` is a validated char boundary in `0..=len`.
    text.get(..end).unwrap_or("")
}

/// Hash one shingle to a 64-bit code: SHA-256, leading 8 bytes,
/// big-endian. Identical primitive to [`crate::classifier::simhash`].
fn hash_shingle(shingle: &str) -> u64 {
    let digest = Sha256::digest(shingle.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

/// Overlapping `k`-token shingles hashed to 64-bit codes. Shingles
/// join their tokens with a single space so the hashed string is
/// unambiguous. When the document has fewer than `k` tokens the whole
/// token sequence becomes one shingle, so short protected documents
/// still fingerprint.
fn shingle_hashes(tokens: &[String], k: usize) -> Vec<u64> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < k {
        return vec![hash_shingle(&tokens.join(" "))];
    }
    let mut hashes = Vec::with_capacity(tokens.len() - k + 1);
    for window in tokens.windows(k) {
        hashes.push(hash_shingle(&window.join(" ")));
    }
    hashes
}

/// Winnowing over shingle hashes (Schleimer et al.). In each window of
/// `window` consecutive hashes the minimum is selected; on ties the
/// rightmost position wins; a fingerprint is recorded only when the
/// selected position changes from the previous window. The window is
/// clamped to the input length so short inputs yield a single global
/// minimum. The returned vector preserves selection order and may
/// contain repeats across distant windows; callers de-duplicate.
fn winnow(hashes: &[u64], window: usize) -> Vec<u64> {
    if hashes.is_empty() {
        return Vec::new();
    }
    let w = window.max(1).min(hashes.len());
    let last_start = hashes.len() - w;
    let mut selected = Vec::new();
    let mut prev_pos: Option<usize> = None;
    for start in 0..=last_start {
        let mut min_pos = start;
        for pos in start..start + w {
            // `<=` makes the rightmost minimum win on ties, matching
            // the Go control-plane port exactly.
            if hashes.get(pos) <= hashes.get(min_pos) {
                min_pos = pos;
            }
        }
        if prev_pos != Some(min_pos) {
            if let Some(value) = hashes.get(min_pos) {
                selected.push(*value);
            }
            prev_pos = Some(min_pos);
        }
    }
    selected
}

/// Sort ascending, de-duplicate, and keep at most `max` fingerprints
/// (the numerically smallest — a stable bottom-`k` sample independent
/// of document order). This is the canonical, reproducible form.
fn finalize(mut fingerprints: Vec<u64>, max: usize) -> Vec<u64> {
    fingerprints.sort_unstable();
    fingerprints.dedup();
    if fingerprints.len() > max {
        fingerprints.truncate(max);
    }
    fingerprints
}

// --- Tokenization (script-aware, parity-locked with SimHash) ---------------

/// True if `c` is a CJK Unified Ideograph (U+4E00..=U+9FFF).
fn is_cjk(c: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&c)
}

/// True if `c` is in the Thai block (U+0E00..=U+0E7F).
fn is_thai(c: char) -> bool {
    ('\u{0E00}'..='\u{0E7F}').contains(&c)
}

/// Tokenize `text` with the same script-aware rule the SimHash path
/// uses ([`crate::classifier::simhash`]): CJK → character bigrams,
/// Thai → character trigrams, otherwise whitespace-delimited tokens.
/// Keeping the rule identical means IDM and SimHash agree on token
/// boundaries for every script.
fn tokenize(text: &str) -> Vec<String> {
    let has_cjk = text.chars().any(is_cjk);
    let has_thai = !has_cjk && text.chars().any(is_thai);
    if has_cjk {
        return char_shingles(text, 2);
    }
    if has_thai {
        return char_shingles(text, 3);
    }
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Overlapping character `n`-grams over the non-whitespace characters
/// of `text`. Fewer than `n` characters collapse to a single token.
fn char_shingles(text: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.is_empty() {
        return Vec::new();
    }
    if chars.len() < n {
        return vec![chars.into_iter().collect()];
    }
    (0..=chars.len() - n)
        .map(|i| {
            chars
                .get(i..i + n)
                .map(|s| s.iter().collect())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests;
