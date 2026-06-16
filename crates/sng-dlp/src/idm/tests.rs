// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

use super::*;

const LOREM: &str = "the quick brown fox jumps over the lazy dog while the \
    diligent engineer reviews the quarterly financial report before the \
    board meeting and the auditor signs the compliance attestation for the \
    regulated tenant in the secure access service edge platform deployment";

#[test]
fn winnow_picks_rightmost_minimum_on_ties() {
    // Window 2 over [3,1,1,2]: windows (3,1)->pos1, (1,1)->pos2 (rightmost
    // tie), (1,2)->pos2 (carried). Selections at pos1 then pos2.
    let hashes = [3u64, 1, 1, 2];
    assert_eq!(winnow(&hashes, 2), vec![1, 1]);
}

#[test]
fn winnow_empty_and_short_inputs() {
    assert!(winnow(&[], 4).is_empty());
    // Window larger than input collapses to the single global minimum.
    assert_eq!(winnow(&[9u64, 4, 7], 8), vec![4]);
}

#[test]
fn fingerprint_document_is_sorted_unique_and_deterministic() {
    let params = FingerprintParams::default();
    let a = fingerprint_document(LOREM, &params);
    let b = fingerprint_document(LOREM, &params);
    assert_eq!(a, b, "fingerprinting must be deterministic");
    assert!(!a.is_empty());
    assert!(
        a.windows(2).all(|w| w[0] < w[1]),
        "sorted ascending + unique"
    );
}

#[test]
fn fingerprint_document_respects_cap() {
    let params = FingerprintParams {
        shingle_size: 3,
        window: 2,
        max_fingerprints: 5,
        ..FingerprintParams::default()
    };
    let fps = fingerprint_document(LOREM, &params);
    assert!(
        fps.len() <= 5,
        "cap must bound fingerprint count, got {}",
        fps.len()
    );
}

#[test]
fn fingerprint_document_handles_empty_and_tiny_inputs() {
    let params = FingerprintParams::default();
    assert!(fingerprint_document("", &params).is_empty());
    // Fewer tokens than the shingle size still yields one fingerprint.
    assert_eq!(fingerprint_document("only three words", &params).len(), 1);
}

#[test]
fn partial_copy_detected_above_threshold() {
    // Protected document.
    let protected = LOREM;
    let protected_fps = fingerprint_document(protected, &FingerprintParams::default());

    // Inspected content: unrelated preamble + a verbatim ~60% slice of the
    // protected document + unrelated trailer (a classic "lifted passage
    // pasted into a bigger file" scenario).
    let tokens: Vec<&str> = protected.split_whitespace().collect();
    let slice = tokens[..(tokens.len() * 6 / 10)].join(" ");
    let inspected = format!(
        "unrelated marketing copy about our weekend sale and free shipping \
         offer {slice} followed by more unrelated newsletter footer text \
         and an unsubscribe link at the very bottom"
    );

    let index = IdmIndex::build(
        [IndexedDocument {
            id: "protected-doc".to_string(),
            fingerprints: protected_fps.clone(),
        }],
        0.3,
    );
    let matches = index.query(&inspected, &FingerprintParams::default());
    assert_eq!(matches.len(), 1, "expected the partial copy to be flagged");
    let m = &matches[0];
    assert_eq!(m.document_id, "protected-doc");
    assert!(
        m.containment >= 0.3,
        "containment {} below threshold",
        m.containment
    );
    assert_eq!(m.document_fingerprints, protected_fps.len());
    assert!(m.matched_fingerprints > 0);
}

#[test]
fn unrelated_content_does_not_false_positive() {
    let protected_fps = fingerprint_document(LOREM, &FingerprintParams::default());
    let index = IdmIndex::build(
        [IndexedDocument {
            id: "protected-doc".to_string(),
            fingerprints: protected_fps,
        }],
        0.3,
    );
    let unrelated = "completely different content discussing astronomy the \
        formation of galaxies stellar nucleosynthesis and the cosmic \
        microwave background radiation across deep time and space";
    let matches = index.query(unrelated, &FingerprintParams::default());
    assert!(
        matches.is_empty(),
        "unrelated text must not match: {matches:?}"
    );
}

#[test]
fn empty_index_returns_no_matches() {
    let index = IdmIndex::new(0.3);
    assert!(index.is_empty());
    assert!(index.query(LOREM, &FingerprintParams::default()).is_empty());
}

#[test]
fn index_counts_reflect_registered_documents() {
    let fps = fingerprint_document(LOREM, &FingerprintParams::default());
    let index = IdmIndex::build(
        [
            IndexedDocument {
                id: "a".into(),
                fingerprints: fps.clone(),
            },
            IndexedDocument {
                id: "b".into(),
                fingerprints: fps.clone(),
            },
        ],
        0.5,
    );
    assert_eq!(index.document_count(), 2);
    // Both documents share the same fingerprints, so distinct count == one
    // document's fingerprint count.
    assert_eq!(index.fingerprint_count(), fps.len());
}

#[test]
fn exact_copy_is_full_containment() {
    let fps = fingerprint_document(LOREM, &FingerprintParams::default());
    let index = IdmIndex::build(
        [IndexedDocument {
            id: "doc".into(),
            fingerprints: fps,
        }],
        0.9,
    );
    let matches = index.query(LOREM, &FingerprintParams::default());
    assert_eq!(matches.len(), 1);
    assert!(
        (matches[0].containment - 1.0).abs() < 1e-9,
        "exact copy => containment 1.0"
    );
}

#[test]
fn cjk_text_fingerprints_via_bigrams() {
    // CJK has no spaces; tokenization must still yield shingles so the
    // document fingerprints (non-empty) and an exact copy is detected.
    let cjk = "机密文件内容需要受到保护防止数据泄露和未经授权的访问与传播";
    let fps = fingerprint_document(cjk, &FingerprintParams::default());
    assert!(!fps.is_empty(), "CJK document must fingerprint");
    let index = IdmIndex::build(
        [IndexedDocument {
            id: "cjk".into(),
            fingerprints: fps,
        }],
        0.9,
    );
    assert_eq!(index.query(cjk, &FingerprintParams::default()).len(), 1);
}

/// Cross-language parity golden vector. These exact fingerprints are
/// reproduced by the Go control-plane port
/// (`internal/service/dlpidm`); if either side changes the shingling,
/// hashing, winnowing, or cap, this and the Go test break together.
#[test]
fn parity_golden_vector() {
    let params = FingerprintParams {
        shingle_size: 3,
        window: 4,
        max_fingerprints: 8,
        max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
    };
    let fps = fingerprint_document("the quick brown fox jumps over the lazy dog", &params);
    assert_eq!(fps, GOLDEN_VECTOR);
}

const GOLDEN_VECTOR: &[u64] = &[
    9_093_497_140_874_896_414,
    9_727_984_356_536_241_109,
    11_621_772_664_254_813_023,
];
