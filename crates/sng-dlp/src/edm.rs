//! Exact-Data-Match (EDM): match content against an operator's
//! registered sensitive records (a customer PII table, a price list, a
//! patient roster) without ever storing the plaintext.
//!
//! ## What is stored — and what is not
//!
//! An operator registers a dataset of sensitive *cell values* (one
//! string per record — e.g. a full name, an account number, an email).
//! Registration ([`EdmDataset::register`]) **immediately** reduces each
//! value to a salted [`HMAC-SHA256`](hmac_sha256) digest and discards
//! the plaintext: the transient normalized buffer is
//! [`Zeroize`]d before it leaves the function. The resulting
//! [`EdmDataset`] holds only
//!
//! * the per-dataset random `salt`,
//! * the set of 32-byte digests, and
//! * the set of token-window lengths present in the dataset
//!
//! so it is safe to ship inside the signed, tenant-scoped endpoint
//! bundle and to persist server-side (migration 067). The original
//! records cannot be recovered from it: HMAC-SHA256 is a one-way
//! function and the salt defeats cross-tenant precomputed-dictionary
//! attacks. This is the privacy contract the [`crate`]-level redaction
//! invariant requires — see [`registration_keeps_no_plaintext`] for the
//! test that pins it.
//!
//! ## Why the salt ships to the endpoint
//!
//! To decide whether incoming content contains a registered value the
//! endpoint must recompute `HMAC(salt, window)` and test set
//! membership, so it needs the salt. The salt is not a password — it is
//! a per-dataset diversifier that ships only inside the Ed25519-signed,
//! per-tenant bundle. Plaintext PII never travels and is never stored;
//! only salt + digests do.
//!
//! ## Matching model
//!
//! Cell values are frequently multi-word ("Jane Doe", "123 Main St").
//! Registration records, per dataset, the *set* of token counts it
//! contains; detection ([`CompiledEdm::matches`]) slides a window of
//! each such length over the normalized token stream of the content and
//! tests each window's digest against the set. Both sides canonicalize
//! identically (NFKC, lowercased, punctuation-trimmed tokens joined by a
//! single space), so a value registered once matches the same text
//! wherever it appears. Window lengths are bounded by
//! [`MAX_EDM_WINDOW_TOKENS`] to keep detection linear in the content
//! size regardless of dataset contents.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// Length in bytes of a dataset salt and of each digest (SHA-256).
pub const EDM_SALT_LEN: usize = 32;
/// Byte length of one stored digest.
pub const EDM_HASH_LEN: usize = 32;

/// Longest cell value, in tokens, EDM will match. Registration records
/// the token-window lengths actually present so detection only slides
/// the windows it must; this constant caps that so a pathological
/// dataset (a record with thousands of words) can never make detection
/// super-linear in the scanned content.
pub const MAX_EDM_WINDOW_TOKENS: usize = 10;

/// A single stored digest.
type Digest32 = [u8; EDM_HASH_LEN];

/// Errors compiling a wire [`EdmDataset`] into a runtime matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdmError {
    /// The salt was not [`EDM_SALT_LEN`] bytes of valid hex.
    BadSalt(String),
    /// A stored digest was not [`EDM_HASH_LEN`] bytes of valid hex.
    BadDigest(String),
}

impl std::fmt::Display for EdmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSalt(s) => write!(f, "invalid EDM salt: {s}"),
            Self::BadDigest(s) => write!(f, "invalid EDM digest: {s}"),
        }
    }
}

impl std::error::Error for EdmError {}

/// HMAC-SHA256 of `msg` under `key`, per RFC 2104. Implemented over the
/// crate's existing `sha2` dependency so EDM adds no new crypto crate;
/// [`hmac_matches_rfc4231`] checks it against the RFC 4231 vectors.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Digest32 {
    const BLOCK: usize = 64;
    // Keys longer than the block are first hashed down, per the spec.
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        // Copy out of the `sha2` `GenericArray` (which we cannot zeroize
        // in place without its zeroize feature) into a buffer we own,
        // then wipe it: the hashed key is key-derived material.
        let mut hashed = [0u8; EDM_HASH_LEN];
        hashed.copy_from_slice(&Sha256::digest(key));
        block[..EDM_HASH_LEN].copy_from_slice(&hashed);
        hashed.zeroize();
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    // `H(ipad || msg)` is key-derived; hold it in an owned buffer so it
    // can be zeroized after it feeds the outer hash.
    let mut inner_digest = [0u8; EDM_HASH_LEN];
    inner_digest.copy_from_slice(&inner.finalize());

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);

    let mut out = [0u8; EDM_HASH_LEN];
    out.copy_from_slice(&outer.finalize());

    // Wipe every key-derived working buffer we own. (The `sha2` hasher
    // states for `inner`/`outer` are not `Zeroize` and are outside our
    // control; the buffers above are the material we can guarantee.)
    block.zeroize();
    ipad.zeroize();
    opad.zeroize();
    inner_digest.zeroize();
    out
}

/// A cryptographically-random dataset salt.
#[must_use]
pub fn random_salt() -> [u8; EDM_SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; EDM_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Normalize `text` into canonical tokens: NFKC-folded, lowercased,
/// split on Unicode whitespace, with surrounding ASCII punctuation
/// trimmed from each token. Empty tokens are dropped. Both registration
/// and detection use this so the two sides agree byte-for-byte.
fn normalize_tokens(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|raw| {
            let folded: String = raw.nfkc().collect::<String>().to_lowercase();
            folded
                .trim_matches(|c: char| c.is_ascii_punctuation())
                .to_owned()
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// The canonical phrase for a token window: the tokens joined by a
/// single space. This is the exact byte sequence that gets hashed on
/// both the registration and detection sides.
fn canonical(window: &[String]) -> String {
    window.join(" ")
}

/// A registered EDM dataset in its wire form: salt + digests +
/// window-length set, all hex-encoded for compact, auditable JSON. It
/// carries **no plaintext**. Ships inside the signed endpoint bundle and
/// is persisted by migration 067.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdmDataset {
    /// Stable dataset id; a [`crate::rules::PatternType::Edm`] rule's
    /// `pattern_data` references this.
    pub id: String,
    /// Operator-facing dataset name (e.g. "Customer PII — 2026Q2").
    pub name: String,
    /// Per-dataset random salt, hex-encoded ([`EDM_SALT_LEN`] bytes).
    pub salt: String,
    /// The token-window lengths present in the dataset (each in
    /// `1..=MAX_EDM_WINDOW_TOKENS`).
    pub window_sizes: BTreeSet<usize>,
    /// The salted digests, hex-encoded and sorted for determinism.
    pub digests: Vec<String>,
}

impl EdmDataset {
    /// Register `records` (each a sensitive cell value) into a dataset
    /// under `salt`, keeping only salted digests. The plaintext is
    /// normalized, hashed, and the transient buffer wiped — no record
    /// value is retained anywhere in the returned dataset.
    ///
    /// Records longer than [`MAX_EDM_WINDOW_TOKENS`] tokens are hashed
    /// but their window length is not recorded, so they will not be
    /// matched (detection never slides a window that long); this keeps
    /// detection linear. Empty / whitespace-only records are skipped.
    #[must_use]
    pub fn register<S: AsRef<str>>(
        id: impl Into<String>,
        name: impl Into<String>,
        salt: &[u8],
        records: &[S],
    ) -> Self {
        let mut window_sizes = BTreeSet::new();
        let mut digest_set: BTreeSet<String> = BTreeSet::new();
        for record in records {
            let mut tokens = normalize_tokens(record.as_ref());
            let n = tokens.len();
            if n == 0 {
                continue;
            }
            let mut phrase = canonical(&tokens);
            let digest = hmac_sha256(salt, phrase.as_bytes());
            // Wipe the transient plaintext as soon as it is hashed.
            phrase.zeroize();
            for t in &mut tokens {
                t.zeroize();
            }
            digest_set.insert(hex::encode(digest));
            if (1..=MAX_EDM_WINDOW_TOKENS).contains(&n) {
                window_sizes.insert(n);
            }
        }
        Self {
            id: id.into(),
            name: name.into(),
            salt: hex::encode(salt),
            window_sizes,
            digests: digest_set.into_iter().collect(),
        }
    }

    /// Number of distinct digests stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Whether the dataset stores no digests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

/// A compiled, ready-to-match EDM dataset: the wire [`EdmDataset`]'s hex
/// fields decoded once into raw bytes + a hash set for `O(1)` membership.
/// The classifier builds one per dataset at policy-compile time, the
/// same way it compiles regex / keyword rules into matchers.
#[derive(Clone, Debug)]
pub struct CompiledEdm {
    id: String,
    salt: Vec<u8>,
    /// Window lengths to slide, ascending; each `1..=MAX_EDM_WINDOW_TOKENS`.
    window_sizes: Vec<usize>,
    digests: HashSet<Digest32>,
}

impl CompiledEdm {
    /// Decode and compile a wire dataset into a runtime matcher.
    ///
    /// # Errors
    /// [`EdmError`] if the salt or any digest is not valid fixed-length
    /// hex.
    pub fn from_dataset(dataset: &EdmDataset) -> Result<Self, EdmError> {
        let salt = hex::decode(&dataset.salt)
            .map_err(|e| EdmError::BadSalt(e.to_string()))
            .and_then(|bytes| {
                if bytes.len() == EDM_SALT_LEN {
                    Ok(bytes)
                } else {
                    Err(EdmError::BadSalt(format!(
                        "expected {EDM_SALT_LEN} bytes, got {}",
                        bytes.len()
                    )))
                }
            })?;

        let mut digests = HashSet::with_capacity(dataset.digests.len());
        for hexd in &dataset.digests {
            let raw = hex::decode(hexd).map_err(|e| EdmError::BadDigest(e.to_string()))?;
            let arr: Digest32 = raw
                .try_into()
                .map_err(|_| EdmError::BadDigest(format!("expected {EDM_HASH_LEN} bytes")))?;
            digests.insert(arr);
        }

        // Slide windows shortest-first; ignore any out-of-range length.
        let window_sizes: Vec<usize> = dataset
            .window_sizes
            .iter()
            .copied()
            .filter(|w| (1..=MAX_EDM_WINDOW_TOKENS).contains(w))
            .collect();

        Ok(Self {
            id: dataset.id.clone(),
            salt,
            window_sizes,
            digests,
        })
    }

    /// The dataset id this matcher was compiled from.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether `content` contains any registered record. Slides each
    /// registered window length over the normalized token stream and
    /// tests membership; returns at the first hit. Never returns or
    /// retains the matched text — only the yes/no decision.
    ///
    /// Complexity is `O(tokens · |window_sizes|)` HMAC evaluations, with
    /// `|window_sizes|` bounded by [`MAX_EDM_WINDOW_TOKENS`], so it is
    /// linear in the content size.
    #[must_use]
    pub fn matches(&self, content: &str) -> bool {
        if self.digests.is_empty() || self.window_sizes.is_empty() {
            return false;
        }
        let tokens = normalize_tokens(content);
        if tokens.is_empty() {
            return false;
        }
        // Reuse one buffer across windows to avoid a per-window alloc.
        let mut phrase = String::new();
        for &w in &self.window_sizes {
            if w > tokens.len() {
                continue;
            }
            for window in tokens.windows(w) {
                phrase.clear();
                for (i, t) in window.iter().enumerate() {
                    if i > 0 {
                        phrase.push(' ');
                    }
                    phrase.push_str(t);
                }
                let digest = hmac_sha256(&self.salt, phrase.as_bytes());
                if self.digests.contains(&digest) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231, Test Case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn salt_changes_digest() {
        let a = EdmDataset::register("d", "d", &[0u8; EDM_SALT_LEN], &["jane doe"]);
        let b = EdmDataset::register("d", "d", &[1u8; EDM_SALT_LEN], &["jane doe"]);
        assert_ne!(a.digests, b.digests, "salt must diversify digests");
    }

    #[test]
    fn registration_keeps_no_plaintext() {
        // The privacy contract: no record value (or any case / spacing
        // variant of it) may appear anywhere in the serialized dataset.
        let salt = [7u8; EDM_SALT_LEN];
        let secrets = ["Jane Doe", "alice@example.com", "123-45-6789"];
        let ds = EdmDataset::register("pii", "Customer PII", &salt, &secrets);
        let json = serde_json::to_string(&ds).expect("serialize");
        for s in secrets {
            assert!(!json.contains(s), "plaintext {s:?} leaked into dataset");
            assert!(!json.contains(&s.to_lowercase()), "lowercased {s:?} leaked");
        }
        // Only salt + digests + window sizes are present.
        assert_eq!(ds.len(), 3);
        assert_eq!(ds.window_sizes, BTreeSet::from([1, 2]));
    }

    #[test]
    fn matches_exact_record_with_context_and_normalization() {
        let salt = random_salt();
        let ds = EdmDataset::register("pii", "PII", &salt, &["Jane Doe", "987654321"]);
        let edm = CompiledEdm::from_dataset(&ds).expect("compile");

        // Embedded in surrounding text, different case / spacing.
        assert!(edm.matches("please contact JANE   DOE about this"));
        assert!(edm.matches("account 987654321 is overdue"));
        // Punctuation-adjacent occurrence.
        assert!(edm.matches("(jane doe)"));
        // A non-registered value must not match.
        assert!(!edm.matches("john smith"));
        assert!(!edm.matches("123456789"));
    }

    #[test]
    fn empty_and_whitespace_records_are_skipped() {
        let ds = EdmDataset::register("d", "d", &[3u8; EDM_SALT_LEN], &["", "   ", "real value"]);
        assert_eq!(ds.len(), 1);
        let edm = CompiledEdm::from_dataset(&ds).expect("compile");
        assert!(edm.matches("this is a real value here"));
        assert!(!edm.matches(""));
    }

    #[test]
    fn over_long_records_are_hashed_but_not_windowed() {
        let salt = [9u8; EDM_SALT_LEN];
        let long: String = (0..MAX_EDM_WINDOW_TOKENS + 3)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ds = EdmDataset::register("d", "d", &salt, std::slice::from_ref(&long));
        // Hashed (stored) but no window length recorded for it.
        assert_eq!(ds.len(), 1);
        assert!(ds.window_sizes.is_empty());
        let edm = CompiledEdm::from_dataset(&ds).expect("compile");
        // Cannot be matched — detection never slides a window that long.
        assert!(!edm.matches(&long));
    }

    #[test]
    fn bad_salt_and_digest_are_compile_errors() {
        let mut ds = EdmDataset::register("d", "d", &[0u8; EDM_SALT_LEN], &["x"]);
        ds.salt = "zz".to_owned();
        assert!(matches!(
            CompiledEdm::from_dataset(&ds),
            Err(EdmError::BadSalt(_))
        ));

        let mut ds2 = EdmDataset::register("d", "d", &[0u8; EDM_SALT_LEN], &["x"]);
        ds2.digests = vec!["nothex".to_owned()];
        assert!(matches!(
            CompiledEdm::from_dataset(&ds2),
            Err(EdmError::BadDigest(_))
        ));
    }

    #[test]
    fn matcher_finds_record_at_scale() {
        // A realistic-sized dataset: 5000 single-token account numbers
        // plus one two-token name; detection must find a needle in a
        // large body and reject content with no registered value.
        let salt = random_salt();
        let mut records: Vec<String> = (0..5000).map(|i| format!("acct{i:07}")).collect();
        records.push("Grace Hopper".to_owned());
        let ds = EdmDataset::register("big", "Big PII", &salt, &records);
        let edm = CompiledEdm::from_dataset(&ds).expect("compile");

        let haystack = "lorem ipsum acct0004321 dolor sit amet";
        assert!(edm.matches(haystack));
        assert!(edm.matches("cc: Grace Hopper <g@x>"));
        assert!(!edm.matches("lorem ipsum dolor sit amet acct9999999"));
    }
}
