//! Managed feed-bundle ingest: the consumer seam for the control
//! plane's signed DNS threat-intel feed.
//!
//! The control plane (`internal/service/threatintel`) fetches DNS
//! reputation / category feeds from upstream sources on a cadence,
//! normalizes them, and distributes a single Ed25519-signed bundle over
//! NATS. This module is the EDGE side of that contract: it verifies the
//! signature against a pinned trust store, parses the bundle, and
//! hot-swaps it into the existing [`crate::Category`] /
//! [`crate::Reputation`] filters via their `replace_*` seams.
//!
//! Trust model — identical to the policy / IPS bundle verifiers:
//!
//! * The wire envelope ([`SignedFeedBundle`]) is self-describing
//!   (algorithm, key id, embedded public key, base64 payload + base64
//!   signature) but the embedded public key is **advisory only**.
//!   Verification trusts exclusively the keys an operator pinned into
//!   the [`FeedVerifier`] out of band, selected by `key_id`. An attacker
//!   who swaps in their own key + re-signs is rejected because their key
//!   is not in the trust store.
//! * The signature is verified BEFORE the payload is parsed, so a
//!   tampered or untrusted payload never reaches the data model
//!   (fail-closed).
//! * The bundle carries a monotonic `serial`; [`ManagedFeedApplier`]
//!   refuses to apply a bundle whose serial is not strictly greater than
//!   the last one applied, so an out-of-order or replayed delivery
//!   cannot roll the feed back to stale data.
//!
//! Disposition stays on the edge: the bundle supplies only category
//! MEMBERSHIP (which domains are in `ads`, `gambling`, …); the per-
//! category Allow / Log / Block policy is the operator's and is passed
//! in at apply time, exactly as [`crate::CategoryDb`] already models it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::category::{Category, CategoryAction, CategoryDb};
use crate::reputation::Reputation;

/// Current managed feed-bundle payload schema version. Must match the
/// producer's `SchemaVersion` constant
/// (`internal/service/threatintel/bundle.go`). A bundle carrying any
/// other version is rejected rather than risk a mis-parse.
pub const SCHEMA_VERSION: u32 = 1;

/// Signature algorithm identifier carried in the envelope. Only Ed25519
/// is accepted, matching the policy / IPS / compliance-evidence
/// bundles.
pub const ALGORITHM: &str = "ed25519";

/// The signed wire envelope distributed over NATS. Mirrors the Go
/// producer's `SignedBundle`: `payload` is the base64 (std) encoding of
/// the canonical [`FeedBundle`] JSON; `signature` is the base64 Ed25519
/// signature over the DECODED payload bytes; `public_key` is the base64
/// 32-byte verifying key (advisory — see the module trust-model note).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedFeedBundle {
    /// Signature algorithm. Must equal [`ALGORITHM`].
    #[serde(rename = "alg")]
    pub algorithm: String,
    /// Identifier of the signing key, used to select the pinned
    /// verifying key from the trust store. May be empty when the trust
    /// store holds exactly one key.
    #[serde(default, rename = "key_id")]
    pub key_id: String,
    /// Base64 (std) 32-byte Ed25519 public key. Advisory only.
    pub public_key: String,
    /// Base64 (std) canonical [`FeedBundle`] JSON.
    pub payload: String,
    /// Base64 (std) Ed25519 signature over the decoded payload bytes.
    pub signature: String,
}

/// The verified feed payload the producer assembled. Platform-global
/// shared threat intelligence — no tenant binding.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FeedBundle {
    /// Payload layout version (see [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Monotonically non-decreasing generation counter (producer unix
    /// seconds). The authoritative ordering / anti-replay key.
    pub serial: i64,
    /// Producer timestamp (RFC3339). Advisory / telemetry only.
    #[serde(default)]
    pub generated_at: String,
    /// `category name -> canonical domain membership` (suffix-match).
    #[serde(default)]
    pub categories: HashMap<String, Vec<String>>,
    /// Exact-match known-bad FQDN set.
    #[serde(default)]
    pub reputation: Vec<String>,
}

impl FeedBundle {
    /// Build a [`CategoryDb`] from the bundle's category membership and
    /// the operator's per-category disposition map. Categories present
    /// in the bundle but absent from `actions` default to
    /// [`CategoryAction::Allow`], matching [`CategoryDb`] semantics, so
    /// an operator can stage a feed before deciding each bucket's
    /// policy.
    #[must_use]
    pub fn category_db(&self, actions: HashMap<String, CategoryAction>) -> CategoryDb {
        let pairs = self.categories.iter().flat_map(|(cat, domains)| {
            domains
                .iter()
                .map(move |domain| (cat.as_str(), domain.as_str()))
        });
        CategoryDb::build(pairs, actions)
    }

    /// The exact-match reputation FQDN set.
    #[must_use]
    pub fn reputation_names(&self) -> &[String] {
        &self.reputation
    }
}

/// Errors raised while verifying / applying a managed feed bundle. Each
/// variant maps to a distinct operational signal so the edge can tell a
/// crypto failure (key rotation / tampering) from a stale delivery
/// (benign, expected on redelivery) from a malformed payload.
#[derive(Debug, thiserror::Error)]
pub enum FeedBundleError {
    /// The envelope's algorithm field was not [`ALGORITHM`].
    #[error("managed feed: unsupported algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// No pinned verifying key matched the envelope's `key_id` (or the
    /// store is empty / ambiguous for an empty `key_id`).
    #[error("managed feed: no trusted key for key_id {0:?}")]
    UnknownKey(String),
    /// A base64 field (payload / signature / public key) failed to
    /// decode, or the signature / key was the wrong length.
    #[error("managed feed: malformed envelope: {0}")]
    Malformed(String),
    /// The signature did not verify against the pinned key.
    #[error("managed feed: signature verification failed")]
    SignatureInvalid,
    /// The payload JSON could not be parsed into a [`FeedBundle`].
    #[error("managed feed: parse payload: {0}")]
    Parse(String),
    /// The payload's schema version is not [`SCHEMA_VERSION`].
    #[error("managed feed: unsupported schema version {got} (want {want})")]
    SchemaVersion {
        /// Version the bundle declared.
        got: u32,
        /// Version this build supports.
        want: u32,
    },
    /// The bundle's serial was not strictly greater than the last
    /// applied serial — an out-of-order or replayed delivery.
    #[error("managed feed: stale serial {got} (last applied {last})")]
    StaleSerial {
        /// Serial the bundle carried.
        got: i64,
        /// Highest serial already applied.
        last: i64,
    },
}

/// Pinned trust store for managed feed bundles. Holds the operator-
/// provisioned Ed25519 verifying keys, keyed by the `key_id` the
/// producer stamps into the envelope. Mirrors the policy-bundle
/// `PolicyVerifier`: a multi-key store so a key rotation can pre-stage
/// the new key before the producer cuts over.
#[derive(Clone, Debug, Default)]
pub struct FeedVerifier {
    keys: HashMap<String, VerifyingKey>,
}

impl FeedVerifier {
    /// Empty trust store. Every [`FeedVerifier::verify`] call fails with
    /// [`FeedBundleError::UnknownKey`] until a key is added.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Pin a verifying key under `key_id`. `key_bytes` must be the
    /// 32-byte Ed25519 public key. Returns the store for chaining.
    pub fn add_key(
        &mut self,
        key_id: impl Into<String>,
        key_bytes: &[u8],
    ) -> Result<&mut Self, FeedBundleError> {
        let arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
            FeedBundleError::Malformed(format!("public key length {}", key_bytes.len()))
        })?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| FeedBundleError::Malformed(format!("public key: {e}")))?;
        self.keys.insert(key_id.into(), key);
        Ok(self)
    }

    /// Number of pinned keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the trust store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Select the verifying key for an envelope: by `key_id` when set,
    /// or the sole pinned key when the envelope omits one and the store
    /// holds exactly one.
    fn select_key(&self, key_id: &str) -> Result<&VerifyingKey, FeedBundleError> {
        if !key_id.is_empty() {
            return self
                .keys
                .get(key_id)
                .ok_or_else(|| FeedBundleError::UnknownKey(key_id.to_string()));
        }
        if self.keys.len() == 1 {
            // Safe: len()==1 guarantees a first element.
            if let Some(key) = self.keys.values().next() {
                return Ok(key);
            }
        }
        Err(FeedBundleError::UnknownKey(key_id.to_string()))
    }

    /// Verify an envelope and parse the payload, fail-closed: the
    /// signature is checked against the pinned key BEFORE the payload is
    /// decoded into the data model, and the schema version is enforced.
    pub fn verify(&self, signed: &SignedFeedBundle) -> Result<FeedBundle, FeedBundleError> {
        if signed.algorithm != ALGORITHM {
            return Err(FeedBundleError::UnsupportedAlgorithm(
                signed.algorithm.clone(),
            ));
        }
        let key = self.select_key(&signed.key_id)?;

        let engine = base64::engine::general_purpose::STANDARD;
        let payload = engine
            .decode(signed.payload.as_bytes())
            .map_err(|e| FeedBundleError::Malformed(format!("payload base64: {e}")))?;
        let sig_bytes = engine
            .decode(signed.signature.as_bytes())
            .map_err(|e| FeedBundleError::Malformed(format!("signature base64: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            FeedBundleError::Malformed(format!("signature length {}", sig_bytes.len()))
        })?;
        let signature = Signature::from_bytes(&sig_arr);

        // verify_strict rejects the small set of malleable / non-
        // canonical signatures `verify` would accept, matching the
        // edge's defensive posture for the other signed bundles.
        key.verify_strict(&payload, &signature)
            .map_err(|_| FeedBundleError::SignatureInvalid)?;

        let bundle: FeedBundle =
            serde_json::from_slice(&payload).map_err(|e| FeedBundleError::Parse(e.to_string()))?;
        if bundle.schema_version != SCHEMA_VERSION {
            return Err(FeedBundleError::SchemaVersion {
                got: bundle.schema_version,
                want: SCHEMA_VERSION,
            });
        }
        Ok(bundle)
    }
}

/// Summary of a successfully applied bundle, returned for telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedFeed {
    /// Serial of the bundle that was applied.
    pub serial: i64,
    /// Number of categories swapped in.
    pub categories: usize,
    /// Number of reputation entries swapped in.
    pub reputation: usize,
}

/// Stateful applier that verifies a signed bundle and hot-swaps it into
/// the [`Category`] and [`Reputation`] filters, enforcing serial
/// monotonicity across calls so a redelivered or reordered bundle is a
/// no-op rather than a rollback.
///
/// Holds its own trust store; construct one per edge process and feed
/// every received [`SignedFeedBundle`] through [`ManagedFeedApplier::apply`].
#[derive(Debug)]
pub struct ManagedFeedApplier {
    verifier: FeedVerifier,
    last_serial: AtomicI64,
}

impl ManagedFeedApplier {
    /// Construct an applier over the given trust store. No bundle has
    /// been applied yet, so the first valid bundle of any serial is
    /// accepted.
    #[must_use]
    pub fn new(verifier: FeedVerifier) -> Self {
        Self {
            verifier,
            last_serial: AtomicI64::new(i64::MIN),
        }
    }

    /// The highest serial applied so far, or `None` if none has been.
    #[must_use]
    pub fn last_serial(&self) -> Option<i64> {
        let v = self.last_serial.load(Ordering::Acquire);
        if v == i64::MIN { None } else { Some(v) }
    }

    /// Verify `signed`, enforce serial monotonicity, and atomically
    /// hot-swap the result into `category` and `reputation`. `actions`
    /// is the operator's per-category disposition map (membership comes
    /// from the bundle, policy stays on the edge).
    ///
    /// On success the filters reflect the new bundle and the internal
    /// last-applied serial advances. On any verification / staleness
    /// error the filters are left untouched (fail-closed): a bad bundle
    /// never degrades the live feed.
    pub fn apply(
        &self,
        signed: &SignedFeedBundle,
        category: &Category,
        reputation: &Reputation,
        actions: &HashMap<String, CategoryAction>,
    ) -> Result<AppliedFeed, FeedBundleError> {
        let bundle = self.verifier.verify(signed)?;

        // Reserve this serial under monotonicity before mutating the
        // filters: a CAS loop means concurrent appliers (or a redelivery
        // racing the first apply) settle on exactly one winner and the
        // loser sees StaleSerial rather than double-applying.
        loop {
            let last = self.last_serial.load(Ordering::Acquire);
            if bundle.serial <= last {
                return Err(FeedBundleError::StaleSerial {
                    got: bundle.serial,
                    last,
                });
            }
            if self
                .last_serial
                .compare_exchange(last, bundle.serial, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        let db = bundle.category_db(actions.clone());
        let categories = db.categories.len();
        category.replace_database(db);
        reputation.replace_entries(bundle.reputation_names());

        Ok(AppliedFeed {
            serial: bundle.serial,
            categories,
            reputation: bundle.reputation.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_bundle(serial: i64) -> FeedBundle {
        let mut categories = HashMap::new();
        categories.insert(
            "ads".to_string(),
            vec!["ads.example".to_string(), "tracker.example".to_string()],
        );
        FeedBundle {
            schema_version: SCHEMA_VERSION,
            serial,
            generated_at: "2024-01-01T00:00:00Z".to_string(),
            categories,
            reputation: vec!["evil.example".to_string()],
        }
    }

    /// Produce a signed envelope the way the Go producer does: sign the
    /// exact payload bytes that get base64-encoded into `payload`.
    fn sign(key: &SigningKey, key_id: &str, bundle: &FeedBundle) -> SignedFeedBundle {
        let payload = serde_json::to_vec(bundle).expect("serialize");
        let sig = key.sign(&payload);
        let engine = base64::engine::general_purpose::STANDARD;
        SignedFeedBundle {
            algorithm: ALGORITHM.to_string(),
            key_id: key_id.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
            payload: engine.encode(&payload),
            signature: engine.encode(sig.to_bytes()),
        }
    }

    fn verifier_with(key: &SigningKey, key_id: &str) -> FeedVerifier {
        let mut v = FeedVerifier::new();
        v.add_key(key_id, &key.verifying_key().to_bytes())
            .expect("add key");
        v
    }

    #[test]
    fn verify_round_trip() {
        let key = signing_key(1);
        let signed = sign(&key, "k1", &sample_bundle(7));
        let v = verifier_with(&key, "k1");
        let bundle = v.verify(&signed).expect("verify");
        assert_eq!(bundle.serial, 7);
        assert_eq!(bundle.reputation, vec!["evil.example".to_string()]);
        assert_eq!(bundle.categories["ads"].len(), 2);
    }

    #[test]
    fn verify_empty_key_id_single_pinned_key() {
        let key = signing_key(1);
        let signed = sign(&key, "", &sample_bundle(1));
        let v = verifier_with(&key, "k1");
        assert!(v.verify(&signed).is_ok());
    }

    #[test]
    fn verify_rejects_untrusted_key() {
        let key = signing_key(1);
        let attacker = signing_key(2);
        // Attacker re-signs with their own key but stamps the trusted id.
        let signed = sign(&attacker, "k1", &sample_bundle(1));
        let v = verifier_with(&key, "k1");
        assert!(matches!(
            v.verify(&signed),
            Err(FeedBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_unknown_key_id() {
        let key = signing_key(1);
        let signed = sign(&key, "other", &sample_bundle(1));
        let v = verifier_with(&key, "k1");
        assert!(matches!(
            v.verify(&signed),
            Err(FeedBundleError::UnknownKey(_))
        ));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = signing_key(1);
        let mut signed = sign(&key, "k1", &sample_bundle(1));
        let engine = base64::engine::general_purpose::STANDARD;
        signed.payload = engine.encode(serde_json::to_vec(&sample_bundle(999)).unwrap());
        let v = verifier_with(&key, "k1");
        assert!(matches!(
            v.verify(&signed),
            Err(FeedBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_bad_schema_version() {
        let key = signing_key(1);
        let mut bundle = sample_bundle(1);
        bundle.schema_version = SCHEMA_VERSION + 1;
        let signed = sign(&key, "k1", &bundle);
        let v = verifier_with(&key, "k1");
        assert!(matches!(
            v.verify(&signed),
            Err(FeedBundleError::SchemaVersion { .. })
        ));
    }

    #[test]
    fn verify_rejects_wrong_algorithm() {
        let key = signing_key(1);
        let mut signed = sign(&key, "k1", &sample_bundle(1));
        signed.algorithm = "rsa".to_string();
        let v = verifier_with(&key, "k1");
        assert!(matches!(
            v.verify(&signed),
            Err(FeedBundleError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn apply_hot_swaps_filters() {
        let key = signing_key(1);
        let applier = ManagedFeedApplier::new(verifier_with(&key, "k1"));
        let category = Category::empty();
        let reputation = Reputation::empty();
        let actions = HashMap::from([("ads".to_string(), CategoryAction::Block)]);

        let summary = applier
            .apply(
                &sign(&key, "k1", &sample_bundle(5)),
                &category,
                &reputation,
                &actions,
            )
            .expect("apply");
        assert_eq!(summary.serial, 5);
        assert_eq!(summary.categories, 1);
        assert_eq!(summary.reputation, 1);
        assert_eq!(category.category_count(), 1);
        assert_eq!(reputation.len(), 1);
        assert_eq!(applier.last_serial(), Some(5));
    }

    #[test]
    fn apply_rejects_stale_serial_and_leaves_filters_intact() {
        let key = signing_key(1);
        let applier = ManagedFeedApplier::new(verifier_with(&key, "k1"));
        let category = Category::empty();
        let reputation = Reputation::empty();
        let actions = HashMap::new();

        applier
            .apply(
                &sign(&key, "k1", &sample_bundle(10)),
                &category,
                &reputation,
                &actions,
            )
            .expect("first apply");
        let rep_len = reputation.len();

        // A bundle with an equal-or-lower serial is refused; the live
        // filters are untouched.
        let err = applier
            .apply(
                &sign(&key, "k1", &sample_bundle(10)),
                &category,
                &reputation,
                &actions,
            )
            .unwrap_err();
        assert!(matches!(err, FeedBundleError::StaleSerial { .. }));
        assert_eq!(reputation.len(), rep_len);
        assert_eq!(applier.last_serial(), Some(10));
    }

    #[test]
    fn apply_rejects_bad_signature_without_mutating() {
        let key = signing_key(1);
        let attacker = signing_key(2);
        let applier = ManagedFeedApplier::new(verifier_with(&key, "k1"));
        let category = Category::empty();
        let reputation = Reputation::empty();
        let actions = HashMap::new();

        let err = applier
            .apply(
                &sign(&attacker, "k1", &sample_bundle(1)),
                &category,
                &reputation,
                &actions,
            )
            .unwrap_err();
        assert!(matches!(err, FeedBundleError::SignatureInvalid));
        assert_eq!(reputation.len(), 0);
        assert_eq!(category.category_count(), 0);
        assert_eq!(applier.last_serial(), None);
    }
}
