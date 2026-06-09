//! Hybrid URL categoriser.
//!
//! The [`crate::categorizer`] module ships [`LocalCategoryDb`], an
//! exact / wildcard `(host, path) -> category` lookup driven by an
//! operator-curated, control-plane-signed feed. That tier is
//! precise but only covers hosts an operator (or a vendor feed) has
//! explicitly catalogued. A real SWG protecting thousands of SME
//! tenants browsing the open web needs coverage for the long tail
//! of hosts nobody has hand-classified — which is what this module
//! adds, *without* abandoning the deterministic precision of the
//! curated tier.
//!
//! [`HybridUrlCategorizer`] is a single [`UrlCategorizer`] that
//! composes four tiers and returns the first confident verdict,
//! most-authoritative first:
//!
//! 1. **Tier 1 — exact / curated** ([`LocalCategoryDb`]). The
//!    operator-curated `(host, path)` table. Exact-host entries and
//!    operator wildcard (`*.suffix`) entries both live here; the
//!    wildcard arm already matches via [`sng_fw::sni_suffix_match`],
//!    so this tier is authoritative and never overridden by a
//!    lower tier. A verdict here is an operator (or signed vendor
//!    feed) decision and wins outright.
//!
//! 2. **Tier 2 — domain pattern** ([`DomainPatternIndex`]). Coarse
//!    registrable-domain → category coverage sourced from community
//!    feeds (Shallalist, UT1) ingested on the control plane into the
//!    `app_registry` format and shipped down. Where Tier 1 is a
//!    hand-curated few-thousand-entry list scanned linearly, the
//!    community feeds are hundreds of thousands of domains, so this
//!    tier is a [`std::collections::HashMap`] keyed on the canonical
//!    domain with a longest-suffix walk (strip leftmost label, probe,
//!    repeat). Suffix containment is confirmed with
//!    [`sng_fw::sni_suffix_match`] so the boundary semantics are
//!    byte-identical to the firewall L7 classifier and the Tier 1
//!    wildcard arm — one matcher, no drift.
//!
//! 3. **Tier 3 — ML classifier** ([`UrlMlClassifier`]). A
//!    TF-IDF + multinomial linear model over URL tokens. Catches
//!    novel hosts whose *tokens* (labels, path words) resemble a
//!    known category even when the exact domain is unseen. The model
//!    is distributed as an Ed25519-signed, revision-stamped bundle
//!    verified with the same trust-store infrastructure as the YARA
//!    / IPS / policy bundles ([`UrlModelVerifier`]); a verdict is
//!    only emitted when the softmax confidence and top-two margin
//!    both clear the model-carried thresholds (margin gating), so a
//!    low-confidence guess falls through rather than mislabelling.
//!
//! 4. **Tier 4 — local LLM fallback** ([`LocalLlmCategorizer`]). An
//!    optional, pluggable, *on-device* LLM consulted only when every
//!    cheaper tier abstains. It is a trait so a deployment wires a
//!    local llama.cpp-backed categoriser (no request data ever
//!    leaves the appliance — a hard privacy requirement for the
//!    multi-tenant SaaS) while tests use a deterministic stub. The
//!    tier is `Option`-al precisely because it is the most expensive
//!    and is meant to be the last resort.
//!
//! ## Hot-swap
//!
//! Every tier's dataset lives behind an [`arc_swap::ArcSwap`] so a
//! control-plane refresh installs a new snapshot atomically without
//! taking a lock on the per-request categorisation path — the same
//! pattern [`LocalCategoryDb`] and [`crate::yara::YaraEngine`] use.
//! Readers (the ext-authz hot path) never block.
//!
//! ## Privacy
//!
//! Tiers 1–3 are pure in-process lookups: no network call, no
//! logging of the request URL, no per-tenant state. Tier 4, when
//! configured, runs a model that is local to the appliance. No tier
//! transmits the browsed URL off-box.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sng_fw::sni_suffix_match;

use crate::categorizer::{Category, LocalCategoryDb, UrlCategorizer};
use crate::error::SwgError;

// =========================================================================
// Tier 2 — domain pattern index
// =========================================================================

/// One `(domain pattern, category)` row in a community / vendor
/// category feed, as ingested into the `app_registry` format on the
/// control plane.
///
/// `pattern` is a registrable domain (`doubleclick.net`) or an
/// explicit wildcard (`*.doubleclick.net`); both are normalised to
/// the same bare suffix at install time, matching the
/// [`crate::categorizer::CategoryEntry`] host convention.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPattern {
    /// Domain suffix to match. A leading `*.` is stripped at install
    /// time — `foo.com` and `*.foo.com` are equivalent here because
    /// the lookup is always suffix-containment (the apex and any
    /// subdomain match).
    pub pattern: String,
    /// Category the matched host resolves to.
    pub category: Category,
}

/// The immutable, installed pattern table. Keyed on the canonical
/// (lowercase, `*.`-stripped, dot-trimmed) domain suffix.
#[derive(Debug, Default)]
struct PatternTable {
    by_domain: HashMap<String, Category>,
}

/// Tier 2 coarse domain → category coverage.
///
/// Backed by a hot-swappable [`ArcSwap`] of a [`HashMap`] keyed on
/// the canonical domain suffix. Lookup walks the request host from
/// most specific to least (`a.b.example.com` → `b.example.com` →
/// `example.com` → `com`), probing the map at each step and
/// returning the first (longest, most specific) hit. Each candidate
/// hit is confirmed with [`sni_suffix_match`] so the match boundary
/// is identical to the rest of the workspace.
#[derive(Debug)]
pub struct DomainPatternIndex {
    inner: ArcSwap<PatternTable>,
}

impl Default for DomainPatternIndex {
    fn default() -> Self {
        Self {
            inner: ArcSwap::from_pointee(PatternTable::default()),
        }
    }
}

impl DomainPatternIndex {
    /// Build an index preloaded with a set of patterns.
    #[must_use]
    pub fn new(patterns: Vec<DomainPattern>) -> Self {
        let idx = Self::default();
        idx.install(patterns);
        idx
    }

    /// Canonicalise a pattern or host to the lookup key form:
    /// trim surrounding whitespace, lowercase, strip a leading
    /// `*.`, and strip any leading / trailing dots. Returns an empty
    /// string for inputs that canonicalise to nothing (rejected by
    /// the caller).
    fn canonical(raw: &str) -> String {
        let mut s = raw.trim().to_ascii_lowercase();
        if let Some(stripped) = s.strip_prefix("*.") {
            s = stripped.to_owned();
        }
        s.trim_matches('.').to_owned()
    }

    /// Atomically swap in a new pattern set. Later entries for the
    /// same canonical domain win (last-wins), mirroring the override
    /// contract [`LocalCategoryDb::install`] enforces, so an operator
    /// overlay appended after the community defaults takes precedence.
    /// Returns the number of distinct domains installed.
    pub fn install(&self, patterns: Vec<DomainPattern>) -> usize {
        let mut by_domain = HashMap::with_capacity(patterns.len());
        for p in patterns {
            let key = Self::canonical(&p.pattern);
            if key.is_empty() {
                continue;
            }
            let mut cat = p.category;
            cat.0 = cat.0.trim().to_ascii_lowercase();
            if cat.0.is_empty() {
                continue;
            }
            by_domain.insert(key, cat);
        }
        let n = by_domain.len();
        self.inner.store(Arc::new(PatternTable { by_domain }));
        n
    }

    /// Number of distinct domains currently installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.load().by_domain.len()
    }

    /// Whether the index has any patterns installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.load().by_domain.is_empty()
    }

    /// Look up the category for a host. Walks the host suffixes
    /// longest-first; the first domain present in the table whose
    /// suffix contains the host (per [`sni_suffix_match`]) wins.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<Category> {
        let host = host.trim().trim_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let snap = self.inner.load();
        if snap.by_domain.is_empty() {
            return None;
        }
        // Walk every suffix of the host from the full host down to
        // the public-suffix tail, stripping one leftmost label at a
        // time. Each candidate is a single O(1) hash probe; a host
        // has only a handful of labels so this is a few probes even
        // against a million-entry table. The first hit is the
        // longest (most specific) matching domain.
        let mut candidate = host.as_str();
        loop {
            if let Some(cat) = snap.by_domain.get(candidate) {
                // Confirm boundary semantics with the shared matcher
                // so Tier 2 matches exactly what the firewall L7
                // classifier and the Tier 1 wildcard arm would.
                if sni_suffix_match(candidate, &host) {
                    return Some(cat.clone());
                }
            }
            match candidate.find('.') {
                Some(dot) => candidate = &candidate[dot + 1..],
                None => return None,
            }
        }
    }
}

// =========================================================================
// Tier 3 — TF-IDF + linear ML classifier
// =========================================================================

/// Fixed-size 64-byte Ed25519 signature over a model bundle body.
/// Wire-compatible with [`crate::yara::YaraRuleSignature`] and the
/// IPS / policy signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlModelSignature {
    /// Raw 64-byte signature.
    pub bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH],
}

/// Stable identifier for an Ed25519 signing key: 16 lowercase-hex
/// chars (an 8-byte public-key prefix). Newtyped so a string/id
/// mix-up is a compile error. Mirrors
/// [`crate::yara::YaraSigningKeyId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UrlModelSigningKeyId(String);

impl UrlModelSigningKeyId {
    /// Construct, validating the shape (16 lowercase hex chars).
    pub fn new(s: impl Into<String>) -> Result<Self, SwgError> {
        let s = s.into();
        if s.len() != 16 {
            return Err(SwgError::UrlModelBodyDecode(format!(
                "signing key id must be 16 hex chars, got {} ({s:?})",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(SwgError::UrlModelBodyDecode(format!(
                "signing key id must be lowercase hex: {s:?}"
            )));
        }
        Ok(Self(s))
    }

    /// Borrow the raw hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The signed model-bundle envelope as it arrives over `sng-comms`.
/// Structurally identical to [`crate::yara::YaraRuleBundle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlModelBundle {
    /// MessagePack-encoded [`UrlModelClaims`] body — the exact bytes
    /// signed by the control plane.
    pub body: Vec<u8>,
    /// Signature over `body`.
    pub signature: UrlModelSignature,
    /// Which trust-store key produced the signature.
    pub signing_key_id: UrlModelSigningKeyId,
}

/// The serialised model parameters. Named-map MessagePack shape so
/// the Go control-plane trainer's `msgpack/v5` map encoding reads it
/// without remapping (matching [`crate::yara::YaraRuleBundleClaims`]).
///
/// The model is a multinomial linear classifier over an L2-normalised
/// TF-IDF feature vector. For a feature vector `x` and class `c` the
/// score is `score_c = bias_c + Σ_i weights[c*V + i] * x_i`; the
/// predicted class is `argmax_c score_c`, with confidence taken from
/// the softmax over scores.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UrlModelClaims {
    /// Schema version (1 today).
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Monotonically increasing revision. The classifier rejects any
    /// model whose `version` is `<=` the installed version.
    #[serde(rename = "rev")]
    pub version: u64,
    /// Free-form compiler / trainer identifier (`"sng-trainer/0.1"`).
    /// Surfaced on telemetry; not security relevant.
    #[serde(rename = "comp")]
    pub compiler: String,
    /// Ordered category labels. Index into this vector is the class
    /// id the weight rows are addressed by.
    #[serde(rename = "classes")]
    pub classes: Vec<String>,
    /// Token → feature index. Indices must be `< idf.len()`.
    #[serde(rename = "vocab")]
    pub vocabulary: HashMap<String, u32>,
    /// Inverse-document-frequency weight per feature index.
    /// `idf.len()` is the feature-space dimensionality `V`.
    #[serde(rename = "idf")]
    pub idf: Vec<f32>,
    /// Row-major `[num_classes * V]` weight matrix.
    #[serde(rename = "w")]
    pub weights: Vec<f32>,
    /// Per-class bias, length `num_classes`.
    #[serde(rename = "b")]
    pub bias: Vec<f32>,
    /// Minimum softmax probability of the top class for the verdict
    /// to be accepted. A guess below this falls through to Tier 4.
    #[serde(rename = "min_conf")]
    pub min_confidence: f32,
    /// Minimum gap between the top-two class probabilities. Guards
    /// against confidently-wrong ties between adjacent categories
    /// (margin gating, as in the on-device safety guardrail).
    #[serde(rename = "min_margin")]
    pub min_margin: f32,
}

impl UrlModelClaims {
    /// Decode a body from MessagePack bytes.
    pub fn from_body(body: &[u8]) -> Result<Self, SwgError> {
        rmp_serde::from_slice(body).map_err(|e| SwgError::UrlModelBodyDecode(e.to_string()))
    }

    /// Encode a claims body to MessagePack bytes (named-map shape so
    /// the Go trainer reads it without remapping).
    pub fn encode(&self) -> Result<Vec<u8>, SwgError> {
        rmp_serde::to_vec_named(self).map_err(|e| SwgError::UrlModelBodyEncode(e.to_string()))
    }
}

/// Trust store keyed by signing key id. Reuses the same shape as
/// [`crate::yara::YaraRuleVerifier`] so one operator trust store
/// covers policy, IPS, YARA, category, and URL-model bundles.
#[derive(Clone, Debug, Default)]
pub struct UrlModelVerifier {
    keys: HashMap<UrlModelSigningKeyId, VerifyingKey>,
}

impl UrlModelVerifier {
    /// Empty verifier — add keys with [`Self::add_key`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a trusted Ed25519 public key under the supplied id.
    pub fn add_key(
        &mut self,
        id: UrlModelSigningKeyId,
        key_bytes: &[u8; 32],
    ) -> Result<(), SwgError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| SwgError::UrlModelUnknownKey(e.to_string()))?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Number of installed keys — useful for boot diagnostics.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify the bundle signature against the trust store, then
    /// decode the body. Combined so a caller cannot decode without
    /// verifying (which would open a TOCTOU hole on the model bytes).
    pub fn verify_and_decode(&self, bundle: &UrlModelBundle) -> Result<UrlModelClaims, SwgError> {
        let key = self.keys.get(&bundle.signing_key_id).ok_or_else(|| {
            SwgError::UrlModelUnknownKey(bundle.signing_key_id.as_str().to_owned())
        })?;
        let sig = Signature::from_bytes(&bundle.signature.bytes);
        key.verify(&bundle.body, &sig)
            .map_err(|_| SwgError::UrlModelSignatureInvalid)?;
        UrlModelClaims::from_body(&bundle.body)
    }
}

/// A validated, ready-to-score model. Distinct from [`UrlModelClaims`]
/// so the per-request scoring path touches only pre-checked
/// invariants (dimensions already reconciled, thresholds clamped).
#[derive(Debug)]
struct LinearModel {
    version: u64,
    classes: Vec<String>,
    vocabulary: HashMap<String, u32>,
    idf: Vec<f32>,
    /// Row-major `[num_classes * vocab_len]`.
    weights: Vec<f32>,
    bias: Vec<f32>,
    min_confidence: f32,
    min_margin: f32,
}

impl LinearModel {
    /// Reconcile and validate the decoded claims into a scorable
    /// model. Rejects any dimension mismatch, out-of-range
    /// vocabulary index, empty class / vocabulary set, or
    /// non-finite parameter so the scoring path can assume a
    /// well-formed model and never panic on an index or NaN.
    fn from_claims(claims: UrlModelClaims) -> Result<Self, SwgError> {
        let vocab_len = claims.idf.len();
        let num_classes = claims.classes.len();
        // A categoriser is inherently multi-class: it emits the argmax
        // class and gates on the top-two margin. A single-class model
        // degenerates — softmax is always 1.0 and the runner-up stays
        // at -inf, so margin == confidence == 1.0 and both gates pass
        // unconditionally, labelling every in-vocabulary URL into that
        // one class. A binary "is/!is category" model must encode both
        // outcomes as two classes, so require >= 2.
        if num_classes < 2 {
            return Err(SwgError::UrlModelInvalid(format!(
                "model needs at least 2 classes, got {num_classes}"
            )));
        }
        if vocab_len == 0 {
            return Err(SwgError::UrlModelInvalid(
                "model has an empty feature space (idf is empty)".to_owned(),
            ));
        }
        if claims.vocabulary.is_empty() {
            return Err(SwgError::UrlModelInvalid(
                "model has an empty vocabulary".to_owned(),
            ));
        }
        // checked_mul so a hostile bundle declaring enormous class /
        // feature counts cannot wrap the expected length on 64-bit and
        // slip past the dimension check into out-of-bounds scoring.
        let expected_weights = num_classes.checked_mul(vocab_len).ok_or_else(|| {
            SwgError::UrlModelInvalid(format!(
                "model dimensions overflow: num_classes ({num_classes}) * vocab ({vocab_len})"
            ))
        })?;
        if claims.weights.len() != expected_weights {
            return Err(SwgError::UrlModelInvalid(format!(
                "weight matrix has {} entries, expected num_classes ({num_classes}) * vocab ({vocab_len}) = {expected_weights}",
                claims.weights.len(),
            )));
        }
        if claims.bias.len() != num_classes {
            return Err(SwgError::UrlModelInvalid(format!(
                "bias has {} entries, expected num_classes = {num_classes}",
                claims.bias.len()
            )));
        }
        for &idx in claims.vocabulary.values() {
            if (idx as usize) >= vocab_len {
                return Err(SwgError::UrlModelInvalid(format!(
                    "vocabulary index {idx} is out of range for feature space {vocab_len}"
                )));
            }
        }
        if claims.idf.iter().any(|v| !v.is_finite())
            || claims.weights.iter().any(|v| !v.is_finite())
            || claims.bias.iter().any(|v| !v.is_finite())
        {
            return Err(SwgError::UrlModelInvalid(
                "model contains a non-finite parameter (NaN / inf)".to_owned(),
            ));
        }
        if !claims.min_confidence.is_finite() || !claims.min_margin.is_finite() {
            return Err(SwgError::UrlModelInvalid(
                "model has a non-finite gating threshold".to_owned(),
            ));
        }
        // Canonicalise class labels to lowercase so the emitted
        // category matches the deny-list / dashboard convention the
        // rest of the SWG uses (see `LocalCategoryDb::install`).
        let classes: Vec<String> = claims
            .classes
            .into_iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        // Reject a model whose class label is empty (or whitespace
        // only) after canonicalisation: such a class would let the
        // classifier emit `Category("")`, an unnamed verdict no
        // deny-list or dashboard can match. The non-empty class set is
        // already checked above; this guards each individual label.
        if classes.iter().any(String::is_empty) {
            return Err(SwgError::UrlModelInvalid(
                "model has an empty class label after canonicalisation".to_owned(),
            ));
        }
        Ok(Self {
            version: claims.version,
            classes,
            vocabulary: claims.vocabulary,
            idf: claims.idf,
            weights: claims.weights,
            bias: claims.bias,
            // Clamp the gates into the valid probability range [0, 1]
            // so an out-of-range (but finite) threshold maps to a
            // sensible extreme rather than comparing nonsensically:
            // <= 0 becomes 0.0 (most permissive — accept any confident
            // prediction) and >= 1 becomes 1.0 (strictest). Both ends
            // are signed-model choices; non-finite thresholds are
            // already rejected above.
            min_confidence: claims.min_confidence.clamp(0.0, 1.0),
            min_margin: claims.min_margin.clamp(0.0, 1.0),
        })
    }

    fn vocab_len(&self) -> usize {
        self.idf.len()
    }

    /// Score a sparse TF-IDF feature vector and return the predicted
    /// category if the confidence + margin gates pass.
    ///
    /// `features` is `(feature_index, tfidf_value)` for the tokens
    /// present in the URL (already L2-normalised by the caller). An
    /// empty feature set yields `None` — a URL with no in-vocabulary
    /// token cannot be classified.
    fn predict(&self, features: &[(usize, f32)]) -> Option<Category> {
        if features.is_empty() {
            return None;
        }
        let vocab_len = self.vocab_len();
        let mut scores = self.bias.clone();
        for (class_idx, score) in scores.iter_mut().enumerate() {
            let base = class_idx * vocab_len;
            let mut acc = *score;
            for &(feat_idx, value) in features {
                acc += self.weights[base + feat_idx] * value;
            }
            *score = acc;
        }
        // Softmax over the class scores. Subtract the max for
        // numerical stability before exponentiating.
        let max_score = scores.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let mut sum = 0.0f32;
        for s in &mut scores {
            *s = (*s - max_score).exp();
            sum += *s;
        }
        if sum <= 0.0 || !sum.is_finite() {
            return None;
        }
        // Find the top-two probabilities in one pass.
        let mut top_idx = 0usize;
        let mut top = f32::NEG_INFINITY;
        let mut second = f32::NEG_INFINITY;
        for (i, &s) in scores.iter().enumerate() {
            let p = s / sum;
            if p > top {
                second = top;
                top = p;
                top_idx = i;
            } else if p > second {
                second = p;
            }
        }
        let margin = if second.is_finite() {
            top - second
        } else {
            top
        };
        if top >= self.min_confidence && margin >= self.min_margin {
            Some(Category::new(self.classes[top_idx].clone()))
        } else {
            None
        }
    }
}

/// Tier 3 ML classifier: tokenises the URL, builds an L2-normalised
/// TF-IDF feature vector, and scores it against a hot-swappable,
/// Ed25519-signed linear model.
///
/// Holds the model behind an [`ArcSwap`] so an
/// [`Self::install_model`] swaps it atomically; the per-request
/// [`Self::classify`] path loads the snapshot lock-free. `None`
/// means no model is installed yet — [`Self::classify`] simply
/// abstains and the hybrid falls through to Tier 4.
#[derive(Debug)]
pub struct UrlMlClassifier {
    inner: ArcSwap<Option<LinearModel>>,
    /// Serialises concurrent [`Self::install_model`] calls so two
    /// simultaneous installs cannot both clear the staleness gate
    /// against the same snapshot and let the older revision win the
    /// store race. Mirrors [`crate::yara::YaraEngine`]'s install
    /// lock. Readers never touch this lock.
    install_lock: parking_lot::Mutex<()>,
}

impl Default for UrlMlClassifier {
    fn default() -> Self {
        Self {
            inner: ArcSwap::from_pointee(None),
            install_lock: parking_lot::Mutex::new(()),
        }
    }
}

impl UrlMlClassifier {
    /// A classifier with no model installed. [`Self::classify`]
    /// abstains until [`Self::install_model`] succeeds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently installed model revision, or `None` when no
    /// model is installed.
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.inner.load().as_ref().as_ref().map(|m| m.version)
    }

    /// Whether a model is currently installed.
    #[must_use]
    pub fn has_model(&self) -> bool {
        self.inner.load().is_some()
    }

    /// Verify + decode + validate + swap a signed model bundle.
    ///
    /// 1. Verify the Ed25519 signature against `verifier`.
    /// 2. Reject a revision `<=` the installed one (downgrade
    ///    protection — a stale model must never silently regress
    ///    accuracy, the same guard the YARA / IPS / category bundles
    ///    apply).
    /// 3. Validate the model structure ([`LinearModel::from_claims`]);
    ///    a malformed model leaves the live model untouched.
    /// 4. ArcSwap the new model in.
    ///
    /// Returns the now-installed revision.
    pub fn install_model(
        &self,
        verifier: &UrlModelVerifier,
        bundle: &UrlModelBundle,
    ) -> Result<u64, SwgError> {
        let claims = verifier.verify_and_decode(bundle)?;
        // Serialise staleness-check → validate → swap so two
        // concurrent installs cannot both clear the staleness gate
        // against the same snapshot.
        let _guard = self.install_lock.lock();
        if let Some(current) = self.inner.load().as_ref().as_ref().map(|m| m.version)
            && claims.version <= current
        {
            return Err(SwgError::UrlModelStale {
                incoming: claims.version,
                current,
            });
        }
        let model = LinearModel::from_claims(claims)?;
        let version = model.version;
        self.inner.store(Arc::new(Some(model)));
        Ok(version)
    }

    /// Classify a URL. Returns `None` when no model is installed, the
    /// URL has no in-vocabulary token, or the verdict fails the
    /// confidence / margin gate.
    #[must_use]
    pub fn classify(&self, host: &str, path: &str) -> Option<Category> {
        let snap = self.inner.load();
        let model = snap.as_ref().as_ref()?;
        let features = build_features(model, host, path);
        model.predict(&features)
    }
}

/// Tokenise a URL into lowercase alphanumeric tokens.
///
/// The host and path are lowercased and split on every run of
/// non-alphanumeric ASCII characters (`.`, `/`, `-`, `_`, `?`, `=`,
/// `&`, digits-vs-letters boundaries are *not* split — `s3` stays
/// one token). Empty tokens are dropped. This is intentionally
/// simple and deterministic so the offline trainer can reproduce the
/// exact tokenisation byte-for-byte: the same split must be applied
/// when building the training vocabulary or the feature indices
/// would not line up with the shipped weights.
fn tokenize(host: &str, path: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for segment in [host, path] {
        for raw in segment.split(|c: char| !c.is_ascii_alphanumeric()) {
            if raw.is_empty() {
                continue;
            }
            tokens.push(raw.to_ascii_lowercase());
        }
    }
    tokens
}

/// Build the L2-normalised sparse TF-IDF feature vector for a URL
/// against a model's vocabulary + idf table.
///
/// Term frequency is the raw in-document count; the feature value is
/// `tf * idf[index]`; the full vector is then L2-normalised (the
/// scikit-learn `TfidfVectorizer` default with `sublinear_tf=False`,
/// `norm="l2"`). Tokens absent from the vocabulary are dropped.
fn build_features(model: &LinearModel, host: &str, path: &str) -> Vec<(usize, f32)> {
    // Accumulate term frequencies per feature index.
    let mut tf: HashMap<usize, f32> = HashMap::new();
    for tok in tokenize(host, path) {
        if let Some(&idx) = model.vocabulary.get(&tok) {
            *tf.entry(idx as usize).or_insert(0.0) += 1.0;
        }
    }
    if tf.is_empty() {
        return Vec::new();
    }
    let mut features: Vec<(usize, f32)> = tf
        .into_iter()
        .map(|(idx, count)| (idx, count * model.idf[idx]))
        .collect();
    // L2-normalise.
    let norm = features.iter().map(|&(_, v)| v * v).sum::<f32>().sqrt();
    if norm > 0.0 && norm.is_finite() {
        for (_, v) in &mut features {
            *v /= norm;
        }
    }
    // Sort by feature index for deterministic scoring order (the
    // score is order-independent, but a stable order keeps the
    // floating-point accumulation reproducible across runs).
    features.sort_unstable_by_key(|&(idx, _)| idx);
    features
}

// =========================================================================
// Tier 4 — local LLM fallback
// =========================================================================

/// Pluggable, on-device LLM categoriser consulted only when every
/// cheaper tier abstains.
///
/// The trait is `async` (an LLM inference is not instantaneous) and
/// intentionally narrow. A production deployment wires a local
/// llama.cpp-backed implementation; the request URL must never leave
/// the appliance (a hard multi-tenant privacy requirement), so a
/// remote LLM is *not* an acceptable implementation of this trait.
#[async_trait]
pub trait LocalLlmCategorizer: Send + Sync + std::fmt::Debug {
    /// Categorise a URL, or return `None` to abstain.
    async fn categorize(&self, host: &str, path: &str) -> Option<Category>;
}

// =========================================================================
// The composite hybrid categoriser
// =========================================================================

/// The four-tier hybrid URL categoriser. Implements
/// [`UrlCategorizer`] so it drops into the ext-authz handler behind
/// the same trait surface as [`LocalCategoryDb`].
#[derive(Debug)]
pub struct HybridUrlCategorizer {
    exact: Arc<LocalCategoryDb>,
    patterns: Arc<DomainPatternIndex>,
    ml: Arc<UrlMlClassifier>,
    llm: Option<Arc<dyn LocalLlmCategorizer>>,
}

impl HybridUrlCategorizer {
    /// Build a hybrid categoriser from its tiers. Use
    /// [`HybridUrlCategorizerBuilder`] for the common case.
    #[must_use]
    pub fn new(
        exact: Arc<LocalCategoryDb>,
        patterns: Arc<DomainPatternIndex>,
        ml: Arc<UrlMlClassifier>,
        llm: Option<Arc<dyn LocalLlmCategorizer>>,
    ) -> Self {
        Self {
            exact,
            patterns,
            ml,
            llm,
        }
    }

    /// Shared handle to the Tier 1 exact / curated table, for
    /// control-plane hot-swap of the operator feed.
    #[must_use]
    pub fn exact(&self) -> &Arc<LocalCategoryDb> {
        &self.exact
    }

    /// Shared handle to the Tier 2 domain-pattern index, for
    /// control-plane hot-swap of the community feed.
    #[must_use]
    pub fn patterns(&self) -> &Arc<DomainPatternIndex> {
        &self.patterns
    }

    /// Shared handle to the Tier 3 ML classifier, for control-plane
    /// hot-swap of the signed model bundle.
    #[must_use]
    pub fn ml(&self) -> &Arc<UrlMlClassifier> {
        &self.ml
    }
}

#[async_trait]
impl UrlCategorizer for HybridUrlCategorizer {
    async fn categorize(&self, host: &str, path: &str) -> Option<Category> {
        // Tier 1 — operator-curated exact / wildcard table. A hit
        // here is authoritative.
        if let Some(c) = self.exact.categorize_sync(host, path) {
            return Some(c);
        }
        // Tier 2 — community / vendor domain-pattern coverage.
        if let Some(c) = self.patterns.lookup(host) {
            return Some(c);
        }
        // Tier 3 — TF-IDF + linear ML, gated on confidence + margin.
        if let Some(c) = self.ml.classify(host, path) {
            return Some(c);
        }
        // Tier 4 — optional on-device LLM, last resort.
        if let Some(llm) = &self.llm {
            return llm.categorize(host, path).await;
        }
        None
    }
}

/// Builder for [`HybridUrlCategorizer`]. Tiers default to empty
/// (Tier 1 / 2 with no entries, Tier 3 with no model, Tier 4
/// disabled) so a caller wires only the tiers it has data for.
#[derive(Default)]
pub struct HybridUrlCategorizerBuilder {
    exact: Option<Arc<LocalCategoryDb>>,
    patterns: Option<Arc<DomainPatternIndex>>,
    ml: Option<Arc<UrlMlClassifier>>,
    llm: Option<Arc<dyn LocalLlmCategorizer>>,
}

impl std::fmt::Debug for HybridUrlCategorizerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridUrlCategorizerBuilder")
            .field("exact_set", &self.exact.is_some())
            .field("patterns_set", &self.patterns.is_some())
            .field("ml_set", &self.ml.is_some())
            .field("llm_set", &self.llm.is_some())
            .finish()
    }
}

impl HybridUrlCategorizerBuilder {
    /// Start an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Tier 1 exact / curated table.
    #[must_use]
    pub fn exact(mut self, exact: Arc<LocalCategoryDb>) -> Self {
        self.exact = Some(exact);
        self
    }

    /// Set the Tier 2 domain-pattern index.
    #[must_use]
    pub fn patterns(mut self, patterns: Arc<DomainPatternIndex>) -> Self {
        self.patterns = Some(patterns);
        self
    }

    /// Set the Tier 3 ML classifier.
    #[must_use]
    pub fn ml(mut self, ml: Arc<UrlMlClassifier>) -> Self {
        self.ml = Some(ml);
        self
    }

    /// Set the Tier 4 local LLM fallback.
    #[must_use]
    pub fn llm(mut self, llm: Arc<dyn LocalLlmCategorizer>) -> Self {
        self.llm = Some(llm);
        self
    }

    /// Finish the build, defaulting any unset tier to its empty form.
    #[must_use]
    pub fn build(self) -> HybridUrlCategorizer {
        HybridUrlCategorizer::new(
            self.exact
                .unwrap_or_else(|| Arc::new(LocalCategoryDb::default())),
            self.patterns
                .unwrap_or_else(|| Arc::new(DomainPatternIndex::default())),
            self.ml.unwrap_or_else(|| Arc::new(UrlMlClassifier::new())),
            self.llm,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::categorizer::CategoryEntry;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;

    // ---- Tier 2: domain pattern index -----------------------------------

    fn dp(pattern: &str, cat: &str) -> DomainPattern {
        DomainPattern {
            pattern: pattern.into(),
            category: Category::new(cat),
        }
    }

    #[test]
    fn pattern_index_matches_apex_and_subdomains() {
        let idx = DomainPatternIndex::new(vec![dp("doubleclick.net", "advertising")]);
        assert_eq!(
            idx.lookup("doubleclick.net"),
            Some(Category::new("advertising")),
            "apex matches"
        );
        assert_eq!(
            idx.lookup("ad.doubleclick.net"),
            Some(Category::new("advertising")),
            "subdomain matches"
        );
        assert_eq!(
            idx.lookup("g.eu.ad.doubleclick.net"),
            Some(Category::new("advertising")),
            "deep subdomain matches"
        );
        assert_eq!(idx.lookup("notdoubleclick.net"), None, "no label boundary");
        assert_eq!(idx.lookup("example.com"), None, "unrelated host");
    }

    #[test]
    fn pattern_index_wildcard_and_plain_are_equivalent() {
        let idx = DomainPatternIndex::new(vec![dp("*.gambling.example", "gambling")]);
        assert_eq!(
            idx.lookup("roulette.gambling.example"),
            Some(Category::new("gambling"))
        );
        assert_eq!(
            idx.lookup("gambling.example"),
            Some(Category::new("gambling")),
            "wildcard still matches the apex"
        );
    }

    #[test]
    fn pattern_index_longest_suffix_wins() {
        let idx = DomainPatternIndex::new(vec![
            dp("example.com", "business"),
            dp("mail.example.com", "webmail"),
        ]);
        assert_eq!(
            idx.lookup("inbox.mail.example.com"),
            Some(Category::new("webmail")),
            "more specific suffix wins"
        );
        assert_eq!(
            idx.lookup("www.example.com"),
            Some(Category::new("business")),
            "less specific suffix for other subdomains"
        );
    }

    #[test]
    fn pattern_index_last_entry_wins_on_conflict() {
        // Operator overlay appended after the community default must
        // win (last-wins), mirroring LocalCategoryDb.
        let idx = DomainPatternIndex::new(vec![
            dp("tracker.example", "advertising"),
            dp("tracker.example", "blocked"),
        ]);
        assert_eq!(
            idx.lookup("tracker.example"),
            Some(Category::new("blocked"))
        );
        assert_eq!(idx.len(), 1, "conflict collapses to one row");
    }

    #[test]
    fn pattern_index_canonicalises_case_and_dots() {
        let idx = DomainPatternIndex::new(vec![dp("  .Ads.Example.COM. ", "Advertising")]);
        assert_eq!(
            idx.lookup("PIXEL.ads.example.com"),
            Some(Category::new("advertising")),
            "host + pattern + category all case-folded"
        );
    }

    #[test]
    fn pattern_index_empty_lookup_is_none() {
        let idx = DomainPatternIndex::default();
        assert!(idx.is_empty());
        assert_eq!(idx.lookup("anything.example"), None);
        assert_eq!(idx.lookup(""), None);
    }

    // ---- Tier 3: signed model + classifier ------------------------------

    fn deterministic_keypair() -> (SigningKey, UrlModelSigningKeyId) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let id = UrlModelSigningKeyId::new("0123456789abcdef").unwrap();
        (signing, id)
    }

    /// A tiny two-class model: class 0 = "gambling" keyed on the
    /// token "casino", class 1 = "news" keyed on the token "news".
    /// idf is 1.0 for both tokens so the math is easy to reason
    /// about; the gates are permissive so a single strong token
    /// classifies.
    fn sample_claims(version: u64) -> UrlModelClaims {
        let mut vocab = HashMap::new();
        vocab.insert("casino".to_owned(), 0u32);
        vocab.insert("news".to_owned(), 1u32);
        UrlModelClaims {
            schema_version: 1,
            version,
            compiler: "sng-test/0".to_owned(),
            classes: vec!["gambling".to_owned(), "news".to_owned()],
            vocabulary: vocab,
            idf: vec![1.0, 1.0],
            // Row-major [2 classes * 2 features]:
            //   class 0 (gambling): casino=+4, news=-4
            //   class 1 (news):     casino=-4, news=+4
            weights: vec![4.0, -4.0, -4.0, 4.0],
            bias: vec![0.0, 0.0],
            min_confidence: 0.6,
            min_margin: 0.1,
        }
    }

    fn make_bundle(
        claims: &UrlModelClaims,
        signing: &SigningKey,
        id: UrlModelSigningKeyId,
    ) -> UrlModelBundle {
        let body = claims.encode().unwrap();
        let sig = signing.sign(&body);
        UrlModelBundle {
            body,
            signature: UrlModelSignature {
                bytes: sig.to_bytes(),
            },
            signing_key_id: id,
        }
    }

    fn verifier_with(signing: &SigningKey, id: &UrlModelSigningKeyId) -> UrlModelVerifier {
        let mut v = UrlModelVerifier::new();
        v.add_key(id.clone(), signing.verifying_key().as_bytes())
            .unwrap();
        v
    }

    #[test]
    fn classifier_installs_and_predicts() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let clf = UrlMlClassifier::new();
        assert!(!clf.has_model());
        assert_eq!(clf.classify("casino.example", "/"), None, "no model yet");

        let bundle = make_bundle(&sample_claims(1), &signing, id);
        assert_eq!(clf.install_model(&verifier, &bundle).unwrap(), 1);
        assert_eq!(clf.version(), Some(1));

        assert_eq!(
            clf.classify("casino.example", "/play"),
            Some(Category::new("gambling"))
        );
        assert_eq!(
            clf.classify("daily.example", "/news/today"),
            Some(Category::new("news"))
        );
        assert_eq!(
            clf.classify("unknown.example", "/about"),
            None,
            "no in-vocabulary token -> abstain"
        );
    }

    #[test]
    fn classifier_rejects_tampered_body() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let clf = UrlMlClassifier::new();
        let mut bundle = make_bundle(&sample_claims(1), &signing, id);
        bundle.body[0] ^= 0x01;
        assert!(matches!(
            clf.install_model(&verifier, &bundle),
            Err(SwgError::UrlModelSignatureInvalid)
        ));
        assert!(!clf.has_model(), "tampered model must not install");
    }

    #[test]
    fn classifier_rejects_unknown_key() {
        let (signing, id) = deterministic_keypair();
        let bundle = make_bundle(&sample_claims(1), &signing, id);
        let empty = UrlModelVerifier::new();
        assert!(matches!(
            UrlMlClassifier::new().install_model(&empty, &bundle),
            Err(SwgError::UrlModelUnknownKey(_))
        ));
    }

    #[test]
    fn classifier_rejects_stale_revision() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let clf = UrlMlClassifier::new();
        clf.install_model(
            &verifier,
            &make_bundle(&sample_claims(5), &signing, id.clone()),
        )
        .unwrap();
        // Equal revision is rejected.
        assert!(matches!(
            clf.install_model(
                &verifier,
                &make_bundle(&sample_claims(5), &signing, id.clone())
            ),
            Err(SwgError::UrlModelStale {
                incoming: 5,
                current: 5
            })
        ));
        // Older revision is rejected.
        assert!(matches!(
            clf.install_model(
                &verifier,
                &make_bundle(&sample_claims(3), &signing, id.clone())
            ),
            Err(SwgError::UrlModelStale {
                incoming: 3,
                current: 5
            })
        ));
        // Newer revision installs.
        assert_eq!(
            clf.install_model(&verifier, &make_bundle(&sample_claims(6), &signing, id))
                .unwrap(),
            6
        );
    }

    #[test]
    fn classifier_rejects_dimension_mismatch() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let mut claims = sample_claims(1);
        claims.bias.push(0.0); // 3 biases for 2 classes
        let clf = UrlMlClassifier::new();
        assert!(matches!(
            clf.install_model(&verifier, &make_bundle(&claims, &signing, id)),
            Err(SwgError::UrlModelInvalid(_))
        ));
    }

    #[test]
    fn classifier_rejects_single_class_model() {
        // A one-class model degenerates: softmax is always 1.0 and the
        // margin gate can never suppress, so it would label every
        // in-vocabulary URL into that class. The load path must reject
        // it even though it is otherwise well-formed and signed.
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let mut claims = sample_claims(1);
        claims.classes = vec!["gambling".to_owned()];
        claims.bias = vec![0.0];
        // weights must stay num_classes * vocab = 1 * 2 = 2.
        claims.weights = vec![1.0, -1.0];
        let clf = UrlMlClassifier::new();
        assert!(matches!(
            clf.install_model(&verifier, &make_bundle(&claims, &signing, id)),
            Err(SwgError::UrlModelInvalid(_))
        ));
    }

    #[test]
    fn classifier_rejects_whitespace_only_class_label() {
        // A class label that canonicalises to the empty string would
        // let the model emit an unnamed `Category("")`; the load path
        // must reject it even though the model is otherwise valid and
        // correctly signed.
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let mut claims = sample_claims(1);
        claims.classes[1] = "   ".to_owned();
        let clf = UrlMlClassifier::new();
        assert!(matches!(
            clf.install_model(&verifier, &make_bundle(&claims, &signing, id)),
            Err(SwgError::UrlModelInvalid(_))
        ));
    }

    #[test]
    fn classifier_rejects_out_of_range_vocab_index() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let mut claims = sample_claims(1);
        claims.vocabulary.insert("oops".to_owned(), 99);
        let clf = UrlMlClassifier::new();
        assert!(matches!(
            clf.install_model(&verifier, &make_bundle(&claims, &signing, id)),
            Err(SwgError::UrlModelInvalid(_))
        ));
    }

    #[test]
    fn classifier_margin_gate_suppresses_ambiguous_verdict() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        // Flat weights -> every class scores equally -> margin 0,
        // below the gate -> abstain even though a token matched.
        let mut claims = sample_claims(1);
        claims.weights = vec![0.0, 0.0, 0.0, 0.0];
        claims.min_margin = 0.5;
        let clf = UrlMlClassifier::new();
        clf.install_model(&verifier, &make_bundle(&claims, &signing, id))
            .unwrap();
        assert_eq!(
            clf.classify("casino.example", "/"),
            None,
            "tie below margin gate must abstain"
        );
    }

    // ---- Tokenisation ---------------------------------------------------

    #[test]
    fn tokenize_splits_host_and_path() {
        assert_eq!(
            tokenize("ad.Doubleclick.net", "/Track?id=9"),
            vec!["ad", "doubleclick", "net", "track", "id", "9"]
        );
    }

    // ---- Tier 4: LLM fallback -------------------------------------------

    #[derive(Debug)]
    struct StubLlm(Option<&'static str>);

    #[async_trait]
    impl LocalLlmCategorizer for StubLlm {
        async fn categorize(&self, _host: &str, _path: &str) -> Option<Category> {
            self.0.map(Category::new)
        }
    }

    // ---- Composite hybrid ordering --------------------------------------

    fn exact_with(entries: Vec<CategoryEntry>) -> Arc<LocalCategoryDb> {
        Arc::new(LocalCategoryDb::new(entries))
    }

    #[tokio::test]
    async fn hybrid_tier1_wins_over_lower_tiers() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let ml = Arc::new(UrlMlClassifier::new());
        ml.install_model(&verifier, &make_bundle(&sample_claims(1), &signing, id))
            .unwrap();
        let h = HybridUrlCategorizerBuilder::new()
            .exact(exact_with(vec![CategoryEntry {
                host: "casino.example".into(),
                path_prefix: None,
                category: Category::new("operator.allow"),
            }]))
            .patterns(Arc::new(DomainPatternIndex::new(vec![dp(
                "casino.example",
                "gambling",
            )])))
            .ml(ml)
            .build();
        // Exact-table verdict beats both the pattern index and the
        // ML model, which would each say "gambling".
        assert_eq!(
            h.categorize("casino.example", "/").await,
            Some(Category::new("operator.allow"))
        );
    }

    #[tokio::test]
    async fn hybrid_tier2_used_when_tier1_misses() {
        let h = HybridUrlCategorizerBuilder::new()
            .patterns(Arc::new(DomainPatternIndex::new(vec![dp(
                "doubleclick.net",
                "advertising",
            )])))
            .build();
        assert_eq!(
            h.categorize("ad.doubleclick.net", "/").await,
            Some(Category::new("advertising"))
        );
    }

    #[tokio::test]
    async fn hybrid_tier3_used_when_tier1_2_miss() {
        let (signing, id) = deterministic_keypair();
        let verifier = verifier_with(&signing, &id);
        let ml = Arc::new(UrlMlClassifier::new());
        ml.install_model(&verifier, &make_bundle(&sample_claims(1), &signing, id))
            .unwrap();
        let h = HybridUrlCategorizerBuilder::new().ml(ml).build();
        assert_eq!(
            h.categorize("casino.unknown", "/play").await,
            Some(Category::new("gambling"))
        );
    }

    #[tokio::test]
    async fn hybrid_tier4_llm_last_resort() {
        let h = HybridUrlCategorizerBuilder::new()
            .llm(Arc::new(StubLlm(Some("ai.guess"))))
            .build();
        assert_eq!(
            h.categorize("mystery.example", "/").await,
            Some(Category::new("ai.guess"))
        );
    }

    #[tokio::test]
    async fn hybrid_all_tiers_abstain_returns_none() {
        let h = HybridUrlCategorizerBuilder::new()
            .llm(Arc::new(StubLlm(None)))
            .build();
        assert_eq!(h.categorize("mystery.example", "/").await, None);
    }

    #[tokio::test]
    async fn hybrid_no_llm_configured_returns_none() {
        let h = HybridUrlCategorizerBuilder::new().build();
        assert_eq!(h.categorize("mystery.example", "/").await, None);
    }
}
