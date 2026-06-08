//! On-device ML Named-Entity-Recognition classifier (Workstream 4).
//!
//! Adds a fifth detector class to the endpoint DLP engine alongside
//! regex / keyword / fingerprint / MIP-label: a lightweight **NER**
//! classifier that labels spans of content as one of six sensitive
//! entity types ([`EntityClass`]) — person name, postal address,
//! phone number, bank account, medical record, or legal document.
//!
//! ## Real on-device inference (no network, no stub)
//!
//! Detection runs a genuine ONNX compute graph through ONNX Runtime
//! (the [`ort`] crate). The graph is a multinomial-logistic-regression
//! NER head — `softmax(features · W + b)` — over a fixed,
//! deterministic 17-dimensional feature vector extracted per token by
//! [`featurize_token`]. The model is tiny (sub-KB) and inference is a
//! single batched matmul, so a whole document classifies in well under
//! the 50 ms budget with zero network calls. The model is authored /
//! exported by `crates/sng-dlp/assets/train_ner_model.py` (see that
//! file for full provenance); the committed `ner_v1.onnx` is the asset
//! shipped inside the signed policy bundle.
//!
//! ## Signed-bundle trust chain
//!
//! The model binary is distributed as part of the Ed25519-signed
//! endpoint policy bundle and additionally carries a detached
//! signature over the model bytes. [`ModelVerifier`] checks that
//! signature against the same operator-provisioned trust store the
//! policy bundle uses ([`sng_core::policy::PolicyVerifier`]) before the
//! bytes are ever handed to ONNX Runtime — an unsigned, untrusted, or
//! tampered model is rejected and never executed
//! ([`NerModel::load_signed`]).
//!
//! ## Fail-safe regex fallback
//!
//! When no model is installed (or a model failed verification / load),
//! detection degrades to a **real** regex-and-context NER
//! ([`RegexNerFallback`]) that detects the same six entity classes
//! using shape patterns plus the locale keyword dictionaries. DLP is
//! never disarmed by a missing model — the fallback is fully
//! functional, just lower-recall than the trained head.
//!
//! ## Redaction invariant
//!
//! Every detection is reported as metadata only — entity class, byte
//! offset, length, and confidence — never the matched bytes, exactly
//! like the rest of [`crate::classifier`].

use crate::error::{DlpError, DlpResult};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ort::session::Session;
use ort::value::Tensor;
use sng_core::ids::PolicySigningKeyId;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

/// Width of the per-token feature vector. MUST equal `FEATURE_DIM` in
/// `assets/train_ner_model.py`; the [`ner_v1.featurecheck.json`]
/// fixture pins specific vectors so any drift between the Python
/// authoring code and [`featurize_token`] fails a unit test.
pub const FEATURE_DIM: usize = 17;

/// Number of output classes the NER head emits: `O` plus the six
/// [`EntityClass`] variants. MUST equal `NUM_CLASSES` in the exporter.
pub const NUM_CLASSES: usize = 7;

/// Minimum softmax probability for a token's predicted entity class to
/// be accepted. Below this the token is treated as `O` (not an
/// entity), so a low-confidence guess never produces a match. Chosen
/// so a bare number / capitalised word with no corroborating context
/// (which the trained head scores near the `O`/entity boundary) is
/// suppressed, keeping precision high.
pub const ML_CONFIDENCE_THRESHOLD: f64 = 0.60;

/// Confidence assigned to a [`RegexNerFallback`] detection. The
/// fallback is a deterministic shape+context match with no learned
/// score, so it reports a fixed, deliberately sub-`1.0` confidence
/// that still clears [`ML_CONFIDENCE_THRESHOLD`] — a contextual scorer
/// downstream can still adjust it.
pub const FALLBACK_CONFIDENCE: f64 = 0.75;

/// A sensitive entity class the NER head can label. The wire strings
/// (`as_wire` / [`EntityClass::from_wire`]) are what an `MlNer` rule's
/// `pattern_data` lists, and they match the column order of the ONNX
/// model's output (column 0 is the implicit `O`/non-entity class).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityClass {
    /// A person's name (`person_name`).
    PersonName,
    /// A postal / street address (`address`).
    Address,
    /// A telephone number (`phone_number`).
    PhoneNumber,
    /// A bank account / IBAN (`bank_account`).
    BankAccount,
    /// A medical record identifier (`medical_record`).
    MedicalRecord,
    /// A legal document / case identifier (`legal_document`).
    LegalDocument,
}

impl EntityClass {
    /// All six classes, in model-column order (after the `O` column).
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::PersonName,
            Self::Address,
            Self::PhoneNumber,
            Self::BankAccount,
            Self::MedicalRecord,
            Self::LegalDocument,
        ]
    }

    /// Canonical wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::PersonName => "person_name",
            Self::Address => "address",
            Self::PhoneNumber => "phone_number",
            Self::BankAccount => "bank_account",
            Self::MedicalRecord => "medical_record",
            Self::LegalDocument => "legal_document",
        }
    }

    /// Parse a wire string into a class, or `None` if unknown.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::all().into_iter().find(|c| c.as_wire() == s)
    }

    /// The output-column index of this class in the ONNX model
    /// (`O` is column 0, so the six entities are 1..=6).
    #[must_use]
    const fn model_column(self) -> usize {
        match self {
            Self::PersonName => 1,
            Self::Address => 2,
            Self::PhoneNumber => 3,
            Self::BankAccount => 4,
            Self::MedicalRecord => 5,
            Self::LegalDocument => 6,
        }
    }

    /// Map an ONNX output column back to an entity class. Column 0
    /// (`O`) maps to `None`.
    #[must_use]
    fn from_model_column(col: usize) -> Option<Self> {
        Self::all().into_iter().find(|c| c.model_column() == col)
    }
}

/// A single NER detection. **Metadata only** — never the matched
/// bytes (see the [`crate::classifier`] redaction invariant).
#[derive(Clone, Debug, PartialEq)]
pub struct DetectedEntity {
    /// The entity class the span was labelled with.
    pub class: EntityClass,
    /// Byte offset of the span within the (NFC-normalised) scan text.
    pub offset: usize,
    /// Byte length of the span in that same text.
    pub length: usize,
    /// Detection confidence in `0.0..=1.0`. For the ONNX head this is
    /// the softmax probability of the predicted class; for the regex
    /// fallback it is the fixed [`FALLBACK_CONFIDENCE`].
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// Tokenizer + feature extractor. Mirrors `assets/train_ner_model.py`
// byte-for-byte; the featurecheck fixture pins the contract.
// ---------------------------------------------------------------------------

/// A whitespace-delimited token with surrounding punctuation trimmed,
/// retaining the byte offset of the trimmed surface form so a match
/// can be reported as a span.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    /// The trimmed surface form.
    pub text: String,
    /// Byte offset of [`Self::text`] within the source string.
    pub offset: usize,
}

/// Surrounding punctuation trimmed from each token end. Mirrors
/// `_TRIM` in the exporter.
fn is_trim(c: char) -> bool {
    matches!(
        c,
        '.' | ','
            | ';'
            | ':'
            | '!'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '"'
            | '\''
            | '«'
            | '»'
            | '<'
            | '>'
    )
}

/// Split `text` on Unicode whitespace and trim surrounding
/// punctuation, mirroring the exporter's `tokenize`. Empty tokens
/// (pure punctuation) are dropped.
#[must_use]
pub fn tokenize(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                push_trimmed(text, s, i, &mut out);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        push_trimmed(text, s, text.len(), &mut out);
    }
    out
}

fn push_trimmed(text: &str, start: usize, end: usize, out: &mut Vec<Token>) {
    let chunk = &text[start..end];
    let trimmed = chunk.trim_matches(is_trim);
    if trimmed.is_empty() {
        return;
    }
    // Offset of the trimmed slice within `text`: start + the byte
    // length of the leading characters that were trimmed.
    let lead = chunk.len() - chunk.trim_start_matches(is_trim).len();
    out.push(Token {
        text: trimmed.to_owned(),
        offset: start + lead,
    });
}

macro_rules! kw_set {
    ($($w:literal),* $(,)?) => {{
        let mut s = HashSet::new();
        $( s.insert($w); )*
        s
    }};
}

static NAME_TITLES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "mr", "mrs", "ms", "miss", "dr", "prof", "sir", "madam", "name", "patient", "attn"
    ]
});
/// Common-given-name + surname gazetteer. A title-cased token that is
/// (or whose neighbour is) a common personal name reads as a person even
/// without a "Mr/Dr/name" cue, while a capitalised place / project word
/// does not. MUST stay byte-identical to `NAME_GAZ` in the exporter.
static NAME_GAZ: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "john",
        "james",
        "robert",
        "michael",
        "william",
        "david",
        "richard",
        "joseph",
        "thomas",
        "charles",
        "daniel",
        "matthew",
        "anthony",
        "mark",
        "paul",
        "steven",
        "andrew",
        "joshua",
        "kevin",
        "brian",
        "george",
        "edward",
        "ronald",
        "peter",
        "mary",
        "patricia",
        "jennifer",
        "linda",
        "elizabeth",
        "barbara",
        "susan",
        "jessica",
        "sarah",
        "karen",
        "nancy",
        "lisa",
        "margaret",
        "betty",
        "sandra",
        "emily",
        "maria",
        "priya",
        "wei",
        "ahmed",
        "ali",
        "omar",
        "fatima",
        "chen",
        "li",
        "kim",
        "smith",
        "johnson",
        "williams",
        "brown",
        "jones",
        "garcia",
        "miller",
        "davis",
        "rodriguez",
        "martinez",
        "hernandez",
        "lopez",
        "wilson",
        "anderson",
        "patel",
        "hassan",
        "khan",
        "carter",
        "nguyen",
        "kumar"
    ]
});
static ADDR_KW: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "street",
        "st",
        "avenue",
        "ave",
        "road",
        "rd",
        "lane",
        "ln",
        "boulevard",
        "blvd",
        "drive",
        "suite",
        "apt",
        "apartment",
        "floor",
        "block",
        "unit",
        "way",
        "court",
        "ct",
        "place",
        "terrace"
    ]
});
static PHONE_KW: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "phone",
        "tel",
        "telephone",
        "mobile",
        "cell",
        "fax",
        "call",
        "contact",
        "ph",
        "mob"
    ]
});
static BANK_KW: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "account",
        "acct",
        "iban",
        "routing",
        "swift",
        "bank",
        "a/c",
        "sort",
        "aba",
        "bic",
        "payment",
        "remit",
        "remittance",
        "transfer",
        "wire",
        "settle",
        "beneficiary",
        "funds",
        "deposit"
    ]
});
static MEDICAL_KW: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "patient",
        "diagnosis",
        "diagnosed",
        "mrn",
        "icd",
        "prescription",
        "prescribed",
        "medical",
        "record",
        "records",
        "hospital",
        "clinic",
        "chart",
        "treatment",
        "physician",
        "lab",
        "labs",
        "results",
        "admission",
        "intake",
        "ward",
        "specimen",
        "nurse",
        "attending"
    ]
});
static LEGAL_KW: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    kw_set![
        "plaintiff",
        "defendant",
        "contract",
        "agreement",
        "whereas",
        "hereby",
        "court",
        "case",
        "vs",
        "v",
        "attorney",
        "counsel",
        "clause",
        "exhibit",
        "docket",
        "matter",
        "deposition",
        "filing"
    ]
});

fn is_title_case(t: &str) -> bool {
    let mut chars = t.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if t.chars().count() < 2 || !first.is_alphabetic() || !first.is_uppercase() {
        return false;
    }
    chars.all(|c| c.is_alphabetic() && c.is_lowercase())
}

fn ascii_digit_count(t: &str) -> usize {
    t.chars().filter(char::is_ascii_digit).count()
}

fn is_all_digits(t: &str) -> bool {
    !t.is_empty() && t.chars().all(|c| c.is_ascii_digit())
}

fn phone_shape(t: &str) -> bool {
    ascii_digit_count(t) >= 7
        && t.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '(' | ')'))
}

/// Whether a phone-shaped token carries telephone punctuation
/// (`+`, `-`, or parentheses) rather than being a bare digit run. A
/// bare digit run is ambiguous, so [`RegexNerFallback`] requires a
/// nearby phone keyword before treating it as a phone number.
fn has_phone_punct(t: &str) -> bool {
    t.chars().any(|c| matches!(c, '+' | '-' | '(' | ')'))
}

fn alnum_account_shape(t: &str) -> bool {
    if t.chars().count() < 10 || !t.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let has_alpha = t.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = t.chars().any(|c| c.is_ascii_digit());
    let upper_only = t
        .chars()
        .all(|c| !c.is_ascii_alphabetic() || c.is_ascii_uppercase());
    has_alpha && has_digit && upper_only
}

fn has_digit_and_sep(t: &str) -> bool {
    t.chars().count() >= 5
        && t.chars().any(|c| c.is_ascii_digit())
        && t.chars().any(|c| matches!(c, '-' | '/'))
}

/// Extract the [`FEATURE_DIM`]-dimensional feature vector for token
/// `i` of `tokens`. Pure function of the token and a `±2` window.
/// Mirrors `featurize_token` in the exporter exactly.
#[must_use]
pub fn featurize_token(tokens: &[Token], i: usize) -> [f32; FEATURE_DIM] {
    let t = tokens[i].text.as_str();
    let lt = t.to_lowercase();
    let n = tokens.len();
    let length = t.chars().count();

    let neighbor_in = |set: &HashSet<&'static str>| -> bool {
        for j in [i.wrapping_sub(2), i.wrapping_sub(1), i + 1, i + 2] {
            if j < n && j != i && set.contains(tokens[j].text.to_lowercase().as_str()) {
                return true;
            }
        }
        false
    };
    let neighbor_title = || -> bool {
        for j in [i.wrapping_sub(1), i + 1] {
            if j < n && j != i && is_title_case(&tokens[j].text) {
                return true;
            }
        }
        false
    };

    // Token lengths and digit counts are tiny (a token is a single
    // whitespace-delimited word), so the `usize -> f32` casts here are
    // exact for every realistic input and the precision-loss lint does
    // not apply.
    #[allow(clippy::cast_precision_loss)]
    let digit_ratio = if length > 0 {
        ascii_digit_count(t) as f32 / length as f32
    } else {
        0.0
    };
    #[allow(clippy::cast_precision_loss)]
    let len_norm = length.min(20) as f32 / 20.0;
    let mut f = [0.0f32; FEATURE_DIM];
    f[0] = 1.0;
    f[1] = f32::from(is_title_case(t));
    f[2] = f32::from(is_all_digits(t));
    f[3] = digit_ratio;
    f[4] = len_norm;
    f[5] = f32::from(t.contains('@') && t.contains('.'));
    f[6] = f32::from(phone_shape(t));
    f[7] = f32::from(alnum_account_shape(t));
    f[8] = f32::from(neighbor_in(&NAME_TITLES));
    f[9] = f32::from(neighbor_in(&ADDR_KW) || ADDR_KW.contains(lt.as_str()));
    f[10] = f32::from(neighbor_in(&PHONE_KW));
    f[11] = f32::from(neighbor_in(&BANK_KW) || BANK_KW.contains(lt.as_str()));
    f[12] = f32::from(neighbor_in(&MEDICAL_KW) || MEDICAL_KW.contains(lt.as_str()));
    f[13] = f32::from(neighbor_in(&LEGAL_KW) || LEGAL_KW.contains(lt.as_str()));
    f[14] = f32::from(neighbor_title());
    f[15] = f32::from(has_digit_and_sep(t));
    f[16] = f32::from(neighbor_in(&NAME_GAZ) || NAME_GAZ.contains(lt.as_str()));
    f
}

/// Merge a per-token `(class, confidence)` label stream into entity
/// spans: consecutive tokens with the same class (each at or above
/// [`ML_CONFIDENCE_THRESHOLD`]) collapse into one span, taking the
/// strongest confidence in the run. Shared by the ONNX and fallback
/// paths so both produce identical span semantics.
fn merge_runs(tokens: &[Token], labels: &[(Option<EntityClass>, f64)]) -> Vec<DetectedEntity> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (Some(class), conf) = labels[i] else {
            i += 1;
            continue;
        };
        if conf < ML_CONFIDENCE_THRESHOLD {
            i += 1;
            continue;
        }
        let start = tokens[i].offset;
        let mut end = tokens[i].offset + tokens[i].text.len();
        let mut best = conf;
        let mut j = i + 1;
        while j < tokens.len() {
            match labels[j] {
                (Some(c), cf) if c == class && cf >= ML_CONFIDENCE_THRESHOLD => {
                    end = tokens[j].offset + tokens[j].text.len();
                    best = best.max(cf);
                    j += 1;
                }
                _ => break,
            }
        }
        out.push(DetectedEntity {
            class,
            offset: start,
            length: end - start,
            confidence: best,
        });
        i = j;
    }
    out
}

// ---------------------------------------------------------------------------
// Signed-model trust chain (mirrors `sng_core::policy::PolicyVerifier`).
// ---------------------------------------------------------------------------

/// A model binary plus the detached Ed25519 signature over its bytes
/// and the id of the key that produced the signature. This is the unit
/// shipped inside the signed endpoint policy bundle; the bundle's own
/// signature authenticates *that this `SignedModel` arrived intact*,
/// and [`ModelVerifier::verify`] re-checks the model bytes directly so
/// a model substituted after bundle decode is still rejected.
#[derive(Clone)]
pub struct SignedModel {
    /// The raw ONNX model bytes.
    pub model: Vec<u8>,
    /// Ed25519 signature over [`Self::model`].
    pub signature: [u8; ed25519_dalek::SIGNATURE_LENGTH],
    /// Identifier of the trusted key that signed the model.
    pub signing_key_id: PolicySigningKeyId,
}

impl std::fmt::Debug for SignedModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedModel")
            .field("model_len", &self.model.len())
            .field("signing_key_id", &self.signing_key_id)
            .finish_non_exhaustive()
    }
}

/// Trust-store-backed model verifier: operator-provisioned signing key
/// id → Ed25519 public key. Built from the same control-plane key
/// directory as [`sng_core::policy::PolicyVerifier`], so the model and
/// the policy that references it share one trust root.
#[derive(Clone, Debug, Default)]
pub struct ModelVerifier {
    keys: HashMap<PolicySigningKeyId, VerifyingKey>,
}

impl ModelVerifier {
    /// Build an empty verifier. Add keys with [`Self::add_key`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted signing key (32-byte raw Ed25519 public key, the
    /// form `crypto/ed25519.PublicKey` produces on the Go side). The
    /// ephemeral sentinel id is rejected for the same reason
    /// [`sng_core::policy::PolicyVerifier::add_key`] rejects it.
    ///
    /// # Errors
    /// Returns [`DlpError::ModelSignatureInvalid`] if `id` is the
    /// ephemeral sentinel or `key_bytes` is not a valid Ed25519 point.
    pub fn add_key(
        &mut self,
        id: PolicySigningKeyId,
        key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> DlpResult<()> {
        if id.is_ephemeral() {
            return Err(DlpError::ModelSignatureInvalid(
                "refusing to trust the ephemeral signing-key sentinel".to_owned(),
            ));
        }
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| DlpError::ModelSignatureInvalid(e.to_string()))?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Returns true if the verifier holds a key with the given id.
    #[must_use]
    pub fn has_key(&self, id: &PolicySigningKeyId) -> bool {
        self.keys.contains_key(id)
    }

    /// Verify a [`SignedModel`]'s Ed25519 signature over its model
    /// bytes against the trust store.
    ///
    /// # Errors
    /// Returns [`DlpError::ModelSignatureInvalid`] if the key id is
    /// ephemeral, no trusted key matches the id, or the signature does
    /// not verify over the model bytes.
    pub fn verify(&self, signed: &SignedModel) -> DlpResult<()> {
        if signed.signing_key_id.is_ephemeral() {
            return Err(DlpError::ModelSignatureInvalid(
                "model carries the ephemeral signing-key sentinel".to_owned(),
            ));
        }
        let key = self.keys.get(&signed.signing_key_id).ok_or_else(|| {
            DlpError::ModelSignatureInvalid(format!(
                "no trusted key for id {}",
                signed.signing_key_id
            ))
        })?;
        let sig = Signature::from_bytes(&signed.signature);
        key.verify(&signed.model, &sig)
            .map_err(|_| DlpError::ModelSignatureInvalid("signature does not verify".to_owned()))
    }
}

// ---------------------------------------------------------------------------
// ONNX model wrapper.
// ---------------------------------------------------------------------------

/// A loaded ONNX NER model ready for on-device inference.
///
/// The ONNX [`Session`] is held behind a [`Mutex`] because
/// `Session::run` takes `&mut self`, while the classifier that owns the
/// model is shared read-only behind the engine's `ArcSwap`. Endpoint
/// inspection classifies one content event at a time per worker and
/// inference is a single sub-millisecond matmul, so the lock is
/// uncontended in practice; serialising the rare concurrent call is the
/// correct, simple choice over per-thread session cloning.
pub struct NerModel {
    session: Mutex<Session>,
}

impl std::fmt::Debug for NerModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerModel").finish_non_exhaustive()
    }
}

impl NerModel {
    /// Load a model from raw ONNX bytes **without** signature
    /// verification. Use [`Self::load_signed`] on the production path;
    /// this entry point exists for tests and for callers that have
    /// already authenticated the bytes through the enclosing signed
    /// bundle.
    ///
    /// # Errors
    /// Returns [`DlpError::ModelLoad`] if the bytes are not a loadable
    /// ONNX graph.
    pub fn load_from_bytes(model: &[u8]) -> DlpResult<Self> {
        let session = Session::builder()
            .and_then(|b| b.commit_from_memory(model))
            .map_err(|e| DlpError::ModelLoad(e.to_string()))?;
        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Verify `signed` against `verifier` and, only if the signature is
    /// valid, load the model. An unsigned / untrusted / tampered model
    /// is rejected before it ever reaches ONNX Runtime.
    ///
    /// # Errors
    /// Returns [`DlpError::ModelSignatureInvalid`] if verification
    /// fails, or [`DlpError::ModelLoad`] if the verified bytes are not
    /// a loadable ONNX graph.
    pub fn load_signed(signed: &SignedModel, verifier: &ModelVerifier) -> DlpResult<Self> {
        verifier.verify(signed)?;
        Self::load_from_bytes(&signed.model)
    }

    /// Run inference over a batch of feature vectors, returning the
    /// argmax `(class, confidence)` per row. `O` (column 0) maps to
    /// `None`.
    ///
    /// # Errors
    /// Returns [`DlpError::ModelInference`] on a poisoned lock or any
    /// ONNX runtime / tensor-shape failure.
    fn infer(&self, rows: &[[f32; FEATURE_DIM]]) -> DlpResult<Vec<(Option<EntityClass>, f64)>> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let mut flat = Vec::with_capacity(rows.len() * FEATURE_DIM);
        for r in rows {
            flat.extend_from_slice(r);
        }
        let tensor = Tensor::from_array(([rows.len(), FEATURE_DIM], flat.into_boxed_slice()))
            .map_err(|e| DlpError::ModelInference(e.to_string()))?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| DlpError::ModelInference("model session lock poisoned".to_owned()))?;
        let outputs = session
            .run(ort::inputs![tensor])
            .map_err(|e| DlpError::ModelInference(e.to_string()))?;
        let (shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| DlpError::ModelInference(e.to_string()))?;
        // Expect [batch, NUM_CLASSES] row-major.
        let cols = shape.get(1).copied().and_then(|d| usize::try_from(d).ok());
        if shape.len() != 2 || cols != Some(NUM_CLASSES) {
            return Err(DlpError::ModelInference(format!(
                "unexpected output shape {shape:?}, want [n, {NUM_CLASSES}]"
            )));
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in data.chunks_exact(NUM_CLASSES) {
            let mut best_col = 0usize;
            let mut best_p = row[0];
            for (col, &p) in row.iter().enumerate() {
                if p > best_p {
                    best_p = p;
                    best_col = col;
                }
            }
            out.push((EntityClass::from_model_column(best_col), f64::from(best_p)));
        }
        Ok(out)
    }

    /// Detect entities in `text` via on-device ONNX inference. Returns
    /// merged entity spans (metadata only).
    ///
    /// # Errors
    /// Propagates [`DlpError::ModelInference`] from [`Self::infer`].
    pub fn detect(&self, text: &str) -> DlpResult<Vec<DetectedEntity>> {
        let tokens = tokenize(text);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<[f32; FEATURE_DIM]> = (0..tokens.len())
            .map(|i| featurize_token(&tokens, i))
            .collect();
        let labels = self.infer(&rows)?;
        Ok(merge_runs(&tokens, &labels))
    }
}

// ---------------------------------------------------------------------------
// Regex + context fallback NER (fail-safe path when no model loaded).
// ---------------------------------------------------------------------------

/// A real regex-and-context NER used when no ONNX model is installed.
///
/// It detects the same six [`EntityClass`]es using token shape
/// (digits, capitalisation, IBAN/phone structure) plus the locale
/// keyword dictionaries the trained head's features are built from.
/// Lower recall than the model, but fully functional — DLP is never
/// disarmed by a missing or rejected model.
#[derive(Debug, Default, Clone)]
pub struct RegexNerFallback;

impl RegexNerFallback {
    /// Classify a single token using only its own shape plus its `±2`
    /// keyword context. Returns the entity class, or `None` for `O`.
    fn classify_token(tokens: &[Token], i: usize) -> Option<EntityClass> {
        let t = tokens[i].text.as_str();
        let lt = t.to_lowercase();
        let n = tokens.len();
        let near = |set: &HashSet<&'static str>| -> bool {
            for j in [i.wrapping_sub(2), i.wrapping_sub(1), i + 1, i + 2] {
                if j < n && j != i && set.contains(tokens[j].text.to_lowercase().as_str()) {
                    return true;
                }
            }
            set.contains(lt.as_str())
        };

        // Shape signals first. A phone-shaped token carrying telephone
        // punctuation (+, -, parentheses) is unambiguous and stands on
        // its own; a *bare* run of digits (an order id, ticket number,
        // etc.) is ambiguous, so it is only called a phone number when
        // a phone keyword sits in its ±2 window — the same PHONE_KW
        // context cue the ONNX model weighs. This keeps the fallback
        // from labelling every long number a phone. An alphanumeric
        // account code (mixed letters+digits) remains a strong
        // standalone signal.
        if phone_shape(t) && (has_phone_punct(t) || near(&PHONE_KW)) {
            return Some(EntityClass::PhoneNumber);
        }
        if alnum_account_shape(t) {
            return Some(EntityClass::BankAccount);
        }

        // Context-gated classes. A token must be "salient" (a number,
        // code, or capitalised word) AND sit in the matching keyword
        // context — this is what keeps the fallback from labelling
        // ordinary words.
        let salient = is_all_digits(t) || has_digit_and_sep(t) || is_title_case(t);
        let numeric = is_all_digits(t) || has_digit_and_sep(t);

        if numeric && near(&BANK_KW) {
            return Some(EntityClass::BankAccount);
        }
        if numeric && near(&MEDICAL_KW) {
            return Some(EntityClass::MedicalRecord);
        }
        if numeric && near(&LEGAL_KW) {
            return Some(EntityClass::LegalDocument);
        }
        if salient && (ADDR_KW.contains(lt.as_str()) || near(&ADDR_KW)) {
            return Some(EntityClass::Address);
        }
        if is_title_case(t) && near(&NAME_TITLES) {
            return Some(EntityClass::PersonName);
        }
        None
    }

    /// Detect entities in `text`. Returns merged spans (metadata only).
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<DetectedEntity> {
        let tokens = tokenize(text);
        if tokens.is_empty() {
            return Vec::new();
        }
        let labels: Vec<(Option<EntityClass>, f64)> = (0..tokens.len())
            .map(|i| (Self::classify_token(&tokens, i), FALLBACK_CONFIDENCE))
            .collect();
        merge_runs(&tokens, &labels)
    }
}

// ---------------------------------------------------------------------------
// Detector facade used by the classifier.
// ---------------------------------------------------------------------------

/// The NER detector the [`crate::classifier::ContentClassifier`] drives
/// for `MlNer` rules. Runs the ONNX model when one is installed and
/// transparently degrades to [`RegexNerFallback`] otherwise.
#[derive(Debug, Default, Clone)]
pub struct MlNerDetector {
    model: Option<std::sync::Arc<NerModel>>,
    fallback: RegexNerFallback,
}

impl MlNerDetector {
    /// A detector with no model: every detection uses the regex
    /// fallback. This is the fail-safe default.
    #[must_use]
    pub fn fallback_only() -> Self {
        Self::default()
    }

    /// A detector backed by `model`, with the regex fallback retained
    /// for the (rare) case inference errors at runtime.
    #[must_use]
    pub fn with_model(model: std::sync::Arc<NerModel>) -> Self {
        Self {
            model: Some(model),
            fallback: RegexNerFallback,
        }
    }

    /// Whether a real ONNX model is installed (vs. fallback-only).
    #[must_use]
    pub fn has_model(&self) -> bool {
        self.model.is_some()
    }

    /// Detect entities in `text`. Uses the ONNX model if present; on
    /// any inference error (which should not happen for a loaded model)
    /// it falls back to the regex NER so detection is never lost.
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<DetectedEntity> {
        if let Some(model) = self.model.as_ref() {
            match model.detect(text) {
                Ok(entities) => return entities,
                Err(e) => {
                    tracing::warn!(error = %e, "ml-ner inference failed; using regex fallback");
                }
            }
        }
        self.fallback.detect(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn tokenize_trims_punctuation_and_tracks_offsets() {
        let text = "Call (Mr. Smith), please.";
        let toks = tokenize(text);
        let forms: Vec<&str> = toks.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(forms, vec!["Call", "Mr", "Smith", "please"]);
        // Offsets point at the trimmed surface form in the source.
        for t in &toks {
            assert_eq!(&text[t.offset..t.offset + t.text.len()], t.text);
        }
    }

    #[test]
    fn entity_class_wire_roundtrip() {
        for c in EntityClass::all() {
            assert_eq!(EntityClass::from_wire(c.as_wire()), Some(c));
        }
        assert_eq!(EntityClass::from_wire("not_a_class"), None);
    }

    #[test]
    fn fallback_detects_phone_and_iban_by_shape() {
        let f = RegexNerFallback;
        let ents = f.detect("Call +1-202-555-0173 or wire to GB29NWBK60161331926819 today");
        let classes: HashSet<EntityClass> = ents.iter().map(|e| e.class).collect();
        assert!(classes.contains(&EntityClass::PhoneNumber));
        assert!(classes.contains(&EntityClass::BankAccount));
    }

    #[test]
    fn fallback_is_context_gated_for_person_names() {
        let f = RegexNerFallback;
        // No name cue: capitalised words are not labelled as names.
        assert!(f.detect("London and Paris are open").is_empty());
        // With a name title cue, the following capitalised run is a name.
        let ents = f.detect("Mr John Smith signed");
        assert!(ents.iter().any(|e| e.class == EntityClass::PersonName));
    }

    #[test]
    fn fallback_detector_used_when_no_model() {
        let d = MlNerDetector::fallback_only();
        assert!(!d.has_model());
        let ents = d.detect("Call +1-202-555-0173");
        assert!(ents.iter().any(|e| e.class == EntityClass::PhoneNumber));
    }
}
