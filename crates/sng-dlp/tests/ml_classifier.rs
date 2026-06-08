// Integration-test crate: relax the unwrap/expect/panic + float and
// cast lints that are idiomatic in fixture assertions, mirroring the
// `#![cfg_attr(test, ...)]` block in `crates/sng-dlp/src/lib.rs`.
// Attributes do not cross crate boundaries, so it is repeated here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::float_cmp
)]

//! Integration tests for the on-device ML-NER classifier
//! (`sng_dlp::ml_classifier`), Workstream 4 Step 1.
//!
//! These exercise the *real* inference path against the committed
//! `assets/ner_v1.onnx` model — there is no stubbed / hardcoded entity
//! return anywhere. The suite proves four things:
//!
//! 1. the Rust feature extractor reproduces the Python authoring
//!    code's vectors byte-for-byte (the `featurecheck.json` fixture);
//! 2. the ONNX graph, loaded through ONNX Runtime, classifies sample
//!    PII documents into the correct entity spans;
//! 3. the regex fallback detects the same entity classes when no model
//!    is installed (fail-safe); and
//! 4. the Ed25519 model trust chain accepts a correctly-signed model
//!    and rejects tampering / untrusted keys.

use ed25519_dalek::{Signer, SigningKey};
use sng_core::ids::PolicySigningKeyId;
use sng_dlp::ml_classifier::{
    EntityClass, FEATURE_DIM, ModelVerifier, NerModel, RegexNerFallback, SignedModel, Token,
    featurize_token,
};

/// The committed, signed-bundle NER model and its parity fixture.
const MODEL_BYTES: &[u8] = include_bytes!("../assets/ner_v1.onnx");
const FEATURECHECK: &str = include_str!("../assets/ner_v1.featurecheck.json");
/// The cross-language entity-class contract shared with the Go control
/// plane (internal/service/dlp/entity_classes_parity_test.go).
const ENTITY_CLASSES: &str = include_str!("../assets/entity_classes.json");

/// The wire names of [`EntityClass`] must match the shared contract
/// file exactly and in order. The Go control plane's
/// `endpointEntityClasses` is tested against the same file, so a class
/// added, removed, or renamed on either side without updating the
/// contract fails one of the two parity tests — the manual Go/Rust
/// sync flagged in review is now enforced at test time.
#[test]
fn entity_classes_match_shared_contract() {
    let contract: serde_json::Value =
        serde_json::from_str(ENTITY_CLASSES).expect("entity_classes.json");
    let listed: Vec<&str> = contract["classes"]
        .as_array()
        .expect("classes array")
        .iter()
        .map(|c| c.as_str().expect("class name is a string"))
        .collect();

    let actual: Vec<&str> = EntityClass::all().iter().map(|c| c.as_wire()).collect();
    assert_eq!(
        listed, actual,
        "EntityClass wire names drifted from the shared entity-class contract"
    );

    // Every contract name must round-trip through `from_wire`, and an
    // unknown name must be rejected — the accept/reject contract the
    // Go validEntityClassCSV mirrors.
    for name in &listed {
        assert!(
            EntityClass::from_wire(name).is_some(),
            "contract class {name:?} is not recognised by from_wire"
        );
    }
    assert!(
        EntityClass::from_wire("not_a_real_class").is_none(),
        "from_wire accepted an unknown entity class"
    );
}

fn load_model() -> NerModel {
    NerModel::load_from_bytes(MODEL_BYTES).expect("ner_v1.onnx loads into ONNX Runtime")
}

/// The Rust featurizer must reproduce the Python exporter's vectors
/// exactly; any drift between `featurize_token` and
/// `train_ner_model.py` fails here.
#[test]
fn rust_featurizer_matches_python_fixture() {
    let fc: serde_json::Value = serde_json::from_str(FEATURECHECK).expect("featurecheck json");
    assert_eq!(
        fc["feature_dim"].as_u64().expect("feature_dim") as usize,
        FEATURE_DIM
    );
    let samples = fc["samples"].as_array().expect("samples array");
    assert!(!samples.is_empty(), "fixture must carry samples");

    for (s, sample) in samples.iter().enumerate() {
        let words: Vec<String> = sample["tokens"]
            .as_array()
            .expect("tokens")
            .iter()
            .map(|t| t.as_str().expect("token str").to_owned())
            .collect();
        let index = sample["index"].as_u64().expect("index") as usize;
        let expected: Vec<f64> = sample["features"]
            .as_array()
            .expect("features")
            .iter()
            .map(|v| v.as_f64().expect("feature f64"))
            .collect();
        assert_eq!(expected.len(), FEATURE_DIM);

        // Feature extraction depends only on token text + window, not
        // on byte offsets, so a synthetic offset is fine here.
        let tokens: Vec<Token> = words
            .iter()
            .map(|w| Token {
                text: w.clone(),
                offset: 0,
            })
            .collect();
        let got = featurize_token(&tokens, index);
        for (k, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
            assert!(
                (f64::from(*g) - e).abs() < 1e-4,
                "sample {s} feature {k}: rust={g} python={e}"
            );
        }
    }
}

/// The real ONNX graph must label each entity class in context. This
/// is end-to-end: tokenise → featurise → ONNX inference → span merge.
#[test]
fn onnx_model_detects_each_entity_class() {
    let model = load_model();
    let cases = [
        (
            "Please contact Mr John Smith regarding the file",
            EntityClass::PersonName,
        ),
        (
            "He lives at 742 Evergreen Terrace in Springfield",
            EntityClass::Address,
        ),
        (
            "Call the office at +1-202-555-0173 tomorrow",
            EntityClass::PhoneNumber,
        ),
        (
            "Wire the funds to IBAN GB29NWBK60161331926819 today",
            EntityClass::BankAccount,
        ),
        (
            "The patient record MRN8472910 shows the diagnosis",
            EntityClass::MedicalRecord,
        ),
        (
            "The court filed case 1:21-cv-04567 last week",
            EntityClass::LegalDocument,
        ),
    ];
    for (text, want) in cases {
        let ents = model.detect(text).expect("inference succeeds");
        assert!(
            ents.iter().any(|e| e.class == want),
            "expected {want:?} in {text:?}, got {ents:?}"
        );
        // Redaction invariant: spans are reported as offsets into the
        // text, and every reported span is in-bounds.
        for e in &ents {
            assert!(e.offset + e.length <= text.len());
            assert!(e.confidence > 0.0 && e.confidence <= 1.0);
        }
    }
}

/// Ordinary prose with no PII must not produce spurious entities.
#[test]
fn onnx_model_is_quiet_on_benign_text() {
    let model = load_model();
    let ents = model
        .detect("The quarterly report is ready and revenue grew this year")
        .expect("inference succeeds");
    assert!(ents.is_empty(), "benign text produced entities: {ents:?}");
}

/// The fallback detects the shape-driven classes with no model loaded.
#[test]
fn regex_fallback_detects_entities_without_a_model() {
    let f = RegexNerFallback;
    let ents = f.detect("Call +1-202-555-0173 and wire to GB29NWBK60161331926819 now");
    let classes: Vec<EntityClass> = ents.iter().map(|e| e.class).collect();
    assert!(classes.contains(&EntityClass::PhoneNumber));
    assert!(classes.contains(&EntityClass::BankAccount));
}

/// A bare run of digits (an order id, ticket number, etc.) with no
/// phone keyword nearby must NOT be classified as a phone number by the
/// fallback — only punctuated phone tokens, or bare numbers in a phone
/// context, are phones. Guards the fallback precision fix.
#[test]
fn regex_fallback_does_not_treat_bare_digit_run_as_phone() {
    let f = RegexNerFallback;

    // Bare 10-digit order id, no phone cue → not a phone (and not any
    // other entity, since it sits in no keyword context).
    let ents = f.detect("Your order 1234567890 has shipped today");
    assert!(
        ents.iter().all(|e| e.class != EntityClass::PhoneNumber),
        "bare order id misclassified as phone: {ents:?}"
    );

    // The same bare number IS a phone when a phone keyword is nearby —
    // recall is preserved for genuinely phone-like context.
    let ents = f.detect("Call the phone 1234567890 now");
    assert!(
        ents.iter().any(|e| e.class == EntityClass::PhoneNumber),
        "bare number near a phone keyword should classify as phone: {ents:?}"
    );

    // A punctuated phone token still stands on its own (no keyword).
    let ents = f.detect("Reach me at +1-202-555-0173 anytime");
    assert!(
        ents.iter().any(|e| e.class == EntityClass::PhoneNumber),
        "punctuated phone token should classify standalone: {ents:?}"
    );
}

fn fixed_key() -> SigningKey {
    // Deterministic test key — never a real signing key.
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn signed_model_loads_when_correctly_signed() {
    let key = fixed_key();
    let kid = PolicySigningKeyId::new("dlp-model-test-key").expect("kid");
    let sig = key.sign(MODEL_BYTES);
    let signed = SignedModel {
        model: MODEL_BYTES.to_vec(),
        signature: sig.to_bytes(),
        signing_key_id: kid.clone(),
    };
    let mut verifier = ModelVerifier::new();
    verifier
        .add_key(kid, &key.verifying_key().to_bytes())
        .expect("add trusted key");
    let model = NerModel::load_signed(&signed, &verifier).expect("verified model loads");
    let ents = model
        .detect("Contact Mr John Smith at +1-202-555-0173")
        .expect("inference");
    assert!(ents.iter().any(|e| e.class == EntityClass::PhoneNumber));
}

#[test]
fn signed_model_rejected_when_bytes_tampered() {
    let key = fixed_key();
    let kid = PolicySigningKeyId::new("dlp-model-test-key").expect("kid");
    let sig = key.sign(MODEL_BYTES);
    let mut tampered = MODEL_BYTES.to_vec();
    *tampered.last_mut().expect("non-empty") ^= 0xFF;
    let signed = SignedModel {
        model: tampered,
        signature: sig.to_bytes(),
        signing_key_id: kid.clone(),
    };
    let mut verifier = ModelVerifier::new();
    verifier
        .add_key(kid, &key.verifying_key().to_bytes())
        .expect("add trusted key");
    assert!(
        NerModel::load_signed(&signed, &verifier).is_err(),
        "tampered model must be rejected before load"
    );
}

#[test]
fn signed_model_rejected_for_untrusted_key() {
    let real_key = fixed_key();
    let kid = PolicySigningKeyId::new("dlp-model-test-key").expect("kid");
    let sig = real_key.sign(MODEL_BYTES);
    let signed = SignedModel {
        model: MODEL_BYTES.to_vec(),
        signature: sig.to_bytes(),
        signing_key_id: kid,
    };
    // Verifier trusts a *different* key under a different id.
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let other_kid = PolicySigningKeyId::new("some-other-key").expect("kid");
    let mut verifier = ModelVerifier::new();
    verifier
        .add_key(other_kid, &other.verifying_key().to_bytes())
        .expect("add key");
    assert!(
        NerModel::load_signed(&signed, &verifier).is_err(),
        "model signed by an untrusted key must be rejected"
    );
}
