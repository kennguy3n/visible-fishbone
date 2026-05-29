//! Device identity bound to an Ed25519 keypair.
//!
//! Every agent / edge is enrolled with a device-bound Ed25519
//! keypair. The keypair plays two roles:
//!
//! * It is the **mTLS client-certificate keypair** — the client
//!   certificate the control plane issued during enrolment binds
//!   the agent's `device_id` to the public half of this key, so
//!   the server can authenticate the agent at the TLS handshake
//!   without an extra application-layer auth roundtrip.
//! * The agent uses the **same key** as the long-lived identity
//!   anchor for signed agent-side artifacts (re-enrolment proofs,
//!   policy-fetch challenges). Reusing a single keypair across
//!   both surfaces matches the SDA / SKA pattern and keeps the
//!   trust store on the server side small.
//!
//! [`DeviceIdentity`] is loaded from a pair of PEM files on disk
//! (private key + certificate chain) at agent startup. The loader
//! validates that the private key's public half matches the leaf
//! certificate's Subject Public Key Info — without this check, an
//! operator who accidentally swaps the wrong cert into place
//! would see a confusing mTLS handshake failure deep inside
//! rustls rather than a precise "your cert and key don't match"
//! error at startup.

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey, VerifyingKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sng_core::ids::DeviceId;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

/// Loaded device identity: an Ed25519 signing key plus the
/// certificate chain the control plane issued for it at
/// enrolment time.
///
/// `DeviceIdentity` deliberately does **not** implement `Clone`
/// because `PrivateKeyDer<'_>` from `rustls-pki-types` only
/// exposes an explicit `clone_key()` (not the standard `Clone`
/// trait) — this is intentional from the upstream crate so
/// private-key bytes are not accidentally copied through
/// derive-based duplication. Callers that need a duplicate
/// should construct one explicitly through
/// [`DeviceIdentity::client_auth_parts`] / [`DeviceIdentity::into_client_auth_parts`]
/// (for the rustls builder) and the public accessors on the
/// remaining fields. The expected pattern is to wrap a single
/// `DeviceIdentity` in `Arc` and share that.
pub struct DeviceIdentity {
    /// Ed25519 signing key (private half). Used as the mTLS client
    /// key and as the signing anchor for re-enrolment / challenge
    /// proofs.
    signing_key: SigningKey,
    /// PEM-decoded certificate chain. The first cert is the leaf
    /// the control plane issued; subsequent certs are
    /// intermediates the server may need to chain back to the
    /// enrolment root.
    certs: Vec<CertificateDer<'static>>,
    /// PKCS#8-encoded private key (matched against the leaf cert
    /// at construction time). Kept owned so callers can build a
    /// `rustls::ClientConfig` without re-reading from disk.
    pkcs8_key: PrivateKeyDer<'static>,
    /// Device id parsed out of the leaf certificate's CN, if
    /// present. Surfaced for log decoration; the authoritative
    /// `device_id` always lives in the config struct.
    device_id_hint: Option<DeviceId>,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include signing-key bytes in Debug output.
        f.debug_struct("DeviceIdentity")
            .field("device_id_hint", &self.device_id_hint)
            .field("certs", &self.certs.len())
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Construct an identity from in-memory PEM blobs. Used
    /// directly by tests and by callers that already have the
    /// bytes; the file-path constructor delegates here after
    /// reading both files off disk.
    ///
    /// The cert chain must contain at least one certificate, the
    /// private key must be PKCS#8 Ed25519, and the private key's
    /// public half must match the leaf certificate's Subject
    /// Public Key Info. Any other combination is rejected with a
    /// specific [`IdentityError`].
    pub fn from_pem(cert_chain_pem: &[u8], private_key_pem: &[u8]) -> Result<Self, IdentityError> {
        // Walk the cert chain PEM ourselves rather than pulling
        // in `rustls-pemfile` (RUSTSEC-2025-0134: unmaintained).
        // PEM is a stable RFC-7468 format and our parser only
        // needs the two blocks the enrolment issuer emits:
        // `CERTIFICATE` and `PRIVATE KEY` (PKCS#8).
        let certs: Vec<CertificateDer<'static>> = decode_pem_blocks(cert_chain_pem, "CERTIFICATE")
            .map_err(IdentityError::CertParse)?
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        if certs.is_empty() {
            return Err(IdentityError::EmptyCertChain);
        }

        // PKCS#8 first — the canonical encoding the rest of the
        // workspace (and Go's `crypto/ed25519`) emits. We accept
        // the canonical `PRIVATE KEY` label (PKCS#8 v1/v2); the
        // BoringSSL-style `EC PRIVATE KEY` and old RSA labels are
        // deliberately rejected to avoid the agent silently
        // loading the wrong key type.
        let pkcs8_bytes = decode_pem_blocks(private_key_pem, "PRIVATE KEY")
            .map_err(IdentityError::KeyParse)?
            .into_iter()
            .next()
            .ok_or(IdentityError::NoPrivateKey)?;
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes);

        // Decode the 32-byte Ed25519 seed out of the PKCS#8
        // envelope. ed25519-dalek's `from_pkcs8_der` is gated
        // behind the `pkcs8` feature which carries its own DER
        // parser; rather than pulling that in (and inflating the
        // `sng-agent` resident set), we extract the seed manually
        // from the well-known PKCS#8 v1 envelope for Ed25519,
        // which is the only encoding the control-plane issuer
        // emits.
        let seed = extract_ed25519_seed_from_pkcs8(pkcs8.secret_pkcs8_der())?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // Cross-check the keypair against the leaf cert's SPKI.
        // Mismatched cert + key is the single most common
        // operator misconfiguration; failing fast here turns it
        // into a clean startup error instead of a confusing
        // mid-handshake `BadCertificate` deep inside rustls.
        let leaf_spki = extract_ed25519_public_key_from_cert(certs[0].as_ref())?;
        if leaf_spki != verifying_key.to_bytes() {
            return Err(IdentityError::KeyCertMismatch);
        }

        let device_id_hint = parse_device_id_from_cert(certs[0].as_ref()).ok();
        debug!(
            device_id_hint = ?device_id_hint,
            cert_chain_len = certs.len(),
            "loaded device identity",
        );

        Ok(Self {
            signing_key,
            certs,
            pkcs8_key: PrivateKeyDer::Pkcs8(pkcs8),
            device_id_hint,
        })
    }

    /// Load an identity from a pair of PEM files on disk. The
    /// canonical layout the agent uses — config points at
    /// `cert_chain.pem` + `private_key.pem`, and this constructor
    /// reads both into memory.
    pub fn from_pem_files(
        cert_chain_path: &Path,
        private_key_path: &Path,
    ) -> Result<Self, IdentityError> {
        let cert_chain_pem = fs::read(cert_chain_path).map_err(|e| IdentityError::ReadFile {
            path: cert_chain_path.to_path_buf(),
            source: e,
        })?;
        let private_key_pem = fs::read(private_key_path).map_err(|e| IdentityError::ReadFile {
            path: private_key_path.to_path_buf(),
            source: e,
        })?;
        Self::from_pem(&cert_chain_pem, &private_key_pem)
    }

    /// Borrow the Ed25519 signing key (private half).
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Borrow the Ed25519 verifying key (public half).
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Borrow the parsed certificate chain — the leaf cert is at
    /// index 0, intermediates follow.
    #[must_use]
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }

    /// Take the PKCS#8 private key + certificate chain in the
    /// shape `rustls::ClientConfig::builder().with_client_auth_cert`
    /// expects. Consumes `self`; callers that need both the
    /// rustls handle and the Ed25519 keypair should clone first.
    #[must_use]
    pub fn into_client_auth_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certs, self.pkcs8_key)
    }

    /// Clone the rustls-shaped client-auth bits without consuming
    /// the identity. Used by the TLS config builder when the
    /// caller still wants the signing key for later use.
    #[must_use]
    pub fn client_auth_parts(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certs.clone(), self.pkcs8_key.clone_key())
    }

    /// Device id parsed out of the leaf cert's CN, if present.
    /// Returned best-effort for log decoration; the authoritative
    /// `device_id` is the value in the agent config.
    #[must_use]
    pub fn device_id_hint(&self) -> Option<DeviceId> {
        self.device_id_hint
    }
}

/// Errors returned by [`DeviceIdentity::from_pem`] /
/// [`DeviceIdentity::from_pem_files`]. Every variant is permanent
/// under the current files on disk — the orchestrator should
/// surface a config error and not retry.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Failed to read one of the PEM files off disk.
    #[error("reading {path:?}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// PEM block-walker returned an error parsing the cert
    /// chain.
    #[error("parsing certificate chain: {0}")]
    CertParse(#[source] io::Error),
    /// The certificate chain PEM did not contain any
    /// `CERTIFICATE` blocks.
    #[error("certificate chain PEM is empty")]
    EmptyCertChain,
    /// The private-key PEM did not contain any
    /// `PRIVATE KEY` block.
    #[error("private key PEM does not contain a PKCS#8 private key")]
    NoPrivateKey,
    /// PEM block-walker returned an error parsing the private
    /// key.
    #[error("parsing private key: {0}")]
    KeyParse(#[source] io::Error),
    /// PKCS#8 envelope did not advertise Ed25519 OID, or the
    /// inner seed was the wrong length.
    #[error("PKCS#8 envelope is not Ed25519 (or wrong seed length)")]
    UnsupportedKeyAlgorithm,
    /// The private key's public half does not match the leaf
    /// certificate's Subject Public Key Info. Almost always means
    /// the operator swapped a wrong cert / key file into place.
    #[error("private key does not match the leaf certificate's public key")]
    KeyCertMismatch,
    /// Leaf certificate's SPKI is not an Ed25519 key, so we
    /// cannot cross-check against the private key.
    #[error("leaf certificate's SubjectPublicKeyInfo is not Ed25519")]
    LeafNotEd25519,
    /// Leaf cert's DER could not be parsed enough to extract the
    /// SPKI. Permanent under the current cert file.
    #[error("leaf certificate could not be parsed: {0}")]
    CertDerInvalid(&'static str),
}

// ---------------------------------------------------------------------------
// Minimal X.509 / PKCS#8 helpers
// ---------------------------------------------------------------------------
//
// We deliberately avoid pulling in a full X.509 parser (x509-parser,
// rustls-webpki's internal parser) for two reasons:
//
//  1. We only need two specific fields — the leaf cert's
//     SubjectPublicKeyInfo (32-byte Ed25519 public key) and the
//     PKCS#8 seed (32-byte Ed25519 private key). The full parser
//     is overkill and would add ~200 KB to the resident `sng-agent`
//     binary.
//  2. The OID + DER framing for Ed25519 (RFC 8410) is fixed and
//     short. A hand-rolled extractor that bails on anything it
//     doesn't recognise is auditable and fast.
//
// Both helpers reject input that is not the well-known Ed25519
// envelope shape — the control plane's enrolment service is the
// only thing producing certs / keys for these agents, and it
// always emits the canonical RFC 8410 encoding.

/// Ed25519 OID `1.3.101.112` encoded as a DER OBJECT IDENTIFIER
/// value (5 bytes). Used as the AlgorithmIdentifier inside both
/// SubjectPublicKeyInfo (RFC 8410 §4) and PKCS#8 PrivateKeyInfo
/// (RFC 8410 §7).
const ED25519_OID_DER: &[u8] = &[0x2b, 0x65, 0x70];

/// Minimal RFC 7468 PEM block walker. Returns the base64-decoded
/// payload bytes of every `-----BEGIN <label>-----` block in
/// `input` whose label matches `wanted_label`. Used instead of
/// `rustls-pemfile` (RUSTSEC-2025-0134: unmaintained) — we only
/// need the two block labels the enrolment issuer emits
/// (`CERTIFICATE` and `PRIVATE KEY`), so a hand-rolled parser
/// is auditable and removes one supply-chain dependency.
fn decode_pem_blocks(mut input: &[u8], wanted_label: &str) -> io::Result<Vec<Vec<u8>>> {
    use base64::Engine as _;
    let begin_prefix = format!("-----BEGIN {wanted_label}-----");
    let end_prefix = format!("-----END {wanted_label}-----");
    let mut blocks = Vec::new();
    while !input.is_empty() {
        // Locate the start of the next block. We accept any
        // begin label and only error if the closing marker for
        // the matched label is missing.
        let Some(begin_idx) = memmem(input, b"-----BEGIN ") else {
            break;
        };
        input = &input[begin_idx..];
        let dash_dash_end = memmem(input, b"-----\n").or_else(|| memmem(input, b"-----\r\n"));
        let Some(header_end) = dash_dash_end else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PEM header missing terminator",
            ));
        };
        let header = &input[..header_end + 5];
        let label_matches = header.starts_with(begin_prefix.as_bytes());
        // Advance past the header line.
        input = &input[header_end + 5..];
        while input.first() == Some(&b'\r') || input.first() == Some(&b'\n') {
            input = &input[1..];
        }
        // Find the end marker (matching this header's label
        // family). We scan for `-----END ` and then validate
        // the label.
        let Some(end_idx) = memmem(input, b"-----END ") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PEM block missing END marker",
            ));
        };
        let payload_b64 = &input[..end_idx];
        let footer_start = end_idx;
        let footer_end_rel = memmem(&input[footer_start..], b"-----")
            .and_then(|i| {
                // Skip the first `-----` (right after END
                // <label>) — we want the second one that closes
                // the footer.
                memmem(&input[footer_start + i + 5..], b"-----").map(|j| footer_start + i + 5 + j)
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PEM block END marker incomplete",
                )
            })?;
        let footer = &input[footer_start..footer_end_rel + 5];
        if label_matches && footer.starts_with(end_prefix.as_bytes()) {
            // Strip whitespace (CR / LF / space / tab) from the
            // base64 payload before decoding.
            let cleaned: Vec<u8> = payload_b64
                .iter()
                .copied()
                .filter(|b| !matches!(*b, b'\r' | b'\n' | b' ' | b'\t'))
                .collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("PEM base64 decode: {e}"),
                    )
                })?;
            blocks.push(decoded);
        }
        input = &input[footer_end_rel + 5..];
    }
    Ok(blocks)
}

/// Naive byte-substring search. Adequate for the (small) PEM
/// blobs we parse — every cert / key is at most a few KiB. We do
/// not pull in `memchr` just for this.
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse a PKCS#8 PrivateKeyInfo for Ed25519 and return the
/// 32-byte seed. Accepts both PKCS#8 v1 (RFC 5208, version=0,
/// no trailing fields) and PKCS#8 v2 / OneAsymmetricKey (RFC
/// 5958, version=1, optional `attributes [0]` and `publicKey [1]`
/// trailing fields). rcgen + the upstream `ring` PKCS#8 builders
/// both emit v2 with the public key included, so v1-only parsing
/// would silently reject every key built in this codebase.
///
/// PKCS#8 wraps the raw seed in two OCTET STRING layers: the
/// outer `PrivateKey` OCTET STRING wraps an inner DER-encoded
/// OCTET STRING whose content IS the seed. We extract by
/// tag-walking — no general-purpose ASN.1 parser required.
fn extract_ed25519_seed_from_pkcs8(pkcs8: &[u8]) -> Result<[u8; 32], IdentityError> {
    let body = strip_der_sequence(pkcs8).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    // Version INTEGER: accept 0 (v1) or 1 (v2). Anything else
    // is a foreign encoding we do not validate against.
    let (version_value, body) =
        split_der_tlv(body, 0x02).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    match version_value {
        [0 | 1] => {}
        _ => return Err(IdentityError::UnsupportedKeyAlgorithm),
    }
    // AlgorithmIdentifier SEQUENCE containing OID 1.3.101.112.
    let (algo, body) = split_der_tlv(body, 0x30).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    let oid_value = strip_der_tlv(algo, 0x06).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    if oid_value != ED25519_OID_DER {
        return Err(IdentityError::UnsupportedKeyAlgorithm);
    }
    // PrivateKey OCTET STRING whose content is an inner OCTET
    // STRING wrapping the 32-byte seed. Use `split_der_tlv` here
    // (not `strip_der_tlv`) because for PKCS#8 v2 there will be
    // trailing optional [0] attributes / [1] publicKey fields we
    // need to ignore.
    let (outer_octet, _trailing) =
        split_der_tlv(body, 0x04).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    let inner_octet =
        strip_der_tlv(outer_octet, 0x04).ok_or(IdentityError::UnsupportedKeyAlgorithm)?;
    if inner_octet.len() != 32 {
        return Err(IdentityError::UnsupportedKeyAlgorithm);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_octet);
    Ok(seed)
}

/// Parse an X.509 Certificate (DER) far enough to extract the
/// SubjectPublicKeyInfo's BIT STRING contents, verifying that
/// the SPKI's AlgorithmIdentifier carries the Ed25519 OID. The
/// returned slice is the 32-byte Ed25519 public key.
fn extract_ed25519_public_key_from_cert(cert_der: &[u8]) -> Result<[u8; 32], IdentityError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let body = strip_der_sequence(cert_der)
        .ok_or(IdentityError::CertDerInvalid("missing outer SEQUENCE"))?;
    // tbsCertificate SEQUENCE.
    let (tbs, _) =
        split_der_tlv(body, 0x30).ok_or(IdentityError::CertDerInvalid("missing tbsCertificate"))?;
    // tbsCertificate fields, in order:
    //   version            [0] EXPLICIT Version DEFAULT v1
    //   serialNumber       INTEGER
    //   signature          AlgorithmIdentifier (SEQUENCE)
    //   issuer             Name (SEQUENCE)
    //   validity           SEQUENCE
    //   subject            Name (SEQUENCE)
    //   subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    //
    // We skip fields until we reach the SPKI by walking TLV
    // boundaries. The version tag is [0] EXPLICIT and only
    // present for v2/v3 certs; the enrolment issuer always emits
    // v3 so we skip it unconditionally if present.
    let mut rest = tbs;
    rest = skip_optional_tag(rest, 0xa0); // [0] EXPLICIT version
    rest = skip_tlv(rest, 0x02).ok_or(IdentityError::CertDerInvalid("missing serial"))?;
    rest = skip_tlv(rest, 0x30).ok_or(IdentityError::CertDerInvalid("missing signature alg"))?;
    rest = skip_tlv(rest, 0x30).ok_or(IdentityError::CertDerInvalid("missing issuer"))?;
    rest = skip_tlv(rest, 0x30).ok_or(IdentityError::CertDerInvalid("missing validity"))?;
    rest = skip_tlv(rest, 0x30).ok_or(IdentityError::CertDerInvalid("missing subject"))?;
    let (spki, _) = split_der_tlv(rest, 0x30).ok_or(IdentityError::CertDerInvalid(
        "missing subjectPublicKeyInfo",
    ))?;
    // Inside SPKI: AlgorithmIdentifier SEQUENCE { OID } || BIT STRING.
    let (algo, after_algo) = split_der_tlv(spki, 0x30)
        .ok_or(IdentityError::CertDerInvalid("malformed SPKI algorithm"))?;
    let oid_value = strip_der_tlv(algo, 0x06)
        .ok_or(IdentityError::CertDerInvalid("missing SPKI algorithm OID"))?;
    if oid_value != ED25519_OID_DER {
        return Err(IdentityError::LeafNotEd25519);
    }
    let bit_string = strip_der_tlv(after_algo, 0x03)
        .ok_or(IdentityError::CertDerInvalid("missing SPKI BIT STRING"))?;
    // BIT STRING in this context: leading byte = number of
    // unused bits (must be 0 for Ed25519), remaining 32 bytes
    // are the raw public key.
    if bit_string.len() != PUBLIC_KEY_LENGTH + 1 || bit_string[0] != 0 {
        return Err(IdentityError::CertDerInvalid("malformed SPKI BIT STRING"));
    }
    let mut public = [0u8; PUBLIC_KEY_LENGTH];
    public.copy_from_slice(&bit_string[1..]);
    Ok(public)
}

/// CommonName attribute type — OID 2.5.4.3.
const CN_OID: &[u8] = &[0x55, 0x04, 0x03];

/// Try to parse a device id (UUID) out of the leaf cert's Subject
/// CN. Best-effort — the cert may use a different naming
/// convention, in which case `None` is returned and callers fall
/// back to the device_id from the config struct.
fn parse_device_id_from_cert(cert_der: &[u8]) -> Result<DeviceId, ()> {
    // Walk to the Subject Name field.
    let body = strip_der_sequence(cert_der).ok_or(())?;
    let (tbs, _) = split_der_tlv(body, 0x30).ok_or(())?;
    let mut rest = tbs;
    rest = skip_optional_tag(rest, 0xa0);
    rest = skip_tlv(rest, 0x02).ok_or(())?; // serial
    rest = skip_tlv(rest, 0x30).ok_or(())?; // signature alg
    rest = skip_tlv(rest, 0x30).ok_or(())?; // issuer
    rest = skip_tlv(rest, 0x30).ok_or(())?; // validity
    let (subject, _) = split_der_tlv(rest, 0x30).ok_or(())?;
    // Subject is a SEQUENCE of RelativeDistinguishedName SETs;
    // each SET contains AttributeTypeAndValue SEQUENCEs.
    let mut subject_rest = subject;
    while !subject_rest.is_empty() {
        let (rdn, after_rdn) = split_der_tlv(subject_rest, 0x31).ok_or(())?;
        subject_rest = after_rdn;
        // Inside the RDN, look for AttributeTypeAndValue with
        // CommonName OID 2.5.4.3 (`55 04 03`).
        let mut atv_rest = rdn;
        while !atv_rest.is_empty() {
            let (atv, after_atv) = split_der_tlv(atv_rest, 0x30).ok_or(())?;
            atv_rest = after_atv;
            // ATV is `SEQUENCE { type OID, value ANY }` — use
            // `split_der_tlv` (not `strip_der_tlv`) so the
            // trailing value TLV can be consumed below.
            let (oid_value, after_oid) = split_der_tlv(atv, 0x06).ok_or(())?;
            if oid_value != CN_OID {
                continue;
            }
            // The value is a (Printable|UTF8|IA5)String — we
            // accept any string-shaped tag and treat its body
            // as UTF-8. The first byte of `after_oid` is the
            // string's ASN.1 tag, which we deliberately ignore
            // (CN is overwhelmingly UTF8String or
            // PrintableString in practice).
            if after_oid.is_empty() {
                return Err(());
            }
            let (_value_tag, len_and_body) = after_oid.split_first().ok_or(())?;
            let (value_len, header_len) = decode_der_len(len_and_body).ok_or(())?;
            let body_start = header_len;
            let body_end = body_start.checked_add(value_len).ok_or(())?;
            if body_end > len_and_body.len() {
                return Err(());
            }
            let value = &len_and_body[body_start..body_end];
            let cn = std::str::from_utf8(value).map_err(|_| ())?;
            return cn.parse::<DeviceId>().map_err(|_| ());
        }
    }
    Err(())
}

/// DER tag-walking primitives. These deliberately reject any
/// length encoding other than short-form (lengths < 128) or
/// long-form with up to 4 length bytes; that covers every cert /
/// key the enrolment issuer emits while keeping the parser
/// auditable.
fn strip_der_sequence(input: &[u8]) -> Option<&[u8]> {
    strip_der_tlv(input, 0x30)
}

fn strip_der_tlv(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (body, rest) = split_der_tlv(input, tag)?;
    if rest.is_empty() { Some(body) } else { None }
}

fn split_der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 || input[0] != tag {
        return None;
    }
    let (len, header_len) = decode_der_len(&input[1..])?;
    let body_start = 1 + header_len;
    let body_end = body_start.checked_add(len)?;
    if body_end > input.len() {
        return None;
    }
    Some((&input[body_start..body_end], &input[body_end..]))
}

fn skip_tlv(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (_, rest) = split_der_tlv(input, tag)?;
    Some(rest)
}

fn skip_optional_tag(input: &[u8], tag: u8) -> &[u8] {
    if input.first() == Some(&tag) {
        match split_der_tlv(input, tag) {
            Some((_, rest)) => rest,
            None => input,
        }
    } else {
        input
    }
}

fn decode_der_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || input.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for byte in &input[1..=count] {
        len = (len << 8) | usize::from(*byte);
    }
    Some((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
        SignatureAlgorithm,
    };

    /// Helper: mint a self-signed Ed25519 cert + the matching
    /// PKCS#8 private key, both in PEM form.
    fn mint_identity_pem() -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
        let mut params = CertificateParams::new(vec!["test-device".into()]).expect("rcgen params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-device");
        let cert = params.self_signed(&key).expect("cert");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    /// Helper: mint a CA-signed Ed25519 cert with a UUID CN.
    fn mint_uuid_cert_pem(device_uuid: &str) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
        let mut params = CertificateParams::new(vec![device_uuid.into()]).expect("rcgen params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, device_uuid);
        let cert = params.self_signed(&key).expect("cert");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    #[test]
    fn loads_matching_pem_pair() {
        let (cert_pem, key_pem) = mint_identity_pem();
        let id = DeviceIdentity::from_pem(&cert_pem, &key_pem).expect("identity loads");
        assert!(!id.cert_chain().is_empty());
        // Sanity-check: signing a payload and verifying the
        // signature against the leaf SPKI public key round-trips.
        let payload = b"sng-comms-identity-roundtrip";
        let sig = ed25519_dalek::Signer::sign(id.signing_key(), payload);
        ed25519_dalek::Verifier::verify(&id.verifying_key(), payload, &sig)
            .expect("signature verifies");
    }

    #[test]
    fn rejects_swapped_pairs() {
        let (cert_pem_a, _key_pem_a) = mint_identity_pem();
        let (_cert_pem_b, key_pem_b) = mint_identity_pem();
        let err =
            DeviceIdentity::from_pem(&cert_pem_a, &key_pem_b).expect_err("swapped pair must fail");
        assert!(matches!(err, IdentityError::KeyCertMismatch));
    }

    #[test]
    fn rejects_empty_cert_chain() {
        let (_cert_pem, key_pem) = mint_identity_pem();
        let err = DeviceIdentity::from_pem(b"", &key_pem).expect_err("empty cert chain must fail");
        assert!(matches!(err, IdentityError::EmptyCertChain));
    }

    #[test]
    fn rejects_missing_private_key() {
        let (cert_pem, _key_pem) = mint_identity_pem();
        let err = DeviceIdentity::from_pem(&cert_pem, b"").expect_err("missing key must fail");
        assert!(matches!(err, IdentityError::NoPrivateKey));
    }

    #[test]
    fn parses_uuid_cn_as_device_id_hint() {
        let device_uuid = "11111111-2222-3333-4444-555555555555";
        let (cert_pem, key_pem) = mint_uuid_cert_pem(device_uuid);
        let id = DeviceIdentity::from_pem(&cert_pem, &key_pem).expect("identity loads");
        let hint = id.device_id_hint().expect("device id hint parses");
        assert_eq!(hint.as_uuid().to_string(), device_uuid);
    }

    #[test]
    fn from_pem_files_reads_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let (cert_pem, key_pem) = mint_identity_pem();
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &key_pem).expect("write key");
        let id = DeviceIdentity::from_pem_files(&cert_path, &key_path)
            .expect("identity loads from disk");
        assert_eq!(id.cert_chain().len(), 1);
    }

    /// We don't pull in `rsa` etc, but a *non-Ed25519* PKCS#8
    /// envelope should be rejected with `UnsupportedKeyAlgorithm`
    /// — i.e. the OID check works. Use rcgen with an RSA key to
    /// exercise the negative path.
    #[test]
    fn rejects_non_ed25519_keys() {
        // rcgen always supports PKCS_RSA_SHA256 for tests.
        let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256);
        // The runtime feature flags on rcgen may not include the
        // RSA backend in this workspace's pinned version; skip
        // gracefully if so.
        let Ok(key) = key else {
            return;
        };
        let params = CertificateParams::new(vec!["test".into()]).expect("params");
        let cert = params.self_signed(&key).expect("cert");
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let err = DeviceIdentity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
            .expect_err("RSA must be rejected");
        // The non-Ed25519 SPKI OID rejection fires first because
        // the leaf check runs before the PKCS#8 check in
        // `from_pem`. Either error is correct here.
        assert!(matches!(
            err,
            IdentityError::UnsupportedKeyAlgorithm | IdentityError::LeafNotEd25519,
        ));
    }

    /// Silence the `unused` warnings on the helper types when
    /// rcgen's RSA backend is compiled out.
    #[allow(dead_code)]
    fn _force_use(_: BasicConstraints, _: IsCa, _: KeyUsagePurpose, _: &SignatureAlgorithm) {}
}
