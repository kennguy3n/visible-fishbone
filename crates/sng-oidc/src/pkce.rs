//! Proof Key for Code Exchange (PKCE), RFC 7636.
//!
//! A native app cannot keep a client secret confidential, so the
//! Authorization Code flow is protected with PKCE instead: the
//! client mints a high-entropy `code_verifier`, sends only its
//! SHA-256 hash (`code_challenge`, method `S256`) on the
//! authorization request, and proves possession of the verifier
//! on the token exchange. An attacker who intercepts the
//! authorization code cannot redeem it without the verifier.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};

/// The PKCE code-challenge method. Only `S256` is implemented;
/// the `plain` method is intentionally unsupported because every
/// provider this crate targets mandates `S256` and `plain`
/// offers no protection against a passive interceptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PkceMethod {
    /// `code_challenge = BASE64URL(SHA256(code_verifier))`.
    S256,
}

impl PkceMethod {
    /// The wire token sent as `code_challenge_method`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

impl fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A generated PKCE verifier/challenge pair.
///
/// The `verifier` is secret — it is sent only to the token
/// endpoint over TLS and never logged. The custom [`fmt::Debug`]
/// implementation redacts it.
#[derive(Clone)]
pub struct PkceChallenge {
    verifier: String,
    challenge: String,
    method: PkceMethod,
}

impl PkceChallenge {
    /// Generate a fresh PKCE pair using 32 bytes of OS entropy.
    ///
    /// The verifier is the BASE64URL (no padding) encoding of the
    /// random bytes, which yields a 43-character string drawn
    /// from the RFC 7636 unreserved set — comfortably inside the
    /// 43–128 character bound.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let verifier = URL_SAFE_NO_PAD.encode(entropy);
        let challenge = Self::derive_challenge(&verifier);
        Self {
            verifier,
            challenge,
            method: PkceMethod::S256,
        }
    }

    /// Derive the `S256` challenge for an existing verifier.
    /// Exposed for testing against the RFC 7636 Appendix B vector.
    #[must_use]
    pub fn derive_challenge(verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    /// The secret code verifier (sent to the token endpoint).
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The code challenge (sent on the authorization request).
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The challenge method (always [`PkceMethod::S256`]).
    #[must_use]
    pub fn method(&self) -> PkceMethod {
        self.method
    }
}

impl fmt::Debug for PkceChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkceChallenge")
            .field("verifier", &"<redacted>")
            .field("challenge", &self.challenge)
            .field("method", &self.method)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn s256_matches_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B: the verifier
        // "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" hashes to
        // the challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = PkceChallenge::derive_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn generated_verifier_is_within_length_bounds_and_url_safe() {
        let pkce = PkceChallenge::generate();
        let len = pkce.verifier().len();
        assert!(
            (43..=128).contains(&len),
            "verifier length {len} out of bounds"
        );
        assert!(
            pkce.verifier()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')),
            "verifier contains non-unreserved characters"
        );
        assert_eq!(pkce.method(), PkceMethod::S256);
    }

    #[test]
    fn challenge_is_deterministic_for_a_verifier() {
        let pkce = PkceChallenge::generate();
        assert_eq!(
            pkce.challenge(),
            PkceChallenge::derive_challenge(pkce.verifier())
        );
    }

    #[test]
    fn distinct_generations_produce_distinct_verifiers() {
        let a = PkceChallenge::generate();
        let b = PkceChallenge::generate();
        assert_ne!(a.verifier(), b.verifier());
    }

    #[test]
    fn debug_redacts_the_verifier() {
        let pkce = PkceChallenge::generate();
        let rendered = format!("{pkce:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(pkce.verifier()));
    }
}
