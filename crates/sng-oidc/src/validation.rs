//! ID-token validation (OIDC Core §3.1.3.7) + JWKS handling.
//!
//! [`JwksClient`] fetches and TTL-caches a provider's JWK Set;
//! [`IdTokenValidator`] resolves the signing key by `kid`,
//! verifies the JWT signature (RS256/384/512 or ES256/384), and
//! enforces the registered claims (`iss`, `aud`, `exp`, `iat`)
//! plus the OIDC-specific `nonce` and `azp` checks. Custom claims
//! (`sub`, `email`, `name`, `groups`) are surfaced as
//! [`IdTokenClaims`] for ZTNA identity binding.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use parking_lot::Mutex;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::discovery::build_http_client;
use crate::error::{OidcError, Result};

/// A single JSON Web Key (RSA or EC public key).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type — `RSA` or `EC`.
    pub kty: String,
    /// Key id matched against the JWT header `kid`.
    #[serde(default)]
    pub kid: Option<String>,
    /// Intended algorithm, if the provider pins one.
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub e: Option<String>,
    /// EC curve name (e.g. `P-256`), present for `kty == "EC"`.
    #[serde(default)]
    pub crv: Option<String>,
    /// EC x coordinate (base64url), present for `kty == "EC"`.
    #[serde(default)]
    pub x: Option<String>,
    /// EC y coordinate (base64url), present for `kty == "EC"`.
    #[serde(default)]
    pub y: Option<String>,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    /// The keys advertised by the provider.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Find a key by `kid`. When the token header carries no
    /// `kid` and the set has exactly one key, that key is used.
    fn select(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }
}

/// Deserialize an `aud` claim that may be a single string or an
/// array of strings into a `Vec<String>`.
fn de_aud<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AudVisitor;

    impl<'de> Visitor<'de> for AudVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or an array of strings")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(AudVisitor)
}

/// The validated claims extracted from an ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier.
    pub iss: String,
    /// Subject — the stable user identifier bound to a ZTNA
    /// session.
    pub sub: String,
    /// Audience(s); normalised to a list.
    #[serde(default, deserialize_with = "de_aud")]
    pub aud: Vec<String>,
    /// Expiry (seconds since the Unix epoch).
    pub exp: i64,
    /// Issued-at (seconds since the Unix epoch).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Replay-binding nonce echoed from the authorization request.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Authorized party — present when the token has multiple
    /// audiences.
    #[serde(default)]
    pub azp: Option<String>,
    /// End-user email, when the `email` scope was granted.
    #[serde(default)]
    pub email: Option<String>,
    /// End-user display name, when the `profile` scope was
    /// granted.
    #[serde(default)]
    pub name: Option<String>,
    /// Group / role membership (provider-specific custom claim)
    /// used for ZTNA entitlement decisions.
    #[serde(default)]
    pub groups: Vec<String>,
    /// iam-core tenant the subject is scoped to (custom
    /// `tenant_id` claim). This is the **sole authoritative**
    /// source of the caller's tenant for tenant-isolation
    /// decisions — never a client-supplied header. `None` when the
    /// issuer is not iam-core or the token predates the claim; a
    /// caller that requires tenant isolation must fail closed on
    /// `None` rather than defaulting.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Authentication Methods References (RFC 8176): the methods
    /// the IdP used to authenticate the subject (e.g. `pwd`,
    /// `otp`, `mfa`, `hwk`). Populated by iam-core's
    /// universal-login when a tenant requires step-up; used to
    /// confirm an MFA-satisfied session without a (nonexistent)
    /// verify endpoint.
    #[serde(default)]
    pub amr: Vec<String>,
    /// Authentication Context Class Reference (`acr`) the IdP
    /// asserted for this token, when present.
    #[serde(default)]
    pub acr: Option<String>,
    /// Optional explicit boolean MFA claim some deployments emit
    /// alongside `amr`. Treated as authoritative when present.
    #[serde(default)]
    pub mfa: Option<bool>,
}

/// `amr` factor values (RFC 8176) that, on their own, prove a
/// second authentication factor was used. A token whose `amr`
/// contains any of these is considered MFA-satisfied even without
/// an explicit `mfa` boolean claim.
///
/// The set covers RFC 8176's possession (`otp`, `totp`, `hwk`,
/// `swk`, `sms`, `tel`) and biometric (`face`, `fpt`, `iris`,
/// `retina`, `vbm`) factors plus the generic `mfa` marker.
/// Single-factor knowledge factors (`pwd`, `pin`, `kba`) are
/// deliberately excluded, as are signals that do not themselves
/// prove a second factor (`geo`, `rba`, `user`). Recognising a
/// factor here only suppresses an unnecessary step-up re-auth; an
/// unrecognised factor fails *safe* (toward step-up), so the list
/// is conservative by design. If iam-core begins emitting a new
/// RFC 8176 factor, add it here.
const MFA_AMR_FACTORS: &[&str] = &[
    "mfa", "otp", "totp", "hwk", "swk", "sms", "tel", "face", "fpt", "iris", "retina", "vbm",
];

impl IdTokenClaims {
    /// The authoritative tenant the subject is scoped to, if the
    /// token carries a non-empty `tenant_id` claim.
    ///
    /// Returns `None` for a missing or blank claim so a caller can
    /// fail closed (a token with no tenant must never be treated
    /// as belonging to a default / wildcard tenant).
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
    }

    /// Whether this token proves an MFA-satisfied authentication.
    ///
    /// True when the explicit `mfa` claim is `true`, or when `amr`
    /// carries any recognised second-factor method
    /// ([`MFA_AMR_FACTORS`]). Used to read MFA state from token
    /// claims per the iam-core contract; step-up re-auth is only
    /// needed when this returns `false`.
    #[must_use]
    pub fn mfa_satisfied(&self) -> bool {
        if self.mfa == Some(true) {
            return true;
        }
        // Case-insensitive match without allocating a `String` per
        // `amr` entry (`eq_ignore_ascii_case` folds in place).
        self.amr
            .iter()
            .any(|m| MFA_AMR_FACTORS.iter().any(|f| m.eq_ignore_ascii_case(f)))
    }
}

/// ID-token validator bound to one issuer + audience (client id).
#[derive(Debug, Clone)]
pub struct IdTokenValidator {
    issuer: String,
    audience: String,
    expected_nonce: Option<String>,
    leeway_secs: u64,
}

impl IdTokenValidator {
    /// Default clock-skew leeway applied to `exp` / `iat` (60s).
    pub const DEFAULT_LEEWAY_SECS: u64 = 60;

    /// Bind a validator to the issuer (from discovery) and the
    /// audience (the OAuth2 client id).
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            expected_nonce: None,
            leeway_secs: Self::DEFAULT_LEEWAY_SECS,
        }
    }

    /// Require the ID token's `nonce` to equal this value (the
    /// nonce sent on the authorization request).
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.expected_nonce = Some(nonce.into());
        self
    }

    /// Override the clock-skew leeway.
    #[must_use]
    pub fn with_leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }

    /// Fetch the JWK Set via `jwks_client` and validate `token`.
    ///
    /// This is the entry point callers should prefer over
    /// [`Self::validate_with_jwks`] because it is rotation-aware:
    /// providers rotate signing keys periodically, and tokens signed
    /// with a freshly-rotated key carry a `kid` that is not yet in
    /// the cached JWKS. When validation fails with
    /// [`OidcError::UnknownSigningKey`] — the precise symptom of that
    /// race — the JWK Set is re-fetched once (bypassing the cache via
    /// [`JwksClient::refresh`]) and validation is retried, so a
    /// rotation does not break sign-in for the remainder of the cache
    /// TTL. Every other error (bad signature, wrong `aud`/`iss`,
    /// expired, …) is returned immediately without a retry.
    pub async fn validate(
        &self,
        token: &str,
        jwks_client: &JwksClient,
        jwks_uri: &str,
    ) -> Result<IdTokenClaims> {
        let jwks = jwks_client.fetch(jwks_uri).await?;
        match self.validate_with_jwks(token, &jwks) {
            Err(OidcError::UnknownSigningKey { .. }) => {
                let refreshed = jwks_client.refresh(jwks_uri).await?;
                self.validate_with_jwks(token, &refreshed)
            }
            other => other,
        }
    }

    /// Validate `token` against an already-fetched `jwks`, returning
    /// the claims on success.
    ///
    /// Prefer [`Self::validate`] in production: it re-fetches the
    /// JWKS and retries on a `kid` miss (key rotation), which this
    /// method cannot do because it has no access to the
    /// [`JwksClient`].
    pub fn validate_with_jwks(&self, token: &str, jwks: &Jwks) -> Result<IdTokenClaims> {
        let header = decode_header(token)?;
        let algorithm = supported_algorithm(header.alg)?;

        let jwk =
            jwks.select(header.kid.as_deref())
                .ok_or_else(|| OidcError::UnknownSigningKey {
                    kid: header.kid.clone(),
                })?;
        // RFC 7517 §4.4: when the JWK pins an intended `alg`, it MUST
        // match the algorithm in the JWT header. Rejecting a mismatch
        // stops a key published for one algorithm (e.g. RS384) from
        // being used to verify a token signed with another (RS256).
        if let Some(jwk_alg) = jwk.alg.as_deref() {
            let pinned = Algorithm::from_str(jwk_alg).map_err(|_| {
                OidcError::Validation(format!("JWKS key pins unsupported alg {jwk_alg:?}"))
            })?;
            if pinned != algorithm {
                return Err(OidcError::Validation(format!(
                    "JWKS key alg {jwk_alg:?} does not match token header alg {algorithm:?}"
                )));
            }
        }
        let key = decoding_key(jwk, algorithm)?;

        let mut validation = Validation::new(algorithm);
        validation.algorithms = vec![algorithm];
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.leeway = self.leeway_secs;

        let data = decode::<IdTokenClaims>(token, &key, &validation)?;
        let claims = data.claims;

        self.check_nonce(&claims)?;
        self.check_iat(&claims)?;
        self.check_azp(&claims)?;

        Ok(claims)
    }

    fn check_nonce(&self, claims: &IdTokenClaims) -> Result<()> {
        if let Some(expected) = &self.expected_nonce {
            if claims.nonce.as_deref() != Some(expected.as_str()) {
                return Err(OidcError::Validation("nonce mismatch".to_owned()));
            }
        }
        Ok(())
    }

    fn check_iat(&self, claims: &IdTokenClaims) -> Result<()> {
        let Some(iat) = claims.iat else {
            return Err(OidcError::Validation("missing iat claim".to_owned()));
        };
        let now = chrono::Utc::now().timestamp();
        let leeway = i64::try_from(self.leeway_secs).unwrap_or(i64::MAX);
        if iat > now.saturating_add(leeway) {
            return Err(OidcError::Validation("iat is in the future".to_owned()));
        }
        Ok(())
    }

    fn check_azp(&self, claims: &IdTokenClaims) -> Result<()> {
        // OIDC Core §3.1.3.7: when there are multiple audiences,
        // `azp` MUST be present and identify this client. When
        // `azp` is present at all, it MUST equal the client id.
        if claims.aud.len() > 1 && claims.azp.is_none() {
            return Err(OidcError::Validation(
                "multiple audiences but azp is absent".to_owned(),
            ));
        }
        if let Some(azp) = &claims.azp {
            if azp != &self.audience {
                return Err(OidcError::Validation(
                    "azp does not match client id".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Map a JWT header algorithm to the supported asymmetric set.
fn supported_algorithm(alg: Algorithm) -> Result<Algorithm> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384 => Ok(alg),
        other => Err(OidcError::Validation(format!(
            "unsupported id-token signing algorithm: {other:?}"
        ))),
    }
}

/// Build a [`DecodingKey`] from a JWK, checking the key type is
/// consistent with the signing algorithm family.
fn decoding_key(jwk: &Jwk, alg: Algorithm) -> Result<DecodingKey> {
    let is_rsa = matches!(alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512);
    match (jwk.kty.as_str(), is_rsa) {
        ("RSA", true) => {
            let n = require_field(jwk.n.as_deref(), "RSA JWK missing n")?;
            let e = require_field(jwk.e.as_deref(), "RSA JWK missing e")?;
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        ("EC", false) => {
            let x = require_field(jwk.x.as_deref(), "EC JWK missing x")?;
            let y = require_field(jwk.y.as_deref(), "EC JWK missing y")?;
            Ok(DecodingKey::from_ec_components(x, y)?)
        }
        (kty, _) => Err(OidcError::Validation(format!(
            "JWK kty {kty} is incompatible with algorithm {alg:?}"
        ))),
    }
}

fn require_field<'a>(value: Option<&'a str>, message: &'static str) -> Result<&'a str> {
    value.ok_or_else(|| OidcError::Validation(message.to_owned()))
}

#[derive(Debug, Clone)]
struct CacheEntry {
    jwks: Arc<Jwks>,
    fetched_at: Instant,
}

/// Caching JWKS client.
#[derive(Debug)]
pub struct JwksClient {
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl JwksClient {
    /// Default cache TTL (1 hour).
    pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

    /// Build a JWKS client with the default TTL and a fresh
    /// rustls-backed HTTP client.
    pub fn new() -> Result<Self> {
        Self::with_ttl(Self::DEFAULT_TTL)
    }

    /// Build a JWKS client with an explicit TTL.
    pub fn with_ttl(ttl: Duration) -> Result<Self> {
        Ok(Self::with_client(build_http_client()?, ttl))
    }

    /// Build a JWKS client around a caller-supplied HTTP client.
    #[must_use]
    pub fn with_client(http: reqwest::Client, ttl: Duration) -> Self {
        Self {
            http,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Fetch (or return a cached copy of) the JWK Set at
    /// `jwks_uri`.
    pub async fn fetch(&self, jwks_uri: &str) -> Result<Arc<Jwks>> {
        if let Some(hit) = self.cached(jwks_uri) {
            return Ok(hit);
        }
        self.fetch_remote(jwks_uri).await
    }

    /// Force a fresh fetch of the JWK Set, bypassing the cache and
    /// replacing the cached copy with the result.
    ///
    /// Used to recover from a provider key rotation: when a token
    /// references a `kid` that is absent from the cached set, the
    /// cache is stale and a forced re-fetch picks up the rotated key.
    pub async fn refresh(&self, jwks_uri: &str) -> Result<Arc<Jwks>> {
        self.fetch_remote(jwks_uri).await
    }

    /// Fetch the JWK Set over the network and update the cache,
    /// unconditionally (callers gate on the cache themselves).
    async fn fetch_remote(&self, jwks_uri: &str) -> Result<Arc<Jwks>> {
        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::http("jwks", e))?;
        if !response.status().is_success() {
            return Err(OidcError::HttpStatus {
                context: "jwks",
                status: response.status().as_u16(),
            });
        }
        let body = response
            .text()
            .await
            .map_err(|e| OidcError::http("jwks", e))?;
        let jwks: Jwks = serde_json::from_str(&body).map_err(|e| OidcError::decode("jwks", e))?;

        let jwks = Arc::new(jwks);
        self.cache.lock().insert(
            jwks_uri.to_owned(),
            CacheEntry {
                jwks: Arc::clone(&jwks),
                fetched_at: Instant::now(),
            },
        );
        Ok(jwks)
    }

    fn cached(&self, jwks_uri: &str) -> Option<Arc<Jwks>> {
        let mut cache = self.cache.lock();
        let entry = cache.get(jwks_uri)?;
        if entry.fetched_at.elapsed() < self.ttl {
            Some(Arc::clone(&entry.jwks))
        } else {
            // Evict the stale entry rather than letting expired
            // key sets pile up for issuers that are no longer used.
            cache.remove(jwks_uri);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use pretty_assertions::assert_eq;

    // Deterministic RSA-2048 test key (generated once with
    // `openssl genrsa -traditional 2048`). Only ever used to sign
    // test fixtures — it protects nothing real.
    const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAvMTG1HiwHybKITBL4mlsLrcgl4fugXlMeH3HO2FdoT1+8NLa\n\
4Xlv4Dhy4xYjlDHuQB0ivLWMzqDcsfj3GisNVI809Q8Dj0zWCGdohFv84Jl4YVVS\n\
RLIFL7zxfYgS38XZ4zPkezrBYduvN2Xmd5z8igG9m0U7FuM3EHv+E5atQ1B6VyiV\n\
Ipca+Zeycw1Ufznn6igf5VREg23sOlCObW3WNFmmi2w4lq/SprA5PDsZqhTjM+Cb\n\
7FluoK2DKPWLjraIgu/OfuKP+jK/Gs6xsRj1fw7wvuRO7spfGTRUnTwcUrOALOV1\n\
feTXSScV5xI+DVZWjuWKoRUOLAZAwrVDSyovXQIDAQABAoIBAFbF5dhZuiw3uobT\n\
Gq7zYyV+TN8bP0oJJlvlBaaINXAfQrEVXER1fDYH/Nfin2xKH4kdW5B/rEB3tbui\n\
BITk8XXDdsaHpk1DNsgaMPNXDcF5CttDS1QEuVmecywPVw3Cd0x32DnFYovHXp4K\n\
m4y0f2o5Lp2nj2gP/on3VW5Pv0nHc/V898oOh1UM+uMhIQAiVXf4ADa1vpOKNBzM\n\
wJF/vErIKGUhokSfLhL4XGO4CHOXkUmLHvMwaUWnD9KY6H5thMmcVM+6RITOCriB\n\
BeTF2a6K7SiSCFCCMF6ylVYjHSPlEeDDm2jf7XXRkFkKaYN8W5XueG7ZYQAypZuI\n\
gaaHC4kCgYEA7+FTu01vTBQaKHvlDu+fT0y97/ygbXKfMWphuoLLJOmb5UEQqibw\n\
dIMbXZPxqQB3Wyv/HbOITYMHi3eIGtwztcE2pIJh/0TI8shpGHjQSkTjEN7Y8vqK\n\
DwqhoX3fi55MXIb/NUfke469yeiWsGmL6MfZJ43pIjZL7F6IbKH+2LsCgYEAyXQs\n\
zsKPWUI2yb9yVgkgN2qRxIJ+QpEh36ZFJvhqhl/cz/r9SeRxHZKXSza4hRO71+7k\n\
8FwSEH5vAl53oMyzXlRVBjGacm5RNcGH/lxMjpHg/u4J0nUn/Ckg6nytyrfRMRe8\n\
/BtTDfW7sEcy8dhKTyqj6fSMM4fW3cvyiN1WwscCgYBd1WKPjgbPV72zwGMlqI5E\n\
0twpmESZC5FCHz8DWk5krg0RbJY8OOcubGqz/D83wLrvqxIsaCIVUAAPij5vY1vG\n\
6UGasHXtCNciQUr7C6dOpgu8ea+bvG1s3NfE+BwN3Wo5d4U1Ll4uBvQumxD3CRJ1\n\
iFdlpZlgjKS+XWw4MlYiKQKBgCPwof3RIBnggj3D9fX7cs/wJ0lTrorZsZ1g4H1v\n\
XDHU8GP6dy2zn6qS+ILmpEy5lI2VhSqMgnyG0e8uQ1Fgs69khDayqsc3fy2D9Wsf\n\
tFjLFcTlWsM9O4D1JXYwACFmYd/MSF8B0PNwn6d3TFNxLvCovs2CX3DiDydKt15L\n\
fqsJAoGBAKASHx8L9w9TSPSIDqtzokn37S6Tl8tmoQCoRPbxIBnNe2fPScRXuzC/\n\
hCBbUiUPyiI4+pZBK9PBJSBfb5sOrlQX+yxgfK+mk0sZSTls/fhKGJmeNCKrIKIX\n\
W6hfl/TTkpSnVaa+z8hT842lIfS+Nk+7VWTjBSJSpwn3/rO6yfGu\n\
-----END RSA PRIVATE KEY-----\n";

    const TEST_RSA_N: &str = "vMTG1HiwHybKITBL4mlsLrcgl4fugXlMeH3HO2FdoT1-8NLa4Xlv4Dhy4xYjlDHuQB0ivLWMzqDcsfj3GisNVI809Q8Dj0zWCGdohFv84Jl4YVVSRLIFL7zxfYgS38XZ4zPkezrBYduvN2Xmd5z8igG9m0U7FuM3EHv-E5atQ1B6VyiVIpca-Zeycw1Ufznn6igf5VREg23sOlCObW3WNFmmi2w4lq_SprA5PDsZqhTjM-Cb7FluoK2DKPWLjraIgu_OfuKP-jK_Gs6xsRj1fw7wvuRO7spfGTRUnTwcUrOALOV1feTXSScV5xI-DVZWjuWKoRUOLAZAwrVDSyovXQ";
    const TEST_RSA_E: &str = "AQAB";
    const TEST_KID: &str = "test-key-1";

    fn test_jwks() -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "RSA".to_owned(),
                kid: Some(TEST_KID.to_owned()),
                alg: Some("RS256".to_owned()),
                n: Some(TEST_RSA_N.to_owned()),
                e: Some(TEST_RSA_E.to_owned()),
                crv: None,
                x: None,
                y: None,
            }],
        }
    }

    fn sign(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_owned());
        let key =
            EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("test RSA PEM should parse");
        encode(&header, claims, &key).expect("signing test JWT should succeed")
    }

    fn base_claims(exp: i64, iat: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-42",
            "aud": "client-abc",
            "exp": exp,
            "iat": iat,
            "nonce": "nonce-xyz",
            "email": "user@example.com",
            "name": "Test User",
            "groups": ["eng", "admins"]
        })
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn validates_a_well_formed_id_token() {
        let token = sign(&base_claims(now() + 3600, now()));
        let validator =
            IdTokenValidator::new("https://idp.example.com", "client-abc").with_nonce("nonce-xyz");
        let claims = validator
            .validate_with_jwks(&token, &test_jwks())
            .expect("token should validate");
        assert_eq!(claims.sub, "user-42");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.groups, vec!["eng".to_owned(), "admins".to_owned()]);
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = sign(&base_claims(now() + 3600, now()));
        let validator = IdTokenValidator::new("https://idp.example.com", "different-client");
        let err = validator
            .validate_with_jwks(&token, &test_jwks())
            .unwrap_err();
        assert!(matches!(err, OidcError::Jwt(_)));
    }

    #[test]
    fn rejects_wrong_issuer() {
        let token = sign(&base_claims(now() + 3600, now()));
        let validator = IdTokenValidator::new("https://evil.example.com", "client-abc");
        let err = validator
            .validate_with_jwks(&token, &test_jwks())
            .unwrap_err();
        assert!(matches!(err, OidcError::Jwt(_)));
    }

    #[test]
    fn rejects_expired_token() {
        let token = sign(&base_claims(now() - 3600, now() - 7200));
        let validator = IdTokenValidator::new("https://idp.example.com", "client-abc");
        let err = validator
            .validate_with_jwks(&token, &test_jwks())
            .unwrap_err();
        assert!(matches!(err, OidcError::Jwt(_)));
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let token = sign(&base_claims(now() + 3600, now()));
        let validator = IdTokenValidator::new("https://idp.example.com", "client-abc")
            .with_nonce("a-different-nonce");
        let err = validator
            .validate_with_jwks(&token, &test_jwks())
            .unwrap_err();
        assert!(matches!(err, OidcError::Validation(_)));
    }

    #[test]
    fn rejects_unknown_kid() {
        let token = sign(&base_claims(now() + 3600, now()));
        let mut jwks = test_jwks();
        jwks.keys[0].kid = Some("some-other-kid".to_owned());
        let validator = IdTokenValidator::new("https://idp.example.com", "client-abc");
        let err = validator.validate_with_jwks(&token, &jwks).unwrap_err();
        assert!(matches!(err, OidcError::UnknownSigningKey { .. }));
    }

    #[test]
    fn rejects_jwk_alg_mismatch() {
        // Token is signed RS256, but the JWK pins RS384.
        let token = sign(&base_claims(now() + 3600, now()));
        let mut jwks = test_jwks();
        jwks.keys[0].alg = Some("RS384".to_owned());
        let validator =
            IdTokenValidator::new("https://idp.example.com", "client-abc").with_nonce("nonce-xyz");
        let err = validator.validate_with_jwks(&token, &jwks).unwrap_err();
        assert!(matches!(err, OidcError::Validation(_)));
    }

    #[test]
    fn accepts_jwk_without_pinned_alg() {
        // A JWK that omits `alg` must still validate against a
        // matching `kid` — the cross-check only applies when pinned.
        let token = sign(&base_claims(now() + 3600, now()));
        let mut jwks = test_jwks();
        jwks.keys[0].alg = None;
        let validator =
            IdTokenValidator::new("https://idp.example.com", "client-abc").with_nonce("nonce-xyz");
        let claims = validator
            .validate_with_jwks(&token, &jwks)
            .expect("token should validate when JWK omits alg");
        assert_eq!(claims.sub, "user-42");
    }

    #[test]
    fn rejects_azp_mismatch() {
        let mut claims = base_claims(now() + 3600, now());
        claims["aud"] = serde_json::json!(["client-abc", "other-aud"]);
        claims["azp"] = serde_json::json!("not-our-client");
        let token = sign(&claims);
        let validator = IdTokenValidator::new("https://idp.example.com", "client-abc");
        let err = validator
            .validate_with_jwks(&token, &test_jwks())
            .unwrap_err();
        assert!(matches!(err, OidcError::Validation(_)));
    }

    #[test]
    fn aud_deserializes_from_string_or_array() {
        let single: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "one", "exp": 1
        }))
        .unwrap();
        assert_eq!(single.aud, vec!["one".to_owned()]);

        let many: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": ["one", "two"], "exp": 1
        }))
        .unwrap();
        assert_eq!(many.aud, vec!["one".to_owned(), "two".to_owned()]);
    }

    #[test]
    fn validate_surfaces_tenant_and_mfa_claims() {
        let mut claims = base_claims(now() + 3600, now());
        claims["tenant_id"] = serde_json::json!("tenant-7");
        claims["amr"] = serde_json::json!(["pwd", "otp"]);
        claims["acr"] = serde_json::json!("urn:iam-core:mfa");
        let token = sign(&claims);
        let validator =
            IdTokenValidator::new("https://idp.example.com", "client-abc").with_nonce("nonce-xyz");
        let validated = validator
            .validate_with_jwks(&token, &test_jwks())
            .expect("token should validate");
        assert_eq!(validated.tenant_id(), Some("tenant-7"));
        assert_eq!(validated.acr.as_deref(), Some("urn:iam-core:mfa"));
        assert!(validated.mfa_satisfied(), "otp in amr proves MFA");
    }

    #[test]
    fn tenant_id_accessor_fails_closed_on_missing_or_blank() {
        let none: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "a", "exp": 1
        }))
        .unwrap();
        assert_eq!(none.tenant_id(), None);

        let blank: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "a", "exp": 1, "tenant_id": "   "
        }))
        .unwrap();
        assert_eq!(blank.tenant_id(), None, "a blank claim must not pass");
    }

    #[test]
    fn mfa_satisfied_reads_explicit_claim_and_single_factor_amr() {
        let explicit: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "a", "exp": 1, "mfa": true, "amr": ["pwd"]
        }))
        .unwrap();
        assert!(explicit.mfa_satisfied(), "explicit mfa=true wins");

        let single_factor: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "i", "sub": "s", "aud": "a", "exp": 1, "amr": ["pwd"]
        }))
        .unwrap();
        assert!(
            !single_factor.mfa_satisfied(),
            "a password-only amr is not MFA"
        );

        // RFC 8176 biometric factors prove a second factor just like
        // `face`/`fpt`; recognising them avoids a spurious step-up.
        for factor in ["iris", "RETINA", "vbm"] {
            let biometric: IdTokenClaims = serde_json::from_value(serde_json::json!({
                "iss": "i", "sub": "s", "aud": "a", "exp": 1, "amr": ["pwd", factor]
            }))
            .unwrap();
            assert!(
                biometric.mfa_satisfied(),
                "biometric amr factor {factor} proves MFA"
            );
        }
    }
}
