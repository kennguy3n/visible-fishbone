//! Agent-side pull of compiled policy bundles.
//!
//! The control-plane endpoint
//! `GET /api/v1/tenants/{tenant_id}/policy/bundles/{target_type}/payload`
//! returns the **MessagePack-encoded compiled bundle body** as
//! the HTTP response body and carries the Ed25519 signature, the
//! signing key id, and bundle / graph identifiers as response
//! headers. ETag / If-None-Match validation is supported on the
//! server side (see `internal/handler/policy.go::downloadBundle`)
//! and we mirror it here so a no-change pull only transfers
//! response headers, not the bundle body.
//!
//! Wire-format references (these MUST stay in sync with the Go
//! side; we re-state them here so anyone reading this module has
//! the contract in front of them):
//!
//! * **Body**: the MessagePack-encoded compiled bundle payload —
//!   the same bytes the Go service signs at
//!   `internal/service/policy/service.go::encodeBundlePayloadFor`.
//! * **`Content-Type`**: `application/vnd.sng.policy-bundle`.
//! * **`ETag`**: weak-comparable hex-encoded SHA-256 of the body,
//!   double-quoted. Used as the `If-None-Match` value on the
//!   next pull.
//! * **`Last-Modified`**: RFC 1123 timestamp of the bundle
//!   compile time. Used as the `If-Modified-Since` value when
//!   the server has been bouncing between bundle revisions and
//!   the ETag is unreliable.
//! * **`X-Sng-Policy-Signature`**: base64-encoded 64-byte
//!   Ed25519 signature over the response body bytes.
//! * **`X-Sng-Policy-Key-Id`**: signing key identifier (matches
//!   the verifier's trust store).
//! * **`X-Sng-Policy-Bundle-Id`**: UUID of the bundle.
//! * **`X-Sng-Policy-Graph-Id`**: UUID of the source policy graph.
//!
//! [`PolicyPuller`] is the high-level surface — call
//! [`PolicyPuller::pull`] from the agent's main loop. The puller
//! owns the [`PolicyTrustStore`] and the cached
//! [`CachedBundle`]; on `304 Not Modified` it returns the
//! cached bundle without re-decoding or re-verifying, mirroring
//! the server's `ETag` semantics.

use crate::client::{CollectedResponse, ControlPlaneConnection, RequestPath};
use crate::error::{CommsError, ResponseClass};
use arc_swap::ArcSwap;
use base64::Engine as _;
use bytes::Bytes;
use http::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use http::{HeaderMap, HeaderValue};
use parking_lot::RwLock;
use sng_core::ids::{PolicyBundleId, PolicyGraphId, PolicySigningKeyId, TenantId};
use sng_core::policy::{
    BundleSignature, BundleTarget, PolicyBundle, PolicyBundleClaims, PolicyVerifier,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// X-headers the control plane attaches to every bundle response.
/// Lowercase because http's `HeaderMap` is case-insensitive but
/// the canonical form for log emission / wire comparison is
/// lower.
pub(crate) const HDR_POLICY_SIGNATURE: &str = "x-sng-policy-signature";
pub(crate) const HDR_POLICY_KEY_ID: &str = "x-sng-policy-key-id";
pub(crate) const HDR_POLICY_BUNDLE_ID: &str = "x-sng-policy-bundle-id";
pub(crate) const HDR_POLICY_GRAPH_ID: &str = "x-sng-policy-graph-id";

/// Errors specific to `PolicyTrustStore` mutation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyTrustStoreError {
    /// The provided key id is empty / over-length / the
    /// ephemeral sentinel — sng-core's `add_key` rejected it.
    #[error("rejected key id: {0}")]
    InvalidKeyId(String),
    /// Public key bytes were not 32 bytes.
    #[error("public key must be 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// Thread-safe wrapper around sng-core's [`PolicyVerifier`].
///
/// The trust store is the agent-side mirror of the control
/// plane's signing-key directory. Operators provision the
/// initial set of public keys at agent enrolment time; key
/// rotation pushes new keys via a separate "trust-store update"
/// channel (out of scope for PR 3 — for now we expose
/// [`insert_key`] / [`remove_key`] for the orchestrator to call
/// directly).
///
/// Reads happen on the hot path (every bundle pull verifies),
/// writes happen rarely (key rotation). We use `ArcSwap<PolicyVerifier>`
/// so reads never block on writers.
#[derive(Debug)]
pub struct PolicyTrustStore {
    inner: ArcSwap<PolicyVerifier>,
}

impl Default for PolicyTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyTrustStore {
    /// Construct an empty trust store. Bundles will fail
    /// verification with `UnknownSigningKey` until keys are
    /// added.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(PolicyVerifier::new()),
        }
    }

    /// Construct a trust store pre-populated with a verifier.
    #[must_use]
    pub fn with_verifier(verifier: PolicyVerifier) -> Self {
        Self {
            inner: ArcSwap::from_pointee(verifier),
        }
    }

    /// Insert (or replace) a public key for the given id. The
    /// caller must have validated the key bytes; we forward to
    /// sng-core's `PolicyVerifier::add_key` for the canonical
    /// rejection rules (empty / over-length / ephemeral id).
    ///
    /// Atomic against concurrent writers. Two operators racing
    /// `insert_key` calls cannot lose either key — the rcu loop
    /// retries the read-modify-write until its CAS commits
    /// against an unchanged inner pointer.
    pub fn insert_key(
        &self,
        id: &PolicySigningKeyId,
        public_key: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> Result<(), PolicyTrustStoreError> {
        // `add_key`'s rejection set (empty / over-length /
        // ephemeral id) is a pure function of `id` and the key
        // bytes, not of the verifier state — so every rcu
        // iteration produces the same Err/Ok outcome. We
        // therefore stash the error from the closure (it will
        // be the same value on every retry) and propagate it
        // after the loop terminates. On error the closure
        // returns the unchanged snapshot, which makes the CAS a
        // no-op and lets concurrent successful writers commit
        // ahead of us without interference.
        let mut err: Option<PolicyTrustStoreError> = None;
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            match next.add_key(id.clone(), public_key) {
                Ok(()) => Arc::new(next),
                Err(e) => {
                    err = Some(PolicyTrustStoreError::InvalidKeyId(format!("{e}")));
                    current.clone()
                }
            }
        });
        err.map_or(Ok(()), Err)
    }

    /// Borrow the current verifier through an Arc. The returned
    /// Arc remains valid even if a concurrent writer swaps the
    /// inner verifier — readers see a consistent snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<PolicyVerifier> {
        self.inner.load_full()
    }
}

/// RFC 7232 entity-tag (`ETag`) value, parsed into a weakness
/// flag and the opaque tag string with surrounding quotes
/// stripped. The structured form lets us round-trip both
/// strong (`"abc"`) and weak (`W/"abc"`) ETags through the
/// `If-None-Match` header without corrupting the wire syntax
/// (a previous version of this module used
/// `s.trim_matches('"')` + `format!("\"{etag}\"")`, which
/// emitted the malformed `"W/"abc"` for weak ETags).
///
/// The Go control plane currently only emits strong ETags (a
/// double-quoted hex SHA-256 of the body), but this module is
/// the agent's defensive parser — a future deployment, a
/// downstream cache, or a reverse proxy could legitimately
/// rewrite an ETag as weak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    /// `true` iff the ETag was prefixed with `W/` on the wire.
    /// Strong ETags imply byte-for-byte identical resources;
    /// weak ETags only imply semantically equivalent ones.
    /// `If-None-Match` semantics are identical either way for
    /// our use (the server uses the ETag for cache validation
    /// only).
    pub weak: bool,
    /// The opaque-tag value, **without** the surrounding
    /// double-quotes.
    pub tag: String,
}

impl EntityTag {
    /// Parse an `ETag` header value per RFC 7232 §2.3.
    /// Returns `None` if the value doesn't match the
    /// `[W/]"opaque-tag"` syntax or if the opaque-tag contains
    /// embedded double-quotes (which RFC 7232 disallows in
    /// unescaped form and our server never emits).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        // RFC 7232 §2.3: entity-tag = [ weak ] opaque-tag;
        //                 weak = "W/";
        //                 opaque-tag = DQUOTE *etagc DQUOTE.
        let (weak, body) = raw
            .strip_prefix("W/")
            .map_or((false, raw), |rest| (true, rest));
        let body = body.strip_prefix('"')?.strip_suffix('"')?;
        // Embedded `"` would require escaping per the BNF and
        // our server never emits them — reject defensively so
        // we never re-emit a malformed `If-None-Match`.
        if body.contains('"') {
            return None;
        }
        Some(Self {
            weak,
            tag: body.to_owned(),
        })
    }

    /// Re-emit as the canonical `[W/]"opaque-tag"` wire form,
    /// suitable for use as an `If-None-Match` header value.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        if self.weak {
            format!("W/\"{}\"", self.tag)
        } else {
            format!("\"{}\"", self.tag)
        }
    }
}

/// Authenticated transport-level headers a successful pull
/// surfaces alongside the bundle. None of these are trusted for
/// security-relevant decisions (those go through the signed body),
/// but they are useful for log decoration and cache control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeaders {
    /// Server-provided ETag, parsed into structured form so we
    /// can correctly round-trip both strong and weak tags
    /// through `If-None-Match`.
    pub etag: Option<EntityTag>,
    /// `Last-Modified` value from the response, verbatim.
    pub last_modified: Option<String>,
    /// `X-Sng-Policy-Bundle-Id` parsed as a UUID.
    pub bundle_id: Option<PolicyBundleId>,
    /// `X-Sng-Policy-Graph-Id` parsed as a UUID.
    pub graph_id: Option<PolicyGraphId>,
}

/// A bundle that has been verified and decoded — what
/// [`PolicyPuller::pull`] returns on a successful 200.
#[derive(Debug, Clone)]
pub struct CachedBundle {
    /// The signed bundle (body + sig + signing key id).
    pub bundle: PolicyBundle,
    /// Authenticated claims decoded from the body.
    pub claims: PolicyBundleClaims,
    /// Transport metadata (ETag etc.) from the response. Not
    /// trusted for security decisions — for cache control only.
    pub headers: ResponseHeaders,
}

impl CachedBundle {
    /// Construct the conditional-request headers
    /// (`If-None-Match` + `If-Modified-Since`) for the next pull
    /// against this cached bundle.
    pub fn conditional_request_headers(&self) -> HeaderMap {
        let mut hdrs = HeaderMap::new();
        if let Some(etag) = self.headers.etag.as_ref() {
            if let Ok(value) = HeaderValue::from_str(&etag.to_header_value()) {
                hdrs.insert(IF_NONE_MATCH, value);
            }
        }
        if let Some(lm) = self.headers.last_modified.as_deref() {
            if let Ok(value) = HeaderValue::from_str(lm) {
                hdrs.insert(IF_MODIFIED_SINCE, value);
            }
        }
        hdrs
    }
}

/// Outcome of a pull. Mirrors the server's 200 / 304 split.
///
/// `CachedBundle` is the heavier variant (carries the decoded
/// `PolicyBundle` + claims + response headers) so we box it to
/// keep the enum's stack size small. The 304 path is the
/// common case in steady state.
#[derive(Debug, Clone)]
pub enum BundlePullOutcome {
    /// `200 OK` — server returned a fresh bundle. Verified,
    /// decoded, ready to load into `sng-policy-eval`.
    Updated(Box<CachedBundle>),
    /// `304 Not Modified` — the cached bundle is still
    /// authoritative.
    NotModified,
}

/// Configuration for [`PolicyPuller`].
#[derive(Debug, Clone)]
pub struct PolicyPullerConfig {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Bundle target — `Edge`, `Endpoint`, etc.
    pub target: BundleTarget,
    /// Optional path prefix override. Defaults to
    /// `/api/v1/tenants/{tenant}/policy/bundles/{target}/payload`.
    /// Exposed for embedding the agent inside a forwarder /
    /// proxy that rewrites the URL.
    pub path_override: Option<String>,
}

/// High-level pull surface. Stateful — caches the most recently
/// fetched bundle so subsequent pulls can use `If-None-Match`.
#[derive(Debug)]
pub struct PolicyPuller {
    config: PolicyPullerConfig,
    trust_store: Arc<PolicyTrustStore>,
    cached: RwLock<Option<CachedBundle>>,
}

impl PolicyPuller {
    /// Construct a fresh puller. The cache starts empty; the
    /// first pull is unconditional.
    #[must_use]
    pub fn new(config: PolicyPullerConfig, trust_store: Arc<PolicyTrustStore>) -> Self {
        Self {
            config,
            trust_store,
            cached: RwLock::new(None),
        }
    }

    /// Snapshot of the currently-cached bundle (if any).
    #[must_use]
    pub fn cached(&self) -> Option<CachedBundle> {
        self.cached.read().clone()
    }

    /// Override the path used for the next pull. Useful for
    /// pinning a specific bundle revision from operator tooling.
    /// Most callers should set this once at construction.
    pub fn set_path_override(&mut self, path: Option<String>) {
        self.config.path_override = path;
    }

    /// Issue a pull against the supplied connection. On a `200`
    /// the bundle is verified, claims-decoded, optionally
    /// downgrade-checked against the previously-cached bundle's
    /// graph version, and stashed into the cache. On a `304`
    /// the cache is unchanged.
    pub async fn pull(
        &self,
        conn: &ControlPlaneConnection,
    ) -> Result<BundlePullOutcome, CommsError> {
        let path = self
            .config
            .path_override
            .clone()
            .unwrap_or_else(|| default_payload_path(self.config.tenant_id, self.config.target));

        let mut request = RequestPath::get(path).with_header(
            http::header::ACCEPT,
            HeaderValue::from_static("application/vnd.sng.policy-bundle"),
        );
        // Attach If-None-Match / If-Modified-Since from the
        // cached bundle, if any.
        if let Some(cached) = self.cached.read().as_ref() {
            for (k, v) in &cached.conditional_request_headers() {
                request.headers.insert(k.clone(), v.clone());
            }
        }
        let response = conn
            .send_request(request, crate::client::RequestBody::Empty)
            .await?;
        self.handle_response(&response)
    }

    /// Internal helper — exposed `pub(crate)` so the integration
    /// tests can drive a pre-recorded response through the
    /// verifier without standing up an HTTP/2 connection.
    pub(crate) fn handle_response(
        &self,
        response: &CollectedResponse,
    ) -> Result<BundlePullOutcome, CommsError> {
        match response.classify() {
            ResponseClass::Success => {
                let headers = parse_response_headers(&response.headers);
                let bundle = self.decode_and_verify(&response.body, &response.headers)?;
                let claims = PolicyBundleClaims::from_body(&bundle.body)?;
                // The bundle_id used in the verification-error
                // log line: prefer the authoritative X-Sng-…
                // header value (already authenticated against
                // the leaf cert during TLS handshake), fall
                // back to a nil sentinel for logging only.
                let bundle_id_for_check = headers
                    .bundle_id
                    .unwrap_or_else(|| PolicyBundleId::from_uuid(uuid::Uuid::nil()));
                claims.check_target(bundle_id_for_check, self.config.target)?;
                let cached = CachedBundle {
                    bundle,
                    claims,
                    headers,
                };
                // Read prev_version + check_not_stale + install
                // under a single write lock so two concurrent
                // `pull` calls cannot interleave such that a
                // staler bundle overwrites a newer one. Previously
                // the prev_version read held a read lock that was
                // released before the install acquired a write
                // lock, leaving a TOCTOU window: thread A reads
                // v5, thread B installs v10, thread A then
                // overwrites with v7 (which passed staleness
                // against the stale v5 read).
                //
                // The expensive work (signature verification,
                // body decode, claims parse) happens *outside*
                // this lock, so concurrent pulls only serialise
                // on the small, cheap version-compare and the
                // pointer install.
                {
                    let mut guard = self.cached.write();
                    let prev_version = guard.as_ref().map(|c| c.claims.graph_version);
                    cached
                        .claims
                        .check_not_stale(bundle_id_for_check, prev_version)?;
                    *guard = Some(cached.clone());
                }
                debug!(
                    bundle_id = ?cached.headers.bundle_id,
                    graph_id = ?cached.headers.graph_id,
                    graph_version = cached.claims.graph_version,
                    "accepted updated policy bundle",
                );
                Ok(BundlePullOutcome::Updated(Box::new(cached)))
            }
            ResponseClass::NotModified => {
                if self.cached.read().is_none() {
                    // 304 without a cache snapshot is a server
                    // protocol violation — it implies the server
                    // matched our If-None-Match value against
                    // something we never had. We surface this
                    // as a permanent BundleRejected error so the
                    // orchestrator can re-pull unconditionally
                    // (clearing whatever stale state caused it).
                    return Err(CommsError::PolicyVersion(
                        "server returned 304 but client has no cached bundle".into(),
                    ));
                }
                debug!("policy bundle cache still authoritative (304)");
                Ok(BundlePullOutcome::NotModified)
            }
            class => Err(CommsError::Server {
                class,
                reason: format!("policy bundle pull returned {}", response.status),
            }),
        }
    }

    /// Decode the bundle body + signature header + key-id
    /// header into a [`PolicyBundle`] and verify it against the
    /// trust store.
    fn decode_and_verify(
        &self,
        body: &Bytes,
        headers: &HeaderMap,
    ) -> Result<PolicyBundle, CommsError> {
        let signature = headers
            .get(HDR_POLICY_SIGNATURE)
            .ok_or_else(|| {
                CommsError::PolicyVersion(format!(
                    "missing required response header `{HDR_POLICY_SIGNATURE}`"
                ))
            })
            .and_then(|v| {
                let raw = v.to_str().map_err(|_| {
                    CommsError::PolicyVersion(format!(
                        "non-ASCII bytes in `{HDR_POLICY_SIGNATURE}` header"
                    ))
                })?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .map_err(|e| {
                        CommsError::PolicyVersion(format!(
                            "base64 decode of `{HDR_POLICY_SIGNATURE}`: {e}"
                        ))
                    })?;
                if bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CommsError::PolicyVersion(format!(
                        "`{HDR_POLICY_SIGNATURE}` must be {} bytes (base64-decoded), got {}",
                        ed25519_dalek::SIGNATURE_LENGTH,
                        bytes.len()
                    )));
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.copy_from_slice(&bytes);
                Ok(BundleSignature { bytes: sig })
            })?;

        let signing_key_id = headers
            .get(HDR_POLICY_KEY_ID)
            .ok_or_else(|| {
                CommsError::PolicyVersion(format!(
                    "missing required response header `{HDR_POLICY_KEY_ID}`"
                ))
            })
            .and_then(|v| {
                v.to_str()
                    .map_err(|_| {
                        CommsError::PolicyVersion(format!(
                            "non-ASCII bytes in `{HDR_POLICY_KEY_ID}` header"
                        ))
                    })
                    .and_then(|s| {
                        s.parse::<PolicySigningKeyId>().map_err(|e| {
                            CommsError::PolicyVersion(format!(
                                "invalid `{HDR_POLICY_KEY_ID}` value: {e}"
                            ))
                        })
                    })
            })?;

        let bundle = PolicyBundle {
            body: body.to_vec(),
            signature,
            signing_key_id,
        };
        let verifier = self.trust_store.snapshot();
        verifier.verify(&bundle)?;
        Ok(bundle)
    }
}

/// Build the canonical pull path for the supplied tenant +
/// target. Exposed `pub` so the orchestrator can paste it into
/// audit log lines without re-stating the URL template.
#[must_use]
pub fn default_payload_path(tenant: TenantId, target: BundleTarget) -> String {
    format!(
        "/api/v1/tenants/{}/policy/bundles/{}/payload",
        tenant.as_uuid(),
        bundle_target_path(target)
    )
}

fn bundle_target_path(target: BundleTarget) -> &'static str {
    match target {
        BundleTarget::Edge => "edge",
        BundleTarget::Endpoint => "endpoint",
        BundleTarget::Cloud => "cloud",
        BundleTarget::Mobile => "mobile",
    }
}

fn parse_response_headers(headers: &HeaderMap) -> ResponseHeaders {
    let etag = headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .and_then(EntityTag::parse);
    let last_modified = headers
        .get(http::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bundle_id = headers
        .get(HDR_POLICY_BUNDLE_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<PolicyBundleId>().ok());
    let graph_id = headers
        .get(HDR_POLICY_GRAPH_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<PolicyGraphId>().ok());
    if etag.is_none() {
        // Surface this as info-level — not an error (the server
        // may legitimately omit it under certain configurations),
        // but worth pinning in logs because it disables our
        // conditional-request optimisation.
        info!("policy bundle response carried no ETag");
    }
    if bundle_id.is_none() || graph_id.is_none() {
        warn!(
            bundle_id_present = bundle_id.is_some(),
            graph_id_present = graph_id.is_some(),
            "policy bundle response missing or malformed bundle/graph id header"
        );
    }
    ResponseHeaders {
        etag,
        last_modified,
        bundle_id,
        graph_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer as _, SigningKey};
    use http::{HeaderValue, StatusCode};
    // Match the production wire shape: the Go control plane signs
    // bodies serialised with named MessagePack maps (matching
    // `rmp_serde::to_vec_named`). Compact / positional encoding
    // would still verify locally because the test signs the same
    // bytes it produces, but wouldn't exercise the deserialiser
    // path the agent runs against real bundles.
    use rmp_serde::to_vec_named as msgpack_encode;
    use sng_core::ids::PolicyGraphId;
    use sng_core::policy::VerificationError;

    fn mk_keypair() -> (SigningKey, PolicySigningKeyId, [u8; 32]) {
        // Deterministic seed so tests are reproducible.
        let mut seed = [0u8; 32];
        seed[0] = 0xab;
        seed[31] = 0xcd;
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let id = PolicySigningKeyId::new("kid-1").expect("valid id");
        (signing, id, public)
    }

    fn mk_claims(graph_version: i64, target: BundleTarget) -> PolicyBundleClaims {
        PolicyBundleClaims {
            schema_version: 1,
            target,
            graph_id: PolicyGraphId::new_v4(),
            graph_version,
            compiler: "test".into(),
            default_action: "deny".into(),
            compiled_at: Utc::now(),
        }
    }

    fn sign_bundle_body(claims: &PolicyBundleClaims, signing: &SigningKey) -> (Vec<u8>, [u8; 64]) {
        let body = msgpack_encode(claims).expect("encode claims");
        let sig = signing.sign(&body).to_bytes();
        (body, sig)
    }

    fn mk_response(
        body: Vec<u8>,
        sig: [u8; 64],
        key_id: &PolicySigningKeyId,
        etag: Option<&str>,
    ) -> CollectedResponse {
        let mut headers = HeaderMap::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        headers.insert(
            HDR_POLICY_SIGNATURE,
            HeaderValue::from_str(&b64).expect("b64"),
        );
        headers.insert(
            HDR_POLICY_KEY_ID,
            HeaderValue::from_str(key_id.as_str()).expect("kid"),
        );
        headers.insert(
            HDR_POLICY_BUNDLE_ID,
            HeaderValue::from_str(&PolicyBundleId::new_v4().to_string()).expect("bid"),
        );
        headers.insert(
            HDR_POLICY_GRAPH_ID,
            HeaderValue::from_str(&PolicyGraphId::new_v4().to_string()).expect("gid"),
        );
        if let Some(e) = etag {
            headers.insert(
                ETAG,
                HeaderValue::from_str(&format!("\"{e}\"")).expect("etag"),
            );
        }
        CollectedResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from(body),
        }
    }

    #[test]
    fn entity_tag_parses_strong_and_weak() {
        // Strong ETag — quotes stripped, weak=false.
        let strong = EntityTag::parse("\"abc\"").expect("strong parses");
        assert!(!strong.weak);
        assert_eq!(strong.tag, "abc");
        assert_eq!(strong.to_header_value(), "\"abc\"");

        // Weak ETag — `W/` prefix recognised, weak=true.
        let weak = EntityTag::parse("W/\"abc\"").expect("weak parses");
        assert!(weak.weak);
        assert_eq!(weak.tag, "abc");
        assert_eq!(
            weak.to_header_value(),
            "W/\"abc\"",
            "weak ETag must round-trip as `W/\"…\"`, not the malformed `\"W/\"abc\"`"
        );

        // Empty opaque-tag is legal per the BNF.
        let empty = EntityTag::parse("\"\"").expect("empty parses");
        assert_eq!(empty.tag, "");
        assert_eq!(empty.to_header_value(), "\"\"");
    }

    #[test]
    fn entity_tag_rejects_malformed() {
        // Missing quotes.
        assert!(EntityTag::parse("abc").is_none());
        // Only leading quote.
        assert!(EntityTag::parse("\"abc").is_none());
        // Only trailing quote.
        assert!(EntityTag::parse("abc\"").is_none());
        // Weak without quotes.
        assert!(EntityTag::parse("W/abc").is_none());
        // Embedded unescaped quote.
        assert!(EntityTag::parse("\"a\"b\"").is_none());
        // Empty string.
        assert!(EntityTag::parse("").is_none());
    }

    #[test]
    fn weak_etag_round_trips_through_conditional_request() {
        // Regression: previously `trim_matches('"')` produced
        // `W/"abc` for input `W/"abc"`, and the re-wrap then
        // emitted the malformed `"W/"abc"` as `If-None-Match`.
        // With the structured `EntityTag`, the round-trip is
        // exact.
        let cached = CachedBundle {
            bundle: PolicyBundle {
                body: vec![],
                signature: BundleSignature { bytes: [0; 64] },
                signing_key_id: PolicySigningKeyId::new("any").expect("id"),
            },
            claims: mk_claims(1, BundleTarget::Edge),
            headers: ResponseHeaders {
                etag: EntityTag::parse("W/\"abc\""),
                last_modified: None,
                bundle_id: None,
                graph_id: None,
            },
        };
        let hdrs = cached.conditional_request_headers();
        assert_eq!(
            hdrs.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()),
            Some("W/\"abc\""),
        );
    }

    #[test]
    fn pull_200_verifies_and_caches() {
        let (signing, kid, pubk) = mk_keypair();
        let trust_store = Arc::new(PolicyTrustStore::new());
        trust_store.insert_key(&kid, &pubk).expect("insert key");
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let claims = mk_claims(7, BundleTarget::Edge);
        let (body, sig) = sign_bundle_body(&claims, &signing);
        let resp = mk_response(body, sig, &kid, Some("abc"));
        let outcome = puller.handle_response(&resp).expect("verifies");
        match outcome {
            BundlePullOutcome::Updated(cached) => {
                assert_eq!(cached.claims.graph_version, 7);
                assert_eq!(
                    cached
                        .headers
                        .etag
                        .as_ref()
                        .map(|e| (e.weak, e.tag.as_str())),
                    Some((false, "abc")),
                );
            }
            BundlePullOutcome::NotModified => panic!("expected Updated"),
        }
        assert!(puller.cached().is_some());
    }

    #[test]
    fn target_mismatch_is_rejected_post_signature_check() {
        let (signing, kid, pubk) = mk_keypair();
        let trust_store = Arc::new(PolicyTrustStore::new());
        trust_store.insert_key(&kid, &pubk).expect("insert");
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        // Sign claims that claim target=Endpoint, but the puller
        // is configured for Edge.
        let claims = mk_claims(1, BundleTarget::Endpoint);
        let (body, sig) = sign_bundle_body(&claims, &signing);
        let resp = mk_response(body, sig, &kid, None);
        let err = puller
            .handle_response(&resp)
            .expect_err("target mismatch must fail");
        assert!(matches!(err, CommsError::Policy(_)));
    }

    #[test]
    fn downgrade_is_rejected() {
        let (signing, kid, pubk) = mk_keypair();
        let trust_store = Arc::new(PolicyTrustStore::new());
        trust_store.insert_key(&kid, &pubk).expect("insert");
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let claims = mk_claims(5, BundleTarget::Edge);
        let (body, sig) = sign_bundle_body(&claims, &signing);
        puller
            .handle_response(&mk_response(body, sig, &kid, None))
            .expect("first accepts");
        // Now a regression to version 3 must be rejected.
        let claims2 = mk_claims(3, BundleTarget::Edge);
        let (body2, sig2) = sign_bundle_body(&claims2, &signing);
        let err = puller
            .handle_response(&mk_response(body2, sig2, &kid, None))
            .expect_err("downgrade must fail");
        assert!(matches!(err, CommsError::Policy(_)));
    }

    #[test]
    fn unknown_key_id_rejected() {
        let (signing, kid, _pubk) = mk_keypair();
        // Do NOT add the key.
        let trust_store = Arc::new(PolicyTrustStore::new());
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let claims = mk_claims(1, BundleTarget::Edge);
        let (body, sig) = sign_bundle_body(&claims, &signing);
        let err = puller
            .handle_response(&mk_response(body, sig, &kid, None))
            .expect_err("unknown key must fail");
        assert!(matches!(
            err,
            CommsError::Policy(VerificationError::UnknownSigningKey(_))
        ));
    }

    #[test]
    fn corrupted_signature_rejected() {
        let (signing, kid, pubk) = mk_keypair();
        let trust_store = Arc::new(PolicyTrustStore::new());
        trust_store.insert_key(&kid, &pubk).expect("insert");
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let claims = mk_claims(1, BundleTarget::Edge);
        let (body, mut sig) = sign_bundle_body(&claims, &signing);
        // Flip a byte.
        sig[0] ^= 0xff;
        let err = puller
            .handle_response(&mk_response(body, sig, &kid, None))
            .expect_err("corrupt sig");
        assert!(matches!(
            err,
            CommsError::Policy(VerificationError::SignatureInvalid)
        ));
    }

    #[test]
    fn not_modified_without_cache_is_rejected() {
        let trust_store = Arc::new(PolicyTrustStore::new());
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let resp = CollectedResponse {
            status: StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let err = puller
            .handle_response(&resp)
            .expect_err("304 without cache must fail");
        assert!(matches!(err, CommsError::PolicyVersion(_)));
    }

    #[test]
    fn not_modified_with_cache_returns_cached() {
        let (signing, kid, pubk) = mk_keypair();
        let trust_store = Arc::new(PolicyTrustStore::new());
        trust_store.insert_key(&kid, &pubk).expect("insert");
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let claims = mk_claims(2, BundleTarget::Edge);
        let (body, sig) = sign_bundle_body(&claims, &signing);
        puller
            .handle_response(&mk_response(body, sig, &kid, Some("e1")))
            .expect("first OK");
        // 304 — cache stays.
        let resp_304 = CollectedResponse {
            status: StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let outcome = puller.handle_response(&resp_304).expect("304 ok");
        assert!(matches!(outcome, BundlePullOutcome::NotModified));
        let cached = puller.cached().expect("still cached");
        assert_eq!(cached.claims.graph_version, 2);
    }

    #[test]
    fn missing_signature_header_rejected() {
        let trust_store = Arc::new(PolicyTrustStore::new());
        let puller = PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: TenantId::new_v4(),
                target: BundleTarget::Edge,
                path_override: None,
            },
            trust_store,
        );
        let mut headers = HeaderMap::new();
        headers.insert(HDR_POLICY_KEY_ID, HeaderValue::from_static("k"));
        let resp = CollectedResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(&[1, 2, 3]),
        };
        let err = puller.handle_response(&resp).expect_err("missing sig hdr");
        assert!(matches!(err, CommsError::PolicyVersion(_)));
    }

    #[test]
    fn default_payload_path_is_canonical() {
        let tenant = TenantId::from_uuid(uuid::Uuid::nil());
        let path = default_payload_path(tenant, BundleTarget::Edge);
        assert_eq!(
            path,
            "/api/v1/tenants/00000000-0000-0000-0000-000000000000/policy/bundles/edge/payload"
        );
    }
}
