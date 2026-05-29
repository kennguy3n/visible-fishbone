//! Build a `rustls::ClientConfig` for the SNG native protocol.
//!
//! Two construction modes:
//!
//! * **No client cert** — used for the bootstrap / enrolment
//!   handshake where the agent does not yet have a device-bound
//!   client cert. The server identifies the agent by the
//!   one-time claim token in the request body.
//! * **Mutual TLS** — used for every authenticated request after
//!   enrolment. Calls `with_client_auth_cert` with the
//!   [`DeviceIdentity`]'s certificate chain + private key.
//!
//! Both modes set `alpn_protocols = [b"h2"]` so the HTTP/2 ALPN
//! identifier (RFC 7540 §3.3) is negotiated on every handshake.
//! Without ALPN, standards-compliant servers either reject the
//! connection or fall back to HTTP/1.1, which silently breaks the
//! HTTP/2 connection preface the client sends next. This is the
//! single most common rustls-h2 misconfiguration; baking the ALPN
//! into the canonical builder ensures no caller has to remember.
//!
//! Root-of-trust posture:
//!
//! * If the caller passes a non-empty list of root certificates,
//!   they are used verbatim. This is the production posture — the
//!   operator configures the agent with the control-plane PKI's
//!   root cert at enrolment time.
//! * If the caller passes an empty list and asks for system roots
//!   ([`build_client_config`]'s `use_system_roots` flag), the
//!   `webpki-roots` Mozilla root bundle is used. This is the
//!   bootstrap posture — used by the enrolment endpoint when the
//!   agent doesn't yet have a tenant-specific root.

use crate::identity::DeviceIdentity;
use rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider, pki_types::CertificateDer};
use thiserror::Error;

/// ALPN identifier for HTTP/2 (RFC 7540 §3.3). Set on every
/// `ClientConfig` this module produces — without it the h2
/// handshake silently falls back to HTTP/1.1 and the next frame
/// (the HTTP/2 connection preface) is parsed as nonsense.
pub(crate) const ALPN_H2: &[u8] = b"h2";

/// Errors returned by [`build_client_config`]. Every variant is
/// permanent under the current files on disk / current build.
#[derive(Debug, Error)]
pub enum ClientConfigError {
    /// The provided trust anchors (operator-supplied or
    /// `webpki-roots`) contained no valid certificates.
    #[error("no usable trust anchors provided")]
    EmptyTrustStore,
    /// `rustls::ClientConfig::builder` refused the supplied
    /// configuration. Surfaces the rustls error in the source
    /// chain.
    #[error("rustls config builder: {0}")]
    Rustls(#[source] rustls::Error),
    /// The process-wide crypto provider could not be installed
    /// from this thread. The first caller wins; subsequent calls
    /// fall through silently because the provider is already
    /// installed.
    #[error("could not install rustls crypto provider")]
    ProviderInstall,
}

/// Install the workspace's pinned `ring`-based rustls crypto
/// provider as the process-wide default, if it has not already
/// been installed. Safe to call multiple times — second and
/// subsequent calls are a no-op once any provider is installed.
///
/// rustls 0.23 requires a crypto provider to be selected before
/// any [`ClientConfig`] can be built. Pinning the `ring` provider
/// here (not `aws-lc-sys`) is the cargo-deny + Cargo feature
/// posture of the workspace; using a different provider would
/// pull `aws-lc-sys` into the link, which is explicitly banned in
/// `deny.toml`.
pub fn install_ring_provider() {
    // `set_default_provider` returns `Err(_)` if a provider is
    // already installed; we silently swallow that because we are
    // idempotent. The actual installation race is a no-op (every
    // worker thread asks for the same provider).
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Build a `rustls::ClientConfig` suitable for the SNG native
/// protocol HTTP/2 client.
///
/// `roots` are the operator-supplied trust anchors the client
/// uses to authenticate the server's certificate. Pass the
/// control-plane CA bundle here for the post-enrolment path.
/// Callers that want the Mozilla / webpki-roots bundle (the
/// bootstrap posture before the operator-issued root is
/// available) should use [`build_client_config_with_webpki_roots`]
/// instead, which extends the trust store from `TrustAnchor`s
/// directly without round-tripping through `CertificateDer`.
///
/// `identity` is the device's mTLS identity, if available. When
/// `None` (bootstrap / enrolment), no client cert is sent and the
/// server falls back to in-body claim-token authentication.
pub fn build_client_config(
    roots: Vec<CertificateDer<'static>>,
    identity: Option<&DeviceIdentity>,
) -> Result<ClientConfig, ClientConfigError> {
    install_ring_provider();

    let mut root_store = RootCertStore::empty();
    let mut added = 0usize;
    for cert in roots {
        // `add` returns an error if the cert is unparseable; we
        // count successful additions so an all-malformed bundle
        // produces an explicit EmptyTrustStore rather than an
        // ambiguous "0 anchors but didn't error" state.
        if root_store.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(ClientConfigError::EmptyTrustStore);
    }

    finish_client_config(root_store, identity)
}

/// Like [`build_client_config`] but seeds the trust store from
/// the Mozilla / webpki-roots default `TrustAnchor` bundle.
/// Used by the bootstrap / enrolment path when the agent does
/// not yet have the operator-supplied control-plane root.
pub fn build_client_config_with_webpki_roots(
    identity: Option<&DeviceIdentity>,
) -> Result<ClientConfig, ClientConfigError> {
    install_ring_provider();

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if root_store.is_empty() {
        return Err(ClientConfigError::EmptyTrustStore);
    }
    finish_client_config(root_store, identity)
}

/// Finalise a `RootCertStore` into a `ClientConfig` with the
/// ALPN identifier pinned to `h2`. Shared by both root-source
/// entry points so the ALPN pinning lives in exactly one place.
fn finish_client_config(
    root_store: RootCertStore,
    identity: Option<&DeviceIdentity>,
) -> Result<ClientConfig, ClientConfigError> {
    let builder = ClientConfig::builder().with_root_certificates(root_store);
    let mut config = if let Some(id) = identity {
        let (cert_chain, key) = id.client_auth_parts();
        builder
            .with_client_auth_cert(cert_chain, key)
            .map_err(ClientConfigError::Rustls)?
    } else {
        builder.with_no_client_auth()
    };
    // RFC 7540 §3.3 — see the module-level doc.
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    /// Mint a self-signed cert + its PEM private key.
    fn mint_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
        let mut params = CertificateParams::new(vec!["test".into()]).expect("rcgen params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test");
        let cert = params.self_signed(&key).expect("cert");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn mint_root_der() -> CertificateDer<'static> {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("root key");
        let mut params = CertificateParams::new(vec!["root".into()]).expect("rcgen params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "root");
        let cert = params.self_signed(&key).expect("root cert");
        CertificateDer::from(cert.der().to_vec())
    }

    #[test]
    fn builds_config_without_client_cert() {
        let cfg = build_client_config(vec![mint_root_der()], None).expect("config builds");
        assert_eq!(cfg.alpn_protocols, vec![ALPN_H2.to_vec()]);
    }

    #[test]
    fn builds_config_with_client_cert() {
        let (cert_pem, key_pem) = mint_pem_pair();
        let id = DeviceIdentity::from_pem(&cert_pem, &key_pem).expect("identity");
        let cfg =
            build_client_config(vec![mint_root_der()], Some(&id)).expect("config builds with cert");
        assert_eq!(cfg.alpn_protocols, vec![ALPN_H2.to_vec()]);
    }

    #[test]
    fn rejects_empty_root_store() {
        let err = build_client_config(vec![], None).expect_err("empty store rejected");
        assert!(matches!(err, ClientConfigError::EmptyTrustStore));
    }
}
