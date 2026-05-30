//! HTTP/2-over-TLS control-plane client.
//!
//! [`ControlPlaneClient`] is the connection factory: it owns the
//! TLS config and the destination address, and `connect()`s a
//! fresh [`ControlPlaneConnection`] on demand. A single
//! `ControlPlaneConnection` carries one TLS connection and one
//! HTTP/2 connection (with multiplexed streams), so callers
//! typically hold one connection per active session and drop +
//! reconnect through the [`ReconnectBackoff`] on failure.
//!
//! The connection construction sequence is:
//!
//! 1. TCP `connect` to the resolved socket address.
//! 2. TLS handshake via `tokio-rustls` using the
//!    [`ClientConfig`](rustls::ClientConfig) built by
//!    [`build_client_config`].
//! 3. Verify the negotiated ALPN protocol is `h2`. RFC 7540 §3.3
//!    requires this; permissive servers may accept the
//!    connection without ALPN but the next frame (the HTTP/2
//!    connection preface) is unparseable on a non-h2 connection.
//! 4. `h2::client::handshake` to spin up the HTTP/2 multiplexer.
//! 5. Spawn the connection driver onto the same runtime; the
//!    driver pumps frames and lives for as long as the
//!    [`ControlPlaneConnection`] is held.

use crate::error::{CommsError, ResponseClass};
use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

/// Body-payload shape for outgoing requests. Either no body
/// (GET / HEAD) or a single `Bytes` blob (POST batch /
/// ETag conditional GET that happens to carry a body, etc.).
///
/// Streaming uploads are intentionally out of scope here — every
/// outgoing request the agent makes fits in a single batch's
/// worth of bytes. If a future telemetry shape needs streaming,
/// add a `Streaming(impl Stream<Item = Bytes>)` variant rather
/// than overloading `Bytes`.
#[derive(Debug, Clone)]
pub enum RequestBody {
    /// No body — GET / HEAD / DELETE.
    Empty,
    /// Single-blob body — POST batch, ETag conditional GET.
    Bytes(Bytes),
}

impl RequestBody {
    /// Inspect the body's byte count without consuming it.
    /// Returns 0 for [`Self::Empty`].
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(b) => b.len(),
        }
    }

    /// Whether the body is empty / has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Logical request shape — what the orchestrator hands to the
/// connection. Carried as a separate type from [`Request`]
/// because the latter's body type parameter is `()` (h2
/// requirement) and the actual body bytes travel separately.
#[derive(Debug, Clone)]
pub struct RequestPath {
    /// HTTP method.
    pub method: http::Method,
    /// Path + query string (e.g. `/api/v1/.../payload?since=…`).
    /// MUST start with `/`.
    pub path_and_query: String,
    /// Request headers. The connection adds `:authority`,
    /// `host`, `accept`, and `content-length` automatically as
    /// needed; callers should set domain-specific headers
    /// (`If-None-Match`, `X-Sng-…`, `accept-encoding`, …).
    pub headers: HeaderMap,
}

impl RequestPath {
    /// Construct a GET request path.
    pub fn get(path_and_query: impl Into<String>) -> Self {
        Self {
            method: http::Method::GET,
            path_and_query: path_and_query.into(),
            headers: HeaderMap::new(),
        }
    }

    /// Construct a POST request path.
    pub fn post(path_and_query: impl Into<String>) -> Self {
        Self {
            method: http::Method::POST,
            path_and_query: path_and_query.into(),
            headers: HeaderMap::new(),
        }
    }

    /// Add a header. Returns `self` for builder-style chaining.
    #[must_use]
    pub fn with_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}

/// Control-plane connection factory.
///
/// Construction is cheap (clones the `Arc<ClientConfig>` and
/// stores the address); the expensive work happens in
/// [`connect`]. A single `ControlPlaneClient` may produce many
/// `ControlPlaneConnection`s over its lifetime — e.g. after a
/// reconnect.
#[derive(Debug, Clone)]
pub struct ControlPlaneClient {
    /// `host:port` to dial. The host portion must also match the
    /// `ServerName` used in the TLS handshake; we store both
    /// fields so callers can connect over an IP-resolved address
    /// while still presenting the original hostname in SNI.
    addr: String,
    /// SNI / certificate-validation server name.
    server_name: ServerName<'static>,
    /// rustls client config — must have ALPN `h2` set. Use
    /// [`build_client_config`] / [`build_client_config_with_webpki_roots`]
    /// to construct.
    tls_config: Arc<rustls::ClientConfig>,
}

impl ControlPlaneClient {
    /// Construct a client. `addr` is `host:port`; `server_name`
    /// is what we present in SNI and validate the server cert
    /// against; `tls_config` is the rustls config built by
    /// [`build_client_config`].
    ///
    /// Rejects a `tls_config` whose `alpn_protocols` does not
    /// include `h2` — this is a defence-in-depth check on top of
    /// the ALPN pinning inside [`build_client_config`], so a
    /// caller who built their own `ClientConfig` directly still
    /// gets the fail-fast error rather than a confusing h2
    /// connection preface error at first request.
    pub fn new(
        addr: impl Into<String>,
        server_name: ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self, CommsError> {
        if !tls_config
            .alpn_protocols
            .iter()
            .any(|p| p.as_slice() == b"h2")
        {
            return Err(CommsError::Config(
                "rustls ClientConfig must advertise the h2 ALPN identifier; \
                 use sng_comms::build_client_config to construct it"
                    .into(),
            ));
        }
        Ok(Self {
            addr: addr.into(),
            server_name,
            tls_config,
        })
    }

    /// Establish a fresh TCP + TLS + HTTP/2 connection. On
    /// success, returns a connection with the driver task spawned.
    /// On any failure (TCP refused, TLS handshake error, ALPN
    /// mismatch, h2 handshake error), returns a [`CommsError`] —
    /// the caller decides whether to retry through the backoff.
    pub async fn connect(&self) -> Result<ControlPlaneConnection, CommsError> {
        // Resolve + dial. We accept the first address in the
        // resolution; an explicit happy-eyeballs / multi-family
        // dialer can live in `sng-edge` / `sng-agent` later if
        // operators ask for it.
        //
        // `tokio::net::lookup_host` performs the resolution on the
        // runtime's blocking-pool thread so the calling task isn't
        // pinned while the resolver waits. `std::net::ToSocketAddrs`
        // would block the current worker thread.
        let addr = lookup_host(self.addr.as_str())
            .await
            .map_err(|e| CommsError::Connect(format!("resolve {}: {e}", self.addr)))?
            .next()
            .ok_or_else(|| CommsError::Connect(format!("no address for {}", self.addr)))?;

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| CommsError::Connect(format!("tcp connect {}: {e}", self.addr)))?;
        // Nagle's algorithm coalesces small writes; for HTTP/2
        // that means the connection preface + an immediate
        // SETTINGS frame can sit in the local kernel buffer for
        // up to 40 ms while we wait for the server's SETTINGS
        // before we can send our first request. Disable it.
        let _ = tcp.set_nodelay(true);

        let connector = TlsConnector::from(self.tls_config.clone());
        let tls = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| CommsError::Connect(format!("tls handshake: {e}")))?;

        // ALPN check: per RFC 7540 §3.3 the server MUST select
        // `h2` from our advertised list. If it didn't, the next
        // frame we send (the HTTP/2 connection preface) is
        // unparseable on the negotiated protocol.
        {
            let (_io, session) = tls.get_ref();
            match session.alpn_protocol() {
                Some(p) if p == b"h2" => {
                    debug!(addr = %self.addr, "h2 ALPN negotiated");
                }
                Some(other) => {
                    warn!(
                        addr = %self.addr,
                        alpn = %String::from_utf8_lossy(other),
                        "server selected non-h2 ALPN",
                    );
                    return Err(CommsError::AlpnMismatch);
                }
                None => {
                    warn!(addr = %self.addr, "server selected no ALPN protocol");
                    return Err(CommsError::AlpnMismatch);
                }
            }
        }

        Self::finish_h2(tls, self.authority()).await
    }

    /// Derive the HTTP `:authority` pseudo-header value. Uses the
    /// SNI `server_name` if it is a DNS name (the typical
    /// control-plane case `agents.cp.example.com:443`), otherwise
    /// falls back to the dial address (IP-literal endpoints in
    /// tests / private deployments).
    fn authority(&self) -> String {
        let port = self.addr.rsplit_once(':').map_or("443", |(_, p)| p);
        match &self.server_name {
            ServerName::DnsName(dns) => format!("{}:{}", dns.as_ref(), port),
            _ => self.addr.clone(),
        }
    }

    /// Test-only: drive the HTTP/2 handshake over a caller-
    /// provided io. Exposed `pub(crate)` so the integration
    /// test can stand up an in-process server with a known
    /// listener address. Production callers use [`connect`].
    pub(crate) async fn finish_h2<IO>(
        io: IO,
        authority: String,
    ) -> Result<ControlPlaneConnection, CommsError>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (send_request, connection) = h2::client::Builder::new()
            // The defaults are conservative; the SNG control
            // plane handles burst telemetry, so widen the
            // initial flow-control window from the spec's
            // default 64 KiB to 1 MiB to avoid stalling on
            // multi-KB batches.
            .initial_window_size(1024 * 1024)
            .max_concurrent_streams(100)
            .handshake(io)
            .await
            .map_err(|e| CommsError::Http2(format!("h2 handshake: {e}")))?;

        // Spawn the connection driver. It owns the read/write
        // halves of the TLS socket and pumps frames until the
        // peer closes. Dropping a `JoinHandle` on its own does
        // NOT abort the task; we stash the handle inside the
        // connection and abort it explicitly in
        // `ControlPlaneConnection::drop` so the socket is torn
        // down deterministically when the caller drops the
        // connection (e.g. on a reconnect after `flush_one`
        // returns a connection error).
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!(error = %e, "h2 connection closed");
            }
        });
        Ok(ControlPlaneConnection {
            send: send_request,
            authority,
            driver,
        })
    }

    /// The configured destination address.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }
}

/// A live HTTP/2 connection to the control plane. Holds the
/// `SendRequest` handle (which is `Clone`able — every concurrent
/// request gets its own clone) plus the spawned driver task.
///
/// Drop semantics: dropping the connection aborts the driver
/// task (see `Drop` impl), which in turn closes the TCP socket.
/// The control plane will see this as a clean GOAWAY-free FIN.
#[derive(Debug)]
pub struct ControlPlaneConnection {
    /// `h2::client::SendRequest` is internally `Arc<Mutex<…>>`;
    /// `Clone` is cheap. Each `send_request` call clones it so
    /// concurrent requests on the same connection do not
    /// serialise on a single `&mut`.
    send: h2::client::SendRequest<Bytes>,
    /// `host:port` used as the HTTP/2 `:authority` pseudo-header
    /// on every request. Derived once per connection at handshake
    /// time so each request build path can use a cheap `&str`
    /// reference rather than re-resolving the SNI / dial-addr
    /// for every request.
    authority: String,
    /// The connection driver. Aborted in `Drop` so the socket
    /// is closed deterministically when the connection is
    /// dropped — `JoinHandle::drop` alone only detaches the
    /// task, leaving the driver to run until the underlying h2
    /// connection closes on its own.
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for ControlPlaneConnection {
    fn drop(&mut self) {
        // Abort the driver task so the TLS socket is torn down
        // synchronously with the connection drop, matching the
        // doc-comment contract above. The driver is otherwise
        // detached from the JoinHandle and would linger until
        // the peer signalled connection close, which delays
        // socket-fd reclamation past the caller's reconnect.
        self.driver.abort();
    }
}

/// Wire-shape of a response — status + headers + collected body.
/// h2 returns the body as a streaming `Recv` we collect into a
/// single `Bytes` here because every endpoint the agent talks
/// to fits in a single batch.
#[derive(Debug)]
pub struct CollectedResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers (case-insensitive map).
    pub headers: HeaderMap,
    /// Body bytes (concatenated from h2's DATA frames).
    pub body: Bytes,
}

impl CollectedResponse {
    /// Classify the response. Surfaces the per-error
    /// classification (Success / Unauthorized / NotFound /
    /// RateLimited / ServerError / …) so callers can drive
    /// retry / re-enrol logic on a stable contract.
    #[must_use]
    pub fn classify(&self) -> ResponseClass {
        ResponseClass::from_status(self.status.as_u16())
    }
}

impl ControlPlaneConnection {
    /// Send a single HTTP/2 request and collect the full
    /// response. Errors propagate the underlying h2 error in
    /// the source chain.
    pub async fn send_request(
        &self,
        request: RequestPath,
        body: RequestBody,
    ) -> Result<CollectedResponse, CommsError> {
        let RequestPath {
            method,
            path_and_query,
            headers,
        } = request;
        if !path_and_query.starts_with('/') {
            return Err(CommsError::Config(format!(
                "request path must start with '/': {path_and_query}"
            )));
        }

        // HTTP/2 requires the request URI to be in absolute
        // form so the `:scheme` and `:authority` pseudo-headers
        // can be derived. We always serve over TLS, so the
        // scheme is `https`; the authority was pinned at
        // handshake time.
        let absolute_uri = format!("https://{}{path_and_query}", self.authority);
        let mut builder = Request::builder()
            .method(method)
            .uri(&absolute_uri)
            // For HTTPS h2 the scheme is implicit but h2 still
            // wants us to set it on the pseudo-headers.
            .version(http::Version::HTTP_2);
        for (k, v) in &headers {
            builder = builder.header(k, v);
        }
        if matches!(body, RequestBody::Bytes(_)) {
            // h2 sends the body in DATA frames; the
            // content-length pseudo-header is optional for h2
            // requests, but the control plane logs cleaner when
            // it sees the length up front.
            let len = body.len();
            builder = builder.header(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from(len as u64),
            );
        }
        // h2 wants the request body type to be `()`; the actual
        // body bytes are sent through the returned send_stream.
        let request: Request<()> = builder
            .body(())
            .map_err(|e| CommsError::Config(format!("invalid request: {e}")))?;

        let send_request = self.send.clone();
        let mut ready = send_request
            .ready()
            .await
            .map_err(|e| CommsError::Http2(format!("send_request ready: {e}")))?;

        let end_of_stream = matches!(body, RequestBody::Empty);
        let (response_fut, mut send_stream) = ready
            .send_request(request, end_of_stream)
            .map_err(|e| CommsError::Http2(format!("send_request: {e}")))?;

        if let RequestBody::Bytes(bytes) = body {
            send_stream
                .send_data(bytes, true)
                .map_err(|e| CommsError::Http2(format!("send_data: {e}")))?;
        }

        let response = response_fut
            .await
            .map_err(|e| CommsError::Http2(format!("recv response: {e}")))?;
        let (parts, mut recv_body) = response.into_parts();

        // Drain the body into a contiguous Bytes. h2's
        // FlowControl wants us to release capacity as we read
        // each frame so the server keeps sending; if we forget
        // to release we will deadlock on the second frame.
        let mut collected: Vec<u8> = Vec::with_capacity(1024);
        let mut flow = recv_body.flow_control().clone();
        while let Some(chunk) = recv_body.data().await {
            let bytes = chunk.map_err(|e| CommsError::Http2(format!("recv body: {e}")))?;
            // Released capacity = number of bytes the server
            // can send next; we release exactly what we
            // consumed.
            let len = bytes.len();
            collected.extend_from_slice(&bytes);
            flow.release_capacity(len)
                .map_err(|e| CommsError::Http2(format!("release flow: {e}")))?;
        }

        let collected_resp = CollectedResponse {
            status: parts.status,
            headers: parts.headers,
            body: Bytes::from(collected),
        };
        Ok(collected_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_emptiness_helpers() {
        assert!(RequestBody::Empty.is_empty());
        assert_eq!(RequestBody::Empty.len(), 0);
        let body = RequestBody::Bytes(Bytes::from_static(b"hello"));
        assert!(!body.is_empty());
        assert_eq!(body.len(), 5);
    }

    #[test]
    fn request_path_builder_chains_headers() {
        let req = RequestPath::get("/foo")
            .with_header(
                http::header::ACCEPT,
                http::HeaderValue::from_static("application/msgpack"),
            )
            .with_header(
                http::header::IF_NONE_MATCH,
                http::HeaderValue::from_static("\"abc\""),
            );
        assert_eq!(req.method, http::Method::GET);
        assert_eq!(req.path_and_query, "/foo");
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn client_rejects_missing_h2_alpn() {
        crate::tls::install_ring_provider();
        // Build a ClientConfig that does NOT pin h2 — go through
        // the rustls API directly so we exercise the defence-in-
        // depth check inside `new`.
        // Build via the helper but strip ALPN explicitly.
        let mut cfg = crate::tls::build_client_config_with_webpki_roots(None).expect("builds");
        cfg.alpn_protocols.clear();
        let name = ServerName::try_from("example.invalid").expect("server name");
        let err = ControlPlaneClient::new("example.invalid:443", name, Arc::new(cfg))
            .expect_err("must reject missing h2 ALPN");
        match err {
            CommsError::Config(msg) => assert!(msg.contains("h2 ALPN")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
