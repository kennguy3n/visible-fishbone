// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Ext-authz HTTP listener.
//!
//! The thin tokio task the [`crate::manager`] docs describe but
//! deliberately do not own. Envoy's ext-authz HTTP filter POSTs the
//! candidate request to a Unix domain socket as a JSON envelope and
//! reads the verdict JSON back; this module is the server that
//! answers it. It wraps [`ExtAuthzHandler::handle_json_bytes`] — the
//! verdict logic stays in [`crate::auth`] and remains unit-testable
//! without a socket, so this layer is purely transport:
//!
//! * Bind a [`tokio::net::UnixListener`] on the operator-configured
//!   socket path (the same path the rendered `envoy.yaml`'s
//!   `ext_authz` cluster points at — see
//!   [`crate::config::EnvoyConfig::minimal_forward_proxy`]).
//! * Accept connections and, per connection, read minimal HTTP/1.1
//!   request frames (request line + headers + `Content-Length`
//!   body), hand the body to the handler, and write the verdict JSON
//!   back as an `HTTP/1.1 200 OK` response. Connections are kept
//!   alive and reused across requests (Envoy's ext-authz client
//!   pools them), so the read loop services successive requests on
//!   one socket until EOF / idle timeout / framing error.
//! * The crate has zero external HTTP-server dependency surface
//!   (mirroring the YAML generator's hand-rolled writer): the frames
//!   here are short and fully under our control, so a parser avoids
//!   pulling a server framework into the edge image.
//!
//! Framing posture: the decision always rides the JSON body
//! ([`crate::auth::ExtAuthzResponse`] carries `action` + `status`),
//! so every reply — including framing-level rejections (oversize
//! body, malformed `Content-Length`) — is an `HTTP/1.1 200 OK` whose
//! body is a verdict document. A framing failure synthesises a
//! `deny` verdict (fail-closed at the transport layer: a request we
//! cannot frame is never waved through), while the handler owns the
//! verdict for every well-framed body.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

use crate::auth::ExtAuthzHandler;
use crate::error::SwgError;

/// Default socket the listener binds and Envoy's ext-authz cluster
/// dials. Matches the address baked into
/// [`crate::config::EnvoyConfig::minimal_forward_proxy`].
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/sng/ext_authz.sock";

/// Hard ceiling on the request header block. Envoy's ext-authz
/// request carries a handful of small headers; 16 KiB is generous
/// while bounding how much a misbehaving / hostile client can make
/// the parser buffer before the body length is even known.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Runtime configuration for an [`ExtAuthzListener`].
#[derive(Clone, Debug)]
pub struct ExtAuthzListenerConfig {
    /// Unix socket path to bind. A stale socket file at this path is
    /// removed before binding so a crash-restart cycle does not fail
    /// with `EADDRINUSE`.
    pub socket_path: PathBuf,
    /// Maximum request body (the JSON envelope) the listener will
    /// buffer. Must comfortably exceed the largest ext-authz body
    /// Envoy forwards — the base64-encoded response body the content
    /// scanner inspects, which is ~4/3 the raw bytes plus the
    /// envelope overhead. Larger bodies are rejected with a
    /// fail-closed `deny` before the handler is called.
    pub max_body_bytes: usize,
    /// Per-read wall-clock ceiling. Bounds how long a half-open or
    /// idle pooled connection ties up a task; on expiry the
    /// connection is closed (Envoy reconnects on its next request).
    pub read_timeout: Duration,
}

impl ExtAuthzListenerConfig {
    /// Conservative defaults: the canonical socket path, a 64 MiB
    /// body ceiling (covers a base64-wrapped 32 MiB scan body — the
    /// `clamd` `max_scan_bytes` default — plus envelope slack), and a
    /// 10 s read timeout (well above any healthy ext-authz round-trip
    /// while still reaping a wedged connection).
    #[must_use]
    pub fn with_socket(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_body_bytes: 64 * 1024 * 1024,
            read_timeout: Duration::from_secs(10),
        }
    }
}

impl Default for ExtAuthzListenerConfig {
    fn default() -> Self {
        Self::with_socket(DEFAULT_SOCKET_PATH)
    }
}

/// A bound ext-authz listener. Construct with [`Self::bind`] (which
/// owns the socket file) and drive with [`Self::run`].
#[derive(Debug)]
pub struct ExtAuthzListener {
    listener: UnixListener,
    socket_path: PathBuf,
    handler: ExtAuthzHandler,
    max_body_bytes: usize,
    read_timeout: Duration,
}

impl ExtAuthzListener {
    /// Bind the Unix socket and capture the handler. A stale socket
    /// file at `cfg.socket_path` is removed first (a previous run's
    /// leftover would otherwise fail the bind), and the parent
    /// directory is created best-effort so a fresh `/var/run/sng`
    /// does not require a separate provisioning step.
    ///
    /// # Errors
    ///
    /// Returns [`SwgError::Io`] when the parent directory cannot be
    /// created or the socket cannot be bound.
    pub fn bind(cfg: &ExtAuthzListenerConfig, handler: ExtAuthzHandler) -> Result<Self, SwgError> {
        if let Some(parent) = cfg.socket_path.parent() {
            // Best-effort: a missing parent is created; an existing
            // one (the common case) is a no-op. A genuine failure
            // surfaces on the bind below with a clearer error.
            let _ = std::fs::create_dir_all(parent);
        }
        Self::remove_stale_socket(&cfg.socket_path)?;
        let listener = UnixListener::bind(&cfg.socket_path)
            .map_err(|e| SwgError::Io(format!("bind {}: {e}", cfg.socket_path.display())))?;
        Ok(Self {
            listener,
            socket_path: cfg.socket_path.clone(),
            handler,
            max_body_bytes: cfg.max_body_bytes,
            read_timeout: cfg.read_timeout,
        })
    }

    /// Remove a leftover socket file so a restart can re-bind. Only a
    /// `NotFound` is swallowed; any other error (e.g. a permission
    /// problem, or the path being a real file/dir we must not clobber
    /// silently) is surfaced so the operator sees it rather than
    /// hitting an opaque `EADDRINUSE` on bind.
    fn remove_stale_socket(path: &Path) -> Result<(), SwgError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SwgError::Io(format!(
                "remove stale socket {}: {e}",
                path.display()
            ))),
        }
    }

    /// The bound socket path. Exposed for diagnostics / tests.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Serve until `shutdown` resolves, then stop accepting and
    /// remove the socket file. Each accepted connection is serviced
    /// on its own spawned task so a slow scan on one request does not
    /// head-of-line block others. In-flight connection tasks are
    /// detached at shutdown — the verdict round-trip is short and the
    /// supervisor's drain budget bounds the process exit — but the
    /// listen socket is closed and unlinked promptly so a restart can
    /// re-bind.
    ///
    /// The handler is cheap to clone (an `Arc` inner), so each task
    /// gets its own clone rather than sharing a lock.
    pub async fn run<F>(self, shutdown: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            let handler = self.handler.clone();
                            let max_body = self.max_body_bytes;
                            let read_timeout = self.read_timeout;
                            tokio::spawn(async move {
                                serve_connection(stream, handler, max_body, read_timeout).await;
                            });
                        }
                        Err(e) => {
                            // A per-accept error (e.g. transient fd
                            // exhaustion) must not kill the listen
                            // loop — log and keep serving.
                            tracing::warn!(
                                target: "sng_swg::listener",
                                error = %e,
                                "ext_authz accept failed"
                            );
                        }
                    }
                }
                () = &mut shutdown => {
                    break;
                }
            }
        }
        // Unlink the socket so the next bind starts clean. Best-effort:
        // the file may already be gone if the dir was torn down.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Service one connection: read successive HTTP/1.1 requests and
/// answer each with the handler's verdict JSON, keeping the
/// connection alive for reuse until EOF / idle timeout / framing
/// error closes it.
async fn serve_connection(
    mut stream: UnixStream,
    handler: ExtAuthzHandler,
    max_body: usize,
    read_timeout: Duration,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    loop {
        // 1. Read until the header terminator is in the buffer.
        let headers_end = loop {
            if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > MAX_HEADER_BYTES {
                let _ =
                    write_verdict(&mut stream, &deny_json(431, "request headers too large")).await;
                return;
            }
            match read_more(&mut stream, &mut buf, read_timeout).await {
                ReadStep::Got => {}
                // Clean EOF before any/more header bytes, an idle
                // timeout, or an I/O error all mean "this connection
                // is done" — close it. Envoy reconnects on demand.
                ReadStep::Eof | ReadStep::TimedOut | ReadStep::Err => return,
            }
        };

        // 2. Resolve the body length from the header block.
        let content_length = match parse_body_length(&buf[..headers_end]) {
            Ok(cl) => cl,
            Err(reason) => {
                let _ = write_verdict(&mut stream, &deny_json(400, &reason)).await;
                return;
            }
        };
        if content_length > max_body {
            let _ = write_verdict(
                &mut stream,
                &deny_json(413, "ext_authz body exceeds max_body_bytes"),
            )
            .await;
            return;
        }

        // 3. Read the full body.
        while buf.len() < headers_end + content_length {
            match read_more(&mut stream, &mut buf, read_timeout).await {
                ReadStep::Got => {}
                // EOF / timeout / error mid-body: the request never
                // completed, so there is nothing to answer — close.
                ReadStep::Eof | ReadStep::TimedOut | ReadStep::Err => return,
            }
        }

        // 4. Hand the body to the verdict engine and reply.
        let body = &buf[headers_end..headers_end + content_length];
        let verdict_json = handler.handle_json_bytes(body).await;
        if write_verdict(&mut stream, &verdict_json).await.is_err() {
            return;
        }

        // 5. Drop the consumed request, keeping any pipelined bytes
        //    that arrived for the next request on this connection.
        buf.drain(..headers_end + content_length);
    }
}

/// Outcome of a single read attempt.
enum ReadStep {
    /// Appended at least one byte to the buffer.
    Got,
    /// Peer closed the connection cleanly (read returned 0).
    Eof,
    /// `read_timeout` elapsed with no bytes.
    TimedOut,
    /// Underlying I/O error.
    Err,
}

/// Read one chunk into `buf`, bounded by `read_timeout`.
async fn read_more(stream: &mut UnixStream, buf: &mut Vec<u8>, read_timeout: Duration) -> ReadStep {
    let mut tmp = [0u8; 8192];
    match timeout(read_timeout, stream.read(&mut tmp)).await {
        Ok(Ok(0)) => ReadStep::Eof,
        Ok(Ok(n)) => {
            buf.extend_from_slice(&tmp[..n]);
            ReadStep::Got
        }
        Ok(Err(_)) => ReadStep::Err,
        Err(_) => ReadStep::TimedOut,
    }
}

/// Parse the body length from a header block, rejecting framing we do
/// not support. Returns the `Content-Length` value (defaulting to 0
/// when absent — a body-less request hands the handler an empty body,
/// which it rejects as a malformed envelope). `Transfer-Encoding:
/// chunked` is refused: Envoy's ext-authz client sends a
/// `Content-Length`, and supporting chunked de-framing here would add
/// parser surface for a shape we never receive.
fn parse_body_length(header_bytes: &[u8]) -> Result<usize, String> {
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "request headers are not valid UTF-8".to_string())?;
    let mut content_length: Option<usize> = None;
    // Skip the request line; iterate the header lines.
    for line in header_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            return Err("chunked transfer-encoding is not supported".to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())?;
            content_length = Some(parsed);
        }
    }
    Ok(content_length.unwrap_or(0))
}

/// Write a verdict JSON body as an `HTTP/1.1 200 OK` response. The
/// JSON itself carries the allow/deny decision, so the HTTP status is
/// always 200; `Connection: keep-alive` lets Envoy reuse the socket.
async fn write_verdict(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Synthesise a `deny` verdict body for a transport-layer rejection
/// (a request we could not frame). Mirrors the JSON shape
/// [`crate::auth::ExtAuthzResponse`] serialises (the `action`,
/// `status`, and `reason` fields), so Envoy reads it through the same
/// path as a handler-produced verdict. The reason strings are all
/// listener-internal literals (no caller-supplied text), so the
/// hand-built JSON needs no escaping.
fn deny_json(status: u16, reason: &str) -> Vec<u8> {
    format!(r#"{{"action":"deny","status":{status},"reason":"{reason}"}}"#).into_bytes()
}

/// Naive subsequence search. `needle` is the 4-byte header
/// terminator, so a byte-by-byte scan is more than fast enough and
/// avoids a dependency.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ExtAuthzHandlerBuilder;
    use crate::bypass::BypassList;
    use crate::categorizer::LocalCategoryDb;
    use crate::malware::StaticMalwareList;
    use crate::rate_limit::RateLimiter;
    use crate::telemetry::SwgEventSource;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Build a minimal but real handler: empty categorizer, empty
    /// malware list, baked-in bypass defaults, a generous rate
    /// limiter, and a telemetry sink whose source half is dropped
    /// (emits are dropped on the closed channel — fine for a
    /// transport-layer test).
    fn handler() -> ExtAuthzHandler {
        let (sink, _source) = SwgEventSource::channel(16);
        ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(LocalCategoryDb::new(vec![])))
            .with_malware(Arc::new(StaticMalwareList::default()))
            .with_bypass(Arc::new(BypassList::industry_defaults()))
            .with_rate_limiter(RateLimiter::with_system_clock(1000.0, 1000.0))
            .with_telemetry(Arc::new(sink))
            .build()
            .expect("handler builds")
    }

    fn cfg(dir: &std::path::Path) -> ExtAuthzListenerConfig {
        let mut c = ExtAuthzListenerConfig::with_socket(dir.join("ext_authz.sock"));
        c.read_timeout = Duration::from_secs(2);
        c
    }

    /// Read a full HTTP/1.1 response (headers + Content-Length body)
    /// off the stream and return (status_line, body_bytes).
    async fn read_http_response(stream: &mut UnixStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let headers_end = loop {
            if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            let mut tmp = [0u8; 1024];
            let n = stream.read(&mut tmp).await.unwrap();
            assert!(n > 0, "unexpected EOF reading response headers");
            buf.extend_from_slice(&tmp[..n]);
        };
        let header_str = String::from_utf8(buf[..headers_end].to_vec()).unwrap();
        let status_line = header_str.lines().next().unwrap_or_default().to_string();
        let cl = header_str
            .split("\r\n")
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                if n.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        while buf.len() < headers_end + cl {
            let mut tmp = [0u8; 1024];
            let n = stream.read(&mut tmp).await.unwrap();
            assert!(n > 0, "unexpected EOF reading response body");
            buf.extend_from_slice(&tmp[..n]);
        }
        let body = buf[headers_end..headers_end + cl].to_vec();
        (status_line, body)
    }

    /// A well-formed ext-authz request envelope that an empty
    /// categorizer + no deny policy resolves to `allow`. The handler
    /// reads the request out of the flat `headers` map (Envoy's
    /// ext-authz emitter lowercases keys and uses the `:method` /
    /// `:scheme` / `:path` pseudo-headers plus `host` and the
    /// `x-sng-*` identity headers).
    fn allow_request() -> String {
        r#"{"headers":[[":method","get"],[":scheme","https"],[":path","/"],["host","example.com"],["x-sng-tenant","t1"],["x-sng-principal","p1"]]}"#.to_string()
    }

    fn post_frame(body: &str) -> Vec<u8> {
        format!(
            "POST /ext_authz HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn allow_request_round_trips_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let listener = ExtAuthzListener::bind(&cfg(dir.path()), handler()).unwrap();
        let path = listener.socket_path().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            listener
                .run(async move {
                    let _ = rx.await;
                })
                .await;
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(&post_frame(&allow_request()))
            .await
            .unwrap();
        let (status_line, body) = read_http_response(&mut client).await;
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Empty categorizer + no deny policy ⇒ allow.
        assert_eq!(json["action"], "allow");

        tx.send(()).unwrap();
        server.await.unwrap();
        // Socket file is unlinked on shutdown.
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn keep_alive_serves_two_requests_on_one_connection() {
        let dir = tempfile::tempdir().unwrap();
        let listener = ExtAuthzListener::bind(&cfg(dir.path()), handler()).unwrap();
        let path = listener.socket_path().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            listener
                .run(async move {
                    let _ = rx.await;
                })
                .await;
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        let req = allow_request();
        for _ in 0..2 {
            client.write_all(&post_frame(&req)).await.unwrap();
            let (status_line, body) = read_http_response(&mut client).await;
            assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["action"], "allow");
        }

        tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversize_body_is_denied_before_handler() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.max_body_bytes = 16; // tiny ceiling
        let listener = ExtAuthzListener::bind(&c, handler()).unwrap();
        let path = listener.socket_path().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            listener
                .run(async move {
                    let _ = rx.await;
                })
                .await;
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        let big = "x".repeat(64);
        client.write_all(&post_frame(&big)).await.unwrap();
        let (status_line, body) = read_http_response(&mut client).await;
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["action"], "deny");
        assert_eq!(json["status"], 413);

        tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_json_body_is_denied_by_handler() {
        let dir = tempfile::tempdir().unwrap();
        let listener = ExtAuthzListener::bind(&cfg(dir.path()), handler()).unwrap();
        let path = listener.socket_path().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            listener
                .run(async move {
                    let _ = rx.await;
                })
                .await;
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(&post_frame("{not json")).await.unwrap();
        let (status_line, body) = read_http_response(&mut client).await;
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["action"], "deny");
        // Handler maps a malformed envelope to a 400.
        assert_eq!(json["status"], 400);

        tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[test]
    fn parse_body_length_reads_content_length() {
        let h = b"POST /ext_authz HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(parse_body_length(h).unwrap(), 42);
    }

    #[test]
    fn parse_body_length_rejects_chunked() {
        let h = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_body_length(h).is_err());
    }

    #[test]
    fn parse_body_length_defaults_to_zero_when_absent() {
        let h = b"POST / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(parse_body_length(h).unwrap(), 0);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ext_authz.sock");
        // Pre-create a stale plain file at the socket path.
        std::fs::write(&path, b"stale").unwrap();
        let c = ExtAuthzListenerConfig::with_socket(&path);
        // Bind must succeed despite the leftover file.
        let listener = ExtAuthzListener::bind(&c, handler()).unwrap();
        assert_eq!(listener.socket_path(), path.as_path());
    }
}
