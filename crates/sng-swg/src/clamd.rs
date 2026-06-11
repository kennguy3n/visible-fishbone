//! ClamAV `clamd` streaming content scanner.
//!
//! This module implements [`ClamdScanner`], a [`ContentScanner`] that streams
//! a download's bytes to a local `clamd` daemon over the INSTREAM protocol and
//! turns the daemon's reply into a [`ContentScanVerdict`]. It is the
//! byte-level counterpart to the hash-only [`crate::malware::StaticMalwareList`]
//! and slots into the response-side verdict pipeline next to it (the hash
//! lookup runs first; clamd scans only what the hash list has not condemned).
//!
//! # Design for low latency at 5000-tenant scale
//!
//! 1. **Bounded connection pool.** Opening a TCP / unix-socket connection and
//!    starting a clamd session per scan would dominate latency and let a burst
//!    of downloads open an unbounded number of sockets to clamd. The pool
//!    ([`Pool`]) reuses connections via clamd's `IDSESSION` mode and caps the
//!    number of concurrent connections with a [`tokio::sync::Semaphore`], so
//!    clamd sees at most `pool_max_connections` in-flight scans regardless of
//!    how many tenants are downloading at once.
//! 2. **Chunked INSTREAM streaming with a size ceiling.** The body is streamed
//!    in `chunk_size` pieces rather than buffered into one allocation, and a
//!    body larger than `max_scan_bytes` is *skipped* (passed through with a
//!    [`ScanSkip::Oversize`] telemetry signal) rather than paying an unbounded
//!    scan cost — a deliberate latency/coverage trade the operator controls.
//! 3. **Verdict cache.** A [`ContentVerdictCache`] keyed by content SHA-256
//!    makes repeat downloads of the same file (shared installers, vendor PDFs,
//!    OS update blobs) O(1) and keeps the connection pool free for novel
//!    content. A file scanned once for one tenant is free for the other 4999.
//! 4. **Per-scan timeout + fail posture.** Every scan is bounded by
//!    `scan_timeout`. A timeout or connection error resolves to the operator's
//!    configured fail posture — fail-open (default; never block an employee on
//!    a scanner outage) or fail-closed — and is *never* cached, since it
//!    reflects backend availability rather than the file.
//!
//! # Wire protocol
//!
//! clamd's session dialog (`z`-prefixed, NUL-terminated commands and replies):
//!
//! ```text
//! -> zIDSESSION\0                         (once per connection, lazily)
//! -> zINSTREAM\0                          (once per scan)
//! -> <u32 BE len><len bytes> ...          (one or more chunks)
//! -> <u32 BE 0>                           (zero-length chunk terminates)
//! <- <id>: stream: OK\0                   (clean)
//! <- <id>: stream: <Signature> FOUND\0    (malicious)
//! -> zEND\0                               (closes the session)
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Semaphore;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::malware::{ContentScanVerdict, ContentScanner, ContentVerdictCache, ScanSkip};

/// Where the `clamd` daemon is reachable.
#[derive(Clone, Debug)]
pub enum ClamdEndpoint {
    /// TCP `host:port` (clamd's `TCPSocket` / `TCPAddr`).
    Tcp(String),
    /// Unix domain socket path (clamd's `LocalSocket`). Lower latency than
    /// TCP for a co-located daemon and the recommended default when clamd
    /// runs on the same host as the gateway.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl std::fmt::Display for ClamdEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

/// Runtime configuration for a [`ClamdScanner`].
///
/// This is the runtime shape (live `Duration`s and byte counts) an operator
/// constructs to enable scanning. Wiring it from the serde-deserialised
/// control-plane bundle and reading it in `manager.rs` is the deferred
/// follow-up documented in the PR body — this type is the opt-in surface,
/// defaulting to nothing until a caller builds one.
#[derive(Clone, Debug)]
pub struct ClamdConfig {
    /// Where clamd listens.
    pub endpoint: ClamdEndpoint,
    /// Maximum body size (bytes) to stream to clamd. Larger bodies are
    /// skipped with [`ScanSkip::Oversize`]. Keep at or below clamd's own
    /// `StreamMaxLength` so clamd never aborts a scan mid-stream.
    pub max_scan_bytes: usize,
    /// INSTREAM chunk size in bytes.
    pub chunk_size: usize,
    /// Wall-clock ceiling for a single scan (including the wait for a pool
    /// slot). On expiry the fail posture applies.
    pub scan_timeout: Duration,
    /// Maximum number of concurrent clamd connections the pool will hold.
    pub pool_max_connections: usize,
    /// Capacity of the content-hash verdict cache.
    pub cache_capacity: usize,
    /// Fail posture on a scan error/timeout: `true` fails open (verdict
    /// [`ContentScanVerdict::Clean`], request allowed — the default so a
    /// scanner outage never blocks employees), `false` fails closed (verdict
    /// [`ContentScanVerdict::scanner_unavailable`], request denied).
    pub fail_open: bool,
}

impl ClamdConfig {
    /// Build a config for a TCP endpoint with conservative defaults.
    #[must_use]
    pub fn tcp(addr: impl Into<String>) -> Self {
        Self::with_endpoint(ClamdEndpoint::Tcp(addr.into()))
    }

    /// Build a config for a unix-socket endpoint with conservative defaults.
    #[cfg(unix)]
    #[must_use]
    pub fn unix(path: impl Into<std::path::PathBuf>) -> Self {
        Self::with_endpoint(ClamdEndpoint::Unix(path.into()))
    }

    fn with_endpoint(endpoint: ClamdEndpoint) -> Self {
        Self {
            endpoint,
            // 32 MiB: covers the overwhelming majority of office documents,
            // installers, and archives while bounding worst-case scan latency
            // and memory. Operators handling large media raise it (and clamd's
            // StreamMaxLength) explicitly.
            max_scan_bytes: 32 * 1024 * 1024,
            // 64 KiB chunks: large enough to amortise per-chunk framing
            // overhead, small enough to keep the streaming write loop's
            // working set in cache.
            chunk_size: 64 * 1024,
            // 5 s: generous for a local daemon scanning a sub-32 MiB body;
            // an overrun trips the fail posture rather than stalling Envoy's
            // ext-authz call.
            scan_timeout: Duration::from_secs(5),
            // 16 reused connections handle a healthy download fan-in without
            // overwhelming a single clamd instance's thread pool.
            pool_max_connections: 16,
            // 8192 hot files cached; at multi-tenant scale the repeat-download
            // hit rate on shared content is high and each entry is tiny.
            cache_capacity: 8192,
            // Default fail-open: a scanner outage must never block employees
            // from legitimate downloads. Regulated tenants opt into
            // fail-closed explicitly.
            fail_open: true,
        }
    }
}

/// A single duplex byte stream to clamd. Boxed so TCP and unix sockets share
/// one connection / pool type.
trait ClamdStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClamdStream for T {}

/// A pooled clamd connection. Carries whether the `IDSESSION` handshake has
/// been sent so it is started lazily on first use and reused thereafter.
struct Connection {
    stream: Box<dyn ClamdStream>,
    session_started: bool,
}

/// Bounded, connection-reusing pool. The semaphore caps *total* live
/// connections: a permit is held for the whole checkout, and a new connection
/// is opened only while holding a permit and finding the idle list empty, so
/// `idle + in_use <= pool_max_connections` always holds.
struct Pool {
    endpoint: ClamdEndpoint,
    idle: Mutex<Vec<Connection>>,
    sem: Semaphore,
}

impl Pool {
    fn new(endpoint: ClamdEndpoint, max: usize) -> Self {
        Self {
            endpoint,
            idle: Mutex::new(Vec::new()),
            sem: Semaphore::new(max.max(1)),
        }
    }

    async fn connect(&self) -> std::io::Result<Connection> {
        let stream: Box<dyn ClamdStream> = match &self.endpoint {
            ClamdEndpoint::Tcp(addr) => Box::new(TcpStream::connect(addr).await?),
            #[cfg(unix)]
            ClamdEndpoint::Unix(path) => Box::new(UnixStream::connect(path).await?),
        };
        Ok(Connection {
            stream,
            session_started: false,
        })
    }

    /// Pop a warm connection if one is idle.
    fn take_idle(&self) -> Option<Connection> {
        self.idle.lock().pop()
    }

    /// Return a healthy connection to the idle list for reuse.
    fn put_back(&self, conn: Connection) {
        self.idle.lock().push(conn);
    }
}

/// Streaming content scanner backed by a local `clamd` daemon.
#[derive(Clone)]
pub struct ClamdScanner {
    inner: Arc<ClamdInner>,
}

struct ClamdInner {
    pool: Pool,
    cache: ContentVerdictCache,
    max_scan_bytes: usize,
    chunk_size: usize,
    scan_timeout: Duration,
    fail_open: bool,
    /// Monotonic session command counter used to label INSTREAM commands; the
    /// id is cosmetic for our single-command-per-checkout usage but keeps the
    /// wire dialog well-formed for clamd's session mode.
    seq: AtomicU64,
}

impl std::fmt::Debug for ClamdScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClamdScanner")
            .field("endpoint", &self.inner.pool.endpoint)
            .field("max_scan_bytes", &self.inner.max_scan_bytes)
            .field("fail_open", &self.inner.fail_open)
            .field("cache_len", &self.inner.cache.len())
            .finish_non_exhaustive()
    }
}

impl ClamdScanner {
    /// Build a scanner from a runtime [`ClamdConfig`]. Construction does not
    /// open a connection — the first scan does — so a misconfigured endpoint
    /// surfaces as a fail-posture scan result (with telemetry) rather than a
    /// constructor error, keeping the verdict pipeline's wiring infallible.
    #[must_use]
    pub fn new(config: ClamdConfig) -> Self {
        Self {
            inner: Arc::new(ClamdInner {
                pool: Pool::new(config.endpoint, config.pool_max_connections),
                cache: ContentVerdictCache::new(config.cache_capacity),
                max_scan_bytes: config.max_scan_bytes,
                chunk_size: config.chunk_size.max(1),
                scan_timeout: config.scan_timeout,
                fail_open: config.fail_open,
                seq: AtomicU64::new(0),
            }),
        }
    }

    /// Number of verdicts currently cached. Exposed for telemetry / tests.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.inner.cache.len()
    }

    /// Resolve a scan error/timeout into the configured fail posture. Always
    /// emits telemetry; never returns a cacheable verdict.
    fn fail(&self, context: &str) -> ContentScanVerdict {
        if self.inner.fail_open {
            tracing::warn!(
                target: "sng_swg::clamd",
                endpoint = %self.inner.pool.endpoint,
                context,
                posture = "fail_open",
                "clamd scan failed; failing open (allowing download)"
            );
            ContentScanVerdict::Clean
        } else {
            tracing::warn!(
                target: "sng_swg::clamd",
                endpoint = %self.inner.pool.endpoint,
                context,
                posture = "fail_closed",
                "clamd scan failed; failing closed (denying download)"
            );
            ContentScanVerdict::scanner_unavailable()
        }
    }

    /// Run one INSTREAM scan: acquire a pool slot, reuse-or-open a connection,
    /// stream the bytes, parse the reply. Reuses the connection on success,
    /// discards it on any I/O error so a half-broken socket is never pooled.
    async fn scan_once(&self, bytes: &[u8]) -> std::io::Result<ContentScanVerdict> {
        // Hold a permit for the whole checkout so total live connections stay
        // bounded by the pool size. The semaphore is owned by the pool for the
        // scanner's lifetime and is never closed, so `acquire` cannot fail in
        // practice; map the impossible error to an I/O error anyway rather than
        // panic, so a future refactor that does close it degrades through the
        // configured fail posture instead of taking down the worker.
        let Ok(_permit) = self.inner.pool.sem.acquire().await else {
            return Err(std::io::Error::other("clamd pool semaphore closed"));
        };

        let mut conn = match self.inner.pool.take_idle() {
            Some(conn) => conn,
            None => self.inner.pool.connect().await?,
        };

        match self.instream(&mut conn, bytes).await {
            Ok(verdict) => {
                self.inner.pool.put_back(conn);
                Ok(verdict)
            }
            Err(e) => {
                // Drop `conn` (do not pool a connection in an unknown state).
                Err(e)
            }
        }
    }

    /// Execute the INSTREAM dialog on an already-checked-out connection.
    async fn instream(
        &self,
        conn: &mut Connection,
        bytes: &[u8],
    ) -> std::io::Result<ContentScanVerdict> {
        let stream = &mut conn.stream;
        if !conn.session_started {
            stream.write_all(b"zIDSESSION\0").await?;
            conn.session_started = true;
        }
        let _id = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        stream.write_all(b"zINSTREAM\0").await?;
        for chunk in bytes.chunks(self.inner.chunk_size) {
            let len = u32::try_from(chunk.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "chunk too large")
            })?;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(chunk).await?;
        }
        // Zero-length chunk terminates the stream.
        stream.write_all(&0u32.to_be_bytes()).await?;
        stream.flush().await?;

        let reply = read_until_nul(stream, 4096).await?;
        parse_reply(&reply)
    }
}

#[async_trait]
impl ContentScanner for ClamdScanner {
    async fn scan(&self, bytes: &[u8], sha256_hex: Option<&str>) -> ContentScanVerdict {
        if bytes.is_empty() {
            return ContentScanVerdict::Skipped {
                reason: ScanSkip::Empty,
            };
        }

        // Oversize check first, before hashing or touching the cache. The
        // verdict is a pure function of the body length and the immutable
        // `max_scan_bytes`, so it can never be served from the cache (the
        // length check always fires before any lookup). Caching it would only
        // burn an LRU slot and evict useful clean/malicious verdicts, and
        // hashing an oversize body we are about to skip is wasted work.
        if bytes.len() > self.inner.max_scan_bytes {
            tracing::info!(
                target: "sng_swg::clamd",
                bytes = bytes.len(),
                max = self.inner.max_scan_bytes,
                "download exceeds max scan size; skipping content scan (passthrough)"
            );
            return ContentScanVerdict::Skipped {
                reason: ScanSkip::Oversize,
            };
        }

        // Resolve the cache key. The pipeline normally supplies the content
        // hash it already computed for the hash-feed lookup; compute it here
        // only when absent so the cache still works for direct callers.
        let key: String = sha256_hex.map_or_else(
            || {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                hex::encode(hasher.finalize())
            },
            str::to_ascii_lowercase,
        );

        if let Some(hit) = self.inner.cache.get(&key) {
            return hit;
        }

        match tokio::time::timeout(self.inner.scan_timeout, self.scan_once(bytes)).await {
            Ok(Ok(verdict)) => {
                // Only cache deterministic scan results. Fail-posture verdicts
                // are produced by `fail()` in the error arms below and never
                // reach here; gating on `is_cacheable()` is belt-and-braces so
                // a transient verdict can never be pinned even if a future
                // refactor routes one through this branch.
                if verdict.is_cacheable() {
                    self.inner.cache.put(&key, verdict.clone());
                }
                verdict
            }
            Ok(Err(e)) => self.fail(&format!("io error: {e}")),
            Err(_elapsed) => self.fail("scan timed out"),
        }
    }
}

/// Read bytes until a NUL terminator or EOF, capping at `max` bytes so a
/// misbehaving peer cannot make us allocate without bound.
async fn read_until_nul<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            break; // EOF without terminator — parse what we have.
        }
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "clamd reply exceeded maximum length",
            ));
        }
    }
    Ok(buf)
}

/// Parse a clamd INSTREAM reply into a verdict.
///
/// Accepts both session (`<id>: stream: ...`) and one-shot (`stream: ...`)
/// reply forms by anchoring on the `stream: ` token. Only the two well-formed
/// outcomes resolve to a verdict: `OK` -> [`ContentScanVerdict::Clean`] and
/// `<Sig> FOUND` -> [`ContentScanVerdict::Malicious`].
///
/// Any other reply — a clamd error string (`INSTREAM size limit exceeded
/// ERROR`), a truncated frame, garbage — is *not* a scan result and must not
/// be turned into one here. Returning a verdict directly (clean **or** the
/// fail-closed sentinel) would bypass the operator's configured fail posture:
/// the caller routes such a value straight out, so a fail-open operator would
/// still get a deny on a malformed reply. Instead we surface it as an
/// [`std::io::Error`] so it flows through [`ClamdScanner::scan_once`] (which
/// discards the possibly-desynced connection) into the scanner's `fail()`
/// path, where the single source of fail-open/closed truth decides.
fn parse_reply(reply: &[u8]) -> std::io::Result<ContentScanVerdict> {
    let text = String::from_utf8_lossy(reply);
    let text = text.trim().trim_end_matches('\0').trim();
    // Anchor on the part after the last "stream: " so the `<id>: ` session
    // prefix (if any) is ignored.
    let payload = text.rsplit("stream: ").next().unwrap_or(text).trim();

    if payload == "OK" {
        Ok(ContentScanVerdict::Clean)
    } else if let Some(sig) = payload.strip_suffix(" FOUND") {
        let signature = sig.trim();
        let signature = if signature.is_empty() {
            "unknown".to_string()
        } else {
            signature.to_string()
        };
        Ok(ContentScanVerdict::Malicious { signature })
    } else {
        // Unexpected reply (clamd error, truncated frame, desynced session).
        // Treat it as a scan failure so the connection is dropped and the
        // configured fail posture — not this parser — decides allow vs deny.
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected clamd reply: {text}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// EICAR test string, assembled at runtime so this source file is not
    /// itself flagged by a host scanner.
    fn eicar_bytes() -> Vec<u8> {
        format!(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}!$H+H*",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        )
        .into_bytes()
    }

    /// How a mock clamd server should behave for a connection.
    #[derive(Clone, Copy)]
    enum MockBehavior {
        /// Speak the real protocol: OK for clean, FOUND for EICAR.
        Normal,
        /// Accept and read the request but never reply (drives a timeout).
        Hang,
        /// Reply with a clamd error string that is neither OK nor FOUND
        /// (e.g. the body exceeded clamd's own `StreamMaxLength`).
        Error,
    }

    /// A mock clamd server over a real loopback TCP listener. It speaks the
    /// genuine session/INSTREAM dialog so the production protocol code is
    /// exercised end to end. `scan_count` records how many INSTREAM commands
    /// it served so tests can assert the verdict cache prevents re-scans.
    struct MockClamd {
        addr: String,
        scan_count: Arc<AtomicUsize>,
        _handle: tokio::task::JoinHandle<()>,
    }

    impl MockClamd {
        async fn start(behavior: MockBehavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let scan_count = Arc::new(AtomicUsize::new(0));
            let counter = scan_count.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        break;
                    };
                    let counter = counter.clone();
                    tokio::spawn(async move {
                        let _ = serve_conn(&mut sock, behavior, &counter).await;
                    });
                }
            });
            Self {
                addr,
                scan_count,
                _handle: handle,
            }
        }

        fn scans(&self) -> usize {
            self.scan_count.load(Ordering::SeqCst)
        }
    }

    /// Serve one connection's session: read commands, reply per behavior.
    async fn serve_conn(
        sock: &mut TcpStream,
        behavior: MockBehavior,
        counter: &AtomicUsize,
    ) -> std::io::Result<()> {
        // Read the (optional) IDSESSION + INSTREAM command framing. We parse
        // the command stream loosely: read a NUL-terminated command token,
        // and when it is INSTREAM, consume chunks then reply.
        loop {
            let Some(cmd) = read_cmd(sock).await? else {
                return Ok(()); // connection closed
            };
            if cmd.contains("IDSESSION") {
                continue;
            }
            if cmd.contains("END") {
                return Ok(());
            }
            if cmd.contains("INSTREAM") {
                let body = read_chunks(sock).await?;
                if matches!(behavior, MockBehavior::Hang) {
                    // Never reply; let the client time out. Keep the socket
                    // open by awaiting forever.
                    std::future::pending::<()>().await;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let eicar = eicar_bytes();
                let reply = if matches!(behavior, MockBehavior::Error) {
                    "1: INSTREAM size limit exceeded ERROR\0".to_string()
                } else if body
                    .windows(eicar.len())
                    .any(|w| w == eicar.as_slice())
                {
                    "1: stream: Eicar-Test-Signature FOUND\0".to_string()
                } else {
                    "1: stream: OK\0".to_string()
                };
                sock.write_all(reply.as_bytes()).await?;
                sock.flush().await?;
            }
        }
    }

    /// Read one `z`-style NUL-terminated command token. Returns `None` on EOF.
    async fn read_cmd(sock: &mut TcpStream) -> std::io::Result<Option<String>> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = sock.read(&mut byte).await?;
            if n == 0 {
                return Ok(None);
            }
            if byte[0] == 0 {
                // Strip a leading 'z'/'n' prefix.
                let s = String::from_utf8_lossy(&buf).to_string();
                return Ok(Some(s));
            }
            buf.push(byte[0]);
            if buf.len() > 64 {
                // Not a command — must be chunk data leaking in; stop.
                return Ok(Some(String::from_utf8_lossy(&buf).to_string()));
            }
        }
    }

    /// Read INSTREAM chunks until the zero-length terminator; return the body.
    async fn read_chunks(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                return Ok(body);
            }
            let mut chunk = vec![0u8; len];
            sock.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
        }
    }

    fn cfg(addr: &str) -> ClamdConfig {
        let mut c = ClamdConfig::tcp(addr);
        c.scan_timeout = Duration::from_millis(300);
        c.cache_capacity = 64;
        c
    }

    #[tokio::test]
    async fn clean_body_scans_to_clean() {
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let scanner = ClamdScanner::new(cfg(&mock.addr));
        let v = scanner.scan(b"a perfectly innocent file", None).await;
        assert_eq!(v, ContentScanVerdict::Clean);
    }

    #[tokio::test]
    async fn eicar_body_scans_to_malicious_with_signature() {
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let scanner = ClamdScanner::new(cfg(&mock.addr));
        let v = scanner.scan(&eicar_bytes(), None).await;
        assert_eq!(
            v,
            ContentScanVerdict::Malicious {
                signature: "Eicar-Test-Signature".to_string()
            }
        );
    }

    #[tokio::test]
    async fn large_chunked_body_streams_correctly() {
        // A body several chunks long must reassemble correctly on the server.
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let mut c = cfg(&mock.addr);
        c.chunk_size = 8; // force many chunks
        let scanner = ClamdScanner::new(c);
        let body = vec![b'x'; 100];
        assert_eq!(scanner.scan(&body, None).await, ContentScanVerdict::Clean);

        // EICAR split across many small chunks must still be detected.
        let v = scanner.scan(&eicar_bytes(), Some(&"e".repeat(64))).await;
        assert!(matches!(v, ContentScanVerdict::Malicious { .. }));
    }

    #[tokio::test]
    async fn oversize_body_is_skipped_without_scanning() {
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let mut c = cfg(&mock.addr);
        c.max_scan_bytes = 16;
        let scanner = ClamdScanner::new(c);
        let v = scanner.scan(&[b'x'; 64], None).await;
        assert_eq!(
            v,
            ContentScanVerdict::Skipped {
                reason: ScanSkip::Oversize
            }
        );
        assert_eq!(mock.scans(), 0, "oversize body must never reach clamd");
    }

    #[tokio::test]
    async fn empty_body_is_skipped() {
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let scanner = ClamdScanner::new(cfg(&mock.addr));
        assert_eq!(
            scanner.scan(b"", None).await,
            ContentScanVerdict::Skipped {
                reason: ScanSkip::Empty
            }
        );
        assert_eq!(mock.scans(), 0);
    }

    #[tokio::test]
    async fn cache_hit_avoids_rescanning_same_content() {
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let scanner = ClamdScanner::new(cfg(&mock.addr));
        let hash = "c".repeat(64);
        let body = b"repeat download of a shared installer";
        let first = scanner.scan(body, Some(&hash)).await;
        let second = scanner.scan(body, Some(&hash)).await;
        assert_eq!(first, ContentScanVerdict::Clean);
        assert_eq!(second, ContentScanVerdict::Clean);
        assert_eq!(
            mock.scans(),
            1,
            "second download of identical content must be served from cache"
        );
        assert_eq!(scanner.cache_len(), 1);
    }

    #[tokio::test]
    async fn timeout_fails_open_by_default() {
        let mock = MockClamd::start(MockBehavior::Hang).await;
        let mut c = cfg(&mock.addr);
        c.scan_timeout = Duration::from_millis(150);
        c.fail_open = true;
        let scanner = ClamdScanner::new(c);
        // Fail-open => Clean (allow) on timeout, and not cached.
        assert_eq!(scanner.scan(b"some bytes", None).await, ContentScanVerdict::Clean);
        assert_eq!(scanner.cache_len(), 0, "fail-open verdict must not be cached");
    }

    #[tokio::test]
    async fn timeout_fails_closed_when_configured() {
        let mock = MockClamd::start(MockBehavior::Hang).await;
        let mut c = cfg(&mock.addr);
        c.scan_timeout = Duration::from_millis(150);
        c.fail_open = false;
        let scanner = ClamdScanner::new(c);
        let v = scanner.scan(b"some bytes", None).await;
        assert!(v.is_malicious(), "fail-closed must deny on timeout");
        assert_eq!(v, ContentScanVerdict::scanner_unavailable());
        assert_eq!(scanner.cache_len(), 0, "fail-closed verdict must not be cached");
    }

    #[tokio::test]
    async fn connection_refused_applies_fail_posture() {
        // Point at a port with nothing listening. Bind then drop to get a
        // very-likely-free port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let mut open = cfg(&addr);
        open.fail_open = true;
        assert_eq!(
            ClamdScanner::new(open).scan(b"bytes", None).await,
            ContentScanVerdict::Clean
        );

        let mut closed = cfg(&addr);
        closed.fail_open = false;
        assert!(
            ClamdScanner::new(closed)
                .scan(b"bytes", None)
                .await
                .is_malicious()
        );
    }

    #[tokio::test]
    async fn unexpected_reply_applies_fail_posture() {
        // A clamd error string (neither OK nor FOUND) is not a scan result.
        // It must be resolved by the operator's fail posture, NOT silently
        // turned into a deny — otherwise a body that exceeds clamd's own
        // StreamMaxLength would block downloads even for a fail-open operator.
        let mock = MockClamd::start(MockBehavior::Error).await;

        let mut open = cfg(&mock.addr);
        open.fail_open = true;
        let scanner = ClamdScanner::new(open);
        assert_eq!(
            scanner.scan(b"some bytes", None).await,
            ContentScanVerdict::Clean,
            "fail-open must allow on an unparseable reply"
        );
        assert_eq!(
            scanner.cache_len(),
            0,
            "a fail-posture verdict must never be cached"
        );

        let mut closed = cfg(&mock.addr);
        closed.fail_open = false;
        let scanner = ClamdScanner::new(closed);
        let v = scanner.scan(b"some bytes", None).await;
        assert_eq!(
            v,
            ContentScanVerdict::scanner_unavailable(),
            "fail-closed must deny on an unparseable reply"
        );
        assert_eq!(scanner.cache_len(), 0);
    }

    #[tokio::test]
    async fn unexpected_reply_discards_connection() {
        // An unparseable reply leaves the session framing in an unknown
        // state, so the connection must be dropped rather than pooled.
        let mock = MockClamd::start(MockBehavior::Error).await;
        let mut c = cfg(&mock.addr);
        c.fail_open = true;
        let scanner = ClamdScanner::new(c);
        let _ = scanner.scan(b"some bytes", None).await;
        assert_eq!(
            scanner.inner.pool.idle.lock().len(),
            0,
            "a connection that produced an unparseable reply must not be pooled"
        );
    }

    #[tokio::test]
    async fn connections_are_reused_across_scans() {
        // Two sequential scans on one scanner should reuse a single pooled
        // connection (the pool keeps it warm via IDSESSION). We assert the
        // scanner produces correct verdicts across reuse; the mock keeps the
        // session open and serves multiple INSTREAM commands per connection.
        let mock = MockClamd::start(MockBehavior::Normal).await;
        let scanner = ClamdScanner::new(cfg(&mock.addr));
        assert_eq!(scanner.scan(b"first", None).await, ContentScanVerdict::Clean);
        assert_eq!(scanner.scan(b"second", None).await, ContentScanVerdict::Clean);
        assert_eq!(mock.scans(), 2);
        // Exactly one connection should be sitting idle in the pool.
        assert_eq!(scanner.inner.pool.idle.lock().len(), 1);
    }

    #[test]
    fn parse_reply_handles_session_and_oneshot_forms() {
        assert_eq!(
            parse_reply(b"1: stream: OK\0").unwrap(),
            ContentScanVerdict::Clean
        );
        assert_eq!(
            parse_reply(b"stream: OK").unwrap(),
            ContentScanVerdict::Clean
        );
        assert_eq!(
            parse_reply(b"1: stream: Win.Test.EICAR_HDB-1 FOUND\0").unwrap(),
            ContentScanVerdict::Malicious {
                signature: "Win.Test.EICAR_HDB-1".to_string()
            }
        );
        assert_eq!(
            parse_reply(b"stream: Some.Sig FOUND").unwrap(),
            ContentScanVerdict::Malicious {
                signature: "Some.Sig".to_string()
            }
        );
        // An unexpected reply is not a scan result: it must surface as an
        // error so the caller's fail posture decides, never a bare verdict.
        let err = parse_reply(b"1: INSTREAM size limit exceeded ERROR").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
