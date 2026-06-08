//! Image download adapter.
//!
//! The download side of the engine is intentionally split from
//! the manifest verifier: the manifest is small enough to fit
//! in memory and is verified up front; the image bytes can be
//! large (50+ MB for a real `sng-edge` build), so they are
//! streamed through a sink that incrementally hashes them
//! (via [`StreamingHasher`]) and persists them to the inactive
//! bank in lockstep (via [`crate::bank::WriteHandle`]).
//!
//! Three halves:
//!
//! * [`ChunkSink`] — the trait the downloader feeds bytes
//!   into. The orchestrator builds a [`TeeChunkSink`] that
//!   forwards each chunk into both a [`StreamingHasher`] and a
//!   bank-write handle so the SHA-256 verification and the
//!   bank persistence happen in a single streaming pass —
//!   the bytes never need to be buffered to disk twice and
//!   they never need to be re-read for verification.
//! * [`ImageDownloader`] — the trait the orchestrator depends
//!   on. A production implementation is backed by
//!   `sng-comms`'s HTTP client; the in-process
//!   [`InMemoryDownloader`] returns caller-supplied bytes.
//! * [`StreamingHasher`] — the SHA-256 accumulator with a
//!   hard upper bound on bytes read. Implements [`ChunkSink`]
//!   directly so simple test cases can pass it without the
//!   tee wrapper.

use crate::error::UpdaterError;
use crate::manifest::{ImageHash, UpdateManifest};
use async_trait::async_trait;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

/// Receipt produced by a finalised [`StreamingHasher`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageReceipt {
    /// Bytes-read counter.
    pub size_bytes: u64,
    /// Observed SHA-256 over all bytes fed through the hasher.
    pub sha256: ImageHash,
}

/// Streaming SHA-256 hasher with a hard upper-bound on bytes
/// read.
///
/// The orchestrator constructs one of these per install
/// attempt, hands it to a [`TeeChunkSink`] that mirrors every
/// chunk into the bank write handle, then calls
/// [`Self::finalise`] to get an [`ImageReceipt`]. The
/// orchestrator then compares the receipt against the manifest
/// claims and either commits the install or surfaces a
/// [`UpdaterError::ImageHashMismatch`] /
/// [`UpdaterError::ImageSizeExceeded`].
#[derive(Debug)]
pub struct StreamingHasher {
    hasher: Sha256,
    size_read: u64,
    max_size: u64,
}

impl StreamingHasher {
    /// Construct a hasher bounded at `max_size` bytes — feed
    /// the manifest's `image_size_bytes` claim.
    #[must_use]
    pub fn new(max_size: u64) -> Self {
        Self {
            hasher: Sha256::new(),
            size_read: 0,
            max_size,
        }
    }

    /// Feed a chunk of bytes. Returns
    /// [`UpdaterError::ImageSizeExceeded`] if the cumulative
    /// byte count strictly exceeds `max_size`; on that error
    /// the orchestrator MUST discard the partial download.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), UpdaterError> {
        let new_total = self.size_read.checked_add(chunk.len() as u64).ok_or(
            UpdaterError::ImageSizeExceeded {
                claimed: self.max_size,
                read: u64::MAX,
            },
        )?;
        if new_total > self.max_size {
            return Err(UpdaterError::ImageSizeExceeded {
                claimed: self.max_size,
                read: new_total,
            });
        }
        self.hasher.update(chunk);
        self.size_read = new_total;
        Ok(())
    }

    /// Finalise the hash. Consumes the hasher.
    #[must_use]
    pub fn finalise(self) -> ImageReceipt {
        let mut out = [0_u8; 32];
        let digest = self.hasher.finalize();
        out.copy_from_slice(&digest);
        ImageReceipt {
            size_bytes: self.size_read,
            sha256: ImageHash::new(out),
        }
    }

    /// Current bytes-read counter — useful for tests asserting
    /// "the hasher saw exactly N bytes" before finalise.
    #[must_use]
    pub fn size_read(&self) -> u64 {
        self.size_read
    }

    /// Manifest-claimed size pin.
    #[must_use]
    pub fn max_size(&self) -> u64 {
        self.max_size
    }
}

/// Async chunk sink the downloader feeds bytes into.
///
/// The orchestrator owns the concrete sink; the downloader
/// is given a `&mut dyn ChunkSink` and never sees the
/// hasher or the bank handle directly. This keeps the
/// download trait minimal (a single method) and lets the
/// orchestrator inject whatever combination of post-chunk
/// work it needs.
#[async_trait]
pub trait ChunkSink: Send {
    /// Consume a chunk of image bytes. Implementations MAY
    /// perform async I/O (e.g. writing to a partition);
    /// they MUST surface any failure as a [`DownloadError`]
    /// so the orchestrator can map it onto the right
    /// [`UpdaterError`] variant downstream.
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DownloadError>;
}

#[async_trait]
impl ChunkSink for StreamingHasher {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DownloadError> {
        Self::write_chunk(self, chunk).map_err(map_hasher_error)
    }
}

/// Sink that mirrors every chunk into a [`StreamingHasher`]
/// and a bank-write handle. The orchestrator constructs one
/// of these per install attempt and hands it to the
/// downloader.
///
/// The hasher's write is sync (in-memory SHA-256) and runs
/// first, so size-overflow is detected before any bytes hit
/// the bank handle. The bank handle's write is async and runs
/// second; on failure the orchestrator unwinds by calling
/// [`crate::bank::WriteHandle::abandon`].
#[allow(missing_debug_implementations)]
pub struct TeeChunkSink<'a> {
    hasher: &'a mut StreamingHasher,
    handle: &'a mut Box<dyn crate::bank::WriteHandle + Send>,
}

impl<'a> TeeChunkSink<'a> {
    /// Construct a tee from a mutable borrow of the hasher
    /// and the bank handle.
    pub fn new(
        hasher: &'a mut StreamingHasher,
        handle: &'a mut Box<dyn crate::bank::WriteHandle + Send>,
    ) -> Self {
        Self { hasher, handle }
    }
}

#[async_trait]
impl ChunkSink for TeeChunkSink<'_> {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DownloadError> {
        // Hasher first so size-overflow is surfaced before
        // the bank handle ever sees a byte over the budget.
        StreamingHasher::write_chunk(self.hasher, chunk).map_err(map_hasher_error)?;
        // Bank handle second — its `write_chunk` is the
        // expensive (async) call.
        crate::bank::WriteHandle::write_chunk(self.handle.as_mut(), chunk)
            .await
            .map_err(|e| map_bank_error(&e))?;
        Ok(())
    }
}

fn map_bank_error(e: &UpdaterError) -> DownloadError {
    // Carry bank-write errors through a DISTINCT variant so the
    // orchestrator's `map_download_error` can reclassify them
    // back to `UpdaterError::BankWrite` (and thus to
    // `ErrorCode::UpdaterBankWriteFailure`). Folding them into
    // `Transport` would silently re-bucket bank-disk failures
    // under `ErrorCode::Io` on operator dashboards — see the
    // `DownloadError::BankWrite` variant doc.
    DownloadError::BankWrite(e.to_string())
}

/// Errors a downloader implementation may surface. Distinct
/// from [`UpdaterError`] so transport-level shapes stay
/// bucketed separately from manifest-shaped shapes. The
/// orchestrator wraps these into the right `UpdaterError`
/// variant.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DownloadError {
    /// Underlying transport (network, HTTP) failed.
    #[error("transport: {0}")]
    Transport(String),
    /// Upstream returned a 4xx/5xx status. Carried as a string
    /// so the orchestrator can include it in the operator
    /// error message.
    #[error("upstream status: {0}")]
    Status(String),
    /// Upstream closed the stream before the manifest's
    /// declared size was reached.
    #[error("truncated: read {read} of {expected}")]
    Truncated {
        /// Bytes the manifest claimed.
        expected: u64,
        /// Bytes received before stream close.
        read: u64,
    },
    /// Size hasher refused a chunk because the cumulative
    /// byte total exceeded the manifest's declared size.
    /// Distinct from [`Self::Truncated`] (which is the
    /// opposite — under-delivery).
    #[error("size exceeded: declared {claimed} bytes, attempted {attempted}")]
    SizeExceeded {
        /// Manifest-declared upper bound.
        claimed: u64,
        /// Cumulative bytes the downloader tried to feed.
        attempted: u64,
    },
    /// The bank-write handle rejected a streaming chunk —
    /// surfaced by [`TeeChunkSink`] when the underlying
    /// [`crate::bank::WriteHandle::write_chunk`] call returned
    /// an [`UpdaterError::BankWrite`]. Distinct from
    /// [`Self::Transport`] so the orchestrator's
    /// `map_download_error` can route this back to
    /// `UpdaterError::BankWrite` and the
    /// `updater.bank.write.failure` dashboard code instead of
    /// silently re-bucketing every disk-side failure under the
    /// generic `io` code. The message body carries the
    /// underlying error's Display so the operator-facing
    /// detail is preserved.
    #[error("bank write: {0}")]
    BankWrite(String),
}

/// Image-bytes adapter trait. Production implementations sit
/// on top of `sng-comms`'s HTTP client; tests use
/// [`InMemoryDownloader`].
///
/// The adapter is responsible for streaming the bytes into the
/// supplied [`ChunkSink`] AND for surfacing transport errors
/// as [`DownloadError`]. The orchestrator's sink (the
/// [`TeeChunkSink`]) is what enforces the manifest's declared
/// size; the downloader does not need to enforce it itself,
/// but it MUST surface a [`DownloadError::Truncated`] if the
/// upstream stream closes before the manifest's declared size
/// is reached.
#[async_trait]
pub trait ImageDownloader: Send + Sync {
    /// Download the bytes at `url`, feeding them through the
    /// supplied sink. The implementation MUST return
    /// `Err(DownloadError::Truncated { .. })` if the stream
    /// closes before the manifest's declared size is reached;
    /// it MUST propagate the sink's
    /// `DownloadError::SizeExceeded` if the byte budget is
    /// blown past.
    async fn download(
        &self,
        url: &Url,
        declared_size: u64,
        sink: &mut (dyn ChunkSink + Send),
    ) -> Result<(), DownloadError>;
}

/// In-process downloader for tests. Holds a single payload
/// keyed by URL; the orchestrator's pull lookup feeds whatever
/// bytes were registered.
#[derive(Debug, Default)]
pub struct InMemoryDownloader {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    payloads: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Optional transport failure to surface on every call.
    fail_with: Mutex<Option<DownloadError>>,
    /// Optional chunk size — the downloader splits the payload
    /// into `chunk_size`-byte chunks before feeding it to the
    /// sink. Defaults to 64 KiB so the SHA-256 loop is
    /// exercised across multiple `update` calls.
    chunk_size: Mutex<usize>,
    /// Call counter — exposed via [`Self::call_count`].
    calls: Mutex<u64>,
    /// Optional truncation — when set, the downloader stops
    /// after writing this many bytes and surfaces a
    /// `DownloadError::Truncated`.
    truncate_after: Mutex<Option<u64>>,
}

impl InMemoryDownloader {
    /// Construct an empty downloader.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                chunk_size: Mutex::new(64 * 1024),
                ..Inner::default()
            }),
        }
    }

    /// Register a payload to be served from the given URL.
    /// Subsequent downloads of the same URL replace the
    /// previous payload.
    pub fn register(&self, url: &Url, bytes: Vec<u8>) {
        self.inner.payloads.lock().insert(url.to_string(), bytes);
    }

    /// Convenience: register from a [`UpdateManifest`] so the
    /// caller does not have to repeat the URL.
    pub fn register_for_manifest(&self, manifest: &UpdateManifest, bytes: Vec<u8>) {
        self.register(&manifest.image_url, bytes);
    }

    /// Force every subsequent download to fail with the given
    /// error. Pass `None` to clear the override.
    pub fn force_failure(&self, e: Option<DownloadError>) {
        *self.inner.fail_with.lock() = e;
    }

    /// Override the chunk size the downloader uses. Useful
    /// for tests that want to assert hasher behaviour across
    /// chunk boundaries.
    pub fn set_chunk_size(&self, size: usize) {
        *self.inner.chunk_size.lock() = size.max(1);
    }

    /// Number of [`ImageDownloader::download`] calls served.
    pub fn call_count(&self) -> u64 {
        *self.inner.calls.lock()
    }

    /// Force the next download to truncate after `n` bytes.
    /// The downloader writes the first `n` bytes through the
    /// sink, then surfaces `DownloadError::Truncated`.
    pub fn force_truncation_after(&self, n: Option<u64>) {
        *self.inner.truncate_after.lock() = n;
    }

    /// Cheap shareable handle for the orchestrator-side reader.
    #[must_use]
    pub fn handle(&self) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[async_trait]
impl ImageDownloader for InMemoryDownloader {
    async fn download(
        &self,
        url: &Url,
        declared_size: u64,
        sink: &mut (dyn ChunkSink + Send),
    ) -> Result<(), DownloadError> {
        *self.inner.calls.lock() += 1;
        if let Some(e) = self.inner.fail_with.lock().clone() {
            return Err(e);
        }
        let bytes = self
            .inner
            .payloads
            .lock()
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| DownloadError::Status(format!("no payload registered for url {url}")))?;
        let chunk_size = *self.inner.chunk_size.lock();
        let truncate_at = *self.inner.truncate_after.lock();
        let total = bytes.len() as u64;
        let mut written: u64 = 0;
        for chunk in bytes.chunks(chunk_size) {
            if let Some(tr) = truncate_at
                && written.saturating_add(chunk.len() as u64) > tr
            {
                // The truncation budget is capped by
                // `truncate_after` (test-supplied) so the
                // remaining-bytes value is always within
                // `usize::MAX` on any platform we ship
                // to; the cast is defensive and never
                // truncates in practice. We use
                // `try_from` to make the bound explicit.
                let take = usize::try_from(tr.saturating_sub(written)).unwrap_or(usize::MAX);
                if take > 0 {
                    sink.write_chunk(&chunk[..take]).await?;
                    written += take as u64;
                }
                return Err(DownloadError::Truncated {
                    expected: declared_size,
                    read: written,
                });
            }
            sink.write_chunk(chunk).await?;
            written += chunk.len() as u64;
        }
        // If the payload-registered bytes are shorter than
        // the manifest claims, surface a `Truncated` rather
        // than a successful download — the orchestrator
        // expects the downloader to enforce "received exactly
        // the bytes the manifest claimed" as part of its
        // contract.
        if total < declared_size {
            return Err(DownloadError::Truncated {
                expected: declared_size,
                read: total,
            });
        }
        Ok(())
    }
}

fn map_hasher_error(e: UpdaterError) -> DownloadError {
    match e {
        UpdaterError::ImageSizeExceeded { claimed, read } => DownloadError::SizeExceeded {
            claimed,
            attempted: read,
        },
        other => DownloadError::Transport(format!("hasher rejected chunk: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ImageVersion, ReleaseChannel, UpdateTarget};
    use pretty_assertions::assert_eq;
    use sha2::Digest;

    fn fixture_manifest(payload_len: u64) -> UpdateManifest {
        let mut hasher = Sha256::new();
        hasher.update(vec![0xAA_u8; payload_len as usize]);
        let mut sha = [0_u8; 32];
        sha.copy_from_slice(&hasher.finalize());
        UpdateManifest {
            schema_version: 1,
            target: UpdateTarget::Edge,
            channel: ReleaseChannel::Stable,
            version: ImageVersion::new(2, 0, 0),
            image_sha256: ImageHash::new(sha),
            image_size_bytes: payload_len,
            image_url: Url::parse("https://x.invalid/img").expect("url"),
            release_notes: String::new(),
            signed_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn streaming_hasher_matches_one_shot_sha256() {
        let payload = vec![0x33_u8; 4096];
        let mut sh = StreamingHasher::new(payload.len() as u64);
        sh.write_chunk(&payload[..1500]).expect("chunk 1");
        sh.write_chunk(&payload[1500..]).expect("chunk 2");
        let receipt = sh.finalise();
        let mut oneshot = Sha256::new();
        oneshot.update(&payload);
        let mut expected = [0_u8; 32];
        expected.copy_from_slice(&oneshot.finalize());
        assert_eq!(receipt.sha256, ImageHash::new(expected));
        assert_eq!(receipt.size_bytes, payload.len() as u64);
    }

    #[test]
    fn streaming_hasher_rejects_size_overflow() {
        let mut sh = StreamingHasher::new(100);
        sh.write_chunk(&[0_u8; 50]).expect("first 50");
        sh.write_chunk(&[0_u8; 50]).expect("second 50");
        let err = sh.write_chunk(&[0_u8; 1]).expect_err("overflow");
        match err {
            UpdaterError::ImageSizeExceeded { claimed, read } => {
                assert_eq!(claimed, 100);
                assert_eq!(read, 101);
            }
            other => panic!("expected ImageSizeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn streaming_hasher_allows_exactly_max_size() {
        let mut sh = StreamingHasher::new(100);
        sh.write_chunk(&[0_u8; 100]).expect("exactly max");
        assert_eq!(sh.size_read(), 100);
    }

    #[tokio::test]
    async fn in_memory_downloader_streams_payload_through_hasher_sink() {
        let mfst = fixture_manifest(2048);
        let payload = vec![0xAA_u8; 2048];
        let dl = InMemoryDownloader::new();
        dl.register_for_manifest(&mfst, payload.clone());
        let mut sh = StreamingHasher::new(mfst.image_size_bytes);
        dl.download(&mfst.image_url, mfst.image_size_bytes, &mut sh)
            .await
            .expect("ok");
        let receipt = sh.finalise();
        assert_eq!(receipt.size_bytes, 2048);
        assert_eq!(receipt.sha256, mfst.image_sha256);
        assert_eq!(dl.call_count(), 1);
    }

    #[tokio::test]
    async fn in_memory_downloader_surfaces_404_for_unregistered_url() {
        let dl = InMemoryDownloader::new();
        let mut sh = StreamingHasher::new(10);
        let err = dl
            .download(
                &Url::parse("https://nope.invalid/x").expect("url"),
                10,
                &mut sh,
            )
            .await
            .expect_err("404");
        assert!(matches!(err, DownloadError::Status(_)));
    }

    #[tokio::test]
    async fn in_memory_downloader_surfaces_forced_failure() {
        let dl = InMemoryDownloader::new();
        dl.force_failure(Some(DownloadError::Transport("tls fail".into())));
        let mut sh = StreamingHasher::new(10);
        let err = dl
            .download(
                &Url::parse("https://x.invalid/y").expect("url"),
                10,
                &mut sh,
            )
            .await
            .expect_err("forced");
        assert!(matches!(err, DownloadError::Transport(_)));
    }

    #[tokio::test]
    async fn in_memory_downloader_surfaces_truncation_when_payload_short() {
        let mfst = fixture_manifest(2048);
        // Payload-registered bytes are SHORTER than the
        // manifest claims.
        let dl = InMemoryDownloader::new();
        dl.register(&mfst.image_url, vec![0xAA_u8; 1024]);
        let mut sh = StreamingHasher::new(mfst.image_size_bytes);
        let err = dl
            .download(&mfst.image_url, mfst.image_size_bytes, &mut sh)
            .await
            .expect_err("trunc");
        match err {
            DownloadError::Truncated { expected, read } => {
                assert_eq!(expected, 2048);
                assert_eq!(read, 1024);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_memory_downloader_force_truncation_surfaces_short_read() {
        let mfst = fixture_manifest(2048);
        let dl = InMemoryDownloader::new();
        dl.register(&mfst.image_url, vec![0xAA_u8; 2048]);
        dl.force_truncation_after(Some(1000));
        let mut sh = StreamingHasher::new(mfst.image_size_bytes);
        let err = dl
            .download(&mfst.image_url, mfst.image_size_bytes, &mut sh)
            .await
            .expect_err("trunc");
        match err {
            DownloadError::Truncated { expected, read } => {
                assert_eq!(expected, 2048);
                assert_eq!(read, 1000);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sink_size_overflow_surfaces_size_exceeded() {
        // Register a 4096-byte payload but tell the hasher
        // only 1024 bytes are expected. The sink refuses on
        // the chunk that crosses 1024.
        let dl = InMemoryDownloader::new();
        let url = Url::parse("https://x.invalid/overflow").expect("url");
        dl.register(&url, vec![0xAA_u8; 4096]);
        dl.set_chunk_size(256);
        let mut sh = StreamingHasher::new(1024);
        let err = dl
            .download(&url, 4096, &mut sh)
            .await
            .expect_err("overflow");
        match err {
            DownloadError::SizeExceeded { claimed, attempted } => {
                assert_eq!(claimed, 1024);
                assert!(attempted > 1024);
            }
            other => panic!("expected SizeExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn small_chunk_size_streams_full_payload() {
        let mfst = fixture_manifest(512);
        let dl = InMemoryDownloader::new();
        dl.register(&mfst.image_url, vec![0xAA_u8; 512]);
        dl.set_chunk_size(7); // weird chunk size — exercises boundary
        let mut sh = StreamingHasher::new(512);
        dl.download(&mfst.image_url, 512, &mut sh)
            .await
            .expect("ok");
        let receipt = sh.finalise();
        assert_eq!(receipt.size_bytes, 512);
        assert_eq!(receipt.sha256, mfst.image_sha256);
    }

    #[tokio::test]
    async fn shared_handle_reflects_call_counts() {
        let dl = InMemoryDownloader::new();
        let url = Url::parse("https://x.invalid/y").expect("url");
        dl.register(&url, vec![0xAA_u8; 16]);
        let handle = dl.handle();
        let mut sh = StreamingHasher::new(16);
        handle.download(&url, 16, &mut sh).await.expect("ok");
        assert_eq!(dl.call_count(), 1);
        assert_eq!(handle.call_count(), 1);
    }

    #[tokio::test]
    async fn tee_chunk_sink_mirrors_to_hasher_and_bank() {
        use crate::bank::{Bank, BankWriter, InMemoryBankWriter};
        let mfst = fixture_manifest(256);
        let dl = InMemoryDownloader::new();
        dl.register(&mfst.image_url, vec![0xAA_u8; 256]);
        let writer = InMemoryBankWriter::cold_start();
        let mut handle = writer.open_for_write(Bank::B).await.expect("open");
        let mut hasher = StreamingHasher::new(256);
        {
            let mut tee = TeeChunkSink::new(&mut hasher, &mut handle);
            dl.download(&mfst.image_url, 256, &mut tee)
                .await
                .expect("ok");
        }
        let outcome = handle.finish(mfst.version).await.expect("finish");
        assert_eq!(outcome.bytes_written, 256);
        let receipt = hasher.finalise();
        assert_eq!(receipt.sha256, mfst.image_sha256);
    }
}
