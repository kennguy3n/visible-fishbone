//! Connection-table state sync from the active edge to the
//! passive one.
//!
//! While the active instance holds the VIP it streams the
//! flow-affecting state the passive would otherwise lose on a
//! failover — conntrack 5-tuples + their NAT mappings, ZTNA
//! sessions, and SD-WAN per-path scores — over a dedicated TCP
//! channel. Records are MessagePack-framed, matching the
//! control-plane wire codec (`rmp-serde`), so the same tooling
//! that decodes a telemetry envelope decodes a sync record.
//!
//! The sync is explicitly **best-effort and non-blocking on the
//! active**. The active enqueues into a bounded [`SyncQueue`];
//! if the passive falls behind and the queue fills, the oldest
//! records are evicted and a `lagged` flag is latched. On
//! promotion the passive consults that flag (surfaced to it via
//! the protocol as a [`SyncRecord::Lagged`] marker the active
//! emits on eviction) and does a full-state pull instead of
//! trusting its partial table. This keeps a slow or wedged
//! passive from ever back-pressuring the data-plane-critical
//! active.
//!
//! The wire framing ([`encode_frame`] / [`read_frame`]) and the
//! queue are pure and unit-tested; the pump loops
//! ([`pump_to_writer`] / [`pump_from_reader`]) are generic over
//! [`tokio::io::AsyncRead`] / [`AsyncWrite`] so tests exercise
//! them over an in-memory [`tokio::io::duplex`] pipe without a
//! real socket.

use crate::error::{HaError, HaResult};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard ceiling on a single decoded frame. A peer (or on-wire
/// corruption) announcing a larger frame is rejected before the
/// receive buffer is allocated, so a bogus length prefix cannot
/// drive an unbounded allocation.
pub const MAX_FRAME_LEN: usize = 1 << 20; // 1 MiB

/// Default bound on the in-memory sync queue. Sized so a burst
/// of new flows during a brief passive stall is absorbed without
/// eviction, while still capping the active's memory footprint.
pub const DEFAULT_QUEUE_CAPACITY: usize = 8192;

/// One connection 5-tuple plus its NAT translation, if any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConntrackEntry {
    /// Original source address.
    pub src_ip: IpAddr,
    /// Original destination address.
    pub dst_ip: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Post-NAT source address/port, when the flow is NATed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_src: Option<(IpAddr, u16)>,
}

/// A live ZTNA session the passive must inherit so an in-flight
/// per-app tunnel survives failover without a re-auth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaSessionState {
    /// Opaque session id (matches the broker's session key).
    pub session_id: String,
    /// Device the session is bound to.
    pub device_id: String,
    /// Application id the session grants access to.
    pub app_id: String,
    /// Unix-epoch-seconds expiry; the passive drops it if past.
    pub expires_at_unix: u64,
}

/// The most recent SD-WAN score for one path so the passive
/// makes the same steering choice immediately on promotion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SdwanPathScoreState {
    /// Path identifier (matches `sng_sdwan::PathId`).
    pub path_id: String,
    /// Composite score (lower is better).
    pub score: f32,
    /// Observation time in unix-epoch-millis.
    pub observed_at_unix_ms: u64,
}

/// A unit of state synced from active to passive.
///
/// Externally tagged (the serde default) rather than internally
/// tagged: an internally-tagged enum buffers each record through
/// serde's `Content` type, and that buffering path drops the
/// `is_human_readable() == false` flag the MessagePack codec
/// sets — which makes a nested [`IpAddr`] (serialized as a
/// non-human-readable enum, i.e. a map) fail to decode against
/// the human-readable string representation. External tagging
/// deserializes each variant straight from the wire and keeps
/// the flag intact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRecord {
    /// A conntrack flow.
    Conntrack(ConntrackEntry),
    /// A ZTNA session.
    ZtnaSession(ZtnaSessionState),
    /// An SD-WAN path score.
    SdwanPathScore(SdwanPathScoreState),
    /// Sentinel the active emits when it had to evict records:
    /// it tells the passive its view is incomplete and it must
    /// do a full-state pull when it next promotes.
    Lagged,
    /// Fencing marker the active emits at the head of every flush,
    /// carrying its current Master epoch (a monotonic generation
    /// number bumped on each promotion). The receiver admits the
    /// stream only while the epoch is `>=` the highest it has seen;
    /// a lower epoch identifies a deposed Master and the receiver
    /// fences (refuses) the rest of that stream. This is what stops
    /// a stale Master that has not yet realised it lost the
    /// election from replaying old state over the live table — the
    /// split-brain write the [`crate::error::HaError::Fenced`]
    /// variant guards against.
    Fence {
        /// The sender's current Master epoch.
        epoch: u64,
    },
}

/// Receiver-side fencing gate.
///
/// Tracks the highest Master epoch observed on the sync stream and
/// admits records only while the announced epoch keeps up with it.
/// A peer announcing a strictly-older epoch is a deposed Master; its
/// writes are fenced so they cannot clobber post-failover state.
///
/// The epoch monotonically increases via [`Self::admit`]; once a
/// higher epoch is seen, every later record claiming a lower one is
/// rejected for the life of the process.
///
/// The high-water mark and the "have we been primed yet?" flag are
/// packed into a single [`AtomicU64`] (`stored = epoch + 1`, with `0`
/// reserved as the unprimed sentinel) so a single load/CAS observes
/// both atomically. Keeping them in one word closes the TOCTOU window
/// a separate `current`/`admitted` pair would expose, where a
/// concurrent caller could see an advanced epoch while the primed flag
/// still read false and thereby skip the staleness check.
#[derive(Debug, Default)]
pub struct FenceState {
    /// `0` = unprimed; otherwise the admitted epoch biased by `+1`.
    state: AtomicU64,
}

/// Decode the packed gate word into `(primed, high_water_epoch)`.
const fn decode_fence(stored: u64) -> (bool, u64) {
    if stored == 0 {
        (false, 0)
    } else {
        (true, stored - 1)
    }
}

impl FenceState {
    /// A fresh gate that has not yet observed any epoch. The first
    /// [`Fence`](SyncRecord::Fence) seen is always admitted and
    /// becomes the baseline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Highest epoch admitted so far (0 before the first fence).
    #[must_use]
    pub fn current(&self) -> u64 {
        decode_fence(self.state.load(Ordering::Acquire)).1
    }

    /// True once at least one fence has been admitted, i.e. the
    /// receiver knows which Master generation it is following.
    #[must_use]
    pub fn is_primed(&self) -> bool {
        decode_fence(self.state.load(Ordering::Acquire)).0
    }

    /// Offer an epoch to the gate.
    ///
    /// Returns `true` and adopts the epoch when it is `>=` the
    /// current high-water mark (a same-or-newer Master); returns
    /// `false` without changing state when it is strictly older (a
    /// stale Master that must be fenced).
    pub fn admit(&self, epoch: u64) -> bool {
        // Single-writer-per-stream in practice (one reader task per
        // peer connection), but use a CAS loop so the gate is sound
        // even if shared. Because primed+epoch live in one word, the
        // staleness check and the advance are based on one consistent
        // snapshot — there is no window where a stale epoch slips past
        // because the primed flag has not caught up yet.
        loop {
            let cur = self.state.load(Ordering::Acquire);
            let (primed, cur_epoch) = decode_fence(cur);
            if primed && epoch < cur_epoch {
                return false;
            }
            // Bias by +1 so any admitted epoch (including 0) is a
            // non-zero "primed" word. saturating_add mirrors the
            // promotion-side epoch mint: at the u64 ceiling the gate
            // stops distinguishing the top two epochs, which is
            // astronomically out of reach in practice.
            let next = epoch.max(cur_epoch).saturating_add(1);
            if self
                .state
                .compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// Snapshot of [`SyncQueue`] counters for the health detail line.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncQueueStats {
    /// Total records pushed.
    pub pushed: u64,
    /// Records evicted because the queue was full.
    pub evicted: u64,
    /// Records drained for transmission.
    pub drained: u64,
    /// Current depth.
    pub depth: usize,
    /// Whether the queue has ever lagged (latched).
    pub lagged: bool,
}

/// Bounded, lock-guarded FIFO of pending sync records.
///
/// `push` never blocks: on a full queue it evicts the oldest
/// record and latches [`Self::is_lagged`], so the active's
/// enqueue path is wait-free with respect to a slow passive.
#[derive(Debug)]
pub struct SyncQueue {
    inner: Mutex<VecDeque<SyncRecord>>,
    capacity: usize,
    lagged: AtomicBool,
    pushed: AtomicU64,
    evicted: AtomicU64,
    drained: AtomicU64,
}

impl SyncQueue {
    /// Create a queue bounded to `capacity` records.
    ///
    /// A zero capacity is clamped to 1 so the structure always
    /// holds at least the most recent record.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
            lagged: AtomicBool::new(false),
            pushed: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            drained: AtomicU64::new(0),
        }
    }

    /// Enqueue one record. Evicts the oldest and latches the
    /// lagged flag if the queue is already at capacity.
    pub fn push(&self, record: SyncRecord) {
        self.pushed.fetch_add(1, Ordering::Relaxed);
        let mut q = self.inner.lock();
        if q.len() >= self.capacity {
            q.pop_front();
            self.evicted.fetch_add(1, Ordering::Relaxed);
            self.lagged.store(true, Ordering::Release);
        }
        q.push_back(record);
    }

    /// Drain up to `max` records in FIFO order for transmission.
    pub fn drain(&self, max: usize) -> Vec<SyncRecord> {
        let mut q = self.inner.lock();
        let n = q.len().min(max);
        let drained: Vec<SyncRecord> = q.drain(..n).collect();
        drop(q);
        self.drained
            .fetch_add(drained.len() as u64, Ordering::Relaxed);
        drained
        // NOTE: `drained.len() as u64` widens usize -> u64 on every
        // target the workspace builds for (see deny.toml `graph`),
        // so it cannot truncate.
    }

    /// Atomically drain up to `max` records *and* take (read-and-clear)
    /// the lagged latch in a single lock acquisition.
    ///
    /// Returns `(was_lagged, records)`. Because [`push`](Self::push)
    /// also sets the latch while holding this same lock, taking it
    /// here closes the read-then-clear race that
    /// `drain` + `is_lagged` + `reset_lagged` had: an eviction that
    /// happens concurrently is either observed by this call (and so
    /// delivered to the passive) or lands after the lock is released
    /// (so the latch stays set for the next flush). Either way the
    /// lag signal is never silently dropped.
    pub fn drain_with_lag(&self, max: usize) -> (bool, Vec<SyncRecord>) {
        let mut q = self.inner.lock();
        let lagged = self.lagged.swap(false, Ordering::AcqRel);
        let n = q.len().min(max);
        let drained: Vec<SyncRecord> = q.drain(..n).collect();
        drop(q);
        self.drained
            .fetch_add(drained.len() as u64, Ordering::Relaxed);
        (lagged, drained)
    }

    /// Re-arm the lagged latch (used to put back a signal that was
    /// taken by [`drain_with_lag`](Self::drain_with_lag) but could
    /// not be delivered because there was nothing else to flush).
    pub fn mark_lagged(&self) {
        self.lagged.store(true, Ordering::Release);
    }

    /// Current queue depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the queue has ever evicted (i.e. the passive's
    /// view is known-incomplete). Latched until [`Self::reset_lagged`].
    #[must_use]
    pub fn is_lagged(&self) -> bool {
        self.lagged.load(Ordering::Acquire)
    }

    /// Clear the lagged latch. The passive calls this after it
    /// completes a full-state pull on promotion.
    pub fn reset_lagged(&self) {
        self.lagged.store(false, Ordering::Release);
    }

    /// Counter snapshot.
    #[must_use]
    pub fn stats(&self) -> SyncQueueStats {
        SyncQueueStats {
            pushed: self.pushed.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            drained: self.drained.load(Ordering::Relaxed),
            depth: self.depth(),
            lagged: self.is_lagged(),
        }
    }
}

/// Encode one record as a length-prefixed MessagePack frame:
/// a big-endian `u32` byte length followed by the `rmp-serde`
/// body.
///
/// # Errors
///
/// Returns [`HaError::Encode`] if serialization fails or
/// [`HaError::FrameTooLarge`] if the body exceeds [`MAX_FRAME_LEN`].
pub fn encode_frame(record: &SyncRecord) -> HaResult<Vec<u8>> {
    let body = rmp_serde::to_vec_named(record).map_err(|e| HaError::Encode(e.to_string()))?;
    // `u32::try_from` doubles as the frame-size guard: any body
    // that does not fit a u32 length prefix is by definition
    // larger than the 1 MiB ceiling, so map both the overflow and
    // the over-ceiling case onto `FrameTooLarge`.
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= MAX_FRAME_LEN)
        .ok_or(HaError::FrameTooLarge {
            len: body.len(),
            max: MAX_FRAME_LEN,
        })?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode one length-prefixed frame from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at a frame boundary (the
/// peer closed the channel between frames).
///
/// # Errors
///
/// Returns [`HaError::FrameTooLarge`] for an oversized length
/// prefix, [`HaError::Socket`] for an I/O error or a truncated
/// frame, and [`HaError::Decode`] for a malformed body.
pub async fn read_frame<R>(reader: &mut R) -> HaResult<Option<SyncRecord>>
where
    R: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(HaError::Socket(format!("read length: {e}"))),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(HaError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|e| HaError::Socket(format!("read body ({len} bytes): {e}")))?;
    let record = rmp_serde::from_slice(&body).map_err(|e| HaError::Decode(e.to_string()))?;
    Ok(Some(record))
}

/// Applies received records to the passive's local tables. The
/// real edge wires this onto the conntrack / ZTNA / SD-WAN
/// subsystems; tests use [`StaticStateApplier`].
#[async_trait]
pub trait StateApplier: Send + Sync + std::fmt::Debug {
    /// Apply one received record. A `Lagged` marker tells the
    /// applier its view is incomplete; the controller acts on it
    /// at promotion time.
    async fn apply(&self, record: SyncRecord) -> HaResult<()>;
}

/// Test double that records every applied record in order.
#[derive(Clone, Debug, Default)]
pub struct StaticStateApplier {
    applied: Arc<Mutex<Vec<SyncRecord>>>,
}

impl StaticStateApplier {
    /// Empty applier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of everything applied so far.
    #[must_use]
    pub fn applied(&self) -> Vec<SyncRecord> {
        self.applied.lock().clone()
    }
}

#[async_trait]
impl StateApplier for StaticStateApplier {
    async fn apply(&self, record: SyncRecord) -> HaResult<()> {
        self.applied.lock().push(record);
        Ok(())
    }
}

/// Drain the queue and write every record to `writer`, stamping the
/// batch with the active's current Master `epoch`.
///
/// A [`SyncRecord::Fence`] carrying `epoch` is emitted at the head of
/// every non-empty flush so the receiver can fence a deposed Master
/// (see [`FenceState`]). A [`SyncRecord::Lagged`] marker follows it
/// whenever the queue has lagged since the last flush, so the passive
/// also learns its view is incomplete. Returns the number of
/// flow-state records written (the fence and lagged markers are not
/// counted).
///
/// # Errors
///
/// Returns [`HaError::Encode`] / [`HaError::Socket`] on a frame
/// encode or write failure.
pub async fn pump_to_writer<W>(
    queue: &SyncQueue,
    writer: &mut W,
    batch: usize,
    epoch: u64,
) -> HaResult<usize>
where
    W: AsyncWrite + Unpin + Send,
{
    // Take the lagged latch together with the batch under one lock,
    // so a concurrent eviction can never have its lag signal cleared
    // without being delivered.
    let (lagged, records) = queue.drain_with_lag(batch);
    if records.is_empty() {
        // Nothing to flush. If we took a lag signal anyway, put it
        // back so the next non-empty flush carries the marker instead
        // of dropping it on the floor.
        if lagged {
            queue.mark_lagged();
        }
        return Ok(0);
    }
    // The records are now out of the queue and the lag latch has been
    // consumed. If any encode/write/flush below fails, this whole
    // batch is lost — so on error re-arm the lag latch before
    // propagating, exactly as the empty-flush path does. That way the
    // next successful flush carries a Lagged marker and the passive
    // does a full-state pull on promotion instead of silently running
    // on an incomplete view. (The lost records themselves are not
    // recoverable, which is fine for best-effort sync; the contract we
    // must keep is that the passive *knows* it is incomplete.)
    let result = async {
        let mut written = 0usize;
        // Fence first: the receiver must learn (and accept) our epoch
        // before it applies any record in this batch.
        let fence = encode_frame(&SyncRecord::Fence { epoch })?;
        writer
            .write_all(&fence)
            .await
            .map_err(|e| HaError::Socket(format!("write fence marker: {e}")))?;
        if lagged {
            let frame = encode_frame(&SyncRecord::Lagged)?;
            writer
                .write_all(&frame)
                .await
                .map_err(|e| HaError::Socket(format!("write lagged marker: {e}")))?;
        }
        for record in &records {
            let frame = encode_frame(record)?;
            writer
                .write_all(&frame)
                .await
                .map_err(|e| HaError::Socket(format!("write record: {e}")))?;
            written += 1;
        }
        writer
            .flush()
            .await
            .map_err(|e| HaError::Socket(format!("flush: {e}")))?;
        Ok::<usize, HaError>(written)
    }
    .await;
    match result {
        Ok(written) => Ok(written),
        Err(e) => {
            queue.mark_lagged();
            Err(e)
        }
    }
}

/// Read frames from `reader` until EOF, applying each flow-state
/// record to `applier` while enforcing the fencing epoch in `fence`.
///
/// A [`SyncRecord::Fence`] is consumed by the gate, never handed to
/// the applier: an admissible epoch (same or newer Master) advances
/// the high-water mark; a strictly-older epoch fails fast with
/// [`HaError::Fenced`] so the caller tears down the deposed Master's
/// session before any of its records reach the table. Flow-state
/// records that arrive before the stream has been primed by a fence
/// are also refused — a peer must identify its generation before it
/// is allowed to write. Returns the number of flow-state records
/// applied: the [`SyncRecord::Lagged`] marker is still delivered to
/// the applier (it carries the lag signal) but is a control marker,
/// not flow state, so it is excluded from the count, and the fence is
/// neither applied nor counted.
///
/// # Errors
///
/// Returns [`HaError::Fenced`] for a stale-Master epoch or an
/// unprimed stream, and propagates [`read_frame`] errors and any
/// error returned by the applier.
pub async fn pump_from_reader<R, A>(
    reader: &mut R,
    applier: &A,
    fence: &FenceState,
) -> HaResult<usize>
where
    R: AsyncRead + Unpin + Send,
    A: StateApplier + ?Sized,
{
    let mut count = 0;
    while let Some(record) = read_frame(reader).await? {
        if let SyncRecord::Fence { epoch } = record {
            if !fence.admit(epoch) {
                return Err(HaError::Fenced {
                    incoming: epoch,
                    current: fence.current(),
                });
            }
            // The fence is a control marker, not flow state: it
            // gates the stream but is never applied.
            continue;
        }
        // Refuse any flow-state record from a peer that has not yet
        // identified its Master generation with a fence. This closes
        // the gap where a stale Master could omit the fence entirely
        // to dodge the epoch check.
        if !fence.is_primed() {
            return Err(HaError::Fenced {
                incoming: 0,
                current: fence.current(),
            });
        }
        // Lagged is a control marker (it signals an incomplete view),
        // not flow state: deliver it to the applier but do not count
        // it among the flow-state records, matching the return-value
        // contract above.
        let is_flow_state = !matches!(record, SyncRecord::Lagged);
        applier.apply(record).await?;
        if is_flow_state {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// An [`AsyncWrite`] that fails every write, used to exercise the
    /// pump's mid-flush failure handling.
    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "boom",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn conntrack(port: u16) -> SyncRecord {
        SyncRecord::Conntrack(ConntrackEntry {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: port,
            dst_port: 443,
            protocol: 6,
            nat_src: Some((IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 51000)),
        })
    }

    #[test]
    fn queue_evicts_oldest_and_latches_lagged() {
        let q = SyncQueue::new(2);
        q.push(conntrack(1));
        q.push(conntrack(2));
        assert!(!q.is_lagged());
        q.push(conntrack(3)); // evicts port 1
        assert!(q.is_lagged());
        assert_eq!(q.depth(), 2);
        let drained = q.drain(10);
        assert_eq!(drained, vec![conntrack(2), conntrack(3)]);
        let stats = q.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.evicted, 1);
        assert_eq!(stats.drained, 2);
    }

    #[test]
    fn queue_zero_capacity_clamped_to_one() {
        let q = SyncQueue::new(0);
        q.push(conntrack(1));
        q.push(conntrack(2));
        assert_eq!(q.depth(), 1);
        assert!(q.is_lagged());
    }

    #[test]
    fn reset_lagged_clears_latch() {
        let q = SyncQueue::new(1);
        q.push(conntrack(1));
        q.push(conntrack(2));
        assert!(q.is_lagged());
        q.reset_lagged();
        assert!(!q.is_lagged());
    }

    #[test]
    fn frame_round_trips_for_every_variant() {
        let records = vec![
            conntrack(7),
            SyncRecord::ZtnaSession(ZtnaSessionState {
                session_id: "s1".into(),
                device_id: "d1".into(),
                app_id: "app".into(),
                expires_at_unix: 123,
            }),
            SyncRecord::SdwanPathScore(SdwanPathScoreState {
                path_id: "mpls".into(),
                score: 12.5,
                observed_at_unix_ms: 999,
            }),
            SyncRecord::Lagged,
        ];
        for r in records {
            let frame = encode_frame(&r).expect("encode");
            // length prefix + body
            assert!(frame.len() > 4);
            let body_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
            assert_eq!(body_len, frame.len() - 4);
        }
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server); // close immediately
        let got = read_frame(&mut client).await.expect("read");
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let bogus =
            (u32::try_from(MAX_FRAME_LEN).expect("MAX_FRAME_LEN fits u32") + 1).to_be_bytes();
        server.write_all(&bogus).await.expect("write");
        server.flush().await.expect("flush");
        let err = read_frame(&mut client).await.expect_err("should reject");
        assert!(matches!(err, HaError::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn pump_round_trip_over_duplex_applies_all_records() {
        let q = SyncQueue::new(8);
        q.push(conntrack(1));
        q.push(conntrack(2));
        q.push(conntrack(3));

        let (mut active, mut passive) = tokio::io::duplex(4096);
        let written = pump_to_writer(&q, &mut active, 16, 1).await.expect("pump");
        assert_eq!(written, 3);
        // Close the writer so the reader sees EOF after the batch.
        active.shutdown().await.expect("shutdown");

        let applier = StaticStateApplier::new();
        let fence = FenceState::new();
        let count = pump_from_reader(&mut passive, &applier, &fence)
            .await
            .expect("pump from");
        assert_eq!(count, 3);
        assert_eq!(
            applier.applied(),
            vec![conntrack(1), conntrack(2), conntrack(3)]
        );
    }

    #[tokio::test]
    async fn pump_emits_lagged_marker_when_queue_lagged() {
        let q = SyncQueue::new(1);
        q.push(conntrack(1));
        q.push(conntrack(2)); // evicts -> lagged latched, depth 1

        let (mut active, mut passive) = tokio::io::duplex(4096);
        let written = pump_to_writer(&q, &mut active, 16, 1).await.expect("pump");
        assert_eq!(written, 1);
        active.shutdown().await.expect("shutdown");
        assert!(!q.is_lagged(), "marker emission resets the latch");

        let applier = StaticStateApplier::new();
        let fence = FenceState::new();
        let count = pump_from_reader(&mut passive, &applier, &fence)
            .await
            .expect("pump from");
        let records = applier.applied();
        assert_eq!(records.first(), Some(&SyncRecord::Lagged));
        assert_eq!(records.len(), 2);
        // The Lagged control marker is delivered to the applier but
        // is NOT counted among the flow-state records: only the one
        // conntrack entry counts.
        assert_eq!(count, 1);
    }

    #[test]
    fn drain_with_lag_takes_latch_atomically() {
        let q = SyncQueue::new(1);
        q.push(conntrack(1));
        q.push(conntrack(2)); // evicts -> lagged latched
        let (lagged, records) = q.drain_with_lag(16);
        assert!(lagged, "should report the latched lag");
        assert_eq!(records, vec![conntrack(2)]);
        assert!(!q.is_lagged(), "latch consumed by drain_with_lag");
        // A second take sees no lag and no records.
        let (lagged2, records2) = q.drain_with_lag(16);
        assert!(!lagged2);
        assert!(records2.is_empty());
    }

    #[tokio::test]
    async fn pump_rearms_lag_signal_when_nothing_to_flush() {
        // Lag is latched but the records were already drained
        // elsewhere, so this flush has nothing to send. The signal
        // must be preserved for the next non-empty flush, not lost.
        let q = SyncQueue::new(1);
        q.push(conntrack(1));
        q.push(conntrack(2)); // evicts -> lagged latched
        let _ = q.drain(16); // drain records but leave the latch set
        assert!(q.is_lagged());

        let (mut active, _passive) = tokio::io::duplex(4096);
        let written = pump_to_writer(&q, &mut active, 16, 1).await.expect("pump");
        assert_eq!(written, 0);
        assert!(
            q.is_lagged(),
            "an undeliverable lag signal must be re-armed, not dropped"
        );
    }

    #[tokio::test]
    async fn pump_rearms_lag_when_write_fails_mid_flush() {
        // A lagged batch is drained (records + latch leave the queue),
        // but the write fails. The records are lost, but the lag latch
        // must be re-armed so the next flush still tells the passive
        // its view is incomplete.
        let q = SyncQueue::new(1);
        q.push(conntrack(1));
        q.push(conntrack(2)); // evicts -> lagged latched, depth 1
        assert!(q.is_lagged());

        let mut writer = FailingWriter;
        let err = pump_to_writer(&q, &mut writer, 16, 1)
            .await
            .expect_err("write must fail");
        assert!(matches!(err, HaError::Socket(_)), "got {err:?}");
        assert!(
            q.is_lagged(),
            "a failed flush must re-arm the lag latch so the passive learns it is incomplete"
        );
    }

    #[test]
    fn fence_admits_monotonic_and_rejects_stale() {
        let f = FenceState::new();
        assert!(!f.is_primed());
        assert_eq!(f.current(), 0);
        // First fence of any value is the baseline.
        assert!(f.admit(5));
        assert!(f.is_primed());
        assert_eq!(f.current(), 5);
        // Same epoch is admissible (a re-flush of the live Master).
        assert!(f.admit(5));
        // A newer Master advances the high-water mark.
        assert!(f.admit(7));
        assert_eq!(f.current(), 7);
        // A deposed Master (lower epoch) is fenced and does not
        // lower the mark.
        assert!(!f.admit(6));
        assert_eq!(f.current(), 7);
    }

    #[test]
    fn fence_admits_zero_epoch_as_baseline() {
        // Epoch 0 is a legitimate first generation: the packed-word
        // encoding must treat admitting 0 as priming the gate, not as
        // "still unprimed".
        let f = FenceState::new();
        assert!(f.admit(0));
        assert!(f.is_primed());
        assert_eq!(f.current(), 0);
        // Re-admitting the same epoch 0 is fine; a strictly-older
        // epoch is impossible below 0, so 0 stays the floor.
        assert!(f.admit(0));
        assert!(f.admit(1));
        assert_eq!(f.current(), 1);
    }

    #[tokio::test]
    async fn pump_fences_stale_master_stream() {
        // The receiver has already followed Master epoch 9.
        let fence = FenceState::new();
        assert!(fence.admit(9));

        // A deposed Master (epoch 3) tries to replay flow state.
        let q = SyncQueue::new(8);
        q.push(conntrack(1));
        q.push(conntrack(2));
        let (mut active, mut passive) = tokio::io::duplex(4096);
        let written = pump_to_writer(&q, &mut active, 16, 3).await.expect("pump");
        assert_eq!(written, 2);
        active.shutdown().await.expect("shutdown");

        let applier = StaticStateApplier::new();
        let err = pump_from_reader(&mut passive, &applier, &fence)
            .await
            .expect_err("stale master must be fenced");
        assert!(matches!(
            err,
            HaError::Fenced {
                incoming: 3,
                current: 9
            }
        ));
        // Crucially, NOTHING from the stale Master was applied: the
        // fence is checked before any record reaches the table.
        assert!(
            applier.applied().is_empty(),
            "fenced stream must not write a single record"
        );
    }

    #[tokio::test]
    async fn pump_refuses_flow_state_before_any_fence() {
        // Hand-craft a stream that omits the leading fence entirely
        // (a malformed / hostile peer trying to dodge the epoch
        // check) and confirm the first flow-state record is refused.
        let frame = encode_frame(&conntrack(1)).expect("encode");
        let (mut active, mut passive) = tokio::io::duplex(4096);
        active.write_all(&frame).await.expect("write");
        active.shutdown().await.expect("shutdown");

        let applier = StaticStateApplier::new();
        let fence = FenceState::new();
        let err = pump_from_reader(&mut passive, &applier, &fence)
            .await
            .expect_err("unprimed stream must be fenced");
        assert!(matches!(err, HaError::Fenced { incoming: 0, .. }));
        assert!(applier.applied().is_empty());
    }

    #[tokio::test]
    async fn pump_admits_newer_master_after_failover() {
        // Receiver was following epoch 1; the new Master (epoch 2)
        // takes over and its stream is admitted.
        let fence = FenceState::new();
        assert!(fence.admit(1));

        let q = SyncQueue::new(8);
        q.push(conntrack(1));
        let (mut active, mut passive) = tokio::io::duplex(4096);
        pump_to_writer(&q, &mut active, 16, 2).await.expect("pump");
        active.shutdown().await.expect("shutdown");

        let applier = StaticStateApplier::new();
        let count = pump_from_reader(&mut passive, &applier, &fence)
            .await
            .expect("newer master admitted");
        assert_eq!(count, 1);
        assert_eq!(fence.current(), 2);
    }
}
