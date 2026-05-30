//! Local PCAP ring buffer for forensic re-hydration.
//!
//! Per ARCHITECTURE.md §4.8, the telemetry collector retains a
//! short local PCAP ring so an operator can pull the raw packet
//! capture that backs a flagged telemetry event without having
//! to enable a full-stack capture out-of-band.
//!
//! Design choices:
//!
//! * Bounded. Two budgets — a packet-count cap and a
//!   total-bytes cap — apply simultaneously; whichever is hit
//!   first triggers eviction of the oldest frame.
//! * Per-packet cap. Individual frames bigger than the
//!   configured `max_packet_bytes` (default 64 KiB) are
//!   rejected at write time. Forensic capture should be
//!   selective — the ring is not a full-jumbo replay log.
//! * Thread-safe. The ring is wrapped in a [`parking_lot::Mutex`]
//!   so concurrent producers (multiple subsystems tapping
//!   packets) can call [`PcapRing::push`] from any thread.
//!   Pull and stats are sync-only too, no async needed.
//! * On-demand pull. The operator-facing pull returns the
//!   currently-buffered frames as a vector of
//!   [`CapturedFrame`]; the ring is not drained.

use std::collections::VecDeque;
use std::time::SystemTime;

use bytes::Bytes;
use parking_lot::Mutex;

use crate::error::TelemetryError;

/// One captured packet plus its observation metadata. The
/// frame's raw bytes are stored as [`Bytes`] so a producer can
/// share the same buffer with the kernel-side reader without
/// a copy when the producer already owns a refcounted slice.
#[derive(Clone, Debug)]
pub struct CapturedFrame {
    /// Producer-side wall-clock time the frame was observed.
    pub captured_at: SystemTime,
    /// Interface or tap label the frame came from
    /// (informational only — used by the operator UI to render
    /// the source column).
    pub interface: String,
    /// Raw link-layer bytes (Ethernet frame, etc.).
    pub bytes: Bytes,
}

impl CapturedFrame {
    /// Length of the captured payload.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the captured payload is zero-length (a degenerate
    /// frame the ring rejects on push).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Static configuration for a [`PcapRing`]. Both caps must be
/// positive; constructing with zero on either is a programmer
/// error and panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapRingConfig {
    /// Maximum number of frames retained at once. When reached,
    /// pushing a new frame evicts the oldest.
    pub max_packets: usize,
    /// Maximum total bytes retained across all buffered frames.
    /// When reached, pushing evicts oldest frames until the new
    /// frame fits.
    pub max_total_bytes: usize,
    /// Maximum bytes per single frame. Frames larger than this
    /// are rejected at write time with [`TelemetryError::Pcap`].
    pub max_packet_bytes: usize,
}

impl Default for PcapRingConfig {
    fn default() -> Self {
        Self {
            max_packets: 2_048,
            max_total_bytes: 32 * 1024 * 1024, // 32 MiB
            max_packet_bytes: 64 * 1024,       // 64 KiB
        }
    }
}

/// Internal mutable state, guarded by a parking-lot mutex.
#[derive(Debug)]
struct RingState {
    /// Currently buffered frames, oldest-first. A VecDeque
    /// gives O(1) push-back and pop-front which is the exact
    /// access pattern we have.
    frames: VecDeque<CapturedFrame>,
    /// Running sum of `frames[i].bytes.len()`. Kept in sync on
    /// every push/pop so the byte-budget check is O(1).
    total_bytes: usize,
    /// Counter of frames dropped due to eviction. Exposed via
    /// [`PcapRing::stats`].
    dropped_packets: u64,
    /// Counter of frames rejected because they exceeded
    /// `max_packet_bytes` at write time. Exposed via
    /// [`PcapRing::stats`].
    rejected_oversize: u64,
}

/// PCAP ring buffer. Cheap to clone — internally Arc-wrapped via
/// the Mutex around shared state — but the design here keeps a
/// non-Arc form for simplicity; callers needing multiple
/// references should wrap the ring in [`std::sync::Arc`]
/// themselves.
#[derive(Debug)]
pub struct PcapRing {
    config: PcapRingConfig,
    state: Mutex<RingState>,
}

/// Snapshot counters exposed by [`PcapRing::stats`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcapStats {
    /// Currently buffered frame count.
    pub buffered_packets: usize,
    /// Currently buffered total bytes.
    pub buffered_bytes: usize,
    /// Frames evicted to make room for newer ones, lifetime
    /// total since construction.
    pub dropped_packets: u64,
    /// Frames rejected at write time because they exceeded
    /// `max_packet_bytes`.
    pub rejected_oversize: u64,
}

impl PcapRing {
    /// New empty ring with the given configuration. Panics if
    /// any of the three caps is zero — that's always a
    /// configuration bug, not a runtime condition the ring should
    /// silently tolerate.
    #[must_use]
    pub fn new(config: PcapRingConfig) -> Self {
        assert!(
            config.max_packets > 0,
            "PcapRingConfig.max_packets must be > 0"
        );
        assert!(
            config.max_total_bytes > 0,
            "PcapRingConfig.max_total_bytes must be > 0"
        );
        assert!(
            config.max_packet_bytes > 0,
            "PcapRingConfig.max_packet_bytes must be > 0"
        );
        Self {
            config,
            state: Mutex::new(RingState {
                frames: VecDeque::new(),
                total_bytes: 0,
                dropped_packets: 0,
                rejected_oversize: 0,
            }),
        }
    }

    /// Configuration the ring was constructed with.
    #[must_use]
    pub fn config(&self) -> &PcapRingConfig {
        &self.config
    }

    /// Push a captured frame. Returns the number of older frames
    /// evicted to make room. Errors out for empty frames or
    /// frames that exceed `max_packet_bytes`.
    pub fn push(&self, frame: CapturedFrame) -> Result<usize, TelemetryError> {
        if frame.bytes.is_empty() {
            return Err(TelemetryError::Pcap(
                "captured frame is empty (zero bytes)".to_string(),
            ));
        }
        if frame.bytes.len() > self.config.max_packet_bytes {
            let mut state = self.state.lock();
            state.rejected_oversize = state.rejected_oversize.saturating_add(1);
            return Err(TelemetryError::Pcap(format!(
                "captured frame is {} bytes, exceeds max_packet_bytes {}",
                frame.bytes.len(),
                self.config.max_packet_bytes
            )));
        }
        let frame_len = frame.bytes.len();
        let mut state = self.state.lock();
        let mut evicted = 0_usize;
        // Evict by both budgets in a single loop. The order
        // matters: the byte-budget check must use the post-push
        // total, so we model the push as a hypothetical
        // (total + frame_len) and pop until that fits.
        while state.frames.len() >= self.config.max_packets
            || state.total_bytes.saturating_add(frame_len) > self.config.max_total_bytes
        {
            let Some(oldest) = state.frames.pop_front() else {
                // No buffered frames left and the new frame
                // STILL exceeds max_total_bytes alone — caller's
                // configuration is inconsistent. Surface a
                // clear error rather than busy-looping.
                state.rejected_oversize = state.rejected_oversize.saturating_add(1);
                return Err(TelemetryError::Pcap(format!(
                    "captured frame is {} bytes but max_total_bytes is {}",
                    frame_len, self.config.max_total_bytes
                )));
            };
            state.total_bytes = state.total_bytes.saturating_sub(oldest.bytes.len());
            state.dropped_packets = state.dropped_packets.saturating_add(1);
            evicted += 1;
        }
        state.total_bytes = state.total_bytes.saturating_add(frame_len);
        state.frames.push_back(frame);
        Ok(evicted)
    }

    /// Take a snapshot of every currently-buffered frame. The
    /// ring is NOT drained — repeated pulls return the same set
    /// until eviction removes a frame. Used by the operator
    /// "pull PCAP for this event" surface.
    #[must_use]
    pub fn snapshot(&self) -> Vec<CapturedFrame> {
        let state = self.state.lock();
        state.frames.iter().cloned().collect()
    }

    /// Drain every buffered frame, leaving the ring empty.
    /// Used by the operator "export PCAP" path that consumes
    /// the buffer once.
    #[must_use]
    pub fn drain(&self) -> Vec<CapturedFrame> {
        let mut state = self.state.lock();
        let out: Vec<CapturedFrame> = state.frames.drain(..).collect();
        state.total_bytes = 0;
        out
    }

    /// Snapshot stats. Cheap; takes only the mutex briefly.
    #[must_use]
    pub fn stats(&self) -> PcapStats {
        let state = self.state.lock();
        PcapStats {
            buffered_packets: state.frames.len(),
            buffered_bytes: state.total_bytes,
            dropped_packets: state.dropped_packets,
            rejected_oversize: state.rejected_oversize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(label: &str, bytes: usize) -> CapturedFrame {
        CapturedFrame {
            captured_at: SystemTime::now(),
            interface: label.to_string(),
            bytes: Bytes::from(vec![0u8; bytes]),
        }
    }

    #[test]
    fn rejects_empty_frame() {
        let r = PcapRing::new(PcapRingConfig::default());
        let err = r
            .push(CapturedFrame {
                captured_at: SystemTime::now(),
                interface: "eth0".into(),
                bytes: Bytes::new(),
            })
            .unwrap_err();
        assert!(matches!(err, TelemetryError::Pcap(_)));
        assert_eq!(r.stats().buffered_packets, 0);
    }

    #[test]
    fn rejects_oversize_frame_and_counts() {
        let r = PcapRing::new(PcapRingConfig {
            max_packets: 8,
            max_total_bytes: 64 * 1024,
            max_packet_bytes: 128,
        });
        let err = r.push(frame("eth0", 256)).unwrap_err();
        assert!(matches!(err, TelemetryError::Pcap(_)));
        assert_eq!(r.stats().rejected_oversize, 1);
    }

    #[test]
    fn evicts_oldest_when_packet_cap_hit() {
        let r = PcapRing::new(PcapRingConfig {
            max_packets: 3,
            max_total_bytes: 64 * 1024,
            max_packet_bytes: 1024,
        });
        for i in 0..3 {
            r.push(frame(&format!("eth{i}"), 16)).unwrap();
        }
        assert_eq!(r.stats().buffered_packets, 3);
        // Pushing a 4th frame must evict the oldest.
        r.push(frame("eth3", 16)).unwrap();
        assert_eq!(r.stats().buffered_packets, 3);
        assert_eq!(r.stats().dropped_packets, 1);
        let snap = r.snapshot();
        assert_eq!(snap[0].interface, "eth1");
        assert_eq!(snap[2].interface, "eth3");
    }

    #[test]
    fn evicts_oldest_when_byte_cap_hit() {
        let r = PcapRing::new(PcapRingConfig {
            max_packets: 100,
            max_total_bytes: 128,
            max_packet_bytes: 64,
        });
        // Two 60-byte frames fit (120 bytes total). A third
        // 60-byte frame puts us at 180 > 128, so the oldest
        // must evict.
        r.push(frame("a", 60)).unwrap();
        r.push(frame("b", 60)).unwrap();
        assert_eq!(r.stats().buffered_bytes, 120);
        r.push(frame("c", 60)).unwrap();
        let stats = r.stats();
        assert_eq!(stats.buffered_packets, 2);
        assert_eq!(stats.buffered_bytes, 120);
        assert_eq!(stats.dropped_packets, 1);
    }

    #[test]
    fn snapshot_does_not_drain() {
        let r = PcapRing::new(PcapRingConfig::default());
        r.push(frame("a", 16)).unwrap();
        r.push(frame("b", 16)).unwrap();
        let s1 = r.snapshot();
        let s2 = r.snapshot();
        assert_eq!(s1.len(), 2);
        assert_eq!(s2.len(), 2);
        // Producer can still push after a snapshot.
        r.push(frame("c", 16)).unwrap();
        assert_eq!(r.stats().buffered_packets, 3);
    }

    #[test]
    fn drain_empties_ring() {
        let r = PcapRing::new(PcapRingConfig::default());
        r.push(frame("a", 16)).unwrap();
        r.push(frame("b", 16)).unwrap();
        let got = r.drain();
        assert_eq!(got.len(), 2);
        assert_eq!(r.stats().buffered_packets, 0);
        assert_eq!(r.stats().buffered_bytes, 0);
    }

    #[test]
    fn thread_safe_concurrent_push() {
        use std::sync::Arc;
        use std::thread;
        let r = Arc::new(PcapRing::new(PcapRingConfig {
            max_packets: 10_000,
            max_total_bytes: 10 * 1024 * 1024,
            max_packet_bytes: 1024,
        }));
        let mut handles = Vec::new();
        for t in 0..8 {
            let r = Arc::clone(&r);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    r.push(frame(&format!("t{t}_{i}"), 32)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(r.stats().buffered_packets, 8 * 100);
    }
}
