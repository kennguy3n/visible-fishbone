//! Multi-queue *wire* transmit-throughput scaling.
//!
//! The single-stream `throughput` mode answers "what does *one*
//! `AF_PACKET` transmit socket on *one* core sustain?" — the ~5.5 Gbps
//! floor the blog honestly quotes. That number understates a real edge
//! box, which fans transmit across many NIC TX rings (one per core), the
//! same way a multi-queue NIC's RSS fans *receive* across cores. This
//! module measures that wire ceiling.
//!
//! ## How it differs from [`crate::multiqueue`]
//!
//! [`crate::multiqueue`] scales the *in-process forwarding decision* — it
//! never touches a socket, so its numbers are a software forwarding model,
//! not a wire measurement. This module scales the *real transmit path*:
//! each stream owns a distinct [`RawSocketGenerator`] (its own `AF_PACKET`
//! socket) and actually crafts and pushes frames at the kernel, exactly as
//! N TX rings pinned to N cores do. `--dry-run` swaps in
//! [`DryRunGenerator`] so the leg is self-testable on an unprivileged
//! runner — those numbers are a craft-rate ceiling, reported as transport
//! `dry-run` and never as a wire number.
//!
//! ## What it reports
//!
//! A scaling curve from one stream up to the widest fanout. For each width
//! it records the aggregate wire rate, the mean per-stream rate, and the
//! scaling efficiency relative to ideal linear scaling
//! (`aggregate / (streams × single_stream)`). Efficiency at or near `1.0`
//! means transmit scales out cleanly; the drop once the fanout exceeds the
//! physical core count is the honest ceiling.

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::report::{WireScalePoint, WireStreamMeasurement};
use crate::traffic_gen::{
    DryRunGenerator, FiveTupleSampler, IpVersion, L4Proto, PacketBuilder, PacketConfig,
    RawSocketGenerator, TrafficError, TrafficGenerator,
};

/// Inputs for a multi-queue wire scaling sweep, decoupled from the CLI
/// surface so the harness is driven identically from the binary and tests.
#[derive(Debug, Clone)]
pub struct WireScalingConfig {
    /// TX-fanout widths to measure. Normalised before use: entries below
    /// `1` are dropped, the list is sorted and de-duplicated, and a
    /// single-stream (`1`) point is always prepended so the wire floor —
    /// the efficiency baseline — is measured every run.
    pub queue_counts: Vec<usize>,
    /// Per-stream measured window. Every stream transmits flat-out for
    /// this long; all streams run concurrently so they genuinely contend
    /// for the host's cores and transmit path for the whole window.
    pub duration: Duration,
    /// On-wire frame size in bytes.
    pub frame_size: u32,
    /// L4 protocol shape of the crafted frames.
    pub l4: L4Proto,
    /// IP version of the crafted frames.
    pub ip_version: IpVersion,
    /// Base RNG seed; stream `q` is seeded `seed + q` so each TX socket
    /// emits a distinct flow set, the way distinct flows hash to distinct
    /// NIC queues.
    pub seed: u64,
    /// Egress interface for live transmission (ignored when `dry_run`).
    pub interface: String,
    /// Craft frames in-process and discard them (no socket, no privilege)
    /// instead of transmitting. Produces a craft-rate ceiling, not a wire
    /// number.
    pub dry_run: bool,
}

impl WireScalingConfig {
    /// The fanout widths this config will measure, normalised: entries
    /// below `1` dropped, sorted ascending, de-duplicated, single-stream
    /// guaranteed first. Mirrors `MultiQueueConfig::normalized_queue_counts`
    /// so the two legs present the same curve shape.
    #[must_use]
    pub fn normalized_queue_counts(&self) -> Vec<usize> {
        let mut counts: Vec<usize> = self
            .queue_counts
            .iter()
            .copied()
            .filter(|&q| q >= 1)
            .collect();
        counts.sort_unstable();
        counts.dedup();
        if counts.first() != Some(&1) {
            counts.insert(0, 1);
        }
        counts
    }

    /// The transport label recorded in the report.
    #[must_use]
    pub fn transport_label(&self) -> &'static str {
        if self.dry_run { "dry-run" } else { "af-packet" }
    }
}

/// Build one stream's packet crafter for the given per-stream seed.
fn builder_for(config: &WireScalingConfig, seed: u64) -> Result<PacketBuilder, TrafficError> {
    // Single source of truth for the benchmark flow space, shared with the
    // single-stream `throughput` floor, so the two legs sample byte-identical
    // 5-tuples and stay directly comparable.
    let sampler = FiveTupleSampler::rfc2544_benchmark(config.ip_version, seed)?;
    let packet = PacketConfig {
        frame_size: config.frame_size,
        l4: config.l4,
        // Locally-administered unicast MACs; AF_PACKET ignores the
        // Ethernet source on TX and the destination is the edge ingress.
        src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        ttl: 64,
    };
    PacketBuilder::new(packet, sampler)
}

/// Build one stream's generator: a live `AF_PACKET` transmitter, or a
/// dry-run craft-only generator. Boxed as `Send` so it can move into a
/// worker thread.
fn generator_for(
    config: &WireScalingConfig,
    seed: u64,
) -> Result<Box<dyn TrafficGenerator + Send>, TrafficError> {
    let builder = builder_for(config, seed)?;
    if config.dry_run {
        Ok(Box::new(DryRunGenerator::new(builder)))
    } else {
        Ok(Box::new(RawSocketGenerator::open(&config.interface, builder)?))
    }
}

/// What one worker thread measured over its own window.
struct StreamOutcome {
    queue_index: usize,
    packets: u64,
    bytes: u64,
    elapsed: Duration,
}

/// Start-gate shared by the fanout's worker threads. Workers park here until
/// the spawning thread either releases them all together (`go`) or cancels
/// them (`abort`) because a sibling failed to spawn. Using a cancellable
/// condition variable instead of a fixed-count `Barrier` means a partial
/// spawn can never strand the workers that *did* start: a `Barrier::new(N)`
/// only releases once `N` threads arrive, so if spawn `k < N` fails the
/// already-parked workers would block forever.
struct StartGate {
    /// Workers may enter their timed loop.
    go: bool,
    /// Workers must exit immediately without measuring.
    abort: bool,
}

/// Run one fanout width: build a distinct generator per stream, then spawn
/// one worker thread per generator that — released together by the
/// [`StartGate`] — transmits flat-out for `duration`. Returns the per-stream
/// outcomes in ascending stream-index order.
///
/// Failures are handled without ever stranding a thread:
/// * Generators are constructed up front, on this thread, before any worker
///   spawns. A construction failure (e.g. `EPERM` without `CAP_NET_RAW`)
///   returns here before a single thread exists.
/// * If a `thread::spawn` itself fails partway (resource exhaustion), the
///   gate is set to `abort`, every already-spawned worker is released to exit
///   immediately, all are joined, and the spawn error is returned. No worker
///   is left parked and no handle is left undetached.
fn run_fanout(
    config: &WireScalingConfig,
    queues: usize,
) -> Result<Vec<StreamOutcome>, TrafficError> {
    let queues = queues.max(1);
    let duration = config.duration;

    let generators: Vec<Box<dyn TrafficGenerator + Send>> = (0..queues)
        .map(|q| generator_for(config, config.seed.wrapping_add(q as u64)))
        .collect::<Result<_, _>>()?;

    let gate = Arc::new((Mutex::new(StartGate { go: false, abort: false }), Condvar::new()));
    let mut handles = Vec::with_capacity(queues);
    let mut spawn_err: Option<std::io::Error> = None;

    for (q, mut emitter) in generators.into_iter().enumerate() {
        let gate = Arc::clone(&gate);
        let spawned = thread::Builder::new()
            .name(format!("wire-mq-{q}"))
            .spawn(move || -> Result<StreamOutcome, TrafficError> {
                // Park until released (go) or cancelled (abort). Checking the
                // predicate under the lock before waiting closes the
                // lost-wakeup window: a worker that reaches the gate after the
                // release sees `go`/`abort` already set and never blocks.
                {
                    let (lock, cv) = &*gate;
                    let mut state = lock.lock().expect("wire start-gate mutex poisoned");
                    while !state.go && !state.abort {
                        state = cv.wait(state).expect("wire start-gate mutex poisoned");
                    }
                    if state.abort {
                        return Ok(StreamOutcome {
                            queue_index: q,
                            packets: 0,
                            bytes: 0,
                            elapsed: Duration::ZERO,
                        });
                    }
                }
                let start = Instant::now();
                let mut packets = 0u64;
                let mut bytes = 0u64;
                let mut err = None;
                while start.elapsed() < duration {
                    match emitter.emit() {
                        Ok(n) => {
                            packets += 1;
                            bytes += n as u64;
                        }
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                let elapsed = start.elapsed();
                match err {
                    Some(e) => Err(e),
                    None => Ok(StreamOutcome {
                        queue_index: q,
                        packets,
                        bytes,
                        elapsed,
                    }),
                }
            });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                spawn_err = Some(e);
                break;
            }
        }
    }

    // Release the spawned workers together, or cancel them if a spawn failed.
    {
        let (lock, cv) = &*gate;
        let mut state = lock.lock().expect("wire start-gate mutex poisoned");
        if spawn_err.is_some() {
            state.abort = true;
        } else {
            state.go = true;
        }
        drop(state);
        cv.notify_all();
    }

    // Always join every thread we spawned so none is left detached.
    let mut outcomes: Vec<StreamOutcome> = Vec::with_capacity(handles.len());
    let mut first_err = None;
    for h in handles {
        match h.join().expect("wire multi-queue worker thread panicked") {
            Ok(o) => outcomes.push(o),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    // A spawn failure means we never produced a full-width measurement, so it
    // takes precedence over any per-stream emit error from the partial set.
    if let Some(e) = spawn_err {
        return Err(TrafficError::from(e));
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    outcomes.sort_by_key(|o| o.queue_index);
    Ok(outcomes)
}

/// Per-stream rate from a stream's own packet/byte counts and measured
/// window. `0` for a degenerate zero-length window.
fn stream_rates(o: &StreamOutcome) -> (f64, f64) {
    let secs = o.elapsed.as_secs_f64();
    if secs <= 0.0 {
        return (0.0, 0.0);
    }
    let pps = o.packets as f64 / secs;
    let gbps = (o.bytes as f64 * 8.0) / secs / 1e9;
    (pps, gbps)
}

/// Measure the full wire scaling curve: every normalised fanout width, in
/// ascending order, with the aggregate wire rate and per-stream scaling at
/// each width. Efficiency is computed against the single-stream
/// (`queues == 1`) aggregate, which is always measured first.
///
/// # Errors
/// Propagates the first [`TrafficError`] from any stream — notably an
/// `AF_PACKET` socket-open failure on a live run without `CAP_NET_RAW`.
pub fn measure_wire_scaling(
    config: &WireScalingConfig,
) -> Result<Vec<WireScalePoint>, TrafficError> {
    let counts = config.normalized_queue_counts();
    let mut single_stream_pps = 0.0f64;
    let mut points = Vec::with_capacity(counts.len());

    for &queues in &counts {
        let outcomes = run_fanout(config, queues)?;

        let streams: Vec<WireStreamMeasurement> = outcomes
            .iter()
            .map(|o| {
                let (pps, gbps) = stream_rates(o);
                WireStreamMeasurement {
                    queue_index: o.queue_index,
                    packets: o.packets,
                    bytes: o.bytes,
                    pps,
                    gbps,
                    elapsed_ms: o.elapsed.as_secs_f64() * 1e3,
                }
            })
            .collect();

        let aggregate_pps: f64 = streams.iter().map(|s| s.pps).sum();
        let aggregate_gbps: f64 = streams.iter().map(|s| s.gbps).sum();
        let mean_gbps_per_queue = if queues > 0 {
            aggregate_gbps / queues as f64
        } else {
            0.0
        };

        // `queues == 1` is always the first normalised point, so this
        // captures the single-stream baseline before any wider point uses
        // it as the linear-scaling reference.
        if queues == 1 {
            single_stream_pps = aggregate_pps;
        }
        let scaling_efficiency = if single_stream_pps > 0.0 && queues > 0 {
            aggregate_pps / (queues as f64 * single_stream_pps)
        } else {
            0.0
        };

        points.push(WireScalePoint {
            queues,
            aggregate_pps,
            aggregate_gbps,
            mean_gbps_per_queue,
            scaling_efficiency,
            streams,
        });
    }

    Ok(points)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_config(queue_counts: Vec<usize>) -> WireScalingConfig {
        WireScalingConfig {
            queue_counts,
            // Short so the suite stays fast; the curve shape, not the
            // absolute rate, is what is asserted.
            duration: Duration::from_millis(40),
            frame_size: 1500,
            l4: L4Proto::Udp,
            ip_version: IpVersion::V4,
            seed: 7,
            interface: "lo".to_string(),
            dry_run: true,
        }
    }

    #[test]
    fn normalization_always_includes_single_stream_sorted_and_deduped() {
        let cfg = dry_config(vec![4, 2, 2, 0, 8]);
        assert_eq!(cfg.normalized_queue_counts(), vec![1, 2, 4, 8]);

        let cfg = dry_config(vec![]);
        assert_eq!(cfg.normalized_queue_counts(), vec![1]);

        let cfg = dry_config(vec![1, 3]);
        assert_eq!(cfg.normalized_queue_counts(), vec![1, 3]);
    }

    #[test]
    fn transport_label_reflects_dry_run() {
        let mut cfg = dry_config(vec![1]);
        assert_eq!(cfg.transport_label(), "dry-run");
        cfg.dry_run = false;
        assert_eq!(cfg.transport_label(), "af-packet");
    }

    #[test]
    fn dry_run_scaling_curve_is_well_formed() {
        let cfg = dry_config(vec![1, 2]);
        let points = measure_wire_scaling(&cfg).expect("dry-run measure never opens a socket");

        // One point per normalised width, single-stream first.
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].queues, 1);
        assert_eq!(points[1].queues, 2);

        // The single-stream point is the efficiency baseline: exactly 1.0.
        assert!((points[0].scaling_efficiency - 1.0).abs() < 1e-9);

        for p in &points {
            // Every stream actually crafted frames in its window.
            assert_eq!(p.streams.len(), p.queues);
            assert!(p.streams.iter().all(|s| s.packets > 0));
            // Aggregate is the sum of the per-stream rates.
            let sum: f64 = p.streams.iter().map(|s| s.pps).sum();
            assert!((p.aggregate_pps - sum).abs() < 1e-6);
            // Efficiency is finite and positive for a real measurement.
            assert!(p.scaling_efficiency.is_finite());
            assert!(p.scaling_efficiency > 0.0);
        }
    }

    #[test]
    fn per_stream_seeds_differ_so_streams_are_distinct_flows() {
        // Two streams seeded `seed` and `seed + 1` must not be identical
        // flow sets — otherwise the multi-queue model would be N copies of
        // one flow, not N distinct RSS-hashed flows.
        let cfg = dry_config(vec![2]);
        let mut a = builder_for(&cfg, cfg.seed).unwrap();
        let mut b = builder_for(&cfg, cfg.seed.wrapping_add(1)).unwrap();
        let mut fa = vec![0u8; a.frame_len()];
        let mut fb = vec![0u8; b.frame_len()];
        a.next(&mut fa).unwrap();
        b.next(&mut fb).unwrap();
        assert_ne!(fa, fb, "distinct per-stream seeds must craft distinct frames");
    }
}
