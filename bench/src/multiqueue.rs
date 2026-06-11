//! Multi-queue / multi-stream wire-throughput model.
//!
//! The single-stream `throughput` mode answers "what does *one* flow on
//! *one* core sustain?" — a deliberately conservative floor (the number
//! the blog quotes, honestly caveated as a single-stream veth measurement,
//! not a multi-queue physical NIC). A real edge box, like the ASIC
//! appliances competitors benchmark, fans traffic across many NIC receive
//! (RSS) queues, one per core, and the per-queue XDP fast path scales with
//! them. This module measures that ceiling.
//!
//! ## How it models a multi-queue NIC
//!
//! Each "queue" is a worker thread that owns a *distinct*
//! [`ForwardingHarness`] — its own firewall engine, conntrack, inspectors,
//! and flow pool — so N queues running concurrently share no mutable
//! state, exactly as N RSS rings pinned to N cores do not. A [`Barrier`]
//! releases every queue into its measured loop at once, so the streams
//! genuinely contend for the host's cores and memory bandwidth for the
//! whole run. The aggregate is therefore bounded by the host's *real*
//! parallelism — which is the line-rate ceiling a single-stream number
//! structurally cannot reveal.
//!
//! ## What it reports
//!
//! A scaling curve from one stream up to the widest fanout. For each
//! width it records the aggregate throughput, the mean per-queue
//! throughput, and the scaling efficiency relative to ideal linear
//! scaling (`aggregate / (queues × single_stream)`). Efficiency at or near
//! `1.0` means the box scales out cleanly; a drop once the fanout exceeds
//! the physical core count is the honest ceiling.
//!
//! This is still *software on a generic VM*, not a multi-queue physical
//! NIC and not an ASIC — the report markdown carries that caveat.

use std::sync::{Arc, Barrier};
use std::thread;

use crate::business_report::TrafficMix;
use crate::datapath::{Backend, ForwardingHarness, ForwardingMode, ForwardingResult};
use crate::report::{MultiQueueScalePoint, MultiQueueStreamMeasurement};

/// Inputs for a multi-queue scaling sweep, decoupled from the CLI surface
/// so the harness is driven identically from the binary and from tests.
#[derive(Debug, Clone)]
pub struct MultiQueueConfig {
    /// Queue-fanout widths to measure. Normalised before use: entries
    /// below `1` are dropped, the list is sorted and de-duplicated, and a
    /// single-stream (`1`) point is always prepended so the floor — the
    /// efficiency baseline — is measured every run.
    pub queue_counts: Vec<usize>,
    /// Packets each stream pushes per measurement.
    pub packets_per_queue: usize,
    /// Synthetic L3/L4 rule count each stream's policy walk evaluates.
    pub rule_count: usize,
    /// Inspection depth measured.
    pub mode: ForwardingMode,
    /// Forwarding substrate measured.
    pub backend: Backend,
}

impl MultiQueueConfig {
    /// The fanout widths this config will measure, normalised: entries
    /// below `1` are dropped, sorted ascending, de-duplicated, and with a
    /// single-stream point guaranteed first.
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
}

/// Run one fanout width: build a distinct [`ForwardingHarness`] per queue,
/// then spawn one worker thread per harness that — released together by a
/// barrier — runs a single measured forwarding stream. Returns the
/// per-stream results in ascending queue-index order.
fn run_fanout(
    mix: &TrafficMix,
    queues: usize,
    packets_per_queue: usize,
    rule_count: usize,
    mode: ForwardingMode,
    backend: Backend,
) -> Vec<(usize, ForwardingResult)> {
    let queues = queues.max(1);

    // Build every per-queue harness up front, on this thread. Construction
    // (engine install, inspector construction) is untimed setup, so keeping
    // it out of the worker threads costs the measurement nothing — and it
    // removes a deadlock: a worker that panicked while constructing its
    // harness would never reach `barrier.wait()`, leaving the surviving
    // N−1 workers (and the join below) blocked forever. With construction
    // here, any such failure aborts cleanly before any worker is spawned.
    let harnesses: Vec<ForwardingHarness> = (0..queues)
        .map(|_| ForwardingHarness::new(rule_count))
        .collect();

    let barrier = Arc::new(Barrier::new(queues));
    let handles: Vec<_> = harnesses
        .into_iter()
        .enumerate()
        .map(|(q, harness)| {
            let mix = *mix;
            let barrier = Arc::clone(&barrier);
            thread::Builder::new()
                .name(format!("mq-queue-{q}"))
                .spawn(move || {
                    // Build this queue's flow pool *before* the barrier so
                    // it is untimed and every queue enters its measured loop
                    // together — the barrier then gates only the timed pass,
                    // and the streams genuinely contend for the host's cores
                    // for the whole run (no per-queue pool-build skew).
                    let stream = harness.prepare_stream(&mix, packets_per_queue);
                    barrier.wait();
                    let r = stream.measure(mode, backend);
                    (q, r)
                })
                .expect("spawn multi-queue worker thread")
        })
        .collect();

    let mut streams: Vec<(usize, ForwardingResult)> = handles
        .into_iter()
        .map(|h| h.join().expect("multi-queue worker thread panicked"))
        .collect();
    streams.sort_by_key(|(q, _)| *q);
    streams
}

/// Integer mean of a `u64` sequence, computed in `u128` so a long,
/// large-valued sequence cannot overflow. `0` for an empty sequence.
fn mean_u64(values: impl Iterator<Item = u64>) -> u64 {
    let mut sum = 0u128;
    let mut n = 0u128;
    for v in values {
        sum += u128::from(v);
        n += 1;
    }
    sum.checked_div(n).unwrap_or(0) as u64
}

/// Measure the full scaling curve: every normalised fanout width, in
/// ascending order, with the aggregate throughput and per-stream scaling
/// at each width. Efficiency is computed against the single-stream
/// (`queues == 1`) aggregate, which is always measured first.
#[must_use]
pub fn measure_scaling(
    mix: &TrafficMix,
    config: &MultiQueueConfig,
    packet_bytes: u32,
) -> Vec<MultiQueueScalePoint> {
    let counts = config.normalized_queue_counts();
    let packets_per_queue = config.packets_per_queue.max(1);

    let mut single_stream_pps = 0.0f64;
    let mut points = Vec::with_capacity(counts.len());

    for &queues in &counts {
        let raw = run_fanout(
            mix,
            queues,
            packets_per_queue,
            config.rule_count,
            config.mode,
            config.backend,
        );

        let streams: Vec<MultiQueueStreamMeasurement> = raw
            .iter()
            .map(|(q, r)| MultiQueueStreamMeasurement {
                queue_index: *q,
                packets: r.packets,
                pps: r.packets_per_sec(),
                gbps: r.gbps(packet_bytes),
                p50_ns: r.p50_ns,
                p99_ns: r.p99_ns,
            })
            .collect();

        let aggregate_pps: f64 = streams.iter().map(|s| s.pps).sum();
        let aggregate_gbps: f64 = streams.iter().map(|s| s.gbps).sum();
        let mean_pps_per_queue = if queues > 0 {
            aggregate_pps / queues as f64
        } else {
            0.0
        };

        // `queues == 1` is always the first normalised point, so this
        // captures the single-stream baseline before any wider point uses
        // it as the linear-scaling reference. Keying on the value (not a
        // loop index) keeps this correct independent of how the queue
        // counts are normalised or ordered.
        if queues == 1 {
            single_stream_pps = aggregate_pps;
        }
        let scaling_efficiency = if single_stream_pps > 0.0 && queues > 0 {
            aggregate_pps / (queues as f64 * single_stream_pps)
        } else {
            0.0
        };

        let p50_ns_mean = mean_u64(streams.iter().map(|s| s.p50_ns));
        let p99_ns_max = streams.iter().map(|s| s.p99_ns).max().unwrap_or(0);

        points.push(MultiQueueScalePoint {
            queues,
            aggregate_pps,
            aggregate_gbps,
            mean_pps_per_queue,
            scaling_efficiency,
            p50_ns_mean,
            p99_ns_max,
            streams,
        });
    }

    points
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_config(queue_counts: Vec<usize>) -> MultiQueueConfig {
        MultiQueueConfig {
            queue_counts,
            // Small so the test suite stays fast; the curve shape, not the
            // absolute rate, is what is asserted.
            packets_per_queue: 2_000,
            rule_count: 16,
            mode: ForwardingMode::RawL3,
            backend: Backend::Xdp,
        }
    }

    #[test]
    fn normalization_always_includes_single_stream_sorted_and_deduped() {
        let cfg = small_config(vec![4, 2, 2, 0, 8]);
        // `0` is filtered, duplicates collapse, and a `1` floor is prepended.
        assert_eq!(cfg.normalized_queue_counts(), vec![1, 2, 4, 8]);

        let cfg = small_config(vec![]);
        assert_eq!(cfg.normalized_queue_counts(), vec![1]);

        let cfg = small_config(vec![1, 3]);
        assert_eq!(cfg.normalized_queue_counts(), vec![1, 3]);
    }

    #[test]
    fn scaling_curve_is_well_formed() {
        let cfg = small_config(vec![1, 2]);
        let points = measure_scaling(&TrafficMix::default(), &cfg, 1500);

        // One point per normalised fanout width, in ascending order.
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].queues, 1);
        assert_eq!(points[1].queues, 2);

        // The single-stream point has exactly one stream and unit
        // efficiency by construction (it is its own baseline).
        assert_eq!(points[0].streams.len(), 1);
        assert!((points[0].scaling_efficiency - 1.0).abs() < f64::EPSILON);

        for p in &points {
            // Every stream actually moved packets at a measurable rate.
            assert_eq!(p.streams.len(), p.queues);
            assert!(p.aggregate_pps > 0.0, "aggregate pps must be positive");
            assert!(p.aggregate_gbps > 0.0, "aggregate gbps must be positive");
            // The mean is the aggregate spread across the queues.
            let expected_mean = p.aggregate_pps / p.queues as f64;
            assert!((p.mean_pps_per_queue - expected_mean).abs() <= 1.0);
            // Efficiency is a finite, positive fraction of linear scaling.
            assert!(p.scaling_efficiency.is_finite());
            assert!(p.scaling_efficiency > 0.0);
            for s in &p.streams {
                assert_eq!(s.packets, cfg.packets_per_queue as u64);
            }
        }
    }
}
