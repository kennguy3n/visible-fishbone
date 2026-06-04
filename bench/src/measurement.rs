//! Measurement primitives for the edge data-path benchmark.
//!
//! Three concerns live here, deliberately decoupled from where the
//! numbers come from (the traffic generator) and where they go (the
//! report):
//!
//!   * [`ThroughputMeasurement`] — a monotonic packet/byte counter the
//!     hot path bumps with relaxed atomics, plus a windowing helper
//!     that turns cumulative counts into a per-second rate series.
//!   * [`LatencyHistogram`] — an HdrHistogram-style log-linear histogram
//!     with bounded, pre-allocated storage. Recording is allocation-free
//!     and O(1) so timestamping a packet never perturbs the result it is
//!     trying to measure.
//!   * [`ResourceMeasurement`] — a `/proc` sampler that converts two
//!     `/proc/stat` snapshots into a busy-CPU percentage and reads RSS
//!     from `/proc/self/status` (or an arbitrary pid's `status`).
//!
//! The histogram and the `/proc` parsers are pure functions of their
//! inputs and carry the unit tests for this crate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;

/// Errors raised while sampling host resources.
#[derive(Debug, Error)]
pub enum ResourceError {
    /// A `/proc` file could not be read (the harness is not on Linux,
    /// or `/proc` is not mounted in the container).
    #[error("reading {path}: {source}")]
    Read {
        /// The `/proc` path that failed.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A `/proc` file was read but did not contain the field we parse
    /// (kernel format drift, or a truncated read).
    #[error("parsing {path}: {detail}")]
    Parse {
        /// The `/proc` path whose contents were malformed.
        path: String,
        /// What specifically was missing or unparseable.
        detail: String,
    },
}

/// A cumulative packet + byte counter shared between the generator /
/// receiver hot path and the sampling thread.
///
/// The hot path calls [`ThroughputMeasurement::record`] with `Relaxed`
/// ordering — there is no happens-before requirement between the
/// counter bump and any other memory, only that the increments are not
/// lost. The sampler reads a consistent-enough snapshot via
/// [`ThroughputMeasurement::snapshot`]; an occasional byte/packet skew
/// of one frame across the two loads is immaterial at benchmark rates.
#[derive(Debug, Default)]
pub struct ThroughputMeasurement {
    packets: AtomicU64,
    bytes: AtomicU64,
}

/// An immutable `(packets, bytes)` reading taken at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Total packets observed since the measurement was created.
    pub packets: u64,
    /// Total bytes observed since the measurement was created.
    pub bytes: u64,
}

impl ThroughputMeasurement {
    /// Create a zeroed counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single frame of `bytes` wire bytes.
    #[inline]
    pub fn record(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record `packets` frames totalling `bytes` wire bytes in one go
    /// (used by batched senders that flush a burst at once).
    #[inline]
    pub fn record_batch(&self, packets: u64, bytes: u64) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Take a snapshot of the cumulative counters.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

/// Convert two cumulative counter snapshots taken `elapsed` apart into a
/// per-second throughput rate.
///
/// Returns `None` when `elapsed` is zero (no defined rate) so a caller
/// that samples too fast does not divide by zero.
#[must_use]
pub fn rate_between(
    earlier: CounterSnapshot,
    later: CounterSnapshot,
    elapsed: Duration,
) -> Option<ThroughputRate> {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return None;
    }
    let d_packets = later.packets.saturating_sub(earlier.packets);
    let d_bytes = later.bytes.saturating_sub(earlier.bytes);
    Some(ThroughputRate {
        pps: d_packets as f64 / secs,
        // 1 byte = 8 bits; bits-per-second is the headline edge metric.
        bps: (d_bytes as f64 * 8.0) / secs,
    })
}

/// A throughput rate over one sampling window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThroughputRate {
    /// Packets per second.
    pub pps: f64,
    /// Bits per second.
    pub bps: f64,
}

impl ThroughputRate {
    /// Throughput in gigabits per second (1 Gbps = 1e9 bps).
    #[must_use]
    pub fn gbps(&self) -> f64 {
        self.bps / 1e9
    }
}

/// An HdrHistogram-style log-linear latency histogram with fixed,
/// pre-allocated storage.
///
/// Values are tracked in nanoseconds from `1` to `highest_trackable`
/// with a guaranteed relative error bounded by
/// `1 / 2^significant_value_digits_in_bits`. Recording is O(1) and
/// never allocates after construction, which is what lets the latency
/// path timestamp every packet without distorting the tail it is
/// measuring.
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    counts: Vec<u64>,
    sub_bucket_half_count_magnitude: u32,
    sub_bucket_half_count: u32,
    sub_bucket_mask: u64,
    sub_bucket_count: u32,
    unit_magnitude: u32,
    leading_zero_count_base: u32,
    highest_trackable: u64,
    total: u64,
    sum: u128,
    min: u64,
    max: u64,
    clamped: u64,
}

impl LatencyHistogram {
    /// Build a histogram tracking `[1, highest_trackable]` with
    /// `significant_value_digits` (1..=5) decimal digits of resolution.
    ///
    /// # Panics
    /// Panics if `highest_trackable < 2` or `significant_value_digits`
    /// is outside `1..=5` — both are programmer errors in the harness
    /// config, not runtime conditions, so failing loudly at setup is
    /// preferable to silently degrading resolution.
    #[must_use]
    pub fn new(highest_trackable: u64, significant_value_digits: u8) -> Self {
        assert!(highest_trackable >= 2, "highest_trackable must be >= 2");
        assert!(
            (1..=5).contains(&significant_value_digits),
            "significant_value_digits must be in 1..=5"
        );

        // Number of distinct values that must resolve to single-unit
        // precision, then rounded up to a power of two.
        let largest_single_unit = 2 * 10u64.pow(u32::from(significant_value_digits));
        let sub_bucket_count_magnitude = 64 - (largest_single_unit - 1).leading_zeros();
        let sub_bucket_count = 1u32 << sub_bucket_count_magnitude;
        let sub_bucket_half_count_magnitude = sub_bucket_count_magnitude - 1;
        let sub_bucket_half_count = sub_bucket_count / 2;
        let unit_magnitude = 0u32; // lowest discernible value == 1ns
        let sub_bucket_mask = (u64::from(sub_bucket_count) - 1) << unit_magnitude;
        let leading_zero_count_base = 64 - unit_magnitude - sub_bucket_count_magnitude;

        let bucket_count =
            Self::buckets_needed(highest_trackable, sub_bucket_count, unit_magnitude);
        let counts_len = (bucket_count + 1) * (sub_bucket_count / 2);

        Self {
            counts: vec![0; counts_len as usize],
            sub_bucket_half_count_magnitude,
            sub_bucket_half_count,
            sub_bucket_mask,
            sub_bucket_count,
            unit_magnitude,
            leading_zero_count_base,
            highest_trackable,
            total: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
            clamped: 0,
        }
    }

    fn buckets_needed(highest: u64, sub_bucket_count: u32, unit_magnitude: u32) -> u32 {
        let mut smallest_untrackable = u64::from(sub_bucket_count) << unit_magnitude;
        let mut buckets = 1u32;
        while smallest_untrackable < highest {
            if smallest_untrackable > u64::MAX / 2 {
                buckets += 1;
                break;
            }
            smallest_untrackable <<= 1;
            buckets += 1;
        }
        buckets
    }

    /// Record one observation of `value` nanoseconds.
    ///
    /// Values above `highest_trackable` are clamped to the ceiling and
    /// counted in [`LatencyHistogram::clamped`] rather than dropped, so
    /// an out-of-range tail still moves the high percentiles instead of
    /// silently vanishing.
    #[inline]
    pub fn record(&mut self, value: u64) {
        self.record_n(value, 1);
    }

    /// Record `count` observations of `value` nanoseconds.
    #[inline]
    pub fn record_n(&mut self, value: u64, count: u64) {
        if count == 0 {
            return;
        }
        let (effective, clamped) = if value > self.highest_trackable {
            (self.highest_trackable, true)
        } else {
            (value, false)
        };
        let idx = self.counts_index_for(effective);
        self.counts[idx] += count;
        self.total += count;
        self.sum += u128::from(value) * u128::from(count);
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
        if clamped {
            self.clamped += count;
        }
    }

    fn bucket_index(&self, value: u64) -> u32 {
        self.leading_zero_count_base - (value | self.sub_bucket_mask).leading_zeros()
    }

    fn sub_bucket_index(&self, value: u64, bucket_index: u32) -> u32 {
        // Safe cast: the shift leaves at most `sub_bucket_count` distinct
        // values, which fits in u32 by construction.
        (value >> (bucket_index + self.unit_magnitude)) as u32
    }

    fn counts_index_for(&self, value: u64) -> usize {
        let bucket_index = self.bucket_index(value);
        let sub_bucket_index = self.sub_bucket_index(value, bucket_index);
        self.counts_index(bucket_index, sub_bucket_index)
    }

    fn counts_index(&self, bucket_index: u32, sub_bucket_index: u32) -> usize {
        let bucket_base = (bucket_index + 1) << self.sub_bucket_half_count_magnitude;
        let offset = sub_bucket_index as i64 - i64::from(self.sub_bucket_half_count);
        (i64::from(bucket_base) + offset) as usize
    }

    /// Lowest value and size of the equivalent range for a counts-array
    /// index — the inverse of [`Self::counts_index`].
    fn value_range_at_index(&self, index: usize) -> (u64, u64) {
        let index = index as u32;
        let mut bucket_index = (index >> self.sub_bucket_half_count_magnitude) as i64 - 1;
        let mut sub_bucket_index =
            (index & (self.sub_bucket_half_count - 1)) + self.sub_bucket_half_count;
        if bucket_index < 0 {
            sub_bucket_index -= self.sub_bucket_half_count;
            bucket_index = 0;
        }
        let shift = bucket_index as u32 + self.unit_magnitude;
        let low = u64::from(sub_bucket_index) << shift;
        let size = 1u64 << shift;
        (low, size)
    }

    /// Total number of recorded observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.total
    }

    /// Number of observations that exceeded `highest_trackable` and were
    /// clamped to the ceiling.
    #[must_use]
    pub fn clamped(&self) -> u64 {
        self.clamped
    }

    /// Smallest recorded value, or `None` if empty.
    #[must_use]
    pub fn min(&self) -> Option<u64> {
        (self.total > 0).then_some(self.min)
    }

    /// Largest recorded value, or `None` if empty.
    #[must_use]
    pub fn max(&self) -> Option<u64> {
        (self.total > 0).then_some(self.max)
    }

    /// Exact arithmetic mean of all recorded values, or `None` if empty.
    ///
    /// The mean is computed from the running sum of the *actual* recorded
    /// values (not bucket midpoints), so it is exact regardless of the
    /// histogram's quantization.
    #[must_use]
    pub fn mean(&self) -> Option<f64> {
        (self.total > 0).then(|| self.sum as f64 / self.total as f64)
    }

    /// Value at the given percentile (`0.0..=100.0`), expressed as the
    /// highest value equivalent to the bucket the percentile falls in.
    ///
    /// Returns `None` for an empty histogram.
    #[must_use]
    pub fn value_at_percentile(&self, percentile: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let p = percentile.clamp(0.0, 100.0);
        // Ceiling so the returned value is one at-or-below which `p`% of
        // observations fall (HdrHistogram semantics).
        let target = ((p / 100.0) * self.total as f64).ceil() as u64;
        let target = target.clamp(1, self.total);

        let mut running = 0u64;
        for (idx, &c) in self.counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            running += c;
            if running >= target {
                let (low, size) = self.value_range_at_index(idx);
                return Some(low + size - 1);
            }
        }
        // Unreachable in practice: the loop must cross `target` once it is
        // <= total. Fall back to the recorded max for total safety.
        Some(self.max)
    }

    /// Convenience accessor for p50.
    #[must_use]
    pub fn p50(&self) -> Option<u64> {
        self.value_at_percentile(50.0)
    }

    /// Convenience accessor for p95.
    #[must_use]
    pub fn p95(&self) -> Option<u64> {
        self.value_at_percentile(95.0)
    }

    /// Convenience accessor for p99.
    #[must_use]
    pub fn p99(&self) -> Option<u64> {
        self.value_at_percentile(99.0)
    }

    /// Merge another histogram into this one. Both must share the same
    /// layout (built with identical constructor arguments); a mismatch
    /// returns `Err` rather than producing silently wrong percentiles.
    ///
    /// # Errors
    /// Returns an error string if the two histograms have incompatible
    /// bucket layouts.
    pub fn merge(&mut self, other: &LatencyHistogram) -> Result<(), String> {
        if self.counts.len() != other.counts.len()
            || self.sub_bucket_count != other.sub_bucket_count
            || self.unit_magnitude != other.unit_magnitude
        {
            return Err("histogram layouts differ; cannot merge".to_string());
        }
        for (dst, src) in self.counts.iter_mut().zip(other.counts.iter()) {
            *dst += *src;
        }
        self.total += other.total;
        self.sum += other.sum;
        self.clamped += other.clamped;
        if other.total > 0 {
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
        }
        Ok(())
    }
}

/// One `/proc/stat` aggregate-CPU sample (the `cpu` summary line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSample {
    /// Jiffies spent doing work (everything except idle + iowait).
    pub busy: u64,
    /// Total jiffies across all states.
    pub total: u64,
}

/// Resource sampler: turns `/proc` snapshots into CPU% and RSS.
#[derive(Debug, Default)]
pub struct ResourceMeasurement {
    last_cpu: Option<CpuSample>,
    peak_rss_bytes: u64,
    busy_pct_sum: f64,
    busy_pct_samples: u64,
}

impl ResourceMeasurement {
    /// Create an empty sampler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `/proc/stat`, returning the aggregate CPU sample.
    ///
    /// # Errors
    /// Returns [`ResourceError`] if `/proc/stat` cannot be read or the
    /// `cpu ` summary line is missing/malformed.
    pub fn read_proc_stat() -> Result<CpuSample, ResourceError> {
        let path = "/proc/stat";
        let content = std::fs::read_to_string(path).map_err(|source| ResourceError::Read {
            path: path.to_string(),
            source,
        })?;
        parse_proc_stat(&content).ok_or_else(|| ResourceError::Parse {
            path: path.to_string(),
            detail: "no parseable `cpu` summary line".to_string(),
        })
    }

    /// Read this process's resident set size in bytes from
    /// `/proc/self/status`.
    ///
    /// # Errors
    /// Returns [`ResourceError`] if the file cannot be read or `VmRSS`
    /// is absent.
    pub fn read_self_rss_bytes() -> Result<u64, ResourceError> {
        let path = "/proc/self/status";
        let content = std::fs::read_to_string(path).map_err(|source| ResourceError::Read {
            path: path.to_string(),
            source,
        })?;
        parse_vm_rss_bytes(&content).ok_or_else(|| ResourceError::Parse {
            path: path.to_string(),
            detail: "no parseable `VmRSS:` line".to_string(),
        })
    }

    /// Take a sample: compute busy-CPU% since the previous CPU sample and
    /// fold the current RSS into the running peak.
    ///
    /// The first call has no previous CPU baseline and therefore yields
    /// `cpu_busy_pct == None`; subsequent calls return the delta-based
    /// utilisation between consecutive samples.
    ///
    /// # Errors
    /// Propagates [`ResourceError`] from the `/proc` reads.
    pub fn sample(&mut self) -> Result<ResourceSample, ResourceError> {
        let cpu = Self::read_proc_stat()?;
        let rss = Self::read_self_rss_bytes()?;
        if rss > self.peak_rss_bytes {
            self.peak_rss_bytes = rss;
        }
        let busy_pct = self.last_cpu.and_then(|prev| cpu_busy_pct(prev, cpu));
        if let Some(pct) = busy_pct {
            self.busy_pct_sum += pct;
            self.busy_pct_samples += 1;
        }
        self.last_cpu = Some(cpu);
        Ok(ResourceSample {
            cpu_busy_pct: busy_pct,
            rss_bytes: rss,
        })
    }

    /// Peak RSS observed across all samples, in bytes.
    #[must_use]
    pub fn peak_rss_bytes(&self) -> u64 {
        self.peak_rss_bytes
    }

    /// Mean busy-CPU% across all delta windows, or `None` if fewer than
    /// two samples were taken.
    #[must_use]
    pub fn mean_cpu_busy_pct(&self) -> Option<f64> {
        (self.busy_pct_samples > 0).then(|| self.busy_pct_sum / self.busy_pct_samples as f64)
    }
}

/// One resource reading.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceSample {
    /// Busy-CPU% since the previous sample, or `None` on the first call.
    pub cpu_busy_pct: Option<f64>,
    /// Resident set size at sample time, in bytes.
    pub rss_bytes: u64,
}

/// Parse the aggregate `cpu` line out of `/proc/stat` content.
///
/// The line is `cpu user nice system idle iowait irq softirq steal ...`;
/// "busy" is everything except `idle` and `iowait`.
#[must_use]
pub fn parse_proc_stat(content: &str) -> Option<CpuSample> {
    let line = content
        .lines()
        .find(|l| l.starts_with("cpu ") || *l == "cpu")?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse::<u64>().ok())
        .collect();
    // user, nice, system, idle, iowait are the minimum we need.
    if fields.len() < 5 {
        return None;
    }
    let idle = fields[3];
    let iowait = fields[4];
    let total: u64 = fields.iter().sum();
    let busy = total.saturating_sub(idle + iowait);
    Some(CpuSample { busy, total })
}

/// Busy-CPU% between two `/proc/stat` samples. `None` when no jiffies
/// elapsed between the two reads (sampling faster than the clock tick).
#[must_use]
pub fn cpu_busy_pct(prev: CpuSample, cur: CpuSample) -> Option<f64> {
    let d_total = cur.total.saturating_sub(prev.total);
    if d_total == 0 {
        return None;
    }
    let d_busy = cur.busy.saturating_sub(prev.busy);
    Some((d_busy as f64 / d_total as f64) * 100.0)
}

/// Parse `VmRSS:` (in kibibytes) from `/proc/<pid>/status` content and
/// return it in bytes.
#[must_use]
pub fn parse_vm_rss_bytes(content: &str) -> Option<u64> {
    let line = content.lines().find(|l| l.starts_with("VmRSS:"))?;
    // Format: `VmRSS:\t   12345 kB`
    let kb: u64 = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())?;
    Some(kb * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_relative_eq;

    #[test]
    fn throughput_rate_is_per_second_and_bits() {
        let earlier = CounterSnapshot {
            packets: 0,
            bytes: 0,
        };
        let later = CounterSnapshot {
            packets: 2_000,
            // 1 Gbit in 1s = 125_000_000 bytes.
            bytes: 125_000_000,
        };
        let rate = rate_between(earlier, later, Duration::from_secs(1)).unwrap();
        assert_relative_eq!(rate.pps, 2_000.0, max_relative = 1e-9);
        assert_relative_eq!(rate.gbps(), 1.0, max_relative = 1e-9);
    }

    #[test]
    fn throughput_rate_rejects_zero_window() {
        let s = CounterSnapshot {
            packets: 1,
            bytes: 1,
        };
        assert!(rate_between(s, s, Duration::ZERO).is_none());
    }

    #[test]
    fn throughput_counter_accumulates() {
        let m = ThroughputMeasurement::new();
        m.record(64);
        m.record(1500);
        m.record_batch(3, 300);
        let snap = m.snapshot();
        assert_eq!(snap.packets, 5);
        assert_eq!(snap.bytes, 64 + 1500 + 300);
    }

    #[test]
    fn histogram_empty_has_no_percentiles() {
        let h = LatencyHistogram::new(1_000_000, 3);
        assert_eq!(h.count(), 0);
        assert!(h.value_at_percentile(50.0).is_none());
        assert!(h.mean().is_none());
        assert!(h.min().is_none());
    }

    #[test]
    fn histogram_constant_values_are_exact() {
        let mut h = LatencyHistogram::new(1_000_000, 3);
        for _ in 0..1000 {
            h.record(500);
        }
        assert_eq!(h.count(), 1000);
        // 500 is small enough to sit in the linear region: exact.
        assert_eq!(h.min(), Some(500));
        assert_eq!(h.max(), Some(500));
        assert_relative_eq!(h.mean().unwrap(), 500.0, max_relative = 1e-9);
        let p50 = h.value_at_percentile(50.0).unwrap();
        assert!((500..=501).contains(&p50), "p50 was {p50}");
    }

    #[test]
    fn histogram_percentiles_match_brute_force_within_tolerance() {
        let mut h = LatencyHistogram::new(10_000_000, 3);
        // Linear ramp 1..=100_000 ns.
        for v in 1..=100_000u64 {
            h.record(v);
        }
        assert_eq!(h.count(), 100_000);

        for &p in &[50.0_f64, 90.0, 95.0, 99.0, 99.9] {
            let expected = (p / 100.0 * 100_000.0).ceil();
            let got = h.value_at_percentile(p).unwrap() as f64;
            // 3 significant digits => <= ~0.2% relative error in the
            // log region; allow 1% for the ceiling/equivalent-value math.
            assert_relative_eq!(got, expected, max_relative = 0.01);
        }
        // Exact running-sum mean of 1..=100_000 is 50_000.5.
        assert_relative_eq!(h.mean().unwrap(), 50_000.5, max_relative = 1e-6);
    }

    #[test]
    fn histogram_clamps_out_of_range_to_ceiling() {
        let mut h = LatencyHistogram::new(1_000, 2);
        h.record(10);
        h.record(5_000); // above ceiling
        assert_eq!(h.clamped(), 1);
        assert_eq!(h.count(), 2);
        // max tracks the true recorded value even when clamped for bucketing.
        assert_eq!(h.max(), Some(5_000));
        // p99 sits at/above the trackable ceiling, not the true value.
        let p99 = h.value_at_percentile(99.0).unwrap();
        assert!(p99 >= 1_000, "p99 {p99} should be at the ceiling");
    }

    #[test]
    fn histogram_merge_combines_distributions() {
        let mut a = LatencyHistogram::new(1_000_000, 3);
        let mut b = LatencyHistogram::new(1_000_000, 3);
        for v in 1..=500u64 {
            a.record(v);
        }
        for v in 501..=1000u64 {
            b.record(v);
        }
        a.merge(&b).unwrap();
        assert_eq!(a.count(), 1000);
        assert_eq!(a.min(), Some(1));
        assert_eq!(a.max(), Some(1000));
    }

    #[test]
    fn histogram_merge_rejects_mismatched_layout() {
        let mut a = LatencyHistogram::new(1_000_000, 3);
        let b = LatencyHistogram::new(1_000_000, 2);
        assert!(a.merge(&b).is_err());
    }

    #[test]
    fn parse_proc_stat_busy_excludes_idle_and_iowait() {
        // user nice system idle iowait irq softirq steal
        let content = "cpu  100 0 50 800 50 0 0 0\ncpu0 50 0 25 400 25 0 0 0\n";
        let sample = parse_proc_stat(content).unwrap();
        // total = 100+0+50+800+50 = 1000; busy = 1000 - (800+50) = 150.
        assert_eq!(sample.total, 1000);
        assert_eq!(sample.busy, 150);
    }

    #[test]
    fn parse_proc_stat_rejects_missing_line() {
        assert!(parse_proc_stat("intr 1 2 3\n").is_none());
    }

    #[test]
    fn cpu_busy_pct_is_delta_over_window() {
        let prev = CpuSample {
            busy: 100,
            total: 1000,
        };
        let cur = CpuSample {
            busy: 300,
            total: 1400,
        };
        // d_busy = 200, d_total = 400 => 50%.
        let pct = cpu_busy_pct(prev, cur).unwrap();
        assert_relative_eq!(pct, 50.0, max_relative = 1e-9);
    }

    #[test]
    fn cpu_busy_pct_rejects_stalled_clock() {
        let s = CpuSample { busy: 1, total: 1 };
        assert!(cpu_busy_pct(s, s).is_none());
    }

    #[test]
    fn parse_vm_rss_converts_kib_to_bytes() {
        let content = "Name:\tsng-bench\nVmRSS:\t   2048 kB\nThreads:\t4\n";
        assert_eq!(parse_vm_rss_bytes(content), Some(2048 * 1024));
    }

    #[test]
    fn parse_vm_rss_rejects_missing_field() {
        assert!(parse_vm_rss_bytes("Name:\tx\nThreads:\t1\n").is_none());
    }
}
