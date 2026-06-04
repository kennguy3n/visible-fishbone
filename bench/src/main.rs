//! `sng-bench` — ShieldNet Gateway edge data-path benchmark harness.
//!
//! The harness drives synthetic traffic at an `sng-edge` data-path NIC
//! and measures it in three modes: maximum throughput, per-packet
//! latency, and maximum concurrent flows. Results are written as a JSON
//! artifact (consumed by the weekly `benchmark.yml` workflow) plus a
//! markdown summary, and can be diffed against a previous run to flag
//! regressions.
//!
//! Running the live modes requires `CAP_NET_RAW` (raw `AF_PACKET`
//! transmission) and a real edge in-path. `--dry-run` exercises the full
//! craft + measure + report pipeline in-process without privileges, which
//! is what makes the harness self-testable on an unprivileged CI runner.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use thiserror::Error;

use sng_bench::measurement::{
    self, LatencyHistogram, ResourceMeasurement, ThroughputMeasurement, rate_between,
};
use sng_bench::report::{
    self, BenchMode, BenchmarkReport, ConcurrentFlowsResult, LatencyResult, RegressionThresholds,
    ResourceResult, RunDimensions, SCHEMA_VERSION, ThroughputResult, detect_regression,
};
use sng_bench::traffic_gen::{
    DryRunGenerator, FiveTupleSampler, L4Proto, PacketBuilder, PacketConfig, RawSocketGenerator,
    Subnet, TrafficError, TrafficGenerator,
};

/// Top-level harness errors.
#[derive(Debug, Error)]
enum BenchError {
    #[error("traffic: {0}")]
    Traffic(#[from] TrafficError),
    #[error("report: {0}")]
    Report(#[from] report::ReportError),
    #[error("resource: {0}")]
    Resource(#[from] measurement::ResourceError),
    #[error("io {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("profile {path}: {detail}")]
    Profile { path: String, detail: String },
    #[error("regression check: {0}")]
    Regression(String),
    #[error("config: {0}")]
    Config(String),
}

/// Reproducible benchmark harness for the SNG edge data path.
#[derive(Debug, Parser)]
#[command(name = "sng-bench", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Measure maximum throughput (pps / Gbps).
    Throughput(RunArgs),
    /// Measure per-packet latency percentiles.
    Latency(RunArgs),
    /// Measure maximum concurrent active flows.
    ConcurrentFlows(RunArgs),
    /// Compare two report JSON files and flag regressions.
    Compare(CompareArgs),
}

/// IP version selector for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliIpVersion {
    V4,
    V6,
}

/// L4 protocol selector for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliL4 {
    Udp,
    TcpSyn,
}

/// Inspection-depth dimension (recorded in the report; the edge under
/// test is configured out-of-band to match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Inspection {
    NoInspect,
    UrlCat,
    FullTls,
}

impl Inspection {
    fn label(self) -> &'static str {
        match self {
            Inspection::NoInspect => "no-inspect",
            Inspection::UrlCat => "url-cat",
            Inspection::FullTls => "full-tls",
        }
    }
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Path to the edge-SKU profile TOML (sets target throughput).
    #[arg(long, env = "SNG_BENCH_PROFILE")]
    profile: PathBuf,

    /// Egress interface to transmit synthetic frames on.
    #[arg(long, default_value = "lo")]
    interface: String,

    /// Measurement duration in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Wire frame size in bytes (64, 512, 1500, 9000).
    #[arg(long, default_value_t = 1500)]
    packet_size: u32,

    /// Number of policy rules loaded on the edge under test.
    #[arg(long, default_value_t = 100)]
    policy_rules: u32,

    /// Inspection depth dimension.
    #[arg(long, value_enum, default_value_t = Inspection::NoInspect)]
    inspection: Inspection,

    /// IP version of the generated traffic.
    #[arg(long, value_enum, default_value_t = CliIpVersion::V4)]
    ip_version: CliIpVersion,

    /// L4 protocol of the generated traffic.
    #[arg(long, value_enum, default_value_t = CliL4::Udp)]
    l4: CliL4,

    /// Target packets-per-second (0 = transmit as fast as possible).
    #[arg(long, default_value_t = 0)]
    target_pps: u64,

    /// RNG seed for reproducible 5-tuple sampling.
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Directory the JSON report is written to.
    #[arg(long, default_value = "bench/results")]
    out_dir: PathBuf,

    /// Git commit recorded in the report.
    #[arg(long, env = "SNG_BENCH_GIT_SHA")]
    git_sha: Option<String>,

    /// Optional baseline report JSON to compare this run against.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Exercise the full pipeline in-process without raw sockets or root.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct CompareArgs {
    /// Baseline (previous) report JSON.
    #[arg(long)]
    baseline: PathBuf,
    /// Current report JSON.
    #[arg(long)]
    current: PathBuf,
    /// Throughput-drop fraction that counts as a regression.
    #[arg(long, default_value_t = 0.10)]
    throughput_drop: f64,
    /// Latency-increase fraction that counts as a regression.
    #[arg(long, default_value_t = 0.10)]
    latency_increase: f64,
}

/// Per-edge-SKU profile loaded from `bench/profiles/*.toml`.
#[derive(Debug, Clone, Deserialize)]
struct Profile {
    name: String,
    #[allow(dead_code)]
    vcpus: u32,
    #[allow(dead_code)]
    ram_gb: u32,
    #[allow(dead_code)]
    nic_gbps: f64,
    target_gbps: f64,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sng-bench: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Exit code 2 signals "ran successfully but found a regression" so the
/// CI workflow can alert without conflating it with a harness crash.
const EXIT_REGRESSION: u8 = 2;

fn run(cli: Cli) -> Result<std::process::ExitCode, BenchError> {
    match cli.command {
        Command::Throughput(args) => run_mode(BenchMode::Throughput, &args),
        Command::Latency(args) => run_mode(BenchMode::Latency, &args),
        Command::ConcurrentFlows(args) => run_mode(BenchMode::ConcurrentFlows, &args),
        Command::Compare(args) => run_compare(&args),
    }
}

fn run_compare(args: &CompareArgs) -> Result<std::process::ExitCode, BenchError> {
    let baseline = load_report(&args.baseline)?;
    let current = load_report(&args.current)?;
    let thresholds = RegressionThresholds {
        throughput_drop: args.throughput_drop,
        latency_increase: args.latency_increase,
    };
    let rr = detect_regression(&baseline, &current, thresholds).map_err(BenchError::Regression)?;
    if rr.has_regression() {
        eprintln!("REGRESSION DETECTED:");
        for r in &rr.regressions {
            eprintln!(
                "  {} {:.3} -> {:.3} ({:+.1}%)",
                r.metric,
                r.previous,
                r.current,
                r.change_fraction * 100.0
            );
        }
        Ok(std::process::ExitCode::from(EXIT_REGRESSION))
    } else {
        println!("no regression: all metrics within thresholds");
        Ok(std::process::ExitCode::SUCCESS)
    }
}

fn load_report(path: &Path) -> Result<BenchmarkReport, BenchError> {
    let s = std::fs::read_to_string(path).map_err(|source| BenchError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(BenchmarkReport::from_json(&s)?)
}

fn load_profile(path: &Path) -> Result<Profile, BenchError> {
    let s = std::fs::read_to_string(path).map_err(|source| BenchError::Io {
        path: path.display().to_string(),
        source,
    })?;
    toml::from_str(&s).map_err(|e| BenchError::Profile {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

fn build_emitter(args: &RunArgs, l4: L4Proto) -> Result<Box<dyn TrafficGenerator>, BenchError> {
    let sampler = build_sampler(args)?;
    let config = PacketConfig {
        frame_size: args.packet_size,
        l4,
        // Locally-administered unicast MACs; the real bind MAC on a live
        // run is the egress NIC's, but AF_PACKET ignores the Ethernet
        // source on TX, and the destination is the edge ingress NIC.
        src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        ttl: 64,
    };
    let builder = PacketBuilder::new(config, sampler)?;
    if args.dry_run {
        Ok(Box::new(DryRunGenerator::new(builder)))
    } else {
        let generator = RawSocketGenerator::open(&args.interface, builder)?;
        Ok(Box::new(generator))
    }
}

fn build_sampler(args: &RunArgs) -> Result<FiveTupleSampler, BenchError> {
    let (src, dst) = match args.ip_version {
        CliIpVersion::V4 => (
            Subnet::V4 {
                base: std::net::Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8,
            },
            Subnet::V4 {
                base: std::net::Ipv4Addr::new(198, 18, 0, 0),
                prefix: 15, // RFC 2544 benchmarking range
            },
        ),
        CliIpVersion::V6 => (
            Subnet::V6 {
                base: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                prefix: 32,
            },
            Subnet::V6 {
                base: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 0),
                prefix: 32,
            },
        ),
    };
    Ok(FiveTupleSampler::new(
        src,
        dst,
        (1024, 65_535),
        (1, 1024),
        args.seed,
    )?)
}

fn run_mode(mode: BenchMode, args: &RunArgs) -> Result<std::process::ExitCode, BenchError> {
    if args.duration == 0 {
        return Err(BenchError::Config("duration must be > 0".to_string()));
    }
    let profile = load_profile(&args.profile)?;
    // Concurrent-flows is a SYN stress regardless of the --l4 flag.
    let l4 = if matches!(mode, BenchMode::ConcurrentFlows) {
        L4Proto::TcpSyn
    } else {
        match args.l4 {
            CliL4::Udp => L4Proto::Udp,
            CliL4::TcpSyn => L4Proto::TcpSyn,
        }
    };
    let mut emitter = build_emitter(args, l4)?;
    let mut resources = ResourceMeasurement::new();

    let (throughput, latency, flows) = match mode {
        BenchMode::Throughput => {
            let t = run_throughput(emitter.as_mut(), args, &mut resources)?;
            (Some(t), None, None)
        }
        BenchMode::Latency => {
            let l = run_latency(emitter.as_mut(), args, &mut resources)?;
            (None, Some(l), None)
        }
        BenchMode::ConcurrentFlows => {
            let f = run_concurrent_flows(emitter.as_mut(), args, &mut resources)?;
            (None, None, Some(f))
        }
    };

    let report = BenchmarkReport {
        schema_version: SCHEMA_VERSION,
        profile: profile.name.clone(),
        mode,
        unix_time_secs: now_secs(),
        git_sha: args.git_sha.clone(),
        dimensions: RunDimensions {
            packet_size: args.packet_size,
            policy_rules: args.policy_rules,
            inspection: args.inspection.label().to_string(),
        },
        throughput,
        latency,
        concurrent_flows: flows,
        resources: ResourceResult {
            mean_cpu_busy_pct: resources.mean_cpu_busy_pct().unwrap_or(0.0),
            peak_rss_bytes: resources.peak_rss_bytes(),
        },
        target_gbps: profile.target_gbps,
    };

    let out_path = write_report(&args.out_dir, &report)?;
    println!("{}", report.to_markdown());
    println!("\nreport written to {}", out_path.display());

    if let Some(baseline_path) = &args.baseline {
        let baseline = load_report(baseline_path)?;
        let rr = detect_regression(&baseline, &report, RegressionThresholds::default())
            .map_err(BenchError::Regression)?;
        if rr.has_regression() {
            eprintln!("REGRESSION DETECTED vs {}", baseline_path.display());
            for r in &rr.regressions {
                eprintln!(
                    "  {} {:.3} -> {:.3} ({:+.1}%)",
                    r.metric,
                    r.previous,
                    r.current,
                    r.change_fraction * 100.0
                );
            }
            return Ok(std::process::ExitCode::from(EXIT_REGRESSION));
        }
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Throughput: pace transmission to `target_pps` (or run flat-out when
/// 0), windowing the cumulative counters into a per-second rate series.
fn run_throughput(
    emitter: &mut dyn TrafficGenerator,
    args: &RunArgs,
    resources: &mut ResourceMeasurement,
) -> Result<ThroughputResult, BenchError> {
    let counter = ThroughputMeasurement::new();
    let frame_len = emitter.frame_len() as u64;
    let start = Instant::now();
    let total = Duration::from_secs(args.duration);
    let mut pacer = Pacer::new(args.target_pps, start);

    let mut last_snap = counter.snapshot();
    let mut last_window = start;
    let mut max_pps = 0.0f64;
    let mut max_gbps = 0.0f64;
    let mut gbps_sum = 0.0f64;
    let mut windows = 0u64;
    // First resource sample establishes the CPU baseline.
    let _ = resources.sample();

    while start.elapsed() < total {
        let due = pacer.due(Instant::now());
        for _ in 0..due {
            emitter.emit()?;
            counter.record(frame_len);
        }
        pacer.advance(due);

        if last_window.elapsed() >= Duration::from_secs(1) {
            let now = Instant::now();
            let snap = counter.snapshot();
            if let Some(rate) = rate_between(last_snap, snap, now.duration_since(last_window)) {
                max_pps = max_pps.max(rate.pps);
                max_gbps = max_gbps.max(rate.gbps());
                gbps_sum += rate.gbps();
                windows += 1;
            }
            last_snap = snap;
            last_window = now;
            let _ = resources.sample();
        }

        if args.target_pps == 0 {
            // Flat-out: no sleep, but yield occasionally so the OS can
            // schedule the sampling work.
            if due == 0 {
                std::hint::spin_loop();
            }
        } else {
            pacer.sleep_until_next();
        }
    }

    let mean_gbps = if windows > 0 {
        gbps_sum / windows as f64
    } else {
        // Sub-second run: derive a single rate over the whole interval.
        let snap = counter.snapshot();
        rate_between(CounterZero, snap, start.elapsed()).map_or(0.0, |r| r.gbps())
    };

    Ok(ThroughputResult {
        max_pps: if windows > 0 {
            max_pps
        } else {
            mean_pps(&counter, start)
        },
        max_gbps: if windows > 0 { max_gbps } else { mean_gbps },
        mean_gbps,
    })
}

/// Zero snapshot sentinel for the sub-second mean fallback.
#[allow(non_upper_case_globals)]
const CounterZero: measurement::CounterSnapshot = measurement::CounterSnapshot {
    packets: 0,
    bytes: 0,
};

fn mean_pps(counter: &ThroughputMeasurement, start: Instant) -> f64 {
    let secs = start.elapsed().as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        counter.snapshot().packets as f64 / secs
    }
}

/// Latency: time each craft+transmit and record into an HDR histogram.
///
/// On a live bench the generator is pointed at the edge ingress with a
/// paired receiver on egress; this loop measures the send-path component
/// per packet, which is the part the harness owns. The histogram tracks
/// up to 1s with 3 significant digits.
fn run_latency(
    emitter: &mut dyn TrafficGenerator,
    args: &RunArgs,
    resources: &mut ResourceMeasurement,
) -> Result<LatencyResult, BenchError> {
    let mut hist = LatencyHistogram::new(1_000_000_000, 3);
    let start = Instant::now();
    let total = Duration::from_secs(args.duration);
    let mut pacer = Pacer::new(args.target_pps, start);
    let mut last_window = start;
    let _ = resources.sample();

    while start.elapsed() < total {
        let due = pacer.due(Instant::now()).max(1);
        for _ in 0..due {
            let t0 = Instant::now();
            emitter.emit()?;
            let elapsed_ns = t0.elapsed().as_nanos();
            // Saturate at u64 range; the histogram clamps to its ceiling.
            hist.record(u64::try_from(elapsed_ns).unwrap_or(u64::MAX));
        }
        pacer.advance(due);
        if args.target_pps != 0 {
            pacer.sleep_until_next();
        }
        if last_window.elapsed() >= Duration::from_secs(1) {
            let _ = resources.sample();
            last_window = Instant::now();
        }
    }

    Ok(LatencyResult {
        p50_ns: hist.p50().unwrap_or(0),
        p95_ns: hist.p95().unwrap_or(0),
        p99_ns: hist.p99().unwrap_or(0),
        max_ns: hist.max().unwrap_or(0),
        clamped: hist.clamped(),
    })
}

/// Concurrent flows: emit unique-5-tuple SYNs and count the distinct
/// flows offered over the run.
///
/// Each emitted SYN carries a freshly sampled 5-tuple drawn from a large
/// address/port space, so every packet represents a new flow the edge
/// must insert into its flow table. On a live bench the egress receiver
/// detects the point at which new-flow setup starts dropping; the
/// generator-side metric reported here is the number of distinct flows
/// successfully offered, which is the harness's half of that measurement.
fn run_concurrent_flows(
    emitter: &mut dyn TrafficGenerator,
    args: &RunArgs,
    resources: &mut ResourceMeasurement,
) -> Result<ConcurrentFlowsResult, BenchError> {
    let start = Instant::now();
    let total = Duration::from_secs(args.duration);
    let mut pacer = Pacer::new(args.target_pps, start);
    let mut flows = 0u64;
    let mut last_window = start;
    let _ = resources.sample();

    while start.elapsed() < total {
        let due = pacer.due(Instant::now()).max(1);
        for _ in 0..due {
            emitter.emit()?;
            flows += 1;
        }
        pacer.advance(due);
        if args.target_pps != 0 {
            pacer.sleep_until_next();
        }
        if last_window.elapsed() >= Duration::from_secs(1) {
            let _ = resources.sample();
            last_window = Instant::now();
        }
    }

    Ok(ConcurrentFlowsResult {
        max_active_flows: flows,
    })
}

/// A token-bucket-style pacer that releases packets at a target rate.
#[derive(Debug)]
struct Pacer {
    target_pps: u64,
    start: Instant,
    sent: u64,
}

impl Pacer {
    fn new(target_pps: u64, start: Instant) -> Self {
        Self {
            target_pps,
            start,
            sent: 0,
        }
    }

    /// Number of packets due to be sent by `now` to stay on the target
    /// rate, capped at a burst ceiling so a long stall does not release a
    /// huge spike. With `target_pps == 0` the caller transmits flat-out
    /// and this returns a fixed batch size.
    fn due(&self, now: Instant) -> u64 {
        if self.target_pps == 0 {
            return 256;
        }
        let elapsed = now.duration_since(self.start).as_secs_f64();
        let should_have_sent = (elapsed * self.target_pps as f64) as u64;
        let due = should_have_sent.saturating_sub(self.sent);
        due.min(4096)
    }

    fn advance(&mut self, n: u64) {
        self.sent += n;
    }

    /// Sleep until the next packet is due (paced mode only).
    fn sleep_until_next(&self) {
        if self.target_pps == 0 {
            return;
        }
        let next_due_time =
            self.start + Duration::from_secs_f64((self.sent as f64 + 1.0) / self.target_pps as f64);
        let now = Instant::now();
        if next_due_time > now {
            let sleep = next_due_time - now;
            // Cap the sleep so we re-check the deadline frequently.
            std::thread::sleep(sleep.min(Duration::from_millis(1)));
        }
    }
}

fn write_report(out_dir: &Path, report: &BenchmarkReport) -> Result<PathBuf, BenchError> {
    std::fs::create_dir_all(out_dir).map_err(|source| BenchError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;
    let filename = format!(
        "{}-{}-{}.json",
        report.profile,
        report.mode.label(),
        report.unix_time_secs
    );
    let path = out_dir.join(filename);
    let json = report.to_json()?;
    std::fs::write(&path, json).map_err(|source| BenchError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(path)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_releases_at_target_rate() {
        let start = Instant::now();
        let p = Pacer::new(1000, start);
        // 0.5s in, ~500 packets should be due.
        let due = p.due(start + Duration::from_millis(500));
        assert!((250..=4096).contains(&due), "due was {due}");
    }

    #[test]
    fn pacer_flat_out_returns_fixed_batch() {
        let p = Pacer::new(0, Instant::now());
        assert_eq!(p.due(Instant::now()), 256);
    }

    #[test]
    fn pacer_caps_burst_after_stall() {
        let start = Instant::now();
        let p = Pacer::new(1_000_000, start);
        // 10s later at 1M pps would be 10M packets; must cap at 4096.
        let due = p.due(start + Duration::from_secs(10));
        assert_eq!(due, 4096);
    }

    #[test]
    fn inspection_labels_are_stable() {
        assert_eq!(Inspection::NoInspect.label(), "no-inspect");
        assert_eq!(Inspection::UrlCat.label(), "url-cat");
        assert_eq!(Inspection::FullTls.label(), "full-tls");
    }
}
