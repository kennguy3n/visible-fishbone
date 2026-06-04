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
use thiserror::Error;

use sng_bench::business_report::{BusinessReport, BusinessSku, SkuProfile};
use sng_bench::competitor::{self, InspectionDepth};
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
    /// Sweep every profile across all modes, packet sizes, and inspection
    /// depths and emit one consolidated business/RFP datasheet.
    BusinessReport(BusinessReportArgs),
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
        self.depth().label()
    }

    /// The library inspection-depth this CLI value denotes.
    fn depth(self) -> InspectionDepth {
        match self {
            Inspection::NoInspect => InspectionDepth::NoInspect,
            Inspection::UrlCat => InspectionDepth::UrlCat,
            Inspection::FullTls => InspectionDepth::FullTls,
        }
    }

    fn from_depth(depth: InspectionDepth) -> Self {
        match depth {
            InspectionDepth::NoInspect => Inspection::NoInspect,
            InspectionDepth::UrlCat => Inspection::UrlCat,
            InspectionDepth::FullTls => Inspection::FullTls,
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

impl RunArgs {
    fn to_spec(&self) -> RunSpec {
        RunSpec {
            interface: self.interface.clone(),
            packet_size: self.packet_size,
            policy_rules: self.policy_rules,
            inspection: self.inspection,
            ip_version: self.ip_version,
            l4: self.l4,
            target_pps: self.target_pps,
            seed: self.seed,
            duration: Duration::from_secs(self.duration),
            dry_run: self.dry_run,
            git_sha: self.git_sha.clone(),
        }
    }
}

/// The emitter + measurement parameters for one run, decoupled from the
/// CLI surface so both the single-mode subcommands and the multi-run
/// `business-report` sweep drive the same measurement core.
#[derive(Debug, Clone)]
struct RunSpec {
    interface: String,
    packet_size: u32,
    policy_rules: u32,
    inspection: Inspection,
    ip_version: CliIpVersion,
    l4: CliL4,
    target_pps: u64,
    seed: u64,
    duration: Duration,
    dry_run: bool,
    git_sha: Option<String>,
}

#[derive(Debug, Args)]
struct BusinessReportArgs {
    /// Directory of profile TOMLs to sweep; every `*.toml` is one SKU.
    #[arg(long, default_value = "bench/profiles")]
    profiles_dir: PathBuf,

    /// Egress interface for live (non-dry-run) transmission.
    #[arg(long, default_value = "lo")]
    interface: String,

    /// Per-run measurement duration in milliseconds. Kept small so the
    /// full sweep (profiles × packet sizes × depths × modes) is runnable
    /// on an unprivileged CI runner.
    #[arg(long, default_value_t = 250)]
    duration_ms: u64,

    /// Wire frame sizes to sweep.
    #[arg(long, value_delimiter = ',', default_values_t = [64u32, 512, 1500, 9000])]
    packet_sizes: Vec<u32>,

    /// Policy-rule count recorded on every run.
    #[arg(long, default_value_t = 100)]
    policy_rules: u32,

    /// IP version of the generated traffic.
    #[arg(long, value_enum, default_value_t = CliIpVersion::V4)]
    ip_version: CliIpVersion,

    /// L4 protocol for throughput/latency runs (concurrent-flows is always
    /// a SYN stress).
    #[arg(long, value_enum, default_value_t = CliL4::Udp)]
    l4: CliL4,

    /// Target packets-per-second (0 = transmit as fast as possible).
    #[arg(long, default_value_t = 0)]
    target_pps: u64,

    /// RNG seed for reproducible 5-tuple sampling.
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Directory the consolidated markdown + JSON are written to.
    #[arg(long, default_value = "bench/results")]
    out_dir: PathBuf,

    /// Git commit recorded in the document.
    #[arg(long, env = "SNG_BENCH_GIT_SHA")]
    git_sha: Option<String>,

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
    /// Concurrent-flows-drop fraction that counts as a regression.
    #[arg(long, default_value_t = 0.10)]
    concurrent_flows_drop: f64,
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
        Command::BusinessReport(args) => run_business_report(&args),
    }
}

fn run_compare(args: &CompareArgs) -> Result<std::process::ExitCode, BenchError> {
    let baseline = load_report(&args.baseline)?;
    let current = load_report(&args.current)?;
    let thresholds = RegressionThresholds {
        throughput_drop: args.throughput_drop,
        latency_increase: args.latency_increase,
        concurrent_flows_drop: args.concurrent_flows_drop,
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

fn load_profile(path: &Path) -> Result<SkuProfile, BenchError> {
    let s = std::fs::read_to_string(path).map_err(|source| BenchError::Io {
        path: path.display().to_string(),
        source,
    })?;
    toml::from_str(&s).map_err(|e| BenchError::Profile {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

/// Load every `*.toml` under `dir` as a SKU profile, sorted by path for a
/// deterministic sweep order.
fn load_profiles_dir(dir: &Path) -> Result<Vec<SkuProfile>, BenchError> {
    let entries = std::fs::read_dir(dir).map_err(|source| BenchError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|source| BenchError::Io {
                path: dir.display().to_string(),
                source,
            })?
            .path();
        if path.extension().is_some_and(|e| e == "toml") {
            paths.push(path);
        }
    }
    paths.sort();
    paths.iter().map(|p| load_profile(p)).collect()
}

fn build_emitter(spec: &RunSpec, l4: L4Proto) -> Result<Box<dyn TrafficGenerator>, BenchError> {
    let sampler = build_sampler(spec)?;
    let config = PacketConfig {
        frame_size: spec.packet_size,
        l4,
        // Locally-administered unicast MACs; the real bind MAC on a live
        // run is the egress NIC's, but AF_PACKET ignores the Ethernet
        // source on TX, and the destination is the edge ingress NIC.
        src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        ttl: 64,
    };
    let builder = PacketBuilder::new(config, sampler)?;
    if spec.dry_run {
        Ok(Box::new(DryRunGenerator::new(builder)))
    } else {
        let generator = RawSocketGenerator::open(&spec.interface, builder)?;
        Ok(Box::new(generator))
    }
}

fn build_sampler(spec: &RunSpec) -> Result<FiveTupleSampler, BenchError> {
    let (src, dst) = match spec.ip_version {
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
        spec.seed,
    )?)
}

/// Run one `(mode, spec)` against `profile` and assemble its report.
///
/// This is the shared measurement core: it builds the emitter, drives the
/// mode's measurement loop, samples resources, and — for throughput runs —
/// attaches the same-class competitor comparison. It does no I/O beyond
/// the run itself (no file write, no printing), so both the single-mode
/// subcommands and the `business-report` sweep reuse it identically.
fn run_single(
    mode: BenchMode,
    spec: &RunSpec,
    profile: &SkuProfile,
) -> Result<BenchmarkReport, BenchError> {
    // Concurrent-flows is a SYN stress regardless of the --l4 flag.
    let l4 = if matches!(mode, BenchMode::ConcurrentFlows) {
        L4Proto::TcpSyn
    } else {
        match spec.l4 {
            CliL4::Udp => L4Proto::Udp,
            CliL4::TcpSyn => L4Proto::TcpSyn,
        }
    };
    let mut emitter = build_emitter(spec, l4)?;
    let mut resources = ResourceMeasurement::new();

    let (throughput, latency, flows) = match mode {
        BenchMode::Throughput => {
            let t = run_throughput(emitter.as_mut(), spec, &mut resources)?;
            (Some(t), None, None)
        }
        BenchMode::Latency => {
            let l = run_latency(emitter.as_mut(), spec, &mut resources)?;
            (None, Some(l), None)
        }
        BenchMode::ConcurrentFlows => {
            let f = run_concurrent_flows(emitter.as_mut(), spec, &mut resources)?;
            (None, None, Some(f))
        }
    };

    // Attach a competitor comparison only when there is a measured
    // throughput number AND a same-class appliance to compare against.
    let competitor_comparison = throughput.as_ref().and_then(|t| {
        let cmp = competitor::comparison_for(profile.vcpus, spec.inspection.depth(), t.max_gbps);
        (!cmp.rows.is_empty()).then_some(cmp)
    });

    Ok(BenchmarkReport {
        schema_version: SCHEMA_VERSION,
        profile: profile.name.clone(),
        mode,
        unix_time_secs: now_secs(),
        git_sha: spec.git_sha.clone(),
        dimensions: RunDimensions {
            packet_size: spec.packet_size,
            policy_rules: spec.policy_rules,
            inspection: spec.inspection.label().to_string(),
        },
        throughput,
        latency,
        concurrent_flows: flows,
        resources: ResourceResult {
            mean_cpu_busy_pct: resources.mean_cpu_busy_pct().unwrap_or(0.0),
            peak_rss_bytes: resources.peak_rss_bytes(),
        },
        target_gbps: profile.target_gbps,
        competitor_comparison,
    })
}

fn run_mode(mode: BenchMode, args: &RunArgs) -> Result<std::process::ExitCode, BenchError> {
    if args.duration == 0 {
        return Err(BenchError::Config("duration must be > 0".to_string()));
    }
    let profile = load_profile(&args.profile)?;
    let report = run_single(mode, &args.to_spec(), &profile)?;

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
    spec: &RunSpec,
    resources: &mut ResourceMeasurement,
) -> Result<ThroughputResult, BenchError> {
    let counter = ThroughputMeasurement::new();
    let frame_len = emitter.frame_len() as u64;
    let start = Instant::now();
    let total = spec.duration;
    let mut pacer = Pacer::new(spec.target_pps, start);

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

        // Flat-out (`target_pps == 0`) runs with no inter-packet sleep; a
        // paced run sleeps until its next token is due.
        if spec.target_pps != 0 {
            pacer.sleep_until_next();
        }
    }

    let mean_gbps = if windows > 0 {
        gbps_sum / windows as f64
    } else {
        // Sub-second run: derive a single rate over the whole interval.
        let snap = counter.snapshot();
        rate_between(COUNTER_ZERO, snap, start.elapsed()).map_or(0.0, |r| r.gbps())
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
const COUNTER_ZERO: measurement::CounterSnapshot = measurement::CounterSnapshot {
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
    spec: &RunSpec,
    resources: &mut ResourceMeasurement,
) -> Result<LatencyResult, BenchError> {
    let mut hist = LatencyHistogram::new(1_000_000_000, 3);
    let start = Instant::now();
    let total = spec.duration;
    let mut pacer = Pacer::new(spec.target_pps, start);
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
        if spec.target_pps != 0 {
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
    spec: &RunSpec,
    resources: &mut ResourceMeasurement,
) -> Result<ConcurrentFlowsResult, BenchError> {
    let start = Instant::now();
    let total = spec.duration;
    let mut pacer = Pacer::new(spec.target_pps, start);
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
        if spec.target_pps != 0 {
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

/// Sweep every profile: throughput and latency across all packet sizes
/// and inspection depths, plus one concurrent-flows run per profile, then
/// assemble and persist one consolidated business report.
fn run_business_report(args: &BusinessReportArgs) -> Result<std::process::ExitCode, BenchError> {
    if args.duration_ms == 0 {
        return Err(BenchError::Config("duration-ms must be > 0".to_string()));
    }
    if args.packet_sizes.is_empty() {
        return Err(BenchError::Config(
            "at least one packet size required".to_string(),
        ));
    }
    let profiles = load_profiles_dir(&args.profiles_dir)?;
    if profiles.is_empty() {
        return Err(BenchError::Config(format!(
            "no .toml profiles found in {}",
            args.profiles_dir.display()
        )));
    }
    let duration = Duration::from_millis(args.duration_ms);
    // Throughput and latency vary with frame size and inspection depth, so
    // they sweep every cell. Concurrent-flows is a SYN flow-table-capacity
    // stress whose result is independent of packet size and depth, so it
    // runs once per profile (see below) rather than redundantly per cell.
    let swept_modes = [BenchMode::Throughput, BenchMode::Latency];

    let mut skus = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let mut reports = Vec::with_capacity(
            args.packet_sizes.len() * InspectionDepth::ALL.len() * swept_modes.len() + 1,
        );
        for &packet_size in &args.packet_sizes {
            for depth in InspectionDepth::ALL {
                let spec = RunSpec {
                    interface: args.interface.clone(),
                    packet_size,
                    policy_rules: args.policy_rules,
                    inspection: Inspection::from_depth(depth),
                    ip_version: args.ip_version,
                    l4: args.l4,
                    target_pps: args.target_pps,
                    seed: args.seed,
                    duration,
                    dry_run: args.dry_run,
                    git_sha: args.git_sha.clone(),
                };
                for mode in swept_modes {
                    reports.push(run_single(mode, &spec, &profile)?);
                }
            }
        }
        // One concurrent-flows run per profile at a representative point
        // (smallest frame, no-inspect): the SYN stress saturates the flow
        // table regardless of frame size or inspection depth.
        let cf_spec = RunSpec {
            interface: args.interface.clone(),
            packet_size: args.packet_sizes.iter().copied().min().unwrap_or(64),
            policy_rules: args.policy_rules,
            inspection: Inspection::from_depth(InspectionDepth::NoInspect),
            ip_version: args.ip_version,
            l4: args.l4,
            target_pps: args.target_pps,
            seed: args.seed,
            duration,
            dry_run: args.dry_run,
            git_sha: args.git_sha.clone(),
        };
        reports.push(run_single(BenchMode::ConcurrentFlows, &cf_spec, &profile)?);
        skus.push(BusinessSku::new(profile, reports));
    }

    let doc = BusinessReport::new(now_secs(), args.git_sha.clone(), skus);
    let (md_path, json_path) = write_business_report(&args.out_dir, &doc)?;
    println!("{}", doc.to_markdown());
    println!(
        "\nbusiness report written to {} and {}",
        md_path.display(),
        json_path.display()
    );
    Ok(std::process::ExitCode::SUCCESS)
}

fn write_business_report(
    out_dir: &Path,
    doc: &BusinessReport,
) -> Result<(PathBuf, PathBuf), BenchError> {
    std::fs::create_dir_all(out_dir).map_err(|source| BenchError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;
    let stem = format!("business-report-{}", doc.generated_unix_secs);
    let md_path = out_dir.join(format!("{stem}.md"));
    let json_path = out_dir.join(format!("{stem}.json"));
    std::fs::write(&md_path, doc.to_markdown()).map_err(|source| BenchError::Io {
        path: md_path.display().to_string(),
        source,
    })?;
    std::fs::write(&json_path, doc.to_json()?).map_err(|source| BenchError::Io {
        path: json_path.display().to_string(),
        source,
    })?;
    Ok((md_path, json_path))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

    #[test]
    fn inspection_depth_round_trips() {
        for d in InspectionDepth::ALL {
            assert_eq!(Inspection::from_depth(d).depth(), d);
        }
    }

    fn test_spec(inspection: Inspection) -> RunSpec {
        RunSpec {
            interface: "lo".to_string(),
            packet_size: 1500,
            policy_rules: 100,
            inspection,
            ip_version: CliIpVersion::V4,
            l4: CliL4::Udp,
            target_pps: 0,
            seed: 7,
            duration: Duration::from_millis(20),
            dry_run: true,
            git_sha: None,
        }
    }

    fn test_profile() -> SkuProfile {
        SkuProfile {
            name: "branch-medium".to_string(),
            vcpus: 4,
            ram_gb: 8,
            nic_gbps: 10.0,
            target_gbps: 5.0,
        }
    }

    #[test]
    fn run_single_throughput_attaches_competitor_comparison() {
        let r = run_single(
            BenchMode::Throughput,
            &test_spec(Inspection::NoInspect),
            &test_profile(),
        )
        .unwrap();
        assert!(r.throughput.is_some());
        let cmp = r
            .competitor_comparison
            .as_ref()
            .expect("comparison attached");
        assert_eq!(cmp.feature, "firewall throughput");
        assert!(!cmp.rows.is_empty());
        // Report round-trips with the new field populated.
        assert_eq!(
            BenchmarkReport::from_json(&r.to_json().unwrap()).unwrap(),
            r
        );
    }

    #[test]
    fn run_single_latency_has_no_competitor_comparison() {
        let r = run_single(
            BenchMode::Latency,
            &test_spec(Inspection::FullTls),
            &test_profile(),
        )
        .unwrap();
        assert!(r.latency.is_some());
        assert!(r.competitor_comparison.is_none());
    }

    #[test]
    fn profiles_dir_loads_committed_skus() {
        let profiles = load_profiles_dir(Path::new("profiles")).unwrap();
        assert!(profiles.iter().any(|p| p.name == "cloud-pop-small"));
        assert!(profiles.len() >= 4, "expected the committed profile set");
    }
}
