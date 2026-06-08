//! `sng-efficacy` — ShieldNet Gateway security-efficacy benchmark.
//!
//! Drives the real FW / SWG / ZTNA / IPS enforcement crates over a
//! known-bad + known-good corpus and emits `efficacy-report.json` for
//! the Go `business-report` consolidator (Section 7), plus a
//! human-readable summary to stdout.

mod dlp;
mod dns;
mod firewall;
mod ips;
mod malware;
mod report;
mod swg;
mod ztna;

use std::path::PathBuf;

use clap::Parser;

use report::{EfficacyReport, FunctionReport, Grade};

#[derive(Parser, Debug)]
#[command(
    name = "sng-efficacy",
    about = "ShieldNet Gateway security-efficacy harness (FW/SWG/ZTNA/IPS block & detection rates)"
)]
struct Cli {
    /// Output path for the JSON report.
    #[arg(long, default_value = "efficacy-report.json")]
    out: PathBuf,

    /// Git SHA to stamp into the report header.
    #[arg(long, env = "GIT_SHA", default_value = "unknown")]
    git_sha: String,

    /// Run only the firewall driver.
    #[arg(long)]
    firewall: bool,
    /// Run only the SWG driver.
    #[arg(long)]
    swg: bool,
    /// Run only the ZTNA driver.
    #[arg(long)]
    ztna: bool,
    /// Run only the IPS driver.
    #[arg(long)]
    ips: bool,
    /// Run only the DLP driver.
    #[arg(long)]
    dlp: bool,
    /// Run only the malware (YARA) driver.
    #[arg(long)]
    malware: bool,
    /// Run only the DNS threat-intel driver.
    #[arg(long)]
    dns: bool,
}

impl Cli {
    /// When no per-function flag is set, run every driver.
    fn selected(&self) -> Selected {
        if self.firewall
            || self.swg
            || self.ztna
            || self.ips
            || self.dlp
            || self.malware
            || self.dns
        {
            Selected {
                firewall: self.firewall,
                swg: self.swg,
                ztna: self.ztna,
                ips: self.ips,
                dlp: self.dlp,
                malware: self.malware,
                dns: self.dns,
            }
        } else {
            Selected {
                firewall: true,
                swg: true,
                ztna: true,
                ips: true,
                dlp: true,
                malware: true,
                dns: true,
            }
        }
    }
}

fn host() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown-host".into())
}

/// Which drivers to run this invocation.
struct Selected {
    firewall: bool,
    swg: bool,
    ztna: bool,
    ips: bool,
    dlp: bool,
    malware: bool,
    dns: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let sel = cli.selected();

    let mut functions: Vec<FunctionReport> = Vec::new();
    if sel.firewall {
        eprintln!("running firewall efficacy (sng-fw)...");
        functions.push(firewall::run().await);
    }
    if sel.swg {
        eprintln!("running SWG efficacy (sng-swg)...");
        functions.push(swg::run().await);
    }
    if sel.ztna {
        eprintln!("running ZTNA efficacy (sng-ztna)...");
        functions.push(ztna::run().await);
    }
    if sel.dlp {
        eprintln!("running DLP efficacy (sng-dlp)...");
        functions.push(dlp::run().await);
        eprintln!("running DLP ML NER efficacy (sng-dlp)...");
        functions.push(dlp::run_ml_ner().await);
    }
    if sel.malware {
        eprintln!("running malware efficacy (sng-swg YARA)...");
        functions.push(malware::run().await);
    }
    if sel.dns {
        eprintln!("running DNS threat-intel efficacy (sng-dns)...");
        functions.push(dns::run().await);
    }
    if sel.ips {
        eprintln!("running IPS efficacy (sng-ips + suricata)...");
        functions.push(ips::run().await);
    }

    let report = EfficacyReport::new(cli.git_sha.clone(), host(), functions);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    if let Err(e) = std::fs::write(&cli.out, &json) {
        eprintln!("failed to write {}: {e}", cli.out.display());
        std::process::exit(1);
    }

    print_summary(&report, &cli.out);

    // Honour the documented contract (README): exit 0 only when every
    // function PASSes, 2 otherwise. WARN and UNTESTED are both non-zero so a
    // half-run suite — e.g. IPS skipped because Suricata is absent — can never
    // masquerade as green at the exit-code level. The JSON always records the
    // true per-function verdict, so the consolidator renders the accurate
    // status regardless of the exit code.
    if report.overall_verdict != Grade::Pass {
        std::process::exit(2);
    }
}

fn print_summary(report: &EfficacyReport, out: &std::path::Path) {
    println!("\n=== ShieldNet Gateway — Security Efficacy ===");
    println!(
        "git={}  host={}  generated={}",
        report.git_sha, report.host, report.generated_at
    );
    println!(
        "{:<10} {:<12} {:>8} {:>8} {:>8} {:>8} {:>8}  {:<8}",
        "function", "kind", "bad", "good", "catch%", "fp%", "acc%", "verdict"
    );
    for f in &report.functions {
        if !f.tested {
            println!(
                "{:<10} {:<12} {:>8} {:>8} {:>8} {:>8} {:>8}  {:<8} ({})",
                f.function,
                kind_str(f.kind),
                "-",
                "-",
                "-",
                "-",
                "-",
                f.verdict.as_str(),
                f.untested_reason.as_deref().unwrap_or("untested"),
            );
            continue;
        }
        println!(
            "{:<10} {:<12} {:>8} {:>8} {:>7.1}% {:>7.1}% {:>7.1}%  {:<8}",
            f.function,
            kind_str(f.kind),
            f.bad_cases,
            f.good_cases,
            f.catch_rate * 100.0,
            f.false_positive_rate * 100.0,
            f.accuracy * 100.0,
            f.verdict.as_str(),
        );
    }
    println!("overall: {}", report.overall_verdict.as_str());

    // Throughput points (when measured) — real microbenchmarks over the hot
    // path. Flag debug builds so a slow unoptimized number is never mistaken
    // for product performance.
    let has_thr = report.functions.iter().any(|f| !f.throughput.is_empty());
    if has_thr {
        println!("\n--- throughput (hot path) ---");
        for f in &report.functions {
            for t in &f.throughput {
                let bw = t
                    .mb_per_sec
                    .map(|m| format!("  {m:.1} MiB/s"))
                    .unwrap_or_default();
                let dbg = if t.debug_build { "  [DEBUG build]" } else { "" };
                println!(
                    "{:<10} {:<10} {:>14.0} {:<12} {:>10.0} ns/op{}{}",
                    f.function, t.label, t.ops_per_sec, t.unit, t.per_op_ns, bw, dbg
                );
            }
        }
    }

    println!("\nreport written to {}", out.display());
}

fn kind_str(k: report::Kind) -> &'static str {
    match k {
        report::Kind::Enforcement => "block-rate",
        report::Kind::Detection => "detect-rate",
    }
}
