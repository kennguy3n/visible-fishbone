//! `sng-efficacy` — ShieldNet Gateway security-efficacy benchmark.
//!
//! Drives the real FW / SWG / ZTNA / IPS enforcement crates over a
//! known-bad + known-good corpus and emits `efficacy-report.json` for
//! the Go `business-report` consolidator (Section 7), plus a
//! human-readable summary to stdout.

mod dlp;
mod firewall;
mod ips;
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
}

impl Cli {
    /// When no per-function flag is set, run every driver.
    fn selected(&self) -> Selected {
        if self.firewall || self.swg || self.ztna || self.ips || self.dlp {
            Selected {
                firewall: self.firewall,
                swg: self.swg,
                ztna: self.ztna,
                ips: self.ips,
                dlp: self.dlp,
            }
        } else {
            Selected {
                firewall: true,
                swg: true,
                ztna: true,
                ips: true,
                dlp: true,
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
    println!("report written to {}", out.display());
}

fn kind_str(k: report::Kind) -> &'static str {
    match k {
        report::Kind::Enforcement => "block-rate",
        report::Kind::Detection => "detect-rate",
    }
}
