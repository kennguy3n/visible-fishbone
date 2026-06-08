//! IPS efficacy: replay a known-bad + known-good PCAP corpus through a
//! *real* Suricata process configured by SNG's own
//! `sng_ips::ConfigGenerator`, then normalise the resulting EVE alerts
//! through `sng_ips::EveRecord` / `EveAlert::to_ips_event`. Measures
//! detection-rate (bad PCAPs that alerted) and false-positive-rate
//! (good PCAPs that alerted).
//!
//! Unlike the FW/SWG/ZTNA drivers — whose decision logic lives inside
//! SNG — detection itself is Suricata's job; SNG owns the config
//! generation and the EVE→event normalisation. This driver exercises
//! that real seam end-to-end. If the `suricata` binary is not present
//! the function is reported as UNTESTED rather than silently skipped.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use sng_ips::{ConfigGenerator, EveRecord, IpsConfigInput, IpsRuntime};

use crate::report::{Case, FunctionReport, Kind, Targets};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/ips")
}

/// Best-effort cleanup of the per-run work dir on every exit path (the happy
/// path and the early UNTESTED returns alike), so repeated runs on a
/// long-lived CI runner don't accumulate stale `sng-efficacy-ips-*` dirs.
struct WorkDirGuard(PathBuf);

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn suricata_available() -> Option<String> {
    let out = tokio::process::Command::new("suricata")
        .arg("-V")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    if out.status.success() {
        // `suricata -V` prints e.g. "This is Suricata version 6.0.4 RELEASE";
        // normalise to a compact "Suricata 6.0.4".
        let raw = String::from_utf8_lossy(&out.stdout);
        let version = raw
            .split("version")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .map(|v| format!("Suricata {v}"))
            .unwrap_or_else(|| raw.trim().to_string());
        Some(version)
    } else {
        None
    }
}

/// Render SNG's suricata.yaml pointing at our corpus rule file and a
/// per-run EVE log path.
fn render_config(rules: &Path, eve: &Path, stats_sock: &Path) -> Result<String, String> {
    let mut input = IpsConfigInput::defaults(IpsRuntime::Ids);
    input.rule_file_path = rules.to_path_buf();
    input.eve_log_path = eve.to_path_buf();
    input.stats_socket_path = stats_sock.to_path_buf();
    // Corpus client is 10.0.0.50 -> default HOME_NET 10.0.0.0/8 already
    // covers it.
    ConfigGenerator::new()
        .render(&input)
        .map(|c| c.text().to_string())
        .map_err(|e| format!("sng-ips ConfigGenerator render failed: {e}"))
}

/// Run Suricata offline over a single PCAP and return the number of
/// EVE `alert` records, normalised through SNG's `EveAlert`.
async fn alerts_for_pcap(
    yaml: &Path,
    pcap: &Path,
    work: &Path,
    eve: &Path,
) -> Result<usize, String> {
    // Fresh EVE log per pcap so counts don't accumulate. A missing file is
    // the normal first-iteration case; any other removal error means a stale
    // EVE could survive and Suricata would *append* to it, folding the
    // previous pcap's alerts into this one's count and corrupting the
    // confusion matrix. Treat that as a hard failure (the caller maps Err to
    // UNTESTED) rather than silently fabricating inflated TP/FP numbers.
    match tokio::fs::remove_file(eve).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "could not clear stale EVE log {}: {e}",
                eve.display()
            ));
        }
    }
    let status = tokio::process::Command::new("suricata")
        .args(["-c"])
        .arg(yaml)
        .arg("-r")
        .arg(pcap)
        .arg("-l")
        .arg(work)
        .args(["--set", "unix-command.enabled=no"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("failed to spawn suricata: {e}"))?;
    if !status.success() {
        return Err(format!(
            "suricata exited with {status} on {}",
            pcap.display()
        ));
    }
    let eve_text = match tokio::fs::read_to_string(eve).await {
        Ok(t) => t,
        // No EVE file => no events => zero alerts (a clean good pcap).
        Err(_) => return Ok(0),
    };
    let mut alerts = 0usize;
    for line in eve_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match EveRecord::parse_line(line) {
            Ok(EveRecord::Alert(a)) => {
                // Exercise the real normalisation seam.
                let _ev = a.to_ips_event();
                alerts += 1;
            }
            Ok(_) => {}
            // A malformed EVE line is a normalisation failure, not a
            // detection signal; skip it.
            Err(_) => {}
        }
    }
    Ok(alerts)
}

struct PcapCase {
    file: &'static str,
    bad: bool,
    desc: &'static str,
}

fn corpus() -> Vec<PcapCase> {
    vec![
        PcapCase {
            file: "bad-eicar.pcap",
            bad: true,
            desc: "EICAR antivirus test string (malware marker)",
        },
        PcapCase {
            file: "bad-traversal.pcap",
            bad: true,
            desc: "directory-traversal exploit (/etc/passwd)",
        },
        PcapCase {
            file: "bad-sqli.pcap",
            bad: true,
            desc: "SQL-injection UNION SELECT probe",
        },
        PcapCase {
            file: "bad-c2-beacon.pcap",
            bad: true,
            desc: "known C2 beacon marker",
        },
        PcapCase {
            file: "bad-ransomware.pcap",
            bad: true,
            desc: "ransomware ransom-note delivery",
        },
        PcapCase {
            file: "bad-lateral-smb.pcap",
            bad: true,
            desc: "SMB PsExec lateral movement (east-west)",
        },
        PcapCase {
            file: "bad-dns-tunnel.pcap",
            bad: true,
            desc: "DNS tunneling long encoded label",
        },
        PcapCase {
            file: "good-https-get.pcap",
            bad: false,
            desc: "benign HTTP GET /index.html",
        },
        PcapCase {
            file: "good-api-call.pcap",
            bad: false,
            desc: "benign JSON API POST",
        },
        PcapCase {
            file: "good-dns.pcap",
            bad: false,
            desc: "benign DNS query",
        },
        PcapCase {
            file: "good-health.pcap",
            bad: false,
            desc: "benign load-balancer health check",
        },
        PcapCase {
            file: "good-smb.pcap",
            bad: false,
            desc: "benign internal SMB file access",
        },
        PcapCase {
            file: "good-dns-txt.pcap",
            bad: false,
            desc: "benign DNS TXT (SPF) lookup",
        },
    ]
}

pub async fn run() -> FunctionReport {
    let version = match suricata_available().await {
        Some(v) => v,
        None => {
            return FunctionReport::untested(
                "ips",
                "sng-ips",
                Kind::Detection,
                "suricata binary not found on PATH; install Suricata to measure IPS detection efficacy",
            );
        }
    };

    let fixtures = fixtures_dir();
    let rules = fixtures.join("test.rules");
    if !rules.exists() {
        return FunctionReport::untested(
            "ips",
            "sng-ips",
            Kind::Detection,
            "IPS rule/PCAP fixtures missing (expected bench/efficacy/fixtures/ips)",
        );
    }

    // Per-process work dir so concurrent harness runs (or a shared CI
    // runner) don't clobber each other's rendered config / EVE logs.
    let work = std::env::temp_dir().join(format!("sng-efficacy-ips-{}", std::process::id()));
    if let Err(e) = tokio::fs::create_dir_all(&work).await {
        return FunctionReport::untested(
            "ips",
            "sng-ips",
            Kind::Detection,
            &format!("could not create IPS work dir {}: {e}", work.display()),
        );
    }
    // Remove the work dir on every return path below (UNTESTED early-returns
    // and the happy path), now that it's guaranteed to exist.
    let _work_guard = WorkDirGuard(work.clone());
    let eve = work.join("eve.json");
    let stats_sock = work.join("suricata-command.socket");
    let yaml_path = work.join("suricata.yaml");

    let yaml = match render_config(&rules, &eve, &stats_sock) {
        Ok(y) => y,
        Err(e) => return FunctionReport::untested("ips", "sng-ips", Kind::Detection, &e),
    };
    if let Err(e) = tokio::fs::write(&yaml_path, &yaml).await {
        return FunctionReport::untested(
            "ips",
            "sng-ips",
            Kind::Detection,
            &format!("could not write rendered suricata.yaml: {e}"),
        );
    }

    let mut cases = Vec::new();
    for c in corpus() {
        let pcap = fixtures.join(c.file);
        // A Suricata execution failure means the measurement is unreliable,
        // not a detection signal. Report the whole function UNTESTED rather
        // than fabricating a verdict: scoring `alerted = false` here would
        // silently book a good case as a clean true-negative (and a bad case
        // as a missed detection), inflating the matrix from a broken run.
        let n = match alerts_for_pcap(&yaml_path, &pcap, &work, &eve).await {
            Ok(n) => n,
            Err(e) => {
                return FunctionReport::untested(
                    "ips",
                    "sng-ips",
                    Kind::Detection,
                    &format!("suricata execution failed on {}: {e}", c.file),
                );
            }
        };
        // bad => expect >=1 alert (detected); good => expect 0 alerts.
        let alerted = n > 0;
        let correct = if c.bad { alerted } else { !alerted };
        cases.push(Case {
            description: c.desc.into(),
            bad: c.bad,
            expected: if c.bad { "detect" } else { "no-alert" }.into(),
            actual: format!("{n} alert(s)"),
            correct,
        });
    }

    FunctionReport::from_cases(
        "ips",
        "sng-ips",
        Kind::Detection,
        Targets::default(),
        cases,
        Some(format!(
            "Real {version} driven by SNG's ConfigGenerator-rendered suricata.yaml; \
             EVE alerts normalised through sng_ips::EveAlert::to_ips_event. Offline \
             PCAP replay in IDS mode."
        )),
    )
}
