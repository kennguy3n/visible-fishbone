//! Wild-traffic efficacy under sustained concurrent load.
//!
//! The curated FW/SWG/ZTNA/IPS/DLP/malware drivers run *decision-boundary*
//! corpora — every case is hand-placed on the right side of a rule, so they
//! score ~100% by construction. That is a correctness proof of the enforcement
//! code, **not** a real-world catch rate.
//!
//! This driver adds a noisier, honest signal. It replays a larger, committed,
//! deterministically-generated corpus (`fixtures/wild/wild-corpus.json`,
//! produced by `blog/harness/wildcorpus`) that blends benign and malicious
//! payloads at a realistic ratio, including:
//!
//!   * benign-but-suspicious traffic the signature engine genuinely flags
//!     (legitimate PE/ELF installers, real apps calling `String.fromCharCode`,
//!     interactive PDF forms carrying `/JavaScript`) — honest **false
//!     positives**, and
//!   * evasive / novel-packed malware a signature engine genuinely misses
//!     (encrypted droppers with no static marker) — honest **false negatives**.
//!
//! Every payload runs through the **real** engines — `sng_swg::YaraEngine`
//! and the `sng_dlp::ContentClassifier` — driven by a pool of OS threads that
//! hammer the engines concurrently, so the reported catch-rate **and**
//! false-positive-rate are measured under sustained contention, not on a quiet
//! single-threaded hot path.
//!
//! It emits informational (non-gating) rows:
//!   * `malware_wild` / `dlp_wild` — catch-rate AND FPR over the blended
//!     corpus under concurrent load, and
//!   * `malware_fpr_load` / `dlp_fpr_load` — FPR over the **benign-only**
//!     slice at maximum concurrency (a dedicated false-positive-under-load
//!     probe; no malicious cases by construction).
//!
//! These are a noisier proxy — still synthetic, still not production traffic.
//! They are graded against the looser [`Targets::wild`] band and marked
//! `informational` so they never gate the curated correctness proof.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use sng_dlp::{
    ContentClassifier, ContentMetadata, DlpChannel, DlpRule, PatternType, RuleAction, Severity,
};
use sng_swg::YaraEngine;

use crate::report::{Case, Feature, FunctionReport, Kind, Targets, ThroughputStat};

/// Default sustained-load duration per blended-corpus row. Each engine's
/// worker pool keeps re-scanning the corpus for this long to hold the engines
/// under contention while the (deterministic) per-entry verdicts settle.
const WILD_LOAD: Duration = Duration::from_millis(1500);
/// Longer window for the benign-only FPR-under-load probe — false positives
/// that only surface under sustained pressure get more chances to appear.
const FPR_LOAD: Duration = Duration::from_millis(2500);

/// DLP detectors compiled for the wild lane. Restricted to credential / card
/// shapes whose validity is unambiguous and reproducible from the Go corpus
/// generator (distinctive vendor prefixes + Luhn), so the ground-truth labels
/// are trustworthy. Each resolves to the same built-in regex + structural
/// validator the production classifier uses.
const DLP_DETECTORS: &[&str] = &[
    "credit_card",
    "aws_access_key_id",
    "google_api_key",
    "github_token",
    "slack_token",
    "stripe_secret_key",
    "private_key_block",
];

// ===== committed corpus ====================================================

#[derive(Debug, Deserialize)]
struct WildCorpus {
    schema: String,
    seed: i64,
    blend: Blend,
    counts: Counts,
    content_sha256: String,
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
struct Blend {
    malicious_fraction_target: f64,
    benign_fraction_target: f64,
}

#[derive(Debug, Deserialize)]
struct Counts {
    total: usize,
    benign: usize,
    malicious: usize,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    label: String,
    engine: String,
    family: String,
    #[allow(dead_code)]
    desc: String,
    payload_b64: String,
}

/// A decoded corpus entry ready to scan.
struct Item {
    bad: bool,
    family: String,
    payload: Vec<u8>,
}

/// The loaded corpus, split into the two engine lanes.
struct Corpus {
    seed: i64,
    schema: String,
    sha256: String,
    blend: Blend,
    counts: Counts,
    yara: Vec<Item>,
    dlp: Vec<Item>,
}

fn corpus_path() -> PathBuf {
    if let Ok(p) = std::env::var("SNG_WILD_CORPUS") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/wild/wild-corpus.json")
}

fn load_corpus() -> Result<Corpus, String> {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read wild corpus {}: {e}", path.display()))?;
    let raw: WildCorpus = serde_json::from_str(&text)
        .map_err(|e| format!("parse wild corpus {}: {e}", path.display()))?;
    if raw.schema != "sng-wild-corpus/v1" {
        return Err(format!(
            "unexpected wild-corpus schema {:?} (expected sng-wild-corpus/v1) — regenerate with `go run ./blog/harness/wildcorpus`",
            raw.schema
        ));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let (mut yara, mut dlp) = (Vec::new(), Vec::new());
    for e in raw.entries {
        let payload = engine
            .decode(e.payload_b64.as_bytes())
            .map_err(|err| format!("decode payload for {} entry: {err}", e.family))?;
        let item = Item {
            bad: e.label == "malicious",
            family: e.family,
            payload,
        };
        match e.engine.as_str() {
            "yara" => yara.push(item),
            "dlp" => dlp.push(item),
            other => return Err(format!("unknown engine lane {other:?} in wild corpus")),
        }
    }
    Ok(Corpus {
        seed: raw.seed,
        schema: raw.schema,
        sha256: raw.content_sha256,
        blend: raw.blend,
        counts: raw.counts,
        yara,
        dlp,
    })
}

// ===== sustained-load runner ===============================================

/// What a single corpus item's scan decided, plus the work done under load.
struct LoadOutcome {
    /// `blocked[i]` is the engine verdict for `items[i]` (true = blocked /
    /// detected). Deterministic — the engines are pure functions of input —
    /// so concurrent re-scans only stress the engines, never change a verdict.
    blocked: Vec<bool>,
    /// Total scans executed across all workers within the window.
    ops: u64,
    /// Total payload bytes scanned (for the MiB/s figure).
    bytes: u64,
    elapsed: Duration,
    workers: usize,
}

/// Drive `eval` over every item with `workers` OS threads that keep pulling
/// the next index (wrapping around the corpus) until `duration` elapses, then
/// fill in any item not yet visited so the confusion matrix is always
/// complete regardless of timing. `eval` must be a pure, thread-safe scan of
/// the real engine.
fn run_load<F>(items: &[Item], workers: usize, duration: Duration, eval: F) -> LoadOutcome
where
    F: Fn(&[u8]) -> bool + Sync,
{
    let n = items.len();
    // 0 = not yet scanned, 1 = allowed, 2 = blocked. AtomicU8 per slot lets
    // workers race freely; repeated writes store the same deterministic value.
    let slots: Vec<AtomicU8> = (0..n).map(|_| AtomicU8::new(0)).collect();
    let cursor = AtomicU64::new(0);
    let ops = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let deadline = Instant::now() + duration;
    let start = Instant::now();

    if n > 0 {
        thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    let mut local_ops = 0u64;
                    let mut local_bytes = 0u64;
                    loop {
                        let idx = (cursor.fetch_add(1, Ordering::Relaxed) as usize) % n;
                        let item = &items[idx];
                        let blocked = eval(&item.payload);
                        slots[idx].store(if blocked { 2 } else { 1 }, Ordering::Relaxed);
                        local_ops += 1;
                        local_bytes += item.payload.len() as u64;
                        // Check the clock every 64 scans to keep the hot loop tight.
                        if local_ops.is_multiple_of(64) && Instant::now() >= deadline {
                            break;
                        }
                    }
                    ops.fetch_add(local_ops, Ordering::Relaxed);
                    bytes.fetch_add(local_bytes, Ordering::Relaxed);
                });
            }
        });
    }
    let elapsed = start.elapsed();

    // Completeness: any slot still 0 (e.g. a degenerate near-zero duration)
    // is scanned once here so the matrix never silently books an unvisited
    // entry as allowed.
    let blocked: Vec<bool> = slots
        .iter()
        .enumerate()
        .map(|(i, slot)| match slot.load(Ordering::Relaxed) {
            2 => true,
            1 => false,
            _ => eval(&items[i].payload),
        })
        .collect();

    LoadOutcome {
        blocked,
        ops: ops.load(Ordering::Relaxed),
        bytes: bytes.load(Ordering::Relaxed),
        elapsed,
        workers,
    }
}

fn worker_count() -> usize {
    thread::available_parallelism().map_or(4, |n| n.get())
}

/// Confusion-matrix cases (one per entry) plus a compact per-family summary
/// that replaces the per-entry cases in the artifact (the wild corpus has
/// thousands of entries; the per-family rollup keeps the JSON auditable
/// without bloating it — the tp/fn/tn/fp counts are derived from the full set).
fn build_cases(items: &[Item], outcome: &LoadOutcome) -> Vec<Case> {
    use std::collections::BTreeMap;
    // (family, bad) -> (total, correct)
    let mut roll: BTreeMap<(String, bool), (usize, usize)> = BTreeMap::new();
    for (item, &blocked) in items.iter().zip(&outcome.blocked) {
        let correct = item.bad == blocked;
        let e = roll
            .entry((item.family.clone(), item.bad))
            .or_insert((0, 0));
        e.0 += 1;
        if correct {
            e.1 += 1;
        }
    }
    roll.into_iter()
        .map(|((family, bad), (total, correct))| {
            let kind = if bad { "malicious" } else { "benign" };
            let expected = if bad { "block" } else { "allow" };
            Case {
                description: format!("{family} ({kind}): {correct}/{total} scored as expected"),
                bad,
                expected: expected.into(),
                actual: format!("{correct}/{total} correct"),
                correct: correct == total,
            }
        })
        .collect()
}

/// Per-entry cases for the confusion matrix (consumed by `from_cases`).
fn matrix_cases(items: &[Item], outcome: &LoadOutcome) -> Vec<Case> {
    items
        .iter()
        .zip(&outcome.blocked)
        .map(|(item, &blocked)| {
            let expected = if item.bad { "block" } else { "allow" };
            let actual = if blocked { "block" } else { "allow" };
            Case {
                description: item.family.clone(),
                bad: item.bad,
                expected: expected.into(),
                actual: actual.into(),
                correct: item.bad == blocked,
            }
        })
        .collect()
}

fn load_throughput(label: &str, unit: &str, outcome: &LoadOutcome) -> ThroughputStat {
    let secs = outcome.elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let ops_per_sec = outcome.ops as f64 / secs;
    let per_op_ns = if ops_per_sec > 0.0 {
        1e9 / ops_per_sec
    } else {
        0.0
    };
    let mb_per_sec = (outcome.bytes as f64 / secs) / (1024.0 * 1024.0);
    ThroughputStat {
        label: label.into(),
        unit: unit.into(),
        iterations: outcome.ops,
        per_op_ns,
        ops_per_sec,
        bytes_per_op: None,
        mb_per_sec: Some(mb_per_sec),
        debug_build: cfg!(debug_assertions),
    }
}

fn blend_note(corpus: &Corpus) -> String {
    format!(
        "Corpus: {total} samples ({mal} malicious / {ben} benign ≈ {malpct:.0}% malicious; \
         target {tgt_mal:.0}%/{tgt_ben:.0}%), seed=0x{seed:X}, sha256={sha:.12}, schema={schema}. \
         Generated by blog/harness/wildcorpus (deterministic).",
        total = corpus.counts.total,
        mal = corpus.counts.malicious,
        ben = corpus.counts.benign,
        malpct = 100.0 * corpus.counts.malicious as f64 / corpus.counts.total.max(1) as f64,
        tgt_mal = corpus.blend.malicious_fraction_target * 100.0,
        tgt_ben = corpus.blend.benign_fraction_target * 100.0,
        seed = corpus.seed,
        sha = corpus.sha256,
        schema = corpus.schema,
    )
}

// ===== engine verdicts =====================================================

/// YARA verdict under *elevated-risk* inspection: block on ANY match
/// (malicious or suspicious). This mirrors the SWG ext-authz handler when
/// elevated-risk mode is on — the security-conscious posture for inspecting
/// untrusted downloads, and the posture that surfaces the honest false
/// positives of benign-but-suspicious traffic (installers, fromCharCode JS).
fn yara_blocks(engine: &YaraEngine, payload: &[u8]) -> bool {
    !engine.scan(payload).is_empty()
}

/// DLP verdict: block when the content classifier returns any match (each
/// DLP rule's action is Block).
fn dlp_blocks(classifier: &ContentClassifier, meta: &ContentMetadata, payload: &[u8]) -> bool {
    !classifier
        .classify(DlpChannel::FileWrite, payload, meta)
        .matches
        .is_empty()
}

fn dlp_rule(pattern: &str) -> DlpRule {
    DlpRule {
        id: pattern.to_string(),
        name: pattern.to_string(),
        pattern_type: PatternType::Regex,
        pattern_data: pattern.to_string(),
        severity: Severity::High,
        action: RuleAction::Block,
        channels: vec![],
    }
}

// ===== public drivers ======================================================

/// `malware_wild` + `malware_fpr_load`, or a single UNTESTED row if the corpus
/// or engine is unavailable.
pub fn run_malware() -> Vec<FunctionReport> {
    let corpus = match load_corpus() {
        Ok(c) => c,
        Err(e) => {
            return vec![
                untested("malware_wild", "sng-swg", &e),
                untested("malware_fpr_load", "sng-swg", &e),
            ]
        }
    };
    let engine = match YaraEngine::with_builtin_rules() {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("YaraEngine build failed: {e}");
            return vec![
                untested("malware_wild", "sng-swg", &msg),
                untested("malware_fpr_load", "sng-swg", &msg),
            ];
        }
    };
    let workers = worker_count();
    let note = blend_note(&corpus);

    // Blended corpus under load: catch-rate AND FPR.
    let blended = run_load(&corpus.yara, workers, WILD_LOAD, |p| {
        yara_blocks(&engine, p)
    });
    let wild = FunctionReport::from_cases(
        "malware_wild",
        "sng-swg",
        Kind::Detection,
        Targets::wild(),
        matrix_cases(&corpus.yara, &blended),
        Some(format!(
            "Real sng_swg::YaraEngine (built-in rules) over the noisy wild corpus under sustained \
             concurrent load ({workers} worker threads, {ops} scans in {ms} ms). Verdict = block on \
             ANY match (elevated-risk inspection). Includes evasive/novel-packed malware the \
             signature set genuinely misses (honest false negatives) and benign-but-suspicious \
             traffic it flags (honest false positives). Noisier proxy, NOT production traffic. {note}",
            ops = blended.ops,
            ms = blended.elapsed.as_millis(),
        )),
    )
    .with_informational()
    .with_features(wild_features("YARA signature scan"))
    .with_throughput(vec![load_throughput("yara_scan_under_load", "scans/s", &blended)])
    .with_cases(build_cases(&corpus.yara, &blended));

    // Benign-only slice at max concurrency: FPR under load.
    let benign: Vec<Item> = corpus
        .yara
        .iter()
        .filter(|i| !i.bad)
        .map(clone_item)
        .collect();
    let fpr = run_load(&benign, workers, FPR_LOAD, |p| yara_blocks(&engine, p));
    let fpr_row = fpr_load_report("malware_fpr_load", "sng-swg", &benign, &fpr, "YARA", &note);

    vec![wild, fpr_row]
}

/// `dlp_wild` + `dlp_fpr_load`, or UNTESTED rows on failure.
pub fn run_dlp() -> Vec<FunctionReport> {
    let corpus = match load_corpus() {
        Ok(c) => c,
        Err(e) => {
            return vec![
                untested("dlp_wild", "sng-dlp", &e),
                untested("dlp_fpr_load", "sng-dlp", &e),
            ]
        }
    };
    let rules: Vec<DlpRule> = DLP_DETECTORS.iter().map(|p| dlp_rule(p)).collect();
    let classifier = match ContentClassifier::compile(&rules) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("ContentClassifier compile failed: {e}");
            return vec![
                untested("dlp_wild", "sng-dlp", &msg),
                untested("dlp_fpr_load", "sng-dlp", &msg),
            ];
        }
    };
    let meta = ContentMetadata::default();
    let workers = worker_count();
    let note = blend_note(&corpus);

    let blended = run_load(&corpus.dlp, workers, WILD_LOAD, |p| {
        dlp_blocks(&classifier, &meta, p)
    });
    let wild = FunctionReport::from_cases(
        "dlp_wild",
        "sng-dlp",
        Kind::Detection,
        Targets::wild(),
        matrix_cases(&corpus.dlp, &blended),
        Some(format!(
            "Real sng_dlp::ContentClassifier ({n} credential/card detectors) over the noisy wild \
             corpus under sustained concurrent load ({workers} worker threads, {ops} scans in \
             {ms} ms). Malicious = content carrying a valid secret/card; benign = prose + near-miss \
             tokens the structural validators must suppress. Noisier proxy, NOT production traffic. {note}",
            n = DLP_DETECTORS.len(),
            ops = blended.ops,
            ms = blended.elapsed.as_millis(),
        )),
    )
    .with_informational()
    .with_features(wild_features("DLP content classification"))
    .with_throughput(vec![load_throughput("classify_under_load", "scans/s", &blended)])
    .with_cases(build_cases(&corpus.dlp, &blended));

    let benign: Vec<Item> = corpus
        .dlp
        .iter()
        .filter(|i| !i.bad)
        .map(clone_item)
        .collect();
    let fpr = run_load(&benign, workers, FPR_LOAD, |p| {
        dlp_blocks(&classifier, &meta, p)
    });
    let fpr_row = fpr_load_report("dlp_fpr_load", "sng-dlp", &benign, &fpr, "DLP", &note);

    vec![wild, fpr_row]
}

fn clone_item(i: &Item) -> Item {
    Item {
        bad: i.bad,
        family: i.family.clone(),
        payload: i.payload.clone(),
    }
}

/// Build a `*_fpr_load` row from a benign-only run. There are no malicious
/// cases by construction, so catch-rate is not applicable; the row reports the
/// false-positive-rate under maximum sustained concurrency.
fn fpr_load_report(
    function: &str,
    crate_name: &str,
    benign: &[Item],
    outcome: &LoadOutcome,
    engine_label: &str,
    note: &str,
) -> FunctionReport {
    let report = FunctionReport::from_cases(
        function,
        crate_name,
        Kind::Detection,
        Targets::wild(),
        matrix_cases(benign, outcome),
        Some(format!(
            "False-positive-rate under maximum sustained concurrent load: {engine} engine over the \
             {n} benign samples only ({workers} worker threads, {ops} scans in {ms} ms). No \
             malicious cases by construction — catch-rate is not applicable (reported as 1.0 for a \
             zero-bad corpus); the meaningful number is the false-positive-rate. {note}",
            engine = engine_label,
            n = benign.len(),
            workers = outcome.workers,
            ops = outcome.ops,
            ms = outcome.elapsed.as_millis(),
        )),
    )
    .with_informational()
    .with_throughput(vec![load_throughput("scan_under_load", "scans/s", outcome)])
    .with_cases(build_cases(benign, outcome));
    report
}

fn wild_features(engine: &str) -> Vec<Feature> {
    vec![Feature {
        name: "Sustained-load wild scan".into(),
        how: format!("{engine} over a noisy benign+malicious blend on a multi-thread worker pool"),
        coverage: "catch-rate + false-positive-rate under concurrent contention".into(),
    }]
}

fn untested(function: &str, crate_name: &str, reason: &str) -> FunctionReport {
    FunctionReport::untested(function, crate_name, Kind::Detection, reason).with_informational()
}

// ===== IPS wild lane (Suricata under concurrent load) ======================

/// How many times each PCAP is replayed across the concurrent worker pool to
/// hold Suricata under sustained load. Replays of the same PCAP yield an
/// identical verdict (deterministic), so they stress concurrency without
/// changing the confusion matrix.
const IPS_REPLICAS: usize = 3;

/// `ips_wild`: replay the committed IPS PCAP corpus through the REAL Suricata
/// engine (configured by SNG's own `ConfigGenerator`) under concurrent
/// processes, reporting detection-rate AND false-positive-rate under load.
///
/// If Suricata is absent this returns a single methodology-only UNTESTED row —
/// the IPS wild signal is *not* fabricated. The network-flow corpus here is the
/// committed PCAP set (small relative to the file/content lanes); this row's
/// value is the FPR / detection behaviour under genuine concurrent IDS load.
pub async fn run_ips() -> FunctionReport {
    let version = match crate::ips::suricata_available().await {
        Some(v) => v,
        None => {
            return FunctionReport::untested(
                "ips_wild",
                "sng-ips",
                Kind::Detection,
                "METHODOLOGY-ONLY: suricata binary not found on PATH; the IPS wild row is not \
                 fabricated. Install Suricata to measure detection-rate / false-positive-rate \
                 under concurrent load over the committed PCAP corpus.",
            )
            .with_informational();
        }
    };

    let fixtures = crate::ips::fixtures_dir();
    let rules = fixtures.join("test.rules");
    if !rules.exists() {
        return FunctionReport::untested(
            "ips_wild",
            "sng-ips",
            Kind::Detection,
            "IPS rule/PCAP fixtures missing (expected bench/efficacy/fixtures/ips)",
        )
        .with_informational();
    }

    let root = std::env::temp_dir().join(format!("sng-efficacy-ipswild-{}", std::process::id()));
    if let Err(e) = tokio::fs::create_dir_all(&root).await {
        return FunctionReport::untested(
            "ips_wild",
            "sng-ips",
            Kind::Detection,
            &format!("could not create IPS wild work dir {}: {e}", root.display()),
        )
        .with_informational();
    }
    let _guard = crate::ips::WorkDirGuard(root.clone());

    let pcaps = crate::ips::corpus();
    let workers = worker_count();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(workers));
    let rules = std::sync::Arc::new(rules);

    // (pcap index, replica) tasks, bounded by the semaphore -> genuine
    // concurrent Suricata processes.
    let mut handles = Vec::new();
    let start = Instant::now();
    for (i, c) in pcaps.iter().enumerate() {
        let pcap = fixtures.join(c.file);
        for r in 0..IPS_REPLICAS {
            let sem = sem.clone();
            let rules = rules.clone();
            let root = root.clone();
            let pcap = pcap.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore");
                let work = root.join(format!("p{i}-r{r}"));
                if let Err(e) = tokio::fs::create_dir_all(&work).await {
                    return (i, Err(format!("create work dir: {e}")));
                }
                let eve = work.join("eve.json");
                let stats = work.join("cmd.sock");
                let yaml_path = work.join("suricata.yaml");
                let yaml = match crate::ips::render_config(&rules, &eve, &stats) {
                    Ok(y) => y,
                    Err(e) => return (i, Err(e)),
                };
                if let Err(e) = tokio::fs::write(&yaml_path, &yaml).await {
                    return (i, Err(format!("write yaml: {e}")));
                }
                let res = crate::ips::alerts_for_pcap(&yaml_path, &pcap, &work, &eve).await;
                (i, res)
            }));
        }
    }

    // Collect: every replica of a pcap is deterministic, so we keep one result
    // per pcap. Any execution error makes the measurement unreliable -> the
    // whole row is UNTESTED rather than a fabricated verdict.
    let mut alerts: Vec<Option<usize>> = vec![None; pcaps.len()];
    let mut runs = 0u64;
    for h in handles {
        match h.await {
            Ok((i, Ok(n))) => {
                alerts[i] = Some(n);
                runs += 1;
            }
            Ok((_, Err(e))) => {
                return FunctionReport::untested(
                    "ips_wild",
                    "sng-ips",
                    Kind::Detection,
                    &format!("suricata execution failed under concurrent load: {e}"),
                )
                .with_informational();
            }
            Err(e) => {
                return FunctionReport::untested(
                    "ips_wild",
                    "sng-ips",
                    Kind::Detection,
                    &format!("IPS wild task join error: {e}"),
                )
                .with_informational();
            }
        }
    }
    let elapsed = start.elapsed();

    let mut cases = Vec::new();
    for (i, c) in pcaps.iter().enumerate() {
        let n = alerts[i].unwrap_or(0);
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

    let secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let throughput = ThroughputStat {
        label: "suricata_pcap_under_load".into(),
        unit: "pcap-scans/s".into(),
        iterations: runs,
        per_op_ns: if runs > 0 {
            1e9 * secs / runs as f64
        } else {
            0.0
        },
        ops_per_sec: runs as f64 / secs,
        bytes_per_op: None,
        mb_per_sec: None,
        debug_build: cfg!(debug_assertions),
    };

    FunctionReport::from_cases(
        "ips_wild",
        "sng-ips",
        Kind::Detection,
        Targets::wild(),
        cases,
        Some(format!(
            "Real {version} (SNG ConfigGenerator-rendered suricata.yaml; EVE alerts normalised \
             through sng_ips::EveAlert::to_ips_event) replaying the committed PCAP corpus under \
             {workers} concurrent Suricata processes ({runs} runs in {ms} ms, {replicas}x replay \
             per pcap). Detection-rate AND false-positive-rate measured under concurrent IDS load. \
             Network-flow corpus is the committed PCAP set — smaller than the file/content wild \
             lanes; noisier proxy, NOT production traffic.",
            workers = workers,
            ms = elapsed.as_millis(),
            replicas = IPS_REPLICAS,
        )),
    )
    .with_informational()
    .with_throughput(vec![throughput])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_load_visits_every_entry_and_is_deterministic() {
        let items: Vec<Item> = (0u8..50)
            .map(|i| Item {
                bad: i.is_multiple_of(2),
                family: "t".into(),
                payload: vec![i],
            })
            .collect();
        // Verdict: "block" iff the single byte is even — matches `bad`.
        let eval = |p: &[u8]| p[0].is_multiple_of(2);
        let out = run_load(&items, 4, Duration::from_millis(50), eval);
        assert_eq!(out.blocked.len(), 50);
        // Perfect classifier on this toy corpus.
        for (i, &b) in out.blocked.iter().enumerate() {
            assert_eq!(b, i.is_multiple_of(2));
        }
        assert!(
            out.ops >= 50,
            "every entry scanned at least once under load"
        );
    }

    #[test]
    fn run_load_completes_with_zero_duration() {
        let items: Vec<Item> = (0u8..16)
            .map(|i| Item {
                bad: false,
                family: "t".into(),
                payload: vec![i],
            })
            .collect();
        // Even a zero-length window must yield a complete matrix (the
        // post-loop completeness pass fills any unvisited slot).
        let out = run_load(&items, 4, Duration::from_millis(0), |_| false);
        assert_eq!(out.blocked.len(), 16);
        assert!(out.blocked.iter().all(|&b| !b));
    }

    #[test]
    fn empty_corpus_is_safe() {
        let out = run_load(&[], 4, Duration::from_millis(10), |_| true);
        assert!(out.blocked.is_empty());
        assert_eq!(out.ops, 0);
    }

    #[test]
    fn build_cases_rolls_up_per_family() {
        let items = vec![
            Item {
                bad: true,
                family: "eicar".into(),
                payload: vec![1],
            },
            Item {
                bad: true,
                family: "eicar".into(),
                payload: vec![1],
            },
            Item {
                bad: false,
                family: "prose".into(),
                payload: vec![0],
            },
        ];
        let outcome = LoadOutcome {
            blocked: vec![true, false, false],
            ops: 3,
            bytes: 3,
            elapsed: Duration::from_millis(1),
            workers: 1,
        };
        let cases = build_cases(&items, &outcome);
        // Two families -> two summary rows (eicar malicious, prose benign).
        assert_eq!(cases.len(), 2);
        let eicar = cases
            .iter()
            .find(|c| c.description.starts_with("eicar"))
            .unwrap();
        // One of two eicar samples was (incorrectly) allowed.
        assert!(eicar.description.contains("1/2"));
        assert!(!eicar.correct);
    }
}
