# `sng-efficacy` — ShieldNet Gateway security-efficacy harness

The performance suites (`bench/`, `bench/controlplane`, `bench/telemetry`)
answer *how fast?* — Gbps, p99 latency, rows/sec. They do **not** answer the
question a security buyer actually asks: **does the box block?** A gateway can
push 5 Gbps while silently passing every attack; fast ≠ secure.

This harness measures **efficacy**: it drives the *real* enforcement decision
code of each security function over a curated **known-bad** corpus (must be
stopped) and a **known-good** corpus (must be allowed), then reports the
confusion matrix and the two KPIs an RFP cares about:

- **catch-rate** = `TP / (TP + FN)` — block-rate (enforcement) or detection-rate (IPS)
- **false-positive-rate** = `FP / (FP + TN)` — known-good traffic wrongly stopped

## Why this is a standalone crate

Like the sibling `bench/` workspace, `bench/efficacy` is its own Cargo
workspace (bare `[workspace]` in [`Cargo.toml`](./Cargo.toml)) and is
deliberately **not** a member of the root workspace, so the per-PR CI gates
never have to compile it. Build and lint it explicitly:

```bash
cd bench/efficacy
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

## What it measures

| Function | Crate | Real seam exercised | KPI |
| --- | --- | --- | --- |
| Firewall | `sng-fw` | `FirewallEngine::evaluate` + `RuleCompiler` → kernel `nft -c` validation | block-rate |
| SWG | `sng-swg` | `ExtAuthzHandler` categorize → deny-list path | block-rate |
| SWG inline DLP | `sng-swg` | `DlpInlineClassifier` on ext-authz path | block-rate |
| SWG AI governance | `sng-swg` | `AiGovernanceClassifier` on ext-authz path | block-rate |
| SWG RBI | `sng-swg` | `RbiClassifier` redirect verdict | block-rate |
| ZTNA | `sng-ztna` | `ZtnaService::evaluate` brokering (device/identity/app/posture) | block-rate |
| ZTNA clientless | `sng-ztna` | `ClientlessSession` access decision | block-rate |
| DEM | `sng-dem` | `ProbeEngine::run_sweep` over DNS/TCP/HTTP targets | pass / timeout |
| IPS | `sng-ips` | Suricata (IDS) over generated config → EVE → `EveAlert::to_ips_event` | detection-rate |

Each driver runs the actual crate API — no mocks. The firewall additionally
compiles its ruleset and feeds it to the Linux `nft` kernel parser to prove
the rendered enforcement artifact is valid. The IPS driver renders Suricata's
config via SNG's own `ConfigGenerator` and normalises alerts through the real
`sng-ips` path.

## Run it

```bash
cd bench/efficacy
cargo run --release -- --out efficacy-report.json --git-sha "$(git rev-parse --short HEAD)"
```

Flags: `--out <path>` (default `efficacy-report.json`), `--git-sha <sha>`, and
per-function toggles (`--firewall`, `--swg`, `--swg-dlp-inline`,
`--swg-ai-governance`, `--swg-rbi`, `--ztna`, `--ztna-clientless`, `--dem`,
`--ips`, `--dlp`, `--malware`, `--dns`, `--adversarial`, `--wild`) to run a subset. Exit code is
`0` only when every **gating** function PASSes, `2` otherwise (a `WARN` or
`UNTESTED` overall verdict also exits `2`, so a half-run suite never reads as
green to a CI gate). The `--wild` rows are *informational* and never affect the
exit code (see below).

### IPS prerequisite

The IPS driver needs the `suricata` binary on `PATH`. If it is missing, that
function is reported as `UNTESTED` (with a reason) instead of aborting the
run — the other three still execute and are scored. Note this makes the overall
verdict `UNTESTED`, so the process still exits `2` (the measurement is
incomplete, not green). Install on Debian/Ubuntu with `apt-get install
suricata`.

### Fixtures

`fixtures/ips/` holds the IPS corpus: self-contained Suricata rules
(`test.rules`, SIDs 1000001–1000004 for EICAR / traversal / SQLi / C2-beacon)
and the matching PCAPs. Regenerate the PCAPs with
[`gen_pcaps.py`](./fixtures/ips/gen_pcaps.py) (`pip install scapy`). The FW,
SWG, and ZTNA corpora are defined in code (no external feeds), so the suite is
fully reproducible offline.

## Output → Section 7 of the business report

The JSON schema is consumed by the Go consolidator in
`bench/business-report`, which renders it as **Section 7: Security Efficacy**
alongside the performance sections:

```bash
go run ./bench/business-report \
  --efficacy /path/to/efficacy-report.json \
  --out-dir /tmp
```

Because these are real enforcement decisions (not synthetic load), the
PASS/WARN/FAIL verdicts stand even when the performance sections are in
`--dry-run` mode — the same way the Section 4 Criterion numbers do.

## Targets

PASS requires catch-rate ≥ 99% **and** false-positive-rate ≤ 2%; WARN is the
looser band (≥ 90% / ≤ 5%); otherwise FAIL. A partially-run suite (e.g. IPS
untested) grades `UNTESTED`, which is treated as worse than WARN so a
half-run suite never masquerades as green.

## Wild-traffic efficacy (noisy proxy, FPR under load)

The curated corpora score ~100% **by construction** — they prove the
enforcement code is correct, not that it catches real-world traffic. The
`--wild` driver ([`src/wild.rs`](./src/wild.rs)) adds an honest, noisier
signal: it replays a larger, committed, deterministically-generated corpus
([`fixtures/wild/wild-corpus.json`](./fixtures/wild), produced by
[`blog/harness/wildcorpus`](../../blog/harness/wildcorpus)) through the **real**
engines under **sustained concurrent load**, and reports BOTH catch-rate AND
false-positive-rate.

| Row | Engine | What it measures |
| --- | --- | --- |
| `malware_wild` | `sng_swg::YaraEngine` | catch-rate + FPR over the blended corpus under load |
| `malware_fpr_load` | `sng_swg::YaraEngine` | FPR over the **benign-only** slice at max concurrency |
| `dlp_wild` | `sng_dlp::ContentClassifier` | catch-rate + FPR over the blended corpus under load |
| `dlp_fpr_load` | `sng_dlp::ContentClassifier` | FPR over the **benign-only** slice at max concurrency |
| `ips_wild` | Suricata (if present) | detection-rate + FPR replaying the committed PCAP corpus under concurrent Suricata processes |

The blended corpus is **2087 samples** (≈22% malicious / 78% benign across
mixed file types). It deliberately includes **benign-but-suspicious** traffic
the signature engine flags (honest false positives) and **evasive/novel-packed**
malware it misses (honest false negatives), so the wild numbers are
intentionally below the curated 100%. The per-entry verdicts are deterministic
(the engines are pure functions of input), so the confusion matrix is
reproducible run-to-run; only the throughput figures vary. FPR is measured
with the worker pool sized to the host's available parallelism.

These rows are **informational**: they are graded against a looser band
(`Targets::wild` — PASS ≥ 90% catch / ≤ 5% FPR, WARN ≥ 75% / ≤ 10%) and are
**excluded from the gating `overall_verdict`** (and the process exit code) so
the honest sub-100% wild numbers neither masquerade as — nor drag down — the
curated decision-boundary correctness proof. They serialize with their own
`verdict` and an `informational: true` flag.

**Honesty contract.** This is a *noisier proxy, still not production traffic*.
The corpus is synthetic, inert stand-in content; the ~1-in-5 malicious density
is denser than live traffic on purpose (so each attack class is statistically
meaningful), and the FPR is measured against the benign majority **under
concurrent load**. If `suricata` is absent, `ips_wild` is reported
`UNTESTED` and labelled **METHODOLOGY-ONLY** — the IPS wild row is never
fabricated.

### Wild fixtures

`fixtures/wild/wild-corpus.json` is the committed, deterministic corpus.
Regenerate it (and verify the `content_sha256` is unchanged) with:

```bash
go run ./blog/harness/wildcorpus              # rewrites the committed artifact
```

See the [`wildcorpus` README](../../blog/harness/wildcorpus/README.md) for the
blend ratios, schema, and determinism details.

## Scope caveat

These are **single-host, development-environment** measurements over
representative corpora. They prove the enforcement *decisions* are correct
end-to-end — not catch-rate at line-rate. Sustained block-rate under load
requires an in-path deployment on representative hardware (a future phase).
