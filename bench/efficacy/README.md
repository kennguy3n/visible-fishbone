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
| ZTNA | `sng-ztna` | `ZtnaService::evaluate` brokering (device/identity/app/posture) | block-rate |
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
per-function toggles (`--firewall`, `--swg`, `--ztna`, `--ips`) to run a
subset. Exit code is `0` only when every function PASSes, `2` otherwise (a
`WARN` or `UNTESTED` overall verdict also exits `2`, so a half-run suite never
reads as green to a CI gate).

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

## Scope caveat

These are **single-host, development-environment** measurements over
representative corpora. They prove the enforcement *decisions* are correct
end-to-end — not catch-rate at line-rate. Sustained block-rate under load
requires an in-path deployment on representative hardware (a future phase).
