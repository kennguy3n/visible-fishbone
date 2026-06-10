# Blog artifacts — provenance & integrity

Every figure in the blog series traces back to one of these files. This README
records exactly how each was produced and what it does (and does not) prove.

## `efficacy-report.json` — security efficacy (REAL, measured)

- **Produced by:** `bench/efficacy` (`sng-efficacy`), which drives the *actual*
  enforcement crate APIs (`sng-fw`, `sng-swg`, `sng-ztna`, `sng-dlp`, `sng-ips`
  + Suricata, `sng-dns`) over curated known-bad / known-good corpora.
- **Command:**
  ```
  ORT_DYLIB_PATH=$HOME/.local/onnxruntime/libonnxruntime.so \
    GIT_SHA=$(git rev-parse HEAD) ./target/release/sng-efficacy --out efficacy-report.json
  ```
- **Dependencies provisioned exactly as the repo blueprint specifies:**
  Suricata (`apt install suricata`) for the IPS tier, and ONNX Runtime v1.22.0
  (`ORT_DYLIB_PATH`) for the DLP ML-NER tier.
- **Result (all PASS):**

  | function | kind | bad | good | catch% | fp% | acc% | throughput |
  | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
  | firewall | block-rate | 7 | 5 | 100.0 | 0.0 | 100.0 | — |
  | swg | block-rate | 6 | 5 | 100.0 | 0.0 | 100.0 | — |
  | ztna | block-rate | 8 | 4 | 100.0 | 0.0 | 100.0 | 1.73M decisions/s · 577 ns/op |
  | dlp | detect-rate | 550 | 550 | 100.0 | 0.0 | 100.0 | 4,532 scans/s · 2.4 MiB/s |
  | dlp_ml_ner | detect-rate | 23 | 8 | 100.0 | 0.0 | 100.0 | 32,509 scans/s · 5.1 MiB/s |
  | malware (YARA) | detect-rate | 8 | 6 | 100.0 | 0.0 | 100.0 | — |
  | dns | detect-rate | 10 | 13 | 100.0 | 0.0 | 100.0 | — |
  | ips (Suricata) | detect-rate | 7 | 6 | 100.0 | 0.0 | 100.0 | — |

- **What it proves:** the enforcement code correctly blocks the known-bad set and
  passes the known-good set, at the measured hot-path op rates.
- **What it does NOT prove:** these are *curated unit-level corpora* (tens of
  samples for most tiers; 1,100 for DLP), not a large adversarial red-team set.
  100% on a small corpus means "no regressions against the cases we encode," not
  "100% against all real-world threats." The blog states corpus sizes inline and
  does not extrapolate to a universal catch-rate.

## `edge-performance-datasheet.{md,json}` — edge throughput (DUAL: dry-run + wire)

- **Produced by:** `bench/` — two `sng-bench business-report` sweeps over
  `profiles/skus` merged by `sng-bench datasheet`. The JSON is a `DualDatasheet`
  (`{ "dry_run": …, "wire": … }`); the markdown renders both columns. The
  `wire-datasheet` job in `.github/workflows/benchmark.yml` regenerates it on the
  self-hosted `sng-bench-wire` runner. To reproduce locally:

  ```sh
  bin=bench/target/release/sng-bench
  $bin business-report --profiles-dir bench/profiles/skus --duration-ms 1000 \
    --packet-sizes 64,512,1500,9000 --out-dir /tmp/ds/dry --dry-run
  $bin business-report --profiles-dir bench/profiles/skus --duration-ms 1000 \
    --packet-sizes 64,512,1500,9000 --interface veth-bench --out-dir /tmp/ds/wire
  $bin datasheet --dry-run-json /tmp/ds/dry/business-report-*.json \
    --wire-json /tmp/ds/wire/business-report-*.json \
    --out-md blog/artifacts/edge-performance-datasheet.md \
    --out-json blog/artifacts/edge-performance-datasheet.json
  ```

- **Two columns, two meanings:**
  - **dry-run** crafts and measures frames **in-process with no NIC / wire I/O**.
    The ~76–100 Gbps figures are the harness's craft→measure pipeline *ceiling*,
    **not** real inspected wire throughput (the tell: throughput is nearly
    SKU-independent and CPU reads ~0%).
  - **wire** is real `AF_PACKET` egress over a veth pair with `sng-edge` in-path
    under `CAP_NET_RAW`. It is a conservative *floor* — a single-stream egress
    path, not a multi-queue physical NIC's line-rate.
- **How the blog uses it:** the dry-run column stays a **methodology
  demonstration**; the wire column is the honest performance floor. The blog
  does **NOT** present the dry-run Gbps as a performance result, and the
  "+N% vs <competitor>" verdicts are computed from the **wire** number when
  present. The harness's "informative, not apples-to-apples, software-only VM"
  caveat is preserved on every competitor row.
- **Competitor rows:** vendor-published datasheet numbers from
  `bench/business-report/competitors.json`, each carrying `source_url` + a
  hardware caveat (most are ASIC appliances; SNG is software-only).

## Honesty contract (applies to the whole series)

1. **Measured** = real crate/code execution (efficacy matrix, hot-path op/s).
   **Dry-run** = in-process harness pipeline (edge Gbps) — labeled as such.
2. Competitor numbers are cited published figures, never head-to-head runs.
3. Screenshots are of real, seeded, error-free pages (Phase 0 audit + PR #117).
4. Each post ends with an honest "where we fall short" section.
