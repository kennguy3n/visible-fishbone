# Blog artifacts — provenance & integrity

Every figure in the blog series traces back to one of these files. This README
records exactly how each was produced and what it does (and does not) prove.

**Provenance:** all artifacts in this directory were regenerated against the
current codebase. The `git_sha` / `generated_at` fields embedded in
`efficacy-report.json` and `edge-performance-datasheet.json` are the
authoritative per-file stamps.

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
- **Result:** overall verdict **PASS** across **16 functions**. The gating tiers
  (firewall, firewall_kernel, swg, ztna, dlp, malware, dns, ips, and the
  malware/ips adversarial legs) all score 100% catch / 0% FPR; `dlp_ml_ner`
  scores 97.4% catch / 97.9% accuracy / 0% FPR. The informational *wild* legs
  never gate and report honest misses (`malware_wild` 90.1% catch / 9.6% FPR).
  The per-function corpus sizes, throughput, and verdicts live in
  `efficacy-report.json` and are summarized in
  [`EVIDENCE_MANIFEST.md`](EVIDENCE_MANIFEST.md) §1.1.

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
  self-hosted `sng-bench-wire` runner and uploads it as a run artifact; the hosted
  `publish-datasheet` job then commits the refreshed artifact back here on the weekly
  scheduled run (the commit is kept off the privileged in-path runner). To reproduce
  locally:

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
3. Screenshots are of real, seeded, error-free pages.
4. Each post ends with an honest "where we fall short" section.
