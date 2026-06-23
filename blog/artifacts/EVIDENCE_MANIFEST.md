# SNG — Evidence Manifest & Provenance Index

This manifest is the provenance index for the blog series. Every number in the
posts traces back to an artifact listed here. Nothing in this set is
hand-edited: each payload is a real control-plane API response, each report is
real harness output, each screenshot is a real CDP capture of the live console.

## 0. Capture context

| Field | Value |
| --- | --- |
| Stack | Postgres 16 + NATS 2.10 (Docker) · `sng-control` on :8080 · vite console on :5173 (proxy → :8080) |
| Host | 8 vCPU AMD EPYC 7763 (AVX2/FMA, no AVX-512/VNNI), 31 GiB RAM, CPU-only |
| Runtime role | `sng_app` (non-superuser) — row-level security is enforced on every captured payload |
| Fleet | 9 tenants under one MSP, seven countries / eight industries (see §3) |
| Feature flags | optional NoOps levers (`HIBERNATION_ENABLED`, `CLICKHOUSE_TIER_SAMPLING_ENABLED`, `ROLLOUT_AUTOPILOT_ENABLED`, `CAPACITY_AUTOPILOT_ENABLED`, `METERING_AUTOPILOT_ENABLED`, `AI_INFERENCE_POOL_ENABLED`, `IDP_DIRECTORY_SYNC_ENABLED`, `DEM_ENABLED`) exercised where a post needs them |

All payloads flow through the real operator API (JWT auth, RLS tenant scoping,
policy compilation, audit log) — the seed/usage/capture/newcaps harnesses drive
the same endpoints a human operator would, so every row is
enforcement-path-authentic.

## 1. Harness results (the load-bearing numbers)

### 1.1 Security efficacy — `efficacy-report.json`
- **Source:** `bench/efficacy` (real enforcement code over known-bad/known-good +
  adversarial + wild corpora). Run with `--firewall --firewall-kernel --swg
  --ztna --ips --dlp --malware --dns --adversarial --wild`, ONNX Runtime 1.22 for
  the ML-NER leg, Suricata for IPS, nftables for the kernel leg. **16 functions.**
- **Overall verdict: PASS.** Gating rows (all PASS, 100% catch / 0% FPR):
  firewall, **firewall_kernel** (kernel nft ruleset accepted by `nft -c`), swg,
  ztna, dlp, malware, dns, ips, **malware_adversarial**, **ips_adversarial**;
  `dlp_ml_ner` 97.4% catch / 97.9% accuracy / 0% FPR.
- **Informational (wild, never gates):** `malware_wild` catch **90.1%** / FPR
  **9.6%** (WARN — honest misses on packed/novel); `malware_fpr_load` FPR 9.6%
  (WARN); `dlp_wild` 100% / 0% FPR; `dlp_fpr_load` 100% / 0% FPR; `ips_wild` 100%.
- **Add-on capabilities** are additionally covered by their crate unit tests,
  all run in the standard `cargo test` flow: AI governance (24), inline DLP (22),
  RBI (16), clientless ZTNA (11), and DEM (10).

### 1.2 Multi-queue throughput — `multiqueue-micro.json`, `multi-queue-branch-large.json`
- **Source:** `sng-bench multi-queue --mode full-stack --backend nftables`.
- **Micro SKU:** single-stream floor **5.718 Gbps → 16-queue ceiling 27.264 Gbps
  (4.77×)** on 8 cores.
- **Branch-large SKU:** floor **4.461 Gbps → 32-queue ceiling 20.588 Gbps
  (4.61×)**.
- We publish floor *and* ceiling side by side; the single-stream wire is a
  per-frame syscall ceiling, not an inspection bound, and CPU headroom is exposed
  by fanning out across RSS queues.

### 1.3 8B LLM validation — `payloads/s6-llm-validation-bonsai-8b-q2_0.json` + `llm_validation/quality_report.{json,md}`
- **Source:** `blog/harness/llm_validation` against the self-hosted
  **Ternary-Bonsai-8B Q2_0** (prism AVX2-repack kernels).
- **8B numbers (live inference, 8-vCPU EPYC profile):** parse 100%, verifier
  100%, classification 100%, fallback-agreement 100%; **latency p50 9,000 ms /
  p95 11,083 ms**. The deterministic verifier/fallback path is exercised and
  passes even when the model is unavailable.

### 1.4 Fleet cost & margin — `payloads/s7-admin-cost-report.json`
- **Source:** `GET /api/v1/admin/cost-report` over the 9-tenant fleet after a
  full `blog/harness/usage` seed (every tenant carries current + 5-month history).
- **9-tenant fleet:** revenue **$8,191/mo** · projected cost **≈$4,025/mo** ·
  **margin ≈$4,166 (≈50.9%)**. Per-tenant margin spans **≈+66.9% (Globex)** down
  to **≈−13.9% (Maple Health)** — Maple is the deliberate *underwater* tenant (a
  professional-tier client consuming enterprise-scale bandwidth/ClickHouse), the
  honest upsell/margin signal the report is built to surface. These are
  *projected* (elapsed-fraction-extrapolated) figures, so they drift sub-percent
  within a billing period; the saved payload is the point-in-time source of
  record and prose uses approximate figures deliberately.
- **Cost anomaly (real):** Initech's `url_cat_lookups` projects **$220.39 vs a
  $72.31 baseline = ratio 3.05, severity `warning`** (`s7-initech-cost-anomalies.json`)
  — a modelled mid-period surge the detector flags while Initech still clears its
  tier. Acme's anomaly set is empty (control).

### 1.5 5,000-tenant capacity plan — `capacity-plan-5000/report.{md,json}`
- **Source:** `sng-bench capacity-plan --tenants 5000`.
- **Dormancy dividend 10×:** with a realistic mix (active every cycle, idle 10×
  less often, dormant 100× less often), per-job background work drops from 5,000
  to ~500 tenant-visits per cycle.
- **Shared AI pool ~3,696× less memory:** one pooled model resident at 4.6 GB vs
  17,000 GB of per-tenant residency.
- Sized recommendations for Postgres pool, ClickHouse batch/shards, NATS
  partitions, and AI pool slots accompany the verdict.

### 1.6 NoOps metrics — `noops-metrics-snapshot.txt`
- Live `sng_capacity_*`, `sng_hibernation_*`, and `sng_ai_inference_pool_*`
  gauges scraped from the seeded stack.

## 2. New-capability evidence (captured via `blog/harness/newcaps`)

Each row is a verbatim, RLS-scoped API response captured by the `newcaps`
harness, which mints an admin JWT from `AUTH_JWT_SECRET`, ingests a deterministic
experience-probe batch, and reads every surface back.

| Capability | Artifact(s) | Load-bearing numbers |
| --- | --- | --- |
| Application identification | `appid-acme-catalog-current.json`, `appid-admin-catalog-versions.json`, `appid-acme-catalog-bundle.json` | **215 apps / 17 categories**, signed catalog with a monotonic serial; matcher ranks most-specific-suffix-first |
| Managed threat content | `threatcontent-acme-posture.json` | **76,432 indicators** across 5 built-in feeds, **ed25519-signed** bundle (digest `ee79836a…`), counts by type (domain / hash / ip / url); no per-tenant config |
| Continuous compliance | `complianceauto-acme-posture.json`, `complianceauto-{acme,globex,maple}-collect-response.json`, `complianceauto-acme-evidence-pack-{soc2,iso27001}.json`, `…-soc2.csv` | **16 controls (10 SOC 2 + 6 ISO 27001)**, 3 collectors; on a bare dev stack Acme scores **SOC 2 6/10**, **ISO 27001 4/6** (the failing controls are real un-wired-service gaps) |
| SWG inline DLP | (code) `crates/sng-swg/src/dlp_inline.rs` | **22 unit tests** covering regex, MIP-label, and fingerprint classification; bounded `scan_ceiling_bytes` on the ext-authz path |
| SWG AI governance | (code) `crates/sng-swg/src/ai_governance.rs` | **24 unit tests** covering per-app / per-category / default / suspected-app actions; allow, monitor, block, redirect-to-RBI |
| SWG RBI | (code) `crates/sng-swg/src/rbi.rs` | **16 unit tests** covering explicit isolate, bypass, and uncategorised-site triggers |
| Clientless ZTNA | (code) `crates/sng-ztna/src/clientless.rs` | **11 unit tests** covering OIDC session, host matching, and reverse-proxy access decisions |
| Digital-experience monitoring | `dem-acme-ingest-result-response.json`, `dem-acme-scores.json`, `dem-acme-targets.json`, `dem-acme-alerts.json` | ingest **HTTP 202** (72 samples), 6 auto-provisioned targets; 5 healthy targets score **100**, Zoom degrades to **30** (availability 50%, p50/p95 3,100 ms), firing **one critical `dem.experience_degraded` alert on Zoom** (below the degrade floor of 70) |
| Active/active work distributor | (code) `internal/service/workshard` | **1,024 shards**, lease TTL 20 s / 7 s safety margin — periodic work spreads across replicas, not one leader |
| Policy recommendation engine | `policyrec-acme-generate-response.json`, `policyrec-acme-list.json` | honest **HTTP 503** on a stack without the telemetry hot tier configured (`unavailable`); the recommendation list is empty until the hot tier is wired |

> The backend capabilities above have **no dedicated console page**, so they
> are evidenced by verbatim payloads + measured numbers + code rather than by
> screenshots. This follows the same treatment the repo already gives `/scim` and
> `/pops`.

## 3. The 9-tenant fleet (residency × industry coverage)

| Tenant | Tier | Residency | Industry | Margin % |
| --- | --- | --- | --- | --- |
| Globex Health Systems | enterprise | US | health | ≈+66.9 |
| Acme Retail Group | enterprise | US | retail | ≈+47.4 |
| Britannia Robotics | enterprise | GB | robotics | ≈+62.7 |
| Umbrella Logistics | starter | SG | logistics | ≈+42.8 |
| Nordic EduCloud | starter | SE | education | ≈+54.2 |
| Lumière Légal | professional | FR | legal | ≈+55.6 |
| Outback Retail Co | professional | AU | retail | ≈+49.7 |
| Initech Financial | professional | EU | financial | ≈+15.6 |
| Maple Health Network | professional | CA | health | ≈−13.9 |

## 4. Payload index (`payloads/`)

- **Scenario payloads:** `s1-*` tenants/MSP/audit · `s2-*` sites/devices/policy-graph
  · `s3-*` alerts · `s4-*` PoPs · `s5-*` DLP/CASB/browser · `s6-*` NL-query /
  posture / playbooks / LLM validation · `s7-*` usage / cost / compliance /
  integrations · `pt-*` per-jurisdiction template renders · `casb-*`
  classifications.
- **NoOps payloads:** `rollout-*-states.json`, `rollout-acme-clamav-enforce-transition.json`,
  `ws5-acme-rollout-*.json` (off→monitor→enforce capability ladder),
  `ws7-*-cost*.json` (margin-autopilot input; Maple underwater).
- **New-capability payloads:** `appid-*`, `threatcontent-*`, `complianceauto-*`,
  `dem-*`, `policyrec-*` (see §2).
- All are real RLS-scoped API responses.

## 5. Screenshot index (`screenshots/`)

Live CDP captures of the seeded console. Highlights:

| File | Route | What it shows |
| --- | --- | --- |
| `refresh-dashboard-fleet.png`, `overview-dashboard.png` | `/` | fleet overview across all 9 tenants |
| `new-metering-fleet-top.png`, `new-metering-fleet-table.png` | `/metering` | 9-tenant cost & margin table, Maple underwater (the cost-report payload is authoritative for exact figures) |
| `new-casb-noops-shadow-it.png` | `/casb` | shadow-IT inventory + per-app risk, sanction, recommended NoOps action |
| `new-dlp-review-queue.png` | `/dlp/review-queue` | live triage console: backlog digest, severity/state breakdown |
| `new-cross-tenant-rollout.png`, `new-msp-cross-tenant-templates.png` | `/policy/rollout`, `/msp/templates` | apply one baseline to many tenants with a per-tenant diff |
| `new-guided-onboarding-wizard.png` | `/onboarding/guided` | Tenant→Residency→Industry→First-policy→Done wizard |
| `refresh-compliance.png` | `/compliance` | compliance baselines for the fleet |
| `s2-policy-graph.png`, `s2-policy-editor-simple.png`, `s2-policy-graph-advanced.png` | `/policy` | the typed policy graph + editor |
| `s3-alerts.png`, `s3-alerts-anomaly-scatter.png` | `/alerts` | anomaly scatter + alert table |
| `s5-dlp-*`, `s5-casb-connectors.png`, `s5-browser-isolation.png` | `/dlp`, `/casb`, `/browser` | DLP/CASB/RBI surfaces |
| `s6-assistant*.png`, `s6-playbooks.png` | `/assistant`, `/playbooks` | AI assistant + playbooks |
| `scenario-00..05.png` | — | the six-scenario capstone |

`/scim` is proxied to the backend SCIM endpoint, not an SPA page, so its evidence
is the conformance suite + `SCIM_CERTIFICATION.md` rather than a screenshot.

## 6. Known honest gaps
- **Global PoP footprint** vs Zscaler/Cloudflare/Cato: SNG ships software you run,
  not a rented anycast network. `deploy/pop/` is a reference topology, not a live
  global edge.
- **Live SCIM certification** vs real Okta/Entra: in-repo hardening + conformance
  suite + documented cert plan only.
- **`malware_wild` FPR 9.6%**: real signature engines miss packed/novel samples —
  published honestly, not smoothed.
- **Policy recommendations need a telemetry hot tier**: on a deployment without
  the hot tier configured, the engine honestly returns `503 unavailable` rather
  than fabricating suggestions.
