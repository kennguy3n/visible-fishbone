# SNG Wave 3 — Evidence Manifest & Provenance Index

This manifest is the provenance index for the **merged-state** blog rewrite (the
12-workstream 5,000-tenant NoOps push). Every number in the posts traces back to
an artifact listed here. Nothing in this set is hand-edited: each payload is a
real control-plane API response, each report is real harness output, each
screenshot is a real CDP capture of the live console. The §0 Wave-3 addendum
covers the artifacts re-measured/added on merged `main`; §2–§8 retain the
Wave-2 provenance for artifacts carried forward unchanged.

## 0. Wave-3 capture context (merged `main`)

| Field | Value |
| --- | --- |
| Repo HEAD | `65824c75cf0d463d64f7ea83ca90f41859b8b76b` (`65824c75`) — all 12 workstreams merged |
| Latest migrations | `068_tenant_hibernation` (WS-3), `069_capability_rollout_monitor_evidence` (WS-5) |
| Stack | Postgres 16 + NATS 2.10 · `sng-control` on :8080 · vite console on :5173 |
| Host | 8 vCPU AMD EPYC 7763, 31 GiB RAM, CPU-only |
| Feature flags this run | **all WS gates ON**: `HIBERNATION_ENABLED`, `CLICKHOUSE_TIER_SAMPLING_ENABLED`, `ROLLOUT_AUTOPILOT_ENABLED`, `CAPACITY_AUTOPILOT_ENABLED`, `METERING_AUTOPILOT_ENABLED`, `AI_INFERENCE_POOL_ENABLED`, `THREAT_INTEL_RETROHUNT`, `CASB_NOOPS_ENABLED`, `IDP_DIRECTORY_SYNC_ENABLED` |

**Re-measured / added on merged `main`:**
- `efficacy-report.json` — full matrix re-run (overall PASS; `dlp` 3,800/3,800 100%/0%; `dlp_ml_ner` 97.4%; gating + adversarial legs 100%; `malware_wild` 90.1%/9.6% WARN).
- `multiqueue-micro.json` (5.569 → 28.567 Gbps, 5.13×) and `multi-queue-branch-large.json` (5.063 → 21.564 Gbps, 4.26×) — WS-8 floor→ceiling.
- `capacity-plan-5000/report.{md,json}` — WS-1 dormancy dividend **10×** (idle 10×, dormant 100× tail; 5,000→500 visits/cycle/job), WS-9 shared AI pool **~3,696×** less memory (4.6 GB vs 17,000 GB), sized ClickHouse/AI/NATS/Postgres recommendations.
- `noops-metrics-snapshot.txt` — live `sng_capacity_*` (reconcile_total{ok}=3, current-vs-recommended sizing), `sng_hibernation_*`, `sng_ai_inference_pool_*` gauges from the seeded stack.
- `payloads/ws5-acme-rollout-capabilities.json`, `ws5-acme-rollout-margin-autopilot.json` — WS-5 off→monitor→enforce capability ladder (RLS-scoped).
- `payloads/ws7-acme-cost.json`, `ws7-maple-cost-report-underwater.json` — WS-7 margin-autopilot input signal (Maple ≈−14.3% underwater).
- `payloads/s7-admin-cost-report.json` — fleet $8,191 rev / ≈$4,039 cost / ≈$4,152 margin (~50.7%), +66.8% (Globex) → −14.3% (Maple).
- `screenshots/` — re-shot fleet/metering/CASB-NoOps/cross-tenant-rollout/DLP-review-queue/IdP/app-registry surfaces via CDP.
- Harness change: `blog/harness/capture/main.go` extended with the WS-5 rollout and WS-7 cost endpoints (reproducible).

---

## 1. Capture context (Wave 2 — retained artifacts)

| Field | Value |
| --- | --- |
| Repo HEAD | `c3d99ce420d39ad50f557543610491dc26f1876a` (`c3d99ce`) |
| Latest migration | `067_dlp_edm_datasets` (C2 EDM); `066_capability_rollout` (P1) below it |
| Stack | Postgres 16 + NATS 2.10 (Docker) · `sng-control` on :8080 · vite console on :5173 (proxy → :8080) |
| Capture window | 2026-06-12 15:19–15:27 UTC |
| Host | `devin-box` — 8 vCPU AMD EPYC 7763 (AVX2/FMA, no AVX-512/VNNI), 31 GiB RAM, CPU-only |
| Fleet | 9 tenants, 4 residencies/industries (see §3) |
| Feature flags this run | `CASB_NOOPS_ENABLED=true` (recommend-only, `NOOPS_AUTO_ENFORCE=false`); rollout gates driven off→monitor→enforce per §4; nftables installed → `firewall_kernel` scored |

All payloads flow through the real operator API (JWT auth, RLS tenant scoping,
policy compilation, audit log) — the seed/usage/capture harnesses drive the same
endpoints a human operator would, so every row is enforcement-path-authentic.

## 2. Harness results (the load-bearing numbers)

### 2.1 Security efficacy — `efficacy-report.json`
- **Source:** `bench/efficacy` (real enforcement code over known-bad/known-good + adversarial + wild corpora). Run with `--firewall --firewall-kernel --swg --ztna --ips --dlp --malware --dns --adversarial --wild`, `git=c3d99ce`, ONNX Runtime 1.22 for the ML-NER leg, Suricata for IPS, nftables for the kernel leg.
- **Overall verdict: PASS.** Gating rows (all PASS): firewall, **firewall_kernel** (kernel nft ruleset accepted by `nft -c`), swg, ztna 100%; dlp 100% (2400/2400), dlp_ml_ner 97.4% catch / 97.9% acc; malware, dns, ips 100%; **malware_adversarial 100%** (42 bad), **ips_adversarial 100%**.
- **Informational (wild, never gates):** `malware_wild` catch **90.1%** / FPR **9.6%** / precision 73.1% (WARN — honest misses on packed/novel); `dlp_wild` 100% catch / 0% FPR; `ips_wild` 100%. Wild corpus: 2,087 samples (457 malicious / 1,630 benign ≈ 22%), seed `0x53475744`, sha256 `07b2e837ed62`, schema `sng-wild-corpus/v1`.
- **Hot-path throughput:** ztna 1,781,586 decisions/s (561 ns/op); dlp_ml_ner 20,197 scans/s; dlp_wild 802,762 scans/s under 8-thread load.
- **Closes caveats:** §3 "firewall kernel leg unverified", §3 "no adversarial/evasion corpus", §3 "curated corpora not wild traffic / no FPR under load", §5 "corpus is synthetic" (now adds a noisy blended corpus with published FPR).

### 2.2 Multi-queue throughput — `multiqueue-micro.json`
- **Source:** `sng-bench multi-queue --profile skus/micro --mode full-stack --backend nftables`.
- **Single-stream floor 5.451 Gbps → 16-queue ceiling 25.976 Gbps (4.77×).** Per-width: 1q 5.451 (100%), 2q 10.427 (96%), 4q 19.874 (91%), 8q 25.008 (57%), 16q 25.976 (30%) on 8 cores.
- **Closes caveats:** §1 "wire numbers are a single-stream floor" (now shown as a floor→ceiling curve), §7 "why is firewall 5.5 == IPS 5.5" (the single-stream wire is a per-frame syscall ceiling, not an inspection bound; CPU headroom is exposed by fanning out).

### 2.3 8B LLM validation — `payloads/s6-llm-validation-bonsai-8b-q2_0.json` + `llm_validation/quality_report.{json,md}`
- **Source:** P3 (#203) live run of `blog/harness/llm_validation` against the self-hosted **Ternary-Bonsai-8B Q2_0** (prism AVX2-repack kernels), committed. Re-confirmed live on THIS VM in deterministic-only mode (20 queries, classification/verifier/fallback **100%**).
- **8B numbers (live inference, identical 8-vCPU EPYC profile):** parse 100%, verifier 100%, classification 100%, fallback-agreement 100%; **latency p50 8,948 ms / p95 10,793 ms** (≈7.6× faster than the pre-repack Q2_0 path).
- **Closes caveats:** §6 "CI validates a small stand-in model, not the 8B at scale" (now a real 8B run with a published latency table), §6 "pinned Q2_0 needs custom kernels" (documented + measured on the prism build).

### 2.4 Fleet cost & margin — `payloads/s7-admin-cost-report.json`
- **Source:** `GET /api/v1/admin/cost-report`, re-captured 2026-06-12T15:43Z after a **clean full re-seed** of `blog/harness/usage` (TRUNCATE + reseed so every tenant carries current + 5-month history; the first Wave-2 capture skipped history on tenants that already had current rows, which corrupted both the anomaly baseline and the fleet totals — superseded here).
- **9-tenant fleet:** revenue $8,191.00/mo · projected cost **≈$4,056/mo** · **margin ≈$4,135 (≈50%)**. Per-tenant margin spans **≈+66.6% (Globex)** down to **≈−14.8% (Maple Health)** — Maple is the deliberate *underwater* tenant (professional $499 tier consuming enterprise-scale bandwidth/ClickHouse → projected ≈$573/mo), the honest upsell/margin signal the report is built to surface. The 4-tenant base cohort (Globex ≈$667, Acme ≈$1,060, Umbrella ≈$57, Initech ≈$425) totals ≈$2,210/mo, reproducing the canonical reconciled figures from #196. **Note on precision:** these are *projected* (elapsed-fraction-extrapolated) figures, so they drift sub-percent within a billing period — successive captures land at e.g. Maple −14.8% / −14.9% / −15.1% and fleet 50.3–50.5%. The saved payload is the point-in-time source of record; prose uses approximate figures deliberately.
- **Cost anomaly (real):** Initech's `url_cat_lookups` projects **$224.77 vs a $72.31 5-month baseline = ratio 3.1083, severity `warning`** (`s7-initech-cost-anomalies.json`) — a modelled mid-period traffic surge the detector flags while Initech still clears its $499 tier. Acme's anomaly set is empty (control). This is the detector firing on real seeded history, not a hand-written example.
- **Closes caveats:** §7 "cost report tenant_count: 4" (now 9, fleet-wide, with a genuine loss-making tenant rather than an all-green table).

## 3. The 9-tenant fleet (residency × industry coverage)

| Tenant | Tier | Residency | Industry | Margin % |
| --- | --- | --- | --- | --- |
| Globex Health Systems | enterprise | US (us-west) | health | ≈66.6 |
| Acme Retail Group | enterprise | US (us-east) | retail | ≈47.0 |
| Britannia Robotics | enterprise | GB (eu-west-2) | robotics | ≈62.4 |
| Umbrella Logistics | starter | SG (ap-southeast) | logistics | ≈42.4 |
| Nordic EduCloud | starter | SE (eu-north-1) | education | ≈53.9 |
| Lumière Légal | professional | FR (eu-west-3) | legal | ≈55.3 |
| Outback Retail | professional | AU (ap-southeast-2) | retail | ≈49.3 |
| Initech Financial | professional | EU (eu-central) | financial | ≈14.8 |
| Maple Health | professional | CA (ca-central-1) | health | ≈−14.8 |

## 4. Rollout staging exercised (off→monitor→enforce)

`payloads/rollout-{acme,globex,initech}-states.json` + `rollout-acme-clamav-enforce-transition.json`.
- **Acme:** `clamav_swg` → **enforce** (full ladder off→monitor→enforce), `noops_autoenforce` → monitor, `idp_directory_sync` off.
- **Globex:** `clamav_swg` → monitor, `idp_directory_sync` → monitor.
- **Initech:** `clamav_swg` → enforce.
- **Closes caveat:** §5 "four new capabilities not wired into the running control plane" (ClamAV/NoOps/IdP-sync are now live behind the staged-enablement gate, with real per-tenant state).

## 5. Payload index (`payloads/`, 61 files)

### New-module / Wave-1 evidence (captured this run)
| File | Source endpoint | Context |
| --- | --- | --- |
| `rollout-acme-states.json`, `rollout-globex-states.json`, `rollout-initech-states.json` | `GET /tenants/{id}/rollout` | per-tenant capability ladder state after §4 transitions |
| `rollout-acme-clamav-enforce-transition.json` | `POST …/rollout/clamav_swg/transition` | the monitor→enforce transition record (reason + actor audited) |
| `s5-acme-dlp-review-queue.json`, `…-digest.json` | `GET …/dlp/review-queue[/digest]` | 4 seeded AI-app exfil signals (redacted finding aggregates only) + severity/state digest |
| `s5-acme-dlp-review-dismiss-action.json`, `…-queue-after-action.json` | `POST …/review-queue/{id}/dismiss` | operator dismiss of the low-confidence item → 3 pending remain |
| `s5-acme-dlp-classify-multijurisdiction.json` | `POST …/dlp/classify` | Acme policy blocks a PAN (PCI) match, confidence 1.0, action block |
| `s5-acme-dlp-fingerprint-register.json`, `s5-acme-dlp-fingerprints.json` | `POST/GET …/dlp/fingerprints` | C2 document fingerprint register + list |
| `pt-rollout-preview-healthcare-us-3tenants.json` | `POST /policy-templates/rollout/preview` | cross-tenant per-tenant diff for Acme+Globex+Initech (C3 roll-out surface) |
| `s5-acme-casb-apps.json`, `s5-globex-casb-apps.json` | `GET …/casb/apps` | shadow-IT inventory enriched with per-app NoOps verdict (sanction + recommended action + confidence) |
| `s5-acme-casb-noops-actions.json`, `s5-globex-casb-noops-actions.json` | `GET …/casb/noops/actions` | NoOps action timeline, `mode=recommend`, `applied=false` |
| `s4-pops.json`, `s4-pops-capacity-plan.json` | `GET /pops[/capacity-plan]` | C4 PoP fleet listing + capacity plan (no live PoPs registered on this VM; topology evidence is `deploy/pop/` + `docs/pop-topology.md`) |

### Scenario payloads (S1–S7, refreshed/retained)
`s1-*` tenants/MSP/audit · `s2-*` sites/devices/policy-graph · `s3-*` alerts · `s5-*` DLP/CASB/browser · `s6-*` NL-query/posture/playbooks · `s7-*` usage/cost/compliance/integrations · `pt-applied-*` per-jurisdiction template renders · `casb-*` classifications. All are real RLS-scoped API responses.

## 6. Screenshot index (`screenshots/`, 35 files)

### New-module captures (this run, 1568×993 CDP)
| File | Route | What it proves |
| --- | --- | --- |
| `new-cross-tenant-rollout.png` | `/policy/rollout` | guided "apply one baseline to many tenants" surface listing all 9 tenants + residency — closes §2 "templates are a catalog, not a roll-out UI" |
| `new-guided-onboarding-wizard.png` | `/onboarding/guided` | 5-step Tenant→Residency→Industry→First-policy→Done wizard — closes §2 "onboarding is API-fast, not wizard-polished" |
| `new-dlp-review-queue.png` | `/dlp/review-queue` | live triage console: backlog digest, severity/state breakdown, 3 pending + 1 dismissed — closes §5 "DLP review queue has no operator API/console" |
| `new-casb-noops-shadow-it.png` | `/casb` | shadow-IT inventory with per-app risk, sanction, recommended NoOps action (recommend-mode) — closes §5 "NoOps not wired into running control plane" |
| `new-msp-cross-tenant-templates.png` | `/msp/templates` | curate-and-roll-out template cohort surface |
| `new-pops-topology.png` | `/pops` | PoP fleet/capacity console (empty live-registry state; topology in `deploy/pop/`) |
| `new-metering-fleet-top.png`, `new-metering-fleet-table.png` | `/metering` | 9-tenant fleet cost & margin table: total ~$4,067 cost / $8,191 rev / ~$4,124 margin, Maple underwater — closes §7 4-tenant cost report (screenshots predate the clean re-seed; the cost-report payload is authoritative for the figures) |
| `refresh-dashboard-fleet.png`, `refresh-compliance.png` | `/`, `/compliance` | fleet overview + compliance baselines refreshed for the 9-tenant fleet |

### Retained scenario/section captures
`scenario-00..05` (six-scenario capstone) · `s1-*`/`s2-*`/`s3-*`/`s4-*`/`s5-*`/`s6-*`/`s7-*` per-section · `overview-dashboard.png`. (`new-scim-provisioning` intentionally omitted — `/scim` is proxied to the backend SCIM endpoint, not an SPA page; C5 evidence is the conformance suite + `SCIM_CERTIFICATION.md`.)

## 7. Caveat-resolution crosswalk (for the rewrite)

| Blog section / caveat | Status | Evidence |
| --- | --- | --- |
| §1 wire = single-stream floor | **measured both ways** | `multiqueue-micro.json` floor 5.45 → ceiling 25.98 Gbps |
| §2 templates = catalog not roll-out UI | **shipped** | `new-cross-tenant-rollout.png`, `pt-rollout-preview-*` |
| §2 onboarding not wizard-polished | **shipped** | `new-guided-onboarding-wizard.png` |
| §2 no cross-region migration | **shipped (prior)** | `internal/service/tenant/migrate_region.go` (merged) |
| §3 firewall kernel leg unverified | **verified** | `efficacy-report.json` `firewall_kernel` PASS (nft ruleset accepted) |
| §3 no adversarial corpus | **measured** | `malware_adversarial`/`ips_adversarial` 100% |
| §3 curated not wild / no FPR | **measured** | `malware_wild` 90.1%/9.6% FPR, `dlp_wild`, `ips_wild` |
| §4 identity depth / user-subject | **shipped (P2)** | merged #201; behind `ztna.user_subject_eval_enabled` |
| §4 no continuous re-eval | **shipped** | `ReevalLoop` wired (default-OFF) |
| §5 review queue has no operator surface | **shipped** | `new-dlp-review-queue.png`, `s5-acme-dlp-review-*` |
| §5 NoOps/ClamAV/safe-browsing not wired | **wired (staged)** | `new-casb-noops-shadow-it.png`, `rollout-*-states.json` |
| §5 NER 6 classes / no fingerprinting | **expanded (C2)** | 21 jurisdictions + EDM + fingerprints (#209), `s5-acme-dlp-fingerprint-*` |
| §6 stand-in model not 8B | **measured** | `s6-llm-validation-bonsai-8b-q2_0.json` (p50 8.9s / p95 10.8s, 100%) |
| §7 cost report 4-tenant | **fleet-wide** | `s7-admin-cost-report.json` 9 tenants, ≈50% fleet margin (Maple ≈−14.8% underwater) |
| §7 global PoP network | **honest gap** | `deploy/pop/` reference topology + `docs/pop-topology.md` ("software you operate, not a rented network") — the one genuinely unclosed competitive gap |

### Wave-3 workstream crosswalk (merged `main`)

| Workstream | Status | Evidence |
| --- | --- | --- |
| WS-1 universal dormancy tiering | **measured** | `capacity-plan-5000/report.md` 10× (idle 10×, dormant 100×), 5,000→500 visits/cycle/job |
| WS-2 `last_active_at` coverage | **merged** | activity signal feeding tiering + hibernation |
| WS-3 hibernation / scale-to-zero | **wired (default-OFF)** | migration 068; `sng_hibernation_*` gauges in `noops-metrics-snapshot.txt` |
| WS-4 tier-aware telemetry sampling | **wired (default-OFF)** | `CLICKHOUSE_TIER_SAMPLING_ENABLED` |
| WS-5 NoOps auto-promotion | **wired (default-OFF)** | migration 069; `ws5-acme-rollout-*.json` off→monitor→enforce ladder |
| WS-6 capacity autopilot | **running** | `sng_capacity_reconcile_total{ok}=3`, current-vs-recommended gauges |
| WS-7 margin autopilot | **wired (default-OFF)** | `ws7-maple-cost-report-underwater.json` (Maple −14.3%) |
| WS-8 multi-queue edge | **measured** | `multiqueue-micro.json` 5.13×, `multi-queue-branch-large.json` 4.26× |
| WS-9 shared AI inference | **measured** | `capacity-plan-5000/report.md` ~3,696× less memory; `sng_ai_inference_pool_*` gauges |
| WS-10a IdP / IGA breadth | **wired (default-OFF)** | `IDP_DIRECTORY_SYNC_ENABLED`; `ws10a-idp-directory.png`, `ws10a-app-registry.png` |
| WS-10b threat-intel breadth | **measured / wired** | JA3 + Suricata rule bundle (`ips`/`ips_adversarial` 100%); retro-hunt `THREAT_INTEL_RETROHUNT` |
| WS-10c CASB + DLP catalog | **measured / wired** | `dlp` 3,800/3,800; `new-casb-noops-shadow-it.png`; SaaS-API connectors |

## 8. Known honest gaps (carry into the rewrite unchanged)
- **Global PoP footprint** vs Zscaler/Cloudflare/Cato: SNG ships software you run, not a rented anycast network. `deploy/pop/` is a reference topology, not a live global edge.
- **Live SCIM certification** vs real Okta/Entra: in-repo hardening + conformance suite + documented cert plan only (no live-tenant cert this cycle, per the product decision).
- **`malware_wild` FPR 9.6%**: real signature engines miss packed/novel samples — published honestly, not smoothed.
