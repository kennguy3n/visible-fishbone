# ShieldNet Gateway — Executive Scenario Catalog

> The contract for the blog series. Defines the executive business
> scenarios the series is built around, the personas and outcomes behind
> each, the product capabilities each exercises, the UI surfaces involved,
> and — critically — **where each blog's evidence actually comes from** and
> **what can vs. cannot be measured for real in a non-privileged VM**.
>
> This catalog is the contract for the rest of the series: every figure,
> screenshot, and payload in a published post must trace back to an
> evidence source named here, or be a clearly-attributed external citation.

---

## Evidence-integrity rules (apply to every post)

1. **Measured ≠ dry-run.** The `bench/` data-path harness has a `--dry-run`
   mode that crafts and measures frames *in-process with no wire I/O*. Its
   Gbps figures reflect the harness's craft→measure pipeline, **not** real
   inspected throughput, and are reported as such. Real wire numbers need
   `CAP_NET_RAW` + an in-path edge; where this VM cannot produce them, the
   post says so and falls back to (a) the methodology + (b) cited public
   numbers — never invented head-to-head results.
2. **Competitor numbers are published datasheet figures, caveated.** They
   live in [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
   with `source_url` + `caveat` per row. Most competitor boxes are
   ASIC-accelerated appliances; SNG is software-only on a generic x86 VM, so
   every comparison row carries that caveat. Cloud-native (Zscaler) rows are
   the more directly comparable ones.
3. **Screenshots are of real, seeded, error-free pages.** Every console route
   is checked for load/console errors before capture. No screenshots of
   loading/error/empty-by-accident states.
4. **Critique is honest.** Each post ends with a "where we fall short"
   section. The series is an evidence-based critique, not marketing.

---

## Personas

| Persona | Who | What they care about |
| --- | --- | --- |
| **Maya** — MSP platform lead | Runs an MSP managing dozens of SME tenants | Time-to-onboard, per-tenant isolation, blast radius, repeatability |
| **Devraj** — SME IT generalist | One-person IT at a 180-seat firm | One console, safe defaults, not needing a CCIE |
| **Lena** — Security analyst (MSP SOC) | Triages alerts across tenants | Catch-rate, false-positive load, time-to-explanation |
| **Tom** — CFO / buyer | Signs the contract | Predictable spend, consolidation savings, compliance evidence |

---

## The scenarios

Seven scenarios span every major product surface. Each names the capability,
the persona, the business outcome, the UI surfaces, and the evidence source.

### S1 — "Stand up a new SME tenant before the kickoff call ends"
- **Persona:** Maya (MSP). **Outcome:** repeatable, isolated multi-tenant onboarding.
- **Capabilities:** multi-tenant control plane (Postgres RLS), MSP portal, tenant
  provisioning, branding, RBAC, SCIM/IdP, policy templates, bulk ops, audit.
- **UI surfaces:** MSP portal, Tenants, Branding, RBAC, SCIM, IdP, Templates, Audit.
- **Evidence:** console screenshots of the onboarding path; control-plane API
  latency + Postgres-scale numbers from [`bench/controlplane`](../../bench/controlplane);
  the tenant-isolation RLS guarantee (migration + integration test);
  audit-log rows for the provisioning actions. Per-tenant periodic work is spread
  across replicas by a lease-fenced active/active work distributor
  (`internal/service/workshard`), so onboarding the 5,000th tenant does not pile
  onto a single leader.
- **Measurable here?** Yes — control-plane runs locally; API-latency + policy-compile
  + postgres-scale benches are Go and run unprivileged.

### S2 — "One typed policy graph lights up a branch: NGFW + IPS + SWG + DNS + SD-WAN"
- **Persona:** Devraj (SME). **Outcome:** one policy model, not five consoles.
- **Capabilities:** unified policy graph + compiler, NGFW (`sng-fw`), IPS (`sng-ips`),
  SWG (`sng-swg`), DNS security, SD-WAN six-class steering, optional in-kernel
  eBPF/XDP fast path (tail-call split pipeline, LRU verdict cache, bounded IPv6
  extension-header walk) with multi-queue forwarding throughput benchmarks.
  Policy predicates are application-aware: a signed, versioned
  application-identification catalog (`crates/sng-appid`, 215 apps / 17
  categories) replaces a closed set of hand-coded protocols. A
  policy-recommendation engine (`internal/service/policyrec`) proposes
  traffic-derived, verifier-checked graph deltas.
- **UI surfaces:** Policy editor (React-Flow graph), Network policies, Sites, Devices.
- **Evidence:** policy-graph screenshots; policy-compile latency from
  [`bench/controlplane`](../../bench/controlplane); edge throughput/latency datasheet
  from [`bench/`](../../bench) (methodology + dry-run caveat); SD-WAN class framework
  from [`docs/TRAFFIC_CLASSIFICATION.md`](../../docs/TRAFFIC_CLASSIFICATION.md);
  competitor throughput rows (caveated).
- **Measurable here?** Partly — policy compile (real, Go); edge throughput is
  dry-run-only on this VM (methodology + cited numbers, labeled).

### S3 — "Stop a malware drop and a phishing campaign at the edge"
- **Persona:** Lena (SOC). **Outcome:** high catch-rate, low false-positive load.
- **Capabilities:** SWG deny-list/categorize, IPS (Suricata), malware (`sng-swg` yara-x),
  DNS threat-intel, anomaly detection (z-score), and **managed threat content** — a
  curated, ed25519-signed indicator bundle (`internal/service/threatfeed`,
  ≈77,000 indicators across five built-in feeds) delivered with no per-tenant
  config.
- **UI surfaces:** Alerts (scatter + table), Troubleshoot, Threat-intel.
- **Evidence:** **confusion matrix + catch-rate/FPR from
  [`bench/efficacy`](../../bench/efficacy)** over known-bad/known-good corpora —
  this is the headline, the harness drives the *real* enforcement code; Alerts UI
  screenshots; sample detection payloads (input → verdict).
- **Measurable here?** Yes for FW/SWG/ZTNA efficacy (real crate APIs). IPS efficacy
  needs Suricata installed; if absent, labeled and methodology-only.

### S4 — "Retire the VPN: zero-trust access to private apps"
- **Persona:** Devraj (SME). **Outcome:** least-privilege access, no flat VPN.
- **Capabilities:** ZTNA brokering (`sng-ztna`: device + identity + app + posture),
  IdP federation, posture checks, and **lightweight digital-experience monitoring**
  (`crates/sng-dem` + `internal/service/dem`) — ZDX-style per-target availability +
  latency scores with degradation alerts.
- **UI surfaces:** Policy (ZTNA rules), Devices (posture), IdP, RBAC.
- **Evidence:** ZTNA block-rate from [`bench/efficacy`](../../bench/efficacy)
  (real `ZtnaService::evaluate`); access-decision payloads (allow/deny + reason);
  posture-check UI screenshots.
- **Measurable here?** Yes — ZTNA evaluate is a pure crate API, runs unprivileged.

### S5 — "Keep regulated data from leaving: DLP + CASB + browser isolation"
- **Persona:** Lena (SOC) / Tom (compliance). **Outcome:** prevent exfiltration.
- **Capabilities:** on-device DLP (ML classifier), data classification, CASB,
  remote browser isolation (RBI action), edge-driven DLP wake
  (inotify file-write + X11 clipboard monitors classify on-write rather than
  polling). The on-device classifier also reads **image-borne data via OCR** and
  matches **document identity via fingerprinting** (`crates/sng-dlp/{ocr,idm}`).
- **UI surfaces:** DLP, CASB, Browser protection — all wired to Postgres repos.
- **Evidence:** DLP policy + match-event screenshots; classifier input→label
  examples; the repo-wiring fix narrative (why they 404'd, the proper fix).
- **Measurable here?** UI + policy/match flows: yes. ML classifier inference needs
  `libonnxruntime.so` (the blueprint provisions it); if absent, labeled.

### S6 — "AI-assisted policy and anomaly response — with a verifier, not a vibe"
- **Persona:** Lena (SOC) / Devraj (SME). **Outcome:** faster, *safe* operations.
- **Capabilities:** AI assistant (self-hosted **Ternary-Bonsai-8B**),
  policy recommendation + **verifier-checked** deltas, deterministic fallback,
  anomaly detection (z-score scatter), and a shared fleet-wide inference pool so
  one model serves every tenant.
- **UI surfaces:** Assistant, Policy (proposed deltas), Alerts (anomaly scatter), Playbooks.
- **Evidence:** assistant request→response payloads; the verifier rejecting an
  unsafe delta; the deterministic-fallback path when the model is unavailable;
  model behavior notes (compact-model prompt adaptation); anomaly scatter screenshot.
- **Measurable here?** Assistant plumbing + fallback + verifier: yes (Go + Python).
  Live 8B inference needs the model served (Ollama); if absent, the deterministic
  fallback path is exercised and labeled as such.

### S7 — "Prove the spend and the compliance posture to the board"
- **Persona:** Tom (CFO). **Outcome:** predictable cost + consolidation savings + audit.
- **Capabilities:** metering, cost model, continuous compliance evidence, audit,
  integrations (SIEM/PSA/RMM).
- **UI surfaces:** Metering / cost metering dashboard, Compliance, Audit, Integrations.
- **Evidence:** metering dashboard screenshots; **cost analysis + consolidation math
  from [`bench/business-report`](../../bench/business-report)**; the live
  continuous-compliance posture + downloadable SOC 2 / ISO 27001 evidence packs
  (`internal/service/complianceauto`); audit completeness.
- **Measurable here?** Metering UI + cost model + business-report: yes (dry-run sweep
  feeds the cost section; the cost math itself is real).

---

## Coverage check — every major surface is represented

| Capability / surface | Scenario(s) |
| --- | --- |
| Multi-tenant + MSP portal | S1 |
| RBAC / SCIM / IdP / Branding / Templates / Bulk | S1 |
| Policy graph + compiler | S2, S6 |
| Application identification (`sng-appid`) | S2, S3 |
| Policy recommendation engine | S2, S6 |
| NGFW (`sng-fw`) | S2, S3 |
| IPS (`sng-ips`) | S2, S3 |
| SWG (`sng-swg`) + malware (yara-x) | S2, S3 |
| DNS security + threat intel | S2, S3 |
| Managed threat content (signed bundle) | S3 |
| SD-WAN six-class steering | S2 |
| ZTNA (`sng-ztna`) | S4 |
| DLP + data classification (incl. OCR + IDM) | S5 |
| CASB | S5 |
| Browser isolation (RBI) | S5 |
| AI assistant + verifier (Ternary-Bonsai-8B) | S6 |
| Anomaly detection | S3, S6 |
| Digital-experience monitoring (`sng-dem`) | S4 |
| Active/active work distributor | S1 |
| Shared AI inference pool | S6 |
| Playbooks | S6 |
| Metering + cost model | S7 |
| Continuous compliance evidence | S7 |
| Audit | S1, S7 |
| Integrations (SIEM/XDR/IAM/PSA/RMM) | S7 |
| Terraform / IaC | S2 (policy-as-code sidebar) |

---

## Blog series outline

0. **Series intro + the honesty contract** — what SNG is, the three forms, and the
   evidence rules above (why dry-run ≠ measured, why competitor rows are caveated).
1. **S2 — one policy graph** (the differentiated-design centerpiece).
2. **S1 — multi-tenant/MSP onboarding** (the operations story).
3. **S3 — detection efficacy** (catch-rate/FPR confusion matrix — the security proof).
4. **S4 — ZTNA / VPN retirement.**
5. **S5 — DLP / CASB / browser isolation.**
6. **S6 — AI-assisted, verifier-checked operations** (the model deep-dive + critique).
7. **S7 — cost + compliance for the buyer** (+ the consolidated competitive critique).

Each post: system context → the scenario walked in the UI (real screenshots) →
the input/output payloads → the measured numbers (or labeled methodology) →
honest competitive read → "where we fall short".
