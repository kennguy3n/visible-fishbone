# SOC2 Type II Readiness — Gap Analysis & Control Mapping

Status: readiness assessment (WS9). This maps SNG's **own** SOC2 Type II
audit posture to the evidence machinery already in
`internal/service/compliance/`, and is honest about what is wired, what
is stubbed at the seam, and what lives outside the product entirely.

## 1. Two different "compliance" surfaces — don't conflate them

The repo has two compliance subsystems that serve different audiences:

1. **Tenant-facing posture reporting** — `ComplianceReport`
   (`internal/service/compliance/report.go`, `types.go`). Maps a
   *tenant's enforced policies* onto regulatory frameworks
   (`PCI_DSS`, `HIPAA`, `SOC2`, `ISO_27001`, plus the regional
   `PDPA`, `NESA_TDRA`, `FDPIC_NDSG`, `BDSG_GDPR`, `CSA_CE` catalogs in
   `regional.go`) and produces a score + per-control status
   (`met` / `partial` / …). This tells a *customer* "given the SNG
   policies you've enabled, here's your control coverage."

2. **SNG's own SOC2 evidence pipeline** — `SOC2EvidenceCollector`,
   `EvidenceService`, `Scheduler` (`soc2.go`, `evidence.go`,
   `scheduler.go`). Collects, signs, and WORM-archives *operational
   evidence about the SNG SaaS itself* for our auditor.

**This document is about #2** — the company's SOC2 Type II
certification. #1 is a product feature and is only referenced where it
doubles as evidence.

## 2. What SOC2 Type II requires (and why the code shape fits)

A SOC2 **Type II** report attests that controls were not only designed
appropriately (that's Type I) but **operated effectively over a period**
(typically 3–12 months). The auditor therefore needs:

- A defined set of controls (the Trust Services Criteria).
- **Recurring, timestamped evidence** that each control operated
  throughout the window — not a single point-in-time snapshot.
- **Tamper-evidence** on that evidence (so a late-created artifact can't
  masquerade as contemporaneous).
- **Gap accountability** — a missed collection must be visible, not
  silently absent.

The existing pipeline is built precisely for this:

| Type II need | Implementation |
|---|---|
| Defined controls | `ExpectedControls = [CC6.1, CC6.2, CC6.3, CC7.1, CC8.1]` (`soc2.go`) |
| Recurring evidence over a period | `Scheduler` runs weekly collections + monthly aggregation (`CollectWeekly`, `AggregateMonthly`) |
| Timestamped, deterministic artifacts | `EvidenceBundle.CanonicalBytes()` → deterministic encoding with a consistent `CollectedAt` |
| Tamper-evidence | Ed25519 detached signature over the canonical bytes (`Signer.Sign`, verified by `VerifySignature`) |
| Immutable retention | S3 **object-lock COMPLIANCE mode**, `DefaultRetentionYears = 7` (`s3store.go` sets `ObjectLockMode=COMPLIANCE` + `RetainUntilDate`) |
| Gap accountability | `Scheduler.DetectGaps` → `GapReport{MissingWeekly, StaleWeekly}`; two-phase `Store` leaves a `collecting`/`failed` row instead of a silent gap |
| Honest non-fabrication | A control whose `Sources` function is `nil` is **omitted**, then flagged as a gap — never back-filled with a fake artifact (`soc2.go` header comment) |

This last property is the most important for an *honest* readiness
posture: the system is designed to under-claim, not over-claim.

## 3. Control mapping (TSC → SNG implementation → evidence source)

The five controls the collector defines, mapped to the real SNG
mechanism that implements them and the `Sources` field that exports the
evidence. "Source wired?" reflects whether the `EvidenceFunc` is
populated in `cmd/sng-control` today.

### CC6.1 — Logical access

- **SNG mechanism**: OIDC-terminated operator identity in production
  (HMAC compiled out — [`SECURITY.md`](../SECURITY.md) §"Operator
  authentication"); per-tenant API keys; Postgres RLS as the primary
  tenant boundary; RBAC roles/permissions.
- **Evidence**: `Sources.RBACPolicy` (`rbac_policy`),
  `Sources.AccessReviews` (`user_access_reviews`).
- **Mapping quality**: Strong. The access-control design is enforced in
  code and defense-in-depth-layered (`SECURITY.md` §"Defense-in-depth
  for tenant isolation").

### CC6.2 — System operations (provisioning/deprovisioning, change exec)

- **SNG mechanism**: blue-green control-plane deploys, dual-bank edge /
  endpoint upgrades ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §8), audited
  change approvals (playbook approval workflow, §3.12).
- **Evidence**: `Sources.DeploymentLogs` (`deployment_logs`),
  `Sources.ChangeApprovals` (`change_approvals`).

### CC6.3 — Change management

- **SNG mechanism**: policy version history + policy-change simulation
  (`internal/service/policy`, ARCHITECTURE §3.9); signed policy bundles
  (Ed25519, rotation per [`key-ceremony.md`](./key-ceremony.md)).
- **Evidence**: `Sources.PolicyChangeHistory` (`policy_change_history`),
  `Sources.SimulationResults` (`simulation_results`).

### CC7.1 — Monitoring (detect & respond)

- **SNG mechanism**: alerting rules/thresholds, incident-response
  playbooks (ARCHITECTURE §3.12), telemetry pipeline (§6).
- **Evidence**: `Sources.AlertConfigs` (`alert_configs`,
  config-snapshot kind), `Sources.IncidentPlaybooks`
  (`incident_playbooks`).

### CC8.1 — Availability (change to meet objectives / resilience)

- **SNG mechanism**: HA control-plane config, capacity planning
  (ARCHITECTURE §3.15), backup schedules + retention.
- **Evidence**: `Sources.UptimeMetrics` (`uptime_metrics`),
  `Sources.HAConfig` (`ha_config`), `Sources.BackupSchedules`
  (`backup_schedules`).

| Control | SNG mechanism | Evidence sources | Code |
|---|---|---|---|
| CC6.1 | OIDC + RLS + RBAC | `RBACPolicy`, `AccessReviews` | `soc2.go`, `SECURITY.md` |
| CC6.2 | Blue-green / dual-bank + change approvals | `DeploymentLogs`, `ChangeApprovals` | `soc2.go`, `playbook/approval.go` |
| CC6.3 | Policy versioning + simulation + signed bundles | `PolicyChangeHistory`, `SimulationResults` | `policy/`, `key-ceremony.md` |
| CC7.1 | Alerting + IR playbooks + telemetry | `AlertConfigs`, `IncidentPlaybooks` | `soc2.go`, ARCH §3.12/§6 |
| CC8.1 | HA + capacity + backups | `UptimeMetrics`, `HAConfig`, `BackupSchedules` | `soc2.go`, ARCH §3.15 |

## 4. Gap analysis

### 4.1 Wiring gaps (in-scope, closeable in code)

The collector is complete; readiness depends on every `Sources`
function being wired in `cmd/sng-control`. Each unwired function is a
real, auto-flagged gap (the control's artifact is omitted and
`DetectGaps` surfaces a missing/stale bundle). Track wiring per source:

- [ ] CC6.1 `RBACPolicy`, `AccessReviews`
- [ ] CC6.2 `DeploymentLogs`, `ChangeApprovals`
- [ ] CC6.3 `PolicyChangeHistory`, `SimulationResults`
- [ ] CC7.1 `AlertConfigs`, `IncidentPlaybooks`
- [ ] CC8.1 `UptimeMetrics`, `HAConfig`, `BackupSchedules`

Because the design omits-and-flags rather than fabricates, partial
wiring produces an *accurate* partial bundle plus a gap signal — exactly
what a Type II auditor expects to see during the ramp.

### 4.2 Trust Services Criteria not modelled in code

The collector encodes five Common Criteria. A full SOC2 Security
(Common Criteria) audit spans **CC1–CC9**. The following are **not**
product-evidenced because they are organizational, not technical, and
must be evidenced out-of-band (HR system, ticketing, vendor register):

- **CC1** (control environment — org structure, board oversight, code
  of conduct), **CC2** (communication), **CC3** (risk assessment),
  **CC4** (monitoring of the control environment), **CC5** (control
  activities) — governance/process evidence.
- **CC6.4–CC6.8** (physical access, data disposal, malware) — partially
  cloud-provider-inherited (data-center physical security is the IaaS
  provider's SOC2, consumed as a subservice-organization report under
  the **carve-out / inclusive** method).
- **CC9** (risk mitigation — vendor management, business continuity).

These belong in the company's GRC tooling, not this repo. This document
flags them so readiness is assessed against the *whole* report, not just
the slice the product automates.

### 4.3 Additional Trust Services Categories

The five controls target the **Security** category. If the report scope
adds **Availability**, **Confidentiality**, **Processing Integrity**, or
**Privacy**, additional criteria (A1.x, C1.x, PI1.x, P1–P8) apply.
SNG has strong technical substrate for several:

- **Confidentiality (C1.x)**: envelope encryption + CMK
  ([`cmk-architecture.md`](./cmk-architecture.md)), tenant-bound AAD,
  data-residency enforcement (`internal/service/residency`).
- **Availability (A1.x)**: capacity planning, HA config, backups
  (already CC8.1-adjacent).
- **Privacy (P-series)**: metadata-first telemetry (payloads dropped at
  the edge unless opted in — `SECURITY.md`), data residency, regional
  framework catalogs (`regional.go`).

Extending `ExpectedControls` + `Sources` to cover a chosen extra
category is the natural follow-on once Security is signed off.

## 5. Evidence integrity posture (auditor-facing)

- **Signed**: every bundle is Ed25519-signed over deterministic
  canonical bytes; the signing key follows the escrow-by-publication
  model in [`key-ceremony.md`](./key-ceremony.md) §7 so an auditor can
  verify historical bundles even after key rotation.
- **Immutable**: S3 object-lock COMPLIANCE mode for 7 years means even a
  root operator cannot alter or delete an archived bundle within the
  window — strong assurance for the "operated throughout the period"
  attestation.
- **Region-correct**: evidence archives are a residency-guarded plane;
  combined with CMK, evidence for an EU tenant's data stays in-region.
- **Gap-honest**: missing/stale evidence is detected and alerted
  (`DetectGaps`), never hidden.

## 6. Readiness summary

| Area | State |
|---|---|
| Control catalog (CC6.1–CC8.1) | **Defined** in code |
| Evidence collection/sign/archive pipeline | **Built** (`EvidenceService`, WORM, signed) |
| Recurring cadence + gap detection | **Built** (`Scheduler`) |
| Source wiring in `cmd/sng-control` | **Partial** — track §4.1 |
| CC1–CC5, CC9 (org/process) | **Out-of-product** — GRC tooling |
| Subservice (IaaS physical/CC6.4) | **Inherited** — collect provider SOC2 |
| Extra TSC categories (A/C/PI/P) | **Substrate exists**, not yet collected |

**Bottom line**: the hard, product-specific machinery for a Security
Type II report — recurring, signed, immutable, gap-detected evidence —
exists and is sound. Readiness work is (a) finishing source wiring
(§4.1), (b) assembling the organizational CC1–CC9 evidence outside the
product, and (c) collecting the subservice provider's report. None of
these require redesign; the seams are correct.
