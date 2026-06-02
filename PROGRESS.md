# ShieldNet Gateway — Implementation Progress

> Living progress tracker for the SNG monorepo. Phased against
> [`PROPOSAL.md`](./PROPOSAL.md) §10. Cross-referenced with
> [`ARCHITECTURE.md`](./ARCHITECTURE.md) for component identity.
> Updated as PRs land on `main`.

**Overall status:** Phase 1 complete (~100%), Phase 2 complete
(~100% — all gaps resolved in Phase 3 Block 1), Phase 3 in
progress (~87%, 26 of 30 tasks complete).

---

## Phase 1 — Foundation (~100%)

Establishes the multi-tenant control-plane bones every later
phase depends on. All Phase 1 surfaces are on `main`.

### Control plane (Go)

- [x] PostgreSQL schema + RLS role bootstrap
      (`migrations/001_initial_schema.*`, `migrations/002_role_bootstrap.*`)
- [x] `repository` interfaces with two backing drivers — `pgxpool`
      and in-memory (`internal/repository/{interfaces.go,postgres,memory}`)
- [x] `repository/postgres` integration harness driven by
      testcontainers
      (`internal/repository/postgres/harness_integration_test.go`)
- [x] `cmd/sng-migrate` runner that applies the embedded SQL
      with the migrate-runner privilege role
      (`internal/migrate/runner.go`)
- [x] Tenant service — lifecycle (active / suspended / deleted),
      slug uniqueness, and creation hooks
      (`internal/service/tenant/`)
- [x] Identity service — user + role assignment, session token
      issuance (`internal/service/identity/`)
- [x] Hierarchical RBAC — system / tenant / site scope composition
      (`internal/service/rbac/`)
- [x] Site service — site CRUD, per-tenant scoping
      (`internal/service/site/`)
- [x] Audit service — append-only audit log with hash-chain
      tail-pointer (`internal/service/audit/`)
- [x] API-key service with KMS-backed envelope encryption and
      per-tenant cap enforcement
      (`internal/service/apikey/`,
      `migrations/006_tenant_api_keys.*`)
- [x] HTTP middleware stack — request ID, structured logging,
      panic recovery, CORS, tenant-context propagation, rate
      limiting, auth (`internal/middleware/`)
- [x] REST handler layer with embedded OpenAPI 3.1 spec
      (`internal/handler/`, `api/openapi.yaml`,
      `internal/handler/openapi.yaml` — kept byte-identical
      via CI)
- [x] OpenAPI lint (Spectral) wired into CI
      (`.github/workflows/ci.yml`, `.spectral.yaml`)
- [x] NATS JetStream stream definitions, durable consumer
      bootstrap, and idempotent publisher
      (`internal/nats/streams.go`, `internal/nats/publisher.go`)
- [x] Event-envelope schema (Go ↔ Rust wire contract)
      (`internal/nats/schema/`)
- [x] Webhook delivery service — outbound HMAC-signed events,
      retry with backoff, claim-token issuance
      (`internal/service/webhook/`,
      `migrations/003_webhooks.*`, `migrations/004_webhook_processing.*`)
- [x] Policy service — typed policy graph, per-target compile
      pipeline, Ed25519 bundle signing with KMS-wrapped keys,
      agent-pull endpoint
      (`internal/service/policy/`,
      `migrations/005_policy_signing_keys.*`,
      `migrations/007_policy_bundle_sha256.*`)
- [x] Application-registry seed + sync from vendor feeds (M365,
      Google, AWS), per-tenant demotion engine
      (`internal/service/appdb/`,
      `migrations/008_app_registry.*`,
      `migrations/009_app_registry_seed.*`)
- [x] CI pipeline with a fast PR gate (lint, unit, tidy,
      openapi-lint) plus a full integration suite (testcontainers
      Postgres + NATS) (`.github/workflows/ci.yml`)
- [x] Spec-drift guard in CI — `api/openapi.yaml` must equal
      `internal/handler/openapi.yaml` byte-for-byte

### Enforcement plane (Rust)

- [x] Cargo workspace — `#![forbid(unsafe_code)]` at the workspace
      level, `1.85` MSRV pin, workspace-pedantic clippy profile
      (`Cargo.toml`, `crates/*/Cargo.toml`)
- [x] `sng-core` — shared types, identifier newtypes, MessagePack
      envelope, signed-bundle verification, error taxonomy,
      lifecycle / supervisor traits
- [x] `sng-pal` — endpoint-side platform abstraction layer
      (traffic capture, posture, tunnel, secure key store) with
      per-OS `unsafe` lifted locally and rationale-commented
- [x] `cargo-deny` for licences / advisories / bans / sources
      with a pinned version (`deny.toml`,
      `.github/workflows/ci.yml`)

---

## Phase 2 — Secure Edge MVP (~100%)

Lands the core "gateway" product surface — branch / site edge
appliance binary, endpoint-client binary, and the twelve library
crates they compose.

### Library crates (all on `main`)

- [x] `sng-comms` — TLS 1.3 + MessagePack + HTTP/2 control-plane
      client, batching, replay-safe ack, bounded spool
      (PR 3 — `feat(sng-comms)`)
- [x] `sng-policy-eval` — local policy evaluation engine,
      verified bundles, hot-swap, fail-closed (PR 4 —
      `feat(sng-policy-eval)`)
- [x] `sng-telemetry` — collector pipeline: dedup, redact,
      enrich, optional PCAP capture, egress; with a boot-time
      identity contract between `Enricher` and `TelemetryClient`
      (PR 5 — `feat(sng-telemetry)`)
- [x] `sng-dns` — filter chain, UDP resolver, telemetry hooks
      (PR 6 — `feat(sng-dns)`)
- [x] `sng-swg` — Envoy ext-authz handler: URL categorization,
      malware verdict, per-tenant rate-limit, bypass list
- [x] `sng-fw` — firewall: L3-L7 policy, NAT, app awareness,
      deterministic nftables rule set
- [x] `sng-ips` — Suricata wrapper: rule sync, alert normalization,
      supervisor + signal lifecycle
- [x] `sng-ztna` — Zero-Trust Network Access: mTLS device
      identities, posture binding, app access broker (PR 10 —
      `feat(sng-ztna)`)
- [x] `sng-sdwan` — SD-WAN overlay tunnels, path scoring, health
      probes, app-aware steering, sticky-flow cache (PR 11 —
      `feat(sng-sdwan)`)
- [x] `sng-updater` — self-update with signed manifests
      (Ed25519), dual-bank install, rollback-safe health window
      (PR 12 — `feat(sng-updater)`)

### Binary crates

- [x] `sng-edge` — edge VM appliance binary, composes every
      enforcement library behind `sng-core::supervisor::Supervisor`
      (PR 13 — `feat(sng-edge,sng-agent)`)
- [x] `sng-agent` — endpoint client binary, strict subset of edge
      subsystems (comms, policy_eval, telemetry, ztna,
      pal_capture / pal_posture / pal_tunnel) (PR 13)
- [x] End-to-end integration tests for both binaries — drain
      bridge buffer before releasing handle on shutdown, keep
      desired-tunnels publisher alive across `supervisor.run()`
      (PR 14 — `test(edge)` / `test(agent)`)

### Control plane support for Phase 2

- [x] Telemetry pipeline scaffold — JetStream pull-consumer that
      drains `SNG_TELEMETRY` with batching, dedup ring, DLQ
      routing, hot + cold writer interfaces, graceful shutdown
      (`internal/service/telemetry/service.go`)
- [x] ClickHouse batch writer — `traffic_class` as
      `LowCardinality(String)`, per-tenant retention, retry with
      exponential backoff, defence-in-depth `Abort()`,
      `PartialDropFlushes` counter
      (`internal/service/telemetry/clickhouse/writer.go`)
- [x] S3 cold archive writer — gzip JSON-Lines objects keyed by
      `tenant_id / yyyy=/mm=/dd= / class`, per-partition size and
      interval triggers
      (`internal/service/telemetry/s3/writer.go`)
- [x] Replay worker — drain `SNG_DLQ`, re-publish onto the
      origin subject, ack only after a successful re-publish
      (`internal/service/telemetry/replay/worker.go`)
- [x] Traffic classification + steering framework — six classes,
      per-deployment-mode steering tables, app-registry overrides,
      byte-deterministic bundle layout
      (`docs/TRAFFIC_CLASSIFICATION.md`,
      `feat(appdb,policy,site,telemetry)`)

### Known Phase 2 gaps (resolved in Phase 3 Block 1)

- [x] **NATS JetStream consumer worker** factored into its own
      file with explicit per-tenant rate-limiting and backpressure
      knobs (`internal/service/telemetry/consumer.go` — Task 1)
- [x] **Telemetry deduplication** factored into a standalone
      service with sequence-number + device-ID keys
      (`internal/service/telemetry/dedup.go` — Task 4)
- [x] **Telemetry normalization** factored into its own pass
      with schema-version validation and tenant + site + identity
      enrichment (`internal/service/telemetry/normalize.go` —
      Task 5)
- [x] **S3 cold archiver** — content-addressed SHA-256 seal,
      zstd compression, per-tenant budget guardrails
      (`internal/service/telemetry/s3/archiver.go` — Task 3)
- [x] **Replay service** — re-hydrate cold-tier events from S3
      and feed them into the policy change simulator
      (`internal/service/telemetry/replay/service.go` — Task 6)

---

## Phase 3 — Unified Operations (in progress)

Converts raw capability into operator UX leverage: change
simulation, baseline alerts + behaviour models, AI-assisted
incident summaries, ticketing integrations, MSP hierarchy +
co-management.

The exit criterion is: support-ticket rate per tenant trends
down; MSP onboarding is repeatable.

### Block 1 — Telemetry pipeline completion

- [x] **Task 1.** NATS JetStream consumer worker —
      `internal/service/telemetry/consumer.go`: durable consumer
      on `sng.<tenant>.telemetry.*`, MessagePack envelope
      decoding, hot + cold routing, graceful shutdown,
      backpressure, per-tenant rate limiting
- [x] **Task 2.** ClickHouse writer completion —
      `internal/service/telemetry/clickhouse/writer.go`: tenant
      isolation contract, `traffic_class` `LowCardinality`,
      retry/backoff, per-tenant retention 30-90 days, new
      migration for the table DDL
      (`migrations/clickhouse/001_sng_telemetry.up.sql`)
- [x] **Task 3.** S3 cold archiver —
      `internal/service/telemetry/s3/archiver.go`: partition by
      `tenant_id/yyyy=/mm=/dd=`, zstd compression, SHA-256 seal
      for tamper detection, per-tenant budget guardrails
- [x] **Task 4.** Telemetry deduplication service —
      `internal/service/telemetry/dedup.go`: rolling-window
      dedup keyed by sequence number + device ID, bounded
      memory with LRU eviction
- [x] **Task 5.** Telemetry normalization —
      `internal/service/telemetry/normalize.go`: schema-version
      validation, tenant + site + identity enrichment, typed
      output structs ready for ClickHouse insertion
- [x] **Task 6.** Telemetry replay service completion —
      `internal/service/telemetry/replay/service.go`: re-hydrate
      cold-tier events from S3, replay against proposed bundles,
      estimate user impact

### Block 2 — Policy change simulation

- [x] **Task 7.** Policy change simulator —
      `internal/service/policy/simulator.go`: deterministic
      simulator that replays Tier-2 telemetry against old + new
      compiled bundles and produces an impact report
- [x] **Task 8.** Policy dry-run mode —
      `internal/service/policy/dryrun.go`: shadow bundles
      distributed to edges / endpoints that log verdicts without
      enforcing; NATS subject routing for dry-run telemetry
- [x] **Task 9.** Policy canary rollout —
      `internal/service/policy/canary.go`: dry-run shadow →
      canary cohort (configurable %) → full fleet; one-click
      rollback at any stage; PostgreSQL-tracked state
      (`migrations/010_policy_rollouts.*`,
      `migrations/011_policy_graphs_is_draft.*`)
- [x] **Task 10.** Policy diff + impact-report API —
      `internal/handler/policy_simulation.go` + OpenAPI: REST
      endpoints for triggering simulations, retrieving impact
      reports, approving / rejecting proposed changes

### Block 3 — Baseline alerts + behaviour models

- [x] **Task 11.** Statistical baseline engine —
      `internal/service/baseline/engine.go`: z-score + EWMA over
      per-tenant dimensions (bytes per app class, DNS query
      volume, failed auth attempts, policy deny rate);
      self-explaining alerts
- [x] **Task 12.** Anomaly detector —
      `internal/service/baseline/anomaly.go`: configurable
      thresholds, alert generation, feed-back into the telemetry
      pipeline and operator portal, per-tenant sensitivity
      tuning
- [x] **Task 13.** Baseline model persistence —
      `internal/repository/{memory,postgres}/baseline.go` +
      `migrations/012_baseline_models.*`: store computed baselines
      per-tenant, per-dimension, with rolling updates (Welford +
      EWMA estimators)
- [x] **Task 14.** Alert routing + suppression —
      `internal/service/alert/router.go` +
      `migrations/013_alerts.*`: dispatch to operator portal,
      NATS subjects, external integrations; typed per-tenant
      suppression rules with audit trail
- [x] **Task 15.** Feedback loop for false-positive reduction —
      `internal/service/alert/feedback.go`: operator feedback on
      dismissed / false-positive alerts feeds back into per-tenant
      baseline tuning

### Block 4 — Integration service

- [x] **Task 16.** Integration service scaffold —
      `internal/service/integration/service.go`: manage external
      connectors (SIEM, ticketing, IAM, RMM / PSA) using the
      same service pattern as tenant / policy / webhook
- [x] **Task 17.** Syslog export —
      `internal/service/integration/syslog.go`: RFC 5424 / 5425
      with TLS, per-tenant destinations, subscribe to telemetry
      NATS subjects, retry with backoff
- [x] **Task 18.** SIEM / XDR webhook export —
      `internal/service/integration/siem_export.go`: outbound
      delivery to Splunk HEC / Elastic / Sentinel via HMAC-signed
      webhooks, retry / backoff, per-tenant destination config
- [x] **Task 19.** Ticketing integration — Jira —
      `internal/service/integration/ticketing/jira.go`:
      bidirectional ticket sync, OAuth 2.0, create incidents
      from SNG alerts, sync status back
- [x] **Task 20.** Ticketing integration — ServiceNow —
      `internal/service/integration/ticketing/servicenow.go`:
      same pattern, REST + OAuth, bidirectional case status sync
- [x] **Task 21.** Integration handler + API —
      `internal/handler/integration.go` + OpenAPI: REST CRUD
      endpoints for connectors, test connectivity, list
      available integrations, view sync status

### Block 5 — MSP hierarchy + co-management

- [x] **Task 22.** MSP hierarchy data model —
      `migrations/015_msps.*` +
      `internal/repository/types.go` extension: MSP entity,
      MSP→tenant relationship, MSP-scoped roles, per-MSP
      branding config, MSP-level RLS extension
- [x] **Task 23.** MSP RBAC extension —
      `internal/service/rbac/msp.go`: MSP → tenant → site → role
      composition, bulk operations across tenant cohorts
- [x] **Task 24.** MSP bulk operations —
      `internal/service/tenant/bulk.go`: apply policy templates
      across tenant cohorts, bulk site provisioning, bulk device
      enrollment-token generation
- [x] **Task 25.** MSP branding —
      `internal/service/tenant/branding.go` +
      `migrations/015_msps.*`: logo, colour scheme, custom domain
      per MSP, inherited by tenants unless overridden
- [x] **Task 26.** MSP handler + API —
      `internal/handler/msp.go` + OpenAPI: lifecycle, MSP↔tenant
      assignments, bulk operations, branding config, MSP-role
      authorization middleware

### Block 6 — AI assistant foundation + identity

- [x] **Task 27.** AI service interface —
      `internal/service/ai/service.go`: methods for
      policy-auto-suggest, incident summarisation,
      troubleshooting assistance; the
      "AI proposes, deterministic systems enforce" invariant
- [x] **Task 28.** Incident summarisation —
      `internal/service/ai/summarizer.go`: LLM-backed summaries
      grounded in ClickHouse evidence; refuses to assert facts
      outside collected evidence; flags output as AI-generated;
      pluggable LLM provider interface
- [ ] **Task 29.** SCIM 2.0 provisioning —
      `internal/service/identity/scim.go` +
      `internal/handler/scim.go`: inbound provisioning for users
      + groups (Okta / Entra / Google Workspace); tenant-isolated
      create / update / delete
- [ ] **Task 30.** Device enrollment flow —
      `internal/service/identity/enrollment.go` +
      `internal/handler/device.go` extension: claim-token
      enrollment, Ed25519 public-key binding, short-lived mTLS
      certificate issuance, device lifecycle (enrolled / active /
      revoked)

---

## Phase 4 — Data protection expansion (planned)

CASB discovery + top SaaS API connectors (M365, Google
Workspace, Slack, Salesforce), web + SaaS DLP, browser
protections, pre-baked policy templates per industry. Exit
criterion: controlled false-positive rate, usable policy
templates published.

### Block 1 — CASB discovery + SaaS connectors

- [ ] **Task 31.** CASB discovery engine —
      `internal/service/casb/discovery.go`: passive traffic
      inspection on SWG flow logs to identify shadow-IT SaaS
      usage per tenant; app fingerprinting against the app
      registry
- [ ] **Task 32.** SaaS API connector framework —
      `internal/service/casb/connector.go`: OAuth 2.0 credential
      lifecycle, pagination helpers, rate-limit backoff, tenant-
      isolated token storage
- [ ] **Task 33.** M365 connector —
      `internal/service/casb/connectors/m365.go`: Graph API
      audit-log ingestion, user activity, sharing events,
      sensitivity-label read
- [ ] **Task 34.** Google Workspace connector —
      `internal/service/casb/connectors/google.go`: Admin SDK
      audit-log, Drive sharing events, OAuth token grants
- [ ] **Task 35.** Slack connector —
      `internal/service/casb/connectors/slack.go`: Enterprise
      Grid audit API, file sharing, external channel detection
- [ ] **Task 36.** Salesforce connector —
      `internal/service/casb/connectors/salesforce.go`: Event
      Monitoring, login events, report export detection

### Block 2 — Web + SaaS DLP

- [ ] **Task 37.** DLP engine scaffold —
      `internal/service/dlp/engine.go`: content inspection
      pipeline; regex + keyword detectors, configurable per-
      tenant policies, verdict (allow / redact / block)
- [ ] **Task 38.** DLP detectors — PII / PCI / PHI —
      `internal/service/dlp/detectors/`: credit-card (Luhn),
      SSN, passport, health-record patterns; per-region variants
- [ ] **Task 39.** DLP for SWG inline —
      `internal/service/dlp/inline.go`: hook into sng-swg
      ext-authz path for upload / paste interception on HTTP
      body inspection
- [ ] **Task 40.** DLP for SaaS API (CASB out-of-band) —
      `internal/service/dlp/oob.go`: scan CASB-discovered files
      and messages via connector APIs; remediation actions
      (quarantine / notify / revoke share)
- [ ] **Task 41.** DLP policy templates —
      `internal/service/dlp/templates/`: PCI-DSS, HIPAA, GDPR
      starter templates; per-industry pre-baked rules
- [ ] **Task 42.** DLP handler + API —
      `internal/handler/dlp.go` + OpenAPI: policy CRUD,
      incident list, false-positive feedback, per-tenant
      dashboard metrics

### Block 3 — Browser protection

- [ ] **Task 43.** Browser isolation proxy —
      `internal/service/browser/isolation.go`: pixel-push or
      DOM-rewrite isolation for high-risk URLs identified by
      SWG categorization
- [ ] **Task 44.** Browser extension policy —
      `internal/service/browser/extension_policy.go`: allow /
      block / audit extension installs; per-tenant allow-list,
      risk scoring from Chrome Web Store metadata
- [ ] **Task 45.** Credential phishing protection —
      `internal/service/browser/phishing.go`: detect corporate
      credential entry on non-corporate domains; real-time
      block + alert generation

### Block 4 — Policy templates + reporting

- [ ] **Task 46.** Industry policy template library —
      `internal/service/policy/templates/`: healthcare, finance,
      education, retail starter bundles; operators clone +
      customize
- [ ] **Task 47.** Compliance posture report —
      `internal/service/compliance/report.go`: map enforced
      policies to regulatory frameworks (PCI-DSS, HIPAA, SOC2,
      ISO 27001); exportable PDF / JSON evidence packs
- [ ] **Task 48.** Data protection dashboard API —
      `internal/handler/data_protection.go` + OpenAPI: DLP
      incident trends, CASB shadow-IT summary, compliance
      posture score, per-tenant drill-down

## Phase 5 — Advanced automation (planned)

Guided remediation playbooks, policy-tightening suggestions
verified by the deterministic compiler, autonomous
troubleshooting with approval gates. eBPF / VPP fast-path on
the data plane when throughput justifies. Exit criterion:
measurable support-time reduction; every AI action verified
against the deterministic compiler.

## Phase 6 — Hardware packaging (planned)

Reference whitebox + OEM appliance SKUs, secure boot + TPM
identity for the hardware path. Container packaging may land
earlier. Exit criterion: software attach + renewal economics
demonstrate stronger margin than hardware revenue alone.

---

## Changelog (most recent first)

- `2026-06-02` — Tasks 1-15, 22-26 checked off (code was merged
  via PRs #38, #40, #41, #42 but PROGRESS.md not updated).
  Phase 2 known gaps all resolved. Phase 3 Block 6 (Tasks 27-30)
  remains in progress. Phase 4 Blocks 1-4 (Tasks 31-48) task list
  added. Overall status updated to Phase 3 ~87% (26/30).
- `2026-06-01` — PROGRESS.md recovery: re-derive phase tracker
  from `PROPOSAL.md` §10 and the actual `main` checkpoint;
  Phase 1 marked complete, Phase 2 marked ~95% complete, Phase 3
  Block-1 through Block-6 task list seeded.

Earlier history pre-dates this file; see `git log` for the
per-PR record.
