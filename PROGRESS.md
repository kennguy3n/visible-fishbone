# ShieldNet Gateway — Implementation Progress

> Living progress tracker for the SNG monorepo. Phased against
> [`PROPOSAL.md`](./PROPOSAL.md) §10. Cross-referenced with
> [`ARCHITECTURE.md`](./ARCHITECTURE.md) for component identity.
> Updated as PRs land on `main`.

**Overall status:** Phases 1-5 complete (~100%). Phase 1
(foundation) and Phase 2 (secure edge MVP) on `main`; Phase 3
(unified operations, Tasks 1-30) complete; Phase 4 (data
protection expansion, Tasks 31-48) complete; Phase 5 (advanced
automation, Tasks 49-77) complete across five feature PRs
(#50, #51, #52, #53, #54). Phase 6 (hardware packaging) not
started.

> **Audit note (Session 6 docs pass).** The Phase 4 Block 3/4
> task descriptions were re-derived from the merged code on
> `main` — several originally-planned items shipped under a
> different shape than the placeholder task list assumed. See
> the per-task entries and the "Audit findings" callout in
> Phase 4 below for the exact planned-vs-shipped reconciliation.

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

## Phase 3 — Unified Operations (~100%)

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
- [x] **Task 29.** SCIM 2.0 provisioning —
      `internal/service/identity/{scim.go,scim_types.go}` +
      `internal/handler/scim.go`: inbound provisioning for users
      + groups (Okta / Entra / Google Workspace); tenant-isolated
      create / update / delete; `/scim/` route prefix, group
      `externalId`, filter parser, single-valued `PatchGroup`
      add (`migrations/020_scim_external_ids.*`; merged via PR #45)
- [x] **Task 30.** Device enrollment flow —
      `internal/service/identity/enrollment.go` +
      `internal/handler/device.go` extension: claim-token
      enrollment, Ed25519 public-key binding, short-lived mTLS
      certificate issuance, device lifecycle (enrolled / active /
      revoked), audit logging on enroll / refresh / revoke
      (`migrations/021_device_enrollment.*`; merged via PR #45)

---

## Phase 4 — Data protection expansion (~100%)

CASB discovery + top SaaS API connectors (M365, Google
Workspace, Slack, Salesforce), web + SaaS DLP, browser
protection, SaaS posture assessment, data classification, and
config-as-code (Terraform provider + drift detection). Exit
criterion: controlled false-positive rate, usable policy
templates published.

> **Audit findings — planned vs shipped.** Blocks 1-2 shipped
> as specified (CASB discovery + four connectors via PR #48; DLP
> classification engine, detectors, template catalog, and REST
> API via PR #46, hardened by PR #49). Blocks 3-4 shipped under
> a revised shape via PR #47 and Session 1's PR #54, and the task
> entries below describe the **code that actually merged**:
> - Browser protection (Task 43) landed as a single unified
>   `browser.Service` policy engine (download / upload / clipboard
>   / print / screenshot / URL-category rules), **not** the three
>   separate isolation-proxy / extension-policy / phishing modules
>   the placeholder list named.
> - DLP inline-ext-authz (planned 39) and out-of-band CASB scan
>   (planned 40) were **not** built in the Go control plane;
>   instead the DLP engine ships a MIP sensitivity-label reader
>   and content fingerprinting, and CASB/DLP telemetry is emitted
>   via `casb.TelemetryEmitter` (Task 45).
> - An industry "policy template library" under
>   `internal/service/policy/templates/` was **not** built; the
>   pre-baked template catalog that did ship is the DLP one
>   (Task 41, `internal/service/dlp/templates.go`). Task 46 instead
>   tracks the data-classification taxonomy that merged.
> - There is **no** dedicated `data_protection` dashboard handler;
>   per-domain metrics are served by the DLP / CASB / compliance
>   handlers. Task 48 instead tracks the Terraform provider +
>   drift detection that merged under PR #47.

### Block 1 — CASB discovery + SaaS connectors (PR #48)

- [x] **Task 31.** CASB discovery engine —
      `internal/service/casb/service.go` (`SyncConnector`,
      `DiscoverSaaSApps`, discovered-app upsert) +
      `internal/service/casb/telemetry.go`: per-tenant SaaS
      discovery from connector syncs, persisted to the
      discovered-apps store (`migrations/016_casb.*`)
- [x] **Task 32.** SaaS API connector framework —
      `internal/service/casb/{connector.go,types.go}`: `Connector`
      interface, OAuth 2.0 credential lifecycle, pagination,
      rate-limit backoff, tenant-isolated token storage
- [x] **Task 33.** M365 connector —
      `internal/service/casb/connectors/m365.go`: Graph API
      audit-log ingestion, user activity, sharing events,
      sensitivity-label read
- [x] **Task 34.** Google Workspace connector —
      `internal/service/casb/connectors/google.go`: Admin SDK
      audit-log, Drive sharing events, OAuth token grants
- [x] **Task 35.** Slack connector —
      `internal/service/casb/connectors/slack.go`: Enterprise
      Grid audit API, file sharing, external channel detection
- [x] **Task 36.** Salesforce connector —
      `internal/service/casb/connectors/salesforce.go`: Event
      Monitoring, login events, report export detection

### Block 2 — Web + SaaS DLP (PR #46, hardened by PR #49)

- [x] **Task 37.** DLP engine scaffold —
      `internal/service/dlp/service.go` +
      `internal/service/dlp/engine/types.go`: content
      classification pipeline, configurable per-tenant policies,
      verdict (allow / redact / block), match persistence
      (`migrations/017_dlp.*`)
- [x] **Task 38.** DLP detectors — PII / PCI / PHI —
      `internal/service/dlp/engine/regex.go`: pre-compiled
      patterns for `credit_card` (Luhn-validated), `ssn_us`,
      `passport_us`, e-mail, plus an LRU regex cache (PR #49)
- [x] **Task 39.** MIP sensitivity-label reader —
      `internal/service/dlp/engine/mip.go`: reads Microsoft
      Information Protection labels so classification can defer
      to upstream tenant labelling *(shipped in place of the
      planned SWG inline ext-authz hook)*
- [x] **Task 40.** Content fingerprinting —
      `internal/service/dlp/engine/fingerprint.go` +
      `internal/service/dlp/fingerprints.go`: exact / partial
      document-match fingerprints with query hoisting (PR #49)
      *(shipped in place of the planned out-of-band CASB scan)*
- [x] **Task 41.** DLP policy template catalog —
      `internal/service/dlp/templates.go`: pre-baked PCI-DSS,
      HIPAA, PII, GDPR, and Financial-data templates with a
      zip-bomb-guarded loader (PR #49)
- [x] **Task 42.** DLP handler + API —
      `internal/handler/dlp.go` + OpenAPI: policy CRUD,
      classification, match / incident listing, per-tenant
      metrics

### Block 3 — Browser protection + SaaS posture (PR #47)

- [x] **Task 43.** Browser protection service —
      `internal/service/browser/service.go` +
      `internal/handler/browser.go`: unified `BrowserPolicy`
      CRUD over download / upload / clipboard / print /
      screenshot / URL-category rules, per-tenant `(tenant_id,
      name)` uniqueness, RLS (`migrations/018_browser_policies.*`)
      *(unified rules engine, not separate isolation / extension
      / phishing modules)*
- [x] **Task 44.** SaaS posture assessment —
      `internal/service/casb/posture.go`: `PostureAssessor.Assess`
      runs 8 standard checks (MFA, SSO, admin count, external
      sharing, API access, audit logging, password policy,
      session timeout); weighted 0-100 risk score; emits an
      `alert.Router` alert when the score crosses threshold
- [x] **Task 45.** CASB / DLP telemetry —
      `internal/service/casb/telemetry.go`: `TelemetryEmitter`
      publishes to `sng.<tenant>.telemetry.{casb,dlp,posture}`;
      ClickHouse migration adds `casb_app_id`, `casb_event_type`,
      `dlp_policy_id`, `dlp_classification`, `posture_risk_score`
      columns

### Block 4 — Data classification, compliance reporting, config-as-code

- [x] **Task 46.** Data classification taxonomy (PR #47) —
      `internal/service/dlp/taxonomy.go`: hierarchical levels
      (`public` → `top_secret`) with per-tenant labels and
      handling rules, idempotent `SeedDefaults`, `Classify(level)`
      resolution (`migrations/019_data_classification.*`)
      *(shipped in place of the planned industry policy-template
      library; the pre-baked template catalog that did ship is
      Task 41's DLP catalog)*
- [x] **Task 47.** Compliance posture report (Session 1, PR #54) —
      `internal/service/compliance/{report.go,types.go}`: maps
      enforced policies to PCI-DSS, HIPAA, SOC2, and ISO-27001
      controls; point-in-time score, per-control status, JSONB
      evidence pack (`migrations/022_compliance.*`)
- [x] **Task 48.** Config-as-code: Terraform provider + drift
      detection (PR #47) —
      `internal/service/terraform/{provider.go,drift.go}` +
      `internal/handler/terraform.go`: `ExportTenantConfig` /
      `ImportTenantConfig` (versioned, idempotent upsert) and
      `DetectDrift` (added / modified / removed per resource type
      via canonical-JSON diff); REST at `/config/{export,import,
      drift}` *(shipped in place of the planned data-protection
      dashboard handler; per-domain metrics live on the DLP /
      CASB / compliance handlers)*

## Phase 5 — Advanced automation (~100%)

Guided remediation playbooks, AI policy-tightening suggestions
verified by the deterministic compiler, autonomous
troubleshooting with approval gates, enhanced AI (correlation /
NL query / posture reports / threat intel / guardrails), and
operational automation. Exit criterion: measurable support-time
reduction; every AI enforcement action verified against the
deterministic compiler. Delivered across five feature PRs
(#54, #50, #51, #52, #53).

### Block 1 — Compliance reporting + remediation playbook engine (Session 1, PR #54)

> Task 47 (compliance posture report) was implemented in this
> session and is tracked in Phase 4 Block 4 above.

- [x] **Task 49.** Playbook engine core —
      `internal/service/playbook/{engine.go,types.go}`: trigger
      condition + ordered response steps, step execution with
      rollback and concurrency control (`migrations/023_playbooks.*`)
- [x] **Task 50.** Playbook step executors —
      `internal/service/playbook/executors/`: `isolate`,
      `block_ip`, `quarantine`, `notify`, `ticket`,
      `policy_update`, `revoke_access` (seven executors behind a
      typed `ExecutorRegistry`)
- [x] **Task 51.** Playbook execution tracking —
      execution + per-step result persistence with NOT-NULL
      output guards (`migrations/024_playbook_executions.*`)
- [x] **Task 52.** Playbook approval workflow —
      `internal/service/playbook/approval.go`: pending / approved
      / rejected / expired states with TTL expiry, TOCTOU-safe
      status transitions, system-role bypass for `ExpireOld`
      (`migrations/025_playbook_approvals.*`)
- [x] **Task 53.** Playbook template library —
      `internal/service/playbook/templates.go`: five built-in
      incident-response playbooks
- [x] **Task 54.** Compliance + playbook REST handlers —
      `internal/handler/{compliance.go,playbook.go}` + OpenAPI:
      tenant-scoped endpoints, wired into `cmd/sng-control/main.go`

### Block 2 — AI policy tightening (Session 2, PR #50)

- [x] **Task 55.** AI suggestion domain + persistence —
      `internal/service/ai/suggestion_types.go`
      (`PolicyChangeSuggestion` etc.) + `AISuggestionRepository`;
      pending → approved/rejected → applied/rolled_back state
      machine (`migrations/026_ai_suggestions.*`)
- [x] **Task 56.** Policy auto-suggest —
      `internal/service/ai/policy_suggest.go`: heuristic + LLM
      analysis; every suggestion MUST compile through the
      deterministic verifier (`ai/verifier.go`) before it can be
      queued
- [x] **Task 57.** Tightening analysis —
      `internal/service/ai/tightening.go`: unused-rule,
      shadowed-rule, and overly-permissive detection (gated on
      hit-count availability), bounded per-tenant report cache
- [x] **Task 58.** Operator review workflow —
      `internal/service/ai/review.go`: approve / reject / modify
      with expected-status (TOCTOU-safe) transitions and full
      audit attribution
- [x] **Task 59.** Periodic analysis scheduler —
      `internal/service/ai/scheduler.go`: per-tenant scheduled
      analysis paced by a cooldown / slot mechanism
- [x] **Task 60.** Suggestion templates + handler —
      `internal/service/ai/suggestion_templates.go` + six
      tenant-scoped endpoints appended to `internal/handler/ai.go`

### Block 3 — Autonomous troubleshooting assistant (Session 3, PR #51)

- [x] **Task 61.** Knowledge base service —
      `internal/service/troubleshoot/kb.go`: CRUD, search,
      category / tag filtering; global (tenant-NULL) + per-tenant
      entries with command-specific RLS
      (`migrations/032_kb_entries.*`)
- [x] **Task 62.** Diagnostic engine —
      `internal/service/troubleshoot/diagnostic.go` +
      `internal/service/troubleshoot/checks/`: connectivity,
      policy, `cert_health`, `integration_health`, and
      performance checks with full cursor-paginated sweeps
- [x] **Task 63.** RAG troubleshooting assistant —
      `internal/service/troubleshoot/assistant.go`: retrieves
      relevant KB entries, runs diagnostics, and answers via the
      shared `LLMProvider`
- [x] **Task 64.** Session management —
      `internal/service/troubleshoot/session.go`: configurable
      message limits and inactivity timeout; active / resolved /
      escalated lifecycle (`migrations/033_troubleshoot_sessions.*`)
- [x] **Task 65.** Diagnostic caching —
      `DiagnosticEngine.RunAll` caches the per-tenant sweep for a
      30 s TTL with a bounded cache; on-demand `RunCheck` stays
      live
- [x] **Task 66.** Troubleshoot REST handler —
      `internal/handler/troubleshoot.go` + OpenAPI: 11
      tenant-scoped endpoints (sessions, diagnostics, KB CRUD),
      wired into the production router

### Block 4 — Enhanced AI capabilities (Session 4, PR #52)

- [x] **Task 67.** Alert correlation engine —
      `internal/service/ai/correlation.go`: temporal / entity /
      pattern clustering into incident groups; LLM (or template)
      cluster summaries; persists only real alert IDs
      (`migrations/029_ai_correlations.*`)
- [x] **Task 68.** Natural-language policy query —
      `internal/service/ai/nl_query.go`: LLM-parsed intent
      evaluated deterministically against the tenant's compiled
      policy graph; flags partial verdicts
- [x] **Task 69.** Security posture reports —
      `internal/service/ai/reports.go`: weekly / monthly posture
      summaries with trend analysis and an LLM-polished summary
- [x] **Task 70.** Threat-intelligence enrichment —
      `internal/service/ai/threat_intel.go`: pluggable threat
      feed, IOC matching, and severity escalation (enum-bounded)
- [x] **Task 71.** AI guardrails —
      `internal/service/ai/guardrails.go`: per-tenant rate
      limiting, PII / secret redaction, and a durable, bounded
      audit log wrapping every AI path (legacy + enhanced)
- [x] **Task 71a.** Verifier-backed enforcement invariant —
      all AI-proposed changes route through `ai/verifier.go` and
      the Policy Graph + Compiler before canary rollout

### Block 5 — Operational automation (Session 5, PR #53)

- [x] **Task 72.** Policy review scheduler —
      `internal/service/policy/review.go`: periodic review
      reminders with stale detection and upcoming-expiry lookahead
      (`migrations/030_scheduled_reviews.*`)
- [x] **Task 73.** Certificate monitoring —
      `internal/service/identity/cert_monitor.go`: device
      certificate health summary, expiring-cert detection, and
      renewal-status tracking
- [x] **Task 74.** Capacity planning —
      `internal/service/telemetry/capacity.go`: linear growth
      forecast, tier recommendations, and threshold alerts as
      tenants approach tier limits
- [x] **Task 75.** Bulk device operations —
      `internal/service/identity/bulk_device.go`: bulk enroll /
      revoke (fail-closed cert revocation) and CSV import / export
      with per-row failure isolation and audit entries
- [x] **Task 76.** Operational health —
      `internal/handler/ops_health.go`: per-tenant health-score
      snapshot recording (validated component scores) + history
      with capped results (`migrations/031_ops_health.*`)
- [x] **Task 77.** Automation audit reporting + bulk device API —
      `internal/service/audit/automation_report.go`
      (compliance-grade JSON export) +
      `internal/handler/bulk_device.go` (REST, 10 MB CSV cap,
      `X-Truncated` on partial exports), both wired in
      `cmd/sng-control/main.go`

## Phase 6 — Hardware packaging (planned)

Reference whitebox + OEM appliance SKUs, secure boot + TPM
identity for the hardware path. Container packaging may land
earlier. Exit criterion: software attach + renewal economics
demonstrate stronger margin than hardware revenue alone.

---

## Changelog (most recent first)

- `2026-06-03` — Session 6 docs pass: re-audited `main` and
  reconciled PROGRESS / README / ARCHITECTURE against the merged
  code. Checked off Tasks 29-48 (Phase 3 Block 6 + Phase 4) and
  Tasks 49-77 (Phase 5); rewrote Phase 4 Block 3/4 and added the
  Phase 5 task list to match shipped code. Overall status moved to
  Phases 1-5 complete (~100%).
- `2026-06-03` — PR #56 merged: re-fix gofmt / gocritic lint
  reintroduced by the feature-merge train (supersedes the closed
  PR #55, which carried the same central lint + duplicate
  `enrollDevice` operationId fix but hit a merge conflict).
- `2026-06-03` — PR #54 merged: compliance reporting + remediation
  playbook engine (Tasks 47, 49-54) — `internal/service/compliance/`,
  `internal/service/playbook/`, migrations 022-025.
- `2026-06-03` — PR #50 merged: AI policy tightening (Tasks 55-60)
  — `internal/service/ai/{policy_suggest,tightening,review,scheduler,
  suggestion_templates}.go`, migration 026.
- `2026-06-03` — PR #51 merged: autonomous troubleshooting assistant
  (Tasks 61-66) — `internal/service/troubleshoot/`, migrations
  032 (kb_entries) / 033 (troubleshoot_sessions). Migrations
  027/028 are intentional `reserved` placeholders.
- `2026-06-03` — PR #52 merged: enhanced AI capabilities (Tasks
  67-71) — `internal/service/ai/{correlation,nl_query,reports,
  threat_intel,guardrails}.go`, migration 029.
- `2026-06-03` — PR #53 merged: operational automation (Tasks
  72-77) — `internal/service/policy/review.go`,
  `internal/service/identity/{cert_monitor,bulk_device}.go`,
  `internal/service/telemetry/capacity.go`,
  `internal/handler/{ops_health,bulk_device}.go`,
  `internal/service/audit/automation_report.go`, migrations
  030 (scheduled_reviews) / 031 (ops_health).
- `2026-06-02` — PR #45 merged: SCIM 2.0 provisioning + device
  enrollment (Tasks 29-30) — `internal/service/identity/`,
  migrations 020-021.
- `2026-06-02` — PR #48 merged: CASB discovery + SaaS API
  connectors (Tasks 31-36) — `internal/service/casb/`, migration 016.
- `2026-06-02` — PR #46 merged: DLP classifier, engines, template
  catalog, and REST API (Tasks 37-42) — `internal/service/dlp/`,
  migration 017. Hardened by PR #49 (zip-bomb guard, LRU regex
  cache, fingerprint query hoisting).
- `2026-06-02` — PR #47 merged: browser protection service, SaaS
  posture assessment, CASB/DLP telemetry, data-classification
  taxonomy, and the Terraform provider + drift detection (Tasks
  43-48) — migrations 018 (browser_policies) / 019
  (data_classification). NOTE: shipped a revised feature shape
  vs. the original placeholder task list (see "Audit findings"
  under Phase 4).
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
