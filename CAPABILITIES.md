# ShieldNet Gateway — Capabilities

This is the capability-by-capability reference for the platform as it
ships today. Each section states what the capability does, where it
lives in the tree, and how it is verified. It complements the
[`README.md`](./README.md) overview and the
[`ARCHITECTURE.md`](./ARCHITECTURE.md) system design, and every figure
quoted here traces to a regenerated artifact under
[`blog/artifacts/`](./blog/artifacts) (see
[`blog/artifacts/EVIDENCE_MANIFEST.md`](./blog/artifacts/EVIDENCE_MANIFEST.md)).

SNG is one product with three enforcement forms — the edge appliance
(`sng-edge`), the endpoint client (`sng-agent`), and the control plane
(`cmd/sng-control`) — that share a single policy model, wire protocol,
and telemetry fabric.

## Control-plane foundation

- **Multi-tenant data layer.** PostgreSQL with `sng.tenant_id`
  GUC-driven row-level security on every tenant-scoped table; the data
  layer reads the GUC back and asserts the expected tenant on each
  connection, and the `AssertTenantContext` middleware backstops it.
  A cross-tenant isolation integration test exercises the boundary.
  (`migrations/`, `internal/repository/postgres/`,
  `internal/middleware/`.)
- **Repositories with two backends.** Every repository interface has a
  `pgxpool` driver and an in-memory driver; the Postgres harness runs
  under testcontainers. (`internal/repository/`.)
- **Tenant, identity, RBAC, site, audit.** Tenant lifecycle
  (active / suspended / deleted) with slug uniqueness; user + role
  assignment and session issuance; hierarchical RBAC composed across
  system / tenant / site / MSP scope; per-tenant site CRUD; an
  append-only, hash-chained audit log. (`internal/service/{tenant,
  identity,rbac,site,audit}/`.)
- **API keys.** Lifecycle with KMS-backed envelope encryption and a
  per-tenant cap. (`internal/service/apikey/`.)
- **Eventing.** NATS JetStream stream definitions, durable consumer
  bootstrap, an idempotent publisher, per-tenant subject ACL templates
  (`deploy/nats/`), and a Go↔Rust event-envelope schema.
  (`internal/nats/`.)
- **API surface.** A REST handler layer with an embedded OpenAPI 3.1
  spec; CI keeps `api/openapi.yaml` and `internal/handler/openapi.yaml`
  byte-identical and lints both with Spectral.
- **Leader election.** Fencing tokens (`FencingToken{LockID, Epoch}`,
  `RunIfLeaderFenced`), `/readyz` leader-state reporting, and the
  `sng_leader_transitions_total` counter let the control plane run
  hot/warm without split-brain writes.

## Enforcement plane (edge + endpoint, Rust)

The edge appliance composes every enforcement library behind
`sng-core::supervisor::Supervisor`; the endpoint client runs the
strict subset that makes sense on a user device. Every crate is
`#![forbid(unsafe_code)]` at the workspace level.

- **NGFW + IDS/IPS.** L3–L7 policy, NAT, application awareness, TLS
  policy, and inline Suricata. (`crates/sng-fw`, `crates/sng-ips`.)
- **Secure Web Gateway.** An Envoy ext-authz handler with URL
  categorization, a malware-verdict API, per-tenant rate limiting, and
  a bypass list. (`crates/sng-swg`.)
- **SWG inline DLP.** Regex (PII/PCI/PHI), MIP-label header inspection,
  and content-fingerprint matching on the synchronous ext-authz path.
  Block short-circuits to deny; log/redact verdicts are carried
  forward so a later malware or category deny can still win. Engine
  policy is hot-swapped via `ArcSwap`; a bounded `scan_ceiling_bytes`
  cap prevents pathological bodies from blocking the verdict path.
  (`crates/sng-swg/src/dlp_inline.rs`.)
- **SWG AI governance.** Destination classification and policy
  enforcement for generative-AI apps (ChatGPT, Claude, Copilot, Gemini,
  and long-tail heuristic detection) on the ext-authz path. Supports
  per-app, per-category, default, and suspected-app actions: allow,
  monitor, block, or redirect to RBI. Suspected heuristic matches
  default to allow so the long tail never blocks on its own.
  (`crates/sng-swg/src/ai_governance.rs`.)
- **SWG RBI.** Remote browser isolation policy engine that redirects
  risky browsing to an RBI proxy. Trigger rules cover explicit
  isolation, explicit bypass, and isolation of uncategorised sites.
  Runs after DLP and before category deny so the isolation redirect
  wins over a category block. (`crates/sng-swg/src/rbi.rs`.)
- **DNS security.** Reputation feed, category filter, and sinkhole on
  both the edge and the endpoint. (`crates/sng-dns`.)
- **SD-WAN.** Overlay tunnels, health probes, path scoring, and
  app-aware steering. (`crates/sng-sdwan`.)
- **DEM (Digital Experience Monitoring).** Bounded synthetic probes
  (DNS, TCP, HTTP/HTTPS) against critical SaaS targets, with
  configurable sweep interval, concurrency, timeout, jitter, and
  max-target limits. Probe results are serialized to structured JSON
  matching the Go control-plane DTOs. Default-off; the subsystem is
  inert when disabled. (`crates/sng-dem`, `crates/sng-edge/src/subsystems/dem.rs`.)
- **ZTNA.** mTLS device identities, posture binding, and a per-app
  access broker. Clientless browser access adds an OIDC-based
  browser path with sharded session store, host matching, and reverse
  proxy routing to internal web apps. (`crates/sng-ztna`.)
- **VPN replacement.** A WireGuard-class tunnel with short-lived keys
  and no implicit whole-network access. (`crates/sng-pal` tunnel
  backends.)
- **Local policy evaluator.** Verified policy bundles, hot-swap, and a
  fail-closed default, with a sub-microsecond per-flow verdict.
  (`crates/sng-policy-eval`.)
- **Telemetry collection.** Metadata-first collection with redaction at
  source, dedup, and at-least-once egress. (`crates/sng-telemetry`.)
- **Native transport.** TLS 1.3 + MessagePack + HTTP/2 with batching, a
  replay-safe ack, and a bounded spool. (`crates/sng-comms`.)
- **Signed self-update.** Ed25519-signed manifests, A/B (dual-bank)
  install, and a rollback-safe health window. (`crates/sng-updater`.)
- **eBPF/XDP fast path.** Policy steering is pushed into the XDP
  classify stage where the kernel can resolve it (IP ranges), with
  nftables enforcing the remainder; hardware-offload data paths plug in
  through the `OffloadDevice` trait.

A throughput sweep on this VM scales linearly across queues — the
multi-queue branch profile climbs from 4.461 Gbps single-queue to
20.588 Gbps at 32 queues, a 4.61× lift
([`blog/artifacts/multi-queue-branch-large.json`](./blog/artifacts/multi-queue-branch-large.json)).

## Endpoint client and mobile SDK

`sng-agent` targets Linux (gnu/musl, x86_64 + aarch64), macOS
(Intel + Apple Silicon), and Windows, with `sng-pal` isolating
OS-specific capture, posture, tunnel, and secure key-store primitives.
The mobile brain is pure Rust (`sng-mobile-core`) driven through a
UniFFI binding layer (`sng-mobile-sdk`) over the iOS and Android PALs
(`sng-mobile-pal-ios`, `sng-mobile-pal-android`) plus a pure-Rust OIDC
client (`sng-oidc`); per-OS PAL modules lift the unsafe ban locally
with a documented rationale.

## Policy operations

- **Typed policy graph + compiler.** A typed graph compiles per target
  into Ed25519-signed bundles with a byte-deterministic layout; agents
  pull verified bundles. (`internal/service/policy/`.)
- **Change simulation.** A deterministic simulator, dry-run shadow
  bundles, and canary rollout with one-click rollback.
- **Policy recommendation engine.** Least-privilege synthesis from
  observed flow / DNS / HTTP traffic, compiler-verified, with coverage
  and prev-vs-next impact proof and one-click apply-as-draft into the
  canary path. On a deployment without a telemetry hot tier it returns
  `503 unavailable` rather than fabricating suggestions.
- **Review scheduler.** Periodic policy-review scheduling as part of
  operational automation.

## Detection, baselines, and threat intelligence

- **Statistical baselines.** A Welford + EWMA anomaly engine with
  per-tenant tuning drives baseline alerts, with routing, suppression,
  and false-positive feedback. (`internal/service/{baseline,alert}/`.)
- **Detection efficacy discipline.** The efficacy bench scores the
  classification stack against a labelled corpus and publishes the
  result honestly: the suite passes overall — on-device ML-NER catches
  97.4% of PII spans across all twelve entity classes at 100% precision
  (zero false positives), while the hardest slice, `malware_wild`, is
  reported as a 9.6% false-positive-rate WARN rather than smoothed
  ([`blog/artifacts/efficacy-report.json`](./blog/artifacts/efficacy-report.json)).
- **Threat intelligence.** Indicator enrichment over a feed of 76,432
  indicators in the seeded fixture. (`internal/service/ai/` threat
  intel + `docs/THREAT_INTEL.md`.)

## Integrations and MSP

- **Integration service.** Syslog (RFC 5424/5425), SIEM/XDR webhooks
  (Splunk / Elastic / Sentinel), and bidirectional Jira and ServiceNow
  sync. (`internal/service/integration/`.)
- **Outbound webhooks.** HMAC-signed event delivery with retry and
  claim-token issuance. (`internal/service/webhook/`.)
- **MSP hierarchy.** An MSP entity model, MSP-scoped RBAC, bulk
  operations, and per-MSP branding, so a provider can co-manage many
  tenants from one console. (`internal/service/tenant/` MSP ops + RBAC.)

## Data protection

- **CASB.** Passive discovery plus M365, Google Workspace, Slack, and
  Salesforce API connectors with SaaS posture assessment. The seeded
  fleet inventories shadow IT with per-app risk, sanction state, and a
  recommended action. (`internal/service/casb/`.)
- **DLP for web + SaaS.** Regex (PII / PCI / PHI), MIP-label awareness,
  and content-fingerprint classification, with a policy-template
  catalog and a data-classification taxonomy. Endpoint DLP adds native
  per-OS file-write, clipboard, print, and USB-transfer interception in
  `sng-pal`, each falling back to a bounded portable watcher when its
  kernel hook is unavailable. The edge SWG now also runs inline DLP
  directly on the ext-authz verdict path for bodies the proxy forwards.
  (`internal/service/dlp/`, `crates/sng-pal/src/dlp/`, `crates/sng-dlp`,
  `crates/sng-swg/src/dlp_inline.rs`.)
- **Browser protection.** A unified policy engine for download, upload,
  clipboard, print, screenshot, and URL-category controls.
  (`internal/service/browser/`.)
- **Application registry.** A vendor-synced app catalogue (M365,
  Google, AWS) with a per-tenant demotion engine; the seeded catalogue
  holds 215 applications. (`internal/service/appdb/`,
  `crates/sng-appid`.)

## Compliance, remediation, and config-as-code

- **Compliance reporting.** PCI-DSS / HIPAA / SOC2 / ISO-27001 control
  mapping with JSON evidence packs. (`internal/service/compliance/`.)
- **Remediation playbooks.** Triggered, approval-gated response
  playbooks with seven step executors. (`internal/service/playbook/`.)
- **Config-as-code.** Terraform-style tenant config export / import and
  drift detection. (`internal/service/terraform/`.)

## AI

The AI layer is verifier-checked and operator-reviewed, not
free-running. (`internal/service/ai/`,
[`docs/ai-model-setup.md`](./docs/ai-model-setup.md).)

- **Policy tightening.** Unused / shadowed / overly-permissive rule
  detection; every suggestion compiles through the deterministic
  verifier before it can be applied.
- **AI governance for SWG.** Inline enforcement on the ext-authz path
  that classifies generative-AI destinations and applies per-app,
  per-category, default, or suspected-app actions. Operators can block,
  monitor, allow, or redirect AI-app traffic to RBI without waiting for
  a control-plane review cycle.
- **Enhanced AI.** Alert correlation, natural-language policy query,
  posture reports, threat-intel enrichment, and guardrails.
- **Autonomous troubleshooting.** A RAG assistant over a knowledge base
  plus a diagnostic engine. (`internal/service/troubleshoot/`.)
- **Self-hosted inference.** The shared-inference path validates
  against a quantized 8B model (Ternary-Bonsai-8B, Q2_0, ≈2.03 GB GGUF)
  that runs on commodity CPU. A 20-query validation set passes at 100%
  on classification, verifier agreement, fallback, parse, and
  raw-agreement
  ([`blog/artifacts/llm_validation/quality_report.md`](./blog/artifacts/llm_validation/quality_report.md)).

## Operational automation and NoOps economics

- **Operational automation.** Policy-review scheduler, certificate
  monitor, capacity planning, bulk device ops, ops-health snapshots,
  and an automation audit report. (`internal/service/` ops surfaces.)
- **Activity-tiered dormancy.** Tenants are classified active → idle →
  dormant → hibernated from a `last_active_at` signal, so idle tenants
  scale toward zero. A 5,000-tenant capacity plan projects the sleep
  schedule and headroom
  ([`blog/artifacts/capacity-plan-5000/report.md`](./blog/artifacts/capacity-plan-5000/report.md)).
- **Cost transparency.** Per-tenant cost and margin are reported in the
  metering surface; the seeded fleet shows an admin cost-report margin
  near 50.9% with at least one tenant (Maple) deliberately underwater
  to exercise the margin-autopilot path.

## How capabilities are verified

The evidence behind every figure here is regenerated end to end from
the running stack by the harnesses under
[`blog/harness/`](./blog/harness) (seed → usage → anomalies → capture →
CASB → new-capability payloads) and the Rust benches under
[`bench/`](./bench) (efficacy with ML-NER, multi-queue throughput,
capacity planning, 8B LLM validation). The add-on capabilities are
covered by crate unit tests: AI governance (24 tests), inline DLP (22
tests), RBI (16 tests), clientless ZTNA (11 tests), and DEM (10 tests)
— all run in the standard `cargo test` flow. Run order, environment, and
the full payload index are documented in
[`blog/artifacts/EVIDENCE_MANIFEST.md`](./blog/artifacts/EVIDENCE_MANIFEST.md).
