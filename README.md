# ShieldNet Gateway (SNG)

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-lightgrey.svg)](./LICENSE)
[![CI](https://github.com/kennguy3n/visible-fishbone/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/visible-fishbone/actions/workflows/ci.yml)

ShieldNet Gateway (SNG) is the network-layer product in the **SN360
family**, alongside [ShieldNet Defense] and [ShieldNet Access]
(ZTNA + PAM). SNG delivers NGFW, IDS/IPS, SWG, DNS security, ZTNA,
VPN replacement, SD-WAN, telemetry, and unified policy orchestration
as a SaaS-managed, multi-tenant platform with edge enforcement —
one console, one policy model, one lightweight endpoint client, one
branch edge image, one telemetry fabric, one support path.

Positioning: **"Fortinet economics + Zscaler simplicity + Palo
Alto-grade management discipline."**

This repository is the SNG monorepo: it contains both the Rust
**enforcement plane** (`crates/sng-*` — the branch / site edge
appliance binary `sng-edge`, the cross-platform endpoint client
binary `sng-agent`, and the twelve library crates they compose)
and the SNG-specific Go **control plane** (`cmd/sng-control`,
`cmd/sng-migrate`, `internal/`, `migrations/`, `api/openapi.yaml`)
that issues signed policy bundles, signed update manifests, and
receives telemetry. The broader SN360 multi-product security-event
platform (Wazuh-based correlation, IOC distribution, SBOM /
inventory, MSP portal across all SN360 products) lives in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform);
SNG integrates with it for cross-product features but does not
depend on it for the gateway product itself.

## Capabilities

SNG ships in **three enforcement forms** that share a single control
plane, policy model, and telemetry fabric.

| Capability | Status | Where it runs |
|---|---|---|
| **NGFW + IDS/IPS** — L3-L7 policy, NAT, app awareness, TLS policy, Suricata inline | Implemented | Edge appliance (`sng-edge`) |
| **SWG** — Envoy-based forward proxy with URL categorization + malware verdict API | Implemented | Edge appliance |
| **DNS security** — reputation feed, category filter, sinkhole | Implemented | Edge appliance + endpoint |
| **SD-WAN** — overlay tunnels, health probes, path scoring, app-aware steering | Implemented | Edge appliance |
| **ZTNA** — mTLS device identities, posture binding, per-app access | Implemented | Edge appliance + endpoint client (`sng-agent`) |
| **VPN replacement** — WireGuard-class tunnel, short-lived keys, no implicit "whole-network" access | Implemented | Endpoint client |
| **Dual-bank self-update** — Ed25519-signed manifests, A/B install, rollback-safe health window | Implemented | Edge appliance + endpoint client |
| **Local policy evaluator** — verified policy bundles, hot-swap, fail-closed | Implemented | Edge appliance + endpoint client |
| **Telemetry collection** — metadata-first, redaction at source, at-least-once egress, dedup | Implemented | Edge appliance + endpoint client |
| **Native protocol transport** — TLS 1.3 + MessagePack + HTTP/2, mTLS device identity | Implemented | All three enforcement forms |
| **Policy change simulation** — deterministic simulator, dry-run shadow bundles, canary rollout with one-click rollback | Implemented | Control plane |
| **Baseline alerts + behavior models** — z-score + EWMA anomaly detection, per-tenant tuning, alert routing + suppression | Implemented | Control plane |
| **Integration service** — Syslog (RFC 5424/5425), SIEM/XDR webhooks (Splunk/Elastic/Sentinel), Jira + ServiceNow bidirectional sync | Implemented | Control plane |
| **MSP hierarchy + co-management** — MSP entity model, MSP-scoped RBAC, bulk operations, per-MSP branding | Implemented | Control plane |
| **CASB discovery + SaaS connectors** — passive discovery + M365 / Google Workspace / Slack / Salesforce API connectors, SaaS posture assessment | Implemented | Control plane |
| **DLP for web + SaaS** — regex (PII/PCI/PHI) + MIP-label + content-fingerprint classification, policy template catalog, data-classification taxonomy | Implemented | Control plane |
| **Browser protection** — unified browser policy engine (download / upload / clipboard / print / screenshot / URL-category) | Implemented | Control plane |
| **Compliance reporting** — PCI-DSS / HIPAA / SOC2 / ISO-27001 control mapping with JSON evidence packs | Implemented | Control plane |
| **Remediation playbook engine** — triggered, approval-gated response playbooks with 7 step executors | Implemented | Control plane |
| **AI policy tightening** — unused / shadowed / overly-permissive rule detection; verifier-checked suggestions with operator review | Implemented | Control plane |
| **Autonomous troubleshooting** — RAG assistant over a knowledge base plus a diagnostic engine | Implemented | Control plane |
| **Enhanced AI** — alert correlation, NL policy query, posture reports, threat-intel enrichment, guardrails | Implemented | Control plane |
| **Operational automation** — policy-review scheduler, certificate monitor, capacity planning, bulk device ops, ops-health snapshots, automation audit report | Implemented | Control plane |
| **Config-as-code** — Terraform-style tenant config export / import + drift detection | Implemented | Control plane |
| **Hardware appliance SKUs (TPM-rooted)** | Planned | Branch edge |

The SNG control plane in this repo (`cmd/sng-control`, `internal/`,
`migrations/`, `api/openapi.yaml`) is the Go service that compiles
the policy graph, signs bundles, accepts telemetry, and serves the
REST API. It also owns the SNG-specific data-protection,
compliance, remediation-playbook, AI (policy tightening,
correlation, NL query, posture reports, threat intel, guardrails),
troubleshooting, and operational-automation services under
`internal/service/`. Purely operator-facing surfaces — admin UI,
MSP portal, ClickHouse hot analytics, S3 cold archive, and the
shared cross-product platform — live in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

## Architecture Overview

```
+--------------------------------------------------------------+
|              SaaS Control Plane (Go, multi-tenant)            |
|  Admin UI + MSP Portal  |  Tenant + Identity  |  Policy       |
|  Graph + Compiler  |  Telemetry Pipeline (NATS JetStream)     |
|  Hot Analytics (ClickHouse)  |  Cold Archive (S3)  |  AI      |
|  Assistant  |  API + Integration Gateway                      |
+--------------------------------------------------------------+
            ^                                  ^
            |  signed policy + telemetry        |  signed policy
            |  (TLS 1.3 + MessagePack + HTTP/2) |  + telemetry
            |  mTLS device identity (Ed25519)   |
            v                                  v
+------------------------------+   +---------------------------+
|  Edge VM / Virtual Appliance |   |  Endpoint Client          |
|  (Rust)                      |   |  (Rust, cross-platform)   |
|  NGFW + IPS (Suricata)       |   |  Traffic steering         |
|  SWG (Envoy)                 |   |  ZTNA + posture           |
|  DNS Security resolver       |   |  VPN replacement tunnel   |
|  SD-WAN overlay              |   |  Experience telemetry     |
|  Local policy evaluator      |   |  Local policy evaluator   |
|  Telemetry collector         |   |  (sng-pal: Win/macOS/Lin) |
|  Dual-bank image upgrades    |   |                           |
+------------------------------+   +---------------------------+
            ^                                  ^
            |  branch / site                    |  user device
            v                                  v
+--------------------------------------------------------------+
|       SME network: branches, remote workers, SaaS apps,       |
|       private apps, identity providers, SIEM / XDR / RMM      |
+--------------------------------------------------------------+
```

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full mermaid
diagrams, data flow, and per-component breakdown, and
[`docs/TRAFFIC_CLASSIFICATION.md`](./docs/TRAFFIC_CLASSIFICATION.md)
for the six-class steering framework that drives the edge / cloud /
endpoint enforcement-point decision.

## Technology Stack

Choices align with SN360 family conventions. Go is the default for
control-plane services; Rust is the default for any agent or
performance-sensitive edge component.

| Layer | Technology | Notes |
|---|---|---|
| Edge enforcement (packet path, policy evaluator, local collectors, parsers) | **Rust** | Matches `sn360-agent-vm` and `sn360-agent-k8s` performance budgets |
| Endpoint client (traffic steering, posture, ZTNA) | **Rust**, cross-platform | Mirrors the [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) architecture (`sda-pal` → `sng-pal`) |
| SNG control plane (`cmd/sng-control`, `internal/`, `api/`) | **Go** | In-repo; PostgreSQL-backed with `sng.tenant_id` GUC-driven row-level security (see [`docs/deploy.md`](./docs/deploy.md)) |
| Admin UI / MSP portal / shared cross-product surfaces | **TypeScript + React** | In [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) |
| Policy / metadata storage | **PostgreSQL** | Row-level security per tenant; schema in `migrations/`, runbook in [`docs/deploy.md`](./docs/deploy.md) |
| Hot analytics | **ClickHouse** | Normalized telemetry, 30-90 day retention |
| Cold retention | **S3-compatible object storage** | Compressed event archive, 1+ year |
| Eventing / pipeline | **NATS JetStream** | Same fabric as `sn360-es` and the SN360 platform repo |
| L7 proxying (SWG) | **Envoy** | Forward proxy with ext-authz handoff to `sng-swg` |
| IDS/IPS | **Suricata** | Inline on edge VM via `sng-ips`; longer-term opt-in eBPF fast-path |
| Container platform | Managed **Kubernetes** / **k3s** | Control plane only |
| Infrastructure as code | **Terraform** | In-repo tenant config-as-code service (`internal/service/terraform/`): versioned export / import + drift detection |
| Agent ↔ gateway wire | **TLS 1.3 + MessagePack + HTTP/2** | SN360 native protocol, same as SDA / VMA / SKA |
| Artifact signing | **Ed25519** | Policy bundles, action jobs, edge images, endpoint installers |

## Workspace Layout

The workspace is two binaries plus twelve library crates. The Rust
`sng-` prefix matches the family pattern (`sda-` desktop, `vma-`
VM, `ska-` Kubernetes, `sng-` gateway). The lib / bin split mirrors
[`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s)
and [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent).

| Crate | Kind | Responsibility |
|---|---|---|
| [`sng-edge`](./crates/sng-edge) | bin | Edge VM appliance binary — composes every enforcement library behind `sng-core::supervisor::Supervisor` |
| [`sng-agent`](./crates/sng-agent) | bin | Endpoint client binary — strict subset of edge subsystems (comms, policy_eval, telemetry, ztna, pal_capture / pal_posture / pal_tunnel) |
| [`sng-core`](./crates/sng-core) | lib | Shared types, identifier newtypes, MessagePack envelope, signed-bundle verification, error taxonomy, lifecycle / supervisor traits |
| [`sng-pal`](./crates/sng-pal) | lib | Platform Abstraction Layer for the endpoint client (Windows / macOS / Linux) — traffic capture, posture, tunnel, secure key store |
| [`sng-policy-eval`](./crates/sng-policy-eval) | lib | Local policy evaluation engine — verified bundles, hot-swap, sub-microsecond per-flow verdict |
| [`sng-comms`](./crates/sng-comms) | lib | SN360 native protocol client — TLS 1.3, MessagePack, HTTP/2, batching, replay-safe ack, bounded spool |
| [`sng-telemetry`](./crates/sng-telemetry) | lib | Local telemetry collection, normalization, dedup, metadata-first redaction, egress |
| [`sng-swg`](./crates/sng-swg) | lib | Envoy ext-authz handler — URL categorization, malware verdict, per-tenant rate-limit, bypass list |
| [`sng-dns`](./crates/sng-dns) | lib | DNS security resolver and filter (reputation, category, sinkhole) |
| [`sng-ztna`](./crates/sng-ztna) | lib | Zero Trust Network Access — mTLS device identities, posture binding, app access broker |
| [`sng-sdwan`](./crates/sng-sdwan) | lib | SD-WAN overlay tunnels, path scoring, health probes, app-aware steering |
| [`sng-ips`](./crates/sng-ips) | lib | Suricata wrapper — rule sync, alert normalization, supervisor + signal lifecycle |
| [`sng-fw`](./crates/sng-fw) | lib | Firewall — L3-L7 policy, NAT, app awareness, deterministic nftables rule set |
| [`sng-updater`](./crates/sng-updater) | lib | Self-update with signed manifests (Ed25519), dual-bank image install, rollback |
| [`sng-mobile-core`](./crates/sng-mobile-core) | lib | Platform-agnostic mobile agent brain — lifecycle, enrolment, posture, telemetry, ZTNA; pure Rust, driven through a UniFFI binding layer |
| [`sng-oidc`](./crates/sng-oidc) | lib | Pure-Rust OIDC client (discovery, PKCE, token exchange, ID-token validation) + the `AuthSurface` browser-presentation trait |
| [`sng-mobile-pal-ios`](./crates/sng-mobile-pal-ios) | lib | iOS Platform Abstraction Layer — Keychain key store, posture, `NEPacketTunnelProvider`, `ASWebAuthenticationSession`; real code under `cfg(target_os = "ios")`, typed-Unsupported host fallback otherwise |
| [`sng-mobile-pal-android`](./crates/sng-mobile-pal-android) | lib | Android Platform Abstraction Layer — Keystore, posture, VpnService, Custom Tabs; real code under `cfg(target_os = "android")`, typed-Unsupported host fallback otherwise |
| [`sng-mobile-sdk`](./crates/sng-mobile-sdk) | lib | UniFFI binding layer composing mobile-core + the iOS/Android PALs + sng-oidc into a single Swift/Kotlin FFI (`MobileSdk`); see its [README](./crates/sng-mobile-sdk) for binding generation + packaging |
| [`sng-uniffi-bindgen`](./crates/sng-uniffi-bindgen) | bin | Workspace `uniffi-bindgen` wrapper used to generate the `sng-mobile-sdk` Swift/Kotlin bindings |

Every crate is `#![forbid(unsafe_code)]` at the workspace level
(per-OS PAL modules lift the ban locally with a documented
rationale) and goes through the workspace-pedantic clippy profile.

## Quick Start

### Prerequisites

- **Go 1.25+** (the module declares `go 1.25.0`)
- **Rust 1.85+** (workspace `rust-version = "1.85"`)
- **Docker** (for testcontainers-based integration tests)
- **NATS Server** (for JetStream telemetry pipeline tests)
- **PostgreSQL 14+** (for integration test harness)

### Clone and build

```bash
git clone https://github.com/kennguy3n/visible-fishbone.git
cd visible-fishbone

# Go control plane
go build ./cmd/sng-control/...
go build ./cmd/sng-migrate/...

# Rust enforcement plane
cargo build --workspace
```

### Run migrations

```bash
go run ./cmd/sng-migrate/...
```

### Start the control plane

```bash
go run ./cmd/sng-control/...
```

### Run tests

```bash
# Go unit + integration tests (uses testcontainers for Postgres + NATS)
go test -race -timeout 300s ./...

# Rust workspace tests
cargo test
```

## Endpoint Client Platforms

`sng-agent` targets the same matrix as `sn360-desktop-agent`. The
Platform Abstraction Layer (`sng-pal`) isolates OS-specific traffic
capture, posture, and tunnel primitives.

| Target | Use |
|---|---|
| `x86_64-unknown-linux-gnu` | Standard Linux laptops / workstations |
| `x86_64-unknown-linux-musl` | Hardened / static Linux distributions |
| `aarch64-unknown-linux-gnu` | ARM Linux endpoints |
| `x86_64-apple-darwin` | Intel macOS |
| `aarch64-apple-darwin` | Apple Silicon macOS |
| `x86_64-pc-windows-msvc` | Windows 10/11 endpoints |

## Roadmap

The current code covers the full enforcement plane, the unified
operations layer (Phase 3), data-protection expansion (Phase 4),
and advanced automation (Phase 5). See [`PROGRESS.md`](./PROGRESS.md)
for the per-task audit trail. Shipped and remaining roadmap:

- **Data protection expansion (Phase 4) — shipped.** CASB discovery
  + SaaS API connectors (M365, Google Workspace, Slack, Salesforce)
  with SaaS posture assessment; DLP for web + SaaS with regex
  (PII/PCI/PHI), MIP label awareness, and content fingerprinting;
  unified browser protection policy engine; data-classification
  taxonomy; Terraform-style config-as-code + drift detection.
- **Advanced automation (Phase 5) — shipped.** Compliance reporting;
  guided remediation playbooks (approval-gated, 7 step executors);
  AI policy-tightening deltas that compile through the deterministic
  verifier before they can be applied; autonomous troubleshooting
  assistant; enhanced AI (alert correlation, NL policy query,
  posture reports, threat-intel enrichment, guardrails); operational
  automation (policy-review scheduler, certificate monitor, capacity
  planning, bulk device ops, ops-health snapshots, automation audit
  report).
- **Hardware packaging (Phase 6) — planned.** Small / medium / large
  branch profiles on vetted OEM platforms; same `sng-edge` image as
  the VM, with the TPM as the root of device identity and the same
  dual-bank install path.

Operator-driven roadmap items should be filed as a GitHub issue
labelled `roadmap`. Include the use case, the workaround you are
using today, and any constraints (network architecture, hypervisor /
cloud, identity provider, MSP context).

## Related Repositories

| Repo | Purpose |
|---|---|
| [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | SN360 shared multi-product platform — identity, policy distribution, correlation, compliance, MSP portal |
| [`sn360-es`](https://github.com/kennguy3n/sn360-es) | ShieldNet Defense — email security for GWS / O365 |
| [`cautious-fishstick`](https://github.com/kennguy3n/cautious-fishstick) | ShieldNet Access — ZTNA + PAM |
| [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) | SN360 endpoint agent (Windows / macOS / Linux) |
| [`sn360-agent-vm`](https://github.com/kennguy3n/sn360-agent-vm) | SN360 server / VM agent |
| [`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s) | SN360 Kubernetes agent |
| [`visible-fishbone`](https://github.com/kennguy3n/visible-fishbone) | ShieldNet Gateway — this repo |

## Documentation

| Document | Purpose |
|---|---|
| [`PROPOSAL.md`](./PROPOSAL.md) | Product design proposal — competitive baseline, SME constraints, capability scope, reference architecture, AI / data / security model, commercial model, risk register |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System architecture — topology diagrams, control plane services, edge VM internals, endpoint client internals, telemetry pipeline, data tiering, security model, SN360 integration points, wire protocol |
| [`docs/TRAFFIC_CLASSIFICATION.md`](./docs/TRAFFIC_CLASSIFICATION.md) | Traffic classification and steering framework — six traffic classes, per-deployment-mode steering tables, app registry overrides, byte-deterministic bundle layout |
| [`docs/deploy.md`](./docs/deploy.md) | Control-plane deployment runbook — PostgreSQL role hierarchy, RLS GUC contract, migration runner privileges, policy signing-key modes, API-key cap |
| [`SECURITY.md`](./SECURITY.md) | Security policy — supported versions, reporting process, response SLAs, scope, crypto / signing posture |
| Per-crate `README.md` | Each library / binary crate carries its own README under [`crates/`](./crates) covering module surface, wire-format compatibility, and local verification commands |
| [`PROGRESS.md`](./PROGRESS.md) | Phase-by-phase task tracker with per-task audit trail |

## Control Plane Service Layout

```
internal/service/
├── ai/             — AI: policy tightening, suggestion review, correlation, NL query, posture reports, threat intel, guardrails, verifier
├── alert/          — Alert routing, suppression, false-positive feedback
├── apikey/         — API-key lifecycle with KMS-backed envelope encryption
├── appdb/          — Application registry, vendor sync, demotion engine
├── audit/          — Append-only hash-chained audit log + automation audit report
├── baseline/       — Statistical baseline engine (Welford + EWMA anomaly)
├── browser/        — Browser protection policy engine (download/upload/clipboard/print/screenshot/URL-category)
├── casb/           — CASB discovery, SaaS API connectors (M365/Google/Slack/Salesforce), posture assessment, telemetry
├── compliance/     — Compliance reports (PCI-DSS/HIPAA/SOC2/ISO-27001) with evidence packs
├── dlp/            — DLP classification (regex/MIP/fingerprint), template catalog, data-classification taxonomy
├── identity/       — User + device identity, SCIM 2.0, enrollment, cert monitor, bulk device ops
├── integration/    — External connectors (Syslog, SIEM, Jira, ServiceNow)
├── playbook/       — Remediation playbook engine, step executors, approval workflow, templates
├── policy/         — Policy graph, compiler, simulator, dry-run, canary, review scheduler
├── rbac/           — Hierarchical RBAC (system / tenant / site / MSP)
├── site/           — Site CRUD, per-tenant scoping
├── telemetry/      — Pipeline: consumer, dedup, normalize, CH writer, S3 archiver, replay, capacity planning
├── tenant/         — Tenant lifecycle, MSP bulk ops, branding
├── terraform/      — Tenant config-as-code export / import + drift detection
├── troubleshoot/   — RAG troubleshooting assistant, diagnostic engine, knowledge base
└── webhook/        — Outbound HMAC-signed event delivery
```

## License

SN360 Proprietary — see [`LICENSE`](./LICENSE) for the full license
terms. Copyright (c) 2026 SN360 Inc. All rights reserved. For
licensing inquiries, contact
[licensing@sn360.com](mailto:licensing@sn360.com).
