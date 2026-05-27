# ShieldNet Gateway (SNG)

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-lightgrey.svg)](./LICENSE)
[![CI](https://github.com/kennguy3n/visible-fishbone/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/visible-fishbone/actions/workflows/ci.yml)

Software-first unified security gateway for SMEs. Part of the **SN360
family** alongside [ShieldNet Access](https://github.com/kennguy3n/sn360-security-platform)
and [ShieldNet Defense](https://github.com/kennguy3n/sn360-es).
SNG delivers NGFW, IDS/IPS, SWG, DNS security, ZTNA, VPN replacement,
SD-WAN, telemetry, and unified policy orchestration as a SaaS-managed,
multi-tenant platform with edge enforcement — one console, one policy
model, one lightweight endpoint client, one branch edge image, one
telemetry fabric, and one support path.

Positioning: **"Fortinet economics + Zscaler simplicity + Palo
Alto-grade management discipline."**

This repository tracks the planning and reference architecture for the
SNG product. The first deliverable is the documentation set below
([`PROPOSAL.md`](./PROPOSAL.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md),
[`PROGRESS.md`](./PROGRESS.md)); source crates land in subsequent
phases.

## SN360 Family

SNG is one of three products in the SN360 family. Each product owns a
slice of the customer's security surface and shares the same tenant
identity, policy graph, telemetry pipeline, and signing trust root.

| Product | Repository | Scope |
|---|---|---|
| **ShieldNet Access** | [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | Multi-tenant control plane: identity, RBAC, signed rule distribution (TRDS), IOC distribution (IOCFS), software-inventory (SIS), Wazuh-based correlation, compliance, alert forwarding |
| **ShieldNet Defense** | [`sn360-es`](https://github.com/kennguy3n/sn360-es) | Email security for GWS / O365: tiered ML phishing / BEC detection, banners, quarantine, post-delivery remediation, end-user education |
| **ShieldNet Gateway** | [`visible-fishbone`](https://github.com/kennguy3n/visible-fishbone) — this repo | Network security gateway: NGFW + IDS/IPS, SWG + DNS, ZTNA + VPN replacement, SD-WAN, edge VM appliance + lightweight endpoint client |

## Core Capabilities

SNG launches with a focused capability surface. Heavier data-protection
and posture features ship in later phases (see [`PROGRESS.md`](./PROGRESS.md)).

| Capability | Launch Status | Complexity |
|---|---|---|
| **NGFW + IDS/IPS** — L3-L7 policy, NAT, app awareness, TLS policy, Suricata inline | Phase 2 (Secure Edge MVP) | High |
| **SWG + DNS Security** — Envoy-based proxy, URL categorization, malware verdict API, resolver-layer filtering, reputation | Phase 2 | Medium |
| **ZTNA + VPN Replacement** — mTLS device identities, posture checks, app-level access, replaces legacy IPsec / SSL-VPN | Phase 2 | Medium |
| **SD-WAN** — overlay tunnels, health probes, path scoring, app-aware steering, failover | Phase 2 | Medium-High |
| **CASB (partial)** — SaaS discovery + top API connectors (no full inline-CASB) | Phase 4 (Data Protection Expansion) | Medium |
| **DLP (partial)** — web + SaaS DLP, browser protections (no endpoint DLP at launch) | Phase 4 | Medium |
| **XDR Integration** — signal export to SN360 Access + third-party SIEM / XDR / IAM / ticketing | Phase 3 (Unified Operations) | Low-Medium |
| **Telemetry + Policy Orchestration** — single typed policy model, change simulation, NATS JetStream ingestion, ClickHouse hot analytics, S3 cold archive | Phase 1 (Foundation) and Phase 3 | High |

## Architecture Overview

SNG ships in **three deployment forms** that share a single control
plane, policy model, and telemetry fabric.

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

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full mermaid diagrams,
data flow, and per-component breakdown.

## Technology Stack

Choices align with SN360 family conventions. Go is the default for
control-plane services; Rust is the default for any agent or
performance-sensitive edge component.

| Layer | Technology | Notes |
|---|---|---|
| Control plane services | **Go** | Matches `sn360-security-platform` (Gateway, TRDS, IOCFS, SIS) and the `sn360-es` single-binary control surface |
| Edge enforcement (packet path, policy evaluator, local collectors, parsers) | **Rust** | Matches `sn360-agent-vm` and `sn360-agent-k8s` performance budgets |
| Endpoint client (traffic steering, posture, ZTNA) | **Rust**, cross-platform | Mirrors the [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) architecture (`sda-pal` → `sng-pal`) |
| Admin UI | **TypeScript + React** | Matches the `sn360-security-platform` web admin |
| Policy / metadata storage | **PostgreSQL** | Row-level security per tenant, same pattern as SN360 Access |
| Hot analytics | **ClickHouse** | Normalized telemetry, 30-90 day retention |
| Cold retention | **S3-compatible object storage** | Compressed event archive, 1+ year |
| Eventing / pipeline | **NATS JetStream** | Same fabric as `sn360-es` and `sn360-security-platform` |
| L7 proxying (SWG) | **Envoy** (or equivalent) | URL categorization + malware verdict API |
| IDS/IPS | **Suricata** | Inline on edge VM; longer-term opt-in eBPF fast-path |
| Container platform | Managed **Kubernetes** / **k3s** | Control plane in EKS / AKS / GKE; k3s for self-hosted reference deployments |
| Infrastructure as code | **Terraform** | Tenant Terraform provider for MSP automation |
| Agent ↔ gateway wire | **TLS 1.3 + MessagePack + HTTP/2** | SN360 native protocol, same as SDA / VMA / SKA |
| Artifact signing | **Ed25519** | Policy bundles, action jobs, edge images, endpoint installers |

## Planned Workspace Layout

Rust crates use the **`sng-`** prefix, following the family pattern
(`sda-` desktop, `vma-` VM, `ska-` Kubernetes, `sng-` gateway). Layout
mirrors the lib/bin split used by `sn360-agent-k8s` and
`sn360-desktop-agent`.

| Crate | Kind | Responsibility |
|---|---|---|
| `sng-agent` | bin | Endpoint client binary — traffic steering, posture, ZTNA, SWG steering, UX telemetry |
| `sng-edge` | bin | Edge VM appliance binary — NGFW, IPS, DNS, SWG proxy, SD-WAN overlay |
| `sng-core` | lib | Shared types, configuration model, lifecycle, error taxonomy |
| `sng-pal` | lib | Platform Abstraction Layer for the endpoint client (Windows / macOS / Linux) |
| `sng-policy-eval` | lib | Local policy evaluation engine (consumes compiled policy bundles) |
| `sng-comms` | lib | SN360 native protocol client — TLS 1.3, MessagePack, HTTP/2, batching, replay-safe ack |
| `sng-telemetry` | lib | Local telemetry collection, normalization, dedup, and metadata-first redaction |
| `sng-swg` | lib | Secure Web Gateway proxy engine (Envoy integration + custom verdict hooks) |
| `sng-dns` | lib | DNS security resolver and filter (reputation, category, sinkhole) |
| `sng-ztna` | lib | Zero Trust Network Access — mTLS device identities, posture binding, app access |
| `sng-sdwan` | lib | SD-WAN overlay tunnels, path scoring, health probes, app-aware steering |
| `sng-ips` | lib | IDS/IPS integration (Suricata wrapper, rule sync, alert normalization) |
| `sng-fw` | lib | Firewall — L3-L7 policy, NAT, app awareness, nftables / conntrack glue |
| `sng-updater` | lib | Self-update with signed manifests (Ed25519), dual-bank image install, rollback |

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

## Related Repositories

| Repo | Purpose |
|---|---|
| [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | ShieldNet Access — multi-tenant control plane, identity, policy distribution, correlation, compliance |
| [`sn360-es`](https://github.com/kennguy3n/sn360-es) | ShieldNet Defense — email security for GWS / O365 |
| [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) | SN360 endpoint agent (Windows / macOS / Linux) |
| [`sn360-agent-vm`](https://github.com/kennguy3n/sn360-agent-vm) | SN360 server / VM agent |
| [`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s) | SN360 Kubernetes agent |
| [`visible-fishbone`](https://github.com/kennguy3n/visible-fishbone) | ShieldNet Gateway — this repo |

## Documentation

| Document | Purpose |
|---|---|
| [`PROPOSAL.md`](./PROPOSAL.md) | Product design proposal — competitive baseline, SME constraints, capability scope, reference architecture, AI / data / security model, commercial model, phased roadmap, risk register |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System architecture — topology diagrams, control plane services, edge VM internals, endpoint client internals, telemetry pipeline, data tiering, security model, SN360 integration points, wire protocol |
| [`PROGRESS.md`](./PROGRESS.md) | Phased delivery roadmap — status per phase (Foundation, Secure Edge MVP, Unified Operations, Data Protection Expansion, Advanced Automation, Hardware Packaging), exit criteria, changelog |

## License

SN360 Proprietary — see [`LICENSE`](./LICENSE) for the full license
terms. Copyright (c) 2026 SN360 Inc. All rights reserved. For
licensing inquiries, contact
[licensing@sn360.com](mailto:licensing@sn360.com).
