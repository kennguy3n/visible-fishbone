# ShieldNet Gateway — Development Progress

This document tracks what has shipped, what is in progress, and what
is planned for ShieldNet Gateway (SNG). It is the SNG analogue of
[`sn360-agent-k8s/ROADMAP.md`](https://github.com/kennguy3n/sn360-agent-k8s/blob/main/ROADMAP.md),
extended with the phased roadmap from [`PROPOSAL.md` §10](./PROPOSAL.md#10-phased-roadmap).

This is a directional roadmap, not a commitment. Priorities shift in
response to design-partner feedback, security advisories, and the
state of the wider SN360 family.

---

## Current Status

**Pre-development / Planning phase.**

The first deliverable for SNG is the documentation set in this
repository:

- [`README.md`](./README.md) — public-facing project README, SN360
  family context, capability matrix, planned workspace layout,
  related repos.
- [`PROPOSAL.md`](./PROPOSAL.md) — product / commercial / roadmap
  proposal grounded in competitive analysis, SME constraints, and
  the family's existing architectural conventions.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — detailed system
  architecture: control plane, edge VM, endpoint client, telemetry
  pipeline, data tiering, security model, SN360 integration points,
  wire protocol.
- [`PROGRESS.md`](./PROGRESS.md) — this file.

No source crates are present in this repo yet. Phase 1 (Foundation)
work starts after the planning docs are approved.

---

## Phase 1 — Foundation

**Status: Not Started.**

The bones the rest of the product depends on.

- **Multi-tenant control plane** (Go) — service skeleton, tenant
  service, identity service, API + Integration Gateway, mTLS device
  enrollment. Same Postgres-RLS-per-tenant pattern as
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
- **Tenant RBAC + site templates** — hierarchical multi-tenant
  RBAC (MSP → tenant → site); site templates for branch / hub /
  cloud-only / home-office.
- **Endpoint client skeleton** (`sng-agent`, Rust, cross-platform
  Windows / macOS / Linux) — lifecycle, config, enrollment,
  `sng-comms` over the SN360 native protocol, `sng-pal` skeleton.
  No enforcement yet.
- **Event schema + NATS JetStream setup** — typed event envelopes,
  tenant-scoped subject hierarchy (`sng.<tenant>.telemetry.<class>`),
  stream + consumer + DLQ configuration.
- **API base** — versioned REST surface, OpenAPI document, HMAC-
  signed webhooks, retry-with-backoff delivery.
- **Policy graph data model** — Postgres schema for the typed
  policy graph; compiler stub that emits empty (default-safe)
  bundles for each target.
- **CI pipeline** — fast PR gate (lint + unit tests) + full suite
  on main (integration + chart lint + signing), matching the
  `sn360-security-platform` / `sn360-agent-k8s` CI shapes.

**Exit criteria.** Pilot tenants enrolled end-to-end (claim token →
device identity → policy bundle → telemetry visibility) with the
admin UI showing live events.

---

## Phase 2 — Secure Edge MVP

**Status: Not Started.**

Land the core gateway product surface.

- **NGFW + IDS/IPS** — `sng-fw` (Rust packet path on nftables /
  conntrack) + `sng-ips` (Suricata wrapper); compiled policy
  bundles drive both.
- **DNS security** — `sng-dns` recursive resolver with
  reputation / category filter / sinkhole.
- **SWG** — `sng-swg` Envoy-based forward proxy with URL
  categorization + malware verdict API.
- **ZTNA + VPN replacement** — `sng-ztna` device-bound mTLS access
  + posture binding; WireGuard-class tunnel as the VPN replacement.
- **SD-WAN basics** — `sng-sdwan` overlay tunnels, active health
  probes, path scoring, app-aware steering, sub-second failover.
- **Edge VM image** — `sng-edge` virtual appliance image
  (VMware / KVM / Hyper-V / cloud), Rust binary, dual-bank install
  with rollback, Ed25519-signed image manifest.
- **Endpoint client** — `sng-agent` traffic steering, posture, and
  ZTNA paths fully online; sub-15 MB resident memory and sub-0.1 %
  idle CPU targets enforced as CI gates.

**Exit criteria.** Stable branch enforcement + remote-access
replacement deployed in 10-20 design-partner tenants for at least one
full operational quarter, with no production-impacting regressions.

---

## Phase 3 — Unified Operations

**Status: Not Started.**

Convert raw capability into operator UX leverage.

- **Policy graph + change simulation** — full typed policy model
  spanning NGFW / SWG / DNS / ZTNA / SD-WAN / DLP; deterministic
  simulator replays recent telemetry against proposed changes
  before any enforcement happens.
- **Baseline alerts + behavior models** — statistical baselines
  (z-score / EWMA) as primary signal; bounded ML (isolation
  forest) as a second pass.
- **Incident summaries (AI-assisted)** — operator-facing prose
  summaries of telemetry-grounded incidents; clearly flagged as
  AI-generated; never assert facts outside the evidence.
- **Ticketing integrations** — bidirectional case sync with Jira,
  ServiceNow, Zendesk, Freshdesk.
- **MSP hierarchy + co-management** — MSP portal, per-MSP
  branding, bulk operations across tenants, per-tenant policy
  templates, Terraform provider for tenant config-as-code.

**Exit criteria.** Support-ticket rate per tenant trends down; first
MSP onboarding cohort completes without bespoke engineering effort;
AI-assisted summaries pass operator review on a representative
sample.

---

## Phase 4 — Data Protection Expansion

**Status: Not Started.**

Move up the security-value stack into data-aware capabilities.

- **CASB discovery + top SaaS API connectors** — M365, Google
  Workspace, Slack, Salesforce; API-mode only (no inline-CASB).
- **DLP for web + SaaS** — regex + classifier + document
  fingerprints; MIP label awareness on Microsoft tenants; pre-baked
  policy templates per industry.
- **Browser protections** — augment SWG with browser-side
  signals; coexist with the existing `sn360-desktop-agent` posture
  feed rather than duplicating it.

**Exit criteria.** Controlled false-positive rate on the published
policy templates; design-partner tenants run Data Guard in
enforcement mode (not just dry-run) without operator escalation
spikes.

---

## Phase 5 — Advanced Automation

**Status: Not Started.**

Reduce operator overhead at scale; keep humans in the loop where it
matters.

- **Guided remediation** — operator-approved playbooks for the
  most common incident classes (impossible-travel, exfil signal,
  app-misconfig).
- **Policy-tightening suggestions** — AI proposes
  least-privilege deltas based on observed usage; every suggestion
  compiles through the deterministic verifier before it can be
  applied.
- **Autonomous troubleshooting with approval gates** — AI can
  *propose* fixes for connectivity / policy / posture issues; an
  operator (or a pre-approved playbook) is required to execute.

**Exit criteria.** Measurable support-time reduction across the
design-partner cohort; every AI-driven action passes the
deterministic verifier; the immutable audit trail correctly records
the verifier outcome for every proposed action.

---

## Phase 6 — Hardware Packaging

**Status: Not Started.**

Capture the customer segment that requires a physical appliance for
operational, regulatory, or procurement reasons.

- **Reference whitebox + OEM appliance SKUs** — small / medium /
  large branch profiles on a small list of vetted OEM platforms;
  SNG software image is the same as the virtual appliance.
- **Secure boot + TPM identity** — hardware path uses the TPM as
  the root of device identity; secure boot enforced; image is the
  same dual-bank install path as the VM.

**Exit criteria.** Software attach + renewal economics on the
hardware path are demonstrably stronger than hardware revenue alone
— i.e. the appliance exists to *sell software*, not to be a
hardware business in disguise.

---

## Changelog

No releases yet.

---

## How to Propose Changes

Operator-driven roadmap items should be filed as a GitHub issue
labelled `roadmap`. Include the use case, the workaround you are
using today, and any constraints (network architecture, hypervisor /
cloud, identity provider, MSP context). The maintainers triage
`roadmap` issues at each release cycle.

Security-sensitive proposals should follow the disclosure process in
`SECURITY.md` once that document is in place (Phase 1 deliverable).
