# Stand up a new tenant before the kickoff call ends (S1)

> **Post 2 of 8.** Persona: **Maya**, MSP platform lead. Outcome: repeatable,
> isolated multi-tenant onboarding with a blast radius of exactly one tenant.

## The MSP's real fear

Maya manages dozens of SME tenants from one console. Her nightmare isn't a slow
onboarding — it's a *leak*: tenant A seeing tenant B's policies, devices, or
audit log. So the operations story and the isolation story are the same story.

## Walking it in the console

One MSP, **Northwind Managed Security**, owns the hierarchy. The MSP portal
shows the managed tenants and the management relationship (owner vs. co-manager):

![MSP hierarchy](../artifacts/screenshots/s1-msp-hierarchy.png)

The tenant list is the per-tenant control surface. Four tenants across three
tiers, each with its own region, plan, and status:

![Tenants](../artifacts/screenshots/s1-tenants.png)

And every privileged action lands in an immutable audit log — typed action
badges, and a clear distinction between operator-initiated and system-initiated
rows:

![Audit log](../artifacts/screenshots/s1-audit-log.png)

## The real data behind it

From `GET /api/v1/msps` ([`s1-msps.json`](../artifacts/payloads/s1-msps.json)):

```json
{ "items": [ {
  "id": "b47fb518-f336-4449-82b0-bd33a1f36833",
  "name": "Northwind Managed Security",
  "slug": "northwind-msp",
  "status": "active"
} ] }
```

`GET /api/v1/tenants` returns the five tenants visible to the platform operator
(four managed + the platform tenant itself). The audit log
([`s1-acme-audit-log.json`](../artifacts/payloads/s1-acme-audit-log.json)) carries
the real provisioning trail, from the `tenant.created` event that anchors each
tenant's history through `policy.compiled`, `policy.signing_key_created`,
`casb.inline_rule_created`, and so on — each with a resource reference and a
timestamp.

## How isolation actually works

This is the part that matters, and it's enforced in Postgres, not in application
code that "remembers" to filter by tenant:

- **Row-level security, per transaction.** Every tenant-scoped query runs inside
  a transaction that first issues `SET LOCAL app.tenant_id = '<uuid>'`. RLS
  policies on every tenant table compare against that GUC. The runtime DB role
  (`sng_app`) is **not** a superuser and does **not** have `BYPASSRLS`, so even a
  bug that forgets the `WHERE tenant_id = …` clause cannot cross tenants — the
  database refuses the rows.
- **Global rows have an explicit, audited bypass.** Some rows are legitimately
  tenant-less (global app-registry mutations, platform audit). Before
  [PR #116](https://github.com/kennguy3n/visible-fishbone/pull/116) these were
  silently dropped on every boot (`audit append failed`). The fix added
  migration 052: `audit_log.tenant_id` is nullable, and a dedicated
  `sng.system_role` RLS bypass writes the tenant-less rows — with a new RLS
  integration test that runs as the **non-superuser** role to prove tenant
  isolation still holds. We fixed the audit gap *without* weakening isolation.

## Onboarding gets smart defaults + a dormancy dividend

Two additions this cycle target Maya's actual day: standing up *many* SME tenants
fast, and not paying for the ones that go quiet.

**Smart-default policy templates ([#157](https://github.com/kennguy3n/visible-fishbone/pull/157)).**
Onboarding no longer starts from an empty policy graph. An SME picks an *industry*
and a *country / compliance regime* and gets a deny-by-default `policy.Graph`
baseline — safe-browsing DNS+SWG, per-regime DLP detectors, an NGFW posture — as a
starting point. The catalog is **14 templates**
(`internal/service/policytemplates`, migration 062), captured verbatim from the
API at
[`policy-templates-catalog.json`](../artifacts/payloads/policy-templates-catalog.json):

- **1 baseline** — `baseline/global`, the universal security baseline
- **8 industries** — retail, healthcare, finance, technology, education, legal,
  professional-services, general
- **5 compliance regimes** — EU GDPR, UK DPA, US baseline, Canada PIPEDA,
  Australia Privacy Act

The buyer-facing walk-through is [business Post B4](business/11-compliance-templates.md).

**Activity-tiered dormancy ([#154](https://github.com/kennguy3n/visible-fishbone/pull/154)).**
An MSP managing dozens of trials carries a long tail of tenants that are
provisioned but idle. The new `SweepPlanner`
(`internal/service/tenancy/planner.go`) tiers every periodic sweep by a tenant's
dormancy: **active** tenants are processed every cycle, **idle** every 10th
(`DefaultIdleEvery = 10`), **dormant** every 100th (`DefaultDormantEvery = 100`).
The signal is the new `last_active_at` column (migration 063), bumped via
`GREATEST(last_active_at, now)` on tenant writes so it only ever moves forward. A
quiet trial therefore costs on the order of 1/100th of an active tenant's periodic
work — without turning the tenant off. The cost angle is
[business Post B1](business/08-noops-dormant-trials.md).

*Integration status: the planner is wired into the IdP `SyncService` and covered
by `tenancy` + `identity` unit tests (green on `main`), but that sync loop isn't
started in `cmd/sng-control` yet — so the tiering is proven by tests, not yet
shaping a live production sweep. Flagged, not hidden.*

## Where we fall short

- **RBAC / SCIM / IdP breadth.** The scaffolding (roles, SCIM provisioning, IdP
  federation, branding, bulk ops) is present in the console, but the depth of,
  say, Okta/Entra SCIM edge-case handling is not at the level of a dedicated IGA
  product. This is honest scaffolding, not a finished IAM suite.
- **Templates are a catalog, not yet a roll-out UI.** The 14-template catalog and
  its render path are real and tested, but the cross-tenant "apply this baseline
  to these 12 tenants" console flow is still thin — today it's an API capability
  more than a guided operator surface.
- **Onboarding is API-fast, not wizard-polished.** Our seed harness stands up a
  full tenant in seconds via the API, which is great for MSP automation. The
  *guided* click-through onboarding wizard is thinner than the API path.
- **No cross-region tenant migration yet.** A tenant's region is set at creation;
  moving it is not a one-click operation.

## Control-plane comparison

The directly-comparable competitor figure here is cloud-native: Zscaler's
published admin-API latency. Per
[`competitors.json`](../../bench/business-report/competitors.json), Zscaler's
admin API tenant-CRUD p99 sits in the **100–300 ms** range, caveated as "cloud
native, directly comparable." SNG's control plane is the right thing to bench
against that (Go API latency is measurable unprivileged) — and unlike a hardware
appliance comparison, this one *is* apples-to-apples.

Next: the security proof — the detection efficacy matrix.
