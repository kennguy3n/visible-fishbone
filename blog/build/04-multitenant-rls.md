# Isolate tenants in the database, not the application

> **Build series, Post 4 of 10 — the isolation boundary.** Reader: engineer-led,
> with a product framing of the trust argument. The decision: *where does
> tenant isolation actually live — in your application code, or below it?*

Multi-tenant isolation is the decision you cannot get wrong, because getting it
wrong is a cross-tenant data breach. There are three common places to draw the
boundary: a database per tenant (strong, expensive), a `WHERE tenant_id = ?` on
every query (cheap, fragile — one forgotten clause is a leak), or **the database
enforcing it for you.** SNG chose the third.

## The build: Postgres row-level security keyed to a session GUC

Every tenant-scoped table has **row-level security (RLS) enabled**, with a policy
that compares the row's `tenant_id` to a Postgres session variable —
`sng.tenant_id`, a custom GUC the application sets at the start of every
request's transaction. The runtime connects as a **non-superuser role
(`sng_app`, `NOLOGIN`, granted to the login role)** so that RLS is actually
enforced — superusers and table owners bypass RLS, so the runtime must be neither.

The mechanism, end to end:

1. A request authenticates and resolves its tenant.
2. The repository layer (`internal/repository/postgres`) opens a transaction and
   sets `sng.tenant_id` to that tenant's UUID.
3. Every query in that transaction sees *only* that tenant's rows — enforced by
   Postgres, not by the Go code remembering to add a clause.
4. If a query forgets a filter, RLS still scopes it. The boundary holds even when
   the application is wrong.

This is why the DLP probe-ingest bug was worth fixing inside this work: the
original code used `COPY FROM`, and **Postgres categorically refuses `COPY FROM`
on an RLS-enabled table.** The fix
(`internal/repository/postgres/dem.go`) swaps the bulk copy for a chunked
multi-row `INSERT` that RLS *can* enforce, and a new integration test runs as the
`sng_app` role against real Postgres 16 to prove the isolation actually holds on
that path. The lesson is the whole point of the decision: *the isolation boundary
is real enough to break your own fast paths*, which is exactly what you want.

## The business call: "the database won't let it leak" is the trust story

The scenario: **Maya, an MSP platform lead,** is onboarding a healthcare tenant
(Globex, HIPAA) and a retail tenant (Acme, PCI) onto the same fleet. Her question
is blunt: *what stops Acme's console from ever seeing Globex's data?* "We're
careful to add `WHERE tenant_id` everywhere" is not an answer that survives an
auditor. "Postgres enforces it below the application, we run as a non-superuser
so we can't bypass it, and here is an integration test that proves a cross-tenant
read returns zero rows" is. The isolation boundary is a sales artifact, not just
an implementation detail — it is the difference between a blast radius Maya can
attest to and one she can only hope about.

It is also cheap per tenant, which is what makes the dormant-trial bet (Post 1)
work. RLS adds rows to shared tables; it does not add a database, a connection
pool, or a server per tenant. Five thousand tenants share the same Postgres, each
walled off by a policy the database enforces.

## How the incumbents approached it

- **Zscaler** is multi-tenant cloud-native by design — the closest peer — and
  isolates tenants within its own cloud platform; the boundary is internal to
  Zscaler's infrastructure rather than a customer-inspectable database policy.
- **Netskope and Cato** are likewise multi-tenant clouds; isolation is a property
  of their platform, opaque to the customer.
- **Fortinet and Palo Alto** historically isolate by *appliance* — a box (or a
  VDOM/vsys partition) per customer or per segment. Strong physical/logical
  isolation, but the unit cost is an appliance or a partition, not a row policy,
  which is the opposite of cheap-per-dormant-tenant.

SNG's distinctive call is making the isolation boundary a *database-enforced,
inspectable* property — you can read the RLS policy, run as the constrained role,
and test the boundary directly — rather than an opaque property of a cloud or a
physical appliance.

## Build it yourself

1. **Enable RLS on every tenant-scoped table** and write a policy that compares
   `tenant_id` to a session GUC you set per transaction.
2. **Run as a non-superuser, non-owner role.** RLS is bypassed by superusers and
   table owners; if your runtime is either, your policy is decoration.
3. **Set the GUC in one place** — the repository layer's transaction setup — so a
   new query physically cannot run outside a tenant scope.
4. **Test the boundary as the constrained role** against a real database. An
   in-memory repo will happily pass a test that RLS would have caught; the DEM
   `COPY FROM` bug hid for exactly this reason.

## Where this approach falls short

- **RLS is only as good as the role discipline.** One migration that runs as the
  owner, or one service that connects as a superuser "just to fix something," and
  the boundary is silently off. It has to be enforced in the deployment, not just
  the schema.
- **`COPY FROM` and some bulk paths are off-limits.** RLS forbids `COPY FROM`, so
  high-throughput ingest needs chunked `INSERT`s (as the DEM fix shows) — a real
  performance tax you pay for the isolation guarantee.
- **Shared tables mean shared blast radius for availability.** Hard *data*
  isolation does not give you *noisy-neighbour* isolation; a runaway query is
  still a shared-Postgres problem, addressed separately by the dormancy/capacity
  work in Post 8.
