# Build a SASE platform like this: the technical-product series

A ten-post companion to the [measured engineering series](../posts/README.md) and
the [business series](../posts/business/README.md). Where those two walk *what*
ShieldNet Gateway (SNG) does and *why a buyer should care*, this series answers a
third question: **how would you actually build a system like this — and how were
the load-bearing decisions made?**

It is written for two readers at once:

- **The engineer** who wants the real architecture: the control-plane/edge
  split, the typed policy graph and its compiler, Postgres row-level security as
  the isolation boundary, the Rust enforcement crates (including SWG add-on inline
  DLP, AI governance, RBI, clientless ZTNA, and default-off DEM) and the eBPF/XDP
  fast path, the signed App-ID catalog, the efficacy harness, and the NoOps
  economics.
- **The product leader** who wants the *decision behind* each of those: what bet
  it encodes, who it serves, what it costs, and how the incumbents (Zscaler,
  Palo Alto, Fortinet, Netskope, Cato) made the same call differently.

Every post follows the same shape:

1. **The build** — the concrete technical design, anchored to real code in this
   repo (paths, primitives, measured numbers).
2. **The business call** — the decision as a product scenario: the tradeoff, the
   buyer it serves, the revenue or cost consequence.
3. **How the incumbents approached it** — the same problem as Zscaler, Palo Alto
   Prisma Access, Fortinet, Netskope, and Cato solved it, with their published
   constraints (caveated; see the [honesty contract](#the-honesty-contract)).
4. **Where this approach falls short** — the honest limits of the choice.

## The posts

| # | Post | The decision | Reader |
| --- | --- | --- | --- |
| 0 | [Why this series exists, and how to read it](00-build-series-intro.md) | — | both |
| 1 | [Pick the bet: SASE for the dormant-trial SME fleet](01-why-sase-for-smes.md) | Who you build for | product-led |
| 2 | [Split the plane: a Go control plane and a Rust edge](02-control-plane-edge-split.md) | Language + topology | engineer-led |
| 3 | [Make policy a typed graph, then compile it](03-typed-policy-graph.md) | Config model | engineer-led |
| 4 | [Isolate tenants in the database, not the application](04-multitenant-rls.md) | Isolation boundary | engineer-led |
| 5 | [Compose the edge from crates, with a kernel fast path](05-enforcement-crates-ebpf.md) | Enforcement architecture | engineer-led |
| 6 | [Identify applications from a signed catalog, not a `match` arm](06-application-identification.md) | Extensibility | both |
| 7 | [Treat detection efficacy as a measured discipline](07-detection-efficacy-discipline.md) | Quality model | both |
| 8 | [Engineer the economics: NoOps for 5,000 mostly-dormant tenants](08-noops-economics.md) | Unit cost | both |
| 9 | [Ship AI you can trust: verify before you suggest](09-ai-you-can-trust.md) | AI safety | both |
| 10 | [Build on evidence: a harness, datasheets, and reproducibility](10-evidence-driven-development.md) | Engineering culture | both |

## The honesty contract

This series inherits the same four rules as the engineering series, because the
*how* is only useful if the numbers behind it are real:

1. **Measured ≠ projected.** Throughput is published as a single-stream floor and
   a multi-queue ceiling, side by side. Where a figure is a model (the
   5,000-tenant capacity plan), it is labelled a model.
2. **Competitor numbers are published datasheet figures, caveated.** They live in
   [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
   with a `source_url` and a `caveat` on every row. Most competitor boxes are
   ASIC-accelerated appliances; SNG is software-only on a generic x86 VM. The
   cloud-native rows (Zscaler) are the only directly comparable ones. Netskope
   and Cato appear as architectural contrasts, not benchmark rows.
3. **Code anchors are real.** Every "build it this way" points at a path that
   exists in this repo.
4. **The critique is honest.** Every post ends with where the approach falls
   short — including the bets that have not paid off yet.

## What you would be able to build

By the end of the series you would understand how to assemble: a multi-tenant
control plane with hard database-level isolation; a typed, compiled, signed
policy model that now also includes AI governance, RBI, inline DLP, clientless
ZTNA, and DEM nodes; a composable software data plane with a kernel fast path; a
signed, versioned application-identification catalog; a measured efficacy
discipline with explicit false-positive budgets; the NoOps economics that make a
trial-heavy fleet profitable; and an evidence harness that keeps every claim
reproducible. None of it requires custom silicon.
