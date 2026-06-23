# Make policy a typed graph, then compile it

> **Build series, Post 3 of 10 — the config model.** Reader: engineer-led, with a
> product framing of why it sells. The decision: *how do you represent a tenant's
> security intent so a tiny team can manage thousands of tenants without breaking
> them?*

This is the single most consequential engineering decision in the whole platform,
and it is the one most products get wrong. The default — the path of least
resistance — is to model policy as a pile of independent rule tables: a firewall
list, a web-filter list, a DLP list, each with its own precedence and its own way
to silently contradict the others. That model is easy to start and impossible to
operate safely at scale, because nothing can tell you when two tabs disagree.

## The build: one typed graph per tenant, compiled and signed

SNG models each tenant's intent as **one typed policy graph**
(`internal/service/policy`, evaluated by the `sng-policy-eval` crate on the
edge). The node types are the SASE primitives — `site`, `device`, `identity`,
`app`, `network-policy`, `dlp-policy`, `threat-policy`, `steering-policy`,
`ai-governance-policy`, `rbi-policy` — and edges express scope and precedence.
NGFW, SWG, DNS, IPS, ZTNA, DLP, SD-WAN steering, CASB, inline DLP, AI governance,
and RBI are not separate subsystems; they are nodes and edges in the *same* graph.

The pipeline is the part that matters:

1. **Type-check.** The graph is validated against its schema — an `allow` edge
   must connect an `identity` to an `app`, a `dlp-policy` must reference a real
   detector, and so on. Malformed intent never compiles.
2. **Resolve precedence deterministically.** The compiler walks the graph and
   resolves precedence with a fixed algorithm, so the same graph always compiles
   to the same rules. No document-order surprises.
3. **Reject contradictions.** A grant that an upstream deny would shadow is a
   *compile error* with the conflicting edge named — not a production incident
   discovered by a confused user.
4. **Sign and hash.** The output is a signed bundle with a content hash. The edge
   verifies the hash before loading and **fails closed to the last-good bundle**
   if it is torn or tampered.

The captured graph for a seeded tenant is verbatim in
[`s2-acme-policy-graph.json`](../artifacts/payloads/s2-acme-policy-graph.json):
typed nodes, explicit edges, compiled bundle metadata. Nothing in it is
hand-authored.

## Six verbs, one graph

Everything an operator wants collapses to six verbs — **route, allow, block,
prioritise, throttle, threat-protection** — and each is an edge type the compiler
understands *together*. That is the payoff: a `block` and a `prioritise` for the
same app are caught as a conflict at compile time because they are edges in one
graph, not two tabs that silently disagree.

## The business call: safe-by-construction is a sales argument

The scenario: **Devraj is a one-person IT team.** He is terrified — correctly —
of a change that silently opens a hole. A rule-list product asks Devraj to hold
the whole precedence model in his head. The typed graph asks the *compiler* to
hold it: if Devraj draws an edge that contradicts an existing one, he gets an
error naming the conflict before anything ships. For the buyer, "the platform
won't let you build a self-contradictory policy" is a feature you can demo in
thirty seconds, and it is the difference between a tool a small team trusts and
one they fear.

There is a second business consequence: because every compile is a structured
audit event with the graph diff, "who changed what, and what did it compile to"
is answerable from the audit log. Compliance (Post 7's cousin) gets the evidence
for free.

## How the incumbents approached it

- **Palo Alto** is the closest in spirit — a rich, centrally-managed policy model
  with Panorama compiling and pushing it (policy-compile p99 300–800 ms,
  [`competitors.json`](../../bench/business-report/competitors.json)). It is
  powerful, but it is built for an enterprise security team that *wants* the
  knobs, not a one-person SME shop.
- **Fortinet** centres FortiManager pushing rule sets to appliances (policy-push
  p99 200–500 ms at 1,000 devices). The model is device-centric rule
  distribution, not a single typed intent graph that conflict-checks across
  features.
- **Zscaler** offers a cloud policy model administered through its API (admin API
  p99 100–300 ms); the unification is real but the buyer is the enterprise.
- **Netskope and Cato** unify policy in their cloud consoles too; the
  differentiator SNG presses is *compile-time conflict rejection across all
  enforcement surfaces from one typed model*, not just a shared UI.

The common incumbent pattern is "one console over several engines." SNG's bet is
"one *typed, compiled* model that the engines are projections of" — so
contradictions are impossible by construction, not caught by careful operators.

## Build it yourself

1. **Define the node and edge types up front** as the SASE primitives, and make
   the schema the source of truth. Resist the urge to add a feature as a new
   side-table; add it as a node type.
2. **Make the compiler deterministic and total.** Same graph in, same bundle
   out, every time. Precedence is an algorithm, not a convention.
3. **Turn contradictions into compile errors.** The verifier that rejects a
   shadowed grant is the feature; build it before you build the editor.
4. **Sign the output and fail closed.** The edge trusts the bundle's hash, not
   the network it arrived over.

## Where this approach falls short

- **A graph has a learning curve.** A first-time operator is better served by
  smart-default templates that render a jurisdiction-correct baseline graph from
  `(industry, country)` than by drawing nodes from scratch. Lean on templates for
  onboarding; reserve the raw editor for the cases that need it.
- **Cross-tenant reuse is still template-shaped.** An MSP wanting "this exact
  subgraph on 200 tenants" uses a template + diff roll-out, not a live shared,
  inherited subgraph. A genuinely shared subgraph is future work.
- **The compiler is now load-bearing.** A bug in precedence resolution is a
  whole-fleet bug. The discipline that makes this safe is the efficacy/test
  harness in Post 10 — the graph model and the evidence discipline are a package
  deal.
