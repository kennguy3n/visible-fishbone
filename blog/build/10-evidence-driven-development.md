# Build on evidence: a harness, datasheets, and reproducibility

> **Build series, Post 10 of 10 — the engineering culture.** Reader: both,
> because the discipline in this post is what makes every other post in the
> series believable. The decision: *how do you build a product whose claims you
> can actually back, and keep backing as the code changes?*

Every preceding post made a claim with a number attached — 5.13× throughput lift,
3,696× memory saving, 100% / 0% on curated corpora, 90.1% / 9.6% on wild malware,
10× fewer tenant-visits. The decision that makes those numbers worth anything is
the last one: **build a culture where every claim traces to a reproducible
artifact, and where the embarrassing numbers get published too.**

## The build: harnesses that emit artifacts, not slides

The evidence lives in [`../artifacts/`](../artifacts/) and is produced by
harnesses in [`../harness/`](../harness/), each of which drives the *real*
product:

- **Seed** (`blog/harness/seed`) — builds the idempotent nine-tenant,
  seven-country fleet that every screenshot and payload is taken against, so
  results are reproducible across reseeds.
- **Capture / newcaps** (`blog/harness/capture`, `blog/harness/newcaps`) — hit a
  running control plane and write **verbatim** API responses to
  [`../artifacts/payloads/`](../artifacts/payloads/): the signed App-ID catalog,
  the managed threat-content posture, the continuous-compliance posture and
  evidence packs, the digital-experience scores and degradation alert, the
  policy-recommendation surface.
- **Efficacy** (`bench/efficacy`) — drives the actual enforcement crates against
  labelled corpora and emits
  [`efficacy-report.json`](../artifacts/efficacy-report.json) (16 functions,
  verdict PASS).
- **Performance** (`bench/`) — emits the floor-and-ceiling throughput artifacts
  ([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json)).
- **Capacity plan** (`bench/controlplane`) — emits the 5,000-tenant model
  ([`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md)),
  labelled a model, never a measurement.

The whole set is regenerable — the
[engineering series README](../posts/README.md#reproducing-the-artifacts) lists
the exact commands. A claim you cannot regenerate is a claim you should not make.

## The four honesty rules, as engineering practice

The honesty contract is not a tone; it is a set of build rules:

1. **Measured ≠ projected.** Throughput is published as a single-stream floor
   *and* a multi-queue ceiling, side by side; the capacity plan is labelled a
   model. You never quote the flattering number alone.
2. **Competitor numbers are caveated datasheet figures**
   ([`competitors.json`](../../bench/business-report/competitors.json)), each with
   a `source_url` and a `caveat` — because ASIC appliances are not
   apples-to-apples with software-on-VM.
3. **Screenshots are of real, seeded, error-free pages** — captured via CDP, never
   mock-ups.
4. **The critique is honest** — every post, including these build posts, ends with
   where the approach falls short, and the wild-malware WARN is published in the
   same table as the 100% curated rows.

## The business call: reproducible honesty is a competitive weapon

The scenario: **Tom, a CFO,** has been burned by vendor benchmarks before. The
SNG pitch is unusual: *here is the harness; re-run it yourself.* The floor is
published next to the ceiling, the loss-making tenant is in the seed data, the
9.6% false-positive rate is in the efficacy table. For a buyer who has learned to
distrust datasheets, "we publish our worst numbers and you can reproduce them" is
more persuasive than any single figure — and it is a claim the incumbents, whose
proof points are periodic third-party labs, structurally cannot make on demand.

## How the incumbents approached it

- The incumbents prove efficacy through **third-party labs** (AV-Comparatives,
  MITRE ATT&CK evaluations, NSS-style tests) and analyst reports — credible and
  independent, but periodic and not buyer-reproducible.
- Performance is proven through **published datasheets** — vendor-run, on vendor
  hardware, typically the favourable configuration.

SNG cannot match a major lab's corpus breadth or a vendor lab's hardware. Its
distinctive call is **in-repo, regenerable evidence with the unflattering numbers
left in** — a different kind of proof: not "an authority vouches for us" but "here
is the harness, run it." Both are legitimate; they suit different buyers, and SNG
is honest that a prudent buyer should want third-party validation too.

## Build it yourself

1. **Make every claim an artifact.** If a number is in a post, a harness emits it
   to a file; if you cannot regenerate it, do not publish it.
2. **Drive the real code.** Harnesses must call production APIs and crates, not
   models of them.
3. **Publish floors with ceilings and WARNs with PASSes.** The discipline is
   showing the bad number next to the good one.
4. **Caveat every external figure** with a source and a reason it is not
   apples-to-apples.
5. **End every claim with its limit.** The "where it falls short" section is not
   modesty; it is the thing that makes the rest credible.

## Where this approach falls short

- **It is one VM, not a fleet.** Per-feature numbers are measured; the
  5,000-tenant economics are modelled. The honest gap is a long-lived staging
  fleet that publishes real wake-latency, promotion, and throttle events.
- **Reproducible is not the same as comprehensive.** The corpora are small next
  to a major lab's, and the competitor contrasts are reasoned from public
  material, not their internals. Buyer-reproducible honesty complements
  third-party validation; it does not replace it.
- **Discipline decays without enforcement.** A harness only stays honest if new
  features arrive with new corpora and new artifacts. The moment a claim ships
  without a regenerable source, the contract is broken — which is why this is the
  last post, not the first: it is the practice that has to outlive the build.
