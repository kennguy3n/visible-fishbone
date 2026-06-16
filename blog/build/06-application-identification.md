# Identify applications from a signed catalog, not a `match` arm

> **Build series, Post 6 of 10 — extensibility.** Reader: both, because this is
> where an engineering shortcut becomes a product ceiling. The decision: *how do
> you recognise the application behind a flow, and how do you add a new one
> without shipping a new build?*

Application identification is the unglamorous capability that quietly decides
whether your product can keep up with the world. The tempting shortcut is to bake
recognition into code: a `match` over a handful of hand-written protocol parsers.
It works on day one and becomes a liability the first time a customer asks about
an app you did not compile in — because now "add an app" means "ship a new data
plane."

## The build: a signed, versioned data catalog the edge consumes

SNG resolves the `app` policy node against a **signed, versioned
application-identification catalog** (`crates/sng-appid`, data in
`crates/sng-appid/data/catalog.json`). The captured catalog is **215
applications across 17 categories**
([`appid-acme-catalog-current.json`](../artifacts/payloads/appid-acme-catalog-current.json)),
each carrying a monotonic serial so the edge can detect a stale copy, and the
whole thing is distributed as an **Ed25519-signed bundle** the edge verifies
before trusting.

The matcher is the part to get right:

- It walks host suffixes **most-specific-first**, so `api.internal.example.com`
  and `example.com` resolve independently and do not collide.
- It only awards an **exact-match bonus** when the catalog entry equals the whole
  observed host — a 2-label suffix match does not get the exact bonus.
- Each app is recorded at its *first* (most specific) match, so ranking is
  deterministic.

The decisive property: **adding an app is a catalog update, not a recompile of
the data plane.** A new serial, a new signed bundle, and every edge picks it up —
no release train, no redeploy of enforcement code. The catalog is data; the
engine that reads it is stable.

## The business call: the catalog is what keeps you current

The scenario: **Devraj** asks "can you see and control [some new SaaS app]?" With
a hard-coded protocol set, the honest answer is "in the next release, maybe." With
a signed catalog, the answer is "it is in the catalog as of serial *N*, and your
edge already has it." For the buyer, application coverage stops being a roadmap
item and becomes a data-update cadence. For the vendor, it means the team ships
*one* identification engine and then maintains *data* — which a much smaller team
can do, which is exactly the constraint the whole platform is built around
(Post 1).

There is a honesty dimension too: because the catalog is signed and versioned, a
buyer can ask "what is your coverage and how fresh is it?" and get a serial and a
count, not a marketing adjective.

## How the incumbents approached it

- **Palo Alto's App-ID** is the canonical version of this idea — a large,
  vendor-maintained application database with regular content updates, decoupled
  from the firmware. SNG's call is the same *shape* (data, not code), at SME scale
  and signed end to end. Palo Alto's catalog is far broader; SNG's is signed,
  versioned, and honest about its size.
- **Fortinet** ships application control signatures via FortiGuard content
  updates — again data-driven, pushed to appliances on a subscription.
- **Zscaler, Netskope, Cato** maintain cloud-side application catalogs (Netskope
  in particular built its brand on deep SaaS/CASB app understanding); the catalog
  lives in their cloud and updates continuously.

The whole industry converged on "application identification is a maintained data
catalog, not compiled-in code." SNG's distinctive call is doing it as a
*signed, serial-versioned, independently-verifiable* bundle the edge checks — so
freshness and integrity are inspectable, not just promised — while being honest
that catalog *breadth* is where a dedicated incumbent still leads.

## Build it yourself

1. **Make the catalog data, not code.** A schema-versioned, serial-stamped file
   the engine loads at runtime — never a `match` arm you have to recompile.
2. **Sign the bundle and verify on load.** The edge trusts the signature and the
   serial, so a stale or tampered catalog is detectable.
3. **Get the matcher's suffix walk right.** Most-specific-first, exact bonus only
   on a whole-host match, deterministic first-match recording. The subtle bugs
   here are silent misattributions.
4. **Decouple coverage from releases.** Adding an app must be a catalog publish,
   not a data-plane deploy, or you have rebuilt the very ceiling you were avoiding.

## Where this approach falls short

- **Breadth is still catching up.** A dedicated incumbent's catalog dwarfs 215
  apps. SNG's differentiator is the *signed, versioned, honest* delivery and the
  zero-recompile update path — not raw app count, which is a genuine gap.
- **A signed data catalog is a supply chain.** You now own a content pipeline:
  curation, signing keys, distribution, and the trust that the catalog is
  accurate. That is real operational surface, not a free lunch.
- **Identification is probabilistic.** Host-suffix matching is robust but not
  omniscient; encrypted, fronted, or fully off-network traffic limits what any
  catalog-driven matcher can attribute, the same honest limit the CASB discovery
  story carries.
