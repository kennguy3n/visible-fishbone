# Multi-PoP Deployment Topology

This document describes how to run the ShieldNet Gateway (SNG) edge as a
**multi-PoP fleet** — two or more Points of Presence across regions,
behind a single front-door that steers each client to a nearby healthy
PoP and away from a failed one.

The runnable/validatable reference assets live in
[`deploy/pop`](../deploy/pop). This document explains the topology, the
front-door options and their tradeoffs, the failover behaviour, and —
[§5](#5-honest-framing) — an explicit honest framing of what a
self-operated PoP fleet does and does not buy you.

> **Read [§5](#5-honest-framing) first if you are evaluating SNG against
> a vendor-run global network.** SNG is software you deploy across your
> own PoPs; it is not a network you rent.

---

## 1. The layers

A PoP is built from three layers, two of which already ship in this
repo. The multi-PoP reference adds the third (the front-door + the
cross-region composition):

```
                         ┌──────────────────────────┐
        clients ───────▶ │   FRONT-DOOR             │   GeoDNS (Route53) or
                         │   nearest healthy PoP    │   anycast/BGP
                         └────────────┬─────────────┘   deploy/pop/frontdoor
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                                 ▼
   ┌──────────────────────┐                        ┌──────────────────────┐
   │  PoP — region SEA     │                        │  PoP — region DACH    │
   │  ap-southeast-1       │                        │  eu-central-1         │
   │                       │                        │                       │
   │  LB (health: /readyz) │                        │  LB (health: /readyz) │
   │   └─ sng-edge x N     │                        │   └─ sng-edge x N     │
   │      /healthz /readyz │                        │      /healthz /readyz │
   └──────────┬───────────┘                        └──────────┬───────────┘
              │  health beacons (NATS)                         │
              └───────────────────────┬────────────────────────┘
                                       ▼
                         ┌──────────────────────────┐
                         │  sng-control (leader)    │  internal/service/pop
                         │  PoP registry + GeoDNS   │  registry + GeoDNSPublisher
                         │  publisher (singleton)   │
                         └──────────────────────────┘
```

| Layer | Provided by | Reference asset |
|-------|-------------|-----------------|
| Regional infrastructure (EKS, RDS, networking, one `/16` per region) | [`deploy/terraform/regions`](../deploy/terraform/regions) | per-region Terraform roots |
| Edge workload (the Rust appliance) | [`deploy/helm/sng-edge`](../deploy/helm/sng-edge) | Helm chart; or [`deploy/pop/k8s`](../deploy/pop/k8s) Kustomize |
| **Front-door + multi-PoP composition** | **this topology** | [`deploy/pop`](../deploy/pop) |

The region-group taxonomy (`SEA` / `GCC` / `DACH`) is defined once in
[`internal/region`](../internal/region) and consumed by the PoP manager
in [`internal/service/pop`](../internal/service/pop). The reference
assets use the same names so a PoP's infra, workload, and steering all
agree on which group it serves.

---

## 2. The front-door: anycast/BGP vs GeoDNS

The front-door is the only part that is genuinely new at the multi-PoP
level: given >=2 regional edge deployments, how does a client reach the
right one? Two options, with a real tradeoff.

### GeoDNS (default)

Steer at the DNS layer: the steering hostname resolves to the nearest
healthy PoP's address. SNG models this directly in
[`internal/service/pop`](../internal/service/pop): the `ZoneGenerator`
emits one record set per enabled PoP (A or AAAA by address family),
weighted by capacity tier (`small=1, medium=5, large=20`), under a
`latency`, `weighted`, or `simple` routing policy; the
`GeoDNSPublisher` — a **leader-gated singleton** — reconciles those
records into Route53/Cloudflare from the live registry. The Terraform in
[`deploy/pop/frontdoor/geodns`](../deploy/pop/frontdoor/geodns)
provisions the hosted zone and the per-PoP Route53 health checks (and,
optionally, the records themselves for a static fleet).

### Anycast / BGP

Announce a single anycast prefix from every PoP and let internet
BGP best-path deliver each client to its nearest PoP. Failover is route
withdrawal in the routing fabric, not a DNS-TTL wait. The reference
([`deploy/pop/frontdoor/anycast`](../deploy/pop/frontdoor/anycast))
is a BIRD speaker per PoP plus a health sidecar that withdraws the
announce when the edge stops passing `/readyz`.

### Tradeoffs

| | **GeoDNS** | **Anycast / BGP** |
|---|---|---|
| Prerequisite | A hosted zone | **Your own ASN + portable IP prefix + BGP peering** |
| Steering granularity | Per-resolver (latency/weighted) | Per-network (BGP topology) |
| Failover latency | Bounded by DNS **TTL** (we use 30s) + resolver caching | Route reconvergence (sub-second–seconds) |
| Sticky sessions | Resolver may flip PoP on re-resolve | Stable unless paths change |
| Operational burden | Low — API calls to a DNS provider | High — you run a network |
| Blast radius of a bad change | One zone | Routing fabric (prefix de-aggregation, filtering) |
| Who can run it | Anyone | Operators who already run a network |

A common production shape combines them: anycast within a metro, GeoDNS
across metros. They are not mutually exclusive, and both are gated on the
same edge readiness signal so steering never disagrees with a PoP's own
health.

---

## 3. Failover behaviour

Failover is health-driven at three independent layers, so no single
failure mode is load-bearing:

1. **Edge readiness (in the PoP).** Each `sng-edge` exposes its
   supervisor health aggregator on `--health-bind` (default `:9119`,
   see [`crates/sng-edge`](../crates/sng-edge)): `/readyz` (ready to
   serve) and `/healthz` (process alive). Kubernetes uses these as the
   readiness/liveness probes (see
   [`deploy/pop/k8s/base/edge-deployment.yaml`](../deploy/pop/k8s/base/edge-deployment.yaml)),
   so an unready replica is pulled from its Service endpoints and an
   unhealthy one is restarted.

2. **PoP health (in the control plane).** Each PoP emits health beacons
   over NATS (`CPUPct`, `MemoryPct`, `ActiveConnections`, `BandwidthMbps`);
   the registry in [`internal/service/pop`](../internal/service/pop)
   keeps the latest per PoP and treats a PoP whose most recent beacon is
   older than `DefaultHealthTTL` (90s) as **not available**. Tenant
   assignment and the GeoDNS record set are both computed from
   `Available()`, so a silent PoP drops out of steering automatically.

3. **Front-door health.**
   - *GeoDNS*: each steering record is tied to a Route53 health check on
     `/readyz`; Route53 stops returning a PoP that fails it. Failover is
     bounded by the record **TTL** (the reference uses 30s) plus resolver
     caching.
   - *Anycast*: the health sidecar runs `birdc disable sng_announce` when
     `/readyz` fails, withdrawing the prefix; BGP reconverges onto the
     remaining PoPs in seconds.
   - *Local simulation*: OSS nginx passive health checks (`max_fails` +
     a `backup` upstream) demonstrate the same failover semantics on one
     host — see [`deploy/pop/compose`](../deploy/pop/compose).

Because the same `/readyz` signal drives all three, a PoP that is
draining, overloaded, or partitioned is removed consistently from
Kubernetes endpoints, control-plane assignment, and the front-door.

---

## 4. Adding a PoP

1. Add a per-region Terraform root under
   [`deploy/terraform/regions`](../deploy/terraform/regions) with a
   non-overlapping `/16` and the region-group tag.
2. Deploy the edge into the new cluster — Helm
   ([`deploy/helm/sng-edge`](../deploy/helm/sng-edge)) or a new Kustomize
   overlay ([`deploy/pop/k8s/overlays`](../deploy/pop/k8s/overlays)).
3. Register the PoP (region, anycast IP, capacity tier) so it enters the
   registry and starts beaconing.
4. Add it to the front-door: a new `pops` entry for GeoDNS
   ([`deploy/pop/frontdoor/geodns`](../deploy/pop/frontdoor/geodns)), or a
   new BIRD speaker announcing the shared prefix for anycast.

No change is needed to the steering *logic* — the publisher and the
front-door pick up the new PoP from the registry / your `pops` input.

---

## 5. Honest framing

**SNG is software you deploy across your own PoPs; it is not a global
network you rent.** Everything in [`deploy/pop`](../deploy/pop) stands up
*your* footprint on *your* cloud accounts and *your* (or your provider's)
network. There is no SNG-operated edge between your users and your PoPs.

This is a real and deliberate difference from vendor-run global networks
(Zscaler, Cloudflare, Cato), and it cuts both ways:

- **What a self-operated fleet gives you.** Data-path sovereignty (every
  byte transits infrastructure you control), no shared-tenant edge, and
  placement exactly where you need it — which for a focused regional
  footprint (e.g. SEA / GCC / DACH) can mean *better* locality than a
  generic global network.
- **What it does not give you.** It does **not** erase the
  scale/footprint gap. A reference topology across two or three regions
  is not hundreds of vendor-operated PoPs with pre-negotiated peering,
  global anycast, and 24/7 NOC-run capacity. Anycast here assumes **you**
  bring an ASN, a prefix, and BGP relationships; GeoDNS assumes **you**
  run enough PoPs for "nearest" to be meaningfully near. Standing up this
  topology **narrows** the gap — it does not close it.

State the gap plainly in evaluations: SNG competes on control, locality
within your chosen regions, and the security data plane — **not** on
raw global footprint. If a requirement is "a vendor-run network already
present in 100+ cities," that is a footprint you would be building and
operating yourself here, not buying.
