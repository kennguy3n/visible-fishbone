# Anycast / BGP front-door (reference)

Announce a single anycast prefix from every PoP and let the internet's
BGP best-path deliver each client to its nearest PoP. This is the lowest
client-side failover latency option — failover is route withdrawal in
the routing fabric, not a DNS-TTL wait — but it requires running your
**own ASN and IP prefix** and BGP sessions with upstreams/IXs.

## Files

| File | Purpose |
|------|---------|
| [`bird.conf.tftpl`](bird.conf.tftpl) | BIRD BGP speaker config, one per PoP, announcing the shared anycast prefix. Templated (`${...}`) for router-id / ASN / prefix / peer. |
| [`health-withdraw.sh`](health-withdraw.sh) | Sidecar that enables/withdraws the announce based on the edge `/readyz` signal, so an unready PoP stops attracting traffic. |

## How it works

1. The anycast VIP is bound to a loopback/dummy interface on **every** PoP.
2. Each PoP's BIRD speaker announces the same prefix (`${anycast_prefix}`)
   to its upstream/IX (`${peer_ip}` / `${peer_asn}`).
3. Clients reach whichever PoP is closest in BGP terms.
4. `health-withdraw.sh` polls the edge readiness endpoint
   (`/readyz` on the health-bind port, default `9119` — see
   [`crates/sng-edge`](../../../../crates/sng-edge)) and runs
   `birdc disable sng_announce` when it fails, withdrawing the route.
   BGP reconverges onto the remaining PoPs within seconds.

## Prerequisites (the honest part)

Anycast is **not** something SNG provides for you. You must:

- own or lease a **portable IP prefix** and an **ASN**;
- establish **BGP sessions** with transit providers or at IXPs in each
  PoP's metro;
- accept that prefix de-aggregation / filtering policies vary by upstream.

If you do not run your own network, use the
[GeoDNS front-door](../geodns) instead — it needs only a hosted zone.

## Validation

The BIRD config is a `.tftpl` template, so it is rendered before use and
is not machine-validated in this repo. After rendering, validate syntax
on a host with BIRD installed:

```bash
bird -p -c bird.conf      # parse-only, no daemon
```
