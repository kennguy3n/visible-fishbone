# Front-door options

A multi-PoP deployment needs a **front-door**: the mechanism that sends
each client to a nearby healthy PoP and away from a failed one. Two
options, pick per your constraints (full tradeoffs in
[`docs/pop-topology.md`](../../../docs/pop-topology.md)):

| Option | Dir | Needs | Failover latency | Best for |
|--------|-----|-------|------------------|----------|
| **GeoDNS** | [`geodns/`](geodns) | A hosted zone (Route53) | DNS TTL (seconds–minutes) | Most operators; no own network. |
| **Anycast / BGP** | [`anycast/`](anycast) | Your own ASN + IP prefix + BGP peering | Route reconvergence (sub-second–seconds) | Operators who already run a network. |

Both are health-gated on the edge `/readyz` signal, so steering stays
consistent with each PoP's own readiness. They are not mutually
exclusive — a common production shape is anycast within a metro and
GeoDNS across metros.
