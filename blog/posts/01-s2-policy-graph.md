# One typed policy graph lights up a branch (S2)

> **Post 1 of 8.** Persona: **Devraj**, the one-person IT shop at a 180-seat
> firm. Outcome: one policy model — not five consoles — drives NGFW, IPS, SWG,
> DNS security, and SD-WAN steering at once.

## The problem with five consoles

In a traditional stack, a "branch turn-up" means touching a firewall ruleset, an
IPS profile, a web-filtering policy, a DNS policy, and an SD-WAN steering config
— five products, five mental models, five places to make a mistake. SNG's
differentiated design is that all of these are *projections of a single typed
policy graph*. You author intent once; the control plane compiles it into a
signed bundle the edge enforces.

## Walking it in the console

The policy editor renders the graph two ways. The **simple** view is a guided
form for Devraj; the **advanced** view is a React-Flow node graph for someone who
wants to see the whole decision flow.

![Policy editor — simple view](../artifacts/screenshots/s2-policy-editor-simple.png)

![Policy editor — advanced graph view](../artifacts/screenshots/s2-policy-graph-advanced.png)

The same graph is also editable as canonical JSON, which is what gets compiled
and signed — this is the policy-as-code surface that the Terraform/IaC provider
targets:

![Policy editor — canonical JSON](../artifacts/screenshots/s2-policy-json.png)

## The real graph behind the screenshots

This isn't a mock. Here is the shape of Acme's live policy graph, captured
verbatim from `GET /api/v1/tenants/{id}/policy`
([`s2-acme-policy-graph.json`](../artifacts/payloads/s2-acme-policy-graph.json)):

```json
{
  "id": "...",
  "tenant_id": "92112770-7c0a-410b-b0f4-09dde70e063a",
  "version": 1,
  "is_draft": false,
  "graph": { "...": "typed nodes + edges across fw/ips/swg/dns/ztna domains" }
}
```

The graph carries a monotonic `version` and an `is_draft` flag — drafts compile
and simulate but don't sign, so an operator can model a change before it touches
the canonical state. The compiler's verdict for a given flow is one of
`allow` / `inspect` / `deny`, and that verdict is exactly what the AI assistant
re-derives deterministically in Post 6.

## How it works under the hood

- **Author once, project many.** The graph has typed nodes per enforcement
  domain (`fw`, `ips`, `swg`, `dns`, `ztna`) plus SD-WAN steering classes. The
  compiler (`sng-policy-eval`) lowers the graph to a single decision pipeline so
  the *same* match logic backs every projection.
- **Compile → sign → distribute.** The control plane compiles the graph to a
  bundle, signs it with the tenant's rotating signing key, and ships it over
  NATS JetStream. The edge verifies the signature before loading — a tenant
  can't be served another tenant's bundle, and an unsigned bundle is refused.
- **Six-class SD-WAN steering.** Steering is part of the same graph, classifying
  flows into six service classes (see
  [`docs/TRAFFIC_CLASSIFICATION.md`](../../docs/TRAFFIC_CLASSIFICATION.md)) rather
  than living in a separate appliance.

## Performance: what we can and can't measure here

Policy **compile latency** is real and measured — it's pure Go and runs
unprivileged. Edge **throughput** is the number we are most careful about.

The `bench/` harness produces a per-SKU throughput matrix, but on this VM it runs
in `--dry-run` mode (crafts and measures frames in-process, no NIC I/O). The tell
is right there in the data: the headline throughput is ~96 Gbps *regardless of
whether the SKU has 2 vCPUs or 8*, and CPU utilisation reads 0.0%. That is a
dry-run artifact, not a wire result, and we present it as such. Real inspected
throughput needs `CAP_NET_RAW` and an in-path edge.

What *is* genuinely informative from the same run is the **per-packet latency
distribution**, because the craft→inspect→measure path exercises the real
inspection code. From the
[edge performance datasheet](../artifacts/edge-performance-datasheet.md)
(branch-large, full-TLS inspection):

| packet size | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| 64B | 80 ns | 151 ns | 170 ns |
| 512B | 110 ns | 190 ns | 191 ns |
| 1500B | 180 ns | 260 ns | 270 ns |
| 9000B | 732 ns | 812 ns | 822 ns |

Sub-microsecond per-packet inspection latency at p99 for sub-jumbo frames is the
honest, defensible performance story here — not the Gbps headline.

## Where we fall short

- **No real wire throughput on this rig.** Until SNG is benched in-path with
  `CAP_NET_RAW` on a real NIC, the Gbps column is methodology + dry-run only. We
  refuse to publish it as a head-to-head number.
- **One graph is a single blast radius.** The flip side of "author once" is that
  a bad compile is a bad compile everywhere. This is why drafts, simulation, and
  the verifier (Post 6) exist — but it's a real design tension worth naming.
- **The advanced graph view has a learning curve.** It's powerful for Lena; it's
  more than Devraj needs day-to-day, which is why the simple view is the default.

Next: the operations story — standing up a new tenant under an MSP, and the RLS
isolation that makes multi-tenancy safe.
