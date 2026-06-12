# Reference multi-PoP deployment topology

Reference infrastructure for running the ShieldNet Gateway (SNG) edge as
a multi-PoP fleet across **two or more regions**, behind a health-gated
front-door.

> **What this is — and is not.** SNG is **software you deploy across your
> own Points of Presence**; it is **not** a global network you rent. This
> directory is the reference *infrastructure* for standing up your own
> PoP footprint — example IaC, manifests, and a runnable local simulation
> — not a hosted edge. Running it narrows, but does not erase, the
> scale/footprint gap versus vendor-run global networks (Zscaler /
> Cloudflare / Cato). See [`docs/pop-topology.md`](../../docs/pop-topology.md)
> for the full topology, tradeoffs, failover behaviour, and the explicit
> honest framing.

## Where this fits

SNG already ships the two lower layers of a PoP; this directory adds the
glue that makes a *set* of PoPs behave as one front-door:

| Layer | Lives in | Role |
|-------|----------|------|
| Regional infrastructure (EKS, RDS, networking) | [`deploy/terraform/regions`](../terraform/regions) | One Terraform root per region/PoP. |
| Edge workload | [`deploy/helm/sng-edge`](../helm/sng-edge) | The Rust edge appliance, per cluster. |
| **Multi-PoP composition + front-door** | **here** | Tie >=2 PoPs together and steer/failover between them. |

Region-groups (`SEA` / `GCC` / `DACH`) are defined once in
[`internal/region`](../../internal/region) and consumed by the PoP
manager in [`internal/service/pop`](../../internal/service/pop); the
assets here use the same taxonomy.

## Contents

| Path | What | Validate with |
|------|------|---------------|
| [`compose/`](compose) | Runnable local two-PoP failover simulation. | `docker compose ... config` |
| [`k8s/`](k8s) | Kustomize base + per-PoP overlays for the edge across >=2 regions, with health probes. | `kustomize build … \| kubeconform` |
| [`frontdoor/geodns/`](frontdoor/geodns) | Route53 GeoDNS front-door (zone + health checks + latency/weighted records). | `terraform validate` |
| [`frontdoor/anycast/`](frontdoor/anycast) | Anycast/BGP front-door (BIRD speaker + health-gated withdraw). | `bird -p` (after templating) |

Everything is **clearly templated** — region/ASN/prefix/VIP/UUID values
are placeholders. Start from [`docs/pop-topology.md`](../../docs/pop-topology.md).

## Validate everything

```bash
# 1) Local simulation composes:
docker compose -f compose/docker-compose.pop.yml config -q

# 2) Both PoP overlays render and pass schema validation:
for o in pop-sea pop-dach; do
  kustomize build k8s/overlays/$o | kubeconform -strict -summary -ignore-missing-schemas
done

# 3) GeoDNS front-door is valid Terraform:
terraform -chdir=frontdoor/geodns init -backend=false >/dev/null
terraform -chdir=frontdoor/geodns validate
terraform -chdir=frontdoor/geodns fmt -check
```
