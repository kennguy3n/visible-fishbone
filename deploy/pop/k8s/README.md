# Multi-PoP edge (Kustomize)

Kustomize base + per-PoP overlays to run the SNG edge across **>=2
regions**, each PoP fronted by a health-checked load balancer that the
[front-door](../frontdoor) steers to.

```
base/                 # edge Deployment + Service(LoadBalancer) + ConfigMap, probes on :9119
overlays/pop-sea/     # SEA  region-group (ap-southeast-1)
overlays/pop-dach/    # DACH region-group (eu-central-1)
```

This is the Kustomize/GitOps-native equivalent of the cloud-PoP form of
the Helm chart at [`deploy/helm/sng-edge`](../../helm/sng-edge) — use
whichever your platform standardises on. Each overlay sets the
region-group label, replica count (size to the PoP's capacity tier), the
anycast VIP / EIP the LB pins, and the per-PoP `edge.toml` identity.
Add a PoP by copying an overlay and changing those values.

Health: both probes hit the edge supervisor's health aggregator
(`--health-bind`, see [`crates/sng-edge`](../../../crates/sng-edge)) —
`/readyz` gates traffic, `/healthz` gates restarts — and the LB health
check targets `/readyz` so an unready PoP is pulled from rotation.

## Render & validate

```bash
# Render an overlay:
kustomize build overlays/pop-sea

# Validate the rendered manifests against the Kubernetes schemas:
kustomize build overlays/pop-sea  | kubeconform -strict -summary -ignore-missing-schemas
kustomize build overlays/pop-dach | kubeconform -strict -summary -ignore-missing-schemas
```

> Replace the placeholders before applying: `eipalloc-REPLACE_*`, the
> `sng/anycast-vip` TEST-NET-3 addresses, and the all-zero UUIDs in each
> overlay's `edge.toml`.
