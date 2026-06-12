# GeoDNS front-door (Route53)

Steer clients to the nearest healthy PoP with DNS. This is the
operationally simplest front-door — it needs only a hosted zone, no ASN
or BGP — at the cost of DNS-TTL-bound failover. It is the default for
fleets that do not run their own network.

This Terraform root matches the in-app GeoDNS model one-for-one
(`internal/service/pop` `ZoneGenerator` / `GeoDNSPublisher`):

- **one record set per enabled PoP**, A or AAAA by address family;
- **latency** routing (nearest region), **weighted** routing proportional
  to capacity tier (`small=1, medium=5, large=20`, the same `tierWeight`
  table as the publisher), or **simple** (flat multi-value answer) —
  the same three policies as the publisher's `RoutingPolicy`;
- each record gated by a **Route53 health check** on the edge `/readyz`
  endpoint, so an unhealthy PoP is pulled from rotation.

## Two modes

| `manage_records` | Who owns the steering records | Use when |
|------------------|-------------------------------|----------|
| `true` (default) | This Terraform root | Static fleet, no in-app publisher running. |
| `false` | The in-app `GeoDNSPublisher` (leader-gated singleton) | The control plane reconciles records from the live registry; Terraform only provisions the zone + health checks the records reference. |

## Validate (no apply, no backend)

```bash
terraform -chdir=deploy/pop/frontdoor/geodns init -backend=false
terraform -chdir=deploy/pop/frontdoor/geodns validate
terraform -chdir=deploy/pop/frontdoor/geodns fmt -check
```

> Not `terraform apply`-ed; validated with `init -backend=false` +
> `validate`/`fmt` only, like [`deploy/terraform/regions`](../../../terraform/regions).

## Example input

```hcl
# frontdoor.auto.tfvars  (do not commit — *.tfvars is gitignored)
zone_name      = "edge.example.com"
hostname       = "pop.edge.example.com"
routing_policy = "latency"

pops = [
  {
    id            = "11111111-1111-1111-1111-111111111111"
    region        = "SEA"
    anycast_ip    = "203.0.113.10"
    capacity_tier = "large"
    aws_region    = "ap-southeast-1"
  },
  {
    id            = "22222222-2222-2222-2222-222222222222"
    region        = "DACH"
    anycast_ip    = "203.0.113.20"
    capacity_tier = "medium"
    aws_region    = "eu-central-1"
  },
]
```
