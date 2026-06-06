# Per-region roots

Each subdirectory is a standalone Terraform root for one ShieldNet Gateway
cloud-PoP region. They compose the reusable [`../sng-infra`](../sng-infra)
module with region-specific networking (a non-overlapping `/16` per region),
capacity, and region-group tags. NATS and ClickHouse run *on* the EKS cluster
each root provisions (Helm subcharts / Altinity operator), not as separate AWS
services.

| Root             | AWS region       | Region-group | VPC CIDR        |
|------------------|------------------|--------------|-----------------|
| `ap-southeast-1` | ap-southeast-1   | SEA          | `10.61.0.0/16`  |
| `me-south-1`     | me-south-1       | GCC          | `10.62.0.0/16`  |
| `eu-central-1`   | eu-central-1     | DACH         | `10.63.0.0/16`  |
| `eu-west-1`      | eu-west-1        | DACH         | `10.64.0.0/16`  |

The region-group taxonomy is the single source of truth in
[`internal/region`](../../../internal/region); PoP selection consumes it in
[`internal/service/pop`](../../../internal/service/pop).

## State

Each root keeps its own state under a distinct S3 key (`sng/<region>.tfstate`),
so regions are blast-radius isolated and can be applied independently.

```bash
terraform -chdir=deploy/terraform/regions/ap-southeast-1 init \
  -backend-config=bucket=<state-bucket> \
  -backend-config=key=sng/ap-southeast-1.tfstate \
  -backend-config=region=<state-region> \
  -backend-config=dynamodb_table=<lock-table>
```

## Validate (no apply, no backend)

```bash
for r in ap-southeast-1 me-south-1 eu-central-1 eu-west-1; do
  terraform -chdir=deploy/terraform/regions/$r init -backend=false
  terraform -chdir=deploy/terraform/regions/$r validate
done
terraform -chdir=deploy/terraform fmt -check -recursive
```

> These roots have **not** been `terraform apply`-ed; they are validated with
> `fmt`/`validate` only. Review instance classes and AZ availability for each
> target region before applying (e.g. confirm Graviton/`m6i` availability and
> AZ count in `me-south-1`).
