# sng-infra Terraform module

Provisions the AWS substrate for a ShieldNet Gateway control-plane region:

- **VPC** with public/private subnets across `az_count` AZs, IGW, and NAT.
- **EKS** cluster + managed node group, with an IAM **OIDC provider** for IRSA.
- **RDS PostgreSQL** primary (Multi-AZ, encrypted) and optional read
  replicas wired to `PG_READ_REPLICA_HOSTS`.
- **ElastiCache** (Redis) replication group — optional.
- **S3** telemetry cold-archive bucket (KMS-encrypted, versioned, Glacier
  lifecycle) plus an **IRSA role** the `sng-control` service account assumes
  for archive access.

NATS and ClickHouse are **not** separate AWS services here — they run *on*
the EKS cluster via the `sng-control` Helm chart's subcharts / the Altinity
ClickHouse operator. This module provisions the cluster they land on.

## Usage

```hcl
module "sng" {
  source = "./deploy/terraform/sng-infra"

  name                  = "sng-prod"
  region                = "us-east-1"
  pg_read_replica_count = 2
  elasticache_enabled   = true
}
```

The `sng_control_env` output emits the non-secret environment values for the
control plane (`PG_HOST`, `PG_READ_REPLICA_HOSTS`, `S3_BUCKET`, …); the
generated DB password is the sensitive `rds_password` output (load it into the
Helm chart's Secret as `PG_PASSWORD`). Annotate the `sng-control` service
account with `sng_control_irsa_role_arn`.

## Validate (no apply)

```bash
terraform -chdir=deploy/terraform/sng-infra init -backend=false
terraform -chdir=deploy/terraform/sng-infra fmt -check -recursive
terraform -chdir=deploy/terraform/sng-infra validate
```

> This module has not been `terraform apply`-ed; it is validated with
> `fmt`/`validate` only. Review subnet sizing, instance classes, and
> deletion-protection settings before applying to a real account.
