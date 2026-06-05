###############################################################################
# Outputs — including the values sng-control needs in its environment
# (see internal/config/config.go and deploy/helm/sng-control/values.yaml).
###############################################################################

output "vpc_id" {
  description = "VPC id."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "Private subnet ids (workloads, RDS, cache)."
  value       = aws_subnet.private[*].id
}

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.this.name
}

output "eks_cluster_endpoint" {
  description = "EKS API server endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "eks_oidc_provider_arn" {
  description = "IAM OIDC provider ARN backing IRSA."
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "rds_primary_address" {
  description = "RDS primary hostname (PG_HOST)."
  value       = aws_db_instance.primary.address
}

output "rds_replica_addresses" {
  description = "RDS read-replica hostnames (PG_READ_REPLICA_HOSTS)."
  value       = aws_db_instance.replica[*].address
}

output "elasticache_primary_endpoint" {
  description = "ElastiCache primary endpoint (null when disabled)."
  value       = var.elasticache_enabled ? aws_elasticache_replication_group.this[0].primary_endpoint_address : null
}

output "s3_archive_bucket" {
  description = "Telemetry cold-archive S3 bucket name (S3_BUCKET)."
  value       = aws_s3_bucket.archive.bucket
}

output "sng_control_irsa_role_arn" {
  description = "IAM role ARN to annotate the sng-control service account with (eks.amazonaws.com/role-arn)."
  value       = aws_iam_role.control_irsa.arn
}

output "rds_password" {
  description = "Generated RDS master password (store in the sng-control Secret as PG_PASSWORD)."
  value       = random_password.pg.result
  sensitive   = true
}

# Convenience: the non-secret subset of sng-control's environment, ready to
# drop into the Helm chart's config.* values. PG_PASSWORD is emitted
# separately via the sensitive rds_password output.
output "sng_control_env" {
  description = "Non-secret sng-control environment values derived from this infra."
  value = {
    PG_HOST               = aws_db_instance.primary.address
    PG_PORT               = "5432"
    PG_DATABASE           = var.pg_database_name
    PG_USER               = var.pg_username
    PG_READ_REPLICA_HOSTS = join(",", aws_db_instance.replica[*].address)
    PG_SSLMODE            = "require"
    S3_BUCKET             = aws_s3_bucket.archive.bucket
    S3_REGION             = var.region
    AWS_REGION            = var.region
  }
}
