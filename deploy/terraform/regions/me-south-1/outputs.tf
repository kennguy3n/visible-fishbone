###############################################################################
# Pass-through of the sng-infra module outputs sng-control needs in its
# environment (see deploy/terraform/sng-infra/outputs.tf).
###############################################################################

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = module.sng.eks_cluster_name
}

output "rds_primary_address" {
  description = "RDS primary hostname (PG_HOST)."
  value       = module.sng.rds_primary_address
}

output "s3_archive_bucket" {
  description = "Telemetry cold-archive S3 bucket name (S3_BUCKET)."
  value       = module.sng.s3_archive_bucket
}

output "sng_control_env" {
  description = "Non-secret sng-control environment values derived from this region."
  value       = module.sng.sng_control_env
}

output "rds_password" {
  description = "Generated RDS master password (store as PG_PASSWORD)."
  value       = module.sng.rds_password
  sensitive   = true
}
