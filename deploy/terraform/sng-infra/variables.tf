variable "name" {
  description = "Name prefix for all resources (e.g. sng-prod)."
  type        = string
  default     = "sng"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Extra tags merged onto every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.60.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones (and public/private subnet pairs) to spread across."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4 for a multi-AZ control-plane footprint."
  }
}

variable "single_nat_gateway" {
  description = "Use a single shared NAT gateway instead of one per AZ (cheaper, less resilient)."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# EKS
# ---------------------------------------------------------------------------
variable "kubernetes_version" {
  description = "EKS control-plane Kubernetes version."
  type        = string
  default     = "1.30"
}

variable "node_instance_types" {
  description = "Instance types for the default managed node group."
  type        = list(string)
  default     = ["m6i.xlarge"]
}

variable "node_desired_size" {
  description = "Desired worker node count."
  type        = number
  default     = 3
}

variable "node_min_size" {
  description = "Minimum worker node count."
  type        = number
  default     = 3
}

variable "node_max_size" {
  description = "Maximum worker node count."
  type        = number
  default     = 10
}

# ---------------------------------------------------------------------------
# RDS PostgreSQL
# ---------------------------------------------------------------------------
variable "pg_engine_version" {
  description = "RDS PostgreSQL engine version."
  type        = string
  default     = "16.4"
}

variable "pg_instance_class" {
  description = "RDS instance class for the primary."
  type        = string
  default     = "db.r6g.xlarge"
}

variable "pg_allocated_storage" {
  description = "Allocated storage (GiB) for the RDS primary."
  type        = number
  default     = 200
}

variable "pg_max_allocated_storage" {
  description = "Storage autoscaling ceiling (GiB)."
  type        = number
  default     = 1000
}

variable "pg_database_name" {
  description = "Initial database name."
  type        = string
  default     = "sng"
}

variable "pg_username" {
  description = "Master username for RDS PostgreSQL."
  type        = string
  default     = "sng"
}

variable "pg_read_replica_count" {
  description = "Number of RDS read replicas (feeds PG_READ_REPLICA_HOSTS). 0 disables."
  type        = number
  default     = 0

  validation {
    condition     = var.pg_read_replica_count >= 0 && var.pg_read_replica_count <= 5
    error_message = "pg_read_replica_count must be between 0 and 5."
  }
}

variable "pg_multi_az" {
  description = "Run the RDS primary as Multi-AZ."
  type        = bool
  default     = true
}

variable "pg_backup_retention_days" {
  description = "Automated backup retention window in days."
  type        = number
  default     = 14
}

variable "pg_deletion_protection" {
  description = "Enable deletion protection on the RDS primary."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# ElastiCache (optional)
# ---------------------------------------------------------------------------
variable "elasticache_enabled" {
  description = "Provision an ElastiCache (Redis) replication group."
  type        = bool
  default     = false
}

variable "elasticache_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.r6g.large"
}

variable "elasticache_num_nodes" {
  description = "Number of cache nodes (>=2 enables automatic failover)."
  type        = number
  default     = 2
}

# ---------------------------------------------------------------------------
# S3 telemetry cold archive
# ---------------------------------------------------------------------------
variable "s3_bucket_name" {
  description = "S3 bucket name for the telemetry cold archive. Empty derives <name>-telemetry-archive-<suffix>."
  type        = string
  default     = ""
}

variable "s3_glacier_transition_days" {
  description = "Days after which archived objects transition to Glacier (see docs/cost-model.md)."
  type        = number
  default     = 90
}

variable "s3_expiration_days" {
  description = "Days after which archived objects expire. 0 disables expiration."
  type        = number
  default     = 0
}

# ---------------------------------------------------------------------------
# IRSA: the Kubernetes service account sng-control runs under, granted S3
# access for the cold archive (see deploy/helm/sng-control serviceAccount).
# ---------------------------------------------------------------------------
variable "sng_control_namespace" {
  description = "Namespace sng-control is deployed into."
  type        = string
  default     = "sng"
}

variable "sng_control_service_account" {
  description = "Service-account name sng-control runs under (must match the Helm release)."
  type        = string
  default     = "sng-control"
}
