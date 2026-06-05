###############################################################################
# Locals, data sources, and shared randomness.
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "random_password" "pg" {
  length  = 32
  special = false
}

locals {
  tags = merge({
    "app.kubernetes.io/part-of" = "shieldnet-gateway"
    "sng/module"                = "sng-infra"
    "sng/name"                  = var.name
  }, var.tags)

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Deterministic /20 carve-up of the VPC CIDR: public subnets first, then
  # private. Supports up to 4 AZs without collision inside a /16.
  public_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  s3_bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${var.name}-telemetry-archive-${random_id.suffix.hex}"

  cluster_name = "${var.name}-eks"
}
