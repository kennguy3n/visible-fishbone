###############################################################################
# ShieldNet Gateway — me-south-1 (Bahrain) region root.
#
# SME cloud-PoP region for the GCC region-group (Dubai / Riyadh — see
# internal/region and internal/service/pop). Bahrain is the AWS landing
# zone closest to the GCC PoP cities. NATS and ClickHouse run on the
# provisioned EKS cluster, not as separate AWS services.
###############################################################################

module "sng" {
  source = "../../sng-infra"

  name     = "sng-gcc"
  region   = "me-south-1"
  vpc_cidr = "10.62.0.0/16"
  az_count = 3

  elasticache_enabled   = true
  pg_read_replica_count = 1
  pg_multi_az           = true

  tags = {
    "sng/region-group" = "GCC"
    "sng/region-role"  = "cloud-pop"
  }
}
