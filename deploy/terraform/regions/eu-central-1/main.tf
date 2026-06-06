###############################################################################
# ShieldNet Gateway — eu-central-1 (Frankfurt) region root.
#
# SME cloud-PoP region for the DACH region-group (Frankfurt / Zurich — see
# internal/region and internal/service/pop). Frankfurt is the primary DACH
# data-residency landing zone. NATS and ClickHouse run on the provisioned
# EKS cluster, not as separate AWS services.
###############################################################################

module "sng" {
  source = "../../sng-infra"

  name     = "sng-dach-fra"
  region   = "eu-central-1"
  vpc_cidr = "10.63.0.0/16"
  az_count = 3

  elasticache_enabled   = true
  pg_read_replica_count = 1
  pg_multi_az           = true

  tags = {
    "sng/region-group" = "DACH"
    "sng/region-role"  = "cloud-pop"
  }
}
