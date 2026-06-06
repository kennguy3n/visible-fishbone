###############################################################################
# ShieldNet Gateway — ap-southeast-1 (Singapore) region root.
#
# SME cloud-PoP region for the SEA region-group (Singapore / Jakarta /
# Bangkok / Kuala Lumpur — see internal/region and internal/service/pop).
# This root composes the reusable ../../sng-infra module with the
# region-specific networking and capacity envelope; NATS and ClickHouse
# run on the provisioned EKS cluster (Helm subcharts / Altinity operator),
# not as separate AWS services.
###############################################################################

module "sng" {
  source = "../../sng-infra"

  name     = "sng-sea"
  region   = "ap-southeast-1"
  vpc_cidr = "10.61.0.0/16"
  az_count = 3

  # Cloud-PoP region: Redis backs PoP session stickiness, and a read
  # replica offloads the control-plane read path (docs/scaling.md).
  elasticache_enabled   = true
  pg_read_replica_count = 1
  pg_multi_az           = true

  tags = {
    "sng/region-group" = "SEA"
    "sng/region-role"  = "cloud-pop"
  }
}
