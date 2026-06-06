###############################################################################
# ShieldNet Gateway — eu-west-1 region root.
#
# Secondary DACH region-group landing zone (serves the Zurich PoP and acts
# as the EU failover for Frankfurt — see internal/region and
# internal/service/pop). NATS and ClickHouse run on the provisioned EKS
# cluster, not as separate AWS services.
###############################################################################

module "sng" {
  source = "../../sng-infra"

  name     = "sng-dach-zrh"
  region   = "eu-west-1"
  vpc_cidr = "10.64.0.0/16"
  az_count = 3

  elasticache_enabled   = true
  pg_read_replica_count = 1
  pg_multi_az           = true

  tags = {
    "sng/region-group" = "DACH"
    "sng/region-role"  = "cloud-pop"
  }
}
