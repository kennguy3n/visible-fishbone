###############################################################################
# ShieldNet Gateway — eu-west-1 region root.
#
# Secondary DACH region-group landing zone. The cluster itself runs in
# AWS eu-west-1 (Dublin, Ireland) — hence the -dub suffix — and serves
# the Zurich PoP while acting as the EU failover for Frankfurt (see
# internal/region and internal/service/pop). The name reflects where the
# infrastructure physically lives, not the PoP it fronts, so operators
# reading EKS cluster names / cost-allocation tags are not misled into
# thinking it sits in Zurich. NATS and ClickHouse run on the provisioned
# EKS cluster, not as separate AWS services.
###############################################################################

module "sng" {
  source = "../../sng-infra"

  name     = "sng-dach-dub"
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
