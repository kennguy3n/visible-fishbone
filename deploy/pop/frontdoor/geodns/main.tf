###############################################################################
# ShieldNet Gateway — GeoDNS front-door (Route53).
#
# Provisions the steering zone and a per-PoP health check, and OPTIONALLY
# the latency/weighted steering records. This is the DNS front-door option
# from docs/pop-topology.md.
#
# In a fleet running the in-app GeoDNS publisher (internal/service/pop
# GeoDNSPublisher, a leader-gated singleton) the records are reconciled
# from the live registry — set manage_records=false so this root only
# creates the zone + health checks the publisher's records reference. For
# a static fleet with no publisher, leave manage_records=true and this
# root owns the records directly. Either way the model matches
# ZoneGenerator.Records(): one set per enabled PoP, A or AAAA by address
# family, weighted by capacity tier.
###############################################################################

locals {
  # Mirrors internal/service/pop.tierWeight so weighted DNS spread matches
  # the in-app publisher exactly.
  tier_weight = {
    small  = 1
    medium = 5
    large  = 20
  }

  pops_by_id = { for p in var.pops : p.id => p }

  zone_id = var.create_zone ? aws_route53_zone.this[0].zone_id : data.aws_route53_zone.this[0].zone_id
}

resource "aws_route53_zone" "this" {
  count = var.create_zone ? 1 : 0
  name  = var.zone_name

  tags = {
    "sng/component" = "frontdoor-geodns"
  }
}

data "aws_route53_zone" "this" {
  count = var.create_zone ? 0 : 1
  name  = var.zone_name
}

# One Route53 health check per PoP, hitting the edge readiness endpoint
# (/readyz on the health port, fronted by the PoP load balancer on 443).
# Route53 stops returning a PoP's record when its health check fails, so
# DNS steering and the edge's own readiness signal stay consistent.
resource "aws_route53_health_check" "pop" {
  for_each = local.pops_by_id

  type              = "HTTPS"
  ip_address        = each.value.anycast_ip
  port              = 443
  resource_path     = "/readyz"
  failure_threshold = 3
  request_interval  = 10

  tags = {
    "sng/component"    = "frontdoor-geodns"
    "sng/pop-id"       = each.value.id
    "sng/region-group" = each.value.region
  }
}

# Per-PoP steering records. Latency policy answers each resolver with the
# nearest region; weighted policy spreads proportional to capacity tier.
resource "aws_route53_record" "pop" {
  for_each = var.manage_records ? local.pops_by_id : {}

  zone_id         = local.zone_id
  name            = var.hostname
  type            = length(regexall(":", each.value.anycast_ip)) > 0 ? "AAAA" : "A"
  ttl             = var.ttl
  records         = [each.value.anycast_ip]
  set_identifier  = each.value.id
  health_check_id = aws_route53_health_check.pop[each.key].id

  dynamic "latency_routing_policy" {
    for_each = var.routing_policy == "latency" ? [each.value.aws_region] : []
    content {
      region = latency_routing_policy.value
    }
  }

  dynamic "weighted_routing_policy" {
    for_each = var.routing_policy == "weighted" ? [each.value.capacity_tier] : []
    content {
      weight = local.tier_weight[weighted_routing_policy.value]
    }
  }

  # "simple" — flat multi-value answer (every healthy PoP), the Route53
  # equivalent of internal/service/pop RoutingSimple. multivalue-answer
  # records still carry a set_identifier and honour the per-PoP health
  # check, so unhealthy PoPs are dropped from the answer.
  multivalue_answer_routing_policy = var.routing_policy == "simple" ? true : null
}
