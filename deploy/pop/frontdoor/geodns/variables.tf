variable "aws_region" {
  description = "Control region for the AWS provider (Route53 is global)."
  type        = string
  default     = "us-east-1"
}

variable "zone_name" {
  description = "Parent hosted-zone domain, e.g. \"edge.example.com\"."
  type        = string
}

variable "create_zone" {
  description = <<-EOT
    Create the Route53 hosted zone. Set false to reuse an existing zone
    (looked up by zone_name) and only manage the steering records.
  EOT
  type        = bool
  default     = true
}

variable "hostname" {
  description = <<-EOT
    Fully-qualified steering hostname clients resolve, e.g.
    "pop.edge.example.com". Must be within zone_name. This is the same
    hostname the in-app GeoDNS publisher reconciles
    (internal/service/pop ZoneGenerator.cfg.Hostname).
  EOT
  type        = string
}

variable "ttl" {
  description = "TTL (seconds) for the steering records. Keep low so failover propagates quickly."
  type        = number
  default     = 30
}

variable "routing_policy" {
  description = <<-EOT
    DNS steering strategy, mirroring internal/service/pop RoutingPolicy:
      "latency"  — one record set per PoP; resolvers get the lowest-latency
                   region (Route53 latency records). Default "nearest PoP".
      "weighted" — weighted record sets proportional to capacity tier
                   (small=1, medium=5, large=20).
  EOT
  type        = string
  default     = "latency"

  validation {
    condition     = contains(["latency", "weighted"], var.routing_policy)
    error_message = "routing_policy must be \"latency\" or \"weighted\"."
  }
}

variable "manage_records" {
  description = <<-EOT
    Manage the per-PoP steering A/AAAA records here in Terraform. Set
    false when the in-app GeoDNS publisher owns the records
    (internal/service/pop GeoDNSPublisher) and Terraform should only
    provision the hosted zone and the Route53 health checks the records
    reference. Defaults true for a static fleet with no publisher.
  EOT
  type        = bool
  default     = true
}

variable "pops" {
  description = <<-EOT
    The PoP fleet to steer across (>=2 for a multi-PoP front-door).
    Mirrors internal/service/pop.PoP: each PoP has a stable id, a region
    string, an anycast/VIP address, a capacity tier (small|medium|large),
    and the AWS region used as the latency-record location.
  EOT
  type = list(object({
    id            = string # stable set identifier (e.g. the PoP UUID)
    region        = string # region-group, e.g. "SEA" / "GCC" / "DACH"
    anycast_ip    = string # IPv4 or IPv6 VIP clients connect to
    capacity_tier = string # small | medium | large
    aws_region    = string # AWS region for the latency record location
  }))

  validation {
    condition     = length(var.pops) >= 2
    error_message = "A multi-PoP front-door needs at least 2 PoPs."
  }

  validation {
    condition = alltrue([
      for p in var.pops : contains(["small", "medium", "large"], p.capacity_tier)
    ])
    error_message = "each pop.capacity_tier must be small|medium|large."
  }
}
