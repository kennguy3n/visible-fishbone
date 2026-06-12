output "zone_id" {
  description = "Route53 hosted-zone ID for the steering zone."
  value       = local.zone_id
}

output "hostname" {
  description = "Steering FQDN clients resolve."
  value       = var.hostname
}

output "health_check_ids" {
  description = "Per-PoP Route53 health-check IDs, keyed by PoP id."
  value       = { for k, hc in aws_route53_health_check.pop : k => hc.id }
}

output "steered_records" {
  description = "Per-PoP steering record FQDN+type, keyed by PoP id (empty when manage_records=false)."
  value       = { for k, r in aws_route53_record.pop : k => "${r.name} ${r.type}" }
}
