###############################################################################
# Outputs.
###############################################################################

output "instance_id" {
  description = "EC2 instance id of the runner."
  value       = aws_instance.runner.id
}

output "private_ip" {
  description = "Private IP of the runner."
  value       = aws_instance.runner.private_ip
}

output "public_ip" {
  description = "Public IP of the runner (null unless associate_public_ip is true)."
  value       = aws_instance.runner.public_ip
}

output "security_group_id" {
  description = "Security group protecting the runner."
  value       = aws_security_group.runner.id
}

output "iam_role_arn" {
  description = "Instance role ARN (attach extra policies here if the job needs more)."
  value       = aws_iam_role.runner.arn
}

output "runner_labels" {
  description = "Full label set the runner registers with — target these from a job's runs-on."
  value       = concat(["self-hosted"], var.runner_labels)
}

output "bench_interface" {
  description = "veth endpoint the harness transmits on (pass as sng-bench --interface)."
  value       = var.bench_interface
}

output "edge_interface" {
  description = "veth endpoint sng-edge enforces on (the in-path peer)."
  value       = local.edge_interface
}
