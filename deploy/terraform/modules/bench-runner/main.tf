###############################################################################
# sng-bench wire-throughput runner — compute, networking, and identity.
#
# One EC2 instance that:
#   * registers as a GitHub Actions self-hosted runner (label sng-bench-wire),
#   * creates a veth pair (<bench_interface> <-> <bench_interface>-edge),
#   * runs sng-edge in-path on the -edge endpoint under CAP_NET_RAW/NET_ADMIN,
#   * grants the runner's jobs CAP_NET_RAW via file capabilities on the bench
#     binary (no root job execution),
# so the `wire` benchmark job can push real AF_PACKET frames through the edge.
###############################################################################

locals {
  tags = merge({
    "app.kubernetes.io/part-of" = "shieldnet-gateway"
    "sng/module"                = "bench-runner"
    "sng/name"                  = var.name
    "sng/role"                  = "bench-wire-runner"
  }, var.tags)

  edge_interface = "${var.bench_interface}-edge"

  # Exactly one registration mechanism must be supplied.
  use_pat = var.github_pat_ssm_parameter != ""

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    name                      = var.name
    github_url                = var.github_url
    github_pat_ssm_parameter  = var.github_pat_ssm_parameter
    github_registration_token = var.github_registration_token
    use_pat                   = local.use_pat
    runner_version            = var.runner_version
    runner_labels             = join(",", concat(["self-hosted"], var.runner_labels))
    runner_group              = var.runner_group
    ephemeral_runner          = var.ephemeral_runner
    aws_region                = data.aws_region.current.name
    repo_url                  = var.repo_url
    repo_ref                  = var.repo_ref
    bench_interface           = var.bench_interface
    edge_interface            = local.edge_interface
    edge_datapath             = var.edge_datapath
    edge_ips_enabled          = var.edge_ips_enabled
    edge_config               = local.edge_config
  })

  edge_config = templatefile("${path.module}/templates/edge.toml.tftpl", {
    edge_interface   = local.edge_interface
    edge_ips_enabled = var.edge_ips_enabled
  })
}

data "aws_region" "current" {}

# Latest Canonical Ubuntu 24.04 LTS amd64, via the AWS-published SSM
# parameter — no hardcoded, region-specific, drift-prone AMI id.
data "aws_ssm_parameter" "ubuntu" {
  count = var.ami_id == "" ? 1 : 0
  name  = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

locals {
  ami_id = var.ami_id != "" ? var.ami_id : nonsensitive(data.aws_ssm_parameter.ubuntu[0].value)
}

# ---------------------------------------------------------------------------
# Security group: no inbound by default (SSM handles shell access); SSH only
# when explicitly allow-listed. Egress open so the runner can reach the
# GitHub API/runner service, package mirrors, and crates.io.
# ---------------------------------------------------------------------------
resource "aws_security_group" "runner" {
  name_prefix = "${var.name}-runner-"
  description = "sng-bench self-hosted wire runner"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-runner" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.runner.id
  description       = "All egress (GitHub runner service, package/crate mirrors)."
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.ssh_ingress_cidrs)
  security_group_id = aws_security_group.runner.id
  description       = "Break-glass SSH"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------
resource "aws_instance" "runner" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.runner.id]
  iam_instance_profile        = aws_iam_instance_profile.runner.name
  associate_public_ip_address = var.associate_public_ip
  key_name                    = var.key_name != "" ? var.key_name : null
  user_data_base64            = base64encode(local.user_data)

  # Re-provision when the bootstrap (registration scope, edge config, refs)
  # changes, so a `terraform apply` rolls a freshly-wired runner.
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only.
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  tags        = merge(local.tags, { Name = "${var.name}-runner" })
  volume_tags = merge(local.tags, { Name = "${var.name}-runner-root" })

  lifecycle {
    precondition {
      condition     = local.use_pat != (var.github_registration_token != "")
      error_message = "Provide exactly one of github_pat_ssm_parameter or github_registration_token."
    }
  }
}
