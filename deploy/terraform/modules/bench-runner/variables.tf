###############################################################################
# Inputs for the sng-bench self-hosted wire-throughput runner.
#
# The module provisions ONE dedicated EC2 instance that registers itself as
# a GitHub Actions self-hosted runner, wires a veth pair, and runs `sng-edge`
# in-path so the `wire` benchmark job (.github/workflows/benchmark.yml) can
# push real AF_PACKET traffic through the edge under `CAP_NET_RAW`.
###############################################################################

variable "name" {
  description = "Name prefix for all resources (e.g. sng-bench)."
  type        = string
  default     = "sng-bench"
}

variable "tags" {
  description = "Extra tags merged onto every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------
variable "subnet_id" {
  description = "Subnet to launch the runner into. A private subnet with NAT egress is recommended; set associate_public_ip=true only for a public subnet."
  type        = string
}

variable "vpc_id" {
  description = "VPC the runner (and its security group) lives in. Must contain subnet_id."
  type        = string
}

variable "associate_public_ip" {
  description = "Assign a public IP. Leave false for a private subnet fronted by a NAT gateway (the secure default)."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Instance shape
# ---------------------------------------------------------------------------
variable "instance_type" {
  description = "EC2 instance type. Must be a 4-core x86_64 (amd64) shape so the wire numbers match the SKU sweep's per-core assumptions and the AF_PACKET TX path is not throttled by a burstable credit balance."
  type        = string
  default     = "c6i.xlarge" # 4 vCPU / 8 GiB, fixed-performance Intel x86_64.

  validation {
    # Guard against accidentally picking a burstable (t-family) or Arm
    # (g-suffixed) shape: both invalidate the published per-core wire
    # numbers. This is a heuristic, not exhaustive, prefix check.
    condition     = !startswith(var.instance_type, "t") && !can(regex("g\\.", var.instance_type))
    error_message = "instance_type must be a fixed-performance x86_64 shape (not a burstable t-family or Arm/Graviton g-suffixed type)."
  }
}

variable "ami_id" {
  description = "AMI to boot. Empty means the latest Canonical Ubuntu 24.04 LTS amd64 (resolved via SSM public parameter)."
  type        = string
  default     = ""
}

variable "root_volume_gb" {
  description = "Root EBS volume size (GiB). Holds the toolchain, a release build of the workspace, and the bench results corpus."
  type        = number
  default     = 60

  validation {
    condition     = var.root_volume_gb >= 30
    error_message = "root_volume_gb must be at least 30 GiB to fit the Rust toolchain plus a release build."
  }
}

variable "key_name" {
  description = "Optional EC2 key pair for SSH break-glass. Empty disables SSH key login; prefer SSM Session Manager (always enabled via the instance profile)."
  type        = string
  default     = ""
}

variable "ssh_ingress_cidrs" {
  description = "CIDRs allowed to reach TCP/22. Empty (the default) opens no inbound SSH — operators use SSM Session Manager instead."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------
# GitHub Actions runner registration
# ---------------------------------------------------------------------------
variable "github_url" {
  description = "Registration scope URL: an org URL (https://github.com/<org>) or a repo URL (https://github.com/<org>/<repo>). The runner registers against this scope."
  type        = string
}

variable "github_pat_ssm_parameter" {
  description = "Name of a SecureString SSM parameter holding a GitHub PAT (scope: repo or manage_runners). The instance reads it at boot to mint a short-lived registration token via the GitHub API, so no long-lived runner token is ever baked into user-data. Mutually exclusive with github_registration_token."
  type        = string
  default     = ""
}

variable "github_registration_token" {
  description = "A pre-minted GitHub Actions runner registration token. Short-lived (~1h) — only useful for a one-shot `terraform apply`. Prefer github_pat_ssm_parameter for anything reusable. Mutually exclusive with github_pat_ssm_parameter."
  type        = string
  default     = ""
  sensitive   = true
}

variable "runner_labels" {
  description = "Extra labels added to the runner alongside the built-in `self-hosted` label. The `wire` job targets `sng-bench-wire`, so keep that label present (or update the workflow's runs-on)."
  type        = list(string)
  default     = ["sng-bench-wire"]

  validation {
    condition     = length(var.runner_labels) > 0
    error_message = "Provide at least one runner label so the wire job's runs-on can target this runner."
  }
}

variable "runner_group" {
  description = "Optional GitHub Actions runner group to register into (org-scoped runners only). Empty uses the default group."
  type        = string
  default     = ""
}

variable "runner_version" {
  description = "GitHub Actions runner release to install (without the leading 'v')."
  type        = string
  default     = "2.319.1"
}

variable "ephemeral_runner" {
  description = "Register the runner as --ephemeral (deregisters after one job). Pair with an autoscaler/scheduled replacement; for an always-on bench rig leave false."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Source under test
# ---------------------------------------------------------------------------
variable "repo_url" {
  description = "Git URL the runner clones to build sng-edge + sng-bench in-path. Defaults to the public HTTPS remote of this repository."
  type        = string
  default     = "https://github.com/kennguy3n/visible-fishbone.git"
}

variable "repo_ref" {
  description = "Git ref (branch, tag, or SHA) to build sng-edge from for the in-path edge. The workflow checks out its own ref for the harness; this pins only the long-running edge service."
  type        = string
  default     = "main"
}

# ---------------------------------------------------------------------------
# Data path / veth wiring
# ---------------------------------------------------------------------------
variable "bench_interface" {
  description = "Name of the veth endpoint the harness transmits on (the `wire` job passes this as --interface). Its peer is <bench_interface>-edge, which sng-edge enforces on."
  type        = string
  default     = "veth-bench"

  validation {
    # Linux network-interface names are capped at 15 bytes; the peer adds
    # a 5-byte "-edge" suffix, so the base must stay <= 10 bytes.
    condition     = length(var.bench_interface) <= 10 && can(regex("^[a-zA-Z][a-zA-Z0-9_-]*$", var.bench_interface))
    error_message = "bench_interface must be <= 10 chars (so the '-edge' peer stays within the 15-byte IFNAMSIZ limit) and a valid interface name."
  }
}

variable "edge_datapath" {
  description = "sng-edge --datapath backend: auto | nftables | ebpf. `auto` probes for XDP and falls back to nftables; pin nftables on kernels without an XDP-capable veth driver."
  type        = string
  default     = "auto"

  validation {
    condition     = contains(["auto", "nftables", "ebpf", "xdp"], var.edge_datapath)
    error_message = "edge_datapath must be one of: auto, nftables, ebpf, xdp."
  }
}

variable "edge_ips_enabled" {
  description = "Enable the sng-edge IPS (Suricata) tier on the in-path edge. Requires the bootstrap to install suricata; disable for a pure firewall/NGFW wire rig."
  type        = bool
  default     = true
}

variable "results_bucket_arn" {
  description = "Optional S3 bucket ARN the runner may write benchmark artifacts to (read/write on <arn>/* ). Empty grants no S3 access."
  type        = string
  default     = ""
}
