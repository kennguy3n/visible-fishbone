# bench-runner

Terraform for the **self-hosted GitHub Actions runner** that produces SNG's
*real wire* throughput numbers. A stock GitHub-hosted runner cannot transmit
AF_PACKET frames or hold `CAP_NET_RAW`, so the `wire` job in
[`.github/workflows/benchmark.yml`](../../../../.github/workflows/benchmark.yml)
targets a runner this module provisions.

The module stands up one EC2 instance that, on first boot:

1. installs the build toolchain (Rust pinned to the bench workspace's
   `rust-version`), `iproute2`, and (optionally) Suricata for the edge IPS tier;
2. builds `sng-edge` from a pinned ref and installs it to `/usr/local/bin`;
3. creates a **veth pair** (`veth-bench` ↔ `veth-bench-edge`) via a oneshot
   systemd unit, and runs **`sng-edge` in-path** on the `-edge` endpoint under
   `CAP_NET_RAW`/`CAP_NET_ADMIN`;
4. registers as a GitHub Actions **self-hosted runner** (labels
   `self-hosted,sng-bench-wire`) installed as a systemd service;
5. grants that runner service **ambient `CAP_NET_RAW`/`CAP_NET_ADMIN`** so a
   freshly built `sng-bench` binary opens AF_PACKET without root or `setcap`.

The `wire` job then runs the harness with `BENCH_DRY_RUN=` (empty) and
`--interface veth-bench`, sweeping all four SKU profiles across all four
inspection (forwarding) modes.

## Design notes

- **No long-lived runner secret in user-data.** The preferred path stores a
  GitHub PAT in an SSM `SecureString` (`github_pat_ssm_parameter`); the
  instance reads it at boot via a least-privilege IAM policy and exchanges it
  for a short-lived *registration token* through the GitHub API. A pre-minted
  `github_registration_token` is supported for one-shot applies but expires in
  ~1h. Exactly one of the two must be set (enforced by a `precondition`).
- **Least-privilege IAM.** The instance role attaches only
  `AmazonSSMManagedInstanceCore` (keyless Session Manager — no inbound SSH
  needed) plus, when used, `ssm:GetParameter` scoped to the single PAT
  parameter and an optional results-bucket grant.
- **Locked-down network.** No inbound rules by default; SSH (22) opens only for
  CIDRs in `ssh_ingress_cidrs`. IMDSv2 is required; the root volume is
  encrypted.
- **Fixed-performance x86_64 only.** A `validation` block rejects burstable
  (`t*`) and Arm (`*g.*`) shapes so the per-core wire numbers stay comparable.
- **Reproducible.** `user_data_replace_on_change` re-provisions a clean runner
  whenever the bootstrap inputs (refs, registration scope, edge config) change.

## Usage

```hcl
# Store a GitHub PAT (scope: repo or manage_runners) once:
#   aws ssm put-parameter --name /sng/bench/github-pat --type SecureString \
#     --value ghp_xxx

module "bench_runner" {
  source = "../../modules/bench-runner"

  name      = "sng-bench"
  vpc_id    = var.vpc_id
  subnet_id = var.private_subnet_id

  github_url               = "https://github.com/kennguy3n/visible-fishbone"
  github_pat_ssm_parameter = "/sng/bench/github-pat"

  # Optional: persist artifacts.
  results_bucket_arn = "arn:aws:s3:::sng-bench-results"

  tags = { "sng/env" = "bench" }
}
```

Then trigger the benchmark workflow (`workflow_dispatch`, `dry_run = false`) or
wait for the weekly schedule; the `wire` job lands on the new runner.

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `name` | Resource name prefix. | `string` | `"sng-bench"` |
| `vpc_id` | VPC the runner lives in. | `string` | n/a |
| `subnet_id` | Subnet to launch into (private + NAT recommended). | `string` | n/a |
| `associate_public_ip` | Assign a public IP. | `bool` | `false` |
| `instance_type` | 4-core x86_64 shape (validated). | `string` | `"c6i.xlarge"` |
| `ami_id` | AMI override; empty = latest Ubuntu 24.04 amd64 via SSM. | `string` | `""` |
| `root_volume_gb` | Root EBS size (GiB, ≥30). | `number` | `60` |
| `key_name` | Optional SSH key pair. | `string` | `""` |
| `ssh_ingress_cidrs` | CIDRs allowed to reach TCP/22. | `list(string)` | `[]` |
| `github_url` | Org or repo URL the runner registers against. | `string` | n/a |
| `github_pat_ssm_parameter` | SSM SecureString name holding a PAT (preferred). | `string` | `""` |
| `github_registration_token` | Pre-minted registration token (one-shot). | `string` | `""` |
| `runner_labels` | Extra runner labels (keep `sng-bench-wire`). | `list(string)` | `["sng-bench-wire"]` |
| `runner_group` | Optional runner group (org runners). | `string` | `""` |
| `runner_version` | Actions runner release. | `string` | `"2.319.1"` |
| `ephemeral_runner` | Register as `--ephemeral`. | `bool` | `false` |
| `repo_url` | Git URL to build `sng-edge` from. | `string` | repo HTTPS remote |
| `repo_ref` | Git ref for the in-path edge build. | `string` | `"main"` |
| `bench_interface` | veth endpoint the harness transmits on (≤10 chars). | `string` | `"veth-bench"` |
| `edge_datapath` | `sng-edge --datapath` backend. | `string` | `"auto"` |
| `edge_ips_enabled` | Enable the Suricata IPS tier. | `bool` | `true` |
| `results_bucket_arn` | Optional S3 bucket for artifacts. | `string` | `""` |

## Outputs

| Name | Description |
|------|-------------|
| `instance_id` | Runner EC2 instance id. |
| `private_ip` / `public_ip` | Runner addresses (`public_ip` null unless `associate_public_ip`). |
| `security_group_id` | Runner security group. |
| `iam_role_arn` | Instance role ARN. |
| `runner_labels` | Full label set the runner registers with. |
| `bench_interface` / `edge_interface` | The veth endpoints. |

## Operating the runner

- **Shell in:** `aws ssm start-session --target <instance_id>` (no SSH key
  required).
- **Bootstrap log:** `/var/log/sng-bench-bootstrap.log`.
- **Edge health:** `systemctl status sng-edge`, `journalctl -u sng-edge`.
- **veth state:** `ip link show veth-bench` / `veth-bench-edge`.
- **Runner service:** `systemctl status 'actions.runner.*'`.

## Prerequisites

- A VPC + subnet with outbound internet (NAT for a private subnet) so the
  runner can reach the GitHub runner service, package mirrors, and crates.io.
- A GitHub PAT with permission to register runners for the target scope, stored
  in SSM (preferred) — or a freshly minted registration token.
- An AWS provider configured by the calling root module (this is a child
  module and declares no `provider` block).
