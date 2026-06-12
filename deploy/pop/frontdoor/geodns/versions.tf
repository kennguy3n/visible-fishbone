terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }

  # Front-door state should live alongside the rest of the SNG state
  # (one key per stack). Configure at init; validation runs with
  # `-backend=false`, which ignores this block.
  #   terraform init -backend-config=bucket=<state-bucket> \
  #     -backend-config=key=sng/frontdoor-geodns.tfstate \
  #     -backend-config=region=<state-region> \
  #     -backend-config=dynamodb_table=<lock-table>
  backend "s3" {}
}

provider "aws" {
  # GeoDNS / Route53 is a global service; us-east-1 is the conventional
  # control region for it. Health checkers run from AWS's global edge
  # regardless of this setting.
  region = var.aws_region
}
