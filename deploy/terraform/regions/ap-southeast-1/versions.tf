terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Production state lives in S3 (one key per region). Configure at init:
  #   terraform init -backend-config=bucket=<state-bucket> \
  #     -backend-config=key=sng/ap-southeast-1.tfstate \
  #     -backend-config=region=<state-region> -backend-config=dynamodb_table=<lock-table>
  # Validation runs with `-backend=false`, which ignores this block.
  backend "s3" {}
}
