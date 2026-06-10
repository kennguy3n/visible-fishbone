###############################################################################
# Instance role — least privilege.
#
# Grants only: SSM core (keyless shell + the Ubuntu AMI parameter), optional
# read of the single GitHub PAT parameter, and optional write to a results
# bucket. No wildcard service access.
###############################################################################

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "runner" {
  name_prefix        = "${var.name}-runner-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

# SSM Session Manager for keyless break-glass access (no inbound SSH needed).
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.runner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_caller_identity" "current" {}

locals {
  # SSM parameter names may or may not carry a leading slash; the ARN always
  # has exactly one between "parameter" and the name.
  pat_parameter_arn = local.use_pat ? format(
    "arn:aws:ssm:%s:%s:parameter/%s",
    data.aws_region.current.name,
    data.aws_caller_identity.current.account_id,
    trimprefix(var.github_pat_ssm_parameter, "/"),
  ) : ""
}

data "aws_iam_policy_document" "runner" {
  # Read the GitHub PAT SecureString (and decrypt it) to mint a short-lived
  # runner registration token at boot — only when that mechanism is used.
  dynamic "statement" {
    for_each = local.use_pat ? [1] : []
    content {
      sid       = "ReadGithubPat"
      actions   = ["ssm:GetParameter"]
      resources = [local.pat_parameter_arn]
    }
  }

  dynamic "statement" {
    for_each = local.use_pat ? [1] : []
    content {
      sid       = "DecryptGithubPat"
      actions   = ["kms:Decrypt"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["ssm.${data.aws_region.current.name}.amazonaws.com"]
      }
    }
  }

  # Optional results-bucket write.
  dynamic "statement" {
    for_each = var.results_bucket_arn != "" ? [1] : []
    content {
      sid       = "WriteResults"
      actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
      resources = [var.results_bucket_arn, "${var.results_bucket_arn}/*"]
    }
  }
}

resource "aws_iam_role_policy" "runner" {
  # Skip an empty inline policy when neither optional grant applies.
  count  = (local.use_pat || var.results_bucket_arn != "") ? 1 : 0
  name   = "${var.name}-runner"
  role   = aws_iam_role.runner.id
  policy = data.aws_iam_policy_document.runner.json
}

resource "aws_iam_instance_profile" "runner" {
  name_prefix = "${var.name}-runner-"
  role        = aws_iam_role.runner.name
  tags        = local.tags
}
