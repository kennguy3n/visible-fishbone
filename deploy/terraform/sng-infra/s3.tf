###############################################################################
# S3 telemetry cold archive + IRSA role granting sng-control access to it.
###############################################################################

resource "aws_s3_bucket" "archive" {
  bucket = local.s3_bucket_name

  tags = {
    Name = "${var.name}-telemetry-archive"
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket = aws_s3_bucket.archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "cold-archive"
    status = "Enabled"

    filter {}

    transition {
      days          = var.s3_glacier_transition_days
      storage_class = "GLACIER"
    }

    dynamic "expiration" {
      for_each = var.s3_expiration_days > 0 ? [1] : []
      content {
        days = var.s3_expiration_days
      }
    }
  }
}

# ---------------------------------------------------------------------------
# IRSA: bind the sng-control Kubernetes service account to an IAM role that
# can read/write the archive bucket.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "control_irsa_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.sng_control_namespace}:${var.sng_control_service_account}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "control_irsa" {
  name               = "${var.name}-control-irsa"
  assume_role_policy = data.aws_iam_policy_document.control_irsa_assume.json
}

data "aws_iam_policy_document" "control_s3" {
  statement {
    sid       = "ListArchiveBucket"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.archive.arn]
  }

  statement {
    sid = "ReadWriteArchiveObjects"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.archive.arn}/*"]
  }
}

resource "aws_iam_role_policy" "control_s3" {
  name   = "${var.name}-control-s3"
  role   = aws_iam_role.control_irsa.id
  policy = data.aws_iam_policy_document.control_s3.json
}
