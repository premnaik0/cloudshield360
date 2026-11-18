data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  buckets = {
    website    = "${var.project_name}-${local.account_id}-website"
    data       = "${var.project_name}-${local.account_id}-data"
    logs       = "${var.project_name}-${local.account_id}-logs"
    quarantine = "${var.project_name}-${local.account_id}-quarantine"
  }

  versioned_buckets = { for k, v in local.buckets : k => v if k != "logs" }
}

resource "aws_s3_bucket" "this" {
  for_each      = local.buckets
  bucket        = each.value
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = aws_s3_bucket.this
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Encryption at rest with S3-managed keys (SSE-S3), no KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# AWS Backup for S3 requires versioning on the source buckets
resource "aws_s3_bucket_versioning" "this" {
  for_each = local.versioned_buckets
  bucket   = aws_s3_bucket.this[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

# New objects in the data bucket are sent to EventBridge, which starts the scanner
resource "aws_s3_bucket_notification" "data" {
  bucket      = aws_s3_bucket.this["data"].id
  eventbridge = true
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket     = aws_s3_bucket.this["data"].id
  depends_on = [aws_s3_bucket_versioning.this]

  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.this["logs"].id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = 90
    }
  }
}

# ---------- Bucket policies ----------

data "aws_iam_policy_document" "tls_only" {
  for_each = aws_s3_bucket.this

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      each.value.arn,
      "${each.value.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "data" {
  source_policy_documents = [data.aws_iam_policy_document.tls_only["data"].json]

  # Objects the scanner marked as infected cannot be read by anyone except the scanner itself
  statement {
    sid       = "DenyReadOfInfectedObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.this["data"].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/ScanStatus"
      values   = ["INFECTED"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.containment["scan_object"].arn]
    }
  }
}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [
    data.aws_iam_policy_document.tls_only["logs"].json,
    data.aws_iam_policy_document.vpc_flow_logs.json,
  ]

  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.this["logs"].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this["logs"].arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

locals {
  bucket_policies = {
    website    = data.aws_iam_policy_document.tls_only["website"].json
    data       = data.aws_iam_policy_document.data.json
    logs       = data.aws_iam_policy_document.logs.json
    quarantine = data.aws_iam_policy_document.tls_only["quarantine"].json
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each = local.bucket_policies
  bucket   = aws_s3_bucket.this[each.key].id
  policy   = each.value

  depends_on = [aws_s3_bucket_public_access_block.this]
}

# ---------- Sample static site ----------

resource "aws_s3_object" "site" {
  for_each     = fileset("${path.module}/site", "*.html")
  bucket       = aws_s3_bucket.this["website"].id
  key          = each.value
  source       = "${path.module}/site/${each.value}"
  etag         = filemd5("${path.module}/site/${each.value}")
  content_type = "text/html"
}
