# Segmentation and automated containment (free-tier edition)
#
# Trust zones (each has its own identity and blast radius):
#   edge        API Gateway + WAF           - public, can only invoke the site function
#   website     website bucket              - read by the site function only, written by deployers
#   data        data bucket                 - scanned on upload, infected reads denied
#   quarantine  quarantine bucket           - written by the scanner, read by incident responders
#   backup      vaults (locked)             - written by the backup role only
#   response    containment functions       - one least-privilege role per function
#
# Containment flows (EventBridge -> Lambda -> SNS):
#   file uploaded to data bucket        -> scan_object        (scan, tag, quarantine if dangerous)
#   backup/logging tamper by a principal -> isolate_principal  (deny-all / revoke sessions / disable key)
#   bucket protection weakened          -> isolate_bucket     (deny everyone except response roles)

locals {
  deployer_arn = data.aws_caller_identity.current.arn

  # Name of the identity running Terraform, so automation never locks you out
  deployer_name = can(regex("assumed-role/([^/]+)/", local.deployer_arn)) ? regex("assumed-role/([^/]+)/", local.deployer_arn)[0] : element(split("/", local.deployer_arn), length(split("/", local.deployer_arn)) - 1)

  protected_principals = distinct(concat([local.deployer_name], var.protected_principals))

  containment_functions = toset(["scan_object", "isolate_principal", "isolate_bucket", "isolate_instance"])

  isolatable_buckets = [
    aws_s3_bucket.this["data"].id,
    aws_s3_bucket.this["website"].id,
  ]

  # Principals that must keep access to an isolated bucket
  bucket_isolation_exempt_arns = [
    "arn:aws:iam::${local.account_id}:root",
    aws_iam_role.ir_responder.arn,
    aws_iam_role.backup.arn,
    aws_iam_role.containment["scan_object"].arn,
    aws_iam_role.containment["isolate_bucket"].arn,
  ]

  backup_tamper_events = [
    "DeleteBackupVault",
    "DeleteRecoveryPoint",
    "DeleteBackupPlan",
    "DeleteBackupVaultLockConfiguration",
    "StopLogging",
    "DeleteTrail",
  ]

  bucket_tamper_events = [
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "DeleteBucketEncryption",
    "PutBucketPublicAccessBlock",
    "DeletePublicAccessBlock",
    "PutBucketVersioning",
    "PutBucketLifecycle",
    "PutBucketLifecycleConfiguration",
  ]
}

# ---------- Incident responder role (humans, MFA required) ----------

data "aws_iam_policy_document" "ir_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "ir_responder" {
  statement {
    sid     = "ReadQuarantine"
    actions = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions"]
    resources = [
      aws_s3_bucket.this["quarantine"].arn,
      "${aws_s3_bucket.this["quarantine"].arn}/*",
    ]
  }

  statement {
    sid     = "ReleaseBucketIsolation"
    actions = ["s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    resources = [
      aws_s3_bucket.this["data"].arn,
      aws_s3_bucket.this["website"].arn,
    ]
  }

  statement {
    sid = "ReleasePrincipalIsolation"
    actions = [
      "iam:DeleteUserPolicy",
      "iam:DeleteRolePolicy",
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "ir_responder" {
  name                 = "${var.project_name}-ir-responder"
  assume_role_policy   = data.aws_iam_policy_document.ir_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "ir_security_audit" {
  role       = aws_iam_role.ir_responder.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "ir_responder" {
  name   = "incident-response"
  role   = aws_iam_role.ir_responder.id
  policy = data.aws_iam_policy_document.ir_responder.json
}

# ---------- One least-privilege role per containment function ----------

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "containment" {
  for_each           = local.containment_functions
  name               = "${var.project_name}-${each.key}-fn"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "scan_object" {
  statement {
    sid = "ReadAndTagUploads"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.this["data"].arn}/*"]
  }

  statement {
    sid       = "RemoveInfectedVersion"
    actions   = ["s3:DeleteObjectVersion", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.this["data"].arn}/*"]
  }

  statement {
    sid       = "WriteQuarantine"
    actions   = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["${aws_s3_bucket.this["quarantine"].arn}/*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

data "aws_iam_policy_document" "isolate_principal" {
  statement {
    sid       = "IsolateIdentity"
    actions   = ["iam:PutUserPolicy", "iam:PutRolePolicy", "iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${local.account_id}:user/*", "arn:aws:iam::${local.account_id}:role/*"]
  }

  # Never let this function touch the project's own identities, even if its code is changed
  statement {
    sid       = "ProtectProjectIdentities"
    effect    = "Deny"
    actions   = ["iam:PutUserPolicy", "iam:PutRolePolicy", "iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${local.account_id}:user/${var.project_name}-*", "arn:aws:iam::${local.account_id}:role/${var.project_name}-*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

data "aws_iam_policy_document" "isolate_bucket" {
  statement {
    sid       = "IsolateBuckets"
    actions   = ["s3:GetBucketPolicy", "s3:PutBucketPolicy"]
    resources = [aws_s3_bucket.this["data"].arn, aws_s3_bucket.this["website"].arn]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

locals {
  containment_policies = {
    scan_object       = data.aws_iam_policy_document.scan_object.json
    isolate_principal = data.aws_iam_policy_document.isolate_principal.json
    isolate_bucket    = data.aws_iam_policy_document.isolate_bucket.json
    isolate_instance  = data.aws_iam_policy_document.isolate_instance.json
  }
}

resource "aws_iam_role_policy" "containment" {
  for_each = local.containment_policies
  name     = "containment"
  role     = aws_iam_role.containment[each.key].id
  policy   = each.value
}

data "aws_iam_policy_document" "containment_logs" {
  for_each = local.containment_functions

  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.containment[each.key].arn}:*"]
  }
}

resource "aws_iam_role_policy" "containment_logs" {
  for_each = local.containment_functions
  name     = "logs"
  role     = aws_iam_role.containment[each.key].id
  policy   = data.aws_iam_policy_document.containment_logs[each.key].json
}

# ---------- Containment functions ----------

locals {
  containment_env = {
    scan_object = {
      DATA_BUCKET        = aws_s3_bucket.this["data"].id
      QUARANTINE_BUCKET  = aws_s3_bucket.this["quarantine"].id
      BLOCKED_EXTENSIONS = join(",", var.blocked_extensions)
      MAX_SCAN_MB        = tostring(var.max_scan_mb)
      TOPIC_ARN          = aws_sns_topic.alerts.arn
    }
    isolate_principal = {
      MODE                 = var.containment_mode
      PROTECTED_PRINCIPALS = join(",", local.protected_principals)
      NAME_PREFIX          = var.project_name
      TOPIC_ARN            = aws_sns_topic.alerts.arn
    }
    isolate_bucket = {
      MODE                  = var.containment_mode
      ISOLATABLE_BUCKETS    = join(",", local.isolatable_buckets)
      EXEMPT_PRINCIPAL_ARNS = join(",", local.bucket_isolation_exempt_arns)
      PROTECTED_PRINCIPALS  = join(",", local.protected_principals)
      NAME_PREFIX           = var.project_name
      TOPIC_ARN             = aws_sns_topic.alerts.arn
    }
    isolate_instance = {
      MODE             = var.containment_mode
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
      VPC_ID           = aws_vpc.main.id
      ASG_NAME         = aws_autoscaling_group.app.name
      TOPIC_ARN        = aws_sns_topic.alerts.arn
    }
  }
}

data "archive_file" "containment" {
  for_each    = local.containment_functions
  type        = "zip"
  source_file = "${path.module}/lambda/${each.key}.py"
  output_path = "${path.module}/build/${each.key}.zip"
}

resource "aws_cloudwatch_log_group" "containment" {
  for_each          = local.containment_functions
  name              = "/aws/lambda/${var.project_name}-${each.key}"
  retention_in_days = 14
}

resource "aws_lambda_function" "containment" {
  for_each         = local.containment_functions
  function_name    = "${var.project_name}-${each.key}"
  role             = aws_iam_role.containment[each.key].arn
  runtime          = "python3.12"
  handler          = "${each.key}.handler"
  filename         = data.archive_file.containment[each.key].output_path
  source_code_hash = data.archive_file.containment[each.key].output_base64sha256
  timeout          = each.key == "scan_object" ? 300 : 60
  memory_size      = each.key == "scan_object" ? 512 : 256

  environment {
    variables = local.containment_env[each.key]
  }

  depends_on = [
    aws_cloudwatch_log_group.containment,
    aws_iam_role_policy.containment,
    aws_iam_role_policy.containment_logs,
  ]
}

# ---------- EventBridge triggers ----------

locals {
  containment_rules = {
    scan_object = jsonencode({
      source        = ["aws.s3"]
      "detail-type" = ["Object Created"]
      detail = {
        bucket = { name = [aws_s3_bucket.this["data"].id] }
      }
    })

    isolate_principal = jsonencode({
      source        = ["aws.backup", "aws.cloudtrail"]
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail = {
        eventName    = local.backup_tamper_events
        userIdentity = { type = ["IAMUser", "AssumedRole"] }
      }
    })

    isolate_bucket = jsonencode({
      source        = ["aws.s3"]
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail = {
        eventName         = local.bucket_tamper_events
        requestParameters = { bucketName = local.isolatable_buckets }
      }
    })

    isolate_instance = jsonencode({
      source        = ["aws.ec2"]
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail = {
        eventSource = ["ec2.amazonaws.com"]
        eventName   = ["CreateTags"]
        requestParameters = {
          tagSet = { items = { key = ["SecurityIsolate"], value = ["true"] } }
        }
      }
    })
  }
}

resource "aws_cloudwatch_event_rule" "containment" {
  for_each      = local.containment_rules
  name          = "${var.project_name}-${replace(each.key, "_", "-")}"
  description   = "Trigger ${each.key} containment"
  event_pattern = each.value
}

resource "aws_cloudwatch_event_target" "containment" {
  for_each = local.containment_rules
  rule     = aws_cloudwatch_event_rule.containment[each.key].name
  arn      = aws_lambda_function.containment[each.key].arn
}

resource "aws_lambda_permission" "containment" {
  for_each      = local.containment_rules
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.containment[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.containment[each.key].arn
}
