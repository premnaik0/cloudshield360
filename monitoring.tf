locals {
  trail_name = "${var.project_name}-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.primary_region}:${local.account_id}:trail/${local.trail_name}"
}

# One multi-region management-event trail (the first copy is free)
resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.this["logs"].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.this]
}

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "sns_from_events" {
  statement {
    sid       = "AllowEventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_from_events.json
}

# Custom detection rules (replace GuardDuty and Security Hub alerts)
locals {
  alert_rules = {
    root_usage = {
      description = "Root account activity"
      pattern = jsonencode({
        "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      })
      input_paths = {
        event = "$.detail.eventName"
        ip    = "$.detail.sourceIPAddress"
      }
      template = "\"Root account activity: <event> from <ip>\""
    }

    console_no_mfa = {
      description = "Console login without MFA"
      pattern = jsonencode({
        source        = ["aws.signin"]
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail = {
          eventName          = ["ConsoleLogin"]
          responseElements   = { ConsoleLogin = ["Success"] }
          additionalEventData = { MFAUsed = ["No"] }
        }
      })
      input_paths = {
        actor = "$.detail.userIdentity.type"
        ip    = "$.detail.sourceIPAddress"
      }
      template = "\"Console login without MFA: <actor> from <ip>\""
    }

    console_failed = {
      description = "Failed console login"
      pattern = jsonencode({
        source        = ["aws.signin"]
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail = {
          eventName        = ["ConsoleLogin"]
          responseElements = { ConsoleLogin = ["Failure"] }
        }
      })
      input_paths = {
        actor = "$.detail.userIdentity.type"
        ip    = "$.detail.sourceIPAddress"
      }
      template = "\"Failed console login: <actor> from <ip>\""
    }

    credential_changes = {
      description = "Credential and MFA changes"
      pattern = jsonencode({
        source        = ["aws.iam"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventName = local.credential_change_events }
      })
      input_paths = {
        event = "$.detail.eventName"
        actor = "$.detail.userIdentity.type"
        ip    = "$.detail.sourceIPAddress"
      }
      template = "\"IAM credential change: <event> by <actor> from <ip>\""
    }

    access_analyzer = {
      description = "IAM Access Analyzer external access findings"
      pattern = jsonencode({
        source        = ["aws.access-analyzer"]
        "detail-type" = ["Access Analyzer Finding"]
        detail        = { status = ["ACTIVE"] }
      })
      input_paths = {
        rtype    = "$.detail.resourceType"
        resource = "$.detail.resource"
      }
      template = "\"Access Analyzer: external access to <rtype> <resource>\""
    }

    backup = {
      description = "Failed AWS Backup and copy jobs"
      pattern = jsonencode({
        source        = ["aws.backup"]
        "detail-type" = ["Backup Job State Change", "Copy Job State Change"]
        detail        = { state = ["FAILED", "ABORTED", "EXPIRED"] }
      })
      input_paths = {
        kind    = "$.detail-type"
        state   = "$.detail.state"
        account = "$.account"
      }
      template = "\"Backup alert: <kind> is <state> in account <account>\""
    }
  }
}

resource "aws_cloudwatch_event_rule" "alerts" {
  for_each      = local.alert_rules
  name          = "${var.project_name}-${replace(each.key, "_", "-")}-alert"
  description   = each.value.description
  event_pattern = each.value.pattern
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = local.alert_rules
  rule     = aws_cloudwatch_event_rule.alerts[each.key].name
  arn      = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths    = each.value.input_paths
    input_template = each.value.template
  }

  depends_on = [aws_sns_topic_policy.alerts]
}
