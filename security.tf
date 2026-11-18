# Free alternatives to GuardDuty and Security Hub:
#  - IAM Access Analyzer reports resources shared outside the account
#  - EventBridge rules on CloudTrail management events detect risky API calls (see monitoring.tf, containment.tf)

resource "aws_accessanalyzer_analyzer" "this" {
  count         = var.enable_access_analyzer ? 1 : 0
  analyzer_name = "${var.project_name}-analyzer"
  type          = "ACCOUNT"
}

locals {
  credential_change_events = [
    "CreateAccessKey",
    "CreateUser",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
  ]

  forward_enabled = var.primary_region != "us-east-1"

  forward_patterns = {
    iam = jsonencode({
      source        = ["aws.iam"]
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail        = { eventName = local.credential_change_events }
    })

    signin = jsonencode({
      source        = ["aws.signin"]
      "detail-type" = ["AWS Console Sign In via CloudTrail"]
    })

    root = jsonencode({
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail        = { userIdentity = { type = ["Root"] } }
    })
  }
}

# IAM and console sign-in events exist only in us-east-1. Forward them to the primary region's default bus.

data "aws_iam_policy_document" "forwarder_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "forwarder" {
  statement {
    actions   = ["events:PutEvents"]
    resources = ["arn:aws:events:${var.primary_region}:${local.account_id}:event-bus/default"]
  }
}

resource "aws_iam_role" "event_forwarder" {
  name               = "${var.project_name}-event-forwarder"
  assume_role_policy = data.aws_iam_policy_document.forwarder_assume.json
}

resource "aws_iam_role_policy" "event_forwarder" {
  name   = "put-events"
  role   = aws_iam_role.event_forwarder.id
  policy = data.aws_iam_policy_document.forwarder.json
}

resource "aws_cloudwatch_event_rule" "forward" {
  for_each      = local.forward_enabled ? local.forward_patterns : {}
  provider      = aws.us_east_1
  name          = "${var.project_name}-forward-${each.key}"
  description   = "Forward ${each.key} events to ${var.primary_region}"
  event_pattern = each.value
}

resource "aws_cloudwatch_event_target" "forward" {
  for_each = local.forward_enabled ? local.forward_patterns : {}
  provider = aws.us_east_1
  rule     = aws_cloudwatch_event_rule.forward[each.key].name
  arn      = "arn:aws:events:${var.primary_region}:${local.account_id}:event-bus/default"
  role_arn = aws_iam_role.event_forwarder.arn
}
