# Permissions of the EC2 isolation function (the function itself is registered in containment.tf)

data "aws_iam_policy_document" "isolate_instance" {
  statement {
    sid       = "DescribeOnly"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "autoscaling:DescribeAutoScalingInstances"]
    resources = ["*"]
  }

  statement {
    sid       = "SwapSecurityGroupOfProjectInstances"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:aws:ec2:${var.primary_region}:${local.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/Project"
      values   = ["CloudShield360"]
    }
  }

  statement {
    sid       = "UseQuarantineSecurityGroup"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:aws:ec2:${var.primary_region}:${local.account_id}:security-group/${aws_security_group.quarantine.id}"]
  }

  statement {
    sid       = "TagIsolatedInstance"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.primary_region}:${local.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/Project"
      values   = ["CloudShield360"]
    }
  }

  statement {
    sid     = "ForensicSnapshots"
    actions = ["ec2:CreateSnapshot"]
    resources = [
      "arn:aws:ec2:${var.primary_region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${var.primary_region}::snapshot/*",
    ]
  }

  statement {
    sid       = "TagSnapshotsAtCreation"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.primary_region}::snapshot/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot"]
    }
  }

  statement {
    sid       = "DetachFromAutoScaling"
    actions   = ["autoscaling:DetachInstances"]
    resources = [aws_autoscaling_group.app.arn]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}
