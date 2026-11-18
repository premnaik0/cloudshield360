# ---------- IAM role used by AWS Backup ----------

data "aws_iam_policy_document" "backup_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "${var.project_name}-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
  ])

  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

# ---------- Vaults ----------
# No kms_key_arn: vaults use the AWS-managed aws/backup key (no customer KMS key).

resource "aws_backup_vault" "primary" {
  name          = "${var.project_name}-prod-vault"
  force_destroy = var.force_destroy_buckets
}

resource "aws_backup_vault" "dr" {
  provider      = aws.dr
  name          = "${var.project_name}-prod-dr-vault"
  force_destroy = var.force_destroy_buckets
}

resource "aws_backup_vault_lock_configuration" "primary" {
  backup_vault_name   = aws_backup_vault.primary.name
  changeable_for_days = var.vault_lock_changeable_for_days
  min_retention_days  = 1
  max_retention_days  = 365
}

resource "aws_backup_vault_lock_configuration" "dr" {
  provider            = aws.dr
  backup_vault_name   = aws_backup_vault.dr.name
  changeable_for_days = var.vault_lock_changeable_for_days
  min_retention_days  = 1
  max_retention_days  = 365
}

# ---------- Backup plan and selection ----------

resource "aws_backup_plan" "s3" {
  name = "${var.project_name}-s3-plan"

  rule {
    rule_name         = "daily-immutable"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = var.backup_schedule
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = var.retention_days
    }

    # Cross-region copy into the locked DR vault
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn

      lifecycle {
        delete_after = var.retention_days
      }
    }
  }

  depends_on = [
    aws_backup_vault_lock_configuration.primary,
    aws_backup_vault_lock_configuration.dr,
  ]
}

resource "aws_backup_selection" "s3" {
  name         = "${var.project_name}-s3-buckets"
  plan_id      = aws_backup_plan.s3.id
  iam_role_arn = aws_iam_role.backup.arn

  resources = [
    aws_s3_bucket.this["data"].arn,
    aws_s3_bucket.this["website"].arn,
  ]

  depends_on = [
    aws_s3_bucket_versioning.this,
    aws_iam_role_policy_attachment.backup,
  ]
}
