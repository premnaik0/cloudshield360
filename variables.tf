variable "project_name" {
  description = "Prefix for resource names (lowercase letters, digits, hyphens)."
  type        = string
  default     = "cloudshield360"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.project_name))
    error_message = "project_name must be 3-20 chars: lowercase letters, digits, hyphens."
  }
}

variable "primary_region" {
  description = "Main region for the buckets, API, backup vault and monitoring."
  type        = string
  default     = "ap-south-1"
}

variable "dr_region" {
  description = "Region for cross-region disaster recovery copies."
  type        = string
  default     = "ap-southeast-1"
}

variable "alert_email" {
  description = "Email address that receives SNS security and backup alerts."
  type        = string
}

variable "retention_days" {
  description = "Days to keep each recovery point. Keep short for demos so vaults can be emptied."
  type        = number
  default     = 7

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 365
    error_message = "retention_days must be between 1 and 365."
  }
}

variable "backup_schedule" {
  description = "Cron expression (UTC) for the AWS Backup plan."
  type        = string
  default     = "cron(30 5 * * ? *)"
}

variable "vault_lock_changeable_for_days" {
  description = "Vault Lock cooling-off period. After this many days the lock becomes permanent. Minimum is 3."
  type        = number
  default     = 3

  validation {
    condition     = var.vault_lock_changeable_for_days >= 3
    error_message = "AWS requires a cooling-off period of at least 3 days."
  }
}

variable "waf_rate_limit" {
  description = "Max requests per 5 minutes from a single IP before WAF blocks it."
  type        = number
  default     = 1000
}

variable "api_rate_limit" {
  description = "API Gateway steady-state requests per second."
  type        = number
  default     = 20
}

variable "api_burst_limit" {
  description = "API Gateway burst requests."
  type        = number
  default     = 40
}

variable "force_destroy_buckets" {
  description = "Allow terraform destroy to delete buckets that still contain objects."
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Create an IAM Access Analyzer (external access) for the account. Set false if you already have one."
  type        = bool
  default     = true
}

variable "containment_mode" {
  description = "enforce = automatically isolate compromised identities and buckets. dry_run = only send alerts that say what would be done."
  type        = string
  default     = "enforce"

  validation {
    condition     = contains(["enforce", "dry_run"], var.containment_mode)
    error_message = "containment_mode must be enforce or dry_run."
  }
}

variable "protected_principals" {
  description = "IAM user or role names automatic isolation must never touch. The identity running Terraform is protected automatically."
  type        = list(string)
  default     = []
}

variable "blocked_cidrs" {
  description = "IPv4 CIDR ranges to block at WAF, e.g. [\"203.0.113.7/32\"]."
  type        = list(string)
  default     = []
}

variable "blocked_extensions" {
  description = "File extensions the data bucket scanner treats as dangerous."
  type        = list(string)
  default     = [".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi", ".ps1", ".vbs", ".jar", ".docm", ".xlsm", ".pptm"]
}

variable "max_scan_mb" {
  description = "Files larger than this are only checked by their first 1 MB."
  type        = number
  default     = 25
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type of the app tier."
  type        = string
  default     = "t3.micro"
}

variable "asg_min_size" {
  description = "Minimum number of app instances."
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum number of app instances."
  type        = number
  default     = 2
}

variable "asg_desired_capacity" {
  description = "Desired number of app instances."
  type        = number
  default     = 1
}

variable "alb_ingress_cidrs" {
  description = "Client ranges allowed to reach the load balancer. Narrow this to your own IP for the demo."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "alb_certificate_arn" {
  description = "ACM certificate ARN for HTTPS on the load balancer. Leave null for HTTP only (demo)."
  type        = string
  default     = null
}
