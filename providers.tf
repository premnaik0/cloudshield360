terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

locals {
  tags = {
    Project   = "CloudShield360"
    ManagedBy = "Terraform"
  }
}

# Primary region
provider "aws" {
  region = var.primary_region
  default_tags { tags = local.tags }
}

# Disaster-recovery region (backup copies)
provider "aws" {
  alias  = "dr"
  region = var.dr_region
  default_tags { tags = local.tags }
}

# IAM and console sign-in events are only published in us-east-1; rules there forward them to the primary region
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = local.tags }
}
