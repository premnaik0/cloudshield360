# Network segmentation: three tiers in one VPC
#   public tier  - Application Load Balancer (internet-facing), route to the internet gateway
#   app tier     - EC2 instances in private subnets, NO route to the internet
#   data tier    - the S3 data bucket, reachable from the app tier only through a gateway endpoint
# Security groups allow only the next tier: internet -> ALB -> app -> S3 endpoint.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs            = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnets = { for i, az in local.azs : az => cidrsubnet(var.vpc_cidr, 8, i) }
  app_subnets    = { for i, az in local.azs : az => cidrsubnet(var.vpc_cidr, 8, i + 10) }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# The default security group is emptied so nothing can use it by accident
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-default-locked" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# ---------- Subnets and route tables ----------

resource "aws_subnet" "public" {
  for_each                = local.public_subnets
  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false

  tags = { Name = "${var.project_name}-public-${each.key}", Tier = "public" }
}

resource "aws_subnet" "app" {
  for_each                = local.app_subnets
  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false

  tags = { Name = "${var.project_name}-app-${each.key}", Tier = "app" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-public-rt" }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

# App tier: only the local VPC route and the S3 gateway endpoint (added below). No internet route.
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-app-rt" }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "app" {
  for_each       = aws_subnet.app
  subnet_id      = each.value.id
  route_table_id = aws_route_table.app.id
}

# ---------- S3 gateway endpoint (data tier access) ----------

data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid       = "AllowProjectDataBucketOnly"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.this["data"].arn, "${aws_s3_bucket.this["data"].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  # Amazon Linux package repositories, so the instance can still be patched without internet
  statement {
    sid       = "AllowAmazonLinuxRepositories"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::al2023-repos-*", "arn:aws:s3:::al2023-repos-*/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.primary_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json

  tags = { Name = "${var.project_name}-s3-endpoint" }
}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.primary_region}.s3"
}

# ---------- Security groups (one per tier) ----------

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Public tier: internet to load balancer"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-alb-sg", Tier = "public" }
}

resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App tier: only the load balancer may connect"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-app-sg", Tier = "app" }
}

resource "aws_security_group" "eice" {
  name        = "${var.project_name}-eice-sg"
  description = "Instance Connect Endpoint: may reach the app tier on SSH only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-eice-sg" }
}

# Used by the isolation function: no inbound and no outbound traffic at all
resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine-sg"
  description = "Quarantine: no traffic in or out"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-quarantine-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from allowed clients"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = var.alb_certificate_arn == null ? toset([]) : toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed clients"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the app tier"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "App traffic from the load balancer only"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_from_eice" {
  security_group_id            = aws_security_group.app.id
  description                  = "SSH through the Instance Connect Endpoint only"
  referenced_security_group_id = aws_security_group.eice.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to S3 through the gateway endpoint only"
  prefix_list_id    = data.aws_prefix_list.s3.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "eice_to_app" {
  security_group_id            = aws_security_group.eice.id
  description                  = "SSH to the app tier"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

# SSH without public IPs, bastion hosts or a NAT gateway
resource "aws_ec2_instance_connect_endpoint" "app" {
  subnet_id          = values(aws_subnet.app)[0].id
  security_group_ids = [aws_security_group.eice.id]
  preserve_client_ip = false

  tags = { Name = "${var.project_name}-eice" }
}

# ---------- VPC flow logs (evidence of allowed and rejected traffic) ----------

data "aws_iam_policy_document" "vpc_flow_logs" {
  statement {
    sid       = "VPCFlowLogsAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.this["logs"].arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "VPCFlowLogsWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this["logs"].arn}/vpc-flow/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${aws_s3_bucket.this["logs"].arn}/vpc-flow/"
  max_aggregation_interval = 60

  depends_on = [aws_s3_bucket_policy.this]
}
