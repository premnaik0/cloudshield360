# App tier (EC2 + Auto Scaling) and public tier (Application Load Balancer)

# ---------- Instance role: least privilege ----------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "app_instance" {
  statement {
    sid       = "ReadWriteAppPrefix"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.this["data"].arn}/app/*"]
  }

  statement {
    sid       = "ListAppPrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.this["data"].arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["app/*"]
    }
  }
}

resource "aws_iam_role" "app_instance" {
  name               = "${var.project_name}-app-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "app_instance" {
  name   = "app-data-prefix"
  role   = aws_iam_role.app_instance.id
  policy = data.aws_iam_policy_document.app_instance.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project_name}-app-instance"
  role = aws_iam_role.app_instance.name
}

# ---------- Launch template ----------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  # Demo application: a tiny web server on port 8080 using only what Amazon Linux already has
  app_user_data = <<-EOT
    #!/bin/bash
    mkdir -p /opt/app
    cat > /opt/app/index.html <<'HTML'
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="utf-8"><title>CloudShield 360 app tier</title></head>
    <body style="font-family:system-ui,sans-serif;text-align:center;padding:4rem">
      <h1>CloudShield 360</h1>
      <p>Application tier: running in a private subnet, reachable only through the load balancer.</p>
    </body></html>
    HTML
    cat > /etc/systemd/system/cloudshield-app.service <<'UNIT'
    [Unit]
    Description=CloudShield 360 app tier demo
    After=network.target
    [Service]
    WorkingDirectory=/opt/app
    ExecStart=/usr/bin/python3 -m http.server 8080
    Restart=always
    User=nobody
    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload
    systemctl enable --now cloudshield-app
    # Prove data-tier access through the S3 endpoint
    TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
    ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
    echo "app tier heartbeat from $ID at $(date -u)" > /tmp/heartbeat.txt
    AWS_DEFAULT_REGION=${var.primary_region} aws s3 cp /tmp/heartbeat.txt s3://${aws_s3_bucket.this["data"].id}/app/heartbeat-$ID.txt || true
  EOT
}

resource "aws_launch_template" "app" {
  name_prefix            = "${var.project_name}-app-"
  image_id               = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.app.id]
  user_data              = base64encode(local.app_user_data)
  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }

  # IMDSv2 only, hop limit 1 (containers and proxies cannot reach credentials)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 8
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "${var.project_name}-app"
      Project = "CloudShield360"
      Tier    = "app"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name    = "${var.project_name}-app"
      Project = "CloudShield360"
    }
  }
}

# ---------- Public tier: load balancer ----------

resource "aws_lb" "app" {
  name                       = "${var.project_name}-alb"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = [for s in aws_subnet.public : s.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name     = "${var.project_name}-app-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Without a certificate the listener serves HTTP only. With alb_certificate_arn it redirects to HTTPS.
resource "aws_lb_listener" "http_forward" {
  count             = var.alb_certificate_arn == null ? 1 : 0
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = var.alb_certificate_arn == null ? 0 : 1
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.alb_certificate_arn == null ? 0 : 1
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# The same regional web ACL that protects the API now also protects the load balancer
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}

# ---------- App tier: Auto Scaling group in private subnets ----------

resource "aws_autoscaling_group" "app" {
  name                      = "${var.project_name}-app-asg"
  min_size                  = var.asg_min_size
  max_size                  = var.asg_max_size
  desired_capacity          = var.asg_desired_capacity
  vpc_zone_identifier       = [for s in aws_subnet.app : s.id]
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 180

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-app"
    propagate_at_launch = true
  }

  tag {
    key                 = "Project"
    value               = "CloudShield360"
    propagate_at_launch = true
  }

  depends_on = [aws_vpc_endpoint.s3]
}
