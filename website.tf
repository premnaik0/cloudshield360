# Free-tier alternative to CloudFront + OAC:
# API Gateway (HTTPS) -> Lambda -> private S3 website bucket, protected by a regional WAF.

# ---------- Site server function ----------

data "aws_iam_policy_document" "site_server" {
  statement {
    sid       = "ReadWebsiteObjects"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.this["website"].arn}/*"]
  }

  statement {
    sid       = "ListForCleanNotFound"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.this["website"].arn]
  }
}

resource "aws_iam_role" "site_server" {
  name               = "${var.project_name}-site-server-fn"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "site_server" {
  name   = "read-website-bucket"
  role   = aws_iam_role.site_server.id
  policy = data.aws_iam_policy_document.site_server.json
}

resource "aws_cloudwatch_log_group" "site_server" {
  name              = "/aws/lambda/${var.project_name}-site-server"
  retention_in_days = 14
}

data "aws_iam_policy_document" "site_server_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.site_server.arn}:*"]
  }
}

resource "aws_iam_role_policy" "site_server_logs" {
  name   = "logs"
  role   = aws_iam_role.site_server.id
  policy = data.aws_iam_policy_document.site_server_logs.json
}

data "archive_file" "site_server" {
  type        = "zip"
  source_file = "${path.module}/lambda/site_server.py"
  output_path = "${path.module}/build/site_server.zip"
}

resource "aws_lambda_function" "site_server" {
  function_name    = "${var.project_name}-site-server"
  role             = aws_iam_role.site_server.arn
  runtime          = "python3.12"
  handler          = "site_server.handler"
  filename         = data.archive_file.site_server.output_path
  source_code_hash = data.archive_file.site_server.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      WEBSITE_BUCKET = aws_s3_bucket.this["website"].id
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.site_server,
    aws_iam_role_policy.site_server,
    aws_iam_role_policy.site_server_logs,
  ]
}

# ---------- API Gateway (REST, regional) ----------

resource "aws_api_gateway_rest_api" "site" {
  name               = "${var.project_name}-site"
  description        = "Serves the private website bucket over HTTPS"
  binary_media_types = ["*/*"]

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.site.id
  parent_id   = aws_api_gateway_rest_api.site.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "root" {
  rest_api_id   = aws_api_gateway_rest_api.site.id
  resource_id   = aws_api_gateway_rest_api.site.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.site.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "root" {
  rest_api_id             = aws_api_gateway_rest_api.site.id
  resource_id             = aws_api_gateway_rest_api.site.root_resource_id
  http_method             = aws_api_gateway_method.root.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.site_server.invoke_arn
}

resource "aws_api_gateway_integration" "proxy" {
  rest_api_id             = aws_api_gateway_rest_api.site.id
  resource_id             = aws_api_gateway_resource.proxy.id
  http_method             = aws_api_gateway_method.proxy.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.site_server.invoke_arn
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.site_server.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.site.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "site" {
  rest_api_id = aws_api_gateway_rest_api.site.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_method.root.id,
      aws_api_gateway_method.proxy.id,
      aws_api_gateway_integration.root.id,
      aws_api_gateway_integration.proxy.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.root,
    aws_api_gateway_integration.proxy,
  ]
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.site.id
  deployment_id = aws_api_gateway_deployment.site.id
  stage_name    = "prod"
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.site.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    throttling_rate_limit  = var.api_rate_limit
    throttling_burst_limit = var.api_burst_limit
  }
}

# ---------- Regional WAF in front of the API ----------

resource "aws_wafv2_ip_set" "api_blocked" {
  name               = "${var.project_name}-api-blocked-ips"
  description        = "IPv4 ranges isolated from the site"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.blocked_cidrs
}

resource "aws_wafv2_web_acl" "api" {
  name        = "${var.project_name}-api-web-acl"
  description = "Web protection for the CloudShield 360 API"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockListedIPs"
    priority = 0

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.api_blocked.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockListedIPs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitPerIP"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-api-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}
