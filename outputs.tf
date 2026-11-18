output "website_url" {
  description = "Open this in a browser after apply."
  value       = "${aws_api_gateway_stage.prod.invoke_url}/"
}

output "website_bucket" {
  value = aws_s3_bucket.this["website"].id
}

output "data_bucket" {
  value = aws_s3_bucket.this["data"].id
}

output "quarantine_bucket" {
  value = aws_s3_bucket.this["quarantine"].id
}

output "primary_vault_arn" {
  value = aws_backup_vault.primary.arn
}

output "backup_plan_id" {
  value = aws_backup_plan.s3.id
}

output "alerts_topic_arn" {
  description = "Confirm the email subscription sent to alert_email, or no alerts are delivered."
  value       = aws_sns_topic.alerts.arn
}

output "ir_responder_role_arn" {
  description = "Assume this role (MFA required) to read quarantined files and release isolations."
  value       = aws_iam_role.ir_responder.arn
}

output "containment_functions" {
  value = { for k, f in aws_lambda_function.containment : k => f.function_name }
}

output "alb_url" {
  description = "Load balancer address of the EC2 app tier (public tier -> app tier)."
  value       = "${var.alb_certificate_arn == null ? "http" : "https"}://${aws_lb.app.dns_name}/"
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "app_autoscaling_group" {
  value = aws_autoscaling_group.app.name
}

output "instance_connect_endpoint_id" {
  value = aws_ec2_instance_connect_endpoint.app.id
}
