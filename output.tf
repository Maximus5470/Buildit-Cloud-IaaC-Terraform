# ============================================================================
# OUTPUTS
# ============================================================================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.alb.dns_name
}

output "nlb_dns_name" {
  description = "DNS name of the Network Load Balancer"
  value       = aws_lb.nlb.dns_name
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_database_name" {
  description = "RDS database name"
  value       = aws_db_instance.main.db_name
}

output "elasticache_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "web_asg_name" {
  description = "Name of the Web Auto Scaling Group"
  value       = aws_autoscaling_group.web.name
}

output "turbo_asg_name" {
  description = "Name of the Turbo Auto Scaling Group"
  value       = aws_autoscaling_group.turbo.name
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "db_subnet_ids" {
  description = "IDs of database subnets"
  value       = aws_subnet.db[*].id
}

output "alb_url" {
  description = "URL to access the web application"
  value       = "http://${aws_lb.alb.dns_name}"
}

output "nlb_url" {
  description = "URL to access the turbo execution service"
  value       = "http://${aws_lb.nlb.dns_name}:${var.turbo_execution_port}"
}

output "db_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret for DB credentials"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch monitoring dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-monitoring"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

# ============================================================================
# VPC FLOW LOGS OUTPUTS
# ============================================================================

output "flow_logs_s3_bucket" {
  description = "S3 bucket name for VPC Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_s3_bucket.flow_logs[0].id : null
}

output "flow_logs_s3_arn" {
  description = "S3 bucket ARN for VPC Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_s3_bucket.flow_logs[0].arn : null
}

output "athena_workgroup" {
  description = "Athena workgroup for querying Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_athena_workgroup.flow_logs[0].name : null
}

output "glue_database" {
  description = "Glue database for Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_glue_catalog_database.flow_logs[0].name : null
}

output "flow_logs_query_guide" {
  description = "Quick guide for querying Flow Logs"
  value       = var.enable_vpc_flow_logs ? join("", [
    "\n",
    "VPC Flow Logs are now enabled!\n",
    "\n",
    "To query your flow logs:\n",
    "1. Go to AWS Athena console\n",
    "2. Select workgroup: ${aws_athena_workgroup.flow_logs[0].name}\n",
    "3. Select database: ${aws_glue_catalog_database.flow_logs[0].name}\n",
    "4. Run queries against table: vpc_flow_logs\n",
    "\n",
    "Example queries are available in the query_examples.sql file.\n"
  ]) : null
}