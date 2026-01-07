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