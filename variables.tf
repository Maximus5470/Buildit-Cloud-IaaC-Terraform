variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "buildit"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones to use"
  type        = list(string)
  default     = ["ap-south-1a", "ap-south-1b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "db_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24"]
}

variable "web_instance_type" {
  description = "Instance type for Web EC2"
  type        = string
  default     = "t2.micro"
}

variable "turbo_instance_type" {
  description = "Instance type for Turbo EC2"
  type        = string
  default     = "t2.micro"
}

variable "web_instance_count_min" {
  description = "Minimum number of Web EC2 instances (baseline)"
  type        = number
  default     = 1
}

variable "web_instance_count_max" {
  description = "Maximum number of Web EC2 instances (peak)"
  type        = number
  default     = 8
}

variable "web_instance_count_desired" {
  description = "Desired number of Web EC2 instances"
  type        = number
  default     = 1
}

variable "turbo_instance_count_min" {
  description = "Minimum number of Turbo EC2 instances (baseline)"
  type        = number
  default     = 1
}

variable "turbo_instance_count_max" {
  description = "Maximum number of Turbo EC2 instances (peak)"
  type        = number
  default     = 8
}

variable "turbo_instance_count_desired" {
  description = "Desired number of Turbo EC2 instances"
  type        = number
  default     = 1
}

variable "db_name" {
  description = "Name of the RDS database"
  type        = string
  default     = "buildit_db"
}

variable "db_username" {
  description = "Master username for RDS"
  type        = string
  default     = "buildit_admin"
  sensitive   = true
}

variable "db_password" {
  description = "Master password for RDS"
  type        = string
  sensitive   = true
}

variable "db_instance_class" {
  description = "Instance class for RDS"
  type        = string
  default     = "db.t4g.micro"
}

variable "elasticache_node_type" {
  description = "Node type for ElastiCache"
  type        = string
  default     = "cache.t4g.micro"
}

variable "elasticache_num_nodes" {
  description = "Number of ElastiCache nodes"
  type        = number
  default     = 2
}

variable "ssh_key_name" {
  description = "Name of SSH key pair for EC2 instances"
  type        = string
  default     = ""
}

variable "turbo_execution_port" {
  description = "Port for Turbo EC2 execution service"
  type        = number
  default     = 8080
}

variable "ebs_volume_size" {
  description = "EBS volume size in GB"
  type        = number
  default     = 24
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring for EC2 instances"
  type        = bool
  default     = true
}

variable "peak_schedule_start" {
  description = "Cron expression for when to scale up to peak (UTC)"
  type        = string
  default     = "0 0 * * 1-6"  # 00:00 UTC Monday-Saturday
}

variable "peak_schedule_end" {
  description = "Cron expression for when to scale down from peak (UTC)"
  type        = string
  default     = "0 8 * * 1-6"  # 08:00 UTC Monday-Saturday (8 hours later)
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "acm_certificate_arn" {
  description = "ARN of ACM certificate for ALB HTTPS listener (leave empty to use HTTP only)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}