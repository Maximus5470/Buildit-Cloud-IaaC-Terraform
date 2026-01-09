terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = var.tags
  }
}

# ============================================================================
# VPC AND NETWORKING
# ============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Public Subnets (for ALB and NLB)
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
    Type = "public"
  }
}

# Private Subnets (for Web EC2 and Turbo EC2)
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
    Type = "private"
  }
}

# Database Subnets (for RDS and ElastiCache)
resource "aws_subnet" "db" {
  count             = length(var.db_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.db_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.project_name}-db-subnet-${count.index + 1}"
    Type = "database"
  }
}

# NAT Gateway for private subnets (optional outbound internet)
resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? length(var.availability_zones) : 0
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? length(var.availability_zones) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.project_name}-nat-gateway-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.main.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[count.index].id
    }
  }

  tags = {
    Name = "${var.project_name}-private-rt-${count.index + 1}"
  }
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-db-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "db" {
  count          = length(var.db_subnet_cidrs)
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}

# ============================================================================
# SECURITY GROUPS
# ============================================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# Web EC2 Security Group
resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "Security group for Web EC2 instances"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-web-sg"
  }
}

# Turbo EC2 Security Group
resource "aws_security_group" "turbo" {
  name        = "${var.project_name}-turbo-sg"
  description = "Security group for Turbo EC2 execution instances"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-turbo-sg"
  }
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds-sg"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}

# ElastiCache Security Group
resource "aws_security_group" "elasticache" {
  name        = "${var.project_name}-elasticache-sg"
  description = "Security group for ElastiCache Valkey"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-elasticache-sg"
  }
}

# ============================================================================
# SECURITY GROUP RULES
# ============================================================================

# ALB Rules
resource "aws_security_group_rule" "alb_ingress_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTP from internet"
  security_group_id = aws_security_group.alb.id
}

resource "aws_security_group_rule" "alb_ingress_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS from internet"
  security_group_id = aws_security_group.alb.id
}

resource "aws_security_group_rule" "alb_egress_web" {
  type                     = "egress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.web.id
  description              = "To Web EC2 only"
  security_group_id        = aws_security_group.alb.id
}

# Web EC2 Rules
resource "aws_security_group_rule" "web_ingress_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  description              = "HTTP from ALB only"
  security_group_id        = aws_security_group.web.id
}

resource "aws_security_group_rule" "web_egress_rds" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rds.id
  description              = "To RDS"
  security_group_id        = aws_security_group.web.id
}

resource "aws_security_group_rule" "web_egress_nlb" {
  type              = "egress"
  from_port         = var.turbo_execution_port
  to_port           = var.turbo_execution_port
  protocol          = "tcp"
  cidr_blocks       = var.public_subnet_cidrs
  description       = "To NLB (via public subnet)"
  security_group_id = aws_security_group.web.id
}

resource "aws_security_group_rule" "web_egress_elasticache" {
  type                     = "egress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.elasticache.id
  description              = "To ElastiCache for job queue and results"
  security_group_id        = aws_security_group.web.id
}

resource "aws_security_group_rule" "web_egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS for package downloads"
  security_group_id = aws_security_group.web.id
}

# Turbo EC2 Rules
resource "aws_security_group_rule" "turbo_ingress_nlb" {
  type              = "ingress"
  from_port         = var.turbo_execution_port
  to_port           = var.turbo_execution_port
  protocol          = "tcp"
  cidr_blocks       = var.public_subnet_cidrs
  description       = "Execution requests from NLB path"
  security_group_id = aws_security_group.turbo.id
}

resource "aws_security_group_rule" "turbo_egress_elasticache" {
  type                     = "egress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.elasticache.id
  description              = "To ElastiCache"
  security_group_id        = aws_security_group.turbo.id
}

resource "aws_security_group_rule" "turbo_egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS for package downloads"
  security_group_id = aws_security_group.turbo.id
}

# RDS Rules
resource "aws_security_group_rule" "rds_ingress_web" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.web.id
  description              = "PostgreSQL from Web EC2"
  security_group_id        = aws_security_group.rds.id
}

resource "aws_security_group_rule" "rds_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "No outbound required"
  security_group_id = aws_security_group.rds.id
}

# ElastiCache Rules
resource "aws_security_group_rule" "elasticache_ingress_web" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.web.id
  description              = "Valkey from Web EC2 for job queue"
  security_group_id        = aws_security_group.elasticache.id
}

resource "aws_security_group_rule" "elasticache_ingress_turbo" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.turbo.id
  description              = "Valkey from Turbo EC2 for job processing"
  security_group_id        = aws_security_group.elasticache.id
}

# ============================================================================
# APPLICATION LOAD BALANCER (ALB)
# ============================================================================

resource "aws_lb" "alb" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false
  enable_http2               = true

  tags = {
    Name = "${var.project_name}-alb"
  }
}

resource "aws_lb_target_group" "web" {
  name     = "${var.project_name}-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.project_name}-web-tg"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

# HTTPS Listener (mandatory for encryption in transit at trust boundary)
resource "aws_lb_listener" "https" {
  count             = var.acm_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06" # TLS 1.2 and 1.3
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

# Target group attachment is handled automatically by Auto Scaling Group

# ============================================================================
# NETWORK LOAD BALANCER (NLB) - Internal Execution Gateway
# ============================================================================

resource "aws_lb" "nlb" {
  name               = "${var.project_name}-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = aws_subnet.private[*].id

  enable_deletion_protection = false

  tags = {
    Name = "${var.project_name}-nlb-execution"
  }
}

resource "aws_lb_target_group" "turbo" {
  name     = "${var.project_name}-turbo-tg"
  port     = var.turbo_execution_port
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    port                = "traffic-port"
    protocol            = "TCP"
    unhealthy_threshold = 2
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.project_name}-turbo-tg"
  }
}

resource "aws_lb_listener" "turbo" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = var.turbo_execution_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.turbo.arn
  }
}

# Target group attachment is handled automatically by Auto Scaling Group

# ============================================================================
# DATA SOURCES
# ============================================================================

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================================
# EC2 AUTO SCALING
# ============================================================================

# Launch Template for Web EC2 Instances
resource "aws_launch_template" "web" {
  name_prefix   = "${var.project_name}-web-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.web_instance_type
  key_name      = var.ssh_key_name != "" ? var.ssh_key_name : null

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_secrets_profile.name
  }

  vpc_security_group_ids = [aws_security_group.web.id]

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.ebs_volume_size
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
              echo "<h1>Web Server $INSTANCE_ID</h1>" > /var/www/html/index.html
              echo "OK" > /var/www/html/health
              EOF
  )

  tag_specifications {
    resource_type = "instance"

    tags = merge(
      var.tags,
      {
        Name = "${var.project_name}-web-ec2"
        Role = "web"
      }
    )
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for Web EC2
resource "aws_autoscaling_group" "web" {
  name                      = "${var.project_name}-web-asg"
  vpc_zone_identifier       = aws_subnet.private[*].id
  target_group_arns         = [aws_lb_target_group.web.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  min_size                  = var.web_instance_count_min
  max_size                  = var.web_instance_count_max
  desired_capacity          = var.web_instance_count_desired

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-web-ec2"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "web"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Scheduled Scaling for Web - Scale Up to Peak
resource "aws_autoscaling_schedule" "web_scale_up" {
  scheduled_action_name  = "${var.project_name}-web-scale-up"
  min_size               = var.web_instance_count_min
  max_size               = var.web_instance_count_max
  desired_capacity       = var.web_instance_count_max
  recurrence             = var.peak_schedule_start
  autoscaling_group_name = aws_autoscaling_group.web.name
}

# Scheduled Scaling for Web - Scale Down to Baseline
resource "aws_autoscaling_schedule" "web_scale_down" {
  scheduled_action_name  = "${var.project_name}-web-scale-down"
  min_size               = var.web_instance_count_min
  max_size               = var.web_instance_count_max
  desired_capacity       = var.web_instance_count_min
  recurrence             = var.peak_schedule_end
  autoscaling_group_name = aws_autoscaling_group.web.name
}

# Launch Template for Turbo EC2 Instances
resource "aws_launch_template" "turbo" {
  name_prefix   = "${var.project_name}-turbo-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.turbo_instance_type
  key_name      = var.ssh_key_name != "" ? var.ssh_key_name : null

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_secrets_profile.name
  }

  vpc_security_group_ids = [aws_security_group.turbo.id]

  # Spot Instance Configuration (cost-optimized for execution workloads)
  instance_market_options {
    market_type = "spot"
    spot_options {
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
      max_price                      = "" # Use on-demand price as max (default)
    }
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.ebs_volume_size
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              # Custom AMI already contains all compilers and interpreters
              # Minimal bootstrap for instance identification
              mkdir -p /opt/turbo
              INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
              echo "Turbo Execution Node $INSTANCE_ID" > /opt/turbo/info.txt
              # Start your execution service here if needed
              EOF
  )

  tag_specifications {
    resource_type = "instance"

    tags = merge(
      var.tags,
      {
        Name = "${var.project_name}-turbo-ec2"
        Role = "execution"
      }
    )
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for Turbo EC2
resource "aws_autoscaling_group" "turbo" {
  name                      = "${var.project_name}-turbo-asg"
  vpc_zone_identifier       = aws_subnet.private[*].id
  target_group_arns         = [aws_lb_target_group.turbo.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  min_size                  = var.turbo_instance_count_min
  max_size                  = var.turbo_instance_count_max
  desired_capacity          = var.turbo_instance_count_desired

  launch_template {
    id      = aws_launch_template.turbo.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-turbo-ec2"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "execution"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Scheduled Scaling for Turbo - Scale Up to Peak
resource "aws_autoscaling_schedule" "turbo_scale_up" {
  scheduled_action_name  = "${var.project_name}-turbo-scale-up"
  min_size               = var.turbo_instance_count_min
  max_size               = var.turbo_instance_count_max
  desired_capacity       = var.turbo_instance_count_max
  recurrence             = var.peak_schedule_start
  autoscaling_group_name = aws_autoscaling_group.turbo.name
}

# Scheduled Scaling for Turbo - Scale Down to Baseline
resource "aws_autoscaling_schedule" "turbo_scale_down" {
  scheduled_action_name  = "${var.project_name}-turbo-scale-down"
  min_size               = var.turbo_instance_count_min
  max_size               = var.turbo_instance_count_max
  desired_capacity       = var.turbo_instance_count_min
  recurrence             = var.peak_schedule_end
  autoscaling_group_name = aws_autoscaling_group.turbo.name
}

# ============================================================================
# RDS POSTGRESQL
# ============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = aws_subnet.db[*].id

  tags = {
    Name = "${var.project_name}-db-subnet-group"
  }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project_name}-postgres"
  engine         = "postgres"
  engine_version = "15.15"
  instance_class = var.db_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az                = true
  publicly_accessible     = false
  backup_retention_period = 30
  skip_final_snapshot     = true

  tags = {
    Name = "${var.project_name}-rds"
  }

  # Ignore credential changes after initial creation (managed via Secrets Manager)
  lifecycle {
    ignore_changes = [username, password]
  }
}

# ============================================================================
# ELASTICACHE (VALKEY/REDIS)
# ============================================================================

resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project_name}-cache-subnet-group"
  subnet_ids = aws_subnet.db[*].id

  tags = {
    Name = "${var.project_name}-cache-subnet-group"
  }
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.project_name}-cache"
  description                = "Redis replication group for ${var.project_name}"
  engine                     = "redis"
  engine_version             = "7.0"
  node_type                  = var.elasticache_node_type
  num_cache_clusters         = var.elasticache_num_nodes
  parameter_group_name       = "default.redis7"
  port                       = 6379
  automatic_failover_enabled = var.elasticache_num_nodes > 1 ? true : false

  # Encryption at rest (strongly recommended - defense in depth)
  at_rest_encryption_enabled = true
  kms_key_id                 = null # Use AWS-managed key

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.elasticache.id]

  tags = {
    Name = "${var.project_name}-elasticache"
  }
}

# ============================================================================
# SECRETS MANAGER
# ============================================================================

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${var.project_name}-db-credentials"
  description = "Database credentials for RDS PostgreSQL"

  tags = {
    Name = "${var.project_name}-db-credentials"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
  })

  # CRITICAL: Prevents Terraform from updating/deleting after initial creation
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ============================================================================
# IAM ROLES FOR SECRETS ACCESS
# ============================================================================

resource "aws_iam_role" "ec2_secrets_role" {
  name = "${var.project_name}-ec2-secrets-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Name = "${var.project_name}-ec2-secrets-role"
  }
}

resource "aws_iam_role_policy" "secrets_access" {
  name = "${var.project_name}-secrets-access"
  role = aws_iam_role.ec2_secrets_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.db_credentials.arn]
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_secrets_profile" {
  name = "${var.project_name}-ec2-secrets-profile"
  role = aws_iam_role.ec2_secrets_role.name
}

# ============================================================================
# VPC ENDPOINT FOR SECRETS MANAGER
# ============================================================================

resource "aws_security_group" "secrets_endpoint" {
  name        = "${var.project_name}-secrets-endpoint-sg"
  description = "Security group for Secrets Manager VPC endpoint"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id, aws_security_group.turbo.id]
    description     = "HTTPS from EC2 instances"
  }

  tags = {
    Name = "${var.project_name}-secrets-endpoint-sg"
  }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.secrets_endpoint.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-secretsmanager-endpoint"
  }
}

# ============================================================================
# CLOUDWATCH MONITORING
# ============================================================================

# SNS Topic for Alarm Notifications
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
  tags = { Name = "${var.project_name}-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ----------------------------------------------------------------------------
# CloudWatch Alarms - Comprehensive Production Monitoring
# ----------------------------------------------------------------------------

# ALB ALARMS
resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.project_name}-alb-high-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_description   = "ALB 5XX error rate high"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_4xx" {
  alarm_name          = "${var.project_name}-alb-high-4xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_4XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"
  alarm_description   = "ALB 4XX error rate unusually high"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_target_5xx" {
  alarm_name          = "${var.project_name}-alb-target-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_description   = "Target (Web EC2) returning 5XX errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
    TargetGroup  = aws_lb_target_group.web.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_latency" {
  alarm_name          = "${var.project_name}-alb-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1.0
  treat_missing_data  = "notBreaching"
  alarm_description   = "ALB response time > 1 second"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_rejected_connections" {
  alarm_name          = "${var.project_name}-alb-rejected-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RejectedConnectionCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_description   = "ALB rejecting connections - capacity issue"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

# TARGET GROUP HEALTH ALARMS
resource "aws_cloudwatch_metric_alarm" "web_unhealthy" {
  alarm_name          = "${var.project_name}-web-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Unhealthy hosts in Web Target Group"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    TargetGroup  = aws_lb_target_group.web.arn_suffix
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "web_healthy_count_low" {
  alarm_name          = "${var.project_name}-web-low-healthy-hosts"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_description   = "Less than 1 healthy Web EC2 instance"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    TargetGroup  = aws_lb_target_group.web.arn_suffix
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "turbo_unhealthy" {
  alarm_name          = "${var.project_name}-turbo-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Unhealthy Turbo execution instances"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    TargetGroup  = aws_lb_target_group.turbo.arn_suffix
    LoadBalancer = aws_lb.nlb.arn_suffix
  }
}

# RDS DATABASE ALARMS
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.project_name}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS CPU utilization > 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_critical" {
  alarm_name          = "${var.project_name}-rds-critical-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 95
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS CPU utilization > 95% - CRITICAL"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.project_name}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10000000000 # 10 GB
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS free storage < 10GB"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_critical" {
  alarm_name          = "${var.project_name}-rds-critical-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 2000000000 # 2 GB
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS free storage < 2GB - CRITICAL"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${var.project_name}-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS database connections > 80"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_read_latency" {
  alarm_name          = "${var.project_name}-rds-high-read-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReadLatency"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 0.01 # 10ms
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS read latency > 10ms"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_write_latency" {
  alarm_name          = "${var.project_name}-rds-high-write-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "WriteLatency"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 0.01 # 10ms
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS write latency > 10ms"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_freeable_memory" {
  alarm_name          = "${var.project_name}-rds-low-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 524288000 # 500 MB
  treat_missing_data  = "notBreaching"
  alarm_description   = "RDS freeable memory < 500MB"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

# ELASTICACHE ALARMS
resource "aws_cloudwatch_metric_alarm" "elasticache_cpu" {
  alarm_name          = "${var.project_name}-elasticache-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  treat_missing_data  = "notBreaching"
  alarm_description   = "ElastiCache CPU > 75%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.replication_group_id}-001"
  }
}

resource "aws_cloudwatch_metric_alarm" "elasticache_memory" {
  alarm_name          = "${var.project_name}-elasticache-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  treat_missing_data  = "notBreaching"
  alarm_description   = "ElastiCache memory usage > 85%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.replication_group_id}-001"
  }
}

resource "aws_cloudwatch_metric_alarm" "elasticache_evictions" {
  alarm_name          = "${var.project_name}-elasticache-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Sum"
  threshold           = 1000
  treat_missing_data  = "notBreaching"
  alarm_description   = "ElastiCache evicting keys - memory pressure"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.replication_group_id}-001"
  }
}

resource "aws_cloudwatch_metric_alarm" "elasticache_replication_lag" {
  alarm_name          = "${var.project_name}-elasticache-replication-lag"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReplicationLag"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_description   = "ElastiCache replication lag > 5 seconds"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.replication_group_id}-001"
  }
}

# EC2 AUTO SCALING ALARMS
resource "aws_cloudwatch_metric_alarm" "web_asg_cpu_high" {
  alarm_name          = "${var.project_name}-web-asg-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_description   = "Web ASG average CPU > 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web.name
  }
}

resource "aws_cloudwatch_metric_alarm" "turbo_asg_cpu_high" {
  alarm_name          = "${var.project_name}-turbo-asg-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  treat_missing_data  = "notBreaching"
  alarm_description   = "Turbo ASG average CPU > 90%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.turbo.name
  }
}

resource "aws_cloudwatch_metric_alarm" "web_status_check_failed" {
  alarm_name          = "${var.project_name}-web-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Web EC2 instance status check failed"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web.name
  }
}

# NAT GATEWAY ALARMS (if enabled)
resource "aws_cloudwatch_metric_alarm" "nat_error_port_allocation" {
  count               = var.enable_nat_gateway ? 1 : 0
  alarm_name          = "${var.project_name}-nat-port-allocation-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ErrorPortAllocation"
  namespace           = "AWS/NATGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_description   = "NAT Gateway port allocation errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    NatGatewayId = aws_nat_gateway.main[0].id
  }
}

# ----------------------------------------------------------------------------
# CloudWatch Dashboards - Separated by Area of Concern
# ----------------------------------------------------------------------------

locals {
  all_alarm_arns = concat([
    aws_cloudwatch_metric_alarm.alb_5xx.arn,
    aws_cloudwatch_metric_alarm.alb_4xx.arn,
    aws_cloudwatch_metric_alarm.alb_target_5xx.arn,
    aws_cloudwatch_metric_alarm.alb_latency.arn,
    aws_cloudwatch_metric_alarm.alb_rejected_connections.arn,
    aws_cloudwatch_metric_alarm.web_unhealthy.arn,
    aws_cloudwatch_metric_alarm.web_healthy_count_low.arn,
    aws_cloudwatch_metric_alarm.turbo_unhealthy.arn,
    aws_cloudwatch_metric_alarm.rds_cpu.arn,
    aws_cloudwatch_metric_alarm.rds_cpu_critical.arn,
    aws_cloudwatch_metric_alarm.rds_storage.arn,
    aws_cloudwatch_metric_alarm.rds_storage_critical.arn,
    aws_cloudwatch_metric_alarm.rds_connections.arn,
    aws_cloudwatch_metric_alarm.rds_read_latency.arn,
    aws_cloudwatch_metric_alarm.rds_write_latency.arn,
    aws_cloudwatch_metric_alarm.rds_freeable_memory.arn,
    aws_cloudwatch_metric_alarm.elasticache_cpu.arn,
    aws_cloudwatch_metric_alarm.elasticache_memory.arn,
    aws_cloudwatch_metric_alarm.elasticache_evictions.arn,
    aws_cloudwatch_metric_alarm.elasticache_replication_lag.arn,
    aws_cloudwatch_metric_alarm.web_asg_cpu_high.arn,
    aws_cloudwatch_metric_alarm.turbo_asg_cpu_high.arn
  ], var.enable_nat_gateway ? [aws_cloudwatch_metric_alarm.nat_error_port_allocation[0].arn] : [])
}

# Dashboard 1: Application Layer (ALB + Web ASG)
resource "aws_cloudwatch_dashboard" "application" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.project_name}-application"

  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "# Application Layer - ALB & Web ASG" } },
      { type = "metric", x = 0, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.alb.arn_suffix, { stat = "Sum" }]], view = "singleValue", region = var.aws_region, title = "Total Requests", period = 300 } },
      { type = "metric", x = 6, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.alb.arn_suffix, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Avg Latency (sec)", period = 300 } },
      { type = "metric", x = 12, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.web.arn_suffix, "LoadBalancer", aws_lb.alb.arn_suffix, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Healthy Targets", period = 60 } },
      { type = "metric", x = 18, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.web.name, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Web ASG CPU %", period = 300 } },
      { type = "metric", x = 0, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", aws_lb.alb.arn_suffix, { stat = "Sum", label = "ALB 5XX", color = "#d62728" }], [".", "HTTPCode_Target_5XX_Count", ".", ".", { stat = "Sum", label = "Target 5XX", color = "#ff7f0e" }]], view = "timeSeries", stacked = true, region = var.aws_region, title = "5XX Errors (Stacked Area)", period = 300 } },
      { type = "metric", x = 12, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.alb.arn_suffix, { stat = "p90", label = "p90" }], ["...", { stat = "p99", label = "p99" }]], view = "timeSeries", region = var.aws_region, title = "ALB Latency (p90, p99)", period = 300 } },
      { type = "metric", x = 0, y = 9, width = 24, height = 5, properties = { metrics = [["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.web.name, { stat = "Average", label = "Web ASG Avg", color = "#1f77b4" }], ["...", { stat = "Maximum", label = "Web ASG Max", color = "#aec7e8" }], ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.turbo.name, { stat = "Average", label = "Turbo ASG Avg", color = "#ff7f0e" }], ["...", { stat = "Maximum", label = "Turbo ASG Max", color = "#ffbb78" }]], view = "timeSeries", region = var.aws_region, title = "CPU Utilization by ASG", period = 300, yAxis = { left = { min = 0, max = 100 } } } }
    ]
  })
}

# Dashboard 2: Database Layer (RDS)
resource "aws_cloudwatch_dashboard" "database" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.project_name}-database"

  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "# Database Layer - RDS PostgreSQL" } },
      { type = "metric", x = 0, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "RDS CPU %", period = 300 } },
      { type = "metric", x = 6, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Connections", period = 300 } },
      { type = "metric", x = 12, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Free Storage (bytes)", period = 300 } },
      { type = "metric", x = 18, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Free Memory (bytes)", period = 300 } },
      { type = "metric", x = 0, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average", label = "CPU %" }]], view = "timeSeries", region = var.aws_region, title = "RDS CPU Utilization", period = 300, yAxis = { left = { min = 0, max = 100 } } } },
      { type = "metric", x = 12, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average" }]], view = "timeSeries", region = var.aws_region, title = "Active Connections", period = 300 } },
      { type = "metric", x = 0, y = 9, width = 12, height = 5, properties = { metrics = [["AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average", label = "Read", color = "#1f77b4" }], [".", "WriteIOPS", ".", ".", { stat = "Average", label = "Write", color = "#ff7f0e" }]], view = "timeSeries", stacked = true, region = var.aws_region, title = "IOPS (Stacked Area)", period = 300 } },
      { type = "metric", x = 12, y = 9, width = 12, height = 5, properties = { metrics = [["AWS/RDS", "ReadLatency", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average", label = "Read" }], [".", "WriteLatency", ".", ".", { stat = "Average", label = "Write" }]], view = "timeSeries", region = var.aws_region, title = "Latency (seconds)", period = 300 } }
    ]
  })
}

# Dashboard 3: Cache Layer (ElastiCache)
resource "aws_cloudwatch_dashboard" "cache" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.project_name}-cache"

  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "# Cache Layer - ElastiCache Valkey" } },
      { type = "metric", x = 0, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "CPU %", period = 300 } },
      { type = "metric", x = 6, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Memory %", period = 300 } },
      { type = "metric", x = 12, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ElastiCache", "CacheHitRate", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Hit Rate %", period = 300 } },
      { type = "metric", x = 18, y = 1, width = 6, height = 3, properties = { metrics = [["AWS/ElastiCache", "Evictions", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Sum" }]], view = "singleValue", region = var.aws_region, title = "Evictions", period = 300 } },
      { type = "metric", x = 0, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/ElastiCache", "CacheHits", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Sum", label = "Hits", color = "#2ca02c" }], [".", "CacheMisses", ".", ".", { stat = "Sum", label = "Misses", color = "#d62728" }]], view = "timeSeries", stacked = true, region = var.aws_region, title = "Cache Hits vs Misses (Stacked)", period = 300 } },
      { type = "metric", x = 12, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Average" }]], view = "timeSeries", region = var.aws_region, title = "Memory Usage %", period = 300, yAxis = { left = { min = 0, max = 100 } } } },
      { type = "metric", x = 0, y = 9, width = 12, height = 5, properties = { metrics = [["AWS/ElastiCache", "Evictions", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Sum" }]], view = "timeSeries", region = var.aws_region, title = "Evictions Over Time", period = 300 } },
      { type = "metric", x = 12, y = 9, width = 12, height = 5, properties = { metrics = [["AWS/ElastiCache", "ReplicationLag", "CacheClusterId", "${aws_elasticache_replication_group.main.replication_group_id}-001", { stat = "Average" }]], view = "timeSeries", region = var.aws_region, title = "Replication Lag (sec)", period = 60 } }
    ]
  })
}

# Dashboard 4: Network Layer (NLB)
resource "aws_cloudwatch_dashboard" "network" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.project_name}-network"

  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "# Network Layer - NLB & Turbo Execution" } },
      { type = "metric", x = 0, y = 1, width = 8, height = 3, properties = { metrics = [["AWS/NetworkELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.turbo.arn_suffix, "LoadBalancer", aws_lb.nlb.arn_suffix, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Healthy Turbo Targets", period = 60 } },
      { type = "metric", x = 8, y = 1, width = 8, height = 3, properties = { metrics = [["AWS/NetworkELB", "UnHealthyHostCount", "TargetGroup", aws_lb_target_group.turbo.arn_suffix, "LoadBalancer", aws_lb.nlb.arn_suffix, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Unhealthy Turbo Targets", period = 60 } },
      { type = "metric", x = 16, y = 1, width = 8, height = 3, properties = { metrics = [["AWS/NetworkELB", "ActiveFlowCount", "LoadBalancer", aws_lb.nlb.arn_suffix, { stat = "Average" }]], view = "singleValue", region = var.aws_region, title = "Active Flows", period = 300 } },
      { type = "metric", x = 0, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/NetworkELB", "ActiveFlowCount", "LoadBalancer", aws_lb.nlb.arn_suffix, { stat = "Average", label = "Active" }], [".", "NewFlowCount", ".", ".", { stat = "Sum", label = "New" }]], view = "timeSeries", region = var.aws_region, title = "NLB Connection Flows", period = 300 } },
      { type = "metric", x = 12, y = 4, width = 12, height = 5, properties = { metrics = [["AWS/NetworkELB", "ProcessedBytes", "LoadBalancer", aws_lb.nlb.arn_suffix, { stat = "Sum" }]], view = "timeSeries", region = var.aws_region, title = "NLB Processed Bytes", period = 300 } }
    ]
  })
}

# Dashboard 5: Alarms Overview - ALL ALARMS
resource "aws_cloudwatch_dashboard" "alarms_overview" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.project_name}-alarms-overview"

  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "# Alarms - Complete Inventory (${length(local.all_alarm_arns)} Total)" } },
      { type = "alarm", x = 0, y = 1, width = 24, height = 10, properties = { title = "All Configured Alarms", alarms = local.all_alarm_arns } }
    ]
  })
}