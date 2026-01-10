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
  name                    = "${var.project_name}-db-credentials"
  description             = "Database credentials for RDS PostgreSQL"
  recovery_window_in_days = 0

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

