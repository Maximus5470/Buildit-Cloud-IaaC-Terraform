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