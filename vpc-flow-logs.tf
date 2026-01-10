# ============================================================================
# VPC FLOW LOGS - S3 DESTINATION (COST-OPTIMIZED)
# ============================================================================

# Data source for AWS account ID
data "aws_caller_identity" "current" {}

# S3 Bucket for Flow Logs
resource "aws_s3_bucket" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = "${var.project_name}-vpc-flow-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name    = "${var.project_name}-vpc-flow-logs"
      Purpose = "VPC Flow Logs Storage"
    }
  )
}

# Enable versioning (best practice for data protection)
resource "aws_s3_bucket_versioning" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.flow_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy to manage costs
resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.flow_logs[0].id

  rule {
    id     = "transition-and-expire"
    status = "Enabled"

    filter {}

    # Move to Infrequent Access after 30 days (50% cost reduction)
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Move to Glacier after 60 days (80% cost reduction)
    transition {
      days          = 60
      storage_class = "GLACIER_IR"
    }

    # Delete after retention period
    expiration {
      days = var.flow_logs_retention_days
    }

    # Clean up incomplete multipart uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "delete-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Block all public access (security best practice)
resource "aws_s3_bucket_public_access_block" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.flow_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.flow_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Policy for Flow Logs Service
resource "aws_s3_bucket_policy" "flow_logs" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.flow_logs[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.flow_logs[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# VPC Flow Log - Optimized Log Format (reduces storage costs)
resource "aws_flow_log" "vpc" {
  count                = var.enable_vpc_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.flow_logs[0].arn
  log_destination_type = "s3"
  traffic_type         = var.flow_logs_traffic_type
  vpc_id               = aws_vpc.main.id

  # Custom log format - only essential fields to reduce volume
  log_format = "$${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  # Organize logs by date for easier querying
  destination_options {
    file_format        = "parquet"  # More efficient than plain text
    per_hour_partition = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-vpc-flow-log"
    }
  )

  depends_on = [aws_s3_bucket_policy.flow_logs]
}

# ============================================================================
# ATHENA CONFIGURATION FOR QUERYING FLOW LOGS
# ============================================================================

# S3 Bucket for Athena query results
resource "aws_s3_bucket" "athena_results" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = "${var.project_name}-athena-results-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name    = "${var.project_name}-athena-results"
      Purpose = "Athena Query Results"
    }
  )
}

# Lifecycle policy for Athena results (auto-delete old queries)
resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  rule {
    id     = "delete-old-results"
    status = "Enabled"

    filter {}

    expiration {
      days = 30  # Delete query results after 30 days
    }
  }
}

# Block public access for Athena results
resource "aws_s3_bucket_public_access_block" "athena_results" {
  count  = var.enable_vpc_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Athena Workgroup for Flow Logs queries
resource "aws_athena_workgroup" "flow_logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${var.project_name}-flow-logs"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false  # Save costs

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results[0].bucket}/flow-logs/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-flow-logs-workgroup"
    }
  )
}

# Glue Database for Flow Logs
resource "aws_glue_catalog_database" "flow_logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${replace(var.project_name, "-", "_")}_flow_logs"

  description = "Database for VPC Flow Logs analysis"
}

# Glue Table for Flow Logs (Parquet format)
resource "aws_glue_catalog_table" "flow_logs" {
  count         = var.enable_vpc_flow_logs ? 1 : 0
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.flow_logs[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "parquet.compression"   = "SNAPPY"
    "projection.enabled"    = "true"
    "projection.dt.type"    = "date"
    "projection.dt.range"   = "2025/01/01,NOW"
    "projection.dt.format"  = "yyyy/MM/dd"
    "storage.location.template" = "s3://${aws_s3_bucket.flow_logs[0].bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/vpcflowlogs/${var.aws_region}/$${dt}"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.flow_logs[0].bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/vpcflowlogs/${var.aws_region}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "interface_id"
      type = "string"
    }
    columns {
      name = "srcaddr"
      type = "string"
    }
    columns {
      name = "dstaddr"
      type = "string"
    }
    columns {
      name = "srcport"
      type = "int"
    }
    columns {
      name = "dstport"
      type = "int"
    }
    columns {
      name = "protocol"
      type = "int"
    }
    columns {
      name = "packets"
      type = "bigint"
    }
    columns {
      name = "bytes"
      type = "bigint"
    }
    columns {
      name = "start"
      type = "bigint"
    }
    columns {
      name = "end"
      type = "bigint"
    }
    columns {
      name = "action"
      type = "string"
    }
    columns {
      name = "log_status"
      type = "string"
    }
  }

  partition_keys {
    name = "dt"
    type = "string"
  }
}