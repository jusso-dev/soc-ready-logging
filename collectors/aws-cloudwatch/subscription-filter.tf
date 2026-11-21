# AWS Terraform Starter — Two-Stream Security Logging Filter
# Filters CloudWatch Logs on `$.stream = "security"` BEFORE Firehose delivery
# to an Object-Lock (WORM) S3 bucket in ap-southeast-2 (ready for Amazon Security Lake,
# Microsoft Sentinel S3/SQS CCF, or jusso-dev/Bower bower-cloud).

variable "app_log_group_name" {
  type        = string
  description = "Existing application CloudWatch Log Group (e.g., /aws/ecs/gov-grants-portal-prod)."
}

variable "security_archive_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for immutable WORM security event archive."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS CMK ARN encrypting security logs at rest (ACSC ISM-1815)."
}

resource "aws_s3_bucket" "security_archive" {
  bucket              = var.security_archive_bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "security_archive" {
  bucket                  = aws_s3_bucket.security_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "security_archive" {
  bucket = aws_s3_bucket.security_archive.id
  rule {
    default_retention {
      mode = "GOVERNANCE" # Use COMPLIANCE for strict immutable regulatory holds
      days = 400          # 12+ months searchable retention (ACSC ISM-1988)
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_archive" {
  bucket = aws_s3_bucket.security_archive.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_iam_role" "firehose_write_only" {
  name = "soc-security-firehose-write-only"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "firehose_write_only" {
  name = "s3-put-only"
  role = aws_iam_role.firehose_write_only.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:PutObject"]
        Resource = [aws_s3_bucket.security_archive.arn, "${aws_s3_bucket.security_archive.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [var.kms_key_arn]
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "security_events" {
  name        = "soc-security-events-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_write_only.arn
    bucket_arn          = aws_s3_bucket.security_archive.arn
    prefix              = "security-events/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "dead-letter/!{firehose:error-output-type}/year=!{timestamp:yyyy}/"
    buffering_interval  = 60
    buffering_size      = 5
    compression_format  = "GZIP"
    kms_key_arn         = var.kms_key_arn
  }
}

resource "aws_iam_role" "cw_to_firehose" {
  name = "soc-cw-logs-to-firehose"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "logs.ap-southeast-2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cw_to_firehose" {
  name = "put-firehose-record"
  role = aws_iam_role.cw_to_firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
      Resource = [aws_kinesis_firehose_delivery_stream.security_events.arn]
    }]
  })
}

# Only stream == "security" events ever leave CloudWatch into the SIEM archive
resource "aws_cloudwatch_log_subscription_filter" "security_stream_only" {
  name            = "soc-security-stream-only"
  log_group_name  = var.app_log_group_name
  filter_pattern  = "{ ($.stream = \"security\") && ($.severity != \"DEBUG\") && ($.severity != \"TRACE\") }"
  destination_arn = aws_kinesis_firehose_delivery_stream.security_events.arn
  role_arn        = aws_iam_role.cw_to_firehose.arn
}
