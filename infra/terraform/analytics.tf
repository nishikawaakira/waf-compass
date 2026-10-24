# CloudFront standard logging v2 is configured in us-east-1 even when the
# private destination bucket and Athena catalog live in the application Region.
resource "aws_s3_bucket" "access_logs" {
  bucket_prefix = "${local.prefix}-access-logs-"
  force_destroy = false
  tags          = local.tags
}

resource "aws_s3_bucket" "athena_results" {
  bucket_prefix = "${local.prefix}-athena-results-"
  force_destroy = false
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  for_each = {
    access_logs    = aws_s3_bucket.access_logs.id
    athena_results = aws_s3_bucket.athena_results.id
  }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  for_each = {
    access_logs    = aws_s3_bucket.access_logs.id
    athena_results = aws_s3_bucket.athena_results.id
  }
  bucket = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-access-logs-after-30-days"
    status = "Enabled"
    expiration { days = 30 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-query-results-after-7-days"
    status = "Enabled"
    expiration { days = 7 }
  }
}

resource "aws_cloudwatch_log_delivery_source" "cloudfront" {
  count        = local.deploy ? 1 : 0
  provider     = aws.use1
  name         = "${local.prefix}-cloudfront-access"
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.web[0].arn
  tags         = local.tags
}

resource "aws_s3_bucket_policy" "access_logs" {
  count  = local.deploy ? 1 : 0
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudFrontV2DeliveryBucketCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.access_logs.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account }
          ArnLike      = { "aws:SourceArn" = aws_cloudwatch_log_delivery_source.cloudfront[0].arn }
        }
      },
      {
        Sid       = "CloudFrontV2DeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/AWSLogs/${local.account}/CloudFront/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account
            "s3:x-amz-acl"      = "bucket-owner-full-control"
          }
          ArnLike = { "aws:SourceArn" = aws_cloudwatch_log_delivery_source.cloudfront[0].arn }
        }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.analytics]
}

resource "aws_cloudwatch_log_delivery_destination" "access_logs" {
  count         = local.deploy ? 1 : 0
  provider      = aws.use1
  name          = "${local.prefix}-s3-access"
  output_format = "json"
  delivery_destination_configuration {
    destination_resource_arn = aws_s3_bucket.access_logs.arn
  }
  tags       = local.tags
  depends_on = [aws_s3_bucket_policy.access_logs]
}

resource "aws_cloudwatch_log_delivery" "access_logs" {
  count                    = local.deploy ? 1 : 0
  provider                 = aws.use1
  delivery_source_name     = aws_cloudwatch_log_delivery_source.cloudfront[0].name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.access_logs[0].arn
  record_fields = [
    "date", "time", "c-ip", "cs-method", "cs-uri-stem", "sc-status",
    "cs(User-Agent)", "x-edge-result-type", "x-edge-detailed-result-type"
  ]
  s3_delivery_configuration = [{
    enable_hive_compatible_path = false
    suffix_path                 = "{distributionid}/{yyyy}/{MM}/{dd}/{HH}"
  }]
  tags = local.tags
}

resource "aws_glue_catalog_database" "analytics" {
  name = replace(local.prefix, "-", "_")
}

resource "aws_glue_catalog_table" "cloudfront_access" {
  count         = local.deploy ? 1 : 0
  name          = "cloudfront_access_logs"
  database_name = aws_glue_catalog_database.analytics.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    EXTERNAL                           = "TRUE"
    "projection.enabled"               = "true"
    "projection.distributionid.type"   = "enum"
    "projection.distributionid.values" = aws_cloudfront_distribution.web[0].id
    "projection.year.type"             = "integer"
    "projection.year.range"            = "2026,2035"
    "projection.month.type"            = "integer"
    "projection.month.range"           = "1,12"
    "projection.month.digits"          = "2"
    "projection.day.type"              = "integer"
    "projection.day.range"             = "1,31"
    "projection.day.digits"            = "2"
    "projection.hour.type"             = "integer"
    "projection.hour.range"            = "0,23"
    "projection.hour.digits"           = "2"
    "storage.location.template"        = "s3://${aws_s3_bucket.access_logs.bucket}/AWSLogs/${local.account}/CloudFront/$${distributionid}/$${year}/$${month}/$${day}/$${hour}/"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.access_logs.bucket}/AWSLogs/${local.account}/CloudFront/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    ser_de_info {
      name                  = "cloudfront-json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        paths = "date,time,c-ip,cs-method,cs-uri-stem,sc-status,cs(User-Agent),x-edge-result-type,x-edge-detailed-result-type"
      }
    }
    columns {

      name = "date"

      type = "string"

    }
    columns {

      name = "time"

      type = "string"

    }
    columns {

      name = "c-ip"

      type = "string"

    }
    columns {

      name = "cs-method"

      type = "string"

    }
    columns {

      name = "cs-uri-stem"

      type = "string"

    }
    columns {

      name = "sc-status"

      type = "string"

    }
    columns {

      name = "cs(User-Agent)"

      type = "string"

    }
    columns {

      name = "x-edge-result-type"

      type = "string"

    }
    columns {

      name = "x-edge-detailed-result-type"

      type = "string"

    }
  }
  partition_keys {

    name = "distributionid"

    type = "string"

  }
  partition_keys {

    name = "year"

    type = "string"

  }
  partition_keys {

    name = "month"

    type = "string"

  }
  partition_keys {

    name = "day"

    type = "string"

  }
  partition_keys {

    name = "hour"

    type = "string"

  }
}

resource "aws_athena_workgroup" "analytics" {
  name          = "${local.prefix}-analytics"
  force_destroy = false
  configuration {
    enforce_workgroup_configuration    = true
    bytes_scanned_cutoff_per_query     = 1073741824
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
  tags = local.tags
}
