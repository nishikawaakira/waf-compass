provider "aws" {
  region = var.aws_region
}
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
}
provider "awscc" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  prefix        = var.name
  deploy        = var.deploy_application
  public_origin = "https://${var.domain_name}"
  account       = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  tags = {
    Project = var.name, ManagedBy = "Terraform"
  }
}

resource "aws_route53_zone" "site" {
  name = var.domain_name
  tags = local.tags
}

resource "aws_acm_certificate" "site" {
  count             = local.deploy ? 1 : 0
  provider          = aws.use1
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
  tags = local.tags
}
resource "aws_route53_record" "certificate" {
  for_each = local.deploy ? {
    for d in aws_acm_certificate.site[0].domain_validation_options : d.domain_name => d
  } : {}
  zone_id         = aws_route53_zone.site.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  ttl             = 60
  records         = [each.value.resource_record_value]
  allow_overwrite = true
}
resource "aws_acm_certificate_validation" "site" {
  count                   = local.deploy ? 1 : 0
  provider                = aws.use1
  certificate_arn         = aws_acm_certificate.site[0].arn
  validation_record_fqdns = [for r in aws_route53_record.certificate : r.fqdn]
}

resource "aws_s3_bucket" "jobs" {
  bucket_prefix = "${local.prefix}-jobs-"
  force_destroy = false
  tags          = local.tags
}
resource "aws_s3_bucket" "results" {
  bucket_prefix = "${local.prefix}-results-"
  force_destroy = false
  tags          = local.tags
}
resource "aws_s3_bucket" "code" {
  bucket_prefix = "${local.prefix}-code-"
  force_destroy = false
  tags          = local.tags
}
resource "aws_s3_bucket_public_access_block" "private" {
  for_each = {
    jobs = aws_s3_bucket.jobs.id, results = aws_s3_bucket.results.id, code = aws_s3_bucket.code.id
  }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  for_each = {
    jobs = aws_s3_bucket.jobs.id, results = aws_s3_bucket.results.id, code = aws_s3_bucket.code.id
  }
  bucket = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "code" {
  bucket = aws_s3_bucket.code.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "jobs" {
  bucket = aws_s3_bucket.jobs.id
  rule {
    id     = "expire-jobs"
    status = "Enabled"
    expiration {
      days = 7
    }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}
resource "aws_s3_bucket_policy" "code" {
  bucket = aws_s3_bucket.code.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Sid = "WebFunctionCodeRead", Effect = "Allow", Principal = {
        Service = "lambda.amazonaws.com"
        }, Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${aws_s3_bucket.code.arn}/web/*", Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:${local.partition}:lambda:${var.aws_region}:${local.account}:web-function/${local.prefix}/revision/*"
        }
      }
    }]
  })
}

resource "aws_dynamodb_table" "budget" {
  name         = "${local.prefix}-budget"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  tags = local.tags
}

resource "aws_ecr_repository" "worker" {
  name = "${local.prefix}-worker"
  image_scanning_configuration {
    scan_on_push = true
  }
  force_delete = false
  tags         = local.tags
}
resource "aws_ecr_repository" "probe" {
  name = "${local.prefix}-probe"
  image_scanning_configuration {
    scan_on_push = true
  }
  force_delete = false
  tags         = local.tags
}
resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1, description = "Keep last ten images", selection = {
        tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10
        }, action = {
        type = "expire"
      }
    }]
  })
}
resource "aws_ecr_lifecycle_policy" "probe" {
  repository = aws_ecr_repository.probe.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1, description = "Keep last ten images", selection = {
        tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10
        }, action = {
        type = "expire"
      }
    }]
  })
}
resource "aws_ecs_cluster" "this" {
  name = local.prefix
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
  tags = local.tags
}
