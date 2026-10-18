resource "aws_s3_object" "web_code" {
  count      = local.deploy ? 1 : 0
  bucket     = aws_s3_bucket.code.bucket
  key        = "web/${filemd5("${path.module}/${var.web_code_zip}")}.zip"
  source     = "${path.module}/${var.web_code_zip}"
  etag       = filemd5("${path.module}/${var.web_code_zip}")
  depends_on = [aws_s3_bucket_versioning.code]
}
resource "awscc_lambda_web_function" "web" {
  count         = local.deploy ? 1 : 0
  function_name = local.prefix
  tags = [{
    key = "Project", value = var.name
  }]
}
resource "awscc_lambda_web_function_revision" "web" {
  count         = local.deploy ? 1 : 0
  function_name = awscc_lambda_web_function.web[0].function_name
  lifecycle {
    create_before_destroy = true
  }
  build_config = {
    code_config = {
      s3_object = {
        bucket = aws_s3_bucket.code.bucket, key = aws_s3_object.web_code[0].key, version_id = aws_s3_object.web_code[0].version_id
      }
    }
    runtime_config = {
      runtime = "nodejs24.x"
    }

  }
  service_config = {
    execution_role_arn              = aws_iam_role.web.arn
    timeout_seconds                 = 30
    max_concurrency_per_environment = 10
    environment_variables = {
      APP_AWS_REGION         = var.aws_region
      PUBLIC_ORIGIN          = local.public_origin
      COGNITO_DOMAIN         = "${var.cognito_domain_prefix}.auth.${var.aws_region}.amazoncognito.com"
      COGNITO_CLIENT_ID      = aws_cognito_user_pool_client.web.id
      COGNITO_USER_POOL_ID   = aws_cognito_user_pool.users.id
      JOB_BUCKET             = aws_s3_bucket.jobs.bucket
      RESULT_BUCKET          = aws_s3_bucket.results.bucket
      BUDGET_TABLE           = aws_dynamodb_table.budget.name
      ECS_CLUSTER            = aws_ecs_cluster.this.arn
      WORKER_TASK_DEFINITION = aws_ecs_task_definition.worker[0].arn
      WORKER_SUBNET          = aws_subnet.worker.id
      WORKER_SECURITY_GROUP  = aws_security_group.worker.id
      TURNSTILE_SITE_KEY     = var.turnstile_site_key
      TURNSTILE_SECRET_ARN   = var.turnstile_secret_arn

    }
    telemetry_config = {
      logging_config = {
        log_group = aws_cloudwatch_log_group.web.name
      }
    }

  }
  depends_on = [aws_iam_role_policy.web, aws_s3_bucket_policy.code]
}
resource "awscc_lambda_web_function_endpoint" "web" {
  count         = local.deploy ? 1 : 0
  function_name = awscc_lambda_web_function.web[0].function_name
  endpoint_name = "prod"
  endpoint_type = "HomeRegion"
  auth_type     = "IamAuth"
  revision_weights = [{
    revision_id = awscc_lambda_web_function_revision.web[0].revision_id, weight = 100
  }]
  scaling_config = {
    max_environments = 2
  }
  throttle_config = {
    rate_limit = 100
  }
}
resource "aws_cloudfront_origin_access_control" "web" {
  count                             = local.deploy ? 1 : 0
  name                              = "${local.prefix}-web"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always-amz-auth"
  signing_protocol                  = "sigv4"
}
data "aws_cloudfront_cache_policy" "disabled" {
  count = local.deploy ? 1 : 0
  name  = "Managed-CachingDisabled"
}
data "aws_cloudfront_origin_request_policy" "all_except_host" {
  count = local.deploy ? 1 : 0
  name  = "Managed-AllViewerExceptHostHeader"
}
resource "aws_wafv2_web_acl" "edge" {
  count    = local.deploy && var.enable_aws_waf ? 1 : 0
  provider = aws.use1
  name     = "${local.prefix}-edge"
  scope    = "CLOUDFRONT"
  default_action {
    allow {}
  }
  rule {
    name     = "rate-limit"
    priority = 0
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = false
    }

  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-edge"
    sampled_requests_enabled   = false
  }
  tags = local.tags
}
resource "aws_cloudfront_distribution" "web" {
  count           = local.deploy ? 1 : 0
  enabled         = true
  is_ipv6_enabled = true
  comment         = local.prefix
  aliases         = [var.domain_name]
  price_class     = "PriceClass_200"
  web_acl_id      = var.enable_aws_waf ? aws_wafv2_web_acl.edge[0].arn : null
  origin {
    domain_name              = awscc_lambda_web_function_endpoint.web[0].domain_name
    origin_id                = "lambda-web"
    origin_access_control_id = aws_cloudfront_origin_access_control.web[0].id
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

  }
  default_cache_behavior {
    target_origin_id         = "lambda-web"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled[0].id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_except_host[0].id
    compress                 = true

  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  tags = local.tags
}
resource "awscc_lambda_resource_policy" "cloudfront" {
  count        = local.deploy ? 1 : 0
  resource_arn = awscc_lambda_web_function.web[0].function_arn
  policy_document = jsonencode({
    Version = "2012-10-17", Statement = [{
      Sid = "AllowCloudFrontOAC", Effect = "Allow", Principal = {
        Service = "cloudfront.amazonaws.com"
        }, Action = "lambda:InvokeWebFunctionEndpoint", Resource = awscc_lambda_web_function_endpoint.web[0].endpoint_arn, Condition = {
        StringEquals = {
          "aws:SourceArn" = aws_cloudfront_distribution.web[0].arn
        }
      }
    }]
  })
}
resource "aws_route53_record" "site_a" {
  count   = local.deploy ? 1 : 0
  zone_id = aws_route53_zone.site.zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.web[0].domain_name
    zone_id                = aws_cloudfront_distribution.web[0].hosted_zone_id
    evaluate_target_health = false
  }
}
resource "aws_route53_record" "site_aaaa" {
  count   = local.deploy ? 1 : 0
  zone_id = aws_route53_zone.site.zone_id
  name    = var.domain_name
  type    = "AAAA"
  alias {
    name                   = aws_cloudfront_distribution.web[0].domain_name
    zone_id                = aws_cloudfront_distribution.web[0].hosted_zone_id
    evaluate_target_health = false
  }
}
