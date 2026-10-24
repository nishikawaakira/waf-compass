output "name_servers" {
  value       = aws_route53_zone.site.name_servers
  description = "Add these NS records to the parent i-wind.jp zone for waf.i-wind.jp."
}
output "worker_repository_url" {
  value = aws_ecr_repository.worker.repository_url
}
output "probe_repository_url" {
  value = aws_ecr_repository.probe.repository_url
}
output "cloudfront_domain" {
  value = var.deploy_application ? aws_cloudfront_distribution.web[0].domain_name : null
}
output "service_url" {
  value = var.deploy_application ? "https://${var.domain_name}" : null
}
output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.users.id
}
output "cognito_client_id" {
  value = aws_cognito_user_pool_client.web.id
}
output "access_log_bucket" {
  value = aws_s3_bucket.access_logs.bucket
}
output "athena_workgroup" {
  value = aws_athena_workgroup.analytics.name
}
output "athena_table" {
  value = var.deploy_application ? "${aws_glue_catalog_database.analytics.name}.${aws_glue_catalog_table.cloudfront_access[0].name}" : null
}
