variable "aws_region" {
  type    = string
  default = "ap-northeast-1"
}
variable "name" {
  type    = string
  default = "waf-rule-evaluations"
}
variable "domain_name" {
  type    = string
  default = "waf.i-wind.jp"
}
variable "deploy_application" {
  type        = bool
  default     = false
  description = "Set true after DNS delegation, container pushes, and web ZIP packaging."
}
variable "worker_image_uri" {
  type    = string
  default = ""
}
variable "probe_image_uri" {
  type    = string
  default = ""
}
variable "web_code_zip" {
  type    = string
  default = "build/web.zip"
}
variable "cognito_domain_prefix" {
  type        = string
  description = "Globally unique Cognito managed-login prefix."
}
variable "turnstile_site_key" {
  type    = string
  default = ""
}
variable "turnstile_secret_arn" {
  type        = string
  default     = ""
  description = "Existing Secrets Manager secret ARN. Never put the secret value in Terraform state."
}
variable "bedrock_model_id" {
  type    = string
  default = ""
}
variable "bedrock_model_arn" {
  type        = string
  default     = ""
  description = "IAM ARN of the model or inference profile used by the worker."
}
variable "bedrock_input_micro_usd_per_million" {
  type    = number
  default = 0
}
variable "bedrock_output_micro_usd_per_million" {
  type    = number
  default = 0
}
variable "max_input_tokens" {
  type    = number
  default = 200000
}
variable "max_output_tokens" {
  type    = number
  default = 2048
}
variable "enable_aws_waf" {
  type    = bool
  default = false
}
