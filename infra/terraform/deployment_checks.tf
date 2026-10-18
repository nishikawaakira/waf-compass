resource "terraform_data" "deployment_inputs" {
  input = var.deploy_application
  lifecycle {
    precondition {
      condition = !var.deploy_application || (
        var.worker_image_uri != "" && var.probe_image_uri != "" &&
        var.turnstile_site_key != "" && var.turnstile_secret_arn != "" &&
        var.bedrock_model_id != "" && var.bedrock_model_arn != "" &&
        var.bedrock_input_micro_usd_per_million > 0 &&
        var.bedrock_output_micro_usd_per_million > 0 &&
        var.max_input_tokens > 0 && var.max_output_tokens > 0
      )
      error_message = "Deployment requires both image URIs, Turnstile keys, Bedrock model ARN/ID, positive prices, and token limits."
    }
  }
}
