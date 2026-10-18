terraform {
  required_version = ">= 1.14.0"
  required_providers {
    aws = {
      source = "hashicorp/aws", version = "~> 6.0"
    }
    awscc = {
      source = "hashicorp/awscc", version = ">= 1.105.0, < 2.0.0"
    }
    archive = {
      source = "hashicorp/archive", version = "~> 2.0"
    }

  }
}
