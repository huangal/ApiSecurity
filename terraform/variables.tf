variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "oauth-m2m"
}

variable "cognito_domain_prefix" {
  description = "Prefix for the Cognito hosted UI domain (must be globally unique)"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for the API Gateway custom domain (must be in the same region)"
  type        = string
}

variable "truststore_s3_version" {
  description = "S3 version ID of the mTLS truststore PEM object in the truststore bucket"
  type        = string
  default     = null
}

variable "lambda_zip_path" {
  description = "Local path to the zipped Lambda deployment package"
  type        = string
  default     = "../lambda/token_proxy.zip"
}

variable "waf_rate_limit" {
  description = "Maximum requests per 5-minute window per IP on /oauth2/token"
  type        = number
  default     = 100
}

# AMAZON IP ranges for the region — bootstrap values.
# Kept up-to-date automatically by the ip-range-updater Lambda.
variable "amazon_ip_ranges" {
  description = "AWS AMAZON service IP ranges for the deployed region (IPv4 CIDRs)"
  type        = list(string)
  default = [
    "3.80.0.0/12",
    "34.192.0.0/12",
    "52.0.0.0/11",
    "54.144.0.0/12",
    "18.208.0.0/13",
    "52.72.0.0/15",
  ]
}

variable "trusted_ca_dns" {
  description = "List of trusted client certificate Subject Distinguished Names for the Lambda Authorizer whitelist"
  type        = list(string)
  default     = []
  # Example:
  # trusted_ca_dns = [
  #   "CN=My Corp CA,O=My Corp,C=US",
  #   "CN=Partner CA,O=Partner Inc,C=GB"
  # ]
}

variable "tags" {
  description = "Additional tags applied to all resources"
  type        = map(string)
  default     = {}
}
