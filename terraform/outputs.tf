output "api_gateway_invoke_url" {
  description = "mTLS token endpoint URL (custom domain)"
  value       = "https://${aws_api_gateway_domain_name.token_proxy.domain_name}/token"
}

output "api_gateway_stage_url" {
  description = "Direct stage URL (use custom domain in production)"
  value       = aws_api_gateway_stage.token_proxy.invoke_url
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.main.arn
}

output "cognito_m2m_client_id" {
  description = "M2M app client ID"
  value       = aws_cognito_user_pool_client.m2m.id
}

output "cognito_m2m_client_secret" {
  description = "M2M app client secret (sensitive)"
  value       = aws_cognito_user_pool_client.m2m.client_secret
  sensitive   = true
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL attached to the Cognito User Pool"
  value       = aws_wafv2_web_acl.cognito_user_pool.arn
}

output "waf_ip_set_arn" {
  description = "ARN of the WAF IP set for AWS AMAZON ranges"
  value       = aws_wafv2_ip_set.api_gateway_ips.arn
}

output "truststore_bucket" {
  description = "S3 bucket for the mTLS truststore PEM — upload your trusted CA chain here"
  value       = aws_s3_bucket.truststore.bucket
}

output "waf_internal_secret_ssm_path" {
  description = "SSM parameter path for the WAF internal header secret (SecureString)"
  value       = aws_ssm_parameter.waf_internal_secret.name
}
