# Generates a cryptographically random 64-char secret used as the
# internal WAF gate header value. Only the Lambda proxy knows this value.
resource "random_password" "waf_internal_secret" {
  length  = 64
  special = false
}

resource "aws_ssm_parameter" "waf_internal_secret" {
  name        = "/${local.name_prefix}/waf/internal-header-secret"
  description = "Secret injected by Lambda into X-Internal-Token header; validated by WAF on Cognito User Pool"
  type        = "SecureString"
  value       = random_password.waf_internal_secret.result

  tags = local.common_tags
}

# Trusted CA Distinguished Names whitelist consumed by the Lambda Authorizer.
# Value must be a JSON array of DN strings, e.g.:
#   ["CN=My Corp CA,O=My Corp,C=US","CN=Partner CA,O=Partner Inc,C=GB"]
# Update this parameter to add/remove trusted CAs without redeploying Lambda.
resource "aws_ssm_parameter" "trusted_ca_dns" {
  name        = "/${local.name_prefix}/authorizer/trusted-ca-dns"
  description = "JSON array of trusted client certificate Subject DNs for the Lambda Authorizer whitelist"
  type        = "SecureString"
  value       = jsonencode(var.trusted_ca_dns)

  tags = local.common_tags
}
