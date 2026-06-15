resource "aws_cognito_user_pool" "main" {
  name = "${local.name_prefix}-user-pool"

  # M2M flows do not use user sign-up or password auth
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # Disable standard user-facing auth schemes — only app clients (M2M) are used
  password_policy {
    minimum_length                   = 16
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  tags = local.common_tags
}

# Cognito hosted domain — exposes /oauth2/token endpoint
resource "aws_cognito_user_pool_domain" "main" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.main.id
}

# M2M app client — client_credentials grant only, no user flows
resource "aws_cognito_user_pool_client" "m2m" {
  name         = "${local.name_prefix}-m2m-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = true

  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["${aws_cognito_resource_server.api.identifier}/read"]
  supported_identity_providers         = ["COGNITO"]

  explicit_auth_flows = []
}

# Resource server defines the custom OAuth2 scopes
resource "aws_cognito_resource_server" "api" {
  identifier   = "https://api.${var.cognito_domain_prefix}.example.com"
  name         = "${local.name_prefix}-resource-server"
  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "read"
    scope_description = "Read access to the API"
  }
}

# Attach the WAF Web ACL to the Cognito User Pool
resource "aws_wafv2_web_acl_association" "cognito" {
  resource_arn = aws_cognito_user_pool.main.arn
  web_acl_arn  = aws_wafv2_web_acl.cognito_user_pool.arn
}
