# ─────────────────────────────────────────────────────────────────────────────
# REST API — mTLS token proxy endpoint
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_api_gateway_rest_api" "token_proxy" {
  name        = "${local.name_prefix}-token-proxy"
  description = "Exposes POST /token with mTLS; proxies requests to Cognito via Lambda."

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = local.common_tags
}

# /token resource
resource "aws_api_gateway_resource" "token" {
  rest_api_id = aws_api_gateway_rest_api.token_proxy.id
  parent_id   = aws_api_gateway_rest_api.token_proxy.root_resource_id
  path_part   = "token"
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda Authorizer — REQUEST type (validates mTLS client cert DN)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_api_gateway_authorizer" "lambda_authorizer" {
  name                             = "${local.name_prefix}-cert-dn-authorizer"
  rest_api_id                      = aws_api_gateway_rest_api.token_proxy.id
  authorizer_uri                   = aws_lambda_function.lambda_authorizer.invoke_arn
  authorizer_result_ttl_in_seconds = 0   # No caching — each cert DN checked fresh
  type                             = "REQUEST"
  identity_source                  = "context.identity.clientCert.subjectDN"
}

# Grant API Gateway permission to invoke the authorizer Lambda
resource "aws_lambda_permission" "authorizer_api_gateway" {
  statement_id  = "AllowAPIGatewayInvokeAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.token_proxy.execution_arn}/authorizers/${aws_api_gateway_authorizer.lambda_authorizer.id}"
}

# ─────────────────────────────────────────────────────────────────────────────
# POST /token method — protected by the Lambda authorizer
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_api_gateway_method" "post_token" {
  rest_api_id   = aws_api_gateway_rest_api.token_proxy.id
  resource_id   = aws_api_gateway_resource.token.id
  http_method   = "POST"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.lambda_authorizer.id

  request_parameters = {
    "method.request.header.Authorization" = true
  }
}

# Lambda proxy integration
resource "aws_api_gateway_integration" "post_token" {
  rest_api_id             = aws_api_gateway_rest_api.token_proxy.id
  resource_id             = aws_api_gateway_resource.token.id
  http_method             = aws_api_gateway_method.post_token.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.token_proxy.invoke_arn
}

# Grant API Gateway permission to invoke the backend Lambda
resource "aws_lambda_permission" "token_proxy_api_gateway" {
  statement_id  = "AllowAPIGatewayInvokeTokenProxy"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.token_proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.token_proxy.execution_arn}/*/POST/token"
}

# ─────────────────────────────────────────────────────────────────────────────
# Deployment & Stage
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_api_gateway_deployment" "token_proxy" {
  rest_api_id = aws_api_gateway_rest_api.token_proxy.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.token,
      aws_api_gateway_method.post_token,
      aws_api_gateway_integration.post_token,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "token_proxy" {
  deployment_id = aws_api_gateway_deployment.token_proxy.id
  rest_api_id   = aws_api_gateway_rest_api.token_proxy.id
  stage_name    = var.environment

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/api-gateway/${local.name_prefix}-token-proxy"
  retention_in_days = 14

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# mTLS — custom domain with truststore
# The truststore S3 object must contain the PEM-encoded trusted CA certificates.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "truststore" {
  bucket = "${local.name_prefix}-mtls-truststore"

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "truststore" {
  bucket = aws_s3_bucket.truststore.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_api_gateway_domain_name" "token_proxy" {
  domain_name              = "token.${var.cognito_domain_prefix}.example.com"
  regional_certificate_arn = var.acm_certificate_arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  mutual_tls_authentication {
    truststore_uri     = "s3://${aws_s3_bucket.truststore.bucket}/truststore.pem"
    truststore_version = var.truststore_s3_version
  }

  tags = local.common_tags
}

resource "aws_api_gateway_base_path_mapping" "token_proxy" {
  api_id      = aws_api_gateway_rest_api.token_proxy.id
  stage_name  = aws_api_gateway_stage.token_proxy.stage_name
  domain_name = aws_api_gateway_domain_name.token_proxy.domain_name
}

# ─────────────────────────────────────────────────────────────────────────────
# SNS subscription — refresh IP set when AWS publishes new ranges
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_permission" "ip_range_updater_sns" {
  statement_id  = "AllowSNSInvokeIPRangeUpdater"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ip_range_updater.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged"
}

resource "aws_sns_topic_subscription" "ip_ranges_update" {
  topic_arn = "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged"
  protocol  = "lambda"
  endpoint  = aws_lambda_function.ip_range_updater.arn
}
