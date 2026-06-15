# ─────────────────────────────────────────────────────────────────────────────
# IAM Role — Token Proxy Lambda
# ─────────────────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "token_proxy_lambda" {
  name               = "${local.name_prefix}-token-proxy-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "token_proxy_lambda" {
  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Read the WAF internal secret from SSM
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.waf_internal_secret.arn]
  }
}

resource "aws_iam_role_policy" "token_proxy_lambda" {
  name   = "${local.name_prefix}-token-proxy-policy"
  role   = aws_iam_role.token_proxy_lambda.id
  policy = data.aws_iam_policy_document.token_proxy_lambda.json
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda — Token Proxy Function
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "token_proxy" {
  function_name = "${local.name_prefix}-token-proxy"
  description   = "Decodes Basic Auth, injects WAF secret header, proxies /oauth2/token to Cognito."
  role          = aws_iam_role.token_proxy_lambda.arn
  runtime       = "python3.12"
  handler       = "token_proxy.lambda_handler"
  filename      = var.lambda_zip_path
  timeout       = 10
  memory_size   = 128

  environment {
    variables = {
      COGNITO_DOMAIN      = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"
      WAF_SECRET_SSM_PATH = aws_ssm_parameter.waf_internal_secret.name
    }
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy.token_proxy_lambda]
}

resource "aws_cloudwatch_log_group" "token_proxy_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.token_proxy.function_name}"
  retention_in_days = 14

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM Role — Lambda Authorizer
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_authorizer" {
  name               = "${local.name_prefix}-lambda-authorizer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "lambda_authorizer" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.trusted_ca_dns.arn]
  }
}

resource "aws_iam_role_policy" "lambda_authorizer" {
  name   = "${local.name_prefix}-lambda-authorizer-policy"
  role   = aws_iam_role.lambda_authorizer.id
  policy = data.aws_iam_policy_document.lambda_authorizer.json
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda — Request-type Authorizer (validates mTLS client cert DN)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "lambda_authorizer" {
  function_name = "${local.name_prefix}-lambda-authorizer"
  description   = "REQUEST-type API Gateway authorizer. Validates client cert DN against trusted CA whitelist."
  role          = aws_iam_role.lambda_authorizer.arn
  runtime       = "python3.12"
  handler       = "authorizer.lambda_handler"
  filename      = var.lambda_zip_path
  timeout       = 5
  memory_size   = 128

  environment {
    variables = {
      SSM_TRUSTED_DNS_PATH = aws_ssm_parameter.trusted_ca_dns.name
      LOG_LEVEL            = "INFO"
    }
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy.lambda_authorizer]
}

resource "aws_cloudwatch_log_group" "lambda_authorizer" {
  name              = "/aws/lambda/${aws_lambda_function.lambda_authorizer.function_name}"
  retention_in_days = 14

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# IP Range Updater — keeps the WAF IP set current when AWS publishes new ranges
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "ip_range_updater" {
  name               = "${local.name_prefix}-ip-range-updater-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "ip_range_updater" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet",
    ]
    resources = [aws_wafv2_ip_set.api_gateway_ips.arn]
  }
}

resource "aws_iam_role_policy" "ip_range_updater" {
  name   = "${local.name_prefix}-ip-range-updater-policy"
  role   = aws_iam_role.ip_range_updater.id
  policy = data.aws_iam_policy_document.ip_range_updater.json
}

resource "aws_lambda_function" "ip_range_updater" {
  function_name = "${local.name_prefix}-ip-range-updater"
  description   = "Refreshes the WAF IP set when AWS publishes updated AMAZON IP ranges."
  role          = aws_iam_role.ip_range_updater.arn
  runtime       = "python3.12"
  handler       = "ip_range_updater.lambda_handler"
  filename      = var.lambda_zip_path
  timeout       = 30
  memory_size   = 128

  environment {
    variables = {
      WAF_IP_SET_ID    = aws_wafv2_ip_set.api_gateway_ips.id
      WAF_IP_SET_NAME  = aws_wafv2_ip_set.api_gateway_ips.name
      WAF_IP_SET_SCOPE = "REGIONAL"
      AWS_REGION_FILTER = var.aws_region
    }
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy.ip_range_updater]
}

resource "aws_cloudwatch_log_group" "ip_range_updater" {
  name              = "/aws/lambda/${aws_lambda_function.ip_range_updater.function_name}"
  retention_in_days = 14

  tags = local.common_tags
}
