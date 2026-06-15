# ─────────────────────────────────────────────────────────────────────────────
# IP Set — AWS AMAZON IP ranges for the region (secondary defense)
# Updated automatically by the ip-range-updater Lambda via the AWS SNS topic.
# Bootstrap values are supplied via var.amazon_ip_ranges.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_wafv2_ip_set" "api_gateway_ips" {
  name               = "${local.name_prefix}-api-gateway-ip-ranges"
  description        = "AWS AMAZON service IP ranges for ${var.aws_region}. Refreshed by ip-range-updater Lambda."
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.amazon_ip_ranges

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# WAF Web ACL — attached to the Cognito User Pool
# Default action: BLOCK. Only requests that match an Allow rule proceed.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_wafv2_web_acl" "cognito_user_pool" {
  name        = "${local.name_prefix}-cognito-protection"
  scope       = "REGIONAL"
  description = "Restricts Cognito /oauth2/token to requests from the API Gateway Lambda proxy only."

  default_action {
    block {
      custom_response {
        response_code            = 403
        custom_response_body_key = "forbidden_body"
      }
    }
  }

  custom_response_body {
    key          = "forbidden_body"
    content_type = "APPLICATION_JSON"
    content = jsonencode({
      error             = "access_denied"
      error_description = "Direct access to this endpoint is not permitted."
    })
  }

  # ── Rule 1 (Priority 1): AWS Managed Common Rule Set ──────────────────────
  # Baseline OWASP protection — SQLi, XSS, bad inputs.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Cognito token POST body is always small; counting avoids false-positives.
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use { count {} }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-AWSManagedCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 2 (Priority 2): Block non /oauth2/token paths ────────────────────
  # The WAF protects the whole User Pool domain; restrict to the token endpoint only.
  rule {
    name     = "AllowOnlyOAuthTokenPath"
    priority = 2

    action {
      block {}
    }

    statement {
      not_statement {
        statement {
          byte_match_statement {
            search_string         = "/oauth2/token"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-BlockNonOAuthPath"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 3 (Priority 3): Require the internal secret header ───────────────
  # Primary gate. Lambda proxy injects X-Internal-Token: <secret>.
  # Any caller without the exact secret is blocked — including direct internet calls.
  rule {
    name     = "RequireInternalSecretHeader"
    priority = 3

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string         = random_password.waf_internal_secret.result
        positional_constraint = "EXACTLY"

        field_to_match {
          single_header {
            name = "x-internal-token"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-RequireInternalHeader"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 4 (Priority 4): Allow AWS AMAZON IP ranges ──────────────────────
  # Belt-and-suspenders. Even if the secret somehow leaks, the source IP
  # must still fall within AWS-owned address space.
  rule {
    name     = "AllowAmazonIPRanges"
    priority = 4

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.api_gateway_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-AllowAmazonIPs"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 5 (Priority 5): Rate limit /oauth2/token per IP ─────────────────
  # Mitigates brute-force and credential-stuffing attacks.
  rule {
    name     = "RateLimitTokenEndpoint"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/oauth2/token"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-RateLimitToken"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-CognitoUserPoolWAF"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch Log Group for WAF full request logging
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "waf" {
  # WAF log group names MUST start with "aws-waf-logs-"
  name              = "aws-waf-logs-${local.name_prefix}-cognito"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_wafv2_web_acl_logging_configuration" "cognito" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.cognito_user_pool.arn

  # Strip the secret header value from logs — never log credentials
  redacted_fields {
    single_header {
      name = "x-internal-token"
    }
  }
}
