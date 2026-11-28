# -----------------------------------------------------------------------------
# AWS WAFv2 Regional Web ACL (Protecting ALB & APIs)
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "main" {
  name        = "${local.name_prefix}-web-acl"
  description = "FleetSec WAFv2 security protection with SQLi, Core Rules, Rate Limiting and Geo-blocking"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf-overall"
    sampled_requests_enabled   = true
  }

  # ---------------------------------------------------------------------------
  # Rule 1: Geographic Restriction (Priority 10)
  # Blocks traffic originating outside authorized fleet operating jurisdictions
  # (Colombia: CO, Peru: PE, United States: US).
  # ---------------------------------------------------------------------------
  rule {
    name     = "GeoMatchRestriction"
    priority = 10

    action {
      block {}
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = var.allowed_countries
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-waf-geomatch"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 2: Dedicated Auth Endpoint Rate Limiting (Priority 20)
  # Mitigates credential stuffing and brute force attacks on authentication.
  # Threshold: 1,000 requests per 5-minute rolling window per source IP.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AuthRateLimit"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.auth_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/auth"

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
      metric_name                = "${local.name_prefix}-waf-auth-ratelimit"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 3: AWS Managed Rules - SQL Injection Protection (Priority 30)
  # Enforced in BLOCK mode to prevent SQLi vectors in queries, forms and bodies.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-waf-sqli"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 4: AWS Managed Rules - Known Bad Inputs (Priority 40)
  # Enforced in BLOCK mode to reject known exploits, OS commands and LFI vectors.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-waf-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 5: AWS Managed Rules - Common Rule Set (Priority 50)
  # Core protection against OWASP Top 10 web vulnerabilities.
  # Justification for COUNT vs BLOCK:
  # - SizeRestrictions_BODY: set to COUNT to avoid false positives during bulk
  #   telemetry ingestion batches (>8KB) from connected vehicle IoT devices.
  # - All other Core rules remain in default BLOCK mode.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-waf-crs"
      sampled_requests_enabled   = true
    }
  }

  tags = merge(local.common_tags, {
    Purpose = "Edge web application firewall"
  })
}
