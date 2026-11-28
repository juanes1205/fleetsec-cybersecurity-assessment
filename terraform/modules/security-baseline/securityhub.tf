# -----------------------------------------------------------------------------
# AWS Security Hub Account & Standard Subscriptions
# -----------------------------------------------------------------------------
resource "aws_securityhub_account" "main" {
  enable_default_standards = false
  control_finding_generator = "SECURITY_CONTROL"
}

# AWS Foundational Security Best Practices (FSBP)
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# CIS AWS Foundations Benchmark v1.4.0
resource "aws_securityhub_standards_subscription" "cis_aws_1_4" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}
