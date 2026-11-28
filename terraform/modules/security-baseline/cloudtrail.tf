# -----------------------------------------------------------------------------
# SNS Topic for Critical Security Alarms
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.service["ecs"].arn

  tags = merge(local.common_tags, {
    Purpose = "Critical security incident notifications"
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Logs Destination for CloudTrail
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/fleetsec/${var.environment}/cloudtrail"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.service["ecs"].arn

  tags = merge(local.common_tags, {
    Purpose = "CloudTrail event audit stream"
  })
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${local.name_prefix}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${local.name_prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# -----------------------------------------------------------------------------
# CloudTrail Multi-Region Audit Trail
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.service["s3"].arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn

  depends_on = [
    aws_s3_bucket_policy.audit
  ]

  tags = merge(local.common_tags, {
    Purpose = "Multi-region immutable audit trail"
  })
}

# -----------------------------------------------------------------------------
# Metric Filters and CloudWatch Alarms (CIS AWS Foundations Benchmark)
# -----------------------------------------------------------------------------

# 1. Root Account Usage
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "${local.name_prefix}-root-login-filter"
  pattern        = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccountLoginEvents"
    namespace = "FleetSecSecurity/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${local.name_prefix}-root-login-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.root_login.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_login.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALERT: Root user login detected. Root should never be used for operational tasks."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = local.common_tags
}

# 2. IAM Policy and Role Changes
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "${local.name_prefix}-iam-changes-filter"
  pattern        = "{($.eventName=CreateUser) || ($.eventName=CreateRole) || ($.eventName=CreatePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=AttachRolePolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=PutUserPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=DeletePolicy) || ($.eventName=DeleteRolePolicy)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "IAMPolicyChangeEvents"
    namespace = "FleetSecSecurity/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${local.name_prefix}-iam-changes-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.iam_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_changes.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALERT: IAM policy, role, or user modifications detected."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = local.common_tags
}

# 3. Security Group Changes
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "${local.name_prefix}-sg-changes-filter"
  pattern        = "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChangeEvents"
    namespace = "FleetSecSecurity/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name          = "${local.name_prefix}-sg-changes-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.sg_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.sg_changes.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALERT: Modifications to VPC Security Group rules detected."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = local.common_tags
}

# 4. KMS DisableKeyRotation or Key Destruction
resource "aws_cloudwatch_log_metric_filter" "disable_key_rotation" {
  name           = "${local.name_prefix}-disable-key-rotation-filter"
  pattern        = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKeyRotation) || ($.eventName=ScheduleKeyDeletion))}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "DisableKeyRotationEvents"
    namespace = "FleetSecSecurity/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "disable_key_rotation" {
  alarm_name          = "${local.name_prefix}-disable-key-rotation-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.disable_key_rotation.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.disable_key_rotation.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CRITICAL: Attempt to disable KMS key rotation or schedule key deletion detected."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = local.common_tags
}
