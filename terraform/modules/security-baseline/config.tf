# -----------------------------------------------------------------------------
# AWS Config Service Role
# -----------------------------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "${local.name_prefix}-aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_service_role" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_delivery" {
  name = "${local.name_prefix}-config-s3-policy"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConfigBucketPermissions"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.audit.arn
      },
      {
        Sid    = "ConfigObjectDelivery"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "ConfigKMSAccess"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.service["s3"].arn
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# AWS Config Recorder and Delivery Channel
# -----------------------------------------------------------------------------
resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name_prefix}-config-delivery"
  s3_bucket_name = aws_s3_bucket.audit.id
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.audit
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.main
  ]
}

# -----------------------------------------------------------------------------
# AWS Config Managed Compliance Rules (Mandatory Baseline)
# -----------------------------------------------------------------------------

# 1. CloudTrail Enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "${local.name_prefix}-cloudtrail-enabled"
  description = "Checks whether AWS CloudTrail is enabled in the account."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}

# 2. Encrypted Volumes
resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "${local.name_prefix}-encrypted-volumes"
  description = "Checks whether EBS volumes attached to EC2 instances are encrypted."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}

# 3. GuardDuty Enabled Centralized
resource "aws_config_config_rule" "guardduty_enabled" {
  name        = "${local.name_prefix}-guardduty-enabled-centralized"
  description = "Checks that Amazon GuardDuty is enabled in all regions."

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}

# 4. S3 Bucket Public Read Prohibited
resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name        = "${local.name_prefix}-s3-bucket-public-read-prohibited"
  description = "Checks that S3 buckets do not allow public read access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}

# 5. IAM Password Policy
resource "aws_config_config_rule" "iam_password_policy" {
  name        = "${local.name_prefix}-iam-password-policy"
  description = "Checks whether the IAM account password policy meets strict complexity criteria."

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention     = "24"
    MaxPasswordAge             = "90"
  })

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}

# 6. Root Account MFA Enabled
resource "aws_config_config_rule" "root_account_mfa_enabled" {
  name        = "${local.name_prefix}-root-account-mfa-enabled"
  description = "Checks whether the root user account has MFA enabled."

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.common_tags
}
