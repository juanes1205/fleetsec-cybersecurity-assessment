locals {
  kms_key_services = toset([
    "rds",
    "s3",
    "ecs"
  ])
}

resource "aws_kms_key" "service" {
  for_each = local.kms_key_services

  description             = "FleetSec ${each.key} encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = concat(
      [
        {
          Sid    = "EnableAccountIAMDelegation"
          Effect = "Allow"

          Principal = {
            AWS = "arn:aws:iam::${var.aws_account_id}:root"
          }

          Action   = "kms:*"
          Resource = "*"
        }
      ],

      each.key == "s3" ? [
        {
          Sid    = "AllowVPCFlowLogsS3Encryption"
          Effect = "Allow"

          Principal = {
            Service = "delivery.logs.amazonaws.com"
          }

          Action = [
            "kms:GenerateDataKey*",
            "kms:Decrypt",
            "kms:DescribeKey"
          ]

          Resource = "*"

          Condition = {
            StringEquals = {
              "aws:SourceAccount" = var.aws_account_id
            }

            ArnLike = {
              "aws:SourceArn" = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"
            }
          }
        },
        {
          Sid    = "AllowCloudTrailS3Encryption"
          Effect = "Allow"

          Principal = {
            Service = "cloudtrail.amazonaws.com"
          }

          Action = [
            "kms:GenerateDataKey*",
            "kms:Decrypt",
            "kms:DescribeKey"
          ]

          Resource = "*"

          Condition = {
            StringEquals = {
              "aws:SourceAccount" = var.aws_account_id
            }

            ArnLike = {
              "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/*"
            }
          }
        },
        {
          Sid    = "AllowConfigS3Encryption"
          Effect = "Allow"

          Principal = {
            Service = "config.amazonaws.com"
          }

          Action = [
            "kms:GenerateDataKey*",
            "kms:Decrypt",
            "kms:DescribeKey"
          ]

          Resource = "*"

          Condition = {
            StringEquals = {
              "aws:SourceAccount" = var.aws_account_id
            }
          }
        }
      ] : [],

      each.key == "ecs" ? [
        {
          Sid    = "AllowCloudWatchLogsEncryption"
          Effect = "Allow"

          Principal = {
            Service = "logs.${var.aws_region}.amazonaws.com"
          }

          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
          ]

          Resource = "*"

          Condition = {
            StringEquals = {
              "aws:SourceAccount" = var.aws_account_id
            }

            ArnLike = {
              "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/fleetsec/${var.environment}/*"
            }
          }
        }
      ] : []
    )
  })

  tags = merge(local.common_tags, {
    Service = each.key
  })
}

resource "aws_kms_alias" "service" {
  for_each = local.kms_key_services

  name          = "alias/${local.name_prefix}-${each.key}"
  target_key_id = aws_kms_key.service[each.key].key_id
}
