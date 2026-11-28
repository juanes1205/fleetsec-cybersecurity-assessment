resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/fleetsec/${var.environment}/vpc-flow-logs"
  retention_in_days = 90

  kms_key_id = aws_kms_key.service["ecs"].arn

  tags = merge(local.common_tags, {
    Purpose = "VPC network traffic monitoring"
  })
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "cloudwatch" {
  vpc_id               = aws_vpc.fleetsec.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn         = aws_iam_role.vpc_flow_logs.arn

  tags = merge(local.common_tags, {
    Destination = "CloudWatch"
  })
}

resource "aws_flow_log" "s3" {
  vpc_id               = aws_vpc.fleetsec.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.audit.arn}/vpc-flow-logs/"

  tags = merge(local.common_tags, {
    Destination = "S3"
  })
}
