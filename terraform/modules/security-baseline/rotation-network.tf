resource "aws_security_group" "rotation_lambda" {
  name        = "${local.name_prefix}-rotation-lambda-sg"
  description = "Restricted network access for RDS secret rotation Lambda"
  vpc_id      = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rotation-lambda-sg"
  })
}

resource "aws_vpc_security_group_egress_rule" "rotation_lambda_to_rds_port" {
  security_group_id            = aws_security_group.rotation_lambda.id
  referenced_security_group_id = aws_security_group.data.id
  description                  = "PostgreSQL access to RDS"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "rotation_lambda_to_endpoint" {
  for_each = toset(local.app_subnet_cidrs)

  security_group_id = aws_security_group.rotation_lambda.id
  description       = "HTTPS to private Secrets Manager endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_security_group" "secrets_manager_endpoint" {
  name        = "${local.name_prefix}-secrets-manager-endpoint-sg"
  description = "HTTPS access to Secrets Manager from rotation Lambda"
  vpc_id      = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-secrets-manager-endpoint-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_rotation_lambda" {
  security_group_id            = aws_security_group.secrets_manager_endpoint.id
  referenced_security_group_id = aws_security_group.rotation_lambda.id
  description                  = "HTTPS from rotation Lambda"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "rotation_lambda_to_rds" {
  security_group_id            = aws_security_group.data.id
  referenced_security_group_id = aws_security_group.rotation_lambda.id
  description                  = "PostgreSQL access from secret rotation Lambda"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_endpoint" "secrets_manager" {
  vpc_id              = aws_vpc.fleetsec.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = [
    for key, subnet in aws_subnet.tier :
    subnet.id if startswith(key, "app-")
  ]

  security_group_ids = [
    aws_security_group.secrets_manager_endpoint.id
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-secrets-manager-endpoint"
  })
}
