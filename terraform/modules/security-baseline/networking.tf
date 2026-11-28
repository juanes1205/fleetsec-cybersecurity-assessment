resource "aws_vpc" "fleetsec" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "fleetsec" {
  vpc_id = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

locals {
  subnet_definitions = {
    for item in flatten([
      for az_index, az in var.availability_zones : [
        {
          key  = "public-${az}"
          az   = az
          tier = "public"
          cidr = cidrsubnet(var.vpc_cidr, 4, az_index)
        },
        {
          key  = "app-${az}"
          az   = az
          tier = "app"
          cidr = cidrsubnet(var.vpc_cidr, 4, az_index + 2)
        },
        {
          key  = "data-${az}"
          az   = az
          tier = "data"
          cidr = cidrsubnet(var.vpc_cidr, 4, az_index + 4)
        }
      ]
    ]) : item.key => item
  }
}

resource "aws_subnet" "tier" {
  for_each = local.subnet_definitions

  vpc_id                  = aws_vpc.fleetsec.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = each.value.tier == "public"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-${each.key}"
    Tier = each.value.tier
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.fleetsec.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fleetsec.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-rt"
  })
}

resource "aws_route_table" "app" {
  vpc_id = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-app-private-rt"
  })
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-data-private-rt"
  })
}

resource "aws_route_table_association" "tier" {
  for_each = aws_subnet.tier

  subnet_id = each.value.id

  route_table_id = (
    startswith(each.key, "public-") ? aws_route_table.public.id :
    startswith(each.key, "app-") ? aws_route_table.app.id :
    aws_route_table.data.id
  )
}

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "Public entry point for HTTP and HTTPS traffic"
  vpc_id      = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from Internet"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from Internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.app.id
  description                  = "Application targets"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_security_group" "app" {
  name        = "${local.name_prefix}-app-sg"
  description = "Private application tier"
  vpc_id      = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-app-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.alb.id
  description                  = "Application traffic from ALB"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "app_to_data" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.data.id
  description                  = "PostgreSQL access to data tier"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_security_group" "data" {
  name        = "${local.name_prefix}-data-sg"
  description = "Private database tier"
  vpc_id      = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-data-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "data_from_app" {
  security_group_id            = aws_security_group.data.id
  referenced_security_group_id = aws_security_group.app.id
  description                  = "PostgreSQL only from application tier"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

locals {
  app_subnet_cidrs = [
    for key, subnet in local.subnet_definitions :
    subnet.cidr if startswith(key, "app-")
  ]

  data_subnet_cidrs = [
    for key, subnet in local.subnet_definitions :
    subnet.cidr if startswith(key, "data-")
  ]
}

locals {
  data_nacl_ingress_rules = {
    for index, cidr in local.app_subnet_cidrs :
    "app-${index}" => {
      rule_number = 100 + index
      cidr_block  = cidr
    }
  }

  data_nacl_egress_rules = {
    for index, cidr in local.app_subnet_cidrs :
    "app-${index}" => {
      rule_number = 100 + index
      cidr_block  = cidr
    }
  }
}

resource "aws_network_acl" "data" {
  vpc_id = aws_vpc.fleetsec.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-data-nacl"
    Tier = "data"
  })
}

resource "aws_network_acl_rule" "data_ingress_postgresql" {
  for_each = local.data_nacl_ingress_rules

  network_acl_id = aws_network_acl.data.id
  rule_number    = each.value.rule_number
  egress         = false
  protocol       = "6"
  rule_action    = "allow"
  cidr_block     = each.value.cidr_block
  from_port      = 5432
  to_port        = 5432
}

resource "aws_network_acl_rule" "data_egress_ephemeral" {
  for_each = local.data_nacl_egress_rules

  network_acl_id = aws_network_acl.data.id
  rule_number    = each.value.rule_number
  egress         = true
  protocol       = "6"
  rule_action    = "allow"
  cidr_block     = each.value.cidr_block
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_association" "data" {
  for_each = {
    for key, subnet in aws_subnet.tier :
    key => subnet if startswith(key, "data-")
  }

  network_acl_id = aws_network_acl.data.id
  subnet_id      = each.value.id
}
