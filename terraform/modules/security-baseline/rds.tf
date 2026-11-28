resource "aws_db_subnet_group" "fleetsec" {
  name        = "${local.name_prefix}-db-subnet-group"
  description = "Private subnets for FleetSec RDS"

  subnet_ids = [
    for key, subnet in aws_subnet.tier :
    subnet.id if startswith(key, "data-")
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
  })
}

resource "aws_db_parameter_group" "fleetsec" {
  name        = "${local.name_prefix}-postgres16"
  family      = "postgres16"
  description = "FleetSec PostgreSQL security parameters"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "pending-reboot"
  }

  tags = local.common_tags
}

resource "aws_db_instance" "fleetsec" {
  identifier = "${local.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = var.database_engine_version
  instance_class = var.database_instance_class

  db_name  = var.database_name
  username = "fleetsec_admin"

  manage_master_user_password = true

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.service["rds"].arn

  multi_az               = true
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.fleetsec.name
  vpc_security_group_ids = [aws_security_group.data.id]
  parameter_group_name   = aws_db_parameter_group.fleetsec.name

  backup_retention_period = var.database_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
  deletion_protection        = true
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${local.name_prefix}-postgres-final"

  apply_immediately = false

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres"
  })
}
