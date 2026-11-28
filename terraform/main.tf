module "security_baseline" {
  source = "./modules/security-baseline"

  aws_region                      = var.aws_region
  aws_account_id                  = var.aws_account_id
  project_name                    = var.project_name
  environment                     = var.environment
  owner                           = var.owner
  vpc_cidr                        = var.vpc_cidr
  availability_zones              = var.availability_zones
  database_name                   = var.database_name
  database_instance_class         = var.database_instance_class
  database_backup_retention_days  = var.database_backup_retention_days
  database_password_rotation_days = var.database_password_rotation_days
  object_lock_retention_days      = var.object_lock_retention_days
  allowed_countries               = var.allowed_countries
  auth_rate_limit                 = var.auth_rate_limit
  tags                            = var.tags
}
