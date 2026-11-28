variable "aws_region" {
  description = "AWS region for the security baseline."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used to identify AWS resources."
  type        = string
  default     = "fleetsec"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "production"
}

variable "owner" {
  description = "Team responsible for the infrastructure."
  type        = string
  default     = "FleetSec"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones used by the network."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "database_name" {
  description = "Application database name."
  type        = string
  default     = "fleetsec"
}

variable "database_engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16.4"
}

variable "database_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "database_backup_retention_days" {
  description = "Number of days to retain RDS backups."
  type        = number
  default     = 7

  validation {
    condition     = var.database_backup_retention_days >= 7
    error_message = "Production database backups must be retained for at least 7 days."
  }
}

variable "object_lock_retention_days" {
  description = "Default COMPLIANCE retention period for the audit log bucket."
  type        = number
  default     = 365
}

variable "allowed_countries" {
  description = "Countries allowed by the WAF geographic restriction."
  type        = list(string)
  default     = ["CO", "PE", "US"]
}

variable "auth_rate_limit" {
  description = "Maximum requests per IP during the WAF evaluation window."
  type        = number
  default     = 1000
}

variable "tags" {
  description = "Additional tags applied to resources."
  type        = map(string)
  default     = {}
}

variable "aws_account_id" {
  description = "AWS account ID used to scope KMS key policies."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must contain exactly 12 digits."
  }
}

variable "database_password_rotation_days" {
  description = "Number of days between automatic RDS master password rotations."
  type        = number
  default     = 30

  validation {
    condition = (
      var.database_password_rotation_days >= 1 &&
      var.database_password_rotation_days <= 365
    )
    error_message = "Database password rotation must be between 1 and 365 days."
  }
}
