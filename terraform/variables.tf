variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS 12-digit account ID"
  type        = string
  default     = "123456789012"
}

variable "project_name" {
  description = "Project identifier"
  type        = string
  default     = "fleetsec"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "owner" {
  description = "Responsible engineering team"
  type        = string
  default     = "FleetSec-Cybersecurity"
}

variable "vpc_cidr" {
  description = "VPC network CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Target availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "database_name" {
  description = "Application database name"
  type        = string
  default     = "fleetsec"
}

variable "database_instance_class" {
  description = "RDS instance size class"
  type        = string
  default     = "db.t3.micro"
}

variable "database_backup_retention_days" {
  description = "RDS backup retention period in days"
  type        = number
  default     = 7
}

variable "database_password_rotation_days" {
  description = "Days between RDS master password rotations"
  type        = number
  default     = 30
}

variable "object_lock_retention_days" {
  description = "Audit log S3 Object Lock retention in COMPLIANCE mode"
  type        = number
  default     = 365
}

variable "allowed_countries" {
  description = "Countries permitted through WAF geo-blocking"
  type        = list(string)
  default     = ["CO", "PE", "US"]
}

variable "auth_rate_limit" {
  description = "WAF auth rate limit per 5 minutes per IP"
  type        = number
  default     = 1000
}

variable "tags" {
  description = "Extra tags"
  type        = map(string)
  default     = {}
}
