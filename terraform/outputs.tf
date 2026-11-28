output "vpc_id" {
  description = "VPC ID"
  value       = module.security_baseline.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.security_baseline.public_subnet_ids
}

output "app_subnet_ids" {
  description = "Application subnet IDs"
  value       = module.security_baseline.app_subnet_ids
}

output "data_subnet_ids" {
  description = "Database subnet IDs"
  value       = module.security_baseline.data_subnet_ids
}

output "alb_security_group_id" {
  description = "ALB security group ID"
  value       = module.security_baseline.alb_security_group_id
}

output "rds_instance_endpoint" {
  description = "RDS PostgreSQL connection endpoint"
  value       = module.security_baseline.rds_instance_endpoint
}

output "data_bucket_arn" {
  description = "S3 data bucket ARN"
  value       = module.security_baseline.data_bucket_arn
}

output "audit_bucket_arn" {
  description = "S3 audit bucket ARN with Object Lock COMPLIANCE"
  value       = module.security_baseline.audit_bucket_arn
}

output "cloudtrail_arn" {
  description = "CloudTrail audit trail ARN"
  value       = module.security_baseline.cloudtrail_arn
}

output "waf_web_acl_arn" {
  description = "WAFv2 Web ACL ARN"
  value       = module.security_baseline.waf_web_acl_arn
}
