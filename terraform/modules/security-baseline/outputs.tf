output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.fleetsec.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value = [
    for k, v in aws_subnet.tier : v.id if startswith(k, "public-")
  ]
}

output "app_subnet_ids" {
  description = "IDs of the private application subnets"
  value = [
    for k, v in aws_subnet.tier : v.id if startswith(k, "app-")
  ]
}

output "data_subnet_ids" {
  description = "IDs of the private database subnets"
  value = [
    for k, v in aws_subnet.tier : v.id if startswith(k, "data-")
  ]
}

output "alb_security_group_id" {
  description = "Security group ID for the ALB"
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "Security group ID for the Application tier"
  value       = aws_security_group.app.id
}

output "data_security_group_id" {
  description = "Security group ID for the Database tier"
  value       = aws_security_group.data.id
}

output "rds_instance_endpoint" {
  description = "RDS connection endpoint"
  value       = aws_db_instance.fleetsec.endpoint
}

output "rds_master_secret_arn" {
  description = "ARN of the Secrets Manager secret for RDS master credentials"
  value       = aws_db_instance.fleetsec.master_user_secret[0].secret_arn
}

output "data_bucket_arn" {
  description = "ARN of the application S3 data bucket"
  value       = aws_s3_bucket.data.arn
}

output "audit_bucket_arn" {
  description = "ARN of the immutable audit S3 bucket"
  value       = aws_s3_bucket.audit.arn
}

output "kms_key_arns" {
  description = "ARNs of KMS customer managed keys"
  value       = { for k, v in aws_kms_key.service : k => v.arn }
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task IAM role"
  value       = aws_iam_role.ecs_task.arn
}

output "ecs_execution_role_arn" {
  description = "ARN of the ECS task execution IAM role"
  value       = aws_iam_role.ecs_execution.arn
}

output "cloudtrail_arn" {
  description = "ARN of the central CloudTrail audit trail"
  value       = aws_cloudtrail.main.arn
}

output "security_alerts_sns_topic_arn" {
  description = "ARN of the SNS topic for security alarms"
  value       = aws_sns_topic.security_alerts.arn
}
