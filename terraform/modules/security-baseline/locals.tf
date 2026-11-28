locals {
  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      Owner       = var.owner
      ManagedBy   = "Terraform"
      Application = "FleetSec"
    },
    var.tags
  )

  name_prefix = "${var.project_name}-${var.environment}"
}
