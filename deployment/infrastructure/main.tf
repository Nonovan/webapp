/**
 * Cloud Infrastructure Platform - Main Terraform Configuration
 * 
 * This file defines the core infrastructure resources for the platform,
 * including networking, compute, database, and monitoring components.
 */

terraform {
  required_version = ">= 1.0.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Local values
locals {
  environment = var.environment
  is_production = var.environment == "production"
  primary_region = var.primary_region
  secondary_region = var.secondary_region
  
  # Load configuration from JSON files based on environment
  primary_config = jsondecode(file("${path.module}/primary_config.json"))
  secondary_config = jsondecode(file("${path.module}/secondary_config.json"))
  
  # Common tags for all resources
  common_tags = {
    Environment = var.environment
    ManagedBy = "terraform"
    Application = "cloud-platform"
    Owner = "platform-team"
  }
}

# Networking module for primary region
module "primary_network" {
  source = "./modules/networking"
  
  environment = local.environment
  region = local.primary_region
  vpc_cidr = local.primary_config.network.vpc_cidr
  subnet_cidrs = local.primary_config.network.subnet_cidrs
  tags = merge(local.common_tags, {
    Region = local.primary_region
    Role = "primary"
  })
}

# Networking module for secondary region (DR)
module "secondary_network" {
  source = "./modules/networking"
  
  environment = local.environment
  region = local.secondary_region
  vpc_cidr = local.secondary_config.network.vpc_cidr
  subnet_cidrs = local.secondary_config.network.subnet_cidrs
  tags = merge(local.common_tags, {
    Region = local.secondary_region
    Role = "secondary"
  })
}

# Compute resources for primary region
module "primary_compute" {
  source = "./modules/compute"
  
  environment = local.environment
  region = local.primary_region
  vpc_id = module.primary_network.vpc_id
  subnet_ids = module.primary_network.private_subnet_ids
  security_group_ids = [module.primary_network.app_security_group_id]
  instance_type = local.is_production ? "r5.large" : "t3.medium"
  min_size = local.is_production ? 3 : 1
  max_size = local.is_production ? 30 : 5
  desired_capacity = local.is_production ? 4 : 1
  
  tags = merge(local.common_tags, {
    Region = local.primary_region
    Role = "primary"
  })
}

# Compute resources for secondary region (DR)
module "secondary_compute" {
  source = "./modules/compute"
  
  environment = local.environment
  region = local.secondary_region
  vpc_id = module.secondary_network.vpc_id
  subnet_ids = module.secondary_network.private_subnet_ids
  security_group_ids = [module.secondary_network.app_security_group_id]
  instance_type = local.is_production ? "r5.large" : "t3.medium"
  min_size = local.is_production ? 2 : 1
  max_size = local.is_production ? 30 : 5
  desired_capacity = local.is_production ? 2 : 1
  
  tags = merge(local.common_tags, {
    Region = local.secondary_region
    Role = "secondary"
  })
}

# Database for primary region
module "primary_database" {
  source = "./modules/database"
  
  environment = local.environment
  region = local.primary_region
  vpc_id = module.primary_network.vpc_id
  subnet_ids = module.primary_network.database_subnet_ids
  security_group_ids = [module.primary_network.db_security_group_id]
  instance_class = local.is_production ? "db.r5.large" : "db.t3.medium"
  allocated_storage = local.is_production ? 100 : 20
  engine_version = "13.4"
  database_name = "cloud_platform_${local.environment}"
  is_primary = true
  replicate_to_secondary = true
  secondary_region = local.secondary_region
  
  tags = merge(local.common_tags, {
    Region = local.primary_region
    Role = "primary"
  })
}

# Database for secondary region (DR)
module "secondary_database" {
  source = "./modules/database"
  
  environment = local.environment
  region = local.secondary_region
  vpc_id = module.secondary_network.vpc_id
  subnet_ids = module.secondary_network.database_subnet_ids
  security_group_ids = [module.secondary_network.db_security_group_id]
  instance_class = local.is_production ? "db.r5.large" : "db.t3.medium"
  allocated_storage = local.is_production ? 100 : 20
  engine_version = "13.4"
  database_name = "cloud_platform_${local.environment}"
  is_primary = false
  primary_region = local.primary_region
  
  tags = merge(local.common_tags, {
    Region = local.secondary_region
    Role = "secondary"
  })
  
  depends_on = [module.primary_database]
}

# Monitoring for primary region
module "primary_monitoring" {
  source = "./modules/monitoring"
  
  environment = local.environment
  region = local.primary_region
  vpc_id = module.primary_network.vpc_id
  compute_asg_name = module.primary_compute.autoscaling_group_name
  database_identifier = module.primary_database.db_instance_id
  alarm_actions = local.primary_config.monitoring.alarm_actions
  
  tags = merge(local.common_tags, {
    Region = local.primary_region
    Role = "primary"
  })
}

# Monitoring for secondary region (DR)
module "secondary_monitoring" {
  source = "./modules/monitoring"
  
  environment = local.environment
  region = local.secondary_region
  vpc_id = module.secondary_network.vpc_id
  compute_asg_name = module.secondary_compute.autoscaling_group_name
  database_identifier = module.secondary_database.db_instance_id
  alarm_actions = local.secondary_config.monitoring.alarm_actions
  
  tags = merge(local.common_tags, {
    Region = local.secondary_region
    Role = "secondary"
  })
}

# Route 53 DNS setup for multi-region
module "dns" {
  source = "./modules/dns"
  
  domain_name = var.domain_name
  environment = local.environment
  primary_lb_dns_name = module.primary_compute.load_balancer_dns_name
  secondary_lb_dns_name = module.secondary_compute.load_balancer_dns_name
  health_check_path = "/health"
  
  tags = local.common_tags
}