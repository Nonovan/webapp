/**
 * Cloud Infrastructure Platform - Terraform Outputs
 * 
 * This file defines the outputs from the Terraform configuration.
 */

# Primary region outputs
output "primary_vpc_id" {
  description = "ID of the primary region VPC"
  value       = module.primary_network.vpc_id
}

output "primary_public_subnet_ids" {
  description = "IDs of public subnets in primary region"
  value       = module.primary_network.public_subnet_ids
}

output "primary_private_subnet_ids" {
  description = "IDs of private application subnets in primary region"
  value       = module.primary_network.private_subnet_ids
}

output "primary_database_subnet_ids" {
  description = "IDs of database subnets in primary region"
  value       = module.primary_network.database_subnet_ids
}

output "primary_lb_dns_name" {
  description = "DNS name of the primary load balancer"
  value       = module.primary_compute.load_balancer_dns_name
}

output "primary_db_endpoint" {
  description = "Endpoint of the primary database"
  value       = module.primary_database.db_endpoint
}

output "primary_bastion_ip" {
  description = "Public IP of the primary bastion host"
  value       = module.primary_network.bastion_public_ip
  sensitive   = true
}

# Secondary region outputs
output "secondary_vpc_id" {
  description = "ID of the secondary region VPC"
  value       = module.secondary_network.vpc_id
}

output "secondary_public_subnet_ids" {
  description = "IDs of public subnets in secondary region"
  value       = module.secondary_network.public_subnet_ids
}

output "secondary_private_subnet_ids" {
  description = "IDs of private application subnets in secondary region"
  value       = module.secondary_network.private_subnet_ids
}

output "secondary_database_subnet_ids" {
  description = "IDs of database subnets in secondary region"
  value       = module.secondary_network.database_subnet_ids
}

output "secondary_lb_dns_name" {
  description = "DNS name of the secondary load balancer"
  value       = module.secondary_compute.load_balancer_dns_name
}

output "secondary_db_endpoint" {
  description = "Endpoint of the secondary database"
  value       = module.secondary_database.db_endpoint
}

output "secondary_bastion_ip" {
  description = "Public IP of the secondary bastion host"
  value       = module.secondary_network.bastion_public_ip
  sensitive   = true
}

# DNS outputs
output "application_endpoint" {
  description = "Main application endpoint"
  value       = module.dns.application_endpoint
}

output "api_endpoint" {
  description = "API endpoint"
  value       = module.dns.api_endpoint
}

# SSM Parameters - paths where configuration values are stored
output "ssm_parameters" {
  description = "SSM parameter paths for application configuration"
  value = {
    database_url  = var.environment == "production" ? "Parameter Store path hidden for security" : aws_ssm_parameter.database_url.name
    secret_key    = var.environment == "production" ? "Parameter Store path hidden for security" : aws_ssm_parameter.secret_key.name
    ics_settings  = var.environment == "production" ? "Parameter Store path hidden for security" : aws_ssm_parameter.ics_settings.name
  }
  sensitive = true
}