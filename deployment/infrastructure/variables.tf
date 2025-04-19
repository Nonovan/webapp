/**
 * Cloud Infrastructure Platform - Variables
 * 
 * This file defines the input variables for the Terraform configuration.
 */

variable "environment" {
  description = "Deployment environment (development, staging, production)"
  type        = string
  default     = "development"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "primary_region" {
  description = "AWS region for the primary deployment"
  type        = string
  default     = "us-west-2"
}

variable "secondary_region" {
  description = "AWS region for the secondary (DR) deployment"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "cloud-platform.example.com"
}

variable "vpc_cidr_primary" {
  description = "CIDR block for the primary VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_cidr_secondary" {
  description = "CIDR block for the secondary VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "db_username" {
  description = "Database admin username"
  type        = string
  sensitive   = true
  default     = "cloud_platform_app"
}

variable "db_password" {
  description = "Database admin password"
  type        = string
  sensitive   = true
}

variable "ssh_allowed_ips" {
  description = "List of IP addresses allowed to SSH to the instances"
  type        = list(string)
  default     = []
}

variable "enable_ics_components" {
  description = "Whether to enable Industrial Control Systems (ICS) components"
  type        = bool
  default     = true
}

variable "ics_restricted_ips" {
  description = "IPs allowed to access ICS endpoints"
  type        = list(string)
  default     = []
}