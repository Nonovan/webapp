/**
 * Cloud Infrastructure Platform - Provider Configuration
 * 
 * This file configures the cloud providers used by the platform.
 */

# AWS Provider configuration for primary region
provider "aws" {
  alias  = "primary"
  region = var.primary_region
  
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Application = "cloud-platform"
    }
  }
}

# AWS Provider configuration for secondary region (DR)
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
  
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Application = "cloud-platform"
    }
  }
}

# Azure Provider configuration
provider "azurerm" {
  features {}
}

# Google Cloud Provider configuration
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}