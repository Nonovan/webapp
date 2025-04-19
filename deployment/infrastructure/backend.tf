/**
 * Cloud Infrastructure Platform - Backend Configuration
 * 
 * This file configures the Terraform state backend.
 */

terraform {
  backend "s3" {
    bucket         = "cloud-platform-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}