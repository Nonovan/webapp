# Terraform Deployment Scripts

This directory contains Terraform automation scripts for managing infrastructure deployments for the Cloud Infrastructure Platform. These scripts provide standardized approaches to initialize, plan, apply, and destroy Terraform-managed infrastructure across various environments.

## Overview

The Terraform deployment scripts provide a consistent interface for managing infrastructure as code across different environments (development, staging, production, and disaster recovery). They handle Terraform state management, workspace selection, variable management, and secure infrastructure deployment with proper safeguards.

## Key Scripts

- **`apply.sh`**: Applies Terraform plans to deploy or update infrastructure.
  - **Usage**: Run this script to deploy infrastructure from a Terraform plan.
  - **Features**:
    - Environment-specific deployments
    - Support for plan files or direct application
    - Auto-approve option for CI/CD pipelines
    - Output capturing for verification
    - Special handling for DR environments

- **`destroy.sh`**: Destroys Terraform-managed infrastructure with safety checks.
  - **Usage**: Run this script to tear down infrastructure in specified environments.
  - **Features**:
    - Restricted environment targeting (prevents accidental production destruction)
    - Multiple confirmation prompts for destructive actions
    - State backup before destruction
    - Special verification for DR environments

- **`init.sh`**: Initializes Terraform and selects the appropriate workspace.
  - **Usage**: Run this script to prepare Terraform for other operations.
  - **Features**:
    - Backend configuration with S3 and DynamoDB
    - Automatic workspace creation and selection
    - Remote state configuration
    - State locking setup

- **`output-state.sh`**: Exports the current Terraform state and outputs.
  - **Usage**: Run this script to capture the current infrastructure state.
  - **Features**:
    - JSON output format for machine readability
    - Timestamped output files
    - Separate state and output value capture

- **`plan.sh`**: Creates Terraform plans for infrastructure changes.
  - **Usage**: Run this script to generate a plan for infrastructure changes.
  - **Features**:
    - Environment-specific planning
    - Timestamped plan files
    - Variable file integration
    - Clear next-step instructions

## Directory Structure

```plaintext
scripts/deployment/terraform/
├── apply.sh         # Applies Terraform configurations
├── destroy.sh       # Destroys Terraform-managed infrastructure
├── init.sh          # Initializes Terraform and selects workspace
├── output-state.sh  # Outputs current Terraform state
├── plan.sh          # Creates Terraform execution plans
└── README.md        # This documentation
```

## Best Practices & Security

- Always run plan.sh before applying changes to review proposed modifications
- Use separate workspaces for different environments
- Restrict production destruction to manual Terraform commands
- Back up state before destructive operations
- Store sensitive variables in secure parameter stores
- Use multiple confirmation prompts for destructive actions
- Maintain state locking to prevent concurrent modifications
- Enable versioning on state storage buckets

## Common Features

- Environment-specific workspace management
- Consistent error handling and logging
- State backup and preservation
- Secure credential management
- Output capture for verification
- Cross-environment compatibility
- Special handling for disaster recovery

## Usage

### Initializing Terraform

```bash
# Initialize for production environment
./scripts/deployment/terraform/init.sh production

# Initialize for development environment
./scripts/deployment/terraform/init.sh development

# Initialize for DR recovery
./scripts/deployment/terraform/init.sh dr-recover
```

### Planning Changes

```bash
# Generate a plan for production
./scripts/deployment/terraform/plan.sh production

# Generate a plan for staging
./scripts/deployment/terraform/plan.sh staging
```

### Applying Changes

```bash
# Apply with plan file
./scripts/deployment/terraform/apply.sh production path/to/plan.tfplan

# Apply with interactive approval
./scripts/deployment/terraform/apply.sh staging

# Apply with auto-approval (CI/CD pipelines)
./scripts/deployment/terraform/apply.sh development --auto-approve
```

### Destroying Infrastructure

```bash
# Destroy development environment (with confirmation prompts)
./scripts/deployment/terraform/destroy.sh development

# Destroy staging environment (with confirmation prompts)
./scripts/deployment/terraform/destroy.sh staging

# Note: Production environment cannot be destroyed with this script
```

### Exporting State

```bash
# Export current state and outputs for production
./scripts/deployment/terraform/output-state.sh production

# Export current state and outputs for dr-recover
./scripts/deployment/terraform/output-state.sh dr-recover
```

## Related Documentation

- Infrastructure Architecture
- Environment Configuration
- Deployment Overview
- Disaster Recovery Plan

## Version History

- **1.3.0 (2024-05-10)**: Added specialized DR recovery environment handling
- **1.2.0 (2024-03-15)**: Enhanced state backup and security controls
- **1.1.0 (2024-01-20)**: Added output-state.sh for state and output export
- **1.0.0 (2023-11-05)**: Initial release of Terraform deployment scripts
