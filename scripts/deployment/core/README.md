# Core Deployment Scripts

This directory contains core deployment scripts for the Cloud Infrastructure Platform. These scripts provide essential functionality for deploying, updating, and maintaining the platform across various environments.

## Overview

The core deployment scripts handle critical deployment operations including pre-deployment verification, deployment execution, post-deployment checks, static asset compilation, and rollback procedures. These scripts support multiple environments (development, staging, production) and implement safeguards to ensure reliable deployments.

## Key Scripts

- **`collect_static.sh`**: Compiles and optimizes static assets.
  - **Usage**: Run this script to prepare static files for deployment.
  - **Features**:
    - Static file collection
    - JavaScript and CSS minification
    - Image optimization
    - Subresource Integrity (SRI) hash generation
    - Environment-aware optimization

- **`deploy.sh`**: Main deployment script for the Cloud Infrastructure Platform.
  - **Usage**: Run this script to deploy the application to a specified environment.
  - **Features**:
    - Environment-specific deployment
    - Dependency management
    - Database migration
    - Service restart
    - Pre and post-deployment checks

- **`post_deploy_check.sh`**: Verifies successful deployment.
  - **Usage**: Run this script to verify that the deployment was successful.
  - **Features**:
    - Application health checks
    - Service status verification
    - Database migration verification
    - Log analysis
    - Security header verification

- **`pre_deploy_check.sh`**: Validates prerequisites before deployment.
  - **Usage**: Run this script to verify that all deployment prerequisites are met.
  - **Features**:
    - Environment validation
    - Dependency checks
    - Git repository status verification
    - Database connectivity testing
    - Security configuration validation

- **`rollback.sh`**: Reverts to a previous version in case of deployment issues.
  - **Usage**: Run this script to roll back to a previous stable version.
  - **Features**:
    - Code rollback to specified version
    - Database rollback capability
    - Service restart
    - Post-rollback verification
    - Backup creation

## Directory Structure

```
scripts/deployment/core/
├── collect_static.sh      # Static asset compilation and optimization
├── deploy.sh              # Main deployment script
├── post_deploy_check.sh   # Post-deployment verification
├── pre_deploy_check.sh    # Pre-deployment validation
├── README.md              # This documentation
└── rollback.sh            # Deployment rollback functionality
```

## Best Practices & Security

- Always run pre-deployment checks before deployment
- Verify deployment with post-deployment checks
- Maintain accurate version control with consistent tagging
- Keep database backups before applying migrations
- Use proper error handling and logging during deployment
- Secure static assets with SRI hashes
- Verify security headers in production environments
- Maintain proper file permissions for configuration files
- Implement proper service restart procedures

## Common Features

- Environment-specific configuration loading
- Comprehensive logging during deployment
- Confirmation prompts for destructive operations
- Backup creation before modifications
- Service status verification
- Atomic deployment operations
- Rollback capability for failed deployments

## Usage

### Standard Deployment

```bash
# Deploy to production environment
./scripts/deployment/core/deploy.sh production

# Deploy to staging environment
./scripts/deployment/core/deploy.sh staging

# Deploy to development environment
./scripts/deployment/core/deploy.sh development
```

### Deployment Verification

```bash
# Run pre-deployment checks for production
./scripts/deployment/core/pre_deploy_check.sh production

# Run post-deployment checks for production
./scripts/deployment/core/post_deploy_check.sh production
```

### Static Assets

```bash
# Compile and optimize static assets
./scripts/deployment/core/collect_static.sh
```

### Rollback

```bash
# Rollback to previous version in production
./scripts/deployment/core/rollback.sh production

# Rollback to specific version in production
./scripts/deployment/core/rollback.sh production --version v1.2.3

# Rollback code and database in production
./scripts/deployment/core/rollback.sh production --database

# Force rollback without confirmation
./scripts/deployment/core/rollback.sh production --force
```

## Related Documentation

- Deployment Overview
- Environment Configuration
- Database Migration Guide
- Static Assets Guide
- Rollback Procedures

## Version History

- **1.4.0 (2024-06-15)**: Added improved static asset handling with SRI
- **1.3.0 (2024-04-10)**: Enhanced rollback functionality with database support
- **1.2.0 (2024-02-20)**: Added security verification in pre/post deployment checks
- **1.1.0 (2023-11-12)**: Enhanced environment-specific configuration
- **1.0.0 (2023-09-01)**: Initial release of core deployment scripts
