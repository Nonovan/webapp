# Configuration Scripts for Cloud Infrastructure Platform

This directory contains configuration management scripts for the Cloud Infrastructure Platform. These scripts handle various aspects of system configuration including validation, resource allocation, connection management, and security settings across different deployment environments.

## Overview

The configuration scripts automate and standardize the process of configuring infrastructure resources and connection parameters across multiple cloud providers and deployment environments. They ensure consistent configuration while implementing appropriate environment-specific settings and security controls.

## Key Scripts

- **`config_validator.sh`**: Validates configuration files against schemas and best practices.
  - **Usage**: Run this script to validate configuration files before deployment.
  - **Features**:
    - Multi-format support (JSON, YAML, INI)
    - Environment-specific validation rules
    - Security best practice checks
    - Detailed validation reports

- **`configure_connections.sh`**: Configures connections to external services like databases, caches, and cloud providers.
  - **Usage**: Run this script to set up connection parameters for various services.
  - **Features**:
    - Support for multiple service types (database, Redis, RabbitMQ, cloud providers)
    - Secure credential handling
    - Configuration backup and versioning
    - Environment-specific configurations

- **`configure_resources.sh`**: Configures compute, memory, storage, and network resources.
  - **Usage**: Run this script to configure infrastructure resources for the platform.
  - **Features**:
    - Multi-cloud provider support (AWS, Azure, GCP, Kubernetes)
    - Environment-aware resource allocation
    - Auto-scaling configuration
    - Dry-run capability

## Directory Structure

```bash
scripts/deployment/config/
├── config_validator.sh       # Configuration validation tool
├── configure_connections.sh  # Connection configuration management
├── configure_resources.sh    # Resource allocation and configuration
├── README.md                 # This documentation
├── schemas/                  # JSON schemas for configuration validation
│   ├── app.schema.json       # Application configuration schema
│   ├── database.schema.json  # Database configuration schema
│   └── security.schema.json  # Security configuration schema
└── templates/                # Configuration templates
    ├── app.ini.template      # Application configuration template
    ├── database.ini.template # Database configuration template
    └── security.ini.template # Security configuration template
```

## Configuration

Each script reads environment-specific configuration from the following locations:

- Default environment files: `deployment/environments/{environment}.env`
- Configuration directory: config
- Schema directory: schemas

## Best Practices & Security

- Always validate configurations before deployment with config_validator.sh
- Use environment-specific configuration files for different environments
- Store sensitive configuration values in environment variables or secure storage
- Perform dry runs before applying changes to production environments
- Backup configurations before making changes
- Use strict permission settings for configuration files (600 or 640)
- Review validation reports for potential security issues
- Follow the principle of least privilege for connection configurations

## Common Features

- Environment-specific configurations (development, staging, production, dr-recovery)
- Consistent error handling and logging
- Backup of existing configurations before changes
- Support for multiple cloud providers
- Security best practice enforcement
- Detailed logging for audit purposes

## Usage

### Configuration Validation

```bash
# Validate production configuration
./config_validator.sh --environment production

# Validate with custom schema directory
./config_validator.sh --environment staging --schema-dir /path/to/schemas

# Generate HTML validation report
./config_validator.sh --environment production --format html --report validation-report.html

# Use strict mode validation
./config_validator.sh --environment production --strict
```

### Resource Configuration

```bash
# Configure AWS resources for production
./configure_resources.sh --environment production --region us-west-2

# Configure Azure resources with auto-scaling
./configure_resources.sh --environment staging --region eastus --auto-scale

# Override default resource allocations
./configure_resources.sh --environment production --cpu 16 --memory 32Gi --disk 500

# Perform a dry run without making changes
./configure_resources.sh --environment production --dry-run
```

### Connection Configuration

```bash
# Configure database connection
./configure_connections.sh --environment production --type database --host db.example.com --port 5432 --username appuser --password-file /path/to/password

# Configure Redis connection
./configure_connections.sh --environment staging --type redis --host redis.example.com --port 6379

# Configure AWS provider
./configure_connections.sh --environment production --type aws --region us-west-2
```

## Related Documentation

- Configuration Guide
- Environment Setup
- Security Hardening
- Disaster Recovery

## Version History

- **1.3.0 (2024-02-15)**: Added multi-cloud provider support and auto-scaling configurations
- **1.2.0 (2023-12-10)**: Enhanced security validation and reporting capabilities
- **1.1.0 (2023-09-05)**: Added support for connection configuration management
- **1.0.0 (2023-07-20)**: Initial release of configuration scripts
