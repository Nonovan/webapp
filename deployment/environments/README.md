# Environment Configuration Files

This directory contains environment-specific configuration files used by the Cloud Infrastructure Platform's deployment processes.

## Contents

- Overview
- File Format
- Directory Structure
- Environment Types
- Security Considerations
- Usage Examples
- Related Documentation

## Overview

The environment configuration files provide tailored settings for different deployment environments of the Cloud Infrastructure Platform. These files maintain consistent configuration format while implementing appropriate environment-specific values and security controls. The system supports development, testing, staging, production, and special-purpose environments with appropriate isolation between them.

## File Format

Each environment file (`*.env`) follows the standard environment variable format:

```plaintext
KEY=value
ANOTHER_KEY=another_value
```

Variables can reference other variables using the `${VAR_NAME}` syntax:

```plaintext
BASE_URL=https://example.com
API_URL=${BASE_URL}/api
```

## Directory Structure

```plaintext
deployment/environments/
├── README.md         # This documentation
├── ci.env            # Continuous Integration environment
├── demo.env          # Demonstration instance configuration
├── development.env   # Local development configuration
├── examples/         # Example configurations
│   ├── .env.example  # Generic environment example
│   ├── development.env.example # Development environment example
│   ├── production.env.example  # Production environment example
│   └── staging.env.example     # Staging environment example
├── production.env    # Production environment
├── staging.env       # Pre-production staging environment
├── templates/        # Template configuration files
│   ├── base.env      # Base configuration template
│   └── example.env   # Example configuration with documentation
└── testing.env       # Automated testing environment configuration
```

## Environment Types

- **CI** (`ci.env`): Configuration for the continuous integration environment
  - Optimized for automated build and test processes
  - Contains minimal configuration with test-specific settings
  - Used by CI/CD pipelines across different providers

- **Demo** (`demo.env`): Configuration for demonstration environments
  - Contains settings for showcase and demonstration instances
  - Uses mock services for non-critical components
  - Includes demonstration-specific feature flags

- **Development** (`development.env`): Configuration for local development
  - Enables development-friendly settings like debug mode
  - Uses local service endpoints where possible
  - Includes verbose logging and developer tools

- **Examples** (directory): Contains example configuration files
  - Provides template configuration files with documentation
  - Includes examples for all standard environments
  - Demonstrates proper configuration patterns

- **Production** (`production.env`): Configuration for production deployment
  - Contains optimized performance settings
  - Implements strict security controls
  - Disables debugging and development features
  - Uses production service endpoints

- **Staging** (`staging.env`): Configuration for pre-production validation
  - Mirrors production configuration with staging-specific endpoints
  - Enables additional validation and testing features
  - Uses separate resources from production

- **Templates** (directory): Contains base configuration templates
  - Provides standardized templates for new environments
  - Contains documentation on configuration options
  - Includes examples of configuration patterns

- **Testing** (`testing.env`): Configuration for automated test execution
  - Optimized for test automation and continuous integration
  - Uses ephemeral resources and in-memory services where possible
  - Enables test-specific instrumentation and metrics

## Security Considerations

- **Credentials Management**: These files should never contain actual production credentials
  - Development and local testing may include non-sensitive credentials
  - All sensitive values should be injected through secure environment variables or secret management systems

- **Access Control**:
  - Restrict access to environment files containing even development credentials
  - Use .gitignore to prevent accidental commits of sensitive versions
  - Store templates in version control, not actual configuration files

- **Deployment Security**:
  - For production deployments, inject credentials through:
    - Environment variables at runtime
    - Secret management services (HashiCorp Vault, AWS Secrets Manager)
    - Kubernetes Secrets or equivalent platform mechanisms
    - Parameter stores integrated with deployment systems

- **File Protection**:
  - Use appropriate file permissions when stored on disk
  - Implement controls to prevent unauthorized access
  - Use encryption for any stored sensitive information

## Usage Examples

### With Deployment CLI

```bash
# Deploy to a specific environment
flask deploy aws deploy --env production

# Get status from a specific environment
flask deploy gcp status --env staging

# Deploy Docker containers for development
flask deploy docker compose --env development --action up
```

### With Docker Compose

```bash
# Start services with environment-specific configuration
docker-compose --env-file deployment/environments/development.env up

# Build with production configuration
docker-compose --env-file deployment/environments/production.env build
```

### With Terraform

```bash
# Apply infrastructure changes with environment variables
export TF_VAR_environment="staging"
terraform apply -var-file="deployment/environments/terraform/staging.tfvars"
```

### With Ansible

```bash
# Run Ansible playbook with environment variables
ansible-playbook -i inventories/staging deploy.yml --extra-vars "@deployment/environments/ansible/staging.yml"
```

## Related Documentation

- Deployment Guide
- CI/CD Pipeline Documentation
- Infrastructure as Code Guide
- Secrets Management Guide
- Environment Bootstrapping Guide
- Configuration Management Architecture
