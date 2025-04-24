# Configuration Package

This directory contains configuration files for the Cloud Infrastructure Platform. It implements a hierarchical, environment-aware configuration system that separates settings by component and environment.

## Overview

The configuration system follows these principles:

- **Environment Separation**: Different environments (development, staging, production) have separate configurations
- **Layered Configuration**: Core settings are inherited and overridden by environment-specific settings
- **Component Organization**: Configuration is separated by functional component
- **Schema Validation**: Configuration files are validated against schemas for consistency
- **Security by Design**: Sensitive information is managed separately from code

## Key Components

- **`base.py`**: Base configuration class with default settings for all environments
- **`development.py`, `staging.py`, `production.py`**: Environment-specific configurations
- **`local.py`**: Local development overrides (not version controlled)
- **`environments.py`**: Environment detection and handling logic
- **`components/`**: Component-specific configuration files
- **`schemas/`**: JSON schemas for configuration validation

## Directory Structure

```plaintext
config/
├── __init__.py               # Package initialization
├── base.py                   # Base configuration class
├── development.py            # Development environment configuration
├── environments.py           # Environment detection logic
├── local.py                  # Local development overrides
├── production.py             # Production environment configuration
├── README.md                 # Configuration documentation (this file)
├── staging.py                # Staging environment configuration
├── testing.py                # Testing environment configuration
├── components/               # Component-specific configurations
│   ├── __init__.py           # Component configuration utilities
│   ├── api.ini               # API gateway configuration
│   ├── api_endpoints.json    # API endpoint definitions
│   ├── app.ini               # Core application settings
│   ├── backup.ini            # Backup and disaster recovery
│   ├── cache.ini             # Caching configuration
│   ├── compliance.ini        # Compliance and regulatory settings
│   ├── database.ini          # Database connection settings
│   ├── email.ini             # Email service configuration
│   ├── logging.ini           # Logging configuration
│   ├── monitoring.ini        # Monitoring system settings
│   ├── network.ini           # Network and connectivity settings
│   ├── privacy.ini           # Privacy and data protection
│   ├── README.md             # Component configuration documentation
│   ├── security.ini          # Security settings
│   └── storage.ini           # Storage system configuration
├── environments/             # Environment-specific overrides
│   ├── __init__.py           # Environment utilities
│   ├── development/          # Development environment overrides
│   ├── production/           # Production environment overrides
│   ├── staging/              # Staging environment overrides
│   └── testing/              # Testing environment overrides
└── schemas/                  # JSON schemas for validation
    ├── __init__.py           # Schema validation utilities
    ├── *.json.schema         # JSON file schemas
    ├── *.yaml.schema         # YAML file schemas
    ├── api.ini.schema        # API configuration schema
    ├── api.json.schema       # API structure schema
    ├── app.ini.schema        # Application settings schema
    ├── backup.ini.schema     # Backup configuration schema
    ├── cache.ini.schema      # Cache configuration schema
    ├── compliance.ini.schema # Compliance settings schema
    ├── database.ini.schema   # Database settings schema
    ├── deployment.yaml.schema # Deployment configuration schema
    ├── email.ini.schema      # Email settings schema
    └── ...                   # Other schema files

```

## Configuration Files

### Core Python Configuration

- **`base.py`**: Defines the Config class with default configuration values
- **`development.py`**: Development environment settings, extends base configuration
- **`staging.py`**: Staging/pre-production settings, extends base configuration
- **`production.py`**: Production environment settings, extends base configuration
- **`testing.py`**: Testing environment settings, extends base configuration

### Component Configuration (INI Files)

- **`app.ini`**: Core application settings (workers, timeouts, features)
- **`api.ini`**: API configuration (rate limits, versioning, documentation)
- **`security.ini`**: Security settings (password policies, session timeouts, MFA)
- **`database.ini`**: Database connection settings for different environments
- **`cache.ini`**: Caching configuration (Redis, Memcached settings)
- **`email.ini`**: Email service configuration (SMTP, templates)
- **`logging.ini`**: Logging levels, formats, and destinations
- **`monitoring.ini`**: Monitoring settings (metrics, alerts, health checks)
- **`backup.ini`**: Backup schedules, retention policies, storage locations
- **`network.ini`**: Network settings, proxy configuration, and connectivity
- **`storage.ini`**: File storage configuration (S3, Azure Blob, local)
- **`compliance.ini`**: Compliance and regulatory settings
- **`privacy.ini`**: Privacy settings (data retention, consent, GDPR)

### JSON Configuration

- **`api_endpoints.json`**: Defines API endpoints, methods, and required permissions

## Usage

### Python Configuration

The Python configuration classes define a hierarchy where environment-specific classes inherit from the base Config class:

```python
from config import get_config, get_config_instance

# Method 1: Get configuration class (not instantiated)
config_class = get_config('production')
app.config.from_object(config_class)

# Method 2: Get instantiated configuration
config = get_config_instance('production')
app.config.update(config.__dict__)

# Method 3: Auto-detect environment
config = get_config_instance()  # Detects from APP_ENV environment variable

```

### Component Configuration

Component configurations can be loaded through the utilities in the `components` module:

```python
from config.components import load_component_config

# Load security configuration for production environment
security_config = load_component_config('security', environment='production')

# Access configuration values
password_min_length = security_config['authentication']['password_min_length']
mfa_enabled = security_config['authentication']['mfa_enabled']

# Load API endpoints configuration (JSON)
endpoints_config = load_component_config('api_endpoints', extension='json')

```

### Environment Variable Overrides

Configuration values can be overridden by environment variables:

- Environment variables take precedence over configuration files
- Variable names follow the pattern: `CLOUDPLATFORM_SECTION_KEY`
- For component configs, use: `CLOUDPLATFORM_COMPONENT_SECTION_KEY`
- Examples:
  - `CLOUDPLATFORM_DATABASE_HOST` overrides the database host
  - `CLOUDPLATFORM_SECURITY_AUTHENTICATION_MFA_ENABLED=false` disables MFA

### Validation

Configuration validation ensures correctness:

```python
from config.components import validate_component_config
from config.schemas import validate_config

# Validate a component configuration
is_valid = validate_component_config('security', environment='production')

# Validate a Python configuration class against its schema
is_valid = validate_config(production_config)

```

## Best Practices & Security

- **Sensitive Information**: Never store passwords, API keys, or tokens in configuration files
- **Secure Storage**: Use environment variables or a secrets manager (Vault, AWS Secrets Manager)
- **Validation**: All configuration files should be validated during CI/CD pipelines
- **Environment Isolation**: Use the strictest security settings in production
- **Naming Consistency**: Maintain consistent naming conventions across environments
- **Documentation**: Document all configuration options with comments
- **Principle of Least Privilege**: Configure minimum necessary permissions
- **Validation Before Deployment**: Use validation tools before applying configurations
- **Audit Trail**: Track configuration changes in version control

## Related Documentation

- Deployment Guide
- Environment Setup
- Security Configuration Guide
- Monitoring Configuration
- Component Configuration Guide
