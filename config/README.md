# Configuration Package

This directory contains configuration files for the Cloud Infrastructure Platform. It implements a hierarchical, environment-aware configuration system that separates settings by component and environment.

## Overview

The configuration system follows these principles:

- **Environment Separation**: Different environments (development, staging, production) have separate configurations
- **Layered Configuration**: Core settings are inherited and overridden by environment-specific settings
- **Component Organization**: Configuration is separated by functional component
- **Schema Validation**: Configuration files are validated against schemas for consistency

## Key Components

- **`base.py`**: Base configuration class with default settings for all environments
- **`development.py`, `staging.py`, `production.py`**: Environment-specific configurations
- **`local.py`**: Local development overrides (not version controlled)
- **`environments.py`**: Environment detection and handling logic
- **`schemas/`**: JSON schemas for configuration validation

## Directory Structure

```plaintext
config/
├── __init__.py               # Package initialization
├── api_endpoints.json        # API endpoint definitions
├── api.ini                   # API gateway configuration
├── app.ini                   # Core application settings
├── backup.ini                # Backup and disaster recovery
├── base.py                   # Base configuration class
├── cache.ini                 # Caching configuration
├── compliance.ini            # Compliance and regulatory settings
├── database.ini              # Database connection settings
├── development.py            # Development environment configuration
├── email.ini                 # Email service configuration
├── environments.py           # Environment detection logic
├── local.py                  # Local development overrides
├── logging.ini               # Logging configuration
├── monitoring.ini            # Monitoring system settings
├── network.ini               # Network and connectivity settings
├── privacy.ini               # Privacy and data protection
├── production.py             # Production environment configuration
├── README.md                 # Configuration documentation (this file)
├── security.ini              # Security settings
├── staging.py                # Staging environment configuration
├── storage.ini               # Storage system configuration
├── testing.py                # Testing environment configuration
└── schemas/                  # JSON schemas for validation
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

### JSON Configuration

- **`api_endpoints.json`**: Defines API endpoints, methods, and required permissions

## Usage

### Python Configuration

The Python configuration classes define a hierarchy where environment-specific classes inherit from the base Config class:

```python
from config import Config, DevelopmentConfig, ProductionConfig

# Base configuration with fallback values
app_config = Config()

# Environment-specific configuration (overrides base config)
if app.debug:
    app_config = DevelopmentConfig()
else:
    app_config = ProductionConfig()
```

### INI File Configuration

INI files are used for component-specific configuration:

```python
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('config/database.ini')

# Access configuration sections
db_config = config['production']
host = db_config.get('host')
port = db_config.getint('port', 5432)
```

## Environment Variables

Configuration values can be overridden by environment variables:

- Environment variables take precedence over configuration files
- Variable names should follow the pattern: `CLOUDPLATFORM_SECTION_KEY`
- Example: `CLOUDPLATFORM_DATABASE_HOST` overrides the database host

## Schema Validation

Configuration files are validated against schemas in the `schemas/` directory:

- JSON schemas follow the JSON Schema standard
- INI schemas define required sections and key-value pairs
- Validation occurs during application startup and deployment

## Best Practices & Security

- Never store sensitive information (passwords, API keys) in configuration files
- Use environment variables or a secure vault for sensitive data
- All configuration files should be validated during CI/CD
- Production configuration should disable debug features
- Use the strictest security settings in production
- Maintain consistent configuration naming across environments
- Document all configuration options with comments and examples

## Related Documentation

- Deployment Guide
- Environment Setup
- Security Configuration
- Monitoring Configuration
