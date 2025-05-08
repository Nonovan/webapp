# Configuration Package

This directory contains configuration files for the Cloud Infrastructure Platform. It implements a hierarchical, environment-aware configuration system that separates settings by component and environment.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Configuration Files](#configuration-files)
- [Usage](#usage)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

The configuration system provides a unified approach to managing application settings across multiple environments with the following key features:

- **Environment Separation**: Different environments (development, staging, production) have separate configurations
- **Layered Configuration**: Core settings are inherited and overridden by environment-specific settings
- **Component Organization**: Configuration is separated by functional component
- **Schema Validation**: Configuration files are validated against schemas for consistency
- **Security by Design**: Sensitive information is managed separately from code
- **File Integrity Monitoring**: Automated detection of unauthorized file modifications
- **Disaster Recovery Support**: Specialized configuration for DR environments

## Architecture

The configuration system consists of two main components:

### 1. Python Configuration Classes

A hierarchy of Python classes that define environment-specific settings:

- **`base.py`**: Base configuration class with default settings for all environments
- **`development.py`, `staging.py`, `production.py`**: Environment-specific configurations
- **`ci.py`**: Continuous Integration environment configuration
- **`dr_recovery.py`**: Disaster recovery environment configuration
- **`local.py`**: Local development overrides (not version controlled)
- **`environments.py`**: Environment detection and handling logic
- **`config_constants.py`**: Common constants used across configurations

### 2. Component-specific Configuration Files

Specialized configuration files for different system components:

- **INI files**: For most system components
- **JSON files**: For structured data like API endpoints
- **YAML files**: For complex configuration scenarios (optional)

## Directory Structure

```plaintext
config/
├── __init__.py               # Package initialization
├── base.py                   # Base configuration class
├── ci.py                     # Continuous Integration environment configuration
├── config_constants.py       # Shared configuration constants
├── development.py            # Development environment configuration
├── dr_recovery.py            # Disaster recovery environment configuration
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
- **`ci.py`**: Continuous Integration settings, extends base configuration
- **`dr_recovery.py`**: Disaster Recovery settings, extends base configuration

### Component Configuration (INI Files)

| File | Description |
| --- | --- |
| **`app.ini`** | Core application settings (workers, timeouts, features) |
| **`api.ini`** | API configuration (rate limits, versioning, documentation) |
| **`security.ini`** | Security settings (password policies, session timeouts, MFA) |
| **`database.ini`** | Database connection settings for different environments |
| **`cache.ini`** | Caching configuration (Redis, Memcached settings) |
| **`email.ini`** | Email service configuration (SMTP, templates) |
| **`logging.ini`** | Logging levels, formats, and destinations |
| **`monitoring.ini`** | Monitoring settings (metrics, alerts, health checks) |
| **`backup.ini`** | Backup schedules, retention policies, storage locations |
| **`network.ini`** | Network settings, proxy configuration, and connectivity |
| **`storage.ini`** | File storage configuration (S3, Azure Blob, local) |
| **`compliance.ini`** | Compliance and regulatory settings |
| **`privacy.ini`** | Privacy settings (data retention, consent, GDPR) |

### JSON Configuration

- **`api_endpoints.json`**: Defines API endpoints, methods, and required permissions

## Usage

### Python Configuration

```python
from flask import Flask
from config import get_config

# Create a Flask application with the appropriate environment configuration
app = Flask(__name__)
config = get_config('production')  # Or 'development', 'staging', etc.
config.init_app(app)

# Access configuration settings
debug_mode = app.config['DEBUG']
database_url = app.config['SQLALCHEMY_DATABASE_URI']
```

### Component Configuration

```python
from config import load_component_config

# Load database configuration for the current environment
db_config = load_component_config('database')

# Access component configuration
host = db_config['postgres']['host']
port = db_config['postgres']['port']

# Load for a specific environment
api_config = load_component_config('api', 'production')
```

### Environment Variable Overrides

```bash
# Override configuration with environment variables
export DATABASE_URL="postgresql://user:password@localhost:5432/db"
export LOG_LEVEL="DEBUG"
export SECURITY_HEADERS_ENABLED="true"
export FILE_INTEGRITY_CHECK_INTERVAL="3600"
```

### Validation

```python
from config.schemas import validate_component_config

# Validate component configuration against schema
is_valid, errors = validate_component_config('security.ini')
if not is_valid:
    print(f"Configuration validation failed: {errors}")
```

### File Integrity Monitoring

The configuration package supports file integrity monitoring to detect unauthorized changes:

```python
from config import update_file_integrity_baseline, validate_baseline_integrity, initialize_file_monitoring

# Initialize file integrity monitoring for the application
initialize_file_monitoring(app)

# Validate file integrity against baseline
is_valid, violations = validate_baseline_integrity(app)
if not is_valid:
    print(f"Found {len(violations)} integrity violations")
    for violation in violations:
        print(f"File: {violation['file']}, Expected: {violation['expected']}, Actual: {violation['actual']}")

# Update the file integrity baseline for the current environment
success, message = update_file_integrity_baseline(
    app=app,
    baseline_path=None,  # Uses default path based on environment
    updates=changes,     # List of file changes to incorporate
    remove_missing=True, # Remove entries for files that no longer exist
    auto_update_limit=10 # Maximum number of files to auto-update (safety limit)
)
```

### Disaster Recovery Configuration

For accessing disaster recovery configuration and checking DR mode:

```python
from config import is_dr_mode_active, verify_dr_recovery_setup

# Check if the application is running in DR mode
if is_dr_mode_active(app):
    print("Application is running in disaster recovery mode")

# Verify that DR setup is properly configured
is_valid, issues = verify_dr_recovery_setup(app)
if not is_valid:
    print(f"DR recovery setup has issues:")
    for issue in issues:
        print(f"- {issue}")
```

## Best Practices & Security

### Security Considerations

- **Sensitive Information**: Never store passwords, API keys, or tokens in configuration files
- **Secure Storage**: Use environment variables or a secrets manager (Vault, AWS Secrets Manager)
- **Principle of Least Privilege**: Configure minimum necessary permissions
- **Environment Isolation**: Use the strictest security settings in production
- **File Integrity**: Enable file integrity monitoring for critical configuration files
- **Baseline Management**: Freeze integrity baselines during disaster recovery procedures

### Configuration Management

- **Validation**: All configuration files should be validated during CI/CD pipelines
- **Naming Consistency**: Maintain consistent naming conventions across environments
- **Documentation**: Document all configuration options with comments
- **Validation Before Deployment**: Use validation tools before applying configurations
- **Audit Trail**: Track configuration changes in version control
- **Baseline Management**: Regularly update file integrity baselines after approved changes
- **DR Preparation**: Ensure DR environment configurations are regularly updated and tested
- **Recovery Prioritization**: Maintain accurate recovery priority configurations

## Related Documentation

- Deployment Guide
- Environment Setup
- Security Configuration Guide
- Monitoring Configuration
- Component Configuration Guide
- File Integrity Monitoring Guide
- Disaster Recovery Guide
