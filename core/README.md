# Core Package

This directory contains core components and utilities that provide the foundational functionality for the Cloud Infrastructure Platform. The core package implements essential services like security middleware, metrics collection, configuration management, and system health monitoring used throughout the application.

## Contents

- Overview
- Key Components
- Directory Structure
- Configuration
- Best Practices & Security
- Common Features
- Usage Examples
- Related Documentation
- Version Information

## Overview

The core package serves as the backbone of the Cloud Infrastructure Platform, providing critical infrastructure components that are used by multiple modules across the system. It implements application-wide concerns including security controls, metrics collection, middleware functionality, configuration management, and system health monitoring.

## Key Components

- **`config.py`**: Central configuration management with environment-specific settings
  - Provides hierarchical configuration with sensible defaults and environment overrides
  - Implements security configuration validation for production environments
  - Manages feature flags and environment-specific settings
- **`factory.py`**: Application factory for Flask application initialization
  - Creates and configures the Flask application with appropriate settings
  - Registers extensions, blueprints, and error handlers
  - Sets up logging and monitoring infrastructure
- **`health.py`**: Health check functionality for system monitoring
  - Implements comprehensive health checks for all system components
  - Provides status reporting for external monitoring systems
  - Supports dependency health verification (database, cache, external services)
  - Includes file integrity monitoring status verification
- **`loggings.py`**: Centralized logging configuration
  - Configures structured logging with appropriate formatting
  - Implements security event logging with proper sanitization
  - Provides context-aware logging with request IDs and correlation
  - Contains file integrity monitoring event handlers and reporting
- **`metrics.py`**: System and application metrics collection
  - Tracks performance metrics for API endpoints and critical functions
  - Monitors system resource utilization (CPU, memory, connections)
  - Provides security metrics for compliance and monitoring
  - Records file integrity verification metrics and status
- **`middleware.py`**: HTTP request/response middleware
  - Implements security headers (CSP, HSTS, XSS protection)
  - Sets up request timing and performance tracking
  - Provides response compression and request logging
  - Performs periodic file integrity checks during requests
- **`utils.py`**: General utility functions
  - Provides commonly used helper functions
  - Implements reusable patterns across the application
  - Contains formatting and conversion utilities
  - Includes file integrity verification and baseline management
- **`seeder.py`**: Data seeding functionality
  - Populates initial data for development and testing
  - Creates default users, roles, and permissions
  - Sets up sample cloud resources and configurations
  - Generates file integrity test scenarios and baseline data

## Directory Structure

```plaintext
core/
├── __init__.py           # Package initialization
├── config.py             # Configuration management
├── factory.py            # Application factory
├── health.py             # Health check functionality
├── loggings.py           # Logging configuration
├── metrics.py            # Metrics collection
├── middleware.py         # HTTP middleware
├── README.md             # This documentation
├── seeder.py             # Data seeding functionality
├── utils.py              # General utilities
├── security/             # Security components
│   ├── __init__.py       # Security package initialization
│   ├── cs_audit.py       # Security audit implementation
│   ├── cs_authentication.py # Authentication services
│   ├── cs_authorization.py  # Authorization services
│   ├── cs_constants.py      # Security constants
│   ├── cs_crypto.py         # Cryptographic operations
│   ├── cs_file_integrity.py # File integrity monitoring
│   ├── cs_metrics.py        # Security metrics
│   ├── cs_monitoring.py     # Security monitoring
│   ├── cs_session.py        # Session management
│   ├── cs_utils.py          # Security utilities
│   └── README.md            # Security module documentation
└── templates/            # Core templates
    ├── errors/           # Error page templates
    └── layouts/          # Base layout templates

```

## Configuration

The core package uses the following configuration settings:

```python
# Security settings
'SESSION_COOKIE_SECURE': True,
'SESSION_COOKIE_HTTPONLY': True,
'SESSION_COOKIE_SAMESITE': 'Lax',
'WTF_CSRF_ENABLED': True,
'SECURITY_HEADERS_ENABLED': True,

# JWT settings
'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=15),
'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),

# Monitoring settings
'METRICS_ENABLED': True,
'LOG_LEVEL': 'INFO',
'SECURITY_LOG_LEVEL': 'WARNING',

# Feature flags
'FEATURE_DARK_MODE': True,
'FEATURE_ICS_CONTROL': True,
'FEATURE_CLOUD_MANAGEMENT': True,
'FEATURE_MFA': True,

# File integrity monitoring settings
'ENABLE_FILE_INTEGRITY_MONITORING': True,
'FILE_INTEGRITY_CHECK_FREQUENCY': 100,
'SECURITY_CRITICAL_FILES': ['app.py', 'config.py', 'core/security_utils.py', 'core/middleware.py'],
'FILE_HASH_ALGORITHM': 'sha256',
'AUTO_UPDATE_BASELINE': False,
'FILE_BASELINE_PATH': 'instance/file_baseline.json'

```

## Best Practices & Security

- **Defense in Depth**: Multiple security controls are layered for comprehensive protection
- **Input Validation**: All user inputs are validated before processing
- **Output Encoding**: Content is properly encoded to prevent XSS
- **Secure Headers**: HTTP security headers are enforced on all responses
- **Principle of Least Privilege**: Access controls follow the principle of least privilege
- **Audit Logging**: Security events are logged with appropriate detail
- **Circuit Breakers**: External service calls implement circuit breakers to prevent cascading failures
- **Resource Protection**: Rate limiting and resource quotas prevent abuse
- **Configuration Validation**: Security-critical configuration is validated before application startup
- **File Integrity Monitoring**: Critical system files are monitored for unauthorized changes
- **Baseline Management**: Secure handling of integrity baselines with controlled updates

## Common Features

- CSP nonce generation for secure inline scripts
- Request timing and performance tracking
- Security header management with proper configuration
- Environment-aware configuration loading
- Comprehensive health check system
- Structured metrics collection
- Standardized error handling
- File integrity verification
- Security event correlation
- Performance-optimized monitoring

## Usage Examples

### Application Factory

```python
from core.factory import create_app

# Create application instance with production config
app = create_app('production')

```

### Security Headers

```python
from flask import Flask
from core.middleware import init_middleware

app = Flask(__name__)
init_middleware(app)  # Sets up security headers, CSP, etc.

```

### Metrics Collection

```python
from core.metrics import track_metrics

@track_metrics('user_registration')
def register_user(data):
    # Function implementation
    pass

```

### Health Checks

```python
from core.health import healthcheck

@app.route('/health')
def health():
    result = healthcheck()
    return jsonify(result)

```

### File Integrity Monitoring

```python
from core.security.cs_file_integrity import check_critical_file_integrity

# Verify integrity of security-critical files
is_valid, changes = check_critical_file_integrity()
if not is_valid:
    log_security_event("file_integrity_violation", f"Detected {len(changes)} modified files")

```

### Updating Integrity Baseline

```python
from core.utils import update_file_integrity_baseline

# Create or update a file integrity baseline
success, message = update_file_integrity_baseline(
    'instance/baseline.json',
    {'app.py': '5d41402abc4b2a76b9719d911017c592'},
    remove_missing=True
)

```

### Logging

```python
from core.loggings import get_logger

logger = get_logger(__name__)
logger.info("Operation completed", extra={"operation": "user_login", "user_id": user.id})

```

### Logging File Integrity Events

```python
from core.loggings import log_file_integrity_event

# Log a file integrity event
log_file_integrity_event(
    file_path='config.py',
    status='modified',
    severity='critical',
    details={'old_hash': 'abc123', 'new_hash': 'def456'}
)

```

### Core Configuration

```python
from core.config import Config

db_url = Config.get('DATABASE_URL')
is_debug = Config.get('DEBUG', False)

```

## Related Documentation

- Security Architecture
- File Integrity Monitoring Guide
- Monitoring and Metrics
- Application Architecture
- Error Handling
- Configuration Management

## Version Information

- **Version**: 0.0.1
- **Last Updated**: 2024-05-20
- **Maintainers**: Platform Engineering Team
