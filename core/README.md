# Core Package

This directory contains core components and utilities that provide the foundational functionality for the Cloud Infrastructure Platform. The core package implements essential services like security middleware, metrics collection, configuration management, and system health monitoring used throughout the application.

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

- **`loggings.py`**: Centralized logging configuration
  - Configures structured logging with appropriate formatting
  - Implements security event logging with proper sanitization
  - Provides context-aware logging with request IDs and correlation

- **`metrics.py`**: System and application metrics collection
  - Tracks performance metrics for API endpoints and critical functions
  - Monitors system resource utilization (CPU, memory, connections)
  - Provides security metrics for compliance and monitoring

- **`middleware.py`**: HTTP request/response middleware
  - Implements security headers (CSP, HSTS, XSS protection)
  - Sets up request timing and performance tracking
  - Provides response compression and request logging

- **`security_utils.py`**: Security utilities and helpers
  - Implements secure cryptographic operations
  - Provides input validation and sanitization
  - Manages security controls and audit logging

- **`seeder.py`**: Data seeding functionality
  - Populates initial data for development and testing
  - Creates default users, roles, and permissions
  - Sets up sample cloud resources and configurations

- **`utils.py`**: General utility functions
  - Provides commonly used helper functions
  - Implements reusable patterns across the application
  - Contains formatting and conversion utilities

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
├── security_utils.py     # Security utilities
├── seeder.py             # Data seeding functionality
├── utils.py              # General utilities
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
'FEATURE_MFA': True
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

## Common Features

- CSP nonce generation for secure inline scripts
- Request timing and performance tracking
- Security header management with proper configuration
- Environment-aware configuration loading
- Comprehensive health check system
- Structured metrics collection
- Standardized error handling

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

### Logging

```python
from core.loggings import get_logger

logger = get_logger(__name__)
logger.info("Operation completed", extra={"operation": "user_login", "user_id": user.id})
```

### Core Configuration

```python
from core.config import Config

db_url = Config.get('DATABASE_URL')
is_debug = Config.get('DEBUG', False)
```

## Related Documentation

- Security Configuration
- Monitoring and Metrics
- Application Architecture
- Error Handling
- Configuration Management

## Version Information

- **Version**: 0.0.0
- **Last Updated**: 2023-10-15
- **Maintainers**: Platform Engineering Team
