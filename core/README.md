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

- **`seeder.py`**: Data seeding functionality
  - Populates initial data for development and testing
  - Creates default users, roles, and permissions
  - Sets up sample cloud resources and configurations
  - Generates file integrity test scenarios and baseline data

- **`utils.py`**: General utility functions
  - Provides commonly used helper functions
  - Implements reusable patterns across the application
  - Contains formatting and conversion utilities
  - Includes file integrity verification and baseline management

- **`utils/`**: Specialized utility modules
  - Contains modular, reusable functionality across the application
  - Provides string manipulation utilities for text processing
  - Implements date/time handling with timezone support
  - Offers file operations with security features
  - Includes collection manipulation and data validation tools
  - Provides basic security utilities for common operations

- **`security/cs_file_integrity.py`**: File integrity monitoring system
  - Detects unauthorized changes to critical system files
  - Compares file hashes against known good baselines
  - Supports permission change detection for critical files
  - Implements configurable severity classification for changes
  - Provides baseline management with secure update mechanisms

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
├── templates/            # Core templates
│   ├── README.md         # Templates documentation
│   ├── cs_file_integrity_2.py # File integrity template utility
│   ├── errors/           # Error page templates
│   │   ├── 400.html      # Bad request error template
│   │   ├── 401.html      # Unauthorized error template
│   │   ├── 403.html      # Forbidden error template
│   │   ├── 404.html      # Not found error template
│   │   ├── 500.html      # Internal server error template
│   │   └── base_error.html # Base template for all error pages
│   └── layouts/          # Base layout templates
│       ├── base.html     # Core layout template
│       ├── minimal.html  # Minimal layout without navigation
│       └── secure.html   # Security-enhanced layout
└── utils/                # Specialized utilities
    ├── __init__.py       # Utility package initialization
    ├── collection.py     # Collection data structure manipulation
    ├── date_time.py      # Date and time handling utilities
    ├── file.py           # File handling utilities
    ├── README.md         # Utility modules documentation
    ├── string.py         # String manipulation utilities
    └── validation.py     # Input validation utilities
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
'FEATURE_CLOUD_MANAGEMENT': True,
'FEATURE_ICS_CONTROL': True,
'FEATURE_MFA': True,

# File integrity monitoring settings
'AUTO_UPDATE_BASELINE': False,
'ENABLE_FILE_INTEGRITY_MONITORING': True,
'FILE_BASELINE_PATH': 'instance/file_baseline.json',
'FILE_HASH_ALGORITHM': 'sha256',
'FILE_INTEGRITY_CHECK_FREQUENCY': 100,
'SECURITY_CRITICAL_FILES': ['app.py', 'config.py', 'core/security_utils.py', 'core/middleware.py']
```

## Best Practices & Security

- **Audit Logging**: Security events are logged with appropriate detail
- **Circuit Breakers**: External service calls implement circuit breakers to prevent cascading failures
- **Configuration Validation**: Security-critical configuration is validated before application startup
- **Defense in Depth**: Multiple security controls are layered for comprehensive protection
- **File Integrity Monitoring**: Critical system files are monitored for unauthorized changes
- **Input Validation**: All user inputs are validated before processing
- **Output Encoding**: Content is properly encoded to prevent XSS
- **Principle of Least Privilege**: Access controls follow the principle of least privilege
- **Resource Protection**: Rate limiting and resource quotas prevent abuse
- **Secure Baseline Management**: Secure handling of integrity baselines with controlled updates
- **Secure Headers**: HTTP security headers are enforced on all responses
- **String Manipulation Safety**: Secure string handling with proper encoding
- **Timezone Awareness**: Date/time handling properly manages timezone information
- **Thread Safety**: Utilities designed for concurrent environment safety

## Common Features

- Comprehensive health check system
- CSP nonce generation for secure inline scripts
- Environment-aware configuration loading
- File integrity verification
- Performance-optimized monitoring
- Request timing and performance tracking
- Security event correlation
- Security header management with proper configuration
- Standardized error handling
- Structured metrics collection
- Common string utilities for consistent text processing
- URL-safe slug generation for content management
- Date/time utilities with timezone support
- Collection manipulation for complex data structures
- Input validation with comprehensive schema support
- Secure file operations with atomic writing

## Usage Examples

### Application Factory

```python
from core.factory import create_app

# Create application instance with production config
app = create_app('production')
```

### Core Configuration

```python
from core.config import Config

db_url = Config.get('DATABASE_URL')
is_debug = Config.get('DEBUG', False)
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
from core.security.cs_file_integrity import update_file_integrity_baseline

# Update the file integrity baseline with new or changed files
update_file_integrity_baseline(
    app,
    baseline_path="instance/file_baseline.json",
    updates=[
        {"path": "config.py", "current_hash": "5d41402abc4b2a76b9719d911017c592"},
        {"path": "app.py", "current_hash": "7d793037a0760186574b0282f2f435e7"}
    ],
    remove_missing=True
)
```

### Checking for Modified Files

```python
from core.security.cs_file_integrity import _detect_file_changes

# Detect changes in critical files
changes = _detect_file_changes(
    basedir="/app",
    reference_hashes=app.config["CRITICAL_FILE_HASHES"],
    critical_patterns=["*.py", "*.config"],
    detect_permissions=True,
    check_signatures=True
)

# Process detected changes
for change in changes:
    if change["severity"] == "critical":
        handle_critical_change(change)
    elif change["severity"] == "high":
        handle_high_severity_change(change)
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

### Logging File Integrity Events

```python
from core.loggings import log_file_integrity_event

# Log file integrity violations with appropriate severity levels
log_file_integrity_event([
    {
        'path': 'config.py',
        'status': 'modified',
        'severity': 'critical',
        'expected_hash': 'abc123',
        'current_hash': 'def456',
        'timestamp': '2024-07-25T14:22:10Z'
    }
])
```

### Metrics Collection

```python
from core.metrics import track_metrics

@track_metrics('user_registration')
def register_user(data):
    # Function implementation
    pass
```

### Security Headers

```python
from flask import Flask
from core.middleware import init_middleware

app = Flask(__name__)
init_middleware(app)  # Sets up security headers, CSP, etc.
```

### String Utilities

```python
from core.utils.string import slugify, truncate_text

# Generate URL-friendly slug
post_slug = slugify("My Blog Post Title!")  # Output: "my-blog-post-title"

# Truncate text with word boundary
excerpt = truncate_text(long_content, length=150)  # Truncates at word boundary
```

### Date/Time Utilities

```python
from core.utils.date_time import utcnow, format_relative_time, parse_iso_datetime

# Get current UTC time
current_time = utcnow()

# Format relative time string
relative = format_relative_time(event_date)  # e.g., "2 hours ago"

# Parse ISO format date
event_date = parse_iso_datetime("2024-07-15T14:30:00Z")
```

### Collection Utilities

```python
from core.utils.collection import deep_get, deep_set, flatten_dict

# Safely access nested dictionary values
user_name = deep_get(data, "user.profile.name", default="Unknown User")

# Set value in nested structure
deep_set(config, "security.headers.content_security_policy.enabled", True)

# Convert nested dictionary to flat structure
flat_data = flatten_dict(nested_data, separator=".")
```

### File Utilities

```python
from core.utils.file import compute_file_hash, save_json_file, is_path_safe

# Compute secure hash of file
file_hash = compute_file_hash("/path/to/file.txt", algorithm="sha256")

# Safely save JSON data atomically
save_json_file("/path/to/output.json", {"key": "value"}, indent=2)

# Validate path safety to prevent path traversal
if is_path_safe(user_path, allowed_base_dirs=["/allowed/path"]):
    process_file(user_path)
```

## Related Documentation

- Application Architecture
- Configuration Management
- Error Handling
- File Integrity Monitoring Guide
- Monitoring and Metrics
- Security Architecture
- String Utility Reference
- Date/Time Utility Reference
- Collection Utility Reference
- File Utility Reference
- URL Generation Guidelines
- Validation Framework Guide

## Version History

- **Version**: 0.1.1
- **Last Updated**: 2024-07-25
