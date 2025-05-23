# Core Package

This directory contains core components and utilities that provide the foundational functionality for the Cloud Infrastructure Platform. The core package implements essential services like security middleware, metrics collection, configuration management, and system health monitoring used throughout the application.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
  - [Application Factory](#application-factory)
  - [Core Configuration](#core-configuration)
  - [File Integrity Monitoring](#file-integrity-monitoring)
  - [Updating Integrity Baseline](#updating-integrity-baseline)
  - [Baseline Verification](#baseline-verification)
  - [Checking for Modified Files](#checking-for-modified-files)
  - [File Integrity Command-line Tools](#file-integrity-command-line-tools)
  - [Health Checks](#health-checks)
  - [Request ID Generation](#request-id-generation)
  - [Logging](#logging)
  - [Logging File Integrity Events](#logging-file-integrity-events)
  - [Cryptographic Operations](#cryptographic-operations)
  - [Path Safety Validation](#path-safety-validation)
  - [String Utilities](#string-utilities)
  - [System Resource Utilities](#system-resource-utilities)
  - [Collection Utilities](#collection-utilities)
  - [Validation Utilities](#validation-utilities)
  - [Security Initialization](#security-initialization)
  - [Environment Management](#environment-management)
- [Related Documentation](#related-documentation)

## Overview

The core package serves as the backbone of the Cloud Infrastructure Platform, providing critical infrastructure components that are used by multiple modules across the system. It implements application-wide concerns including security controls, metrics collection, middleware functionality, configuration management, and system health monitoring.

The design emphasizes modularity, security, and performance with clean separation of concerns. The core components are designed to be reusable, well-documented, and thoroughly tested to provide a solid foundation for building application features.

## Key Components

- **`config.py`**: Central configuration management with environment-specific settings
  - Provides hierarchical configuration with sensible defaults and environment overrides
  - Implements security configuration validation for production environments
  - Manages feature flags and environment-specific settings

- **`environment.py`**: Environment variable and runtime environment management
  - Detects and manages application environments (development, staging, production)
  - Provides centralized access to environment variables with type conversion
  - Supports multiple environment file formats (.env, JSON, YAML)
  - Implements secure handling of sensitive environment data
  - Enables environment-specific behavior and configuration

- **`factory.py`**: Application factory for Flask application initialization
  - Creates and configures the Flask application with appropriate settings
  - Registers extensions, blueprints, and error handlers
  - Sets up logging and monitoring infrastructure

- **`health.py`**: Health check functionality for system monitoring
  - Implements comprehensive health checks for all system components
  - Provides status reporting for external monitoring systems
  - Supports dependency health verification (database, cache, external services)
  - Includes file integrity monitoring status verification

- **`middleware.py`**: HTTP request/response middleware
  - Implements security headers (CSP, HSTS, XSS protection)
  - Sets up request timing and performance tracking with request ID generation
  - Provides response compression and request logging
  - Performs periodic file integrity checks during requests

- **`metrics.py`**: System and application metrics collection
  - Tracks performance metrics for API endpoints and critical functions
  - Monitors system resource utilization (CPU, memory, connections)
  - Provides security metrics for compliance and monitoring
  - Records file integrity verification metrics and status

- **`seeder.py`**: Data seeding functionality
  - Populates initial data for development and testing
  - Creates default users, roles, and permissions
  - Sets up sample cloud resources and configurations
  - Generates file integrity test scenarios and baseline data
  - Implements file integrity baseline management functions

- **`utils/`**: Specialized utility modules
  - Organized collection of focused utility modules
  - Each module provides specialized functionality for a specific domain
  - Modules include string, date/time, file, collection, system, validation, and logging utilities
  - Promotes code reuse and proper separation of concerns

- **`security/`**: Comprehensive security module
  - Centralized security implementation spanning multiple security domains
  - Modular approach with specialized components for different security concerns
  - Includes file integrity monitoring, cryptographic operations, and authentication services
  - Implements security event logging and audit trail functionality

## Directory Structure

```plaintext
core/
├── __init__.py           # Package initialization
├── config.py             # Configuration management
├── environment.py        # Environment management
├── factory.py            # Application factory
├── health.py             # Health check functionality
├── metrics.py            # Metrics collection
├── middleware.py         # HTTP middleware with request ID generation
├── README.md             # This documentation
├── seeder.py             # Data seeding functionality
├── security/             # Security components
│   ├── __init__.py       # Security package initialization
│   ├── cs_audit.py       # Security audit implementation
│   ├── cs_authentication.py # Authentication services
│   ├── cs_authorization.py  # Authorization services
│   ├── cs_constants.py      # Security constants with integrity settings
│   ├── cs_crypto.py         # Cryptographic operations (includes hash functions)
│   ├── cs_file_integrity.py # File integrity monitoring
│   ├── cs_metrics.py        # Security metrics
│   ├── cs_monitoring.py     # Security monitoring
│   ├── cs_session.py        # Session management
│   ├── cs_utils.py          # Security utility functions
│   └── README.md            # Security module documentation
├── templates/            # Core templates
│   ├── README.md         # Templates documentation
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
└── utils/                # Specialized utilities (modular organization)
    ├── __init__.py       # Utility package initialization and exports
    ├── collection.py     # Collection data structure manipulation
    ├── date_time.py      # Date and time handling utilities
    ├── file.py           # File handling utilities
    ├── logging_utils.py  # Logging configuration utilities
    ├── README.md         # Utility modules documentation
    ├── string.py         # String manipulation utilities
    ├── system.py         # System resource utilities
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
'SECURITY_CRITICAL_FILES': ['app.py', 'config.py', 'core/security/*.py', 'core/middleware.py'],
'MAX_BASELINE_FILE_SIZE': 10 * 1024 * 1024,  # 10MB limit for monitored files
'SAFE_BASELINE_UPDATE_PATH': 'instance/security/baseline',  # Default baseline storage location

# Request tracking settings
'REQUEST_ID_PREFIX': 'req',
'REQUEST_ID_INCLUDE_TIMESTAMP': True,
'REQUEST_ID_INCLUDE_HOST': True,
'REQUEST_ID_INCLUDE_PID': True,
'TRACK_SLOW_REQUESTS': True,
'SLOW_REQUEST_THRESHOLD': 2.0  # Seconds
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
- **Modular Organization**: Code organized by feature area with specialized modules
- **Request Tracing**: Consistent request ID generation and propagation
- **Atomic Operations**: File operations use atomic patterns to prevent partial writes
- **Permission Verification**: File and directory permission checks for security
- **Environment Awareness**: Components adapt behavior based on runtime environment

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
- Request ID generation for tracing requests through the system
- System resource monitoring and tracking
- Permission monitoring for critical files
- Environment detection and management
- Secure environment variable handling

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
    baseline_path="instance/file_baseline.json",
    updates=[
        {"path": "config.py", "current_hash": "5d41402abc4b2a76b9719d911017c592"},
        {"path": "app.py", "current_hash": "7d793037a0760186574b0282f2f435e7"}
    ],
    remove_missing=True
)
```

### Baseline Verification

```python
from core.security.cs_file_integrity import verify_baseline_update

# Verify if a baseline update should be permitted
is_safe = verify_baseline_update(
    file_path="config.py",
    current_hash="a1b2c3d4e5f6",
    expected_hash="5d41402abc"
)

if not is_safe:
    log_security_event("baseline_update_rejected", "Unsafe baseline update rejected")
```

### Checking for Modified Files

```python
from core.security.cs_file_integrity import detect_file_changes

# Detect changes in critical files
changes = detect_file_changes(
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

### File Integrity Command-line Tools

```bash
# Update the file integrity baseline
flask integrity update-baseline

# Use patterns to include specific files
flask integrity update-baseline --include "*.py" "config/*.yaml"

# Force update including critical files
flask integrity update-baseline --force

# Create a backup before updating
flask integrity update-baseline --backup

# Verify files against the baseline
flask integrity verify

# Analyze files for potential integrity risks
flask integrity analyze --path /app --pattern "*.py" "*.config"
```

Or programmatically:

```python
from core.seeder import update_integrity_baseline, verify_baseline_integrity

# Update the integrity baseline with custom patterns
result = update_integrity_baseline(
    include_pattern=["*.py", "config/*.yaml"],
    exclude_pattern=["__pycache__/*", "*.pyc"],
    backup=True,
    verbose=True
)

if result['success']:
    print(f"Baseline updated with {result['stats']['added']} new files")

# Verify the integrity of files against the baseline
verification = verify_baseline_integrity(verbose=True)
if verification['changes_detected']:
    print(f"Warning: {len(verification['changes'])} integrity violations found")
    for change in verification['changes']:
        if change['severity'] == 'critical':
            print(f"Critical: {change['path']} has been {change['status']}")
```

### Health Checks

```python
from core.health import healthcheck

@app.route('/health')
def health():
    result = healthcheck()
    return jsonify(result)
```

### Request ID Generation

```python
from core.middleware import generate_request_id

# Generate a unique request ID
request_id = generate_request_id(
    prefix="req",
    include_timestamp=True,
    include_host=True,
    include_pid=True
)
```

### Logging

```python
from core.utils.logging_utils import get_logger

logger = get_logger(__name__)
logger.info("Operation completed", extra={"operation": "user_login", "user_id": user.id})
```

### Logging File Integrity Events

```python
from core.utils.logging_utils import log_file_integrity_event

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

### Cryptographic Operations

```python
from core.security.cs_crypto import compute_hash

# Use the unified hash computation function (merged from previous functions)
file_hash = compute_hash(file_path="/path/to/file.txt", algorithm="sha256")
data_hash = compute_hash(data="Text to hash", algorithm="sha384", output_format="base64")
sri_hash = compute_hash(data="SRI data", algorithm="sha384", output_format="sri")
```

### Path Safety Validation

```python
from core.security.cs_utils import is_safe_file_operation, sanitize_path

# Validate path safety to prevent path traversal
safe_path = sanitize_path(user_input, base_dir="/safe/directory")

# Check if a file operation is safe
if is_safe_file_operation("write", target_path, safe_dirs=["/app/uploads", "/app/temp"]):
    # Operation is safe
    write_to_file(target_path, data)
```

### String Utilities

```python
from core.utils.string import slugify, truncate_text

# Generate URL-friendly slug
post_slug = slugify("My Blog Post Title!")  # Output: "my-blog-post-title"

# Truncate text with word boundary
excerpt = truncate_text(long_content, length=150)  # Truncates at word boundary
```

### System Resource Utilities

```python
from core.utils.system import get_system_resources, measure_execution_time

# Get current system resources
resources = get_system_resources()
print(f"CPU: {resources['cpu_percent']}%, Memory: {resources['memory_used']} MB")

# Time a function's execution
with measure_execution_time() as timer:
    result = expensive_operation()
print(f"Operation took {timer.duration:.2f} seconds")
```

### Collection Utilities

```python
from core.utils.collection import deep_get, deep_set, safe_json_serialize

# Safely access nested dictionary values
user_name = deep_get(data, "user.profile.name", default="Unknown User")

# Set value in nested structure
deep_set(config, "security.headers.content_security_policy.enabled", True)

# Safely serialize complex objects to JSON
json_string = safe_json_serialize(complex_object_with_dates_and_custom_classes)
```

### Validation Utilities

```python
from core.utils.validation import validate_with_schema, is_valid_email, is_valid_choice

# Validate data against a schema
user_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 2},
        "email": {"type": "string", "format": "email"},
        "age": {"type": "integer", "minimum": 18},
        "role": {"type": "string"}
    },
    "required": ["name", "email"]
}

is_valid, errors = validate_with_schema(user_data, user_schema)
if not is_valid:
    raise ValidationError(f"Invalid user data: {errors}")

# Check if value is within valid choices
valid_roles = ["admin", "editor", "user", "guest"]
if is_valid_choice(user_data.get("role"), valid_roles):
    # Process role
    assign_role(user_data["role"])
```

### Security Initialization

```python
from core.security import init_security, initialize_security_components

# Initialize all security components at application startup
init_security()

# Set up specific security components with custom configuration
initialize_security_components(
    enable_audit_logging=True,
    enable_file_integrity=True,
    enable_metrics=True
)
```

### Environment Management

```python
from core.environment import load_env, get_current_environment, is_production

# Load environment configuration
env = load_env(env_file=".env.production")

# Check current environment
current_env = get_current_environment()
print(f"Running in {current_env} environment")

# Get typed environment variables
database_url = env.get("DATABASE_URL")
max_connections = env.get_int("MAX_CONNECTIONS", default=100)
debug_mode = env.get_bool("DEBUG_MODE", default=False)
allowed_hosts = env.get_list("ALLOWED_HOSTS", separator=",")

# Environment-specific behavior
if is_production():
    # Apply production-specific settings
    logging.getLogger().setLevel(logging.WARNING)
else:
    # Apply development settings
    logging.getLogger().setLevel(logging.DEBUG)
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
- Core Security Utility Migration Guide
- System Resource Monitoring Guide
- Permission Security Model
- Baseline Management Guide
- File Integrity CLI Tools Guide
- Environment Management
- Configuration Hierarchy
