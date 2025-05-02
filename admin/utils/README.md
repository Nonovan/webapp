# Administrative Utilities

This directory contains utility modules and helper functions used by the administrative tools in the Cloud Infrastructure Platform. These utilities provide core functionality for authentication, audit logging, configuration validation, secure credential handling, and more.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
  - [Authentication and Authorization](#authentication-and-authorization)
  - [Multi-Factor Authentication](#multi-factor-authentication)
  - [Audit Logging](#audit-logging)
  - [Configuration Validation](#configuration-validation)
  - [Secure Credential Handling](#secure-credential-handling)
  - [Password Management](#password-management)
  - [Error Handling](#error-handling)
  - [Metrics Collection](#metrics-collection)
  - [Security Utilities](#security-utilities)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The administrative utilities implement shared functionality used by the CLI tools, scripts, and other administrative components of the platform. These utilities ensure consistent behavior, proper security controls, and adherence to platform standards across all administrative tools. They provide reusable implementations of common operations such as authentication, authorization, audit logging, configuration validation, credential handling, and error handling.

## Key Components

- **`admin_auth.py`**: Administrative authentication and authorization
  - MFA integration for administrative access
  - Role-based permission verification
  - Authentication token management
  - Session security controls
  - Emergency access support
  - Login attempt monitoring and protection
  - MFA enforcement for sensitive operations

- **`audit_utils.py`**: Administrative audit logging facilities
  - Comprehensive audit trail generation
  - Tamper-evident log format
  - Admin action recording
  - User tracking and attribution
  - Event filtering and search capabilities
  - Compliance-ready logging format
  - MFA verification auditing

- **`config_validation.py`**: Configuration validation tools
  - Schema-based configuration validation
  - Type checking and constraint verification
  - Cross-field validation rules
  - Environment-specific validation
  - Default value management
  - Migration support for configuration changes
  - Security control validation

- **`secure_credentials.py`**: Secure credential handling
  - Secure storage and retrieval of credentials
  - Integration with platform secrets management
  - Credential rotation support
  - Temporary credential management
  - Memory protection for sensitive data
  - Secure credential disposal

- **`encryption_utils.py`**: Encryption and decryption utilities
  - AES-256 encryption for secure data storage
  - RSA-based key management
  - Secure random token generation
  - Envelope encryption for sensitive data

- **`error_handling.py`**: Centralized error handling utilities
  - Standardized error messages
  - Exception logging and categorization
  - Graceful recovery mechanisms

- **`metrics_utils.py`**: Performance and usage metrics collection
  - Resource usage monitoring (CPU, memory)
  - Execution time tracking for operations
  - Integration with monitoring systems (e.g., Prometheus)
  - Security event metrics tracking

- **`password_utils.py`**: Password generation and validation
  - Secure password generation with configurable complexity
  - Password strength validation against security requirements
  - Password history verification to prevent reuse
  - Integration with core security modules

- **`security_utils.py`**: Security utility functions
  - API token generation
  - Secure hash computation
  - Cryptographic primitives for administrative operations

## Directory Structure

```plaintext
admin/utils/
├── README.md             # This documentation
├── __init__.py           # Package initialization
├── admin_auth.py         # Authentication and authorization utilities
├── audit_utils.py        # Audit logging utilities
├── config_validation.py  # Configuration validation tools
├── encryption_utils.py   # Encryption and decryption utilities
├── error_handling.py     # Centralized error handling
├── metrics_utils.py      # Performance and usage metrics collection
├── password_utils.py     # Password generation and validation
├── secure_credentials.py # Secure credential management
└── security_utils.py     # Security utility functions
```

## Usage

### Authentication and Authorization

```python
from admin.utils.admin_auth import authenticate_admin, check_permission

# Authenticate an administrative user
auth_result = authenticate_admin(username, password, mfa_token)
session_token = auth_result["token"]

# Check if a user has the required permission
if check_permission(session_token, "system:configuration:write"):
    # Perform privileged operation
    update_system_configuration(new_config)
else:
    # Handle insufficient permissions
    raise AdminPermissionError("Insufficient permissions to modify system configuration")
```

### Multi-Factor Authentication

```python
from admin.utils.admin_auth import require_permission, require_mfa, verify_mfa_token

# Verify an MFA token manually
if verify_mfa_token(username, mfa_token):
    # MFA verification successful
    perform_sensitive_operation()

# Using the MFA decorator for sensitive operations
@require_permission("admin:system:maintenance")
@require_mfa("system_maintenance")
def perform_maintenance(system_id, maintenance_type, **kwargs):
    # This function will only execute if:
    # 1. User has the required permission
    # 2. MFA has been verified with a valid token
    # The operation_name "system_maintenance" is included in audit logs
    return execute_maintenance_task(system_id, maintenance_type)

# The function can be called with an MFA token
result = perform_maintenance(
    "primary-db-cluster",
    "scheduled-backup",
    auth_token="admin-session-token",
    mfa_token="123456"  # TOTP code from authenticator app
)
```

### Audit Logging

```python
from admin.utils.audit_utils import log_admin_action, get_audit_logs

# Log an administrative action
log_admin_action(
    action="user.create",
    user_id=current_user.id,
    details={
        "created_user": "jsmith",
        "roles_assigned": ["user", "developer"]
    },
    status="success"
)

# Retrieve audit logs for review
audit_logs = get_audit_logs(
    start_time="2023-07-15T00:00:00Z",
    end_time="2023-07-15T23:59:59Z",
    actions=["user.create", "user.modify"],
    user_id=admin_user_id
)
```

### Configuration Validation

```python
from admin.utils.config_validation import validate_config, load_schema

# Load a validation schema
schema = load_schema("system_configuration")

# Validate configuration against the schema
validation_result = validate_config(config_data, schema)

if validation_result.is_valid:
    # Apply the validated configuration
    apply_configuration(config_data)
else:
    # Handle validation errors
    for error in validation_result.errors:
        print(f"Validation error: {error.message} at {error.path}")
```

### Secure Credential Handling

```python
from admin.utils.secure_credentials import get_credential, store_credential

# Retrieve a secure credential
api_key = get_credential("external_service_api_key")

# Store a credential securely
store_credential(
    key="database_password",
    value=new_password,
    expires_in=3600  # Optional expiration in seconds
)

# Use secure credential with automatic cleanup
with secure_credential("encryption_key") as key:
    encrypted_data = encrypt_data(sensitive_data, key)
    # Key will be securely wiped from memory after the block
```

### Password Management

```python
from admin.utils.password_utils import generate_password, validate_password_strength, check_password_history

# Generate a secure random password
password = generate_password(
    length=16,
    include_uppercase=True,
    include_lowercase=True,
    include_digits=True,
    include_special=True
)

# Validate password strength
is_valid, error_messages = validate_password_strength(
    password="Proposed@Password123",
    username="admin.user",  # To prevent username in password
    min_length=12
)

if not is_valid:
    for error in error_messages:
        print(f"Password validation error: {error}")

# Check if password was previously used
password_history = ["$2a$10$...", "$2a$10$..."]  # Password hashes
is_unique, error = check_password_history(
    password="NewPassword123!",
    password_history=password_history,
    history_size=24
)

if not is_unique:
    print(f"Password history error: {error}")
```

### Error Handling

```python
from admin.utils.error_handling import handle_admin_error

try:
    # Perform some operation
    perform_operation()
except Exception as e:
    handle_admin_error(e, context="Configuration update", log_audit=True)
```

### Metrics Collection

```python
from admin.utils.metrics_utils import track_operation

# Track resource usage and execution time of a function
@track_operation("database_backup", "maintenance")
def perform_database_backup():
    # Function will be automatically timed and resource usage tracked
    run_backup_process()
```

### Security Utilities

```python
from admin.utils.security_utils import generate_api_token, compute_hash

# Generate a secure API token
token = generate_api_token(prefix="admin", length=32)

# Compute a secure hash with salt
password_hash, salt = compute_hash(data="sensitive_password")
```

## Best Practices & Security

- **Authentication**: Always verify user identity before granting access
- **Authorization**: Implement fine-grained permission checks for all operations
- **Audit Trail**: Log all administrative actions for accountability
- **Credential Protection**: Never store credentials in plaintext
- **Input Validation**: Validate and sanitize all inputs
- **Least Privilege**: Follow principle of least privilege for all operations
- **Memory Safety**: Avoid leaving sensitive data in memory
- **Multi-Factor Authentication**: Enforce MFA for sensitive operations
- **Secure Defaults**: Use secure default settings requiring explicit opt-out
- **Session Management**: Implement proper session controls and timeouts
- **MFA Enforcement**: Require MFA verification before allowing sensitive operations
- **Operation Documentation**: Include descriptive operation names in MFA requirements

## Common Features

All administrative utilities share these common features:

- **Comprehensive Logging**: Detailed logging for audit purposes
- **Error Handling**: Standardized error handling and reporting
- **Input Validation**: Thorough validation of all inputs
- **Metrics Collection**: Performance and usage metrics
- **Multi-Environment Support**: Support for development, staging, and production
- **Security Controls**: Built-in security best practices
- **Secure Defaults**: Conservative security defaults
- **Type Annotations**: Python type hints for better IDE support
- **Unit Testing**: Comprehensive test coverage
- **Version Information**: Clear version tracking
- **MFA Integration**: Support for multi-factor authentication
- **Decorator Patterns**: Function decorators for common security controls

## Related Documentation

- Administrative CLI
- Administrative Scripts
- Permission Model Reference
- Authentication Framework
- Multi-Factor Authentication Guide
- Audit Requirements
- Configuration Management
- Security Best Practices
- Emergency Access Procedures
