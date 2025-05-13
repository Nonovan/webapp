# Security Module for Core Scripts

This directory contains security-related functionality that provides core security capabilities for the Cloud Infrastructure Platform.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Security Best Practices](#security-best-practices)
- [Common Features](#common-features)
- [Integration Points](#integration-points)
- [Module Dependencies](#module-dependencies)
- [Related Documentation](#related-documentation)
- [Version History](#version-history)

## Overview

The security module provides fundamental security capabilities that can be leveraged across the entire Cloud Infrastructure Platform. It implements secure cryptographic operations, file integrity verification, and permission management that follow industry best practices including NIST guidelines, CIS benchmarks, and OWASP recommendations. These components are designed to be reusable building blocks that enforce consistent security controls throughout the platform.

## Key Components

- **`crypto.py`**: Cryptographic operations framework for secure data handling.
  - **Usage**: Import this module for encryption, hashing, and key management.
  - **Features**:
    - AES-GCM encryption with authenticated encryption
    - RSA asymmetric encryption for key exchange
    - Secure key derivation functions (PBKDF2, Argon2)
    - Cryptographically secure random number generation
    - Password hashing with adjustable work factors
    - Digital signature generation and verification
    - Hash computation with multiple algorithms
    - Key rotation management
    - Secure data wiping
    - Cryptographic parameter validation

- **`integrity_check.py`**: File integrity monitoring and verification system.
  - **Usage**: Import this module to verify file integrity and detect unauthorized changes.
  - **Features**:
    - Multiple hash algorithm support (SHA-256, SHA-512, BLAKE2)
    - Baseline generation for integrity verification
    - Change detection with detailed reporting
    - Recursive directory scanning
    - File exclusion patterns
    - Integrity status caching
    - Verification scheduling
    - Critical file prioritization
    - Tamper evidence logging
    - Integration with notification system
    - Secure baseline storage

- **`permissions.py`**: Secure file and directory permissions management.
  - **Usage**: Import this module to handle permission checks and enforcement.
  - **Features**:
    - Permission validation against security baselines
    - Recursive permission application
    - Security-focused permission patterns
    - Ownership verification
    - SUID/SGID detection
    - World-writable file detection
    - Executable stack detection
    - Compliance checking against standards
    - Permission audit logging
    - Platform-aware permission handling
    - Security policy enforcement

- **`__init__.py`**: Centralized initialization for security components.
  - **Usage**: Import to initialize security modules with dependencies.
  - **Features**:
    - Security component dependency resolution
    - Cryptography subsystem initialization
    - File integrity monitoring setup
    - Permission management configuration
    - Security metrics collection
    - Centralized security logging
    - Component availability tracking
    - Initialization status reporting

## Directory Structure

```plaintext
scripts/core/security/
├── README.md              # This documentation
├── __init__.py            # Module initialization and exports
├── crypto.py              # Cryptographic operations
├── integrity_check.py     # File integrity verification
└── permissions.py         # Permission management
```

## Usage Examples

### Cryptographic Operations

```python
from scripts.core.security.crypto import (
    encrypt_data, decrypt_data,
    hash_data, verify_hash,
    generate_key, derive_key_from_password
)

# Generate a secure encryption key
encryption_key = generate_key()

# Encrypt sensitive data
plaintext = "Sensitive information"
encrypted_data = encrypt_data(plaintext, encryption_key)

# Decrypt data
decrypted_data = decrypt_data(encrypted_data, encryption_key)
assert decrypted_data == plaintext

# Derive a key from a password with salt
password = "user_secure_password"
salt = os.urandom(16)
derived_key = derive_key_from_password(password, salt, iterations=100000)

# Calculate secure hash
file_hash = hash_data(open("important_file.txt", "rb").read())

# Verify hash
is_valid = verify_hash("important_file.txt", file_hash)
```

### File Integrity Verification

```python
from scripts.core.security.integrity_check import (
    create_baseline, verify_integrity,
    verify_file_integrity, update_baseline
)

# Create baseline for a directory
baseline_path = "/var/baseline/checksums.json"
create_baseline("/etc/config", baseline_path,
                algorithms=["sha256"],
                exclude_patterns=["*.tmp", "*.bak"])

# Verify integrity of an entire directory
integrity_result = verify_integrity("/etc/config", baseline_path)
if not integrity_result.is_valid:
    for violation in integrity_result.violations:
        print(f"Integrity violation: {violation.file_path} ({violation.reason})")

# Verify single file integrity
file_path = "/etc/config/app.conf"
if not verify_file_integrity(file_path, baseline_path):
    print(f"Integrity check failed for {file_path}")
    # Take remedial action

# Update baseline after approved changes
update_baseline("/etc/config", baseline_path,
                changes_approved_by="admin",
                comment="Configuration update 2024-09-01")
```

### Permission Management

```python
from scripts.core.security.permissions import (
    check_file_permissions, set_secure_permissions,
    audit_directory_permissions, fix_permissions
)

# Check if file has secure permissions
file_path = "/etc/config/secrets.conf"
if not check_file_permissions(file_path, mode=0o640, owner="root", group="app"):
    print(f"Insecure permissions on {file_path}")

# Apply secure permissions
set_secure_permissions(file_path, mode=0o640, owner="root", group="app")

# Audit directory for permission issues
audit_results = audit_directory_permissions(
    "/etc/config",
    recursive=True,
    security_baseline="production"
)

# Fix permissions based on security policy
if audit_results.has_violations:
    fix_permissions(audit_results.violations,
                   dry_run=False,
                   log_changes=True)
```

### Module Initialization

```python
from scripts.core.security import (
    initialize_security_components,
    get_security_component_status,
    verify_security_prerequisites
)

# Initialize security components
success, errors = initialize_security_components(
    security_level="high",
    log_level="INFO"
)

if not success:
    print(f"Failed to initialize security components: {errors}")
    # Handle initialization failure

# Check component availability
status = get_security_component_status()
if not status["crypto"]:
    print("Cryptographic operations are not available")

# Verify security prerequisites
prereq_results = verify_security_prerequisites()
for category, result in prereq_results.items():
    if not result["status"]:
        print(f"Security issue in {category}: {result['issues']}")
```

## Security Best Practices

- Always use the platform's cryptographic functions rather than implementing your own
- Validate file paths against directory traversal attempts before operations
- Never store encryption keys in source code or configuration files
- Use environment variables or a secure secrets manager for sensitive credentials
- Apply the principle of least privilege for all permission operations
- Keep baseline files in a secure location with restricted access
- Regularly verify integrity of critical system files
- Follow defensive programming patterns when handling security operations
- Implement circuit breaker patterns to prevent cascading failures
- Log all security-relevant operations for audit purposes
- Validate that files exist before performing security operations
- Use security modules consistently across the platform

## Common Features

- Comprehensive error handling for all security operations
- Detailed logging with appropriate security event classification
- Input validation for all parameters
- Secure defaults that require explicit override
- Cross-platform compatibility where possible
- Thread safety for shared resources
- Performance optimization for large-scale operations
- Integration with notification system for security events
- Support for different security levels by environment
- Compliance with industry security standards
- Reporting capabilities for audit requirements

## Integration Points

The security module integrates with several other platform components:

- **Core Logger**: All security events are logged through the centralized logging system
- **Error Handler**: Security-specific errors are properly handled and reported
- **Notifications**: Critical security events trigger appropriate notifications
- **Config Loader**: Security configuration is loaded from configuration files
- **Environment**: Environment-appropriate security levels are applied
- **Compliance Scripts**: Security module helps enforce compliance requirements
- **Deployment System**: Integrity verification during deployments
- **Monitoring System**: Security metrics are collected and monitored

## Module Dependencies

- **`logger.py`**: For security event logging
- **`error_handler.py`**: For standardized error handling
- **`environment.py`**: For environment-aware security settings
- **`config_loader.py`**: For security configuration

## Related Documentation

- Security Architecture Overview
- Cryptographic Standards
- File Integrity Monitoring Guide
- Permission Security Model
- Security Scripts
- Security Monitoring

## Version History

- **0.0.3 (2024-08-25)**: Enhanced integrity checking with baseline management
- **0.0.2 (2024-01-05)**: Added permission management capabilities
- **0.0.1 (2023-04-15)**: Initial release with core cryptographic operations
