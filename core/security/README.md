# Security Module for Cloud Infrastructure Platform

This directory contains the security module for the Cloud Infrastructure Platform, providing comprehensive security capabilities including authentication, authorization, encryption, integrity checking, audit logging, monitoring, metrics collection, and validation.

## Overview

The security module implements a defense-in-depth security approach with multiple security layers to protect the platform's infrastructure, applications, data, and communications. It follows industry best practices including NIST Cybersecurity Framework, CIS benchmarks, and OWASP guidelines.

## Key Components

- **`cs_audit.py`**: Security event logging and audit functionality
  - Records security events for compliance and investigation
  - Supports severity levels and structured logging
  - Integrates with monitoring systems for alerts
  - Real-time threat correlation and analysis

- **`cs_authentication.py`**: Authentication and identity verification
  - Token generation and verification
  - Password strength validation
  - Session management functions
  - IP validation utilities
  - URL validation and security checks
  - Secure token generation

- **`cs_authorization.py`**: Permission and access control
  - Role-based permission decorators
  - Multi-factor authentication enforcement
  - UI access control functions
  - Authorization enforcement
  - Rate limiting implementation

- **`cs_constants.py`**: Security configuration settings
  - Centralized security parameters
  - Environment-specific configurations
  - Security thresholds and timeouts
  - Default security values
  - File integrity severity classifications
  - Request tracking constants
  - Integrity monitoring priorities
  - File extension security classifications
  - Monitored file patterns by priority

- **`cs_crypto.py`**: Cryptographic operations
  - Encryption/decryption of sensitive data
  - AES-GCM encryption implementation
  - URL and filename sanitization
  - Secure key management
  - Unified hash computation
  - SRI hash generation
  - File hash calculation with various output formats
  - Password hashing and verification

- **`cs_file_integrity.py`**: File integrity monitoring
  - Critical file integrity verification
  - Configuration integrity checks
  - File signature verification
  - Change detection with severity classification
  - Automated baseline updating with security controls
  - Permission security validation (world-writable, world-executable, setuid/setgid)
  - Suspicious file detection with pattern matching
  - Baseline comparison and reporting
  - File permission security checks
  - Directory traversal prevention
  - Security event logging for violations
  - Redis-based caching of integrity status
  - Baseline creation and management
  - Detection of file changes
  - Integrity status retrieval and reporting
  - Baseline update consideration functionality
  - Additional critical files checking

- **`cs_metrics.py`**: Security metrics collection
  - Security posture measurement
  - Risk scoring algorithms
  - Security recommendation generation
  - Threat intelligence metrics
  - Geolocation-based risk analysis
  - Security trend analysis
  - Metrics initialization and setup
  - Authentication metrics tracking
  - Customizable security dashboards
  - Integrity metrics collection
  - Performance tracking for security operations

- **`cs_monitoring.py`**: Security monitoring capabilities
  - Failed login tracking
  - Suspicious IP detection
  - Account lockout monitoring
  - Session monitoring
  - Location change analysis
  - Permission violation detection
  - Security anomaly detection
  - Integrity status monitoring
  - File integrity violation tracking
  - Circuit breaker pattern implementation
  - Service resilience monitoring

- **`cs_session.py`**: Session security management
  - Session timeout enforcement
  - Session validation and fingerprinting
  - Session attribute management
  - Anti-hijacking protections
  - Location-based session verification
  - Suspicious activity detection
  - MFA enforcement for sensitive operations
  - Session regeneration with secure state preservation
  - Session invalidation controls

- **`cs_utils.py`**: General security utilities
  - Security component initialization
  - Security configuration validation
  - Security metrics initialization
  - File integrity monitoring setup
  - Security dependency verification
  - Security status reporting
  - Security headers management
  - CSP nonce generation
  - Sanitization utilities (path, file operations)
  - Safe file operation validation
  - Directory traversal prevention
  - Sensitive data obfuscation

- **`cs_validation.py`**: Input and configuration validation
  - Password complexity validation
  - Path security validation
  - URL and domain validation
  - Input format validation
  - File permission validation
  - Configuration security validation
  - Email format validation
  - User input sanitization
  - Username validation
  - Hash format validation
  - IP address validation
  - UUID format validation
  - Request security validation

## Directory Structure

```plaintext
core/security/
├── __init__.py              # Package initialization and exports
├── cs_audit.py              # Security audit logging functionality
├── cs_authentication.py     # Authentication functions
├── cs_authorization.py      # Access control implementation
├── cs_constants.py          # Security configuration constants
├── cs_crypto.py             # Cryptographic operations
├── cs_file_integrity.py     # File integrity verification
├── cs_metrics.py            # Security metrics collection
├── cs_monitoring.py         # Security monitoring functions
├── cs_session.py            # Session security management
├── cs_utils.py              # Security utility functions
├── cs_validation.py         # Input validation functions
└── README.md                # This documentation
```

## Usage

### Authentication

```python
from core.security import verify_token, validate_password_strength, generate_secure_token, validate_url

# Verify JWT token
token_data = verify_token(token)

# Check password strength
is_strong, requirements = validate_password_strength(password)

# Generate secure random token
token = generate_secure_token(length=64)

# Validate URL safety
is_valid, error = validate_url("https://example.com/page", required_schemes=["https"])
```

### Authorization

```python
from core.security import require_permission, require_mfa

# Require specific permission for a function
@require_permission('cloud_resources:read')
def get_resources():
    # Only users with 'cloud_resources:read' permission can access this
    pass

# Require MFA for sensitive operations
@require_mfa
def update_user_permissions():
    # Only accessible after MFA verification
    pass
```

### Security Logging

```python
from core.security import log_security_event, log_error, log_warning, log_info, log_debug

# Log security events for audit and compliance
log_security_event(
    event_type='user_action',
    description='User changed password',
    severity='info',
    user_id=user.id,
    details={'ip_address': request.remote_addr}
)

# Log different severity levels
log_error("Failed to validate security token")
log_warning("Multiple failed login attempts detected")
log_info("User password updated successfully")
log_debug("Authentication process started")
```

### Cryptographic Operations

```python
from core.security import encrypt_sensitive_data, decrypt_sensitive_data, compute_hash

# Encrypt sensitive data
encrypted = encrypt_sensitive_data({"ssn": "123-45-6789", "dob": "1980-01-01"})

# Decrypt previously encrypted data
decrypted = decrypt_sensitive_data(encrypted)

# Generate file hash
file_hash = compute_hash(file_path="/path/to/file", algorithm="sha256")

# Generate hash for data with specific format
hash_value = compute_hash(
    data="Text to hash",
    algorithm="sha384",
    output_format="base64"  # Options: hex, base64, sri
)
```

### File Integrity Verification

```python
from core.security import check_critical_file_integrity, update_file_integrity_baseline

# Check integrity of critical files
is_valid, changes = check_critical_file_integrity()

if not is_valid:
    for change in changes:
        if change['severity'] == 'critical':
            # Handle critical changes
            notify_security_team(f"Critical file changed: {change['path']}")

        # Log all changes
        log_security_event(
            'file_integrity_violation',
            f"File {change['path']} has been {change['status']}",
            'warning',
            details=change
        )

# Update baseline with approved changes
update_file_integrity_baseline(
    app,
    baseline_path="instance/file_baseline.json",
    updates=changes,
    remove_missing=True
)
```

### Advanced Integrity Operations

```python
from core.security import _detect_file_changes, _consider_baseline_update, _check_for_permission_changes

# Perform low-level integrity check with detailed control
changes = _detect_file_changes(
    basedir="/app",
    reference_hashes=app.config["CRITICAL_FILE_HASHES"],
    critical_patterns=["*.py", "*.config", "*.json"],
    detect_permissions=True,
    check_signatures=True
)

# Check specifically for permission issues
_check_for_permission_changes(
    basedir="/app",
    reference_hashes=app.config["CRITICAL_FILE_HASHES"],
    modified_files=detected_changes
)

# Consider automatic baseline updates for low-severity changes
_consider_baseline_update(
    app,
    changes=detected_changes,
    expected_hashes=app.config["CRITICAL_FILE_HASHES"]
)
```

### File Path Safety (Migrated Functions)

```python
from core.security import sanitize_path, is_within_directory, is_safe_file_operation

# Validate path safety
safe_path = sanitize_path(user_input, base_dir="/safe/directory")
if safe_path:
    # Process the safe path
    process_file(safe_path)

# Check if a path is within an allowed directory
if is_within_directory(file_path, allowed_directory):
    # Path is safe to use
    read_file(file_path)

# Check if a file operation is safe
if is_safe_file_operation("write", target_path, safe_dirs=["/app/uploads", "/app/temp"]):
    # Operation is safe
    write_to_file(target_path, data)
```

### Session Security

```python
from core.security import (
    initialize_secure_session, check_session_attacks,
    regenerate_session_safely, mark_requiring_mfa,
    is_mfa_verified
)

# Initialize a secure session after successful login
initialize_secure_session(user_id=user.id, role=user.role)

# Check for potential session attacks (returns tuple: (is_valid, attack_type))
session_valid, attack_type = check_session_attacks()
if not session_valid:
    # Handle potential attack (session fixation, hijacking, etc.)
    terminate_session(attack_type)

# Regenerate session safely when privilege level changes
regenerate_session_safely()

# Mark session as requiring MFA for sensitive operations
mark_requiring_mfa()

# Check if MFA has been verified before sensitive operations
if is_mfa_verified():
    # Proceed with sensitive operation
    pass
else:
    # Redirect to MFA verification
    pass
```

### Security Metrics and Monitoring

```python
from core.security import (
    calculate_risk_score, get_security_metrics,
    get_suspicious_ips, detect_suspicious_activity
)

# Get current risk score for the system
risk_score = calculate_risk_score()
if risk_score > 70:
    # High risk detected
    notify_security_team("High security risk detected", risk_score)

# Get security metrics for dashboard
metrics = get_security_metrics()

# Check for suspicious IPs
suspicious_ips = get_suspicious_ips(threshold=5)
for ip in suspicious_ips:
    # Block suspicious IP addresses
    block_ip(ip, reason="Suspicious activity detected")

# Detect suspicious user activity
suspicious_activity = detect_suspicious_activity(user_id=123)
if suspicious_activity:
    # Handle suspicious activity
    require_additional_verification(user_id=123)
```

### Metrics Setup

```python
from core.security import setup_security_metrics, setup_auth_metrics

# Initialize security metrics in your Flask application
def configure_metrics(app):
    # Set up security metrics collectors
    setup_security_metrics(app)

    # Set up authentication metrics collectors
    setup_auth_metrics(app)

    # Additional metrics configuration
    # ...
```

### Input Validation

```python
from core.security import (
    validate_password_complexity, validate_path_security,
    is_valid_email, validate_input_against_pattern
)

# Validate password complexity
if not validate_password_complexity(password):
    raise ValueError("Password does not meet complexity requirements")

# Validate file path security
if not validate_path_security(user_path, base_dir="/app/data"):
    raise ValueError("Invalid or unsafe file path")

# Validate email format
if not is_valid_email(email):
    raise ValueError("Invalid email format")

# Validate input against custom pattern
if not validate_input_against_pattern(input_value, pattern=r'^[A-Za-z0-9\-_]+$'):
    raise ValueError("Input contains invalid characters")
```

## Best Practices & Security

- Import only the specific functions you need rather than the entire module
- Always validate user inputs before processing
- Use appropriate error handling for all security operations
- Follow the principle of least privilege when assigning permissions
- Log all security-relevant events with appropriate detail
- Regularly update security constants based on evolving threats
- Apply defense-in-depth with multiple security controls
- Implement circuit breakers to prevent cascading failures
- Use secure defaults for all security settings
- Validate file integrity regularly, especially after deployments
- Enforce MFA for all administrative and sensitive operations
- Implement proper rate limiting for authentication endpoints
- Review security metrics and alerts daily
- Monitor and respond to security recommendations
- Regularly test security controls through automated checks
- Use atomic file operations for baseline updates to prevent corruption
- Create and verify file integrity baselines after system updates
- Ensure proper permissions on security baseline files themselves
- Use constants from cs_constants.py rather than hardcoded values
- Verify security dependencies are available during initialization
- Include context data in security events for better correlation
- Store only hashed/encrypted sensitive data in monitoring systems
- Consolidate similar validation functions into `cs_validation.py`
- Maintain backward compatibility when refactoring
- Use standard patterns for handling redirects and URL validation
- Ensure thread safety for shared resources

## Related Documentation

- Security Architecture Overview
- Authentication Standards
- Cryptographic Standards
- Incident Response Procedures
- Compliance Requirements
- File Integrity Monitoring Guide
- Security Metrics Dashboard
- Core Security Utility Migration Guide
- Circuit Breaker Implementation Guide
- Redis Security Cache Documentation
- Security Monitoring Strategy
- API Security Best Practices
- Input Validation Framework
- Security Constants Reference
