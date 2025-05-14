# Common Security Utilities

This directory contains shared utility scripts used across the security scripts in the Cloud Infrastructure Platform. These utilities provide foundational functionality including logging, notification handling, and input validation to ensure consistent behavior, security, and reliability across all security operations.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The common security utilities implement standardized functionality needed by multiple security scripts, reducing code duplication and ensuring consistent behavior. These utilities are designed to be sourced by other security scripts rather than executed directly. Each utility follows defense-in-depth principles and adheres to industry standards such as CIS benchmarks, NIST guidelines, and OWASP recommendations.

## Key Components

- **`logging.sh`**: Provides standardized logging functionality for all security scripts.
  - **Usage**: Source this file to use centralized logging functions.
  - **Features**:
    - Consistent log formatting
    - Multiple severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - Automatic timestamping
    - Context tagging
    - Log rotation integration
    - Log file permission management
    - Multi-destination logging (file, syslog, stdout)
    - Sensitive data masking

- **`notification.sh`**: Implements alert and notification capabilities.
  - **Usage**: Source this file to enable notification functions.
  - **Features**:
    - Multi-channel notifications (email, SMS, chat)
    - Priority-based routing
    - Rate limiting for notifications
    - Template-based messages
    - Notification batching
    - Delivery confirmation
    - Fallback mechanisms
    - Integration with monitoring systems

- **`validation.sh`**: Provides input validation and sanitization functions.
  - **Usage**: Source this file for input validation capabilities.
  - **Features**:
    - Command-line argument validation
    - Path traversal prevention
    - Numeric bounds checking
    - Format validation (IP, domain, email, etc.)
    - Character allowlisting
    - Environment variable validation
    - Command injection prevention
    - Exit code validation
    - Regular expression pattern validation
    - UUID/GUID validation

## Directory Structure

```plaintext
scripts/security/common/
├── logging.sh             # Standardized logging functionality
├── notification.sh        # Alert and notification utilities
├── validation.sh          # Input validation functions
└── README.md              # This documentation
```

## Configuration

These utilities read configuration from multiple sources in the following order of precedence:

1. Command-line arguments passed to the sourcing script
2. Environment variables defined in the environment
3. Configuration files located at:
   - `/etc/cloud-platform/security/common.conf` (system-wide)
   - `~/.cloud-platform/security.conf` (user-specific)
   - `./.security.conf` (directory-specific)

### Environment Variables

Key environment variables include:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_LOG_LEVEL` | `INFO` | Minimum log level to record |
| `SECURITY_LOG_DIR` | `/var/log/cloud-platform/security` | Directory for log files |
| `SECURITY_NOTIFICATION_EMAILS` | - | Comma-separated list of emergency contacts |
| `SECURITY_NOTIFICATION_CHANNELS` | `email` | Notification channels to use |
| `SECURITY_MAX_NOTIFICATIONS` | `10` | Maximum notifications per hour |
| `SECURITY_VALIDATION_STRICT` | `true` | Enable strict input validation |
| `SECURITY_NOTIFICATION_RATE_LIMIT_PERIOD` | `3600` | Rate limit window in seconds |
| `SECURITY_NOTIFICATION_TEMPLATE_DIR` | `/etc/cloud-platform/security/templates` | Notification template directory |

## Best Practices & Security

- Always source these utility scripts at the beginning of your scripts
- Validate all user inputs using the provided validation functions
- Use appropriate logging levels to avoid log flooding
- Handle sensitive information carefully, using the masking functions
- Ensure proper error handling when utilizing notification functions
- Use rate limiting for notifications to prevent alert fatigue
- Apply consistent security practices across all security operations
- Never modify these utility scripts directly; extend them instead
- Keep backward compatibility when updating these utilities
- Maintain secure default settings for all security functions
- Log security-relevant events at appropriate levels for audit purposes
- Set proper file permissions for any generated output files

## Common Features

- Thread-safe operation for all utility functions
- Comprehensive error handling with clear error messages
- Default secure behaviors that require explicit opt-out
- Performance optimizations for frequently used functions
- Clear, consistent documentation of all parameters
- Support for different security levels by environment
- Resilient operation even in degraded environments
- Script version and dependency tracking
- Integration with platform-wide security components
- Support for audit and compliance requirements
- Fallback mechanisms when primary functions are unavailable
- Self-diagnostics and runtime environment verification

## Usage Examples

### Logging

```bash
# Source the logging utility
source "$(dirname "$0")/../common/logging.sh"

# Log messages at different levels
log_debug "Detailed debugging information"
log_info "Script starting normal operation"
log_warning "Potential issue detected"
log_error "An error occurred during operation"
log_critical "Critical failure requires immediate attention"

# Log with context
log_info "User account created" "user=jsmith action=create"

# Log with sensitive data masking
log_info "Authentication attempt" "username=jsmith password=$(mask_sensitive 'actualpassword')"
```

### Notification

```bash
# Source the notification utility
source "$(dirname "$0")/../common/notification.sh"

# Send a basic notification
send_notification "Security scan completed" "Scan completed successfully with 0 findings" "info"

# Send an urgent notification to specific recipients
send_urgent_notification "Critical vulnerability detected" "CVE-2023-1234 found in system component"

# Send notification with template
send_template_notification "security_breach" \
  "system=authentication,severity=high,affected_users=250,timestamp=2023-08-15T14:30:00Z"

# Send notification to specific channels
send_multi_channel_notification "Security patch required" "email,sms" "Critical patches must be applied by EOD" "critical"

# Use notification batching for multiple related messages
start_notification_batch
add_to_notification_batch "Firewall Rule Updated" "Rule 24 modified to allow port 443"
add_to_notification_batch "Service Restarted" "Firewall service restarted to apply changes"
send_notification_batch "Security Configuration Changes" "medium"
```

### Validation

```bash
# Source the validation utility
source "$(dirname "$0")/../common/validation.sh"

# Validate command-line arguments
validate_argument "--target" "$TARGET" "required"
validate_argument "--days" "$DAYS" "numeric" "min=1,max=365"

# Validate file paths
if ! validate_file "$config_file" "r"; then
  log_error "Config file not readable or not a regular file"
  exit 1
fi

# Validate IPs and domains
if is_ip_address "$target"; then
  log_info "Target is a valid IP address"
elif is_hostname "$target"; then
  log_info "Target is a valid hostname"
else
  log_error "Invalid target specified"
  exit 1
fi

# Protect against command injection
user_input=$(sanitize_shell_input "$user_input")

# Validate environment variables
validate_env_var "DATABASE_URL" "required"
validate_env_var "PORT" "numeric" "min=1024,max=65535"

# Check if a path contains directory traversal attempts
if ! has_dir_traversal "$user_path"; then
  log_error "Path contains potential directory traversal sequences"
  exit 1
fi
```

## Related Documentation

- Security Scripts Overview
- Security Architecture Overview
- Security Incident Response Procedures
- Logging Standards
- Notification Configuration Guide
- Security Baseline Requirements
- Security Hardening Guidelines
- Core Security Module
