# Services Package

This directory contains service classes that implement business logic and coordinate interactions between different parts of the Cloud Infrastructure Platform application.

## Contents

- [Overview](#overview)
- [Key Services](#key-services)
- [Directory Structure](#directory-structure)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage](#usage)
  - [Authentication](#authentication)
  - [Email Sending](#email-sending)
  - [SMS Messaging](#sms-messaging)
  - [Security Operations](#security-operations)
  - [Security Scanning](#security-scanning)
  - [Audit Logging](#audit-logging)
  - [Notifications](#notifications)
  - [Webhook Management](#webhook-management)
  - [File Integrity Management](#file-integrity-management)
    - [Basic Operations](#basic-operations)
    - [Enhanced Baseline Management](#enhanced-baseline-management)
    - [Notifications Integration](#notifications-integration)
    - [Baseline Verification and Export](#baseline-verification-and-export)
- [Related Documentation](#related-documentation)
- [Version History](#version-history)

## Overview

Services encapsulate complex operations and provide clean APIs for controllers/routes to use. They follow a functional core/imperative shell architecture where business logic is separated from side effects (like database operations). This approach enhances testability and maintainability by reducing complexity in individual components.

The service layer centralizes business logic, ensuring consistent application of security controls, error handling, and validation across the platform. Services communicate with models for data persistence and expose functionality to API endpoints, CLI tools, and web interfaces through a clean, consistent API.

## Key Services

- **`AuthService`**: User authentication, registration, and session management
  - **Usage**: Use this service for user authentication, registration, and session-related operations
  - **Features**:
    - Password-based authentication with brute force protection
    - User registration with validation
    - Session management with security features
    - JWT token generation for API authentication
    - Two-factor authentication support

- **`AuditService`**: Logging and retrieval of audit trail information
  - **Usage**: Use this service to log significant events and retrieve audit logs for compliance and analysis
  - **Features**:
    - Event logging with user context, action, target, status, and details
    - Flexible log retrieval with filtering and pagination
    - Severity levels for events (info, warning, error, critical)
    - Integration with database models for persistent storage
    - File integrity event tracking

- **`ConfigService`**: System configuration management
  - **Usage**: Use this service to read, update, and validate configuration settings
  - **Features**:
    - Secure configuration storage
    - Environment-specific configuration
    - Configuration validation
    - Export/import capabilities
    - Sensitive value protection through encryption
    - Change audit tracking

- **`EmailService`**: Email template rendering and delivery
  - **Usage**: Use this service to send emails using templates or raw content
  - **Features**:
    - Template-based email rendering
    - Multiple content formats (HTML and plain text)
    - File attachment support
    - Email delivery tracking
    - Batch email operations

- **`FileIntegrityService`**: Comprehensive file integrity baseline management
  - **Usage**: Use this service for advanced file integrity management with notifications and auditing
  - **Features**:
    - Enhanced baseline creation and updates with notifications
    - File integrity verification with severity classification
    - Automated backup management for baselines
    - Integration with notification systems for alerts
    - Comprehensive audit logging of baseline changes
    - Baseline consistency verification and validation
    - Export capabilities for compliance reporting
    - Environment-specific security controls

- **`MonitoringService`**: System health monitoring and metrics collection
  - **Usage**: Use this service to check system health, gather metrics, and trigger alerts
  - **Features**:
    - System resource monitoring (CPU, memory, disk)
    - Health checks for critical components (database, cache, filesystem)
    - Network connectivity validation
    - Real-time alerting for system issues
    - Integration with Prometheus metrics
    - Security posture monitoring integration

- **`NewsletterService`**: Subscription management and newsletter distribution
  - **Usage**: Use this service to handle newsletter subscriptions and send newsletters to subscribers
  - **Features**:
    - Subscription with email verification
    - Unsubscribe functionality
    - Newsletter distribution to subscribers
    - Subscription analytics and reporting
    - Batch sending with configurable limits

- **`NotificationService`**: Centralized notification delivery
  - **Usage**: Use this service to send notifications via multiple channels (in-app, email, SMS)
  - **Features**:
    - Multi-channel notification dispatch (in-app, email, SMS)
    - User-specific notification targeting
    - Notification types and priorities
    - Integration with `EmailService` and `SMSService`
    - Marking notifications as read

- **`ScanningService`**: Security scanning management
  - **Usage**: Use this service for managing security scans across different infrastructure components
  - **Features**:
    - Multiple scan types (vulnerability, compliance, configuration, etc.)
    - Scan scheduling and execution
    - Result processing and storage
    - Finding classification and reporting
    - Severity-based result prioritization
    - Integration with security monitoring systems
    - Scan profile management

- **`SecurityService`**: Security operations including file integrity monitoring
  - **Usage**: Use this service for security-related operations including file integrity verification
  - **Features**:
    - File integrity monitoring and verification
    - Security baseline management
    - File hash calculation with multiple algorithms
    - Change detection for security-critical files
    - Secure baseline updates with validation
    - File integrity status reporting
    - Comprehensive security logging and metrics
    - Severity-based change classification
    - Backup creation and management

- **`SMSService`**: SMS messaging and phone number validation
  - **Usage**: Use this service to send SMS messages and verify phone numbers
  - **Features**:
    - Single and bulk SMS messaging
    - Multiple provider support (Twilio, AWS SNS, MessageBird, Vonage)
    - Phone number validation and formatting
    - Delivery status tracking
    - Rate limiting with configurable thresholds
    - Priority-based message handling
    - Integration with user notification preferences
    - Message templating capabilities

- **`WebhookService`**: Management of webhook subscriptions and deliveries
  - **Usage**: Use this service to manage webhook subscriptions and trigger event deliveries
  - **Features**:
    - Webhook subscription creation, update, and deletion
    - Secure secret generation for signature verification
    - Triggering webhook deliveries for specific events
    - Test webhook functionality
    - Delivery history tracking
    - Subscription groups and rate limiting
    - Health monitoring for subscriptions
    - Rate limiting to prevent abuse

## Directory Structure

```plaintext
services/
├── __init__.py             # Package initialization with exported components
├── audit_service.py        # Audit logging service
├── auth_service.py         # Authentication and authorization service
├── config_service.py       # Configuration management service
├── email_service.py        # Email sending and templating service
├── file_integrity_service.py # File integrity management functions
├── monitoring_service.py   # System monitoring and health check service
├── newsletter_service.py   # Newsletter management service
├── notification_service.py # Multi-channel notification service
├── scanning_service.py     # Security scanning management service
├── security_service.py     # Security operations and file integrity services
├── service_constants.py    # Centralized constants for service configuration
├── sms_service.py          # SMS messaging and phone validation service
├── webhook_service.py      # Webhook management and delivery service
├── notification/           # Enhanced notification framework
│   ├── __init__.py         # Package initialization
│   └── note_manager.py     # Notification manager implementation
└── README.md               # This documentation
```

## Best Practices & Security

- Always validate inputs before processing in services
- Use parameterized queries to prevent SQL injection
- Handle exceptions gracefully and provide meaningful error messages
- Implement proper transaction management with rollbacks on errors
- Store sensitive data securely using appropriate encryption
- Use rate limiting for public-facing services
- Log sensitive operations for audit purposes (using `AuditService`)
- Avoid hardcoding credentials in service files
- Create unit tests for all service functions
- Implement circuit breakers for external service calls
- Verify file integrity for security-critical files
- Use secure connections for all SMS and webhook communications
- Validate phone numbers before sending SMS messages
- Apply appropriate throttling to prevent SMS and email abuse
- Create backups before updating critical baselines
- Implement proper permission checks for all security operations
- Follow defense-in-depth strategy with multiple validation layers

## Common Features

- Comprehensive error handling with consistent error formats
- Database transaction management
- Secure resource access through proper authentication
- Input validation and sanitization
- Detailed logging with appropriate levels
- Cache integration for performance optimization
- Rate limiting for public-facing endpoints
- Defensive programming patterns
- Security event monitoring and alerting
- Health checks with automatic administrator notifications
- User preference integration for communication services
- Multi-provider support with fallback mechanisms
- Metrics collection for operational monitoring
- Audit trail generation for compliance and security

## Usage

### Authentication

```python
from services import AuthService

# Authenticate a user
user, token = AuthService.authenticate(username="user@example.com", password="secure_password")
if user:
    print(f"User authenticated: {user.username}, token: {token}")
else:
    print("Authentication failed")

# Register a new user
result = AuthService.register_user(
    username="new_user@example.com",
    password="secure_password",
    first_name="John",
    last_name="Doe"
)
if result['success']:
    print(f"User registered: {result['user'].username}")
else:
    print(f"Registration failed: {result['error']}")
```

### Email Sending

```python
from services import send_email, send_template_email

# Send a simple email
result = send_email(
    to="recipient@example.com",
    subject="Important notification",
    body="This is an important notification about your account."
)
print(f"Email sent: {result['success']}")

# Send a templated email
result = send_template_email(
    to="recipient@example.com",
    template="welcome",
    context={"username": "john_doe", "activation_link": "https://example.com/activate/token"}
)
print(f"Template email sent: {result['success']}")
```

### SMS Messaging

```python
from services import send_sms, verify_phone_number, test_sms_configuration
from services import SMSProvider

# Send an SMS message
result = send_sms(
    to="+1234567890",
    message="Your verification code is 123456. It expires in 10 minutes.",
    priority="high"
)
print(f"SMS sent: {result['success']}, ID: {result['message_id']}")

# Verify a phone number
verified, formatted_number = verify_phone_number("+1234567890")
print(f"Phone number verified: {verified}, Formatted: {formatted_number}")

# Test SMS provider connection
connection_test = test_sms_configuration(provider=SMSProvider.TWILIO)
print(f"Connection test result: {connection_test['success']}")
```

### Security Operations

```python
from services import verify_file_hash, update_security_baseline, check_integrity, get_integrity_status

# Verify a file's hash
is_valid, details = verify_file_hash('/path/to/important/file.py')
if not is_valid:
    print(f"File integrity check failed: {details['status']}")
    print(f"Current hash: {details['current_hash']}")

# Update the security baseline for specific files
success, msg = update_security_baseline(
    paths_to_update=['/path/to/file1.py', '/path/to/file2.py']
)
print(f"Baseline update: {success}, {msg}")

# Check integrity of all baseline files
status, changes = check_integrity()
if not status:
    print(f"Integrity check failed with {len(changes)} changes detected")
    for change in changes:
        print(f"  {change['path']}: {change['status']}")

# Get the current status of file integrity monitoring
status = get_integrity_status()
print(f"Baseline status: {status['baseline_status']}")
print(f"Files monitored: {status['file_count']}")
print(f"Changes detected: {status['changes_detected']}")

# Update file integrity baseline with enhanced notifications and audit logging
success, message, stats = update_file_integrity_baseline_with_notifications(
    baseline_path="instance/security/baseline.json",
    changes=[
        {"path": "/path/to/file.py", "hash": "abc123...", "severity": "critical"},
        {"path": "/path/to/another.py", "hash": "def456...", "severity": "medium"}
    ],
    remove_missing=True,
    notify=True,
    audit=True,
    severity_threshold="medium",  # Send notifications for medium+ severity
    message="Weekly scheduled update"  # Optional message for notifications/audit
)
print(f"Baseline update with notifications: {success}")
print(f"Critical changes: {stats['critical_changes']}")
print(f"High severity changes: {stats['high_severity_changes']}")
```

### Security Scanning

```python
from services import start_security_scan, get_scan_status

# Start a security scan
scan_id = start_security_scan(
    target="web_application",
    profile="standard",
    options={"depth": "deep", "include_dependencies": True}
)
print(f"Scan started with ID: {scan_id}")

# Check scan status
status = get_scan_status(scan_id)
print(f"Scan {scan_id} is {status['status']}, progress: {status['progress']}%")
print(f"Findings so far: {status['findings_count']} ({status['critical_count']} critical)")
```

### Audit Logging

```python
from services import AuditService

# Log a security event
AuditService.log_event(
    action="user.login",
    status="success",
    target_id="user123",
    target_type="user",
    details={"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0..."}
)

# Retrieve audit logs
logs = AuditService.get_logs(
    actions=["user.login", "user.logout"],
    start_date="2023-01-01",
    end_date="2023-01-31",
    user_id="user123",
    limit=50
)

# Log a file integrity event
AuditService.log_file_integrity_event(
    status="changed",
    action="update",
    changes=[{"path": "/etc/config.json", "status": "changed", "severity": "high"}],
    details={"baseline_path": "/var/integrity/baseline.json"},
    severity="high"
)
```

### Notifications

```python
from services import notify_stakeholders, NOTIFICATION_CATEGORY_SECURITY

# Send a notification to all security stakeholders
notify_stakeholders(
    subject="Security Policy Update",
    message="The security policy has been updated with new password requirements.",
    level="info",
    category=NOTIFICATION_CATEGORY_SECURITY,
    data={"policy_id": 123, "version": "2.0"}
)
```

### Webhook Management

```python
from services import WebhookService

# Create a webhook subscription
subscription = WebhookService.create_subscription(
    url="https://example.com/webhook",
    events=["security.scan.completed", "security.incident.created"],
    description="Security alerts webhook"
)

# Trigger a webhook event
WebhookService.trigger_event(
    event_type="security.scan.completed",
    payload={"scan_id": "scan-123", "status": "completed", "findings": 5}
)
```

### File Integrity Management

The platform provides comprehensive file integrity monitoring capabilities to detect unauthorized changes to critical system files and ensure system integrity.

#### Basic Operations

```python
from services import SecurityService

# Check file integrity against the baseline
status, changes = SecurityService.check_file_integrity()
if not status:
    print(f"Integrity violations detected: {len(changes)} files")
    for change in changes:
        print(f"File {change['path']}: {change['status']} (Severity: {change['severity']})")

# Update the baseline for specific files
success, message = SecurityService.update_baseline(
    paths_to_update=["/path/to/file1.py", "/path/to/file2.py"],
    remove_missing=False
)
print(f"Baseline update: {success}, {message}")

# Get integrity status information
status = SecurityService.get_integrity_status()
print(f"Baseline exists: {status['baseline_exists']}")
print(f"Files monitored: {status['file_count']}")
print(f"Last updated: {status['last_updated']}")
```

#### Enhanced Baseline Management

For more sophisticated baseline management with comprehensive notifications, audit logging, and security controls:

```python
from services import update_file_integrity_baseline_with_notifications

# Update baseline with enhanced features
success, message, stats = update_file_integrity_baseline_with_notifications(
    baseline_path="instance/security/baseline.json",
    changes=[
        {
            "path": "/etc/config/app.conf",
            "current_hash": "a1b2c3d4e5f6...",
            "severity": "critical"
        },
        {
            "path": "/var/www/html/app.js",
            "current_hash": "b2c3d4e5f6g7...",
            "severity": "medium"
        }
    ],
    remove_missing=True,           # Remove entries for missing files
    notify=True,                   # Send notifications about changes
    audit=True,                    # Log to audit trail
    severity_threshold="medium",   # Send notifications for medium+ severity
    message="Monthly security review"   # Custom message for audit/notifications
)

# Access detailed statistics from the operation
print(f"Update operation successful: {success}")
print(f"Message: {message}")
print(f"Critical changes: {stats['critical_changes']}")
print(f"High severity changes: {stats['high_severity_changes']}")
print(f"Medium severity changes: {stats['medium_severity_changes']}")
print(f"Low severity changes: {stats['low_severity_changes']}")
print(f"Notification sent: {stats['notification_sent']}")
print(f"Audit logged: {stats['audit_logged']}")
print(f"Operation duration (ms): {stats['duration_ms']}")
```

#### Notifications Integration

File integrity baseline updates can be integrated with the notification system to alert stakeholders about important changes:

```python
from services import update_file_integrity_baseline_with_notifications

# Update baseline with notifications for security stakeholders
success, message, stats = update_file_integrity_baseline_with_notifications(
    baseline_path="instance/security/baseline.json",
    changes=[
        {"path": "/etc/config/app.conf", "severity": "critical"},
        {"path": "/var/www/html/js/app.js", "severity": "medium"}
    ],
    remove_missing=True,
    notify=True,
    audit=True,
    severity_threshold="high"  # Only notify on high or critical changes
)

# Check if notification was sent
if stats["notification_sent"]:
    print("Security stakeholders were notified of the changes")

# Check if audit log was created
if stats["audit_logged"]:
    print("Changes were logged to the security audit trail")
```

#### Baseline Verification and Export

Verify baseline consistency and export for compliance reporting:

```python
from services import verify_baseline_consistency, validate_baseline_consistency, export_baseline

# Verify baseline consistency (checks for structural issues)
is_consistent, issues = verify_baseline_consistency("instance/security/baseline.json")
if not is_consistent:
    print(f"Baseline has consistency issues: {len(issues)} problems found")
    for issue in issues:
        print(f"  • {issue['type']}: {issue['message']}")

# Validate baseline against current filesystem (deeper validation)
is_valid, validation_results = validate_baseline_consistency(
    baseline_path="instance/security/baseline.json",
    check_permissions=True,  # Also verify file permissions
    verify_content=True      # Deep content verification
)
print(f"Baseline validation status: {'Valid' if is_valid else 'Invalid'}")
print(f"Files validated: {validation_results['files_checked']}")
print(f"Issues found: {validation_results['issues_found']}")

# Export baseline for compliance reporting
export_result = export_baseline(
    baseline_path="instance/security/baseline.json",
    export_format="csv",
    output_path="reports/file_integrity_baseline.csv",
    include_metadata=True
)
print(f"Baseline exported: {export_result['success']}")
print(f"Records exported: {export_result['records_exported']}")
print(f"Export location: {export_result['output_path']}")
```

## Related Documentation

- API Documentation
- Authentication Guide
- Audit Log Reference
- Email Templates Guide
- File Integrity Monitoring Guide
- Health Check Implementation
- Monitoring Strategy
- Notification System Design
- Security Baseline Management
- Security Policies
- Security Scanning Framework
- SMS Integration Guide
- System Health Metrics
- Webhook Implementation Guide

## Version History

- **0.0.5 (2024-10-10)**: Enhanced file integrity management with backup, verification and notification integration
- **0.0.4 (2024-09-01)**: Added SMS messaging service and enhanced file integrity baseline management
- **0.0.3 (2024-08-15)**: Enhanced security monitoring and webhook management capabilities
- **0.0.2 (2024-07-28)**: Added ScanningService for security vulnerability scanning
- **0.0.1 (2023-09-01)**: Initial implementation of core service classes
