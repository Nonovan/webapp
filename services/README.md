# Services Package

This directory contains service classes that implement business logic and coordinate interactions between different parts of the Cloud Infrastructure Platform application.

## Contents

- [Overview](#overview)
- [Key Services](#key-services)
- [Directory Structure](#directory-structure)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage](#usage)
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
  - **Usage**: Use this service to log significant events and retrieve audit logs for compliance and analysis.
  - **Features**:
    - Event logging with user context, action, target, status, and details
    - Flexible log retrieval with filtering and pagination
    - Severity levels for events (info, warning, error, critical)
    - Integration with database models for persistent storage

- **`EmailService`**: Email template rendering and delivery
  - **Usage**: Use this service to send emails using templates or raw content
  - **Features**:
    - Template-based email rendering
    - Multiple content formats (HTML and plain text)
    - File attachment support
    - Email delivery tracking
    - Batch email operations

- **`MonitoringService`**: System health monitoring and metrics collection
  - **Usage**: Use this service to check system health, gather metrics, and potentially trigger alerts.
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
  - **Usage**: Use this service to send notifications via multiple channels (in-app, email).
  - **Features**:
    - Multi-channel notification dispatch (in-app, email, SMS)
    - User-specific notification targeting
    - Notification types and priorities
    - Integration with `EmailService` and `SMSService`
    - Marking notifications as read

- **`ScanningService`**: Security scanning management
  - **Usage**: Use this service for managing security scans across different infrastructure components.
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
  - **Usage**: Use this service to manage webhook subscriptions and trigger event deliveries.
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
├── email_service.py        # Email sending and templating service
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
from services import send_sms, send_bulk_sms, verify_phone_number, SMSProvider

# Verify a phone number
verification = verify_phone_number("+12345678901")
if verification['valid']:
    print(f"Phone number is valid: {verification['formatted']}")
else:
    print(f"Invalid phone number: {verification['error']}")

# Send a simple SMS message
result = send_sms(
    to="+12345678901",
    message="Your verification code is: 123456",
    priority="high"
)
print(f"SMS sent: {result['success']}")

# Send bulk SMS messages
recipients = ["+12345678901", "+19876543210"]
result = send_bulk_sms(
    recipients=recipients,
    message="System maintenance scheduled for tomorrow at 2AM.",
    respect_preferences=True  # Honor user communication preferences
)
print(f"Bulk SMS sent: {result['stats']['sent']}/{result['stats']['total']}")

# Test SMS provider connectivity
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
    audit=True
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
AuditService.log_security_event(
    event_type="user.login_attempt",
    description="Failed login attempt with incorrect password",
    severity="warning",
    user_id=None,  # Unknown user
    ip_address="192.168.1.100",
    details={"username": "admin", "method": "password", "failure_reason": "invalid_password"}
)

# Search audit logs
audit_logs = AuditService.search_logs(
    event_types=["user.login_attempt", "user.password_change"],
    severity_min="warning",
    start_time="2023-01-01T00:00:00Z",
    end_time="2023-12-31T23:59:59Z",
    user_id=123,
    limit=100
)
print(f"Found {len(audit_logs)} matching audit logs")
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
from services import create_webhook_subscription, trigger_webhook_event

# Create a webhook subscription
subscription, secret, error = create_webhook_subscription(
    user_id=123,
    target_url="https://example.com/webhook",
    event_types=["resource.created", "resource.updated"],
    description="Production environment change notifications"
)

if subscription:
    print(f"Webhook subscription created: {subscription.id}")
    print(f"Secret for validation: {secret}")
else:
    print(f"Failed to create webhook subscription: {error}")

# Trigger a webhook event
delivery_count = trigger_webhook_event(
    event_type="resource.created",
    payload={
        "resource_id": 456,
        "resource_type": "instance",
        "action": "created",
        "timestamp": "2023-06-15T14:30:00Z"
    }
)
print(f"Event delivered to {delivery_count} subscribers")
```

## Related Documentation

- API Documentation (docs/api/README.md)
- Authentication Guide (docs/security/authentication-standards.md)
- Audit Log Reference (docs/api/reference/audit.md)
- Email Templates Guide (admin/templates/email/README.md)
- File Integrity Monitoring Guide (docs/security/file-integrity-monitoring.md)
- Health Check Implementation (docs/operations/health-checks.md)
- Monitoring Strategy (docs/operations/monitoring-overview.md)
- Notification System Design (docs/api/notifications.md)
- Security Baseline Management (admin/security/assessment_tools/config_files/security_baselines/README.md)
- Security Policies (docs/security/README.md)
- Security Scanning Framework (docs/security/scanning-framework.md)
- SMS Integration Guide (docs/communications/sms-integration.md)
- System Health Metrics (docs/operations/system-metrics.md)
- Webhook Implementation Guide (docs/api/guides/webhooks.md)

## Version History

- **0.0.4 (2024-09-01)**: Added SMS messaging service and enhanced file integrity baseline management
- **0.0.3 (2024-08-15)**: Enhanced security monitoring and webhook management capabilities
- **0.0.2 (2024-07-28)**: Added ScanningService for security vulnerability scanning
- **0.0.1 (2023-09-01)**: Initial implementation of core service classes
