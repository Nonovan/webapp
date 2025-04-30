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
    - Multi-channel notification dispatch (in-app, email)
    - User-specific notification targeting
    - Notification types and priorities
    - Integration with `EmailService`
    - Marking notifications as read

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

- **`WebhookService`**: Management of webhook subscriptions and deliveries
  - **Usage**: Use this service to manage webhook subscriptions and trigger event deliveries.
  - **Features**:
    - Webhook subscription creation, update, and deletion
    - Secure secret generation for signature verification
    - Triggering webhook deliveries for specific events
    - Test webhook functionality
    - Delivery history tracking
    - Subscription groups and rate limiting

## Directory Structure

```plaintext
services/
├── __init__.py           # Package initialization with exported components
├── audit_service.py      # Audit logging service
├── auth_service.py       # Authentication and authorization service
├── email_service.py      # Email sending and templating service
├── monitoring_service.py # System monitoring and health check service
├── newsletter_service.py # Newsletter management service
├── notification_service.py # Multi-channel notification service
├── security_service.py   # Security operations and file integrity services
├── webhook_service.py    # Webhook management and delivery service
└── README.md             # This documentation
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

## Usage

### Authentication

```python
from services import AuthService

# User login
success, user, error_message = AuthService.authenticate_user('username', 'password')
if success:
    AuthService.login_user_session(user)
else:
    print(f"Login failed: {error_message}")

# User registration
success, user, error_message = AuthService.register_user(
    username='newuser',
    email='user@example.com',
    password='secure_password'
)
```

### Email Sending

```python
from services import send_email, send_template_email

# Send a simple email
send_email(
    to='recipient@example.com',
    subject='Important notification',
    html_content='<h1>Hello!</h1><p>This is an important message.</p>'
)

# Send a templated email
send_template_email(
    to='recipient@example.com',
    subject='Welcome to our platform',
    template_name='welcome_email',
    template_data={
        'username': 'john_doe',
        'activation_link': 'https://example.com/activate/123'
    }
)
```

### Newsletter Management

```python
from services import NewsletterService

# Subscribe a user
result = NewsletterService.subscribe_email('subscriber@example.com')

# Send a newsletter
result = NewsletterService.send_newsletter(
    subject='Monthly Update',
    content='<h1>Monthly Newsletter</h1><p>Latest updates...</p>'
)

# Get subscription statistics
stats = NewsletterService.get_stats()
```

### Security Operations

```python
from services import check_integrity, update_security_baseline

# Check file integrity
integrity_status, changes = check_integrity()
if not integrity_status:
    print(f"File integrity check failed with {len(changes)} changes detected")
    for change in changes:
        print(f"File: {change['path']}, Status: {change['status']}")

# Update security baseline for specific paths
paths_to_update = ['/path/to/critical/file.py', '/path/to/config.json']
success, message = update_security_baseline(paths_to_update)
if success:
    print(f"Baseline updated successfully: {message}")
else:
    print(f"Baseline update failed: {message}")
```

### Audit Logging

```python
from services import AuditService
from flask import request

# Log a user login attempt
AuditService.log_event(
    user_id=user.id if user else None,
    action='user.login.attempt',
    status='success' if success else 'failure',
    ip_address=request.remote_addr,
    details={'username': 'attempted_user'}
)

# Retrieve recent critical audit logs
logs, total_count = AuditService.get_logs(severity='critical', limit=10)
```

### Monitoring

```python
from services import MonitoringService

# Get current system status
status_data = MonitoringService.get_system_status(include_security=True)
print(f"CPU Usage: {status_data['system']['cpu_percent']}%")
print(f"Memory Usage: {status_data['system']['memory_percent']}%")
print(f"Disk Usage: {status_data['system']['disk_percent']}%")

# Perform a comprehensive health check
is_healthy, health_details = MonitoringService.perform_health_check()
if not is_healthy:
    print(f"System health check failed: {health_details['components']}")

# Get snapshot of system metrics
metrics_snapshot = MonitoringService.get_metrics_snapshot(categories=['system', 'application'])
print(f"Network connections: {metrics_snapshot['system']['network']['connections']}")

# Check specific network connectivity
network_ok, network_details = MonitoringService.check_network_connectivity()
if not network_ok:
    print(f"Network issues detected: {network_details}")
```

### Notifications

```python
from services import NotificationService, send_security_alert

# Send an informational in-app notification
NotificationService.send_in_app_notification(
    user_ids=[123, 456],
    message="Your report is ready for download.",
    action_url="/reports/download/xyz"
)

# Send a critical security alert via in-app and email
send_security_alert(
    user_ids=789,
    message="Suspicious login detected on your account.",
    email_subject="Security Alert: Suspicious Login",
    email_template="security_alert",
    email_template_data={'ip_address': '192.168.1.100', 'time': '2024-07-26 10:00 UTC'}
)
```

### Webhook Management

```python
from services import WebhookService

# Create a webhook subscription
subscription, secret, error = WebhookService.create_subscription(
    user_id=123,
    target_url='https://example.com/webhook-receiver',
    event_types=['resource.created', 'resource.deleted'],
    description='Notify on resource changes'
)
if subscription:
    print(f"Subscription created. Secret: {secret}") # Store the secret securely!
else:
    print(f"Failed to create subscription: {error}")

# Trigger an event
payload = {'resource_id': 'res-abc', 'type': 'vm', 'status': 'created'}
WebhookService.trigger_event(event_type='resource.created', payload=payload)
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
- System Health Metrics (docs/operations/system-metrics.md)
- Webhook Implementation Guide (docs/api/guides/webhooks.md)

## Version History

- **0.1.0 (2023-09-01)**: Initial implementation of core service classes
