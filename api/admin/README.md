# Administrative API

The Administrative API module provides secure endpoints for system management, user administration, configuration control, and audit capabilities in the Cloud Infrastructure Platform. This module is restricted to authorized administrators and implements enhanced security controls to protect privileged operations.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Error Handling](#error-handling)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Related Documentation](#related-documentation)

## Overview

The Administrative API implements RESTful endpoints following security best practices including strict authentication requirements, multi-factor authentication enforcement, comprehensive audit logging, and detailed permission controls. It provides system administrators with the tools needed to manage users, monitor system health, configure application settings, and review security events.

The API follows a layered architecture with clear separation of concerns:

- Request validation and authentication
- Business logic execution
- Audit logging and metrics collection
- Standardized response formatting

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for administrative operations
  - System status and health monitoring dashboards
  - Application configuration management
  - Administrative notifications and alerts
  - Environment and feature flag management
  - System maintenance operations
  - Data backup and recovery management
  - Administrative task scheduling
  - File integrity monitoring controls

- **`user_management.py`**: User administration functionality
  - User account creation and management
  - Role and permission assignment
  - Account lockout management
  - User activity monitoring
  - Administrative privilege management
  - Temporary access elevation with approval workflows
  - Account merging and data migration
  - Bulk user operations with validation
  - Password policy enforcement

- **`system_config.py`**: System configuration management
  - Environment settings management
  - Feature flag control
  - System parameter configuration
  - Security policy management
  - Integration settings maintenance
  - Configuration validation and testing
  - Configuration version history tracking
  - Environment-specific overrides management
  - Secure default configuration templates

- **`audit.py`**: Administrative audit functionality
  - Security event log access
  - User activity reporting
  - Compliance reporting tools
  - Security incident tracking
  - System change auditing
  - Access anomaly detection
  - Audit data export capabilities
  - Retention policy management
  - Advanced filtering and search

- **`decorators.py`**: Administrative security decorators
  - Role and permission validation
  - Enhanced audit logging for administrative actions
  - Multi-factor authentication enforcement
  - IP restriction validation
  - Rate limiting for sensitive operations
  - Context-based access controls
  - Approval workflow enforcement for critical actions
  - Session security verification
  - Request integrity validation

- **`schemas.py`**: Request/response validation schemas
  - Comprehensive input validation
  - Field-level validation rules
  - Schema versioning support
  - Cross-field validation logic
  - Data sanitization rules
  - Type conversion and normalization
  - Response formatting templates
  - Documentation generation support

- **`middleware.py`**: Request preprocessing middleware
  - Authentication verification
  - Authorization enforcement
  - Request logging and tracking
  - Performance monitoring
  - Input sanitization
  - Content security policy enforcement
  - IP restriction validation
  - Rate limit checking
  - Request correlation

- **`errors.py`**: Error handling and standardization
  - Consistent error formatting
  - Detailed validation error reporting
  - Security-aware error messages
  - Correlation ID inclusion
  - Error categorization
  - Audit integration for security errors
  - Comprehensive HTTP status code mapping
  - Error documentation references
  - Client-friendly error messages

- **`__init__.py`**: Module initialization with strict security controls
  - Blueprint registration with admin routes
  - Admin-specific metrics collection
  - Security event handlers
  - Authorization middleware configuration
  - Request validation setup
  - Error handling customization
  - Metrics registration
  - Secure defaults configuration
  - File integrity monitoring setup

- **`ws/`**: WebSocket endpoints for real-time administrative functions
  - Secure WebSocket connection management
  - Real-time system health streaming
  - Live audit log monitoring
  - Interactive administrative console
  - Security event notifications
  - Resource utilization dashboards
  - Active user session monitoring
  - Command execution with approval workflow
  - Real-time metrics visualization

## Directory Structure

```plaintext
api/admin/
├── __init__.py          # Module initialization and exports
├── README.md            # This documentation
├── routes.py            # Main API endpoint implementations
├── user_management.py   # User administration functions
├── system_config.py     # System configuration management
├── audit.py             # Audit log access and reporting
├── decorators.py        # Administrative security decorators
├── schemas.py           # Request/response validation schemas
├── middleware.py        # Request preprocessing middleware
├── errors.py            # Error handling and standardization
└── ws/                  # WebSocket endpoints for real-time admin functions
    ├── __init__.py      # WebSocket connection management
    ├── README.md        # WebSocket API documentation
    ├── routes.py        # WebSocket route handlers
    ├── auth.py          # Authentication and authorization
    ├── schemas.py       # Message validation schemas
    └── metrics.py       # Connection and message metrics
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/admin/users` | GET | List all users with filter options | Admin |
| `/api/admin/users` | POST | Create a new user account | Admin |
| `/api/admin/users/{id}` | GET | Get detailed user information | Admin |
| `/api/admin/users/{id}` | PUT | Update user account details | Admin |
| `/api/admin/users/{id}/role` | PATCH | Modify user role assignments | SuperAdmin |
| `/api/admin/users/{id}/mfa` | GET | Check user MFA status | Admin |
| `/api/admin/users/{id}/mfa` | POST | Reset user MFA configuration | SuperAdmin |
| `/api/admin/users/{id}/activity` | GET | View user activity history | Admin |
| `/api/admin/users/{id}/unlock` | POST | Unlock a locked user account | Admin |
| `/api/admin/users/bulk` | POST | Perform bulk user operations | SuperAdmin |
| `/api/admin/roles` | GET | List all roles and permissions | Admin |
| `/api/admin/roles` | POST | Create a new role | SuperAdmin |
| `/api/admin/roles/{id}` | PUT | Update an existing role | SuperAdmin |
| `/api/admin/roles/{id}/permissions` | PATCH | Modify role permissions | SuperAdmin |
| `/api/admin/config` | GET | Get system configuration | Admin |
| `/api/admin/config` | PUT | Update system configuration | SuperAdmin |
| `/api/admin/config/history` | GET | View configuration change history | Admin |
| `/api/admin/config/test` | POST | Test configuration changes | SuperAdmin |
| `/api/admin/audit/logs` | GET | Access security audit logs | Auditor, Admin |
| `/api/admin/audit/events` | GET | Access security events | Auditor, Admin |
| `/api/admin/audit/export` | POST | Export audit data | Auditor, Admin |
| `/api/admin/system/health` | GET | System health dashboard | Admin |
| `/api/admin/system/metrics` | GET | System performance metrics | Admin |
| `/api/admin/system/maintenance` | POST | Perform maintenance operations | SuperAdmin |
| `/api/admin/system/backup` | POST | Initiate system backup | SuperAdmin |
| `/api/admin/system/restore` | POST | Restore from backup | SuperAdmin |
| `/api/admin/system/tasks` | GET | View scheduled administrative tasks | Admin |
| `/api/admin/system/tasks` | POST | Create administrative task | SuperAdmin |
| `/api/admin/security/baseline` | GET | View file integrity baseline | SecurityAdmin |
| `/api/admin/security/baseline` | PUT | Update file integrity baseline | SecurityAdmin |
| `/api/admin/security/baseline/verify` | POST | Verify file integrity status | SecurityAdmin |
| `/api/admin/security/incidents` | GET | List security incidents | SecurityAdmin |
| `/api/admin/security/incidents` | POST | Create security incident | SecurityAdmin |
| `/api/admin/reports` | GET | List available administrative reports | Admin |
| `/api/admin/reports/{report_id}` | GET | Generate administrative report | Admin |

## Configuration

The administrative system uses several configuration settings that can be adjusted in the application config:

```python
# Administrative security settings
'ADMIN_MFA_REQUIRED': True,              # Require MFA for all admin operations
'ADMIN_SESSION_DURATION_MINUTES': 15,    # Short admin session lifetime
'ADMIN_IP_WHITELIST': ['10.0.0.0/8'],    # Restrict admin access by IP range
'ADMIN_MAX_FAILED_ATTEMPTS': 3,          # Lock account after failed attempts
'ADMIN_AUDIT_DETAILED_LOGGING': True,    # Enable verbose audit logging
'ADMIN_APPROVAL_REQUIRED': True,         # Require approval for critical changes
'ADMIN_APPROVAL_EXPIRY_MINUTES': 60,     # Time window for approvals
'ADMIN_REQUIRE_SECURE_CHANNEL': True,    # Require HTTPS for admin API
'ADMIN_PASSWORD_SCORE_MIN': 80,          # Admin password strength requirement
'ADMIN_STRICT_PERMISSION_CHECK': True,   # No permission inheritance for admin actions
'ADMIN_FILE_INTEGRITY_CHECK': True,      # Enable file integrity monitoring
'ADMIN_CRITICAL_FILES': ['app.py', 'config.py', 'api/admin/*.py'],  # Protected files

# Rate limiting settings
'RATELIMIT_ADMIN_DEFAULT': "30 per minute",
'RATELIMIT_ADMIN_CONFIG': "10 per minute",
'RATELIMIT_ADMIN_USER_CREATE': "5 per minute",
'RATELIMIT_ADMIN_SYSTEM': "20 per minute",
'RATELIMIT_ADMIN_AUDIT': "60 per minute",
'RATELIMIT_ADMIN_HEALTH': "12 per minute",
'RATELIMIT_ADMIN_SECURITY': "15 per minute",
'RATELIMIT_ADMIN_EXPORT': "10 per minute",

# WebSocket settings
'ADMIN_WS_MAX_CONNECTIONS': 50,          # Maximum concurrent admin WebSocket connections
'ADMIN_WS_HEARTBEAT_SECONDS': 30,        # WebSocket heartbeat interval
'ADMIN_WS_RECONNECT_MAX_ATTEMPTS': 5,    # Maximum reconnect attempts
'ADMIN_WS_COMMAND_TIMEOUT_SECONDS': 120, # Command execution timeout
'ADMIN_WS_REQUIRE_APPROVAL': True,       # Require approval for WebSocket commands
'ADMIN_WS_METRICS_ENABLED': True,        # Enable WebSocket metrics collection
'ADMIN_WS_METRICS_INTERVAL': 30,         # Interval for metrics emission in seconds
'ADMIN_WS_METRICS_CHANNELS': ['admin:metrics'] # Channels to emit metrics to
```

## Security Features

- **Multi-Factor Authentication**: Enforced for all administrative actions
- **IP Restriction**: Administrative access can be limited to specific IP ranges
- **Enhanced Audit Logging**: Detailed logging of all administrative operations
- **Privileged Access Management**: Time-limited administrative access
- **Session Timeouts**: Short session durations for administrative sessions
- **Permission Separation**: Role-based restrictions on administrative capabilities
- **Strict Rate Limiting**: Prevents abuse of administrative endpoints
- **Real-time Security Alerting**: Notifications of suspicious admin activity
- **Secure WebSocket Connections**: Encrypted real-time administrative data
- **Administrative Action Approval**: Two-person approval for critical changes
- **Context-Aware Authorization**: Validates client context for additional security
- **Request Validation**: Schema-based validation for all incoming requests
- **Secret Data Protection**: Automatic redaction of sensitive data in logs
- **Circuit Breakers**: Automatic protection against cascading failures
- **Replay Protection**: Prevention of request replay attacks
- **Security Headers**: Strict security headers on all responses
- **Secure Defaults**: Conservative defaults requiring explicit opt-out
- **File Integrity Monitoring**: Detection and alerting of unauthorized file modifications
- **Access Anomaly Detection**: Machine learning algorithms identify unusual access patterns
- **API Versioning**: Controlled API changes through versioned endpoints
- **Request Tracing**: Correlation IDs for tracking requests across services

## Usage Examples

### User Management

```http
POST /api/admin/users
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
X-API-Version: 2023-07-01

{
  "username": "john.smith",
  "email": "john.smith@example.com",
  "first_name": "John",
  "last_name": "Smith",
  "role_id": 3,
  "permissions": ["user:read", "cloud:read"],
  "active": true,
  "require_password_change": true,
  "notification_preferences": {
    "email": true,
    "sms": false
  }
}
```

Response:

```json
{
  "id": 42,
  "username": "john.smith",
  "email": "john.smith@example.com",
  "first_name": "John",
  "last_name": "Smith",
  "role_id": 3,
  "role_name": "Operator",
  "created_at": "2023-07-15T10:30:45Z",
  "created_by": "admin.user",
  "permissions": ["user:read", "cloud:read"],
  "active": true,
  "require_password_change": true,
  "notification_preferences": {
    "email": true,
    "sms": false
  },
  "message": "User created successfully",
  "audit_id": "audit-20230715-104592"
}
```

### System Configuration

```http
GET /api/admin/config?component=security
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
X-Request-ID: req-9a582031-4370-4456-8c3d-748d24cca45e
```

Response:

```json
{
  "component": "security",
  "settings": {
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_special": true,
      "history_count": 10,
      "max_age_days": 90
    },
    "session_policy": {
      "duration_minutes": 30,
      "idle_timeout_minutes": 15,
      "regeneration_interval_minutes": 10,
      "single_session": false,
      "enforce_ip_binding": true
    },
    "login_security": {
      "max_attempts": 5,
      "lockout_duration_minutes": 30,
      "mfa_required": true,
      "mfa_remember_days": 30,
      "geo_blocking_enabled": true,
      "anomaly_detection_enabled": true
    },
    "file_integrity": {
      "enabled": true,
      "check_interval_minutes": 120,
      "notify_on_change": true,
      "critical_paths": [
        "/etc/security/",
        "/app/config/"
      ]
    }
  },
  "environment": "production",
  "last_modified": "2023-06-22T14:20:30Z",
  "last_modified_by": "security.admin",
  "version": 8,
  "changes_require_approval": true
}
```

### Audit Log Access

```http
GET /api/admin/audit/logs?event_type=security&severity=warning&start_date=2023-07-01&end_date=2023-07-15&page=1&per_page=10&sort=timestamp&direction=desc
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
X-Request-ID: req-7c191fd3-9c4a-42ef-8812-157ac4b7521a
```

Response:

```json
{
  "data": [
    {
      "id": 12345,
      "timestamp": "2023-07-10T08:24:15Z",
      "event_type": "security",
      "severity": "warning",
      "description": "Multiple failed login attempts",
      "user_id": 28,
      "username": "david.johnson",
      "ip_address": "198.51.100.73",
      "request_id": "req-a9f12c4d-2e3f-4c5b-8d9e-1f2a3b4c5d6e",
      "details": {
        "attempts": 5,
        "timespan_minutes": 3,
        "action_taken": "temporary_lockout",
        "source_location": "office.east",
        "device_type": "desktop"
      },
      "related_events": [12340, 12342, 12343, 12344]
    },
    {
      "id": 12401,
      "timestamp": "2023-07-12T16:08:32Z",
      "event_type": "security",
      "severity": "warning",
      "description": "Permission elevation detected",
      "user_id": 42,
      "username": "john.smith",
      "ip_address": "198.51.100.29",
      "request_id": "req-b8e71d3c-1d2e-3a4b-7c8d-9e0f1a2b3c4d",
      "details": {
        "permission_added": "system:write",
        "approved_by": "admin.user",
        "justification": "Emergency maintenance",
        "expiration": "2023-07-12T20:08:32Z",
        "ticket_id": "INC-2023-0701"
      },
      "related_events": [12399, 12400]
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 10,
    "total_pages": 5,
    "total_items": 48,
    "filters_applied": {
      "event_type": "security",
      "severity": "warning",
      "start_date": "2023-07-01T00:00:00Z",
      "end_date": "2023-07-15T23:59:59Z"
    },
    "export_formats": ["csv", "json", "pdf"],
    "query_time_ms": 43
  }
}
```

### File Integrity Monitoring

```http
GET /api/admin/security/baseline/verify
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
X-Request-ID: req-8d7e6f5d-4c3b-2a1e-9f8g-7h6i5j4k3l2m
```

Response:

```json
{
  "status": "incomplete",
  "timestamp": "2023-07-16T08:45:22Z",
  "total_files": 156,
  "verified": 156,
  "modified": 2,
  "added": 0,
  "removed": 0,
  "verification_id": "verify-20230716-084522",
  "critical_modifications": [
    {
      "path": "/app/config/security.ini",
      "status": "modified",
      "expected_hash": "a1b2c3d4e5f6g7h8i9j0...",
      "current_hash": "k1l2m3n4o5p6q7r8s9t0...",
      "last_modified": "2023-07-15T22:14:37Z",
      "severity": "critical"
    }
  ],
  "other_modifications": [
    {
      "path": "/app/logs/application.log",
      "status": "modified",
      "expected_hash": "u1v2w3x4y5z6a7b8c9d0...",
      "current_hash": "e1f2g3h4i5j6k7l8m9n0...",
      "last_modified": "2023-07-16T08:30:12Z",
      "severity": "low"
    }
  ],
  "recommendations": [
    "Investigate unauthorized modifications to security.ini",
    "Update baseline for expected log file changes"
  ],
  "actions": [
    {
      "name": "Update Baseline",
      "endpoint": "/api/admin/security/baseline",
      "method": "PUT"
    },
    {
      "name": "Create Incident",
      "endpoint": "/api/admin/security/incidents",
      "method": "POST"
    }
  ]
}
```

## Error Handling

All API endpoints implement standardized error handling with detailed information for troubleshooting while protecting sensitive implementation details:

```json
{
  "error": "Bad Request",
  "status_code": 400,
  "message": "Invalid parameters in request",
  "details": {
    "role_id": "Value must be one of [1, 2, 3, 4, 5]",
    "notification_preferences": "Missing required field: email"
  },
  "request_id": "req-c7b69a12-d3e4-5f6a-7b8c-9d0e1f2a3b4c",
  "documentation_url": "https://docs.example.com/api/errors/400",
  "trace_id": "trace-d8e9f0a1-2b3c-4d5e-6f7a-8b9c0d1e2f3a"
}
```

Common error status codes:

| Status | Code Name | Description |
|--------|-----------|-------------|
| 400 | Bad Request | Invalid input parameters or structure |
| 401 | Unauthorized | Missing or invalid authentication token |
| 403 | Forbidden | Valid authentication but insufficient permissions |
| 404 | Not Found | Requested resource doesn't exist |
| 409 | Conflict | Resource state prevents requested operation |
| 422 | Unprocessable Entity | Request validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server-side error |
| 503 | Service Unavailable | Service temporarily down or in maintenance mode |
| 507 | Insufficient Storage | Storage quota exceeded for operation |
| 511 | Network Authentication Required | Network access requires authentication |

## Metrics and Monitoring

The Administrative API collects and exposes metrics to help monitor usage patterns, performance, and security events:

- **Request Metrics**: Volume, response times, error rates by endpoint and method
- **Authentication Metrics**: Success/failure rates, MFA usage, token lifetimes
- **Authorization Metrics**: Permission denials, access patterns, role distribution
- **Operation Metrics**: Resource creation/modification/deletion counts, batch operation efficiency
- **Security Metrics**: Suspicious access attempts, privilege elevations, integrity violations
- **Performance Metrics**: Database operation times, caching efficiency, response size
- **WebSocket Metrics**: Connection counts, message throughput, subscription patterns
- **File Integrity Metrics**: Baseline verification results, change frequencies
- **Audit Metrics**: Event volume by type and severity, export frequency
- **System Health Metrics**: Resource utilization, service availability, endpoint response times

These metrics are available through the monitoring system and the `/api/admin/system/metrics` endpoint, subject to appropriate permissions. Real-time monitoring dashboards are accessible via the WebSocket interface for authorized administrators.

## Related Documentation

- Administrative Guidelines
- User Management Guide
- System Configuration Guide
- Security Incident Response
- Audit Log Reference
- Administrative API Reference
- RBAC Implementation Guide
- WebSocket Security Guidelines
- File Integrity Monitoring Guide
- Administrative Reports Guide
- Security Baseline Management
- Multi-Factor Authentication Setup
- Rate Limiting Guidelines
- Administrative Metrics Reference
- API Security Best Practices
