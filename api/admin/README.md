# Administrative API

The Administrative API module provides secure endpoints for system management, user administration, configuration control, and audit capabilities in the Cloud Infrastructure Platform. This module is restricted to authorized administrators and implements enhanced security controls to protect privileged operations.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Usage Examples
- Related Documentation

## Overview

The Administrative API implements RESTful endpoints following security best practices including strict authentication requirements, multi-factor authentication enforcement, comprehensive audit logging, and detailed permission controls. It provides system administrators with the tools needed to manage users, monitor system health, configure application settings, and review security events.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for administrative operations
  - System status and health monitoring dashboards
  - Application configuration management
  - Administrative notifications and alerts
  - Environment and feature flag management
  - System maintenance operations

- **`user_management.py`**: User administration functionality
  - User account creation and management
  - Role and permission assignment
  - Account lockout management
  - User activity monitoring
  - Administrative privilege management

- **`system_config.py`**: System configuration management
  - Environment settings management
  - Feature flag control
  - System parameter configuration
  - Security policy management
  - Integration settings maintenance

- **`audit.py`**: Administrative audit functionality
  - Security event log access
  - User activity reporting
  - Compliance reporting tools
  - Security incident tracking
  - System change auditing

- **`decorators.py`**: Administrative security decorators
  - Role and permission validation
  - Enhanced audit logging for administrative actions
  - Multi-factor authentication enforcement
  - IP restriction validation
  - Rate limiting for sensitive operations

- **`__init__.py`**: Module initialization with strict security controls
  - Blueprint registration with admin routes
  - Admin-specific metrics collection
  - Security event handlers
  - Authorization middleware configuration

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
└── ws/                  # WebSocket endpoints for real-time admin functions
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/admin/users` | GET | List all users with filter options | Admin |
| `/api/admin/users` | POST | Create a new user account | Admin |
| `/api/admin/users/{id}` | GET | Get detailed user information | Admin |
| `/api/admin/users/{id}` | PUT | Update user account details | Admin |
| `/api/admin/users/{id}/role` | PATCH | Modify user role assignments | SuperAdmin |
| `/api/admin/roles` | GET | List all roles and permissions | Admin |
| `/api/admin/config` | GET | Get system configuration | Admin |
| `/api/admin/config` | PUT | Update system configuration | SuperAdmin |
| `/api/admin/audit/logs` | GET | Access security audit logs | Auditor, Admin |
| `/api/admin/audit/events` | GET | Access security events | Auditor, Admin |
| `/api/admin/system/health` | GET | System health dashboard | Admin |
| `/api/admin/system/maintenance` | POST | Perform maintenance operations | SuperAdmin |

## Configuration

The administrative system uses several configuration settings that can be adjusted in the application config:

```python
# Administrative security settings
'ADMIN_MFA_REQUIRED': True,              # Require MFA for all admin operations
'ADMIN_SESSION_DURATION_MINUTES': 15,    # Short admin session lifetime
'ADMIN_IP_WHITELIST': ['10.0.0.0/8'],    # Restrict admin access by IP range
'ADMIN_MAX_FAILED_ATTEMPTS': 3,          # Lock account after failed attempts
'ADMIN_AUDIT_DETAILED_LOGGING': True,    # Enable verbose audit logging

# Rate limiting settings
'RATELIMIT_ADMIN_DEFAULT': "30 per minute",
'RATELIMIT_ADMIN_CONFIG': "10 per minute",
'RATELIMIT_ADMIN_USER_CREATE': "5 per minute",
'RATELIMIT_ADMIN_SYSTEM': "20 per minute",
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

## Usage Examples

### User Management

```http
POST /api/admin/users
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456

{
  "username": "john.smith",
  "email": "john.smith@example.com",
  "first_name": "John",
  "last_name": "Smith",
  "role_id": 3,
  "permissions": ["user:read", "cloud:read"],
  "active": true
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
  "message": "User created successfully"
}
```

### System Configuration

```http
GET /api/admin/config?component=security
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
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
      "history_count": 10
    },
    "session_policy": {
      "duration_minutes": 30,
      "idle_timeout_minutes": 15,
      "regeneration_interval_minutes": 10
    },
    "login_security": {
      "max_attempts": 5,
      "lockout_duration_minutes": 30,
      "mfa_required": true
    }
  },
  "last_modified": "2023-06-22T14:20:30Z",
  "last_modified_by": "security.admin"
}
```

### Audit Log Access

```http
GET /api/admin/audit/logs?event_type=security&severity=warning&start_date=2023-07-01&end_date=2023-07-15
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456
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
      "details": {
        "attempts": 5,
        "timespan_minutes": 3,
        "action_taken": "temporary_lockout"
      }
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
      "details": {
        "permission_added": "system:write",
        "approved_by": "admin.user",
        "justification": "Emergency maintenance"
      }
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 10,
    "total_pages": 5,
    "total_items": 48
  }
}
```

## Related Documentation

- Administrative Guidelines
- User Management Guide
- System Configuration
- Security Incident Response
- Audit Log Reference
- Administrative API Reference
