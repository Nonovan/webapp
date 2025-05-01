# Authentication API

The Authentication API module provides secure endpoints for user authentication, registration, token management, and session handling in the Cloud Infrastructure Platform. This module serves as the entry point for programmatic authentication with cloud resources and ICS systems.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Authentication Decorators
- Usage Examples
- Related Documentation

## Overview

The Authentication API implements RESTful endpoints following security best practices including rate limiting, suspicious IP detection, comprehensive audit logging, and proper error handling. It uses JWT tokens for stateless API access and provides session management for web interfaces with security features like session regeneration and device fingerprinting.

## Key Components

- **`__init__.py`**: Module initialization with metrics and event handlers
  - Blueprint registration with proper routes
  - Event handler registration
  - Security metrics integration
  - Session manager configuration

- **`decorators.py`**: Authentication-specific decorator functions
  - Authorization enforcement
  - MFA requirement validation
  - Permission checking
  - Role verification
  - Token validation
  - API activity tracking
  - Security event auditing

- **`extend_session.py`**: Session management implementation with security features
  - Device fingerprinting for client verification
  - IP binding for high-security environments
  - Session regeneration to prevent session fixation attacks
  - Suspicious activity detection and reporting
  - Configurable security settings

- **`mfa.py`**: Multi-factor authentication implementation
  - Backup code management
  - FIDO2/WebAuthn support
  - MFA enrollment workflow
  - One-time password validation
  - TOTP configuration

- **`password_reset.py`**: Password reset functionality
  - Email verification
  - Password history enforcement
  - Reset token generation
  - Secure link handling
  - Token expiration management

- **`routes.py`**: Implements RESTful API endpoints with comprehensive input validation
  - Account registration with validation
  - Logout functionality for both web and API contexts
  - Session management with security protections
  - Token verification and refresh operations
  - User authentication with brute force protection

- **`session_status.py`**: Session information and status
  - Permission validation
  - Session expiration tracking
  - Session security status
  - Session validation
  - User context management

## Directory Structure

```plaintext
api/auth/
├── __init__.py         # Module initialization and exports
├── decorators.py       # Authentication-specific decorators
├── extend_session.py   # Session management functionality
├── mfa.py              # Multi-factor authentication implementation
├── password_reset.py   # Password reset functionality
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
└── session_status.py   # Session information and status
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/api/auth/login` | POST | Authenticate user and issue JWT token | 10/minute |
| `/api/auth/logout` | POST/GET | Invalidate current token | None |
| `/api/auth/mfa/setup` | POST | Configure multi-factor authentication | 3/hour |
| `/api/auth/mfa/verify` | POST | Verify MFA challenge | 10/minute |
| `/api/auth/password/reset` | POST | Initiate password reset workflow | 3/hour |
| `/api/auth/refresh` | POST | Refresh an existing JWT token | 20/minute |
| `/api/auth/register` | POST | Create new user account | 5/hour |
| `/api/auth/extend_session` | POST | Extend session lifetime | 30/minute |
| `/api/auth/session/status` | GET | Check current session status and permissions | 60/minute |
| `/api/auth/verify` | POST | Verify token validity | 60/minute |

## Configuration

The authentication system uses several configuration settings that can be adjusted in the application config:

```python
# Session security settings
'SESSION_DURATION_MINUTES': 30,          # Default session duration
'SESSION_REGENERATION_INTERVAL': 30,     # Minutes between session ID regeneration
'MAX_SESSIONS_PER_USER': 5,              # Maximum concurrent sessions per user
'ENABLE_SESSION_IP_BINDING': False,      # Restrict sessions to originating IP
'ENABLE_SESSION_FINGERPRINT_BINDING': True, # Bind sessions to browser fingerprint
'HIGH_SECURITY_MODE': False,             # Enable stricter security controls
'STRICT_SESSION_SECURITY': False,        # Enforce user-agent validation

# Rate limiting settings
'RATELIMIT_DEFAULT': "200 per day, 50 per hour",
'RATELIMIT_LOGIN': "10 per minute",
'RATELIMIT_REGISTER': "5 per hour",

# MFA settings
'MFA_REQUIRED_ROLES': ["admin", "security"],  # Roles requiring MFA
'MFA_TOTP_ISSUER': "Cloud Platform",          # TOTP issuer name
'MFA_VERIFY_TOLERANCE': 1,                    # TOTP window tolerance
'MFA_BACKUP_CODE_COUNT': 10,                  # Number of backup codes

# Password reset settings
'PASSWORD_RESET_EXPIRATION_MINUTES': 15,      # Reset link expiration
'PASSWORD_RESET_EMAIL_THROTTLE': 5,           # Minutes between reset emails
```

## Security Features

- **Brute Force Protection**: Implements progressive lockouts for failed attempts
- **Comprehensive Audit Logging**: Records all authentication events for security monitoring
- **Device Fingerprinting**: Validates session requests against browser fingerprints
- **Input Validation**: Validates all inputs before processing
- **Multi-Factor Authentication**: Supports TOTP and hardware security keys
- **Rate Limiting**: Prevents brute force attacks with endpoint-specific limits
- **Secure Error Handling**: Prevents information leakage in error responses
- **Secure Token Handling**: Implements JWT token validation and secure storage
- **Session Protection**: Regenerates session IDs periodically to prevent session fixation
- **Suspicious IP Detection**: Flags and logs suspicious IP addresses

## Authentication Decorators

The decorators.py module provides powerful security decorators that can be applied to API endpoints to enforce various security controls:

### `token_required`

Enforces JWT token authentication for API routes.

```python
@token_required
def protected_api_endpoint():
    # Only accessible with valid JWT token
    pass
```

### `require_api_role`

Restricts access based on user roles.

```python
@require_api_role('admin')  # Single role
def admin_only_endpoint():
    pass

@require_api_role(['admin', 'security'])  # Multiple roles
def security_endpoint():
    pass
```

### `require_api_permission`

Restricts access based on specific permissions.

```python
@require_api_permission('users:write')
def user_update_endpoint():
    pass
```

### `require_api_mfa`

Enforces multi-factor authentication for sensitive operations.

```python
@require_api_mfa
def sensitive_operation():
    pass
```

### `validate_session`

Validates web sessions for hybrid endpoints supporting both web and API access.

```python
@validate_session
def hybrid_endpoint():
    pass
```

### `track_api_activity`

Records detailed API activity for security auditing.

```python
@track_api_activity('user_management', description="User profile modification")
def update_user_profile():
    pass
```

### `audit_api_action`

Creates security audit logs for sensitive operations.

```python
@audit_api_action('security_configuration', severity="critical")
def update_security_settings():
    pass
```

### Combined Decorator Usage

Decorators can be combined for layered security:

```python
@require_api_role('admin')
@require_api_mfa
@audit_api_action('security_change', severity="high")
def update_security_policy():
    # Protected by role checks, MFA requirement, and security auditing
    pass
```

## Usage Examples

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin_user",
  "password": "secure_password"
}
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin_user",
    "role": "admin"
  }
}
```

### MFA Setup

```http
POST /api/auth/mfa/setup
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "type": "totp"
}
```

Response:

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgo...",
  "setup_token": "a1b2c3d4e5f6"
}
```

### Password Reset

```http
POST /api/auth/password/reset
Content-Type: application/json

{
  "email": "user@example.com"
}
```

Response:

```json
{
  "success": true,
  "message": "Password reset instructions sent if email exists"
}
```

### Registration

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "new_user",
  "email": "user@example.com",
  "password": "SecureP@ssword1",
  "first_name": "John",
  "last_name": "Doe"
}
```

Response:

```json
{
  "message": "Registration successful",
  "user_id": 42
}
```

### Session Extension

```http
POST /api/auth/extend_session
```

Response:

```json
{
  "success": true,
  "message": "Session extended successfully",
  "expires_at": "2023-01-01T12:30:00Z"
}
```

### Session Status

```http
GET /api/auth/session/status
```

Response:

```json
{
  "authenticated": true,
  "user_id": 42,
  "username": "admin_user",
  "role": "admin",
  "permissions": ["user:read", "user:write"],
  "expires_at": "2023-01-01T12:30:00Z",
  "mfa_verified": true
}
```

### Token Verification

```http
POST /api/auth/verify
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Response:

```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "admin_user",
    "role": "admin"
  }
}
```

## Related Documentation

- API Reference
- Authentication Service
- Password Policy Documentation
- Security Best Practices
- Security Module
- User and Permission Models
