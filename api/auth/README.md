# Authentication API

The Authentication API module provides secure endpoints for user authentication, registration, token management, and session handling in the Cloud Infrastructure Platform. This module serves as the entry point for programmatic authentication with cloud resources and ICS systems.

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

The Authentication API implements RESTful endpoints following security best practices including rate limiting, suspicious IP detection, comprehensive audit logging, and proper error handling. It uses JWT tokens for stateless API access and provides session management for web interfaces with security features like session regeneration and device fingerprinting.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints with comprehensive input validation
  - User authentication with brute force protection
  - Account registration with validation
  - Session management with security protections
  - Token verification and refresh operations
  - Logout functionality for both web and API contexts

- **`extend_session.py`**: Session management implementation with security features
  - Session regeneration to prevent session fixation attacks
  - Device fingerprinting for client verification
  - IP binding for high-security environments
  - Suspicious activity detection and reporting
  - Configurable security settings

- **`__init__.py`**: Module initialization with metrics and event handlers
  - Blueprint registration with proper routes
  - Security metrics integration
  - Event handler registration
  - Session manager configuration

## Directory Structure

```plaintext
api/auth/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── extend_session.py   # Session management functionality
└── routes.py           # API endpoint implementations
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/api/auth/login` | POST | Authenticate user and issue JWT token | 10/minute |
| `/api/auth/register` | POST | Create new user account | 5/hour |
| `/api/auth/extend_session` | POST | Extend session lifetime | 30/minute |
| `/api/auth/verify` | POST | Verify token validity | 60/minute |
| `/api/auth/refresh` | POST | Refresh an existing JWT token | 20/minute |
| `/api/auth/logout` | POST/GET | Invalidate current token | None |

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
```

## Security Features

- **Rate Limiting**: Prevents brute force attacks with endpoint-specific limits
- **Session Protection**: Regenerates session IDs periodically to prevent session fixation
- **Device Fingerprinting**: Validates session requests against browser fingerprints
- **Suspicious IP Detection**: Flags and logs suspicious IP addresses
- **Progressive Lockouts**: Implements account lockout after multiple failed attempts
- **Comprehensive Audit Logging**: Records all authentication events for security monitoring
- **Secure Token Handling**: Implements JWT token validation and secure storage
- **Input Validation**: Validates all inputs before processing
- **Secure Error Handling**: Prevents information leakage in error responses

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

- Authentication Service
- User and Permission Models
- Security Module
- API Reference
- Security Best Practices
