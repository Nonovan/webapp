# Authentication Blueprint

This blueprint provides authentication functionality for the Cloud Infrastructure Platform, implementing secure user authentication flows, session management, and security controls.

## Contents

- Overview
- Key Components
- Directory Structure
- Routes
- Configuration
- Security Features
- Usage Examples
- Related Documentation

## Overview

The Authentication Blueprint implements comprehensive user authentication functionality including login, registration, password management, multi-factor authentication, and session control. The blueprint follows security best practices with proper input validation, rate limiting, suspicious activity detection, and comprehensive audit logging. All security-critical operations are protected against common threats including brute force attacks, session hijacking, and credential stuffing.

## Key Components

- **`__init__.py`**: Blueprint initialization and request hooks
  - Authentication metrics collection
  - Error handlers for 401/403 responses
  - Request lifecycle management
  - Security monitoring integration
  - Teardown handlers for cleanup

- **`decorators.py`**: Security decorators
  - Anonymous-only route protection
  - MFA requirement enforcement
  - Permission validation
  - Rate limiting controls
  - Role-based access control

- **`routes.py`**: Authentication endpoints
  - Login with brute-force protection
  - Logout with proper session termination
  - Multi-factor authentication flows
  - Password management functionality
  - Registration with proper validation
  - Social authentication integration

- **`templates/`**: Authentication user interfaces
  - Change password interface
  - Login interface with security features
  - MFA setup and management screens
  - Registration form with validation
  - Reset password workflow templates

- **`utils.py`**: Authentication utilities
  - JWT token generation and validation
  - Password strength validation
  - Security input validation
  - Session management functions
  - Token-based authentication helpers

## Directory Structure

```plaintext
blueprints/auth/
├── README.md         # This documentation
├── __init__.py       # Blueprint initialization
├── decorators.py     # Security decorators
├── routes.py         # Authentication endpoints
├── templates/        # HTML templates
│   └── auth/         # Authentication templates
│       ├── README.md # Templates documentation
│       ├── change_password.html  # Password change interface
│       ├── login.html           # Authentication interface
│       ├── mfa_setup.html       # Multi-factor authentication setup
│       ├── register.html        # User registration interface
│       └── reset_password.html  # Password reset functionality
└── utils.py          # Authentication utilities
```

## Routes

| Route | Methods | Purpose | Security |
|-------|---------|---------|----------|
| `/auth/login` | GET, POST | User authentication | Rate limited: 5/minute |
| `/auth/logout` | GET | Session termination | Session validation |
| `/auth/register` | GET, POST | New account creation | Rate limited: 3/hour |
| `/auth/change-password` | GET, POST | Password management | Authentication required |
| `/auth/forgot-password` | GET, POST | Password reset initiation | Rate limited: 3/hour |
| `/auth/reset-password/<token>` | GET, POST | Password reset completion | Token validation |
| `/auth/mfa-setup` | GET, POST | MFA configuration | Authentication required |
| `/auth/mfa-verify` | POST | MFA challenge verification | Rate limited: 5/minute |

## Configuration

The authentication blueprint uses these configuration settings:

```python
# Rate limiting settings
RATELIMIT_DEFAULT = "200 per day, 50 per hour"
RATELIMIT_LOGIN = "5 per minute"
RATELIMIT_REGISTER = "3 per hour"
RATELIMIT_PASSWORD_RESET = "3 per hour"

# Session security settings
SESSION_COOKIE_SECURE = True              # In production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
PERMANENT_SESSION_LIFETIME = 1800         # 30 minutes
SESSION_REFRESH_EACH_REQUEST = True

# Authentication settings
ENABLE_MFA = True
MFA_REQUIRED_ROLES = ["admin", "security"]
BCRYPT_LOG_ROUNDS = 12
LOGIN_DISABLED = False
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_MINUTES = 15
PASSWORD_MINIMUM_LENGTH = 12

# Security headers (set via Flask-Talisman)
CONTENT_SECURITY_POLICY = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"],
    'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    'img-src': ["'self'", "data:", "https://www.google.com"],
    'frame-src': ["'self'", "https://www.google.com/recaptcha/"]
}
```

## Security Features

- **Anti-Automation**: reCAPTCHA integration to prevent automated attacks
- **Brute Force Protection**: Progressive account lockouts after failed login attempts
- **CSRF Protection**: Cross-Site Request Forgery tokens for all forms
- **Client Validation**: JavaScript validation for immediate user feedback
- **Content Security Policy**: CSP headers with nonces for inline scripts
- **Password Strength**: Real-time password strength visualization
- **Rate Limiting**: Request rate limits on security-critical endpoints
- **Secure Headers**: Security headers for XSS and clickjacking protection
- **Session Security**: Secure session handling with proper expiration
- **Subresource Integrity**: SRI hashes for external resources
- **Two-Factor Authentication**: TOTP-based multi-factor authentication

## Usage Examples

### Authentication Flow

```python
from flask import redirect, url_for, flash
from flask_login import login_user, logout_user
from models.user import User
from services.auth_service import AuthService

def login_example():
    username = "user@example.com"
    password = "secure_password"

    # Use AuthService for authentication
    success, user, message = AuthService.authenticate_user(username, password)

    if success and user:
        # Login the user
        login_user(user)
        return redirect(url_for('main.dashboard'))
    else:
        flash(message, 'danger')
        return redirect(url_for('auth.login'))
```

### Session Management

```python
from flask import session
import datetime

def extend_session():
    # Update session activity timestamp
    session['last_active'] = datetime.datetime.utcnow().isoformat()
    session.modified = True

def check_session_expired():
    last_active = datetime.datetime.fromisoformat(session.get('last_active', ''))
    current_time = datetime.datetime.utcnow()

    # Check if session has expired (30 minute timeout)
    return (current_time - last_active).total_seconds() > 1800
```

### Password Validation

```python
from blueprints.auth.utils import validate_password

def change_password_example(current_password, new_password):
    # First validate the user's current password
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return False

    # Validate password strength
    valid, message = validate_password(new_password)
    if not valid:
        flash(message, 'danger')
        return False

    # Update the password
    current_user.set_password(new_password)
    db.session.commit()

    # Log the password change for audit
    log_security_event('password_change', current_user.id)
    return True
```

## Related Documentation

- Authentication Service
- Content Security Policy
- Multi-Factor Authentication
- Password Policy
- Security Controls
- Security Best Practices
- CSRF Protection
- User Management
