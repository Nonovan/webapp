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
│       ├── confirm_password.html # Password confirmation for sensitive operations
│       ├── errors/              # Authentication-specific error pages
│       │   ├── 401.html        # Unauthorized error template
│       │   └── 403.html        # Forbidden error template
│       ├── login.html          # Authentication interface
│       ├── mfa_backup_codes.html # Backup codes display
│       ├── mfa_setup.html      # Multi-factor authentication setup
│       ├── mfa_verify.html     # MFA verification during login
│       ├── register.html       # User registration interface
│       ├── reset_password.html # Password reset functionality
│       └── components/         # Shared template components
│           ├── password_requirements.html  # Password requirement display
│           ├── mfa_instructions.html       # MFA setup instructions
│           └── security_notice.html        # Security notifications
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
| `/auth/mfa-verify` | GET, POST | MFA challenge verification | Rate limited: 5/minute |
| `/auth/confirm-password` | GET, POST | Password re-verification | Authentication required |
| `/auth/mfa-disable` | POST | MFA deactivation | Admin role required |
| `/auth/access-denied` | GET | Forbidden access response | None |

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
SESSION_TIMEOUT_MINUTES = 30              # Session inactivity timeout
SESSION_REFRESH_EACH_REQUEST = True
PASSWORD_CONFIRM_TTL = 300                # Password confirmation validity (5 minutes)

# Authentication settings
ENABLE_MFA = True
MFA_REQUIRED_ROLES = ["admin", "security"]
BCRYPT_LOG_ROUNDS = 12
LOGIN_DISABLED = False
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_MINUTES = 15
PASSWORD_MINIMUM_LENGTH = 12
ACCOUNT_LOCKOUT_MINUTES = 15
USER_ACTIVITY_UPDATE_INTERVAL = 300       # Activity logging interval (5 minutes)

# Security headers (set via Flask-Talisman)
CONTENT_SECURITY_POLICY = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"],
    'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    'img-src': ["'self'", "data:", "https://www.google.com"],
    'frame-src': ["'self'", "https://www.google.com/recaptcha/"]
}

# reCAPTCHA configuration
ENABLE_RECAPTCHA = True
RECAPTCHA_SITE_KEY = "your-site-key"
RECAPTCHA_SECRET_KEY = "your-secret-key"

# Social authentication
SOCIAL_AUTH_ENABLED = True
ALLOWED_REDIRECT_DOMAINS = ["trusted-domain.com"]  # For social auth callbacks
```

## Security Features

- **Anti-Automation**: reCAPTCHA integration to prevent automated attacks
- **Brute Force Protection**: Progressive account lockouts after failed login attempts
- **CSRF Protection**: Cross-Site Request Forgery tokens for all forms
- **Client Validation**: JavaScript validation for immediate user feedback
- **Content Security Policy**: CSP headers with nonces for inline scripts
- **IP Verification**: Token binding to IP for session security
- **MFA Implementation**: Time-based One-Time Password (TOTP) authentication
- **Password Strength**: Real-time password strength visualization
- **Rate Limiting**: Request rate limits on security-critical endpoints
- **Secure Headers**: Security headers for XSS and clickjacking protection
- **Session Security**: Secure session handling with proper expiration
- **Session Regeneration**: Session ID regeneration after authentication
- **Subresource Integrity**: SRI hashes for external resources
- **Suspicious Activity Detection**: Monitoring of unusual login patterns
- **Two-Factor Authentication**: TOTP-based multi-factor authentication

## Usage Examples

### Authentication Flow

```python
from flask import redirect, url_for, flash
from flask_login import login_user
from models.auth import User
from services.auth_service import AuthService

def login_example():
    username = "user@example.com"
    password = "secure_password"

    # Use AuthService for authentication
    success, user, message = AuthService.authenticate_user(
        username,
        password,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )

    if success and user:
        # Login the user
        login_user(user)

        # Record successful login for auditing
        record_login_success(user)

        # Regenerate session ID to prevent session fixation
        regenerate_session()

        return redirect(url_for('main.dashboard'))
    else:
        # Record failed login attempt for security monitoring
        record_login_failure(username, message or "Invalid credentials")

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
    if 'last_active' not in session:
        return True

    last_active = datetime.datetime.fromisoformat(session.get('last_active'))
    current_time = datetime.datetime.utcnow()
    timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', 30)

    # Check if session has expired based on inactivity timeout
    return (current_time - last_active).total_seconds() > (timeout_minutes * 60)

def regenerate_session():
    """Regenerate session ID to prevent session fixation attacks"""
    if 'user_id' in session:
        # Store the current session data
        user_id = session.get('user_id')
        role = session.get('role')
        last_active = datetime.datetime.utcnow().isoformat()

        # Clear the session to get a new session ID
        session.clear()

        # Restore the session data
        session['user_id'] = user_id
        session['role'] = role
        session['last_active'] = last_active
        session['session_regenerated_at'] = datetime.datetime.utcnow().isoformat()

        # Mark the session as modified
        session.modified = True
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

    # Log the security event for audit
    log_security_event(
        event_type='password_change',
        description=f"Password changed for user: {current_user.username}",
        severity="info",
        user_id=current_user.id,
        ip_address=request.remote_addr
    )

    # Force a session regeneration for security
    regenerate_session()

    return True
```

### MFA Implementation

```python
from blueprints.auth.utils import validate_totp
from services.auth_service import AuthService

def setup_mfa():
    # Generate a new TOTP secret
    secret = AuthService.generate_totp_secret()

    # Get QR code for the secret
    qr_code_url = AuthService.get_totp_qr_code(current_user.username, secret)

    # Store temporarily in session until verified
    session['mfa_setup_secret'] = secret

    return qr_code_url, secret

def verify_and_enable_mfa(verification_code):
    # Get the secret from the session
    secret = session.get('mfa_setup_secret')
    if not secret:
        return False, "MFA setup not initiated"

    # Verify the provided code
    if not AuthService.verify_totp_code(secret, verification_code):
        return False, "Invalid verification code"

    # Enable MFA for the user
    success = AuthService.enable_totp_mfa(current_user.id, secret)
    if not success:
        return False, "Failed to enable MFA"

    # Generate backup codes
    backup_codes = AuthService.generate_backup_codes(current_user.id)

    # Clear the setup secret from session
    session.pop('mfa_setup_secret', None)

    # Log the security event
    log_security_event(
        event_type='mfa_enabled',
        description=f"MFA enabled for user: {current_user.username}",
        severity="info",
        user_id=current_user.id,
        ip_address=request.remote_addr
    )

    return True, backup_codes
```

### Brute Force Protection

```python
from blueprints.auth.utils import check_bruteforce_attempts, reset_login_attempts

def login_with_protection(username, password):
    # Check for previous failed attempts
    is_locked, attempts_remaining = check_bruteforce_attempts(username)

    if is_locked:
        # Log security event
        log_security_event(
            event_type='account_lockout',
            description=f"Login attempt on locked account: {username}",
            severity="warning",
            ip_address=request.remote_addr
        )

        return False, None, "Account temporarily locked due to too many failed attempts"

    # Attempt authentication
    success, user, message = AuthService.authenticate_user(username, password)

    if success and user:
        # Reset failed login attempts counter
        reset_login_attempts(username)
        return True, user, None
    else:
        # Failed login will increment the counter in check_bruteforce_attempts
        return False, None, message or "Invalid username or password"
```

## Related Documentation

- Authentication Service
- Authentication Decorators
- Authentication Templates
- Authentication Utilities
- Content Security Policy
- CSRF Protection
- Multi-Factor Authentication
- Password Policy
- Security Controls
- User Models
