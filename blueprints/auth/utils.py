"""
Authentication utility functions for myproject.

This module provides utility functions for authentication-related operations,
implementing security best practices for:
- Input validation and sanitization
- Password strength verification
- JWT token generation and verification
- Authorization decorators for role-based access control
- Rate limiting for security-critical operations
- Session security and verification
- IP address and geographic location validation

These utilities are used throughout the application to ensure consistent
security practices and to centralize authentication logic for easier
maintenance and updates.
"""
import ipaddress
import re
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union, cast
from urllib.parse import urlparse

import jwt
from flask import (abort, current_app, flash, g, redirect, request, session,
                   url_for)
from werkzeug.security import generate_password_hash, check_password_hash

from core.security import log_security_event
from extensions import cache, db, limiter, metrics
from models.auth import User, UserSession

# Define a generic type variable for decorators
T = TypeVar('T', bound=Callable)

# Constants for security settings
TOKEN_ALGORITHM = 'HS256'
DEFAULT_TOKEN_EXPIRY = 3600  # 1 hour
SESSION_TIMEOUT_MINUTES = 30
PASSWORD_MIN_LENGTH = 12

# List of common passwords to check against
COMMON_PASSWORDS_FILE = 'data/security/common_passwords.txt'
common_passwords = set()
try:
    with open(COMMON_PASSWORDS_FILE, 'r') as f:
        common_passwords = set(line.strip().lower() for line in f if line.strip())
except (FileNotFoundError, IOError):
    current_app.logger.warning(f"Common passwords file not found: {COMMON_PASSWORDS_FILE}")


def validate_input(text: str, pattern: str = r'^[\w\s-]{1,100}$') -> bool:
    """
    Validate and sanitize general text input.

    This function checks if the input is a valid string and matches a safe pattern
    for usernames and other text fields to prevent injection attacks.

    Args:
        text: The input string to validate
        pattern: Regex pattern to validate against (default: alphanumeric, space, hyphen)

    Returns:
        bool: True if the input is valid, False otherwise

    Examples:
        >>> validate_input("john_doe123")
        True
        >>> validate_input("<script>alert('XSS')</script>")
        False
        >>> validate_input("email@example.com", r'^[\w.@+-]+$')
        True
    """
    if not text or not isinstance(text, str):
        return False
    text = text.strip()
    return bool(re.match(pattern, text))


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength with comprehensive checks.

    This function verifies that a password meets security requirements for:
    - Minimum length (12 characters)
    - Character diversity (uppercase, lowercase, numbers, special chars)
    - Not in common password list
    - No repeating patterns

    Args:
        password: The password string to validate

    Returns:
        tuple[bool, Optional[str]]:
            - A boolean indicating if the password is valid
            - An error message if invalid, None otherwise

    Examples:
        >>> validate_password("short")
        (False, "Password must be at least 12 characters")
        >>> validate_password("StrongP@ssw0rd")
        (True, None)
    """
    if not password or not isinstance(password, str):
        return False, "Password cannot be empty"

    min_length = current_app.config.get('PASSWORD_MIN_LENGTH', PASSWORD_MIN_LENGTH)

    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters"

    # Check for character diversity
    if not re.search("[a-z]", password):
        return False, "Password must include at least one lowercase letter"

    if not re.search("[A-Z]", password):
        return False, "Password must include at least one uppercase letter"

    if not re.search("[0-9]", password):
        return False, "Password must include at least one number"

    if not re.search("[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character"

    # Check for common passwords
    if password.lower() in common_passwords:
        return False, "This password is too common and easily guessed"

    # Check for repeating characters (e.g., "aaa")
    if re.search(r'(.)\1{2,}', password):
        return False, "Password contains repeating characters"

    # Check for sequential patterns (e.g., "123", "abc")
    sequences = ["abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for sequence in sequences:
        for i in range(len(sequence) - 2):
            if sequence[i:i+3].lower() in password.lower():
                return False, "Password contains a common sequence"

    return True, None


def generate_token(user_id: Union[int, str],
                  role: str,
                  expires_in: int = DEFAULT_TOKEN_EXPIRY,
                  additional_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a secure JWT token with user information and expiration.

    This function creates a signed JWT token containing the user's ID and role,
    with automatic expiration for security. It can include additional data as needed.

    Args:
        user_id: The user's ID to encode in the token
        role: The user's role for authorization checks
        expires_in: Token lifetime in seconds (default: 1 hour)
        additional_data: Optional additional claims to include in the token

    Returns:
        str: A signed JWT token string

    Raises:
        RuntimeError: If token generation fails

    Examples:
        >>> token = generate_token(123, "admin", 7200)  # 2-hour admin token
        >>> token = generate_token(456, "user")  # 1-hour user token
        >>> token = generate_token(789, "api", 3600, {"scope": "read:users"})
    """
    try:
        payload = {
            'sub': str(user_id),  # Subject (user ID)
            'role': role,
            'iat': datetime.utcnow(),  # Issued at
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),  # Expiration
            'jti': secrets.token_hex(16)  # JWT ID for uniqueness
        }

        # Add client info for security tracking
        payload['ip'] = request.remote_addr if hasattr(request, 'remote_addr') else None
        payload['ua'] = str(request.user_agent) if hasattr(request, 'user_agent') else None

        # Incorporate additional data if provided
        if additional_data and isinstance(additional_data, dict):
            for key, value in additional_data.items():
                if key not in payload:  # Don't overwrite standard claims
                    payload[key] = value

        # Get the secret key from configuration
        secret_key = current_app.config.get('JWT_SECRET_KEY', current_app.config['SECRET_KEY'])

        # Generate the token
        token = jwt.encode(
            payload,
            secret_key,
            algorithm=TOKEN_ALGORITHM
        )

        # Track token generation in metrics
        metrics.info('token_generation_total', 1, labels={
            'role': role,
            'success': 'true'
        })

        # Convert bytes to str if using older PyJWT
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        # Log the token generation
        current_app.logger.debug(
            f"Generated token for user {user_id} with role {role}",
            extra={
                "expires_in": expires_in,
                "token_id": payload["jti"]
            }
        )

        return token

    except Exception as e:
        # Log the error with appropriate context
        current_app.logger.error(f"Token generation failed: {str(e)}",
                                exc_info=True,
                                extra={
                                    "user_id": user_id,
                                    "role": role
                                })

        # Track failed token generation
        metrics.info('token_generation_error', 1)

        # Log security event for audit trail
        log_security_event(
            event_type='token_generation_failed',
            description=f"Failed to generate token for user {user_id}",
            severity='error',
            user_id=user_id,
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )

        raise RuntimeError(f"Failed to generate token: {str(e)}")


@cache.memoize(timeout=300)
def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token with caching for performance.

    This function validates a JWT token's signature and expiration,
    returning the decoded payload if valid. Results are cached to
    reduce cryptographic operations. The function also includes security
    checks for token reuse and tampering.

    Args:
        token: The JWT token string to verify

    Returns:
        Optional[Dict[str, Any]]: The decoded token payload if valid, None otherwise

    Examples:
        >>> payload = verify_token("eyJhbGciOiJIUzI1...")
        >>> if payload:
        ...     user_id = payload.get("sub")
    """
    if not token:
        return None

    try:
        # Get the secret key from configuration
        secret_key = current_app.config.get('JWT_SECRET_KEY', current_app.config['SECRET_KEY'])

        # Decode and verify the token
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[TOKEN_ALGORITHM]
        )

        # Check if token has required fields
        if 'sub' not in payload or 'exp' not in payload:
            raise jwt.InvalidTokenError("Token missing required claims")

        # Additional security check - verify IP address if present in token
        if 'ip' in payload and hasattr(request, 'remote_addr') and payload['ip'] != request.remote_addr:
            # This could indicate token theft
            log_security_event(
                event_type='token_ip_mismatch',
                description="Token used from different IP than issued to",
                severity='warning',
                user_id=payload.get('sub'),
                ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None,
                details={
                    "token_ip": payload['ip'],
                    "request_ip": request.remote_addr
                }
            )
            raise jwt.InvalidTokenError("Token IP mismatch")

        # Track successful verification
        metrics.info('token_verification_success', 1)

        # Log successful verification at debug level
        current_app.logger.debug(f"Token verified for user {payload.get('sub')}")

        return payload

    except jwt.ExpiredSignatureError:
        # Track expired token metrics
        metrics.info('token_verification_expired', 1)
        current_app.logger.info('Expired token detected')
        return None

    except jwt.InvalidTokenError as e:
        # Track invalid token metrics
        metrics.info('token_verification_invalid', 1)

        # Log the specific error at warning level
        current_app.logger.warning(f"Invalid token: {str(e)}")

        # Log security event for potential token tampering
        log_security_event(
            event_type='invalid_token',
            description=f"Invalid token detected: {str(e)}",
            severity='warning',
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )

        return None
    except Exception as e:
        # Catch any other exceptions
        metrics.info('token_verification_error', 1)
        current_app.logger.error(f"Token verification failed with unexpected error: {str(e)}", exc_info=True)
        return None


def anonymous_required(f: T) -> T:
    """
    Decorator that restricts access to routes for authenticated users.

    This decorator ensures that authenticated users cannot access routes
    intended for anonymous users (such as login and registration pages),
    redirecting them to the dashboard if they try.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that checks for authenticated status
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get('user_id'):
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return cast(T, decorated_function)


def login_required(f: T) -> T:
    """
    Decorator to restrict route access to authenticated users.

    This decorator checks that a valid user session exists, redirecting
    to the login page if not. It also implements session timeout for
    security, requiring re-authentication after a period of inactivity.

    Args:
        f: The route handler function to decorate

    Returns:
        Callable: A decorated function that enforces authentication

    Examples:
        >>> @app.route('/profile')
        >>> @login_required
        >>> def profile():
        ...     return "Authenticated user's profile"
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check if user is logged in
        if 'user_id' not in session:
            # Log unauthorized access attempt
            current_app.logger.warning(
                'Unauthenticated access attempt',
                extra={
                    'url': request.path,
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else None
                }
            )

            metrics.info('auth_unauthenticated_access_total', 1)
            next_url = request.full_path if request.method == 'GET' else None
            flash('You need to log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=next_url))

        # Check for session timeout
        if 'last_active' in session:
            last_active = datetime.fromisoformat(session['last_active'])
            timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', SESSION_TIMEOUT_MINUTES)

            if datetime.utcnow() - last_active > timedelta(minutes=timeout_minutes):
                # Log session timeout
                log_security_event(
                    event_type='session_timeout',
                    description=f"Session timed out for user {session['user_id']}",
                    severity='info',
                    user_id=session['user_id'],
                    ip_address=request.remote_addr
                )

                metrics.info('auth_session_timeout_total', 1)
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('auth.login', next=request.full_path))

        # Update last active timestamp
        session['last_active'] = datetime.utcnow().isoformat()

        # Set user information in g for convenient access in route handlers
        if not hasattr(g, 'user') or not g.user:
            try:
                g.user = User.query.get(session['user_id'])
            except Exception as e:
                current_app.logger.error(f"Error fetching user: {str(e)}")
                session.clear()
                flash('An error occurred with your session. Please log in again.', 'danger')
                return redirect(url_for('auth.login'))

        return f(*args, **kwargs)

    return cast(T, decorated_function)


def require_role(role: str) -> Callable[[T], T]:
    """
    Decorator to restrict route access to users with a specific role.

    This decorator checks that the authenticated user has the required role,
    aborting with a 403 Forbidden response if the user lacks sufficient
    permissions.

    Args:
        role: The role string required to access the route

    Returns:
        Decorator function that enforces role-based authorization

    Examples:
        >>> @app.route('/admin-only')
        >>> @require_role('admin')
        >>> def admin_page():
        ...     return "Admin access granted"
    """
    def decorator(f: T) -> T:
        @wraps(f)
        @login_required
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not g.user or not g.user.has_role(role):
                # Log unauthorized access attempt
                log_security_event(
                    event_type='authorization_failure',
                    description=f"User attempted to access resource requiring role '{role}'",
                    severity='warning',
                    user_id=g.user.id if g.user else None,
                    ip_address=request.remote_addr
                )

                metrics.info('auth_authorization_failure_total', 1, labels={
                    'required_role': role
                })

                flash('You do not have permission to access this resource.', 'danger')
                abort(403)
            return f(*args, **kwargs)
        return cast(T, decorated_function)
    return decorator


def require_permission(permission: str) -> Callable[[T], T]:
    """
    Decorator to restrict route access to users with a specific permission.

    This decorator checks that the authenticated user has the required permission,
    aborting with a 403 Forbidden response if the user lacks sufficient
    permissions.

    Args:
        permission: The permission string required to access the route

    Returns:
        Decorator function that enforces permission-based authorization

    Examples:
        >>> @app.route('/user-management')
        >>> @require_permission('manage:users')
        >>> def manage_users():
        ...     return "User management page"
    """
    def decorator(f: T) -> T:
        @wraps(f)
        @login_required
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not g.user or not g.user.has_permission(permission):
                # Log unauthorized access attempt
                log_security_event(
                    event_type='permission_denied',
                    description=f"User attempted to access resource requiring permission '{permission}'",
                    severity='warning',
                    user_id=g.user.id if g.user else None,
                    ip_address=request.remote_addr
                )

                metrics.info('auth_permission_denied_total', 1, labels={
                    'required_permission': permission
                })

                flash('You do not have permission to access this resource.', 'danger')
                abort(403)
            return f(*args, **kwargs)
        return cast(T, decorated_function)
    return decorator


def rate_limit(limit: str = "5/minute") -> Callable[[T], T]:
    """
    Apply custom rate limiting to routes.

    This function provides a more readable way to apply rate limiting
    to specific routes, helping prevent abuse and brute force attempts.

    Args:
        limit: Rate limit string in the format "number/period"
              (default: "5/minute")

    Returns:
        Callable: A rate limiting decorator that can be applied to route handlers

    Examples:
        >>> @app.route('/sensitive')
        >>> @rate_limit("3/minute")
        >>> def sensitive_operation():
        ...     return "Rate-limited sensitive operation"
    """
    def decorator(f: T) -> T:
        @wraps(f)
        @limiter.limit(limit)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)
        return cast(T, decorated_function)
    return decorator


def require_mfa(f: T) -> T:
    """
    Decorator to enforce multi-factor authentication for sensitive routes.

    This decorator checks that the user has completed MFA verification
    within the current session before allowing access to protected routes.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces MFA verification
    """
    @wraps(f)
    @login_required
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check if MFA is required but not completed in the session
        if current_app.config.get('ENABLE_MFA', False) and not session.get('mfa_verified'):
            # Check if user has MFA set up
            if g.user and g.user.two_factor_enabled:
                # Log MFA enforcement
                log_security_event(
                    event_type='mfa_required',
                    description="MFA verification required for protected resource",
                    severity='info',
                    user_id=g.user.id,
                    ip_address=request.remote_addr
                )

                metrics.info('auth_mfa_enforcement_total', 1)
                return redirect(url_for('auth.verify_mfa', next=request.full_path))

            # If user doesn't have MFA set up but it's required for their role
            if g.user and g.user.role in current_app.config.get('MFA_REQUIRED_ROLES', []):
                flash('Multi-factor authentication setup is required for your role.', 'warning')
                return redirect(url_for('auth.setup_mfa', next=request.full_path))

        return f(*args, **kwargs)
    return cast(T, decorated_function)


def confirm_password(f: T) -> T:
    """
    Decorator for sensitive operations that require password reconfirmation.

    This decorator enforces password reconfirmation for security-critical
    operations even if the user is already authenticated.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces password reconfirmation
    """
    @wraps(f)
    @login_required
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check if password was recently confirmed
        password_confirmed_at = session.get('password_confirmed_at')
        confirmation_ttl = current_app.config.get('PASSWORD_CONFIRM_TTL', 300)  # 5 minutes default

        if not password_confirmed_at or \
           datetime.utcnow() - datetime.fromisoformat(password_confirmed_at) > timedelta(seconds=confirmation_ttl):
            # Store original request path for redirect after confirmation
            session['password_confirm_next'] = request.full_path

            # Log security event
            log_security_event(
                event_type='password_confirmation_required',
                description="Password confirmation required for sensitive operation",
                severity='info',
                user_id=session.get('user_id'),
                ip_address=request.remote_addr
            )

            return redirect(url_for('auth.confirm_password'))

        return f(*args, **kwargs)
    return cast(T, decorated_function)


def sanitize_input(text: Optional[str]) -> str:
    """
    Sanitize user input by removing potentially dangerous characters.

    This function removes HTML tags and other potentially malicious
    characters from user input to prevent XSS and injection attacks.

    Args:
        text: The input string to sanitize

    Returns:
        str: The sanitized string

    Examples:
        >>> sanitize_input("<script>alert('XSS')</script>")
        "alertXSS"
        >>> sanitize_input("Normal text")
        "Normal text"
    """
    if not text or not isinstance(text, str):
        return ""

    # Remove HTML tags and dangerous characters
    sanitized = re.sub(r'<[^>]*>', '', text)
    sanitized = re.sub(r'[<>\'"`;()]', '', sanitized)

    return sanitized.strip()


def is_safe_redirect_url(url: Optional[str]) -> bool:
    """
    Check if a URL is safe to redirect to.

    This function prevents open redirect vulnerabilities by ensuring
    redirect URLs are either relative or point to trusted domains.

    Args:
        url: The URL to validate

    Returns:
        bool: True if the URL is safe for redirection, False otherwise
    """
    if not url:
        return False

    # Allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return True

    # Get list of allowed domains from config
    allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])
    current_domain = request.host

    if current_domain:
        allowed_domains.append(current_domain)

    try:
        # Parse the URL
        parsed = urlparse(url)

        # Check if the domain is in the allowed list
        return parsed.netloc in allowed_domains
    except Exception:
        return False


def is_valid_ip(ip_address: Optional[str]) -> bool:
    """
    Check if a string is a valid IP address.

    This function validates IPv4 and IPv6 addresses.

    Args:
        ip_address: The IP address string to validate

    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    if not ip_address:
        return False

    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    This function creates a secure token of specified length using
    the secrets module.

    Args:
        length: The length of the token to generate (default: 32)

    Returns:
        str: A cryptographically secure token string
    """
    if length < 16:
        current_app.logger.warning("Token length less than 16 is not recommended")

    # Generate a secure token with specified length
    return secrets.token_urlsafe(length)


def generate_password(length: int = 16) -> str:
    """
    Generate a strong random password.

    This function creates a password with mixed character types
    that meets the system's password requirements.

    Args:
        length: The length of the password to generate (default: 16)

    Returns:
        str: A secure random password
    """
    if length < PASSWORD_MIN_LENGTH:
        length = PASSWORD_MIN_LENGTH

    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Ensure at least one of each character type
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]

    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle the password characters
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


def regenerate_session() -> None:
    """
    Regenerate the session ID to prevent session fixation attacks.

    This function preserves the user's session data while creating
    a new session ID, which helps prevent session fixation attacks.
    """
    if 'user_id' in session:
        # Store the current session data
        user_id = session.get('user_id')
        role = session.get('role')
        last_active = datetime.utcnow().isoformat()

        # Clear the session to get a new session ID
        session.clear()

        # Restore the session data
        session['user_id'] = user_id
        session['role'] = role
        session['last_active'] = last_active
        session['session_regenerated_at'] = datetime.utcnow().isoformat()

        # Mark the session as modified
        session.modified = True


def audit_security_event(event_type: str, description: str, severity: str = "info") -> None:
    """
    Record a security-related event for auditing purposes.

    This function logs security events to both the application log
    and the security audit log for compliance and monitoring.

    Args:
        event_type: The type of security event
        description: A description of the event
        severity: The severity level of the event (default: "info")
    """
    user_id = session.get('user_id') if hasattr(session, 'get') else None
    ip_address = request.remote_addr if hasattr(request, 'remote_addr') else None

    # Log to security event system
    log_security_event(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        ip_address=ip_address
    )

    # Also log to application logger for immediate visibility
    log_message = f"Security event - {event_type}: {description}"
    if severity == "critical":
        current_app.logger.critical(log_message)
    elif severity == "error":
        current_app.logger.error(log_message)
    elif severity == "warning":
        current_app.logger.warning(log_message)
    else:
        current_app.logger.info(log_message)


def update_last_activity() -> None:
    """
    Update the user's last activity timestamp.

    This function updates both the user's session and database record
    to track their last activity time for monitoring and timeout purposes.
    """
    # Update session timestamp
    if 'user_id' in session:
        session['last_active'] = datetime.utcnow().isoformat()
        session.modified = True

        # Update database record periodically (not on every request)
        update_interval = current_app.config.get('USER_ACTIVITY_UPDATE_INTERVAL', 300)  # 5 minutes default
        last_db_update = session.get('last_db_activity_update')

        if not last_db_update or \
           datetime.utcnow() - datetime.fromisoformat(last_db_update) > timedelta(seconds=update_interval):
            try:
                # Update the user record
                user = User.query.get(session['user_id'])
                if user:
                    user.last_active = datetime.utcnow()
                    db.session.commit()

                    # Update session timestamp for DB updates
                    session['last_db_activity_update'] = datetime.utcnow().isoformat()
                    session.modified = True
            except Exception as e:
                current_app.logger.error(f"Failed to update user last activity: {str(e)}")
                # Don't raise the exception - this is a non-critical operation


def check_bruteforce_attempts(username: str, increment: bool = True) -> Tuple[bool, int]:
    """
    Check for potential brute force attacks against a user account.

    This function tracks login attempts for a user and determines if
    the account should be temporarily locked due to too many failures.

    Args:
        username: The username or email being attempted
        increment: Whether to increment the failed attempt counter (default: True)

    Returns:
        tuple: (is_locked, attempts_remaining)
    """
    redis_client = current_app.extensions.get('redis')
    max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_time = current_app.config.get('ACCOUNT_LOCKOUT_MINUTES', 15)

    if not redis_client:
        current_app.logger.warning("Redis not available for brute force protection")
        return False, max_attempts

    # Keys for tracking
    attempt_key = f"login:attempts:{username.lower()}"
    lockout_key = f"login:lockout:{username.lower()}"

    # Check if account is locked
    if redis_client.exists(lockout_key):
        # Get the remaining lockout time
        ttl = redis_client.ttl(lockout_key)
        lockout_minutes = max(1, ttl // 60)

        # Log and track metrics
        metrics.info('auth_account_locked', 1, labels={"username": username})
        current_app.logger.warning(f"Account locked: {username} (for {lockout_minutes} more minutes)")

        # Log security event
        log_security_event(
            event_type='account_locked',
            description=f"Login attempt on locked account: {username}",
            severity='warning',
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )

        return True, 0

    # Get current attempt count
    attempts = int(redis_client.get(attempt_key) or 0)

    if increment:
        # Increment attempt counter
        attempts = redis_client.incr(attempt_key)

        # Set expiration if first attempt
        if attempts == 1:
            redis_client.expire(attempt_key, 24 * 60 * 60)  # 24 hours

    # Check if we need to lock the account
    if attempts >= max_attempts:
        # Lock the account
        redis_client.setex(lockout_key, lockout_time * 60, 1)

        # Reset attempt counter
        redis_client.delete(attempt_key)

        # Log and track metrics
        metrics.info('auth_account_lockout', 1, labels={"username": username})
        current_app.logger.warning(f"Account locked due to too many failed attempts: {username}")

        # Log security event
        log_security_event(
            event_type='account_lockout',
            description=f"Account locked due to excessive failed login attempts: {username}",
            severity='warning',
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )

        return True, 0

    # Return false (not locked) and remaining attempts
    return False, max_attempts - attempts


def reset_login_attempts(username: str) -> None:
    """
    Reset the failed login attempt counter for a user.

    This function is called after a successful login to clear
    any previous failed attempt records.

    Args:
        username: The username or email to reset attempts for
    """
    redis_client = current_app.extensions.get('redis')

    if not redis_client:
        return

    attempt_key = f"login:attempts:{username.lower()}"
    lockout_key = f"login:lockout:{username.lower()}"

    # Remove both keys to reset attempts and unlock account
    redis_client.delete(attempt_key, lockout_key)


def record_login_success(user: User) -> None:
    """
    Record a successful login for security auditing.

    This function updates the user record with login statistics
    and creates an audit entry for the successful login.

    Args:
        user: The User model instance that logged in
    """
    try:
        # Update user login statistics
        user.login_count = (user.login_count or 0) + 1
        user.last_login = datetime.utcnow()
        user.failed_login_count = 0
        user.last_failed_login = None
        db.session.commit()

        # Create session record
        user_session = UserSession(
            user_id=user.id,
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None,
            user_agent=request.user_agent.string if hasattr(request, 'user_agent') else None,
            client_type=UserSession.SESSION_CLIENT_TYPE_WEB
        )
        db.session.add(user_session)
        db.session.commit()

        # Store session ID in user session
        if user_session.id:
            session['session_id'] = user_session.id

        # Record metrics
        metrics.info('auth_login_success', 1, labels={
            "user_id": user.id,
            "username": user.username
        })

        # Log security event
        log_security_event(
            event_type='login_success',
            description=f"Successful login for user {user.username}",
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )
    except Exception as e:
        current_app.logger.error(f"Failed to record successful login: {str(e)}")


def record_login_failure(username: str, reason: str = "Invalid credentials") -> None:
    """
    Record a failed login attempt for security auditing.

    This function updates user records if the user exists and creates
    an audit entry for the failed login attempt.

    Args:
        username: The username or email that failed to login
        reason: The reason for the login failure
    """
    # Try to find the user
    user = User.query.filter((User.username == username) | (User.email == username)).first()

    try:
        if user:
            # Update user's failed login statistics
            user.failed_login_count = (user.failed_login_count or 0) + 1
            user.last_failed_login = datetime.utcnow()
            db.session.commit()

        # Record metrics
        metrics.info('auth_login_failure', 1, labels={
            "reason": reason,
            "user_exists": bool(user)
        })

        # Log security event
        log_security_event(
            event_type='login_failure',
            description=f"Failed login attempt for username '{username}': {reason}",
            severity='warning',
            user_id=user.id if user else None,
            ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
        )
    except Exception as e:
        current_app.logger.error(f"Failed to record login failure: {str(e)}")


def get_client_info() -> Dict[str, str]:
    """
    Get information about the client for security logging.

    This function collects client information from the request
    for use in security monitoring and audit logging.

    Returns:
        dict: Dictionary of client information
    """
    client_info = {
        'ip_address': request.remote_addr if hasattr(request, 'remote_addr') else 'unknown',
        'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else 'unknown',
        'method': request.method if hasattr(request, 'method') else 'unknown',
        'path': request.path if hasattr(request, 'path') else 'unknown',
    }

    # Add referrer if available
    if hasattr(request, 'referrer') and request.referrer:
        client_info['referrer'] = request.referrer

    return client_info
