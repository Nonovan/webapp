"""
Authentication utilities for Cloud Infrastructure Platform.

This module provides comprehensive authentication functionality including
token verification, password validation, secure token generation, and
session management to ensure secure user authentication and access control.
"""

import base64
import hashlib
import os
import re
import uuid
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address, ip_network
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from extensions import db, metrics
from extensions import get_redis_client
from .cs_constants import SECURITY_CONFIG
from .cs_audit import log_security_event, log_error, log_warning, log_info, log_debug

# Type definitions
TokenPayload = Dict[str, Any]
ValidationResult = Tuple[bool, List[str]]


def _create_validation_compatibility_wrapper(func_name: str):
    """
    Creates a backward compatibility wrapper that redirects to cs_validation functions.

    Args:
        func_name: The name of the function to import from cs_validation

    Returns:
        A function that wraps the corresponding function from cs_validation
    """
    def wrapper(*args, **kwargs):
        import warnings
        warnings.warn(
            f"The function {func_name}() has moved to cs_validation.py. "
            "Import from core.security.cs_validation instead.",
            DeprecationWarning,
            stacklevel=2
        )
        # Dynamically import the specific function from cs_validation
        from importlib import import_module
        validation_module = import_module('.cs_validation', package='core.security')
        actual_func = getattr(validation_module, func_name)

        # Call the imported function with the provided arguments
        return actual_func(*args, **kwargs)

    return wrapper

# Create backward compatibility functions
is_valid_ip = _create_validation_compatibility_wrapper('is_valid_ip')
is_valid_domain = _create_validation_compatibility_wrapper('is_valid_domain')
is_valid_hash = _create_validation_compatibility_wrapper('is_valid_hash')
is_valid_username = _create_validation_compatibility_wrapper('is_valid_username')
validate_password_strength = _create_validation_compatibility_wrapper('validate_password_strength')
validate_path = _create_validation_compatibility_wrapper('validate_path')
validate_url = _create_validation_compatibility_wrapper('validate_url')


def verify_token(token: str, secret_key: Optional[str] = None) -> Optional[TokenPayload]:
    """
    Verify JWT token and return payload if valid.

    This function validates a JWT token against various security criteria including
    signature verification, expiration time, audience validation, and required claims.

    Args:
        token: JWT token string
        secret_key: Secret key for JWT verification (uses app secret if None)

    Returns:
        Dict or None: Token payload if valid, None if invalid
    """
    if not token:
        return None

    try:
        import jwt

        # Use provided secret or fall back to app secret
        key = secret_key
        if key is None and has_app_context():
            key = current_app.config.get('JWT_SECRET_KEY')

        if not key:
            log_error('JWT_SECRET_KEY not configured')
            return None

        # Get audience and algorithm from app config if available
        audience = None
        algorithm = 'HS256'
        if has_app_context():
            audience = current_app.config.get('JWT_AUDIENCE')
            algorithm = current_app.config.get('JWT_ALGORITHM', algorithm)

        # Verify token with standard security options
        payload = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'verify_aud': audience is not None,
                'require': ['exp', 'iat', 'sub']  # Require these claims
            },
            audience=audience
        )

        # Additional validation for required claims
        required_claims = ['exp', 'sub']
        for claim in required_claims:
            if claim not in payload:
                log_warning(f'Token missing required claim: {claim}')
                metrics.increment('security.token_verification_invalid')
                return None

        # Track success metric
        metrics.increment('security.token_verification_success')
        return payload

    except jwt.ExpiredSignatureError:
        metrics.increment('security.token_verification_expired')
        log_warning('Token expired')
        return None
    except jwt.InvalidTokenError as e:
        metrics.increment('security.token_verification_invalid')
        log_warning(f'Invalid token: {e}')
        return None
    except ImportError:
        log_error('JWT library not available')
        return None
    except Exception as e:
        metrics.increment('security.token_verification_error')
        log_error(f'Error verifying token: {e}')
        return None


def generate_secure_token(length: int = 64, url_safe: bool = True) -> str:
    """
    Generate a cryptographically secure random token.

    Creates a secure random token suitable for authentication,
    session management, or CSRF protection using strong cryptographic
    randomness.

    Args:
        length: Length of the token in bytes (default: 64)
        url_safe: Whether to use URL-safe encoding (default: True)

    Returns:
        str: Base64-encoded secure token
    """
    if length < 16:  # Ensure minimum security
        log_warning(f"Token length {length} is too short, using minimum of 16 bytes")
        length = 16

    # Generate secure random bytes
    try:
        token_bytes = os.urandom(length)

        # Convert to base64 encoding
        if url_safe:
            token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        else:
            token = base64.b64encode(token_bytes).decode('utf-8')

        # Track metric
        metrics.increment('security.token_generated')
        return token
    except Exception as e:
        log_error(f"Error generating secure token: {e}")
        # Fallback mechanism (less secure but better than failing)
        import uuid
        return str(uuid.uuid4()) + str(uuid.uuid4())


def regenerate_session() -> bool:
    """
    Regenerate the session to prevent session fixation attacks.

    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks by
    rotating session identifiers after authentication events.

    Returns:
        bool: True if session was regenerated, False if there was an error
    """
    if not has_request_context():
        log_warning("Cannot regenerate session outside request context")
        return False

    try:
        # Save the important session values
        saved_data = {}
        keys_to_preserve = [
            'user_id', 'username', 'role', 'last_active',
            'csrf_token', 'mfa_verified', 'permissions'
        ]

        # Add custom preserve keys if configured
        if has_app_context():
            custom_keys = current_app.config.get('SESSION_PRESERVE_KEYS', [])
            keys_to_preserve.extend(custom_keys)

        for key in keys_to_preserve:
            if key in session:
                saved_data[key] = session[key]

        # Generate a new session ID
        session_id = str(uuid.uuid4())

        # Clear the current session
        session.clear()

        # Set the new session ID
        session['session_id'] = session_id

        # Restore the saved values
        for key, value in saved_data.items():
            session[key] = value

        # Update last active time
        session['last_active'] = datetime.now(timezone.utc).isoformat()

        # Generate new CSRF token if the app supports it
        if has_app_context() and hasattr(current_app, 'csrf'):
            session['csrf_token'] = current_app.csrf.generate_csrf_token()

        # Log the event
        user_id = saved_data.get('user_id', 'unknown')
        log_info(f"Session regenerated for user_id={user_id}")

        # Track metric
        metrics.increment('security.session_regenerated')

        # Log security event
        try:
            log_security_event(
                event_type='session_regenerated',
                description=f"Session regenerated",
                severity='info',
                user_id=saved_data.get('user_id'),
                ip_address=request.remote_addr if request else None
            )
        except Exception as e:
            log_warning(f"Failed to log security event for session regeneration: {e}")

        return True
    except Exception as e:
        log_error(f"Failed to regenerate session: {e}")
        metrics.increment('security.session_regeneration_failed')
        return False


def invalidate_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a specific user.

    This function searches for and removes all active sessions belonging to
    the specified user, providing a way to force logout across all devices
    for security purposes such as password changes or suspicious activity.

    Args:
        user_id: User ID whose sessions should be invalidated

    Returns:
        bool: True if sessions were invalidated, False otherwise
    """
    if not user_id:
        log_warning("Cannot invalidate sessions without user ID")
        return False

    try:
        # Get Redis client
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, unable to invalidate sessions")
            return False

        # Find all sessions for this user
        session_pattern = "session:*"
        sessions = []

        # Use cursor-based iteration to handle large sets of keys
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match=session_pattern, count=100)

            # Convert byte keys to strings if needed
            string_keys = [k.decode('utf-8') if isinstance(k, bytes) else k for k in keys]

            for key in string_keys:
                try:
                    session_data = redis_client.get(key)
                    if session_data:
                        # Check both integer and string formats to be safe
                        data_str = session_data.decode('utf-8')
                        if (f'"user_id":{user_id}' in data_str or
                            f'"user_id": {user_id}' in data_str or
                            f'"user_id":"{user_id}"' in data_str):
                            sessions.append(key)
                except Exception as e:
                    log_error(f"Error processing session key {key}: {e}")

            # Exit when we've scanned all keys
            if cursor == 0:
                break

        # Delete the sessions in batches to avoid timeout issues
        if sessions:
            batch_size = 100
            deleted_count = 0

            for i in range(0, len(sessions), batch_size):
                batch = sessions[i:i + batch_size]
                result = redis_client.delete(*batch)
                deleted_count += result if result else 0

            log_info(f"Invalidated {deleted_count} sessions for user ID {user_id}")

            # Track metric
            metrics.increment('security.sessions_invalidated', deleted_count)

            # Log security event
            try:
                log_security_event(
                    event_type='sessions_invalidated',
                    description=f"Invalidated {deleted_count} sessions for user ID {user_id}",
                    severity='info',
                    user_id=user_id
                )
            except Exception as e:
                log_warning(f"Failed to log security event for session invalidation: {e}")

        else:
            log_info(f"No active sessions found for user ID {user_id}")

        return True
    except Exception as e:
        log_error(f"Failed to invalidate user sessions: {e}")
        metrics.increment('security.session_invalidation_failed')
        return False


def is_ip_in_whitelist(ip_str: str, whitelist: List[str]) -> bool:
    """
    Check if an IP address is in the whitelist.

    Args:
        ip_str: IP address to check
        whitelist: List of IP addresses or CIDR ranges

    Returns:
        bool: True if IP is in whitelist, False otherwise
    """
    if not ip_str or not whitelist:
        return False

    try:
        # Convert string IP to IP address object
        check_ip = ip_address(ip_str)

        # Check against each whitelist entry
        for entry in whitelist:
            try:
                if '/' in entry:  # CIDR notation
                    if check_ip in ip_network(entry):
                        return True
                else:  # Single IP
                    if check_ip == ip_address(entry):
                        return True
            except ValueError:
                continue

        return False
    except ValueError:
        log_warning(f"Invalid IP address format: {ip_str}")
        return False


def get_client_ip() -> Optional[str]:
    """
    Get the client's IP address from the request.

    This function handles proxies and X-Forwarded-For headers securely.

    Returns:
        str or None: Client IP address or None if not available
    """
    if not has_request_context():
        return None

    # Check for X-Forwarded-For header (only trust if configured)
    trusted_proxies = []
    if has_app_context():
        trusted_proxies = current_app.config.get('TRUSTED_PROXIES', [])

    if trusted_proxies and request.remote_addr in trusted_proxies:
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Get the leftmost IP (client IP) from the chain
            return forwarded_for.split(',')[0].strip()

    # Fall back to remote_addr
    return request.remote_addr


def require_mfa(view_func=None, *, redirect_endpoint: str = 'auth.mfa_verify', exempt_roles: List[str] = None):
    """
    Decorator to enforce MFA verification for sensitive operations.

    This decorator checks if the current user has completed Multi-Factor Authentication
    before allowing access to the protected function. If MFA is not verified or has expired,
    the user is redirected to the MFA verification page or receives a structured API error.

    Args:
        view_func: The function to decorate
        redirect_endpoint: The endpoint to redirect to for MFA verification
        exempt_roles: List of roles that are exempt from MFA requirement

    Returns:
        Decorated function that checks MFA status before execution

    Example:
        @require_mfa
        def sensitive_function():
            # Function code here

        # With parameters
        @require_mfa(redirect_endpoint='auth.api_mfa_verify', exempt_roles=['system'])
        def sensitive_api_endpoint():
            # Function code here
    """
    # Handle direct decoration (@require_mfa) vs parameterized (@require_mfa(...))
    def decorator(view_func):
        from functools import wraps
        from .cs_session import is_mfa_verified, mark_requiring_mfa
        from .cs_authorization import _should_require_mfa

        @wraps(view_func)
        def decorated_function(*args, **kwargs):
            # Check request context
            if not has_request_context():
                log_warning("MFA check outside request context")
                return {"error": "Authentication required", "code": "AUTH_REQUIRED"}, 401

            # Skip MFA check if user role is exempt
            if exempt_roles and _should_require_mfa(exempt_roles) is False:
                return view_func(*args, **kwargs)

            # Check if MFA is globally disabled
            if has_app_context():
                mfa_enabled = current_app.config.get('MFA_ENABLED',
                              SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', True))
                if not mfa_enabled:
                    return view_func(*args, **kwargs)

            # Check if MFA is verified using the session utility
            if not is_mfa_verified():
                # Mark session as requiring MFA
                mark_requiring_mfa()

                # Track metric
                metrics.increment('security.mfa_required')

                # Log security event
                user_id = None
                if hasattr(g, 'user_id'):
                    user_id = g.user_id
                elif 'user_id' in session:
                    user_id = session.get('user_id')

                try:
                    log_security_event(
                        event_type='mfa_required',
                        description="MFA verification required for sensitive operation",
                        severity='info',
                        user_id=user_id,
                        ip_address=request.remote_addr,
                        details={
                            'endpoint': request.endpoint,
                            'path': request.path,
                            'method': request.method
                        }
                    )
                except Exception as e:
                    log_warning(f"Failed to log MFA requirement: {e}")

                # Handle API requests differently from browser requests
                is_api = _is_api_request()
                if is_api:
                    return {
                        "error": "MFA verification required",
                        "code": "MFA_REQUIRED",
                        "message": "Multi-factor authentication is required for this operation."
                    }, 403
                else:
                    # For browser requests, redirect to MFA verification
                    from flask import redirect, url_for, flash

                    # Show a flash message if supported
                    try:
                        flash('Please complete two-factor authentication to continue.', 'warning')
                    except RuntimeError:
                        # Flash not available or no request context
                        pass

                    # Ensure we can return to the original page
                    next_url = request.path
                    query_string = request.query_string.decode('utf-8')
                    if query_string:
                        next_url = f"{next_url}?{query_string}"

                    return redirect(url_for(redirect_endpoint, next=next_url))

            return view_func(*args, **kwargs)

        return decorated_function

    # Handle both @require_mfa and @require_mfa(...) syntax
    if view_func:
        return decorator(view_func)
    return decorator


def _is_api_request() -> bool:
    """
    Determine if the current request is an API request.

    Returns:
        bool: True if the request is an API request
    """
    if not has_request_context():
        return False

    # Check if explicitly marked as API request
    if has_app_context() and current_app.config.get('API_REQUEST', False):
        return True

    # Check common API indicators
    if request.path.startswith('/api/'):
        return True

    # Check Accept header for API-like content types
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept or 'application/xml' in accept:
        return True

    # Check if it's an XHR request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True

    return False


def is_safe_redirect_url(url: str, allowed_hosts: List[str] = None) -> bool:
    """
    Check if a URL is safe for redirection to prevent open redirects.

    Args:
        url: URL to check
        allowed_hosts: List of allowed redirect hosts (if None, only relative URLs are allowed)

    Returns:
        True if URL is safe for redirection, False otherwise
    """
    if not url:
        return False

    # Allow relative URLs that start with / and don't include protocol markers
    if url.startswith('/') and not url.startswith('//') and '//' not in url:
        return True

    # For absolute URLs, check against allowed hosts
    if allowed_hosts:
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc in allowed_hosts
        except ValueError:
            return False

    # If no allowed hosts specified, only allow relative URLs
    return False


def is_request_secure() -> bool:
    """
    Determine if the current request is using a secure channel (HTTPS).

    This function checks various request headers and server environment
    settings to determine if the current request uses secure transport.

    Returns:
        bool: True if the request is secure, False otherwise
    """
    if not has_request_context():
        return False

    # Direct check if Flask knows the connection is secure
    if request.is_secure:
        return True

    # Check for secure forwarding headers set by proxies
    forwarded_proto = request.headers.get('X-Forwarded-Proto')
    if forwarded_proto and forwarded_proto.lower() == 'https':
        return True

    # Check for HTTPS in server environment variables
    if request.environ.get('HTTPS', '').lower() == 'on':
        return True

    if request.environ.get('HTTP_X_FORWARDED_SSL', '').lower() == 'on':
        return True

    if request.environ.get('HTTP_X_FORWARDED_SCHEME', '').lower() == 'https':
        return True

    # Check for standard HTTPS port
    server_port = request.environ.get('SERVER_PORT')
    if server_port and server_port == '443':
        return True

    # Check if we're in a test environment with secure transport simulation
    if has_app_context() and (current_app.testing or current_app.debug):
        if current_app.config.get('SIMULATE_HTTPS', False):
            return True

    # Track metrics for insecure requests (if they should be secure)
    if has_app_context() and current_app.config.get('REQUIRE_SECURE', False):
        metrics.increment('security.insecure_request')

    return False


def authenticate_user(username: str, password: str, ip_address: str = None, user_agent: str = None) -> dict:
    """
    Authenticate a user with username and password.

    This function validates user credentials against the database and handles
    security controls like failed login tracking, account lockouts, and audit logging.

    Args:
        username: The username to authenticate
        password: The password to verify
        ip_address: The IP address of the client (optional)
        user_agent: The user agent string of the client (optional)

    Returns:
        dict: Authentication result with keys:
            - success: Boolean indicating if authentication succeeded
            - user_id: ID of the authenticated user if successful
            - user: User object if authentication succeeded
            - token: JWT token if authentication succeeded
            - requires_mfa: Boolean indicating if MFA is required
            - error: Error message if authentication failed
    """
    from flask import current_app, request, has_app_context
    from models.auth import User
    from extensions import db
    from .cs_audit import log_security_event

    # Sanitize input
    from .cs_utils import sanitize_username
    username = sanitize_username(username) if username else ""

    # Default values for tracking
    if not ip_address and has_app_context() and request:
        ip_address = request.remote_addr

    # Attempt to find the user
    user = User.query.filter_by(username=username).first()

    # If user doesn't exist or password is invalid
    if not user or not user.check_password(password):
        # Record the failed attempt if user exists
        if user:
            user.record_failed_login()
            db.session.commit()

        # Log the security event
        log_security_event(
            event_type="login_failed",
            description=f"Failed login attempt for user: {username}",
            severity="warning",
            ip_address=ip_address,
            user_id=user.id if user else None
        )

        return {"success": False, "error": "Invalid username or password"}

    # Check if account is locked
    if hasattr(user, 'is_locked') and user.is_locked():
        log_security_event(
            event_type="login_blocked",
            description=f"Login attempt on locked account: {username}",
            severity="warning",
            ip_address=ip_address,
            user_id=user.id
        )

        return {"success": False, "error": "Account is locked due to too many failed attempts"}

    # Check if account is inactive
    if hasattr(user, 'status') and user.status != 'active':
        log_security_event(
            event_type="login_blocked",
            description=f"Login attempt on inactive account: {username}",
            severity="warning",
            ip_address=ip_address,
            user_id=user.id
        )

        return {"success": False, "error": f"Account is {user.status}"}

    # Authentication successful, record the successful login
    if hasattr(user, 'update_last_login'):
        user.update_last_login()
        user.reset_failed_logins()
        db.session.commit()

    # Generate token for the user
    token = user.generate_token() if hasattr(user, 'generate_token') else None

    # Check if MFA is required
    requires_mfa = False
    if hasattr(user, 'two_factor_enabled'):
        requires_mfa = user.two_factor_enabled

    # Log successful authentication
    log_security_event(
        event_type="login_success",
        description=f"Successful login: {username}",
        severity="info",
        ip_address=ip_address,
        user_id=user.id,
        details={"user_agent": user_agent}
    )

    return {
        "success": True,
        "user_id": user.id,
        "user": user,
        "token": token,
        "requires_mfa": requires_mfa
    }

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP (Time-Based One-Time Password) code.

    This function validates a TOTP code against a secret key following RFC 6238.
    It includes clock drift tolerance to accommodate slight time differences.

    Args:
        secret: The secret key used for TOTP generation
        code: The TOTP code to verify

    Returns:
        bool: True if the code is valid, False otherwise
    """
    import pyotp
    from flask import current_app
    from extensions import metrics

    try:
        # Clean up code (remove spaces and other formatting characters)
        code = ''.join(c for c in code if c.isdigit())

        # Default tolerance (1 means accepting codes from t-30s and t+30s)
        tolerance = current_app.config.get('MFA_VERIFY_TOLERANCE', 1)

        # Create TOTP object
        totp = pyotp.TOTP(secret)

        # Verify code with tolerance for clock drift
        result = totp.verify(code, valid_window=tolerance)

        # Record metrics
        if result:
            metrics.increment('security.mfa_totp_verification_success')
        else:
            metrics.increment('security.mfa_totp_verification_failure')

        return result

    except Exception as e:
        from .cs_audit import log_error
        log_error(f"TOTP verification error: {e}")
        metrics.increment('security.mfa_totp_verification_error')
        return False
