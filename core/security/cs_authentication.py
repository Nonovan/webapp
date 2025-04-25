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
from .cs_audit import log_security_event
from core.utils import log_error, log_warning, log_info, log_debug

# Type definitions
TokenPayload = Dict[str, Any]
ValidationResult = Tuple[bool, List[str]]


def is_valid_ip(ip: str) -> bool:
    """
    Validate if the given string is a valid IP address.

    Args:
        ip: The IP address string to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


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


def validate_password_strength(password: str) -> ValidationResult:
    """
    Validate password strength against security requirements.

    This function checks passwords against multiple security criteria including
    length, character types, common patterns, dictionary words, and context-specific
    terms to ensure strong password selection.

    Args:
        password: Password to validate

    Returns:
        Tuple of (bool, List[str]): Success flag and list of failed requirements
    """
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 12)
    failed_requirements = []

    # Check length
    if len(password) < min_length:
        failed_requirements.append(f"Password must be at least {min_length} characters long")

    # Check for lowercase
    if not re.search(r'[a-z]', password):
        failed_requirements.append("Password must include lowercase letters")

    # Check for uppercase
    if not re.search(r'[A-Z]', password):
        failed_requirements.append("Password must include uppercase letters")

    # Check for numbers
    if not re.search(r'[0-9]', password):
        failed_requirements.append("Password must include numbers")

    # Check for special characters
    if not re.search(r'[^a-zA-Z0-9]', password):
        failed_requirements.append("Password must include special characters")

    # Check for common sequential patterns
    sequential_patterns = ['123456', 'abcdef', 'qwerty', 'password', 'admin', '123123']
    if any(pattern in password.lower() for pattern in sequential_patterns):
        failed_requirements.append("Password contains common sequential patterns")

    # Check for repeating characters (3+ in a row)
    if re.search(r'(.)\1{2,}', password):
        failed_requirements.append("Password contains repeating characters")

    # Check for common passwords if available
    if has_app_context() and current_app.config.get('COMMON_PASSWORDS_FILE'):
        common_passwords_file = current_app.config.get('COMMON_PASSWORDS_FILE')
        if os.path.exists(common_passwords_file):
            try:
                # Use hash to avoid loading the entire file into memory
                password_hash = hashlib.sha256(password.lower().encode()).hexdigest()

                with open(common_passwords_file, 'r') as f:
                    for line in f:
                        line_hash = line.strip()
                        if line_hash == password_hash:
                            failed_requirements.append("Password is too common or has been compromised")
                            break
            except Exception as e:
                log_error(f"Error checking common passwords: {e}")

    # Check for common password patterns based on app name or domain
    if has_app_context():
        app_name = current_app.config.get('APP_NAME', '').lower()
        domain = current_app.config.get('APP_DOMAIN', '').lower()

        if app_name and app_name in password.lower():
            failed_requirements.append("Password contains the application name")

        if domain and domain in password.lower():
            failed_requirements.append("Password contains the domain name")

    is_valid = len(failed_requirements) == 0

    # Track metrics
    if is_valid:
        metrics.increment('security.password_validation_success')
    else:
        metrics.increment('security.password_validation_failure')

    return is_valid, failed_requirements


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


def require_mfa(view_func):
    """
    Decorator to enforce MFA verification for sensitive operations.

    Usage:
        @require_mfa
        def sensitive_function():
            # Function code here

    Returns:
        Decorated function that checks MFA status before execution
    """
    from functools import wraps

    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if not has_request_context():
            log_warning("MFA check outside request context")
            return {"error": "Authentication required"}, 401

        # Check if MFA is verified
        mfa_verified = session.get('mfa_verified', False)
        mfa_timestamp = session.get('mfa_verified_at')

        # Check if MFA has expired
        if mfa_verified and mfa_timestamp:
            try:
                # Parse the timestamp
                verified_at = datetime.fromisoformat(mfa_timestamp)
                # Get MFA timeout from config
                mfa_timeout = SECURITY_CONFIG.get('MFA_TIMEOUT', 24 * 3600)  # Default: 24 hours
                # Check if MFA has expired
                if datetime.now(timezone.utc) - verified_at > timedelta(seconds=mfa_timeout):
                    mfa_verified = False
            except (ValueError, TypeError):
                mfa_verified = False

        if not mfa_verified:
            # Track metric
            metrics.increment('security.mfa_required')

            # User needs to verify MFA
            if has_app_context() and current_app.config.get('API_REQUEST', False):
                return {"error": "MFA verification required"}, 403
            else:
                from flask import redirect, url_for
                return redirect(url_for('auth.mfa_verify', next=request.path))

        return view_func(*args, **kwargs)

    return decorated_function
