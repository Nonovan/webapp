import base64
import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from extensions import db, metrics
from extensions import get_redis_client
from .cs_constants import SECURITY_CONFIG
from core.utils import log_error, log_warning, log_info


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

def verify_token(token: str, secret_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token and return payload if valid.

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

        # Get audience from app config if available
        audience = None
        if has_app_context():
            audience = current_app.config.get('JWT_AUDIENCE')

        # Verify token with standard security options
        payload = jwt.decode(
            token,
            key,
            algorithms=['HS256'],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'verify_aud': audience is not None,
            },
            audience=audience
        )

        # Additional validation
        if 'exp' not in payload:
            log_warning('Token missing expiration claim')
            return None

        if 'sub' not in payload:
            log_warning('Token missing subject claim')
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


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password strength against security requirements.

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
    sequential_patterns = ['123456', 'abcdef', 'qwerty', 'password']
    if any(pattern in password.lower() for pattern in sequential_patterns):
        failed_requirements.append("Password contains common sequential patterns")

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

    return len(failed_requirements) == 0, failed_requirements


def generate_secure_token(length: int = 64, url_safe: bool = True) -> str:
    """
    Generate a cryptographically secure random token.

    Creates a secure random token suitable for authentication,
    session management, or CSRF protection.

    Args:
        length: Length of the token in bytes (default: 64)
        url_safe: Whether to use URL-safe encoding (default: True)

    Returns:
        str: Base64-encoded secure token
    """
    # Generate secure random bytes
    token_bytes = os.urandom(length)

    # Convert to base64 encoding
    if url_safe:
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
    else:
        token = base64.b64encode(token_bytes).decode('utf-8')

    return token


def regenerate_session() -> bool:
    """
    Regenerate the session to prevent session fixation attacks.

    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks.

    Returns:
        bool: True if session was regenerated, False if there was an error
    """
    try:
        # Save the important session values
        saved_data = {}
        keys_to_preserve = [
            'user_id', 'username', 'role', 'last_active',
            'csrf_token', 'mfa_verified', 'permissions'
        ]

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

        return True
    except Exception as e:
        log_error(f"Failed to regenerate session: {e}")
        return False


def invalidate_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a specific user.

    This function searches for and removes all active sessions belonging to
    the specified user, providing a way to force logout across all devices.

    Args:
        user_id: User ID whose sessions should be invalidated

    Returns:
        bool: True if sessions were invalidated, False otherwise
    """
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

            for key in keys:
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
            for i in range(0, len(sessions), batch_size):
                batch = sessions[i:i + batch_size]
                redis_client.delete(*batch)

            log_info(f"Invalidated {len(sessions)} sessions for user ID {user_id}")

            # Track metric
            metrics.increment('security.sessions_invalidated', len(sessions))
        else:
            log_info(f"No active sessions found for user ID {user_id}")

        return True
    except Exception as e:
        log_error(f"Failed to invalidate user sessions: {e}")
        return False
