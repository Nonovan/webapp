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


def is_valid_domain(domain: str) -> bool:
    """
    Validate if the given string is a valid domain name.

    This function checks if a string represents a valid domain name
    by verifying it follows DNS naming rules.

    Args:
        domain: The domain name string to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False

    # Domain validation pattern
    # - Allows standard domain names with alphanumeric characters, hyphens, and dots
    # - Requires at least one dot (for TLD)
    # - Domain parts must start and end with alphanumeric characters
    # - Domain parts must be 1-63 characters
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'

    try:
        if re.match(pattern, domain):
            # Track successful validation
            metrics.increment('security.domain_validation_success')
            return True

        # Track validation failure
        metrics.increment('security.domain_validation_failure')
        return False
    except Exception as e:
        log_error(f"Error validating domain: {e}")
        metrics.increment('security.domain_validation_error')
        return False


def is_valid_hash(hash_value: str, algorithm: Optional[str] = None) -> bool:
    """
    Validate if the given string is a valid cryptographic hash.

    This function verifies that a string matches the expected format
    for common cryptographic hash algorithms.

    Args:
        hash_value: The hash string to validate
        algorithm: Optional specific algorithm to validate against
                  (md5, sha1, sha256, sha512)

    Returns:
        bool: True if valid, False otherwise
    """
    if not hash_value:
        return False

    # Define patterns for common hash algorithms
    hash_patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
        'sha384': r'^[a-fA-F0-9]{96}$',
        'sha512': r'^[a-fA-F0-9]{128}$',
        'blake2b': r'^[a-fA-F0-9]{128}$',
        'blake2s': r'^[a-fA-F0-9]{64}$'
    }

    try:
        # If algorithm is specified, check only that pattern
        if algorithm:
            algorithm = algorithm.lower()
            if algorithm not in hash_patterns:
                log_warning(f"Unknown hash algorithm specified: {algorithm}")
                metrics.increment('security.hash_validation_unknown_algorithm')
                return False

            is_valid = bool(re.match(hash_patterns[algorithm], hash_value))

            if is_valid:
                metrics.increment('security.hash_validation_success')
            else:
                metrics.increment('security.hash_validation_failure')

            return is_valid

        # If no algorithm specified, check against all known patterns
        for algo, pattern in hash_patterns.items():
            if re.match(pattern, hash_value):
                metrics.increment('security.hash_validation_success')
                return True

        # No matches found
        metrics.increment('security.hash_validation_failure')
        return False

    except Exception as e:
        log_error(f"Error validating hash: {e}")
        metrics.increment('security.hash_validation_error')
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


def validate_path(path: str, base_dir: Optional[str] = None, allow_absolute: bool = False) -> bool:
    """
    Validate a file path for security concerns like path traversal attacks.

    This function verifies that a file path is secure by checking for directory
    traversal attempts, ensuring proper path format, and optionally verifying
    the path stays within a specified base directory.

    Args:
        path: The file path to validate
        base_dir: Optional base directory that the path must be within
        allow_absolute: Whether to allow absolute paths (default: False)

    Returns:
        bool: True if the path is valid and secure, False otherwise

    Example:
        >>> validate_path("uploads/file.txt")
        True
        >>> validate_path("../etc/passwd")
        False
        >>> validate_path("subdir/file.txt", base_dir="/var/uploads")
        True
    """
    if not path:
        log_warning("Empty path provided for validation")
        metrics.increment('security.path_validation_failure')
        return False

    try:
        # Check for directory traversal attempts
        if '..' in path.split('/') or '..' in path.split('\\'):
            log_warning(f"Path traversal attempt detected: {path}")
            metrics.increment('security.path_traversal_attempt')
            return False

        # Check for tilde (home directory) expansion
        if '~' in path:
            log_warning(f"Home directory expansion attempt detected: {path}")
            metrics.increment('security.path_validation_failure')
            return False

        # Check if path is absolute but not allowed
        if not allow_absolute and (path.startswith('/') or path.startswith('\\')):
            log_warning(f"Absolute path not allowed: {path}")
            metrics.increment('security.path_validation_failure')
            return False

        # If base directory is specified, ensure path stays within it
        if base_dir:
            import os
            # Normalize paths for consistent comparison
            norm_base = os.path.normpath(os.path.abspath(base_dir))

            # Handle both absolute and relative paths
            if os.path.isabs(path):
                norm_path = os.path.normpath(path)
            else:
                norm_path = os.path.normpath(os.path.join(norm_base, path))

            # Check if the normalized path starts with the base directory
            if not norm_path.startswith(norm_base):
                log_warning(f"Path would escape base directory: {path}")
                metrics.increment('security.path_validation_failure')
                return False

        # Path validation passed
        metrics.increment('security.path_validation_success')
        return True

    except Exception as e:
        log_error(f"Error validating path: {e}")
        metrics.increment('security.path_validation_error')
        return False


def validate_url(url: str, required_schemes: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate if the given string is a valid and safe URL.

    This function checks URLs for security concerns including proper format,
    unsafe schemes, and optionally restricts to specific URI schemes.

    Args:
        url: The URL string to validate
        required_schemes: List of allowed schemes (e.g., ['http', 'https'])
                         If None, common safe schemes are allowed

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
        - First element is True if valid, False if invalid
        - Second element contains error message if invalid, None if valid

    Example:
        >>> validate_url("https://example.com/page")
        (True, None)
        >>> validate_url("javascript:alert(1)")
        (False, "URL uses unsafe scheme: javascript")
        >>> validate_url("ftp://example.com", required_schemes=["http", "https"])
        (False, "URL scheme must be one of: http, https")
    """
    if not url:
        metrics.increment('security.url_validation_failure')
        return False, "URL cannot be empty"

    try:
        # Try to parse the URL to validate its format
        from urllib.parse import urlparse
        parsed = urlparse(url)

        # Check if URL has both scheme and netloc for absolute URLs, or path for relative
        if not parsed.scheme and not parsed.netloc and not parsed.path:
            metrics.increment('security.url_validation_failure')
            return False, "URL is malformed"

        # Block unsafe schemes
        unsafe_schemes = ['javascript', 'data', 'vbscript', 'file']
        if parsed.scheme and parsed.scheme.lower() in unsafe_schemes:
            metrics.increment('security.unsafe_url_blocked')
            log_warning(f"Blocked unsafe URL scheme: {parsed.scheme}")

            # Log security event if in request context
            if has_request_context():
                try:
                    log_security_event(
                        event_type="unsafe_url_blocked",
                        description=f"Blocked unsafe URL scheme: {parsed.scheme}",
                        severity="warning",
                        ip_address=request.remote_addr,
                        details={"url": url[:100]}  # Limit URL length in logs
                    )
                except Exception as e:
                    log_warning(f"Failed to log security event for unsafe URL: {e}")

            return False, f"URL uses unsafe scheme: {parsed.scheme}"

        # If specific schemes are required, enforce them
        if required_schemes and parsed.scheme:
            if parsed.scheme.lower() not in [s.lower() for s in required_schemes]:
                metrics.increment('security.url_validation_failure')
                schemes_str = ", ".join(required_schemes)
                return False, f"URL scheme must be one of: {schemes_str}"

        # Check for relative URLs
        if not parsed.scheme and not parsed.netloc:
            # For relative URLs, enforce they start with / to prevent path traversal
            if not parsed.path.startswith('/'):
                metrics.increment('security.unsafe_path_blocked')
                return False, "Relative URL must start with /"

        # Additional validation based on project's security policies
        if SECURITY_CONFIG.get('STRICT_URL_VALIDATION', False):
            # In strict mode, apply additional rules from config
            allowed_domains = []
            if has_app_context():
                allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])

            # If URL has host and we have domain restrictions
            if parsed.netloc and allowed_domains:
                host = parsed.netloc.lower()
                if not any(host == domain.lower() or host.endswith('.' + domain.lower()) for domain in allowed_domains):
                    metrics.increment('security.url_validation_failure')
                    return False, "Domain not in allowed list"

        # URL validation passed
        metrics.increment('security.url_validation_success')
        return True, None

    except Exception as e:
        log_error(f"Error validating URL: {e}")
        metrics.increment('security.url_validation_error')
        return False, f"Error validating URL: {str(e)}"
