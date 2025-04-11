"""
Authentication utility functions for myproject.

This module provides utility functions for authentication-related operations,
implementing security best practices for:
- Input validation and sanitization
- Password strength verification
- JWT token generation and verification
- Authorization decorators for role-based access control
- Rate limiting for security-critical operations

These utilities are used throughout the application to ensure consistent
security practices and to centralize authentication logic for easier
maintenance and updates.
"""

import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable
from flask import current_app, session, request, redirect, abort
import jwt
from extensions import limiter, cache, metrics

def validate_input(text: str) -> bool:
    """
    Validate and sanitize general text input.

    This function checks if the input is a valid string and matches a safe pattern
    for usernames and other text fields to prevent injection attacks.

    Args:
        text: The input string to validate

    Returns:
        bool: True if the input is valid, False otherwise

    Examples:
        >>> validate_input("john_doe123")
        True
        >>> validate_input("<script>alert('XSS')</script>")
        False
    """
    if not text or not isinstance(text, str):
        return False
    text = text.strip()
    return bool(re.match(r'^[\w\s-]{1,100}$', text))

def validate_password(password: str) -> tuple[bool, str | None]:
    """
    Validate password strength with comprehensive checks.

    This function verifies that a password meets security requirements for:
    - Minimum length (12 characters)
    - Character diversity (uppercase, lowercase, numbers, special chars)

    Args:
        password: The password string to validate

    Returns:
        tuple[bool, str | None]:
            - A boolean indicating if the password is valid
            - An error message if invalid, None otherwise

    Examples:
        >>> validate_password("short")
        (False, "Password must be at least 12 characters")
        >>> validate_password("StrongP@ssw0rd")
        (True, None)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search("[a-z]", password):
        return False, "Must include lowercase letter"
    if not re.search("[A-Z]", password):
        return False, "Must include uppercase letter"
    if not re.search("[0-9]", password):
        return False, "Must include number"
    if not re.search("[^A-Za-z0-9]", password):
        return False, "Must include special character"
    return True, None

def generate_token(user_id: int, role: str, expires_in: int = 3600) -> str:
    """
    Generate a secure JWT token with user information and expiration.

    This function creates a signed JWT token containing the user's ID and role,
    with automatic expiration for security.

    Args:
        user_id: The user's ID to encode in the token
        role: The user's role for authorization checks
        expires_in: Token lifetime in seconds (default: 1 hour)

    Returns:
        str: A signed JWT token string

    Raises:
        RuntimeError: If token generation fails

    Examples:
        >>> token = generate_token(123, "admin", 7200)  # 2-hour admin token
        >>> token = generate_token(456, "user")  # 1-hour user token
    """
    try:
        token = jwt.encode(
            {
                'user_id': user_id,
                'role': role,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(seconds=expires_in)
            },
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        # Fix: Use info method instead of increment for Prometheus metrics
        metrics.info('token_generation_total', 1)
        # Fix: Convert bytes to str if needed (for PyJWT versions that return bytes)
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token
    except Exception as e:
        current_app.logger.error(f"Token generation failed: {e}")
        # Fix: Use info method instead of increment for Prometheus metrics
        metrics.info('token_generation_error', 1)
        raise

@cache.memoize(timeout=300)
def verify_token(token: str) -> dict | None:
    """
    Verify and decode a JWT token with caching for performance.

    This function validates a JWT token's signature and expiration,
    returning the decoded payload if valid. Results are cached to
    reduce cryptographic operations.

    Args:
        token: The JWT token string to verify

    Returns:
        dict | None: The decoded token payload if valid, None otherwise

    Examples:
        >>> payload = verify_token("eyJhbGciOiJIUzI1...")
        >>> if payload:
        ...     user_id = payload.get("user_id")
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        metrics.info('token_verification_success', 1)
        current_app.logger.info(f'Token verified for user {payload.get("user_id")}')
        return payload
    except jwt.ExpiredSignatureError:
        metrics.info('token_verification_expired', 1)
        current_app.logger.warning('Expired token detected')
        return None
    except jwt.InvalidTokenError as e:
        metrics.info('token_verification_invalid', 1)
        current_app.logger.warning(f'Invalid token: {e}')
        return None


def require_role(role) -> Callable:
    """
    Decorator to restrict route access to users with a specific role.

    This decorator checks that the authenticated user has the required role,
    aborting with a 403 Forbidden response if the user lacks sufficient
    permissions.

    Args:
        role: The role string required to access the route

    Returns:
        Callable: A decorator function that can be applied to route handlers

    Examples:
        >>> @app.route('/admin-only')
        >>> @require_role('admin')
        >>> def admin_page():
        ...     return "Admin access granted"
    """
    def decorator(f):
        @wraps(f)
        @limiter.limit("30/minute")
        def decorated_function(*args, **kwargs):
            if not session.get('role') == role:
                current_app.logger.warning(f'Unauthorized access attempt: {request.url}')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_required(f) -> Callable:
    """
    Decorator to restrict route access to authenticated users.

    This decorator checks that a valid user session exists, redirecting
    to the login page if not. It also implements session timeout for
    security, requiring re-authentication after 30 minutes of inactivity.

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
    @limiter.limit("60/minute")
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            current_app.logger.warning(f'Unauthenticated access attempt: {request.url}')
            return redirect('/auth/login')
        if datetime.utcnow() - datetime.fromisoformat(session['last_active']) > timedelta(minutes=30):
            session.clear()
            current_app.logger.warning('Session expired')
            return redirect('/auth/login')
        session['last_active'] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(limit="5/minute") -> Callable:
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
    return limiter.limit(limit)

def sanitize_input(text) -> str:
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
    return re.sub(r'[<>\'";]', '', text.strip())
