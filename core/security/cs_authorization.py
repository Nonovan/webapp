"""
Authorization utilities for the Cloud Infrastructure Platform.

This module provides authorization related functionality, including permission
checking, multi-factor authentication enforcement, and UI element access control.
These components ensure that users only access resources and perform actions
they are authorized for.
"""

from functools import wraps
from typing import Callable, Dict, Any, Optional, Union, List

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context
from flask import redirect, url_for, flash, abort
from flask_login import current_user

# Internal imports
from extensions import db, metrics
from .cs_audit import log_security_event
from .cs_constants import SECURITY_CONFIG
from .cs_session import is_mfa_verified, mark_requiring_mfa
from models.audit_log import AuditLog


def require_permission(permission: str, audit_access: bool = True):
    """
    Decorator to ensure user has the required permission.

    This decorator checks that the current user has the specified permission
    before allowing access to the decorated function. If the user lacks the
    permission, a 403 Forbidden response is returned.

    Args:
        permission: The permission name required (format: 'resource:action')
        audit_access: Whether to record successful access in audit log

    Returns:
        Decorator function that checks permission

    Example:
        @app.route('/admin/users')
        @require_permission('users:list')
        def list_users():
            return render_template('users.html')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                # Log failed authentication attempt if audit is enabled
                if audit_access:
                    log_security_event(
                        event_type=AuditLog.EVENT_AUTH_REQUIRED,
                        description=f"Authentication required for: {request.path}",
                        severity='info',
                        details={
                            'permission': permission,
                            'endpoint': request.endpoint,
                            'path': request.path
                        }
                    )

                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.path))

            # Skip check if superuser or admin role, if such attributes exist
            if _is_superuser_or_admin():
                # Log superuser/admin access if audit is enabled
                if audit_access:
                    log_security_event(
                        event_type=AuditLog.EVENT_ADMIN_ACCESS,
                        description=f"Admin accessed: {request.path}",
                        severity='info',
                        user_id=current_user.id if hasattr(current_user, 'id') else None,
                        details={
                            'permission': permission,
                            'endpoint': request.endpoint,
                            'path': request.path,
                            'role': getattr(current_user, 'role', 'superuser')
                        }
                    )
                return f(*args, **kwargs)

            # Check permission
            has_permission = getattr(current_user, 'has_permission', lambda p: False)(permission)

            if has_permission:
                # User has permission, log access if audit is enabled
                if audit_access:
                    log_security_event(
                        event_type=AuditLog.EVENT_PERMISSION_GRANTED,
                        description=f"Permission granted: {permission}",
                        severity='info',
                        user_id=current_user.id if hasattr(current_user, 'id') else None,
                        details={
                            'permission': permission,
                            'endpoint': request.endpoint,
                            'path': request.path
                        }
                    )
                return f(*args, **kwargs)
            else:
                # Log the permission denial
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Permission denied: {permission}",
                    severity='warning',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'permission': permission,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                # Track metric
                metrics.increment('security.permission_denied')

                # Return 403 Forbidden
                return abort(403, description=f"You don't have the required permission: {permission}")

        return decorated_function
    return decorator


def require_mfa(f=None, *, redirect_to: str = 'auth.verify_mfa', exempt_roles: List[str] = None):
    """
    Decorator to ensure user has completed Multi-Factor Authentication.

    This decorator checks that the current user has completed MFA verification
    before allowing access to the decorated function. If MFA is not verified,
    the user is redirected to the MFA verification page.

    Args:
        f: The function to decorate
        redirect_to: The endpoint to redirect to for MFA verification
        exempt_roles: List of roles that are exempt from MFA requirement

    Returns:
        Decorated function that checks MFA verification

    Example:
        @app.route('/sensitive-data')
        @login_required
        @require_mfa
        def view_sensitive_data():
            return render_template('sensitive_data.html')

        # With parameters
        @app.route('/api/sensitive')
        @login_required
        @require_mfa(redirect_to='auth.api_mfa', exempt_roles=['system', 'api'])
        def sensitive_api():
            return jsonify(sensitive_data)
    """
    # Handle both @require_mfa and @require_mfa() syntax
    actual_decorator = _make_mfa_decorator(redirect_to, exempt_roles or [])
    if f:
        return actual_decorator(f)
    return actual_decorator


def _make_mfa_decorator(redirect_to: str, exempt_roles: List[str]):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.path))

            # Check if MFA is required for this user based on config and role
            if not _should_require_mfa(exempt_roles):
                return f(*args, **kwargs)

            # Use the session utility to check if MFA is verified
            if not is_mfa_verified():
                # Mark session as requiring MFA
                mark_requiring_mfa()

                # Show a flash message if this isn't an API request
                if not _is_api_request():
                    flash('Please complete two-factor authentication to access this page.', 'warning')

                # Log the MFA requirement
                log_security_event(
                    event_type=AuditLog.EVENT_MFA_REQUIRED,
                    description='MFA verification required for sensitive action',
                    severity='info',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                # Track metric
                metrics.increment('security.mfa_required')

                # Determine response based on request type (API vs web)
                if _is_api_request():
                    return {"error": "MFA verification required", "code": "MFA_REQUIRED"}, 403
                else:
                    # Redirect to MFA verification with return URL
                    return redirect(url_for(redirect_to, next=request.path))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def can_access_ui_element(element_id: str, required_permission: str = None,
                         mfa_required: bool = False):
    """
    Decorator factory to control access to UI elements based on permissions.

    This decorator manages UI element visibility based on user permissions without
    raising errors. It allows for progressive UI enhancement where elements are
    conditionally shown based on the user's access rights.

    Args:
        element_id: The UI element identifier that will be used in templates
        required_permission: The permission name required to see the element
                            (format: 'resource:action')
        mfa_required: Whether MFA verification is required to see this element

    Returns:
        Callable: A decorator that controls UI element access

    Example:
        @app.route('/dashboard')
        @can_access_ui_element('admin_panel', 'admin:access')
        def dashboard():
            return render_template('dashboard.html')
    """
    def decorator(view_func):
        @wraps(view_func)
        def decorated_function(*args, **kwargs):
            # Initialize ui_permissions dict if it doesn't exist
            kwargs['ui_permissions'] = kwargs.get('ui_permissions', {})

            # Default to showing the element
            has_access = True

            # Check permission if one is required
            if required_permission:
                # Guard against current_user not being authenticated
                if not hasattr(current_user, 'is_authenticated') or not current_user.is_authenticated:
                    has_access = False
                # Check the actual permission
                elif not hasattr(current_user, 'has_permission') or not current_user.has_permission(required_permission):
                    has_access = False

            # Check MFA if required
            if has_access and mfa_required and has_request_context():
                has_access = is_mfa_verified()

            # Store the result in the ui_permissions dict
            kwargs['ui_permissions'][element_id] = has_access

            # Add element_id to a list of checked elements for debugging
            if 'checked_elements' not in kwargs:
                kwargs['checked_elements'] = []
            kwargs['checked_elements'].append(element_id)

            return view_func(*args, **kwargs)
        return decorated_function
    return decorator


def api_key_required(f):
    """
    Decorator to ensure request has a valid API key.

    This decorator checks that the request includes a valid API key
    before allowing access to the decorated function.

    Args:
        f: The function to decorate

    Returns:
        Decorated function that checks for API key

    Example:
        @app.route('/api/data')
        @api_key_required
        def get_api_data():
            return jsonify(data)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip check in development mode if configured
        if has_app_context() and current_app.config.get('BYPASS_API_AUTH_IN_DEV', False):
            if current_app.debug or current_app.config.get('TESTING', False):
                return f(*args, **kwargs)

        # Get API key from header or query parameter
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')

        if not api_key:
            log_security_event(
                event_type=AuditLog.EVENT_API_AUTH_FAILED,
                description="API request missing API key",
                severity='warning',
                ip_address=request.remote_addr,
                details={'endpoint': request.endpoint, 'path': request.path}
            )
            metrics.increment('security.api_auth_failed')
            return {"error": "API key required"}, 401

        # Validate API key
        if not _validate_api_key(api_key):
            log_security_event(
                event_type=AuditLog.EVENT_API_AUTH_FAILED,
                description="Invalid API key",
                severity='warning',
                ip_address=request.remote_addr,
                details={'endpoint': request.endpoint, 'path': request.path}
            )
            metrics.increment('security.api_auth_failed')
            return {"error": "Invalid API key"}, 401

        # API key is valid, proceed
        return f(*args, **kwargs)

    return decorated_function


def rate_limit(limit: int = None, period: int = 60, key_function=None):
    """
    Decorator to apply rate limiting to a route.

    This decorator tracks and limits the number of requests a client
    can make in a given time period based on IP address or custom key.

    Args:
        limit: Maximum requests allowed in the period (defaults to config value)
        period: Time period in seconds (defaults to 60s)
        key_function: Function to generate the rate limit key (defaults to IP address)

    Returns:
        Decorated function with rate limiting

    Example:
        @app.route('/api/search')
        @rate_limit(limit=10, period=60)
        def search_api():
            # Code that might be resource intensive
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_request_context():
                return f(*args, **kwargs)

            # Use redis for rate limiting if available
            redis = getattr(current_app, 'redis_client', None)
            if not redis:
                # No redis, so we can't rate limit
                return f(*args, **kwargs)

            # Determine limit value
            actual_limit = limit or SECURITY_CONFIG.get('API_RATE_LIMIT', 100)
            actual_period = period or SECURITY_CONFIG.get('API_RATE_LIMIT_WINDOW', 60)

            # Generate rate limiting key
            if key_function:
                rate_key = key_function()
            else:
                rate_key = f"ratelimit:{request.remote_addr}:{request.endpoint}"

            # Check current request count
            current = redis.get(rate_key)
            if current is not None:
                current = int(current)
                if current >= actual_limit:
                    # Too many requests
                    log_security_event(
                        event_type=AuditLog.EVENT_RATE_LIMIT_EXCEEDED,
                        description=f"Rate limit exceeded: {rate_key}",
                        severity='warning',
                        ip_address=request.remote_addr,
                        details={'endpoint': request.endpoint, 'limit': actual_limit, 'period': actual_period}
                    )
                    metrics.increment('security.rate_limit_exceeded')

                    # Return 429 Too Many Requests
                    response = {"error": "Too many requests", "retry_after": actual_period}, 429
                    return response

            # Increment request count
            pipe = redis.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, actual_period)
            pipe.execute()

            return f(*args, **kwargs)

        return decorated_function
    return decorator


# Helper functions

def _is_superuser_or_admin() -> bool:
    """Check if current user is a superuser or has admin role."""
    # Check if user has superuser attribute
    if hasattr(current_user, 'is_superuser') and current_user.is_superuser:
        return True

    # Check if user has admin role
    if hasattr(current_user, 'role') and current_user.role == 'admin':
        return True

    # Check if user has roles list with admin
    if hasattr(current_user, 'roles') and 'admin' in current_user.roles:
        return True

    return False


def _should_require_mfa(exempt_roles: List[str] = None) -> bool:
    """
    Determine if MFA should be required based on configuration and user role.

    Args:
        exempt_roles: List of roles that are exempt from MFA requirement

    Returns:
        bool: True if MFA should be required, False otherwise
    """
    if not has_app_context():
        # Default to requiring MFA
        return True

    # Check if MFA is globally disabled
    mfa_enabled = current_app.config.get('MFA_ENABLED', SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', True))
    if not mfa_enabled:
        return False

    # Check if user is exempt from MFA
    if hasattr(current_user, 'mfa_exempt') and current_user.mfa_exempt:
        return False

    # Check if user's role is in exempt list
    if exempt_roles and hasattr(current_user, 'role'):
        user_role = current_user.role
        if user_role in exempt_roles:
            return False

    # Check if user has multiple roles and any are exempt
    if exempt_roles and hasattr(current_user, 'roles'):
        user_roles = current_user.roles
        if any(role in exempt_roles for role in user_roles):
            return False

    return True


def _is_api_request() -> bool:
    """Determine if the current request is an API request."""
    if not has_request_context():
        return False

    # Check if the request is to an API endpoint
    if request.path.startswith('/api/'):
        return True

    # Check if the request wants JSON
    if request.headers.get('Accept') == 'application/json':
        return True

    # Check if the config marks this as an API request
    if has_app_context():
        return current_app.config.get('API_REQUEST', False)

    return False


def _validate_api_key(api_key: str) -> bool:
    """
    Validate an API key against the database or configuration.

    Args:
        api_key: The API key to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not has_app_context():
        return False

    # Check against hard-coded keys in config (development only)
    if current_app.debug:
        dev_keys = current_app.config.get('DEV_API_KEYS', [])
        if api_key in dev_keys:
            return True

    # Check against database model if available
    try:
        # Import here to avoid circular imports
        from models.auth.api_key import APIKey
        key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

        if key_obj:
            # Check if key has expired
            if key_obj.is_expired():
                log_warning(f"API key has expired: {api_key[:8]}...")
                return False

            # Update last used time
            key_obj.record_usage()
            return True
    except ImportError:
        log_warning("APIKey model not available")
    except Exception as e:
        log_error(f"Error validating API key: {e}")

    return False


def log_warning(message: str) -> None:
    """Log a warning message."""
    if has_app_context():
        current_app.logger.warning(message)
    else:
        print(f"WARNING: {message}")


def log_error(message: str) -> None:
    """Log an error message."""
    if has_app_context():
        current_app.logger.error(message)
    else:
        print(f"ERROR: {message}")
