"""
Authorization utilities for the Cloud Infrastructure Platform.

This module provides authorization related functionality, including permission
checking, multi-factor authentication enforcement, and UI element access control.
These components ensure that users only access resources and perform actions
they are authorized for.
"""

from functools import wraps
from typing import Callable, Dict, Any, Optional, Union, List, Tuple, Set
import time
import hashlib
import re

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context
from flask import redirect, url_for, flash, abort, jsonify, make_response
from flask_login import current_user

# Internal imports
from extensions import db, metrics, get_redis_client
from .cs_audit import log_security_event
from .cs_constants import SECURITY_CONFIG
from .cs_session import is_mfa_verified, mark_requiring_mfa
from models.security import AuditLog


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
                            'path': request.path,
                            'method': request.method
                        }
                    )

                # Handle API requests differently
                if _is_api_request():
                    return {"error": "Authentication required", "code": "AUTH_REQUIRED"}, 401
                else:
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
                            'method': request.method,
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
                            'path': request.path,
                            'method': request.method
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
                        'path': request.path,
                        'method': request.method
                    }
                )

                # Track metric
                metrics.increment('security.permission_denied')

                # Return appropriate response based on request type
                if _is_api_request():
                    return {
                        "error": "Permission denied",
                        "code": "PERMISSION_DENIED",
                        "message": f"You don't have the required permission: {permission}"
                    }, 403
                else:
                    # Return 403 Forbidden for browser requests
                    return abort(403, description=f"You don't have the required permission: {permission}")

        return decorated_function
    return decorator


def require_mfa(redirect_to: str = 'auth.verify_mfa', exempt_roles: List[str] = None):
    """
    Decorator to ensure user has completed Multi-Factor Authentication.

    This decorator is kept for backwards compatibility and redirects to
    the implementation in cs_authentication.py which is now the primary
    decorator for MFA requirements.

    Args:
        redirect_to: The endpoint to redirect to for MFA verification
        exempt_roles: List of roles that are exempt from MFA requirement

    Returns:
        Decorated function that checks MFA verification
    """
    # Import the implementation from cs_authentication to avoid duplicating code
    from .cs_authentication import require_mfa as auth_require_mfa

    # Map parameter names to match the new implementation
    return auth_require_mfa(redirect_endpoint=redirect_to, exempt_roles=exempt_roles)


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
                # Allow superusers/admins to see all UI elements
                elif _is_superuser_or_admin():
                    has_access = True

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


def api_key_required(f=None, *, scopes: List[str] = None, validate_ip: bool = True):
    """
    Decorator to ensure request has a valid API key.

    This decorator checks that the request includes a valid API key
    before allowing access to the decorated function.

    Args:
        f: The function to decorate
        scopes: List of required API key scopes
        validate_ip: Whether to validate the caller's IP against the API key's allowed IPs

    Returns:
        Decorated function that checks for API key

    Example:
        @app.route('/api/data')
        @api_key_required
        def get_api_data():
            return jsonify(data)

        @app.route('/api/users')
        @api_key_required(scopes=['users:read'], validate_ip=True)
        def get_users_api():
            return jsonify(users)
    """
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # Skip check in development mode if configured
            if has_app_context() and current_app.config.get('BYPASS_API_AUTH_IN_DEV', False):
                if current_app.debug or current_app.config.get('TESTING', False):
                    return func(*args, **kwargs)

            # Get API key from header or query parameter (prefer header)
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')

            if not api_key:
                log_security_event(
                    event_type=AuditLog.EVENT_API_AUTH_FAILED,
                    description="API request missing API key",
                    severity='warning',
                    ip_address=request.remote_addr,
                    details={
                        'endpoint': request.endpoint,
                        'path': request.path,
                        'method': request.method
                    }
                )
                metrics.increment('security.api_auth_failed')
                return {"error": "API key required", "code": "API_KEY_REQUIRED"}, 401

            # Validate API key and get key details
            validation_result, key_data = _validate_api_key(api_key)

            if not validation_result:
                log_security_event(
                    event_type=AuditLog.EVENT_API_AUTH_FAILED,
                    description="Invalid API key",
                    severity='warning',
                    ip_address=request.remote_addr,
                    details={
                        'endpoint': request.endpoint,
                        'path': request.path,
                        'method': request.method,
                        'key_prefix': api_key[:8] if api_key else None
                    }
                )
                metrics.increment('security.api_auth_failed')
                return {"error": "Invalid API key", "code": "INVALID_API_KEY"}, 401

            # Validate IP restrictions if enabled
            if validate_ip and key_data and 'allowed_ips' in key_data:
                client_ip = request.remote_addr
                if not _is_ip_allowed(client_ip, key_data['allowed_ips']):
                    log_security_event(
                        event_type=AuditLog.EVENT_API_AUTH_FAILED,
                        description="API key IP restriction violation",
                        severity='warning',
                        ip_address=client_ip,
                        details={
                            'endpoint': request.endpoint,
                            'path': request.path,
                            'key_prefix': api_key[:8] if api_key else None,
                            'user_id': key_data.get('user_id')
                        }
                    )
                    metrics.increment('security.ip_restriction_violation')
                    return {"error": "IP address not allowed for this API key", "code": "IP_RESTRICTED"}, 403

            # Validate scopes if required
            if scopes and key_data and 'scopes' in key_data:
                key_scopes = key_data['scopes']
                if not all(scope in key_scopes for scope in scopes):
                    log_security_event(
                        event_type=AuditLog.EVENT_API_AUTH_FAILED,
                        description="API key missing required scope",
                        severity='warning',
                        ip_address=request.remote_addr,
                        details={
                            'endpoint': request.endpoint,
                            'path': request.path,
                            'required_scopes': scopes,
                            'key_scopes': key_scopes,
                            'user_id': key_data.get('user_id')
                        }
                    )
                    metrics.increment('security.api_scope_denied')
                    return {"error": "API key is missing required scope", "code": "INSUFFICIENT_SCOPE"}, 403

            # Store key data in request context for later use if needed
            if has_request_context():
                g.api_key_data = key_data
                g.authenticated_via = 'api_key'
                if 'user_id' in key_data:
                    g.user_id = key_data['user_id']

            # API key is valid, proceed
            return func(*args, **kwargs)

        return decorated_function

    # Allow decorator to be used with or without arguments
    if f:
        return decorator(f)
    return decorator


def rate_limit(limit: int = None, period: int = 60, key_function=None, error_message: str = None):
    """
    Decorator to apply rate limiting to a route.

    This decorator tracks and limits the number of requests a client
    can make in a given time period based on IP address or custom key.

    Args:
        limit: Maximum requests allowed in the period (defaults to config value)
        period: Time period in seconds (defaults to 60s)
        key_function: Function to generate the rate limit key (defaults to IP address)
        error_message: Custom error message to return when limit is exceeded

    Returns:
        Decorated function with rate limiting

    Example:
        @app.route('/api/search')
        @rate_limit(limit=10, period=60)
        def search_api():
            # Code that might be resource intensive

        # With custom key function
        @app.route('/api/user/<user_id>')
        @rate_limit(limit=5, key_function=lambda: f"user:{g.user_id}")
        def user_api(user_id):
            # User-specific rate limiting
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_request_context():
                return f(*args, **kwargs)

            # Get Redis client for rate limiting
            redis = get_redis_client()
            if not redis:
                # No redis, so we can't rate limit
                if has_app_context() and not current_app.testing:
                    log_warning("Rate limiting disabled - Redis not available")
                return f(*args, **kwargs)

            # Determine limit value
            actual_limit = limit or SECURITY_CONFIG.get('API_RATE_LIMIT', 100)
            actual_period = period or SECURITY_CONFIG.get('API_RATE_LIMIT_WINDOW', 60)

            # Generate rate limiting key
            if key_function:
                rate_key = key_function()
            else:
                # Default: rate limit by IP and endpoint
                rate_key = f"ratelimit:{request.remote_addr}:{request.endpoint}"

            # Check current request count using sliding window
            current_time = int(time.time())
            window_key = f"{rate_key}:{current_time // actual_period}"

            try:
                current = redis.get(window_key)
                if current is not None:
                    current = int(current)
                    if current >= actual_limit:
                        # Too many requests
                        log_security_event(
                            event_type=AuditLog.EVENT_RATE_LIMIT_EXCEEDED,
                            description=f"Rate limit exceeded: {rate_key}",
                            severity='warning',
                            ip_address=request.remote_addr,
                            details={
                                'endpoint': request.endpoint,
                                'path': request.path,
                                'limit': actual_limit,
                                'period': actual_period
                            }
                        )
                        metrics.increment('security.rate_limit_exceeded')

                        # Create response with appropriate headers
                        message = error_message or "Too many requests"
                        response = make_response(jsonify({
                            "error": message,
                            "code": "RATE_LIMIT_EXCEEDED",
                            "retry_after": actual_period
                        }), 429)

                        # Add standard rate limit headers
                        response.headers['Retry-After'] = str(actual_period)
                        response.headers['X-RateLimit-Limit'] = str(actual_limit)
                        response.headers['X-RateLimit-Remaining'] = '0'
                        response.headers['X-RateLimit-Reset'] = str(current_time + actual_period)

                        return response

                # Increment request count with pipeline for atomicity
                pipe = redis.pipeline()
                pipe.incr(window_key)
                pipe.expire(window_key, actual_period)
                result = pipe.execute()

                # Add rate limit headers to response
                current_count = result[0] if result else 1
                remaining = max(0, actual_limit - current_count)

                # Process the request
                response = f(*args, **kwargs)

                # Add headers to the response
                if isinstance(response, tuple) and len(response) >= 2:
                    response_obj, status_code = response[0], response[1]
                    if hasattr(response_obj, 'headers'):
                        response_obj.headers['X-RateLimit-Limit'] = str(actual_limit)
                        response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
                        response_obj.headers['X-RateLimit-Reset'] = str(current_time + actual_period)

                return response

            except Exception as e:
                log_error(f"Rate limiting error: {e}")
                # Continue if rate limiting fails
                return f(*args, **kwargs)

        return decorated_function
    return decorator


def role_required(role_names: Union[str, List[str]]):
    """
    Decorator to ensure user has at least one of the specified roles.

    This decorator checks that the current user has one of the required roles
    before allowing access to the decorated function.

    Args:
        role_names: Role name or list of role names, one of which is required

    Returns:
        Decorator function that checks role

    Example:
        @app.route('/admin/dashboard')
        @role_required('admin')
        def admin_dashboard():
            return render_template('admin/dashboard.html')

        @app.route('/reports')
        @role_required(['analyst', 'manager', 'admin'])
        def reports():
            return render_template('reports.html')
    """
    if isinstance(role_names, str):
        role_names = [role_names]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                # Log failed authentication attempt
                log_security_event(
                    event_type=AuditLog.EVENT_AUTH_REQUIRED,
                    description=f"Authentication required for: {request.path}",
                    severity='info',
                    details={
                        'roles_required': role_names,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                # Handle API requests differently
                if _is_api_request():
                    return {"error": "Authentication required", "code": "AUTH_REQUIRED"}, 401
                else:
                    flash('Please log in to access this page.', 'warning')
                    return redirect(url_for('auth.login', next=request.path))

            # Check if user has any of the required roles
            has_role = False

            # Check single role attribute
            if hasattr(current_user, 'role'):
                has_role = current_user.role in role_names

            # Check roles list attribute if exists
            elif hasattr(current_user, 'roles'):
                user_roles = current_user.roles
                has_role = any(role in role_names for role in user_roles)

            # Also check if superuser/admin
            if _is_superuser_or_admin():
                has_role = True

            if has_role:
                # Log successful access
                log_security_event(
                    event_type=AuditLog.EVENT_ROLE_ACCESS,
                    description=f"Role-based access granted: {request.path}",
                    severity='info',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'roles_required': role_names,
                        'user_role': getattr(current_user, 'role', None),
                        'user_roles': getattr(current_user, 'roles', []),
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )
                return f(*args, **kwargs)
            else:
                # Log role access denial
                log_security_event(
                    event_type=AuditLog.EVENT_ROLE_DENIED,
                    description=f"Role-based access denied: {request.path}",
                    severity='warning',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'roles_required': role_names,
                        'user_role': getattr(current_user, 'role', None),
                        'user_roles': getattr(current_user, 'roles', []),
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                metrics.increment('security.role_access_denied')

                # Return appropriate response based on request type
                if _is_api_request():
                    return {
                        "error": "Insufficient role privileges",
                        "code": "ROLE_REQUIRED",
                        "required_roles": role_names
                    }, 403
                else:
                    return abort(403, description=f"Required role(s): {', '.join(role_names)}")

        return decorated_function
    return decorator


def verify_permission(user_id: int, permission: str) -> bool:
    """
    Verify if a user has a specific permission.

    This function checks if the user with the given ID has the specified permission.
    It supports wildcard matching with "*" for resource or action components.

    Args:
        user_id: The ID of the user to check permissions for
        permission: The permission string to check (format: "resource:action")

    Returns:
        bool: True if the user has the permission, False otherwise
    """
    from flask import current_app, has_app_context

    if not user_id:
        return False

    try:
        # Import here to avoid circular imports
        from models.auth.user import User

        user = User.query.get(user_id)
        if not user:
            return False

        # Check direct permission match
        if hasattr(user, 'has_permission') and callable(user.has_permission):
            # Handle wildcard permissions
            if permission.endswith(':*'):
                resource = permission.split(':', 1)[0]
                # Find any permission that matches the resource prefix
                return _check_resource_permissions(user, resource)
            elif permission == '*:*' or permission == '*':
                # Super permission - only for system admins
                return getattr(user, 'is_admin', False)
            else:
                # Standard permission check
                return user.has_permission(permission)

        # Fall back to role-based check if has_permission method unavailable
        if hasattr(user, 'role'):
            admin_roles = ['admin', 'superuser', 'system_admin']
            if user.role in admin_roles:
                return True

    except Exception as e:
        if has_app_context():
            current_app.logger.error(f"Error verifying permission '{permission}' for user {user_id}: {str(e)}")
        return False

    return False


def get_user_permissions(user_id: int) -> List[str]:
    """
    Get a list of all permissions assigned to a user.

    This function retrieves all permissions a user has through:
    1. Direct permission assignments
    2. Role-based permissions
    3. Active delegated permissions

    Args:
        user_id: The ID of the user whose permissions to retrieve

    Returns:
        List[str]: List of permission names the user has access to

    Raises:
        SQLAlchemyError: If there's a database access error
    """
    from flask import current_app, has_app_context
    from sqlalchemy.exc import SQLAlchemyError

    if not user_id:
        return []

    try:
        # Import here to avoid circular imports
        from models.auth.user import User
        from datetime import datetime, timezone

        user = User.query.get(user_id)
        if not user:
            return []

        # Handle superadmin privilege as a special case
        if getattr(user, 'is_admin', False):
            # If the user is an admin, they implicitly have all permissions
            if has_app_context():
                # If possible, get a list of all possible permissions from the system
                from models.auth.permission import Permission
                try:
                    return [p.name for p in Permission.query.filter_by(is_active=True).all()]
                except Exception:
                    # If we can't query all permissions, return a wildcard indicator
                    return ['*:*']
            return ['*:*']  # Wildcard permission

        # Get all permissions the user has directly or via roles
        all_permissions = set()

        # 1. Direct permissions
        if hasattr(user, 'permissions'):
            all_permissions.update(p.name for p in user.permissions if hasattr(p, 'name'))

        # 2. Role-based permissions
        if hasattr(user, 'role') and user.role and hasattr(user.role, 'permissions'):
            all_permissions.update(p.name for p in user.role.permissions if hasattr(p, 'name'))

        # Handle multiple roles if the system supports it
        if hasattr(user, 'roles'):
            for role in user.roles:
                if hasattr(role, 'permissions'):
                    all_permissions.update(p.name for p in role.permissions if hasattr(p, 'name'))

        # 3. Active delegated permissions
        try:
            from models.auth.permission_delegation import PermissionDelegation

            # Get current time for checking active delegations
            now = datetime.now(timezone.utc)

            # Query active permission delegations for this user
            delegations = PermissionDelegation.query.filter_by(
                delegate_id=user_id,
                is_active=True
            ).filter(
                PermissionDelegation.start_time <= now,
                PermissionDelegation.end_time > now
            ).all()

            # Add delegated permissions
            for delegation in delegations:
                if hasattr(delegation, 'permission') and delegation.permission:
                    all_permissions.add(delegation.permission.name)
                elif hasattr(delegation, 'permissions') and isinstance(delegation.permissions, list):
                    # Handle case where permissions is stored as a list of strings
                    all_permissions.update(delegation.permissions)

        except (ImportError, SQLAlchemyError) as e:
            # Log the error but don't fail - just don't include delegated permissions
            if has_app_context():
                current_app.logger.warning(f"Error retrieving delegated permissions: {str(e)}")

        # Support for the legacy get_all_permissions method
        if hasattr(user, 'get_all_permissions') and callable(user.get_all_permissions):
            try:
                user_permissions = user.get_all_permissions()
                if isinstance(user_permissions, (list, tuple, set)):
                    all_permissions.update(user_permissions)
            except Exception as e:
                if has_app_context():
                    current_app.logger.warning(f"Error calling get_all_permissions: {str(e)}")

        # Convert the set to a list for return
        return list(all_permissions)

    except Exception as e:
        if has_app_context():
            current_app.logger.error(f"Error retrieving permissions for user {user_id}: {str(e)}")
        return []


def get_user_roles(user_id: int) -> List[str]:
    """
    Get a list of all roles assigned to a user.

    This function retrieves all roles a user has, including direct assignments
    and inherited roles through role hierarchy.

    Args:
        user_id: The ID of the user whose roles to retrieve

    Returns:
        List[str]: List of role names assigned to the user

    Raises:
        SQLAlchemyError: If there's a database access error
    """
    from flask import current_app, has_app_context
    from sqlalchemy.exc import SQLAlchemyError

    if not user_id:
        return []

    try:
        # Import here to avoid circular imports
        from models.auth.user import User

        user = User.query.get(user_id)
        if not user:
            return []

        all_roles = set()

        # 1. Get single role if the user model has 'role' attribute
        if hasattr(user, 'role') and user.role:
            if isinstance(user.role, str):
                all_roles.add(user.role)
            elif hasattr(user.role, 'name'):
                all_roles.add(user.role.name)

        # 2. Get multiple roles if the user model has 'roles' attribute (list of Role objects)
        if hasattr(user, 'roles') and user.roles:
            if isinstance(user.roles, (list, tuple, set)):
                for role in user.roles:
                    if isinstance(role, str):
                        all_roles.add(role)
                    elif hasattr(role, 'name'):
                        all_roles.add(role.name)

        # 3. Use get_all_roles method if available
        if hasattr(user, 'get_all_roles') and callable(user.get_all_roles):
            try:
                user_roles = user.get_all_roles()
                if isinstance(user_roles, (list, tuple, set)):
                    all_roles.update(r if isinstance(r, str) else getattr(r, 'name', str(r))
                                    for r in user_roles)
            except Exception as e:
                if has_app_context():
                    current_app.logger.warning(f"Error calling get_all_roles: {str(e)}")

        # 4. Get inherited roles through role hierarchy
        if all_roles:
            # Get parent roles if role hierarchy is supported
            try:
                from models.auth.role import Role

                # Get all role objects for the roles we already found
                role_objects = Role.query.filter(Role.name.in_(all_roles)).all()

                # Check each role for a parent
                for role in role_objects:
                    # Add parent roles recursively up to max depth
                    parent_roles = _get_parent_roles(role, depth=0, max_depth=5)
                    all_roles.update(parent_roles)

            except (ImportError, SQLAlchemyError) as e:
                if has_app_context():
                    current_app.logger.debug(f"Could not resolve role hierarchy: {str(e)}")

        # Sort and return the final list
        return sorted(list(all_roles))

    except Exception as e:
        if has_app_context():
            current_app.logger.error(f"Error retrieving roles for user {user_id}: {str(e)}")
        return []


def _get_parent_roles(role, depth: int = 0, max_depth: int = 5) -> Set[str]:
    """
    Get all parent roles in the role hierarchy recursively.

    This helper function walks up the role hierarchy to find all parent
    roles that the given role inherits permissions from.

    Args:
        role: The role object to check for parents
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent infinite loops

    Returns:
        Set[str]: Set of parent role names
    """
    # Prevent excessive recursion
    if depth >= max_depth:
        return set()

    parent_roles = set()

    # Check if role has a parent
    if hasattr(role, 'parent') and role.parent:
        # Add the direct parent role name
        if hasattr(role.parent, 'name'):
            parent_roles.add(role.parent.name)

        # Recursively get parents of the parent
        parent_roles.update(_get_parent_roles(role.parent, depth + 1, max_depth))

    return parent_roles


def has_role(user_id: int, role_name: str) -> bool:
    """
    Check if a user has a specific role.

    Args:
        user_id: The ID of the user to check
        role_name: The name of the role to check for

    Returns:
        bool: True if the user has the role, False otherwise
    """
    user_roles = get_user_roles(user_id)
    return role_name in user_roles


def has_any_role(user_id: int, role_names: List[str]) -> bool:
    """
    Check if a user has any of the specified roles.

    Args:
        user_id: The ID of the user to check
        role_names: List of role names to check for

    Returns:
        bool: True if the user has any of the roles, False otherwise
    """
    user_roles = get_user_roles(user_id)
    return any(role in user_roles for role in role_names)


def get_role_permissions(role_name: str) -> List[str]:
    """
    Get all permissions associated with a role.

    Args:
        role_name: The name of the role whose permissions to retrieve

    Returns:
        List[str]: List of permission names for the specified role
    """
    from flask import current_app, has_app_context
    from sqlalchemy.exc import SQLAlchemyError

    try:
        # Import here to avoid circular imports
        from models.auth.role import Role

        # Get the role by name
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return []

        # Use built-in get_permission_names if available
        if hasattr(role, 'get_permission_names') and callable(role.get_permission_names):
            try:
                return role.get_permission_names()
            except Exception as e:
                if has_app_context():
                    current_app.logger.warning(f"Error calling role.get_permission_names: {str(e)}")

        # Fall back to manual permission gathering
        permissions = []

        if hasattr(role, 'permissions'):
            for permission in role.permissions:
                if hasattr(permission, 'name'):
                    permissions.append(permission.name)

        return permissions

    except (ImportError, SQLAlchemyError) as e:
        if has_app_context():
            current_app.logger.error(f"Error retrieving permissions for role {role_name}: {str(e)}")
        return []


def get_user_roles_with_permissions(user_id: int) -> Dict[str, List[str]]:
    """
    Get all roles and their permissions for a user.

    This function is useful when you need both the roles and their permissions
    for a user in a single call, optimizing database queries.

    Args:
        user_id: The ID of the user whose roles and permissions to retrieve

    Returns:
        Dict[str, List[str]]: Dictionary mapping role names to lists of permission names
    """
    roles = get_user_roles(user_id)
    result = {}

    for role_name in roles:
        permissions = get_role_permissions(role_name)
        result[role_name] = permissions

    return result


def is_admin_role(role_name: str) -> bool:
    """
    Check if a role is an administrative role.

    Args:
        role_name: The name of the role to check

    Returns:
        bool: True if the role is an admin role, False otherwise
    """
    # Check against common admin role names
    admin_roles = ['admin', 'superadmin', 'administrator', 'system_admin', 'super_admin']

    # Case-insensitive check for exact matches
    if role_name.lower() in [r.lower() for r in admin_roles]:
        return True

    # Perform more complex checks if available
    try:
        from models.auth.role import Role
        role = Role.query.filter_by(name=role_name).first()

        # If role has a specific admin flag
        if role and hasattr(role, 'is_admin') and role.is_admin:
            return True

        # If role has admin permissions
        admin_permission_patterns = ['admin:*', '*:admin', 'admin.*']
        if role and hasattr(role, 'get_permission_names'):
            permissions = role.get_permission_names()
            for pattern in admin_permission_patterns:
                if pattern in permissions:
                    return True

            # Check for wildcard permission which typically indicates admin
            if '*:*' in permissions:
                return True
    except Exception:
        pass

    return False


def get_effective_permissions(user_id: int) -> Dict[str, Dict[str, Any]]:
    """
    Get effective permissions for a user with their source role.

    This function returns a detailed mapping of permissions and which role
    granted them, useful for permission auditing and UI displays.

    Args:
        user_id: The ID of the user whose permissions to analyze

    Returns:
        Dict[str, Dict[str, Any]]: Dictionary mapping permission names to details
                                 about the permission, including source role
    """
    from flask import current_app, has_app_context

    try:
        # Get all user roles with their permissions
        roles_with_permissions = get_user_roles_with_permissions(user_id)

        # Track permissions and their sources
        effective_permissions = {}

        # Process each role and its permissions
        for role_name, permissions in roles_with_permissions.items():
            for permission in permissions:
                # If we haven't seen this permission yet, or we're overriding from a more
                # specific role (simplistic approach - would need customization for real hierarchy)
                if permission not in effective_permissions:
                    effective_permissions[permission] = {
                        'name': permission,
                        'source_role': role_name,
                        'inherited': False
                    }

        # Add directly assigned permissions if available
        try:
            from models.auth.user import User
            user = User.query.get(user_id)

            if user and hasattr(user, 'permissions'):
                for permission in user.permissions:
                    if hasattr(permission, 'name'):
                        perm_name = permission.name
                        effective_permissions[perm_name] = {
                            'name': perm_name,
                            'source_role': 'direct_assignment',
                            'inherited': False
                        }
        except Exception as e:
            if has_app_context():
                current_app.logger.debug(f"Error checking direct permissions: {str(e)}")

        return effective_permissions

    except Exception as e:
        if has_app_context():
            current_app.logger.error(f"Error analyzing effective permissions for user {user_id}: {str(e)}")
        return {}


def _check_resource_permissions(user, resource: str) -> bool:
    """
    Check if user has any permission for the specified resource.

    Args:
        user: User object
        resource: Resource name to check

    Returns:
        bool: True if user has any permission for the resource
    """
    # If user has a get_permissions method, use it
    if hasattr(user, 'get_permissions') and callable(user.get_permissions):
        permissions = user.get_permissions()
        if isinstance(permissions, (list, tuple, set)):
            return any(p.startswith(f"{resource}:") for p in permissions)
        return False

    # Otherwise check admin status as fallback
    return getattr(user, 'is_admin', False)


# Helper functions

def _is_superuser_or_admin() -> bool:
    """
    Check if current user is a superuser or has admin role.

    Returns:
        bool: True if user is superuser or admin
    """
    # Check if user has superuser attribute
    if hasattr(current_user, 'is_superuser') and current_user.is_superuser:
        return True

    # Check if user has admin role
    if hasattr(current_user, 'role') and current_user.role == 'admin':
        return True

    # Check if user has roles list with admin
    if hasattr(current_user, 'roles') and isinstance(current_user.roles, (list, tuple, set)) and 'admin' in current_user.roles:
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
    # Feature flag check
    if not has_app_context():
        # Default to requiring MFA when context is uncertain
        return True

    # Check if MFA is globally disabled in app config
    mfa_enabled = current_app.config.get('MFA_ENABLED',
                 SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', True))
    if not mfa_enabled:
        return False

    # If not authenticated, no MFA needed (login will handle this)
    if not current_user or not current_user.is_authenticated:
        return False

    # Check if user is exempt from MFA by attribute
    if hasattr(current_user, 'mfa_exempt') and current_user.mfa_exempt:
        return False

    # Handle exempt roles list
    if exempt_roles:
        # Check if user's role is in the exempt list
        if hasattr(current_user, 'role'):
            user_role = current_user.role
            if user_role in exempt_roles:
                return False

        # Check if any of user's roles are in exempt list
        if hasattr(current_user, 'roles') and isinstance(current_user.roles, (list, tuple, set)):
            if any(role in exempt_roles for role in current_user.roles):
                return False

    # Default to requiring MFA for sensitive operations
    return True


def _is_api_request() -> bool:
    """
    Determine if the current request is an API request.

    Returns:
        bool: True if the current request appears to be an API request
    """
    if not has_request_context():
        return False

    # Check common API indicators

    # 1. Path-based detection
    if request.path.startswith('/api/'):
        return True

    # 2. Accept header indicates preference for JSON
    accept_header = request.headers.get('Accept', '')
    if 'application/json' in accept_header and not 'text/html' in accept_header:
        return True

    # 3. Content-Type header is JSON for POST/PUT/PATCH
    if request.method in ('POST', 'PUT', 'PATCH') and request.headers.get('Content-Type', '').startswith('application/json'):
        return True

    # 4. XHR request header
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True

    # 5. Explicit API flag in request or app config
    if request.args.get('format') == 'json' or request.args.get('output') == 'json':
        return True

    # 6. App config explicitly marks this as API request
    if has_app_context() and current_app.config.get('API_REQUEST', False):
        return True

    return False


def _validate_api_key(api_key: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate an API key against the database or configuration.

    Args:
        api_key: The API key to validate

    Returns:
        Tuple of (is_valid, key_data) where key_data contains information about the key
    """
    if not api_key or not has_app_context():
        return False, None

    # Check against hard-coded keys in config (development only)
    if current_app.debug:
        dev_keys = current_app.config.get('DEV_API_KEYS', [])
        if api_key in dev_keys:
            return True, {'scopes': ['*'], 'name': 'Development Key'}

    # Check Redis cache first for performance
    redis = get_redis_client()
    if redis:
        try:
            # Create a hash of the key for cache lookup (avoid storing raw keys in cache)
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            cache_key = f"api_key:{key_hash}"

            # Check if key is in cache
            cached_data = redis.get(cache_key)
            if cached_data:
                try:
                    import json
                    key_data = json.loads(cached_data)

                    # Return immediately if key is invalid (negative caching)
                    if key_data.get('valid', True) is False:
                        metrics.increment('security.api_key_invalid_cached')
                        return False, None

                    # Return key data if it's cached and valid
                    metrics.increment('security.api_key_valid_cached')
                    return True, key_data

                except (ValueError, TypeError):
                    # Cache data corrupted, continue to database check
                    pass
        except Exception as e:
            log_error(f"Error checking API key cache: {e}")
            # Continue to database check on error

    # Check against database model if available
    try:
        # Import here to avoid circular imports
        from models.auth.api_key import APIKey
        key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

        if not key_obj:
            # Cache negative result to avoid repeated DB lookups for invalid keys
            if redis:
                try:
                    import json
                    redis.setex(
                        f"api_key:{hashlib.sha256(api_key.encode()).hexdigest()}",
                        300,  # Cache invalid keys for 5 minutes
                        json.dumps({'valid': False})
                    )
                except Exception:
                    pass
            return False, None

        # Check if key has expired
        if key_obj.is_expired():
            log_warning(f"API key has expired: {api_key[:8]}...")
            return False, None

        # Update last used time and usage count
        key_obj.record_usage(request.remote_addr)

        # Create key data dictionary with information about the key
        key_data = {
            'id': key_obj.id,
            'name': key_obj.name,
            'scopes': key_obj.scopes,
            'user_id': key_obj.user_id,
            'allowed_ips': key_obj.allowed_ips,
            'expires_at': key_obj.expires_at.isoformat() if key_obj.expires_at else None,
            'created_at': key_obj.created_at.isoformat() if key_obj.created_at else None
        }

        # Cache the valid key for future requests
        if redis:
            try:
                import json
                # Cache for a reasonable period (10 minutes)
                redis.setex(
                    f"api_key:{hashlib.sha256(api_key.encode()).hexdigest()}",
                    600,  # 10 minutes
                    json.dumps(key_data)
                )
            except Exception as e:
                log_warning(f"Failed to cache API key: {e}")

        return True, key_data

    except ImportError:
        log_warning("APIKey model not available")
    except Exception as e:
        log_error(f"Error validating API key: {e}")

    # Default to invalid key
    return False, None


def _is_ip_allowed(ip_address: str, allowed_ips: List[str]) -> bool:
    """
    Check if an IP address is in the allowed list.

    Supports CIDR notation for IP ranges.

    Args:
        ip_address: The IP address to check
        allowed_ips: List of allowed IPs or CIDR ranges

    Returns:
        bool: True if IP is allowed
    """
    if not ip_address or not allowed_ips:
        return False

    # If allowed_ips contains '*', all IPs are allowed
    if '*' in allowed_ips:
        return True

    # Try to match exact IP
    if ip_address in allowed_ips:
        return True

    try:
        # Check for CIDR ranges
        import ipaddress

        # Convert string IP to IPv4/IPv6 object
        try:
            check_ip = ipaddress.ip_address(ip_address)
        except ValueError:
            # If IP address is invalid, deny access
            return False

        # Check each CIDR range
        for allowed in allowed_ips:
            if '/' in allowed:
                try:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if check_ip in network:
                        return True
                except ValueError:
                    # Skip invalid CIDR notations
                    continue
    except ImportError:
        # Fall back to simple prefix matching if ipaddress module not available
        for allowed in allowed_ips:
            if allowed.endswith('*') and ip_address.startswith(allowed[:-1]):
                return True

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
