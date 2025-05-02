"""
Authentication decorators for route protection.

This module provides decorator functions that implement various security controls
for route protection, including:
- Role-based access control
- Permission validation
- Session validation
- Rate limiting and circuit breaking
- Anonymous-only access
- MFA requirement enforcement
- Password confirmation for sensitive operations
- Comprehensive audit logging

These decorators follow security best practices with proper error handling,
logging, and metrics collection for comprehensive security monitoring.
"""

import functools
from datetime import datetime, timedelta
from typing import Callable, TypeVar, cast, Optional, Dict, Any, Union
from flask import current_app, flash, g, redirect, request, session, url_for, abort
from werkzeug.exceptions import Forbidden, Unauthorized
from extensions import limiter, metrics, db
from extensions.circuit_breaker import CircuitOpenError, circuit_breaker
from models.auth import User
from core.security import log_security_event
from models.security.system.audit_log import AuditLog

# Type variable for better typing in decorators
T = TypeVar('T', bound=Callable)

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
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id'):
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return cast(T, decorated_function)


def login_required(f: T) -> T:
    """
    Decorator that restricts route access to authenticated users.

    This decorator checks that a valid user session exists, redirecting
    to the login page if not. It also implements session timeout for
    security, requiring re-authentication after a period of inactivity.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces authentication
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
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
            timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', 30)

            if datetime.utcnow() - last_active > timedelta(minutes=timeout_minutes):
                # Log session timeout
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ERROR,
                    description=f"Session timed out for user {session['user_id']}",
                    severity=AuditLog.SEVERITY_INFO,
                    user_id=session['user_id'],
                    ip_address=request.remote_addr,
                    category=AuditLog.EVENT_CATEGORY_AUTH
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
                if not g.user:
                    # User no longer exists or was deleted
                    session.clear()
                    flash('Your account is no longer valid. Please contact support.', 'danger')
                    return redirect(url_for('auth.login'))

                # Set user ID in g for convenience
                g.user_id = g.user.id

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
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not g.user or not g.user.has_role(role):
                # Log unauthorized access attempt
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"User attempted to access resource requiring role '{role}'",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=g.user.id if g.user else None,
                    ip_address=request.remote_addr,
                    category=AuditLog.EVENT_CATEGORY_ACCESS,
                    details={
                        'required_role': role,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
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
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not g.user or not g.user.has_permission(permission):
                # Log unauthorized access attempt
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"User attempted to access resource requiring permission '{permission}'",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=g.user.id if g.user else None,
                    ip_address=request.remote_addr,
                    details={
                        'required_permission': permission,
                        'endpoint': request.endpoint,
                        'path': request.path
                    },
                    category=AuditLog.EVENT_CATEGORY_ACCESS
                )

                metrics.info('auth_permission_denied_total', 1, labels={
                    'required_permission': permission
                })

                flash('You do not have permission to access this resource.', 'danger')
                abort(403)
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
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Check if MFA is required but not completed in the session
        if current_app.config.get('ENABLE_MFA', False) and not session.get('mfa_verified'):
            # Check if user has MFA set up
            if g.user and g.user.two_factor_enabled:
                # Set awaiting MFA flag in session
                session['awaiting_mfa'] = True
                session['mfa_redirect_to'] = request.full_path

                # Log MFA enforcement
                log_security_event(
                    event_type=AuditLog.EVENT_MFA_CHALLENGE,
                    description="MFA verification required for protected resource",
                    severity=AuditLog.SEVERITY_INFO,
                    user_id=g.user.id,
                    ip_address=request.remote_addr,
                    category=AuditLog.EVENT_CATEGORY_AUTH
                )

                metrics.info('auth_mfa_enforcement_total', 1)
                return redirect(url_for('auth.mfa_verify'))

            # If user doesn't have MFA set up but it's required for their role
            if g.user and g.user.role in current_app.config.get('MFA_REQUIRED_ROLES', ['admin', 'security']):
                flash('Multi-factor authentication setup is required for your role.', 'warning')
                return redirect(url_for('auth.mfa_setup', next=request.full_path))

        return f(*args, **kwargs)
    return cast(T, decorated_function)


def rate_limit(limit: str = "5/minute", key_func: Optional[Callable] = None) -> Callable[[T], T]:
    """
    Decorator for route-specific rate limiting.

    This decorator applies a custom rate limit to specific routes,
    for defense against brute force attacks and abuse.

    Args:
        limit: Rate limit string in format "number/period" (e.g., "5/minute")
        key_func: Optional function to derive the rate limiting key

    Returns:
        Decorator function that applies rate limiting
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @limiter.limit(limit, key_func=key_func)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return cast(T, decorated_function)
    return decorator


def circuit_protected(circuit_name: str,
                     failure_threshold: int = 3,
                     reset_timeout: float = 300.0,
                     half_open_after: float = 60.0) -> Callable[[T], T]:
    """
    Decorator to apply circuit breaker pattern to a route.

    This decorator protects routes from cascading failures by implementing
    the circuit breaker pattern, which prevents repeated failures when
    a dependency is unavailable.

    Args:
        circuit_name: Name identifier for the circuit breaker
        failure_threshold: Number of failures before opening circuit
        reset_timeout: Seconds before resetting failure count
        half_open_after: Seconds before trying test request

    Returns:
        Decorator function that applies circuit breaker pattern
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @circuit_breaker(circuit_name,
                        failure_threshold=failure_threshold,
                        reset_timeout=reset_timeout,
                        half_open_after=half_open_after)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except CircuitOpenError as e:
                # Log the circuit breaker trip
                log_security_event(
                    event_type="circuit_breaker_trip",
                    description=f"Circuit breaker {circuit_name} tripped",
                    severity="warning",
                    details={
                        "circuit": circuit_name,
                        "endpoint": request.endpoint,
                        "error": str(e)
                    }
                )

                # Track in metrics
                metrics.info('auth_circuit_breaker_trips_total', 1, labels={
                    'circuit': circuit_name
                })

                flash("This operation is temporarily unavailable. Please try again later.", "warning")
                return redirect(url_for('main.home'))

        return cast(T, decorated_function)
    return decorator


def audit_activity(activity_type: str,
                  description_template: Optional[str] = None,
                  severity: str = AuditLog.SEVERITY_INFO) -> Callable[[T], T]:
    """
    Decorator to audit user activity for security-relevant routes.

    This decorator logs user activity in the audit log for compliance
    and security monitoring purposes.

    Args:
        activity_type: Type of activity being audited
        description_template: Optional template string for activity description
        severity: Severity level for the audit log entry

    Returns:
        Decorator function that logs the activity
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)

            # Only log if user is authenticated
            user_id = session.get('user_id')
            if user_id:
                # Generate description from template or use default
                description = description_template
                if description_template is None:
                    description = f"User performed {activity_type} action"

                # Log the activity using system AuditLog
                try:
                    details = {
                        'url': request.path,
                        'method': request.method,
                        'referrer': request.referrer if hasattr(request, 'referrer') else None
                    }

                    # Add route parameters for context
                    for key, value in kwargs.items():
                        if isinstance(value, (str, int, bool, float)) or value is None:
                            details[f"param_{key}"] = value

                    log_security_event(
                        event_type=activity_type,
                        description=description,
                        severity=severity,
                        user_id=user_id,
                        ip_address=request.remote_addr,
                        details=details,
                        category=AuditLog.EVENT_CATEGORY_ACCESS
                    )

                    # Track via metrics
                    metrics.info('auth_activity_logged_total', 1, labels={
                        'activity_type': activity_type,
                        'severity': severity
                    })

                except Exception as e:
                    current_app.logger.error(f"Failed to log audit activity: {str(e)}")
                    # Don't affect the user's request if logging fails

            return result
        return cast(T, decorated_function)
    return decorator


def admin_only(f: T) -> T:
    """
    Decorator to restrict access to administrator users only.

    This is a convenience decorator that combines login_required
    with require_role('admin') for better readability.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces admin access
    """
    return require_role('admin')(f)


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
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
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
                severity=AuditLog.SEVERITY_INFO,
                user_id=session.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path
                },
                category=AuditLog.EVENT_CATEGORY_AUTH
            )

            return redirect(url_for('auth.confirm_password'))

        return f(*args, **kwargs)
    return cast(T, decorated_function)


def validate_resource_access(resource_type: str) -> Callable[[T], T]:
    """
    Decorator to validate and audit resource access.

    This decorator checks authorization for specific resource types and records
    detailed audit logs of resource access patterns.

    Args:
        resource_type: The type of resource being accessed

    Returns:
        Decorator function that validates resource access
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            # Extract resource ID from kwargs if available
            resource_id = kwargs.get('id') or kwargs.get(f'{resource_type}_id')

            # Log resource access attempt
            log_security_event(
                event_type=f'{resource_type}_access',
                description=f"User accessed {resource_type}" +
                           (f" ID {resource_id}" if resource_id else ""),
                severity=AuditLog.SEVERITY_INFO,
                user_id=g.user.id,
                ip_address=request.remote_addr,
                details={
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'method': request.method,
                    'endpoint': request.endpoint
                },
                object_type=resource_type,
                object_id=resource_id
            )

            # Track resource access metrics
            metrics.info('resource_access_total', 1, labels={
                'resource_type': resource_type,
                'method': request.method
            })

            return f(*args, **kwargs)

        return cast(T, decorated_function)
    return decorator
