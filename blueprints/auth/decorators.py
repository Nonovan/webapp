"""
Authentication decorators for route protection.

This module provides decorator functions that implement various security controls
for route protection, including:
- Role-based access control
- Permission validation
- Session validation
- Rate limiting
- Anonymous-only access
- MFA requirement enforcement

These decorators follow security best practices with proper error handling,
logging, and metrics collection for comprehensive security monitoring.
"""

import functools
from typing import Callable, TypeVar, cast, Optional
from flask import current_app, flash, g, redirect, request, session, url_for, abort
from werkzeug.exceptions import Forbidden, Unauthorized
from extensions import limiter, metrics, db
from datetime import datetime, timedelta
from models.auth import User
from core.security import log_security_event

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
                    'user_agent': request.user_agent.string
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
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
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
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
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
            if g.user and g.user.mfa_enabled:
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


def rate_limit(limit: str = "5/minute") -> Callable[[T], T]:
    """
    Decorator for route-specific rate limiting.

    This decorator applies a custom rate limit to specific routes,
    for defense against brute force attacks and abuse.

    Args:
        limit: Rate limit string in format "number/period" (e.g., "5/minute")

    Returns:
        Decorator function that applies rate limiting
    """
    def decorator(f: T) -> T:
        @functools.wraps(f)
        @limiter.limit(limit)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return cast(T, decorated_function)
    return decorator


def audit_activity(activity_type: str, description_template: Optional[str] = None) -> Callable[[T], T]:
    """
    Decorator to audit user activity for security-relevant routes.

    This decorator logs user activity in the audit log for compliance
    and security monitoring purposes.

    Args:
        activity_type: Type of activity being audited
        description_template: Optional template string for activity description

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

                # Log the activity
                try:
                    from models.audit_log import AuditLog

                    log = AuditLog(
                        user_id=user_id,
                        event_type=activity_type,
                        description=description,
                        ip_address=request.remote_addr,
                        user_agent=request.user_agent.string,
                        details={
                            'url': request.path,
                            'method': request.method,
                            'referrer': request.referrer
                        }
                    )

                    db.session.add(log)
                    db.session.commit()

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
                severity='info',
                user_id=session.get('user_id'),
                ip_address=request.remote_addr
            )

            return redirect(url_for('auth.confirm_password'))

        return f(*args, **kwargs)
    return cast(T, decorated_function)
