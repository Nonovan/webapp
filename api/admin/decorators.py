"""
Administrative security decorators for API routes.

This module provides decorator functions that implement security controls specifically
for administrative API endpoints, including:
- Role-based access controls for admin, super admin, and auditor roles
- Multi-factor authentication enforcement
- Comprehensive audit logging of administrative actions

These decorators ensure that administrative operations are properly secured and
fully logged to maintain a complete audit trail for compliance and security purposes.
"""

import functools
from typing import Callable, Any, Dict, Optional, TypeVar, cast, Union
from datetime import datetime

from flask import request, jsonify, g, current_app
from werkzeug.exceptions import Forbidden
from sqlalchemy.exc import SQLAlchemyError

from models.auth.role import Role
from core.security import log_security_event
from extensions import metrics

# Define a type variable for decorators
F = TypeVar('F', bound=Callable)


def admin_required(f: F) -> F:
    """
    Decorator to restrict API route access to administrators.

    This decorator ensures that only users with the admin role can access
    the decorated endpoint.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces admin access
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or g.user.role != Role.ROLE_ADMIN:
            # Log unauthorized access attempt
            log_security_event(
                event_type="admin_api_unauthorized_access",
                description=f"Unauthorized admin API access attempt at {request.path}",
                severity="medium",
                user_id=g.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'path': request.path,
                    'method': request.method,
                    'required_role': Role.ROLE_ADMIN
                }
            )

            # Track unauthorized access in metrics
            metrics.counter('admin_api_unauthorized_access_total').inc()

            return jsonify({
                "error": "Administrator access required",
                "code": "ADMIN_REQUIRED"
            }), 403

        return f(*args, **kwargs)
    return cast(F, decorated)


def super_admin_required(f: F) -> F:
    """
    Decorator to restrict API route access to super administrators.

    This decorator ensures that only users with the super_admin role can access
    the decorated endpoint. This is for highest privilege operations.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces super admin access
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or g.user.role != Role.ROLE_SUPER_ADMIN:
            # Log unauthorized access attempt
            log_security_event(
                event_type="admin_api_unauthorized_access",
                description=f"Unauthorized super admin API access attempt at {request.path}",
                severity="high",
                user_id=g.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'path': request.path,
                    'method': request.method,
                    'required_role': Role.ROLE_SUPER_ADMIN
                }
            )

            # Track unauthorized access in metrics
            metrics.counter('admin_api_unauthorized_access_total').inc()

            return jsonify({
                "error": "Super administrator access required",
                "code": "SUPER_ADMIN_REQUIRED"
            }), 403

        return f(*args, **kwargs)
    return cast(F, decorated)


def auditor_required(f: F) -> F:
    """
    Decorator to restrict API route access to auditors.

    This decorator ensures that only users with the auditor role can access
    the decorated endpoint. Allows access to audit data without full admin privileges.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces auditor or admin access
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or (g.user.role != Role.ROLE_AUDITOR and g.user.role != Role.ROLE_ADMIN):
            # Log unauthorized access attempt
            log_security_event(
                event_type="admin_api_unauthorized_access",
                description=f"Unauthorized auditor API access attempt at {request.path}",
                severity="medium",
                user_id=g.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'path': request.path,
                    'method': request.method,
                    'required_role': f"{Role.ROLE_AUDITOR} or {Role.ROLE_ADMIN}"
                }
            )

            # Track unauthorized access in metrics
            metrics.counter('admin_api_unauthorized_access_total').inc()

            return jsonify({
                "error": "Auditor access required",
                "code": "AUDITOR_REQUIRED"
            }), 403

        return f(*args, **kwargs)
    return cast(F, decorated)


def require_mfa(f: F) -> F:
    """
    Decorator to enforce MFA verification for sensitive admin operations.

    This decorator checks if the user has completed MFA verification
    before allowing access to protected administrative routes.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces MFA verification
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Skip MFA check if MFA is not enabled in config
        if not current_app.config.get('ENABLE_MFA', False):
            return f(*args, **kwargs)

        # Check if current session has MFA verification
        if not g.get('mfa_verified'):
            # Log MFA requirement
            log_security_event(
                event_type="admin_api_mfa_required",
                description=f"MFA verification required for admin operation: {request.path}",
                severity="medium",
                user_id=g.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'path': request.path,
                    'method': request.method
                }
            )

            # Track MFA enforcement in metrics
            metrics.counter('admin_api_mfa_required_total').inc()

            return jsonify({
                "error": "Multi-factor authentication required for this operation",
                "code": "MFA_REQUIRED"
            }), 403

        return f(*args, **kwargs)
    return cast(F, decorated)


def log_admin_action(action_type: str) -> Callable[[F], F]:
    """
    Decorator to log administrative actions for security auditing.

    Creates detailed security audit logs for all administrative actions,
    ensuring a complete trail of administrative operations.

    Args:
        action_type: Type of administrative action being performed

    Returns:
        Decorator function that logs the administrative action
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Record start time for duration tracking
            start_time = datetime.utcnow()

            # Execute the wrapped function
            try:
                result = f(*args, **kwargs)
                status = "success"
                status_code = 200

                # Extract status code from response if it's a tuple
                if isinstance(result, tuple) and len(result) > 1 and isinstance(result[1], int):
                    status_code = result[1]
                    # Consider 4xx/5xx as errors
                    if status_code >= 400:
                        status = "failure"

                return result

            except Exception as e:
                status = "failure"

                # Log and re-raise the exception
                current_app.logger.error(f"Error during admin action {action_type}: {str(e)}")
                raise

            finally:
                # Calculate operation duration
                end_time = datetime.utcnow()
                duration_ms = int((end_time - start_time).total_seconds() * 1000)

                # Extract relevant information for the log
                user_id = g.get('user_id')
                username = getattr(g.user, 'username', 'unknown') if hasattr(g, 'user') else 'unknown'

                # Build details dictionary with allowed request params
                details = {
                    'action': action_type,
                    'status': status,
                    'duration_ms': duration_ms,
                    'endpoint': request.endpoint,
                }

                # Add request parameters (filtered to avoid sensitive data)
                if request.args:
                    filtered_args = {
                        k: '******' if k.lower() in ('token', 'password', 'key', 'secret')
                        else v for k, v in request.args.items()
                    }
                    details['request_args'] = filtered_args

                # Record for target ID if available
                if kwargs and ('id' in kwargs or 'user_id' in kwargs):
                    details['target_id'] = kwargs.get('id', kwargs.get('user_id'))

                # Track operation in audit log
                try:
                    log_security_event(
                        event_type="admin_action",
                        description=f"Administrative action: {action_type}",
                        severity="medium" if status == "success" else "high",
                        user_id=user_id,
                        ip_address=request.remote_addr,
                        details=details
                    )

                    # Update metrics
                    metrics.counter(
                        'admin_api_actions_total',
                        labels={'action': action_type, 'status': status}
                    ).inc()

                    # Record operation duration
                    metrics.histogram(
                        'admin_api_action_duration_seconds',
                        labels={'action': action_type}
                    ).observe(duration_ms / 1000)  # convert to seconds

                except Exception as e:
                    # Don't fail if logging fails
                    current_app.logger.error(f"Failed to log admin action: {str(e)}")

        return cast(F, decorated_function)
    return decorator
