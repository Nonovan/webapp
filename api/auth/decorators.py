"""
Authentication and security decorators for API routes.

This module provides decorator functions that implement various security controls
for API authentication and authorization, including:
- JWT token validation
- API key validation
- Session verification
- MFA enforcement
- Role and permission checks
- Rate limiting wrappers

These decorators follow security best practices with proper error handling,
logging, and metrics collection for comprehensive security monitoring.
"""

import functools
from datetime import datetime
from typing import Callable, Dict, List, Optional, TypeVar, Union, Any, cast

from flask import request, jsonify, current_app, g
from sqlalchemy.exc import SQLAlchemyError

from core.security import is_suspicious_ip, log_security_event
from extensions import metrics, db
from models import AuditLog
from services import AuthService

# Define a type variable for decorators
F = TypeVar('F', bound=Callable)


def token_required(f: F) -> F:
    """
    Decorator to validate JWT token for protected API routes.

    This decorator checks that a valid JWT token exists in the request headers,
    validates it, and makes the authenticated user available in the request context.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces JWT authentication
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Get auth header
        auth_header = request.headers.get('Authorization')

        # Check if token exists in header
        if not auth_header or not auth_header.startswith('Bearer '):
            log_security_event(
                event_type=AuditLog.EVENT_API_AUTH_FAILED,
                description="Missing or invalid authorization header",
                severity="warning",
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )
            metrics.increment('security.api_auth_failed')
            return jsonify({"error": "Authorization required", "code": "AUTH_REQUIRED"}), 401

        # Extract token
        token = auth_header.split(' ')[1]

        # Validate token
        is_valid, user, error_message = AuthService.verify_api_token(token)

        if not is_valid:
            log_security_event(
                event_type=AuditLog.EVENT_API_AUTH_FAILED,
                description="Invalid token: " + (error_message or "Unknown error"),
                severity="warning",
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )
            metrics.increment('security.token_invalid')
            return jsonify({"error": error_message or "Invalid token", "code": "INVALID_TOKEN"}), 401

        # Store user in request context
        g.user = user
        g.user_id = user.id
        g.authenticated_via = 'token'

        # Check for suspicious IP
        if is_suspicious_ip(request.remote_addr):
            log_security_event(
                event_type=AuditLog.EVENT_SUSPICIOUS_ACCESS,
                description=f"API access from suspicious IP: {request.remote_addr}",
                severity="warning",
                user_id=user.id,
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )
            metrics.increment('security.suspicious_ip_access')
            # We continue to allow access but log the suspicious activity

        return f(*args, **kwargs)

    return cast(F, decorated)


def require_api_role(role: Union[str, List[str]]) -> Callable[[F], F]:
    """
    Decorator to restrict API route access based on user role.

    This decorator ensures users have one of the specified roles
    before allowing access to the decorated function.

    Args:
        role: Role name or list of role names required for access

    Returns:
        Decorator function that checks for required role(s)
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        @token_required
        def decorated_function(*args, **kwargs):
            roles = [role] if isinstance(role, str) else role

            if not hasattr(g, 'user') or not g.user:
                return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

            if not any(g.user.has_role(r) for r in roles):
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Role required: {roles}",
                    severity="warning",
                    user_id=g.user.id,
                    ip_address=request.remote_addr,
                    details={
                        'required_role': roles,
                        'user_role': g.user.role,
                        'endpoint': request.endpoint
                    }
                )
                metrics.increment('security.role_permission_denied')
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS"
                }), 403

            return f(*args, **kwargs)
        return cast(F, decorated_function)
    return decorator


def require_api_permission(permission: str) -> Callable[[F], F]:
    """
    Decorator to restrict API route access based on user permission.

    This decorator ensures users have the specified permission
    before allowing access to the decorated function.

    Args:
        permission: Permission name required for access

    Returns:
        Decorator function that checks for required permission
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        @token_required
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user') or not g.user:
                return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

            if not g.user.has_permission(permission):
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Permission required: {permission}",
                    severity="warning",
                    user_id=g.user.id,
                    ip_address=request.remote_addr,
                    details={
                        'required_permission': permission,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )
                metrics.increment('security.api_permission_denied')
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS"
                }), 403

            return f(*args, **kwargs)
        return cast(F, decorated_function)
    return decorator


def require_api_mfa(f: F = None) -> F:
    """
    Decorator to enforce MFA verification for sensitive API operations.

    This decorator checks if the user has completed MFA verification
    within the current session before allowing access to protected API routes.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces MFA verification
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        @token_required
        def decorated_function(*args, **kwargs):
            # Check if MFA is required by config
            if not current_app.config.get('ENABLE_MFA', False):
                return f(*args, **kwargs)

            user = g.user

            # Check if MFA is required for this user's role
            mfa_required_roles = current_app.config.get('MFA_REQUIRED_ROLES', [])
            if user.role not in mfa_required_roles and not user.mfa_enabled:
                return f(*args, **kwargs)

            # Check if MFA is verified in current session
            if not g.get('mfa_verified') and not request.headers.get('X-MFA-Token'):
                log_security_event(
                    event_type='mfa_required',
                    description="API MFA verification required for sensitive operation",
                    severity='info',
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    details={
                        'endpoint': request.endpoint,
                        'path': request.path,
                        'method': request.method
                    }
                )
                metrics.increment('security.api_mfa_required')
                return jsonify({
                    "error": "MFA verification required",
                    "code": "MFA_REQUIRED",
                    "message": "Multi-factor authentication required for this operation"
                }), 403

            # If MFA token is provided in header, verify it
            mfa_token = request.headers.get('X-MFA-Token')
            if mfa_token:
                # Verify the token
                if not AuthService.verify_totp_code(user.mfa_secret, mfa_token):
                    log_security_event(
                        event_type='mfa_verification_failed',
                        description="API MFA verification failed",
                        severity='warning',
                        user_id=user.id,
                        ip_address=request.remote_addr
                    )
                    metrics.increment('security.api_mfa_verification_failed')
                    return jsonify({
                        "error": "Invalid MFA token",
                        "code": "INVALID_MFA_TOKEN"
                    }), 401

                # Mark MFA as verified
                g.mfa_verified = True

            return f(*args, **kwargs)

        # If called with @require_api_mfa
        if f:
            return decorated_function

        # If called with @require_api_mfa()
        return decorated_function

    # Handle both @require_api_mfa and @require_api_mfa() syntax
    if f:
        return decorator(f)
    return decorator


def track_api_activity(activity_type: str, description: Optional[str] = None) -> Callable[[F], F]:
    """
    Decorator to track API activity for security auditing.

    Records detailed activity logs for API operations to assist with
    security monitoring, troubleshooting, and compliance reporting.

    Args:
        activity_type: Type of activity to record
        description: Optional description template for the activity

    Returns:
        Decorator function that logs the API activity
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the wrapped function first
            result = f(*args, **kwargs)

            # Extract user information for logging
            user_id = getattr(g, 'user_id', None)

            # Skip if not authenticated
            if user_id is None:
                return result

            # Generate activity description
            activity_desc = description
            if activity_desc is None:
                activity_desc = f"API {activity_type} operation on {request.path}"

            # Record the activity
            try:
                from models.user_activity import UserActivity

                UserActivity.log_activity(
                    user_id=user_id,
                    activity_type=activity_type,
                    details={
                        'path': request.path,
                        'method': request.method,
                        'endpoint': request.endpoint,
                        'ip_address': request.remote_addr,
                        'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else None
                    }
                )

                # Commit the transaction
                db.session.commit()

            except SQLAlchemyError as e:
                current_app.logger.error(f"Failed to log API activity: {e}")
                db.session.rollback()
            except Exception as e:
                current_app.logger.error(f"Error tracking API activity: {e}")

            return result
        return cast(F, decorated_function)
    return decorator


def validate_session(f: F) -> F:
    """
    Decorator to validate web session for API routes that support session auth.

    This decorator checks if a valid session exists for routes that can be accessed
    either via API token or web session, making it useful for endpoints shared
    between the web UI and API clients.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that validates the session
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Check for API authorization header first
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # Use token_required decorator instead
            return token_required(f)(*args, **kwargs)

        # Validate session
        is_valid, error_message = AuthService.validate_session()

        if not is_valid:
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_ERROR,
                description=error_message or "Invalid session",
                severity="warning",
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )
            metrics.increment('security.api_session_invalid')
            return jsonify({
                "error": "Authentication required",
                "code": "SESSION_INVALID"
            }), 401

        return f(*args, **kwargs)

    return cast(F, decorated)


def audit_api_action(action_type: str, severity: str = "info") -> Callable[[F], F]:
    """
    Decorator to audit security-relevant API actions.

    Records detailed security audit logs for sensitive operations with
    configurable severity levels.

    Args:
        action_type: Type of action being performed
        severity: Severity level for the audit log (info, warning, critical)

    Returns:
        Decorator function that logs the security event
    """
    def decorator(f: F) -> F:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the wrapped function first
            result = f(*args, **kwargs)

            # Extract user information for logging
            user_id = getattr(g, 'user_id', None)

            # Create audit log
            try:
                description = f"API {action_type} action on {request.path}"

                log_security_event(
                    event_type=action_type,
                    description=description,
                    severity=severity,
                    user_id=user_id,
                    ip_address=request.remote_addr,
                    details={
                        'endpoint': request.endpoint,
                        'path': request.path,
                        'method': request.method,
                        'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else None
                    }
                )

            except Exception as e:
                current_app.logger.error(f"Failed to create audit log: {e}")

            return result
        return cast(F, decorated_function)
    return decorator
