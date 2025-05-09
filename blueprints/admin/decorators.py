"""
Administrative decorators for the Cloud Infrastructure Platform.

This module provides specialized decorators for administrative routes,
implementing required security controls including role verification,
audit logging, and access restriction based on user privileges.

Decorators enforce security through multiple layers:
- Authentication verification
- Role-based authorization
- MFA enforcement for sensitive operations
- Comprehensive audit logging
- Activity metrics tracking
"""

import functools
import logging
from typing import Callable, TypeVar, cast, Optional, Dict, Any

from flask import g, request, redirect, url_for, flash, current_app, abort, session
from werkzeug.exceptions import Forbidden

from extensions import metrics
from core.security import log_security_event
from models.security import AuditLog

# Initialize logger
logger = logging.getLogger(__name__)

# Type variable for decorator functions
F = TypeVar('F', bound=Callable)

def admin_required(f: F) -> F:
    """
    Decorator to restrict access to admin users only.

    Verifies that the current user has the admin role before
    allowing access to the decorated function. Implements
    proper audit logging and metrics tracking.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces admin access
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user exists and has admin role
        if not g.user or not g.user.has_role('admin'):
            # Log unauthorized access attempt
            log_security_event(
                event_type=AuditLog.EVENT_PERMISSION_DENIED,
                description=f"Non-admin user attempted to access admin function: {request.path}",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=getattr(g.user, 'id', None) if hasattr(g, 'user') else None,
                ip_address=request.remote_addr,
                details={
                    'required_role': 'admin',
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )

            # Track metrics for unauthorized access
            metrics.info('admin_authorization_failure_total', 1, labels={
                'required_role': 'admin',
                'endpoint': request.endpoint or 'unknown'
            })

            # Notify user and redirect
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('auth.login', next=request.full_path))

        # Track administrative action
        metrics.info('admin_action_total', 1, labels={
            'endpoint': request.endpoint.split('.')[-1] if request.endpoint else 'unknown',
            'method': request.method
        })

        return f(*args, **kwargs)

    return cast(F, decorated_function)


def super_admin_required(f: F) -> F:
    """
    Decorator to restrict access to super admin users only.

    Verifies that the current user has the super_admin role before
    allowing access to the decorated function. Implements proper
    audit logging and metrics tracking for these high-privilege operations.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces super admin access
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user exists and has super_admin role
        if not g.user or not g.user.has_role('super_admin'):
            # Log unauthorized access attempt with high severity
            log_security_event(
                event_type=AuditLog.EVENT_PERMISSION_DENIED,
                description=f"User attempted to access super admin function: {request.path}",
                severity=AuditLog.SEVERITY_HIGH,
                user_id=getattr(g.user, 'id', None) if hasattr(g, 'user') else None,
                ip_address=request.remote_addr,
                details={
                    'required_role': 'super_admin',
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )

            # Track metrics for unauthorized super admin access
            metrics.info('admin_authorization_failure_total', 1, labels={
                'required_role': 'super_admin',
                'endpoint': request.endpoint or 'unknown'
            })

            # If user is an admin but not super_admin, show specific message
            if hasattr(g, 'user') and g.user.has_role('admin'):
                flash('This action requires super administrator privileges.', 'danger')
                # Return to admin dashboard instead of login page
                return redirect(url_for('admin.dashboard'))

            # Regular users get redirected to login
            flash('You need super administrator privileges to access this page.', 'danger')
            return redirect(url_for('auth.login', next=request.full_path))

        # Track super admin action
        metrics.info('super_admin_action_total', 1, labels={
            'endpoint': request.endpoint.split('.')[-1] if request.endpoint else 'unknown',
            'method': request.method
        })

        # Log high-privilege action
        if request.method != 'GET':
            log_security_event(
                event_type="super_admin_action",
                description=f"Super admin performed action: {request.endpoint}",
                severity=AuditLog.SEVERITY_NOTICE,
                user_id=g.user.id,
                ip_address=request.remote_addr,
                details={
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )

        return f(*args, **kwargs)

    return cast(F, decorated_function)


def auditor_required(f: F) -> F:
    """
    Decorator to restrict access to users with auditor role.

    Verifies that the current user has either the auditor role
    or admin/super_admin roles (which implicitly include auditor privileges).
    Implements proper audit logging and metrics tracking.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces auditor access
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user exists and has appropriate roles
        if not g.user or not (g.user.has_role('auditor') or
                             g.user.has_role('admin') or
                             g.user.has_role('super_admin')):
            # Log unauthorized access attempt
            log_security_event(
                event_type=AuditLog.EVENT_PERMISSION_DENIED,
                description=f"User attempted to access auditor function: {request.path}",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=getattr(g.user, 'id', None) if hasattr(g, 'user') else None,
                ip_address=request.remote_addr,
                details={
                    'required_role': 'auditor',
                    'endpoint': request.endpoint,
                    'path': request.path,
                    'method': request.method
                }
            )

            # Track metrics for unauthorized auditor access
            metrics.info('admin_authorization_failure_total', 1, labels={
                'required_role': 'auditor',
                'endpoint': request.endpoint or 'unknown'
            })

            # Notify user and redirect
            flash('You need auditor privileges to access this page.', 'danger')
            return redirect(url_for('auth.login', next=request.full_path))

        # Track auditor action
        metrics.info('auditor_action_total', 1, labels={
            'endpoint': request.endpoint.split('.')[-1] if request.endpoint else 'unknown',
            'method': request.method
        })

        return f(*args, **kwargs)

    return cast(F, decorated_function)


def require_mfa(f: F) -> F:
    """
    Decorator to require MFA verification for sensitive operations.

    Verifies that the current user has completed MFA verification
    before allowing access to the decorated function.

    Args:
        f: The route handler function to decorate

    Returns:
        Decorated function that enforces MFA verification
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if MFA is enabled and required
        if current_app.config.get('ADMIN_MFA_REQUIRED', True) and not session.get('mfa_verified'):
            # Log MFA requirement
            log_security_event(
                event_type=AuditLog.EVENT_MFA_REQUIRED,
                description=f"MFA required for admin operation: {request.path}",
                severity=AuditLog.SEVERITY_INFO,
                user_id=g.user.id,
                ip_address=request.remote_addr,
                details={'path': request.path, 'method': request.method}
            )

            # Store original destination
            session['mfa_redirect_to'] = request.full_path

            # Redirect to MFA verification
            flash('Multi-factor authentication is required for this operation.', 'warning')
            return redirect(url_for('auth.mfa_verify'))

        return f(*args, **kwargs)

    return cast(F, decorated_function)


def log_admin_action(action_type: str, description: str, status: str = 'success',
                    details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log an administrative action with proper audit trail.

    Creates consistent audit entries for administrative actions
    with appropriate metadata and context information.

    Args:
        action_type: Type of administrative action
        description: Human-readable description of the action
        status: Outcome status (success, failure, etc.)
        details: Additional structured data for the audit log
    """
    user_id = getattr(g.user, 'id', None) if hasattr(g, 'user') else None

    # Create audit log entry
    log_security_event(
        event_type=action_type,
        description=description,
        severity=AuditLog.SEVERITY_INFO,
        user_id=user_id,
        ip_address=request.remote_addr,
        details={
            'status': status,
            **(details or {})
        }
    )

    # Track metrics
    action_name = action_type.split('.')[-1] if '.' in action_type else action_type
    metrics.info('admin_action_logged', 1, labels={
        'action': action_name,
        'status': status
    })
