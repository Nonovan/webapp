"""
Administrative interface blueprint for the Cloud Infrastructure Platform.

This blueprint provides the administration interface for the application, including
system configuration management, user management, security controls, and compliance
reporting. It implements secure administrative functions with strict access controls
and comprehensive audit logging.

Key features:
- User and permission management
- System configuration and settings
- Security policy administration
- Audit log analysis and reporting
- Compliance monitoring and reporting
- File integrity monitoring administration
- Incident response management
- System health monitoring

The admin blueprint enforces strict access controls including role-based permissions,
multi-factor authentication requirements, comprehensive audit logging, and detailed
rate limiting to ensure secure administration of the platform.
"""

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union

from flask import Blueprint, g, request, session, Response, current_app, jsonify, abort, render_template
from werkzeug.exceptions import Forbidden, Unauthorized, BadRequest
from werkzeug.local import LocalProxy

from extensions import metrics, db, cache, limiter
from core.security import log_security_event
from core.security.cs_authentication import is_authenticated, get_current_user_id
from core.security.cs_authorization import require_role
from core.security.cs_utils import get_client_ip, sanitize_header
from models.security import AuditLog

# Initialize logger
logger = logging.getLogger(__name__)

# Create the blueprint with proper configuration
admin_bp = Blueprint(
    'admin',
    __name__,
    url_prefix='/admin',
    template_folder='templates',
    static_folder='static'
)

# Track security context across requests
security_context = LocalProxy(lambda: getattr(g, 'security_context', {}))

# Constants
ADMIN_REQUIRED_ROLE = 'admin'
AUDIT_LOG_RETENTION_DAYS = 90
ADMIN_SESSION_TIMEOUT = 15  # minutes
FILE_INTEGRITY_AVAILABLE = False

# Try to import file integrity features
try:
    from core.security.cs_file_integrity import check_integrity, get_integrity_summary, update_file_integrity_baseline
    FILE_INTEGRITY_AVAILABLE = True
except ImportError:
    logger.debug("File integrity monitoring not available in admin blueprint")


@admin_bp.before_request
def before_request() -> None:
    """
    Enforce authentication and authorization for all admin routes.

    Performs the following security checks:
    1. Ensures the user is authenticated
    2. Verifies the user has admin role
    3. Enforces MFA for sensitive operations
    4. Checks for session timeout
    5. Logs all administrative access

    Aborts with appropriate HTTP status codes on security violations.
    """
    # Record request start time for performance monitoring
    g.start_time = datetime.utcnow()

    # Setup security context for the request
    g.security_context = {
        'ip_address': get_client_ip(request),
        'user_agent': sanitize_header(request.user_agent.string) if request.user_agent else 'unknown',
        'referer': sanitize_header(request.referrer) if request.referrer else 'direct',
        'request_id': getattr(g, 'request_id', None)
    }

    # Track metrics
    endpoint_name = request.endpoint.split('.')[-1] if request.endpoint else 'unknown'
    metrics.info('admin_requests_total', 1, labels={
        'method': request.method,
        'endpoint': endpoint_name,
        'path': request.path
    })

    # Enforce admin access with audit logging for all admin endpoints
    # Skip authorization check for login routes if they exist in this blueprint
    if endpoint_name not in ['login', 'auth', 'static']:
        if not is_authenticated():
            log_security_event(
                event_type=AuditLog.EVENT_UNAUTHORIZED_ACCESS,
                description="Unauthenticated user attempted to access admin blueprint",
                severity=AuditLog.SEVERITY_WARNING,
                ip_address=g.security_context['ip_address'],
                details={'path': request.path, 'method': request.method}
            )
            metrics.info('admin_unauthorized_access_total', 1)
            abort(401)

        # Verify administrator role
        user_id = get_current_user_id()
        try:
            from models.auth import User, Role
            user = User.query.get(user_id)
            if not user or not user.has_role(ADMIN_REQUIRED_ROLE):
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Non-admin user attempted to access admin blueprint: {user_id}",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=user_id,
                    ip_address=g.security_context['ip_address'],
                    details={'path': request.path, 'method': request.method}
                )
                metrics.info('admin_permission_denied_total', 1)
                abort(403)

            # Enforce MFA for sensitive operations if configured
            if current_app.config.get('ADMIN_MFA_REQUIRED', True):
                # Check specific paths or operations that are particularly sensitive
                is_sensitive_path = any(p in request.path for p in [
                    '/security', '/users', '/roles', '/system', '/config',
                    '/baseline', '/audit', '/integrity'
                ])
                is_state_changing = request.method in ['POST', 'PUT', 'PATCH', 'DELETE']

                if (is_sensitive_path or is_state_changing) and not session.get('mfa_verified'):
                    log_security_event(
                        event_type=AuditLog.EVENT_MFA_REQUIRED,
                        description=f"MFA required for admin operation: {request.path}",
                        severity=AuditLog.SEVERITY_INFO,
                        user_id=user_id,
                        ip_address=g.security_context['ip_address'],
                        details={'path': request.path, 'method': request.method}
                    )
                    return jsonify({
                        'error': 'MFA required',
                        'message': 'Multi-factor authentication required for this operation',
                        'code': 'mfa_required'
                    }), 403

            # Check for session timeout for admin functions
            if 'last_active' in session:
                last_active = datetime.fromisoformat(session['last_active'])
                timeout_minutes = current_app.config.get('ADMIN_SESSION_TIMEOUT', ADMIN_SESSION_TIMEOUT)

                if (datetime.utcnow() - last_active).total_seconds() > (timeout_minutes * 60):
                    # Session timed out, clear session and require re-authentication
                    session.clear()
                    log_security_event(
                        event_type=AuditLog.EVENT_SESSION_TIMEOUT,
                        description="Admin session timed out due to inactivity",
                        severity=AuditLog.SEVERITY_INFO,
                        user_id=user_id,
                        ip_address=g.security_context['ip_address']
                    )
                    abort(401)

        except Exception as e:
            logger.error(f"Error during admin authorization: {str(e)}")
            abort(500)

        # Log admin access for sensitive operations
        is_read_only = request.method == 'GET'
        audit_severity = AuditLog.SEVERITY_INFO if is_read_only else AuditLog.SEVERITY_NOTICE

        log_security_event(
            event_type=AuditLog.EVENT_ADMIN_ACCESS,
            description=f"Admin access to {request.path}",
            severity=audit_severity,
            user_id=user_id,
            ip_address=g.security_context['ip_address'],
            details={
                'path': request.path,
                'method': request.method,
                'endpoint': endpoint_name
            }
        )


@admin_bp.after_request
def after_request(response: Response) -> Response:
    """
    Process response before returning it to the client.

    Adds security headers, performance metrics, and other post-processing
    to all responses from the admin blueprint.

    Args:
        response: The Flask response object

    Returns:
        Response: The processed response
    """
    # Add security headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Set strict CSP for admin pages
    csp = current_app.config.get('ADMIN_CSP', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:")
    response.headers['Content-Security-Policy'] = csp

    # Set cache policy to prevent caching of admin pages
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'

    # Record response time
    if hasattr(g, 'start_time'):
        duration_ms = (datetime.utcnow() - g.start_time).total_seconds() * 1000
        endpoint = request.endpoint.split('.')[-1] if request.endpoint else 'unknown'
        metrics.timing('admin_response_time_ms', duration_ms, labels={
            'endpoint': endpoint,
            'method': request.method,
            'status': response.status_code
        })

    return response


@admin_bp.teardown_request
def teardown_request(exception: Optional[Exception]) -> None:
    """
    Clean up resources after request processing.

    Performs necessary cleanup operations, error logging,
    and resource management at the end of each request.

    Args:
        exception: Exception raised during request processing, if any
    """
    # Log any exceptions that occurred
    if exception:
        logger.error(f"Error during admin request: {str(exception)}")

        # Track error metrics
        metrics.info('admin_request_errors', 1, labels={
            'error_type': type(exception).__name__,
            'endpoint': request.endpoint.split('.')[-1] if request.endpoint else 'unknown',
            'method': request.method
        })

    # Ensure database session is cleaned up
    if db:
        try:
            db.session.remove()
        except Exception as e:
            logger.error(f"Error cleaning up database session: {str(e)}")


@admin_bp.route('/')
def dashboard():
    """Admin dashboard showing system overview and recent activity."""
    from .routes import dashboard
    return dashboard()


@admin_bp.errorhandler(Forbidden)
def handle_forbidden(error):
    """Handle 403 Forbidden errors with proper logging."""
    log_security_event(
        event_type=AuditLog.EVENT_PERMISSION_DENIED,
        description="Admin access forbidden",
        severity=AuditLog.SEVERITY_WARNING,
        ip_address=g.security_context['ip_address'],
        details={'path': request.path, 'method': request.method}
    )
    if request.is_xhr or request.accept_mimetypes.best == 'application/json':
        return jsonify({
            'success': False,
            'error': 'forbidden',
            'message': 'You do not have permission to access this resource'
        }), 403
    return render_template('admin/errors/403.html'), 403


@admin_bp.errorhandler(Unauthorized)
def handle_unauthorized(error):
    """Handle 401 Unauthorized errors with proper logging."""
    log_security_event(
        event_type=AuditLog.EVENT_UNAUTHORIZED_ACCESS,
        description="Unauthorized access attempt to admin area",
        severity=AuditLog.SEVERITY_WARNING,
        ip_address=g.security_context['ip_address'],
        details={'path': request.path, 'method': request.method}
    )
    if request.is_xhr or request.accept_mimetypes.best == 'application/json':
        return jsonify({
            'success': False,
            'error': 'unauthorized',
            'message': 'Authentication required'
        }), 401
    return render_template('admin/errors/401.html'), 401


def init_app(app):
    """
    Initialize the admin blueprint with the Flask application.

    Args:
        app: Flask application instance
    """
    from .routes import register_routes

    # Register rate limiting for admin routes
    limiter.limit(app.config.get('ADMIN_RATE_LIMIT', '60/minute'))(admin_bp)

    # Register blueprint routes
    register_routes(admin_bp)

    # Register error handlers
    for code in [400, 404, 500]:
        admin_bp.errorhandler(code)(handle_error)

    # Initialize audit logging
    if hasattr(app, 'config'):
        app.config.setdefault('ADMIN_AUDIT_RETENTION_DAYS', AUDIT_LOG_RETENTION_DAYS)

    logger.info("Admin blueprint initialized")


def handle_error(error):
    """Generic error handler for HTTP errors."""
    status_code = error.code if hasattr(error, 'code') else 500

    # Log all server errors (5xx)
    if status_code >= 500:
        logger.error(f"Server error in admin blueprint: {error}", exc_info=True)

    # Return JSON for API requests
    if request.is_xhr or request.accept_mimetypes.best == 'application/json':
        return jsonify({
            'success': False,
            'error': type(error).__name__,
            'message': str(error)
        }), status_code

    # Return HTML for browser requests
    return render_template(f'admin/errors/{status_code}.html', error=error), status_code


# Version information
__version__ = '0.1.1'
