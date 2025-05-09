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

from flask import Blueprint, g, request, session, Response, current_app, jsonify, abort
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
    Set up request context and verify administrative access.

    This function runs before each request to the admin blueprint. It:
    - Records the request start time for performance measurement
    - Assigns a unique request ID for request tracing
    - Verifies the user has admin privileges
    - Sets up security context for the request
    - Enforces strict session timeout for admin functions
    - Performs MFA verification for sensitive operations
    - Logs administrative access for audit purposes

    Returns:
        None: This function sets up request context as a side effect
        or aborts the request if authorization fails
    """
    g.start_time = datetime.utcnow()
    g.request_id = request.headers.get('X-Request-ID') or f"admin-{time.time()}-{os.urandom(4).hex()}"

    # Establish security context
    g.security_context = {
        'ip_address': get_client_ip(request),
        'user_agent': request.user_agent.string if request.user_agent else 'unknown',
        'referrer': sanitize_header(request.referrer) if request.referrer else 'direct',
        'request_id': g.request_id
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
    if not endpoint_name in ['login', 'auth', 'static']:
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

