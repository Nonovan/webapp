"""
Authentication blueprint package for myproject.

This blueprint handles all authentication-related functionality including:
- User login and logout flows
- Session management
- Authentication error handling
- Security metrics collection

The package provides the auth_bp Blueprint with request hooks for security
monitoring, metrics tracking, and proper cleanup after each request. It implements
appropriate error handlers for authentication-related HTTP status codes such as
401 Unauthorized and 403 Forbidden to provide consistent error responses.

Request metrics are automatically collected to track authentication attempts,
failures, and patterns for security monitoring purposes.
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, Union

from flask import Blueprint, current_app, request, session, g, jsonify, render_template
from werkzeug.exceptions import Unauthorized, Forbidden

from extensions import metrics, db, cache, limiter
from extensions.circuit_breaker import CircuitOpenError, RateLimitExceededError
from core.security import log_security_event
from core.security.cs_authentication import is_request_secure
from core import generate_request_id
from models.security import AuditLog

# Initialize module-level logger
logger = logging.getLogger(__name__)

auth_bp = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    template_folder='templates'
)

@auth_bp.before_request
def before_request() -> None:
    """
    Set up request context data for authentication routes.

    This function runs before each request to auth blueprint routes.
    It performs the following tasks:
    - Records the start time for performance tracking
    - Increments authentication request metrics with user context
    - Sets request ID for traceability
    - Enforces HTTPS for production environments
    - Validates request headers for security

    Returns:
        None: This function modifies the Flask g object as a side effect

    Raises:
        Unauthorized: If request contains suspicious security headers
    """
    g.start_time = datetime.utcnow()

    # Generate or retrieve request ID for tracing
    g.request_id = request.headers.get('X-Request-ID', generate_request_id())

    # Track metrics for this request
    metrics.info('auth_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })

    # Enforce HTTPS in production
    if current_app.config.get('ENV') == 'production' and not is_request_secure(request):
        logger.warning(
            'Insecure authentication request rejected',
            extra={'url': request.url, 'ip': request.remote_addr}
        )
        raise Unauthorized("Authentication requires secure connection")

    # Check for suspicious headers that might indicate request forgery
    if _contains_suspicious_headers(request.headers):
        log_security_event(
            event_type=AuditLog.EVENT_SUSPICIOUS_REQUEST,
            description=f"Suspicious authentication request detected from {request.remote_addr}",
            severity=AuditLog.SEVERITY_WARNING,
            user_id=session.get('user_id'),
            ip_address=request.remote_addr,
            details={
                'headers': {k: v for k, v in request.headers.items()
                           if k.lower() not in ('cookie', 'authorization')},
                'path': request.path,
                'method': request.method
            }
        )
        metrics.info('auth_suspicious_request_total', 1)


def _contains_suspicious_headers(headers: Dict[str, str]) -> bool:
    """
    Check request headers for suspicious patterns.

    Args:
        headers: HTTP request headers dictionary

    Returns:
        bool: True if suspicious patterns detected, False otherwise
    """
    suspicious_patterns = [
        # Unusual proxy chains that might be trying to obfuscate source
        lambda h: len(h.getlist('X-Forwarded-For', type=str)) > 3,

        # Mismatch between forwarded protocol and actual protocol
        lambda h: h.get('X-Forwarded-Proto') == 'https' and request.scheme == 'http',

        # Suspicious user agent strings known to be used in attacks
        lambda h: any(x in h.get('User-Agent', '').lower()
                    for x in ['sqlmap', 'nikto', 'nessus', 'burp', 'openvas'])
    ]

    return any(pattern(headers) for pattern in suspicious_patterns)


@auth_bp.after_request
def after_request(response):
    """
    Process response data after each authentication request.

    This function adds security headers and performs other post-processing
    tasks on responses to authentication requests.

    Args:
        response: Flask response object

    Returns:
        Response: Modified Flask response
    """
    # Add security headers for auth routes
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(), payment=()'

    # Add cache control directives for sensitive auth pages
    if request.endpoint in ['auth.login', 'auth.reset_password', 'auth.mfa_verify',
                          'auth.register', 'auth.change_password', 'auth.confirm_password']:
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response


@auth_bp.app_errorhandler(401)
def unauthorized_error(_error) -> Union[Tuple[Dict[str, Any], int], Tuple[str, int]]:
    """
    Handle unauthorized access attempts (HTTP 401).

    This error handler processes 401 Unauthorized responses, which occur
    when authentication credentials are missing or invalid. It logs the
    unauthorized attempt and returns a standardized error response.

    Args:
        _error: The error that triggered this handler (unused but required)

    Returns:
        tuple: Either JSON response with 401 status or HTML template with 401 status
               depending on request Accept header
    """
    current_app.logger.warning(
        'Unauthorized access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id'),
            'request_id': g.get('request_id', 'unknown')
        }
    )

    # Log security event for audit trail
    log_security_event(
        event_type=AuditLog.EVENT_UNAUTHORIZED_ACCESS,
        description=f"Unauthorized access attempt to {request.path}",
        severity=AuditLog.SEVERITY_WARNING,
        user_id=session.get('user_id'),
        ip_address=request.remote_addr,
        details={
            'url': request.path,
            'method': request.method,
            'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else None,
        },
        category=AuditLog.EVENT_CATEGORY_AUTH
    )

    metrics.info('auth_unauthorized_total', 1)

    # Return appropriate response format based on request
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Unauthorized access',
            'code': 401,
            'message': 'Authentication is required to access this resource'
        }), 401
    else:
        return render_template('auth/errors/401.html'), 401


@auth_bp.app_errorhandler(403)
def forbidden_error(_error) -> Union[Tuple[Dict[str, Any], int], Tuple[str, int]]:
    """
    Handle forbidden access attempts (HTTP 403).

    This error handler processes 403 Forbidden responses, which occur
    when a user is authenticated but lacks necessary permissions for
    the requested resource. It logs the forbidden access attempt and
    returns a standardized error response.

    Args:
        _error: The error that triggered this handler (unused but required)

    Returns:
        tuple: Either JSON response with 403 status or HTML template with 403 status
               depending on request Accept header
    """
    current_app.logger.warning(
        'Forbidden access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id'),
            'request_id': g.get('request_id', 'unknown'),
            'endpoint': request.endpoint
        }
    )

    # Log security event for audit and compliance
    log_security_event(
        event_type=AuditLog.EVENT_PERMISSION_DENIED,
        description=f"Permission denied for {request.path}",
        severity=AuditLog.SEVERITY_WARNING,
        user_id=session.get('user_id'),
        ip_address=request.remote_addr,
        details={
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path
        },
        category=AuditLog.EVENT_CATEGORY_ACCESS
    )

    metrics.info('auth_forbidden_total', 1, labels={
        'endpoint': request.endpoint
    })

    # Return appropriate response format based on request
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Forbidden access',
            'code': 403,
            'message': 'You do not have permission to access this resource'
        }), 403
    else:
        return render_template('auth/errors/403.html'), 403


@auth_bp.errorhandler(CircuitOpenError)
def handle_circuit_open_error(error):
    """
    Handle circuit breaker errors to provide user-friendly responses.

    Returns:
        Rendered error template with proper message
    """
    current_app.logger.warning(f"Circuit breaker error: {str(error)}")
    metrics.info('auth_circuit_breaker_trips_total', 1, labels={
        'circuit': getattr(error, 'circuit_name', 'unknown')
    })

    log_security_event(
        event_type="circuit_breaker_trip",
        description=f"Authentication circuit breaker tripped",
        severity=AuditLog.SEVERITY_WARNING,
        details={
            "circuit_name": getattr(error, 'circuit_name', 'unknown'),
            "endpoint": request.endpoint,
            "error": str(error)
        }
    )

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Service temporarily unavailable',
            'code': 503,
            'retry_after': 60  # Suggest retry after 1 minute
        }), 503

    flash_message = "The authentication service is temporarily unavailable. Please try again later."

    if 'awaiting_mfa' in session and session['awaiting_mfa']:
        return redirect(url_for('auth.login'))

    return render_template('auth/errors/service_unavailable.html',
                          message=flash_message), 503


@auth_bp.errorhandler(RateLimitExceededError)
def handle_rate_limit_exceeded_error(error):
    """
    Handle rate limit exceeded errors to provide user-friendly responses.

    Returns:
        Rendered error template with proper message
    """
    current_app.logger.warning(f"Rate limit exceeded: {str(error)}")
    metrics.info('auth_rate_limit_exceeded_total', 1, labels={
        'endpoint': request.endpoint
    })

    # Extract retry_after information if available
    retry_after = getattr(error, 'retry_after', 60)

    # Add to security audit log
    log_security_event(
        event_type=AuditLog.EVENT_RATE_LIMIT,
        description=f"Rate limit exceeded on auth endpoint: {request.endpoint}",
        severity=AuditLog.SEVERITY_WARNING,
        ip_address=request.remote_addr,
        details={
            'endpoint': request.endpoint,
            'method': request.method,
            'retry_after': retry_after
        },
        category=AuditLog.EVENT_CATEGORY_SECURITY
    )

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Rate limit exceeded',
            'code': 429,
            'retry_after': retry_after
        }), 429, {'Retry-After': str(retry_after)}

    flash_message = "You've made too many requests. Please wait a moment before trying again."
    return render_template('auth/errors/rate_limit.html',
                          message=flash_message,
                          retry_seconds=retry_after), 429, {'Retry-After': str(retry_after)}


@auth_bp.teardown_request
def teardown_request(exc) -> None:
    """
    Clean up resources after each authentication request.

    This function runs after each request to auth blueprint routes, regardless
    of whether an exception was raised. It performs error tracking for failed
    requests and ensures database sessions are properly managed.

    Args:
        exc: Exception that occurred during request handling, or None if no exception

    Returns:
        None: This function performs cleanup as a side effect
    """
    # Handle database cleanup for exceptions
    if exc:
        db.session.rollback()

        # Track error metrics with specific labels
        metrics.info('auth_errors_total', 1, labels={
            'type': exc.__class__.__name__,
            'endpoint': request.endpoint or 'unknown'
        })

        # Log security-related exceptions specifically
        if isinstance(exc, (Unauthorized, Forbidden)) or 'csrf' in str(exc).lower():
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_ERROR,
                description=f"Authentication error: {str(exc)}",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=session.get('user_id'),
                ip_address=request.remote_addr,
                details={
                    'exception_type': exc.__class__.__name__,
                    'endpoint': request.endpoint
                },
                category=AuditLog.EVENT_CATEGORY_AUTH
            )

    # Always remove db session
    db.session.remove()

    # Calculate and record request duration
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.info('auth_request_duration_seconds', duration, labels={
            'endpoint': request.endpoint,
            'method': request.method,
            'status': int(request.environ.get('werkzeug.request_exception') is not None)
        })


# Ensure Flask imports these correctly
from flask import flash, redirect, url_for
import flask
