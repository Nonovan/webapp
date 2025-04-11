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

from datetime import datetime
from flask import Blueprint, current_app, request, session, g
from extensions import metrics, db

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

    Returns:
        None: This function modifies the Flask g object as a side effect
    """
    g.start_time = datetime.utcnow()
    metrics.info('auth_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })

@auth_bp.app_errorhandler(401)
def unauthorized_error(_error) -> tuple[dict[str, str], int]:
    """
    Handle unauthorized access attempts (HTTP 401).

    This error handler processes 401 Unauthorized responses, which occur
    when authentication credentials are missing or invalid. It logs the
    unauthorized attempt and returns a standardized error response.

    Args:
        _error: The error that triggered this handler (unused but required)

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 401
    """
    current_app.logger.warning(
        'Unauthorized access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id')
        }
    )
    metrics.info('auth_unauthorized_total', 1)
    return {'error': 'Unauthorized access'}, 401

@auth_bp.app_errorhandler(403)
def forbidden_error(_error) -> tuple[dict[str, str], int]:
    """
    Handle forbidden access attempts (HTTP 403).

    This error handler processes 403 Forbidden responses, which occur
    when a user is authenticated but lacks necessary permissions for
    the requested resource. It logs the forbidden access attempt and
    returns a standardized error response.

    Args:
        _error: The error that triggered this handler (unused but required)

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 403
    """
    current_app.logger.warning(
        'Forbidden access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id')
        }
    )
    metrics.info('auth_forbidden_total', 1)
    return {'error': 'Forbidden access'}, 403

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
    if exc:
        db.session.rollback()
        metrics.info('auth_errors_total', 1, labels={
            'type': exc.__class__.__name__
        })
    db.session.remove()

    # Calculate request duration if start time was recorded
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.info('auth_request_duration_seconds', duration, labels={
            'endpoint': request.endpoint
        })
