"""
Error handling module for the main blueprint.

This module provides centralized error handling for the main blueprint, ensuring
consistent error responses across different routes and error types. It implements
handlers for common HTTP error codes and application-specific exceptions.

Key features:
- JSON vs HTML responses based on request content type
- Standardized error logging with context information
- Metrics collection for error monitoring
- Database error handling with transaction rollback
- Network error handling with retry information
- Security event logging for suspicious errors
- Consistent error templates with proper status codes

Error handlers are registered with the blueprint during initialization and
provide both user-friendly error pages and structured API error responses
depending on the client's Accept header.
"""

from datetime import datetime
from typing import Dict, Any, Optional, Tuple, Union

from flask import Blueprint, request, jsonify, g, session, render_template, current_app
import json
import random
import traceback
from sqlalchemy.exc import SQLAlchemyError, DBAPIError, TimeoutError as SQLAlchemyTimeoutError
from werkzeug.exceptions import HTTPException

from extensions import db, metrics
from core.security import log_security_event, check_critical_file_integrity
from core.security.cs_authentication import _is_api_request

def log_error(error, level='error', context=None) -> None:
    """
    Log an error with context information.

    This function provides standardized error logging with consistent formatting
    and contextual information to aid in troubleshooting and monitoring.

    Args:
        error: The error object containing code and message
        level: Log level to use (default: 'error')
        context: Optional context information to include in log

    Returns:
        None: This function logs information as a side effect

    Example:
        log_error(error, level='warning', context={'user_id': 123})
    """
    # Extract error code from various error types
    if hasattr(error, 'code'):
        error_code = error.code
    elif hasattr(error, 'status_code'):
        error_code = error.status_code
    else:
        error_code = 500  # Default to internal server error

    # Build context dictionary with request information
    log_context = {
        'url': request.url,
        'method': request.method,
        'ip': request.remote_addr,
        'user_agent': str(request.user_agent),
        'timestamp': datetime.utcnow().isoformat()
    }

    # Add user ID if available
    if hasattr(g, 'user') and hasattr(g.user, 'id'):
        log_context['user_id'] = g.user.id
    elif 'user_id' in session:
        log_context['user_id'] = session['user_id']

    # Add transaction ID if available
    if hasattr(g, 'transaction_id'):
        log_context['transaction_id'] = g.transaction_id

    # Merge with provided context if any
    if context:
        log_context.update(context)

    # Format the log message
    log_message = f'Error {error_code}: {request.url} - {error}'

    # Use appropriate logger method based on level
    logger = current_app.logger
    getattr(logger, level)(log_message, extra=log_context)

    # Record metric using the metrics API
    metrics.info(f'error_{error_code}', 1, labels={
        'path': request.path,
        'method': request.method,
        'user_agent_type': _categorize_user_agent(request.user_agent.string)
    })

    # For server errors (5xx), log security event to audit log
    if error_code >= 500:
        try:
            log_security_event(
                event_type='server_error',
                description=f"Server error {error_code} occurred: {str(error)}",
                severity='error',
                details=log_context
            )

            # For critical errors, verify file integrity
            # to detect potential security incidents
            if error_code >= 500 and level == 'error':
                _verify_integrity_after_error(error)

        except Exception as e:
            # Don't let security logging itself cause further errors
            logger.warning(f"Failed to log security event: {e}")

def _categorize_user_agent(user_agent: str) -> str:
    """Categorize user agent for metrics aggregation."""
    user_agent_lower = user_agent.lower()
    if 'mozilla' in user_agent_lower or 'chrome' in user_agent_lower or 'safari' in user_agent_lower:
        return 'browser'
    elif 'curl' in user_agent_lower or 'wget' in user_agent_lower:
        return 'cli'
    elif 'python' in user_agent_lower or 'requests' in user_agent_lower:
        return 'script'
    elif 'postman' in user_agent_lower:
        return 'api_tool'
    elif 'bot' in user_agent_lower or 'spider' in user_agent_lower or 'crawler' in user_agent_lower:
        return 'bot'
    else:
        return 'other'

def _verify_integrity_after_error(error) -> None:
    """Verify file integrity after a server error to detect tampering."""
    try:
        integrity_status, modified_files = check_critical_file_integrity()
        if not integrity_status and modified_files:
            current_app.logger.critical(
                "File integrity violation detected after server error",
                extra={
                    'modified_files': modified_files,
                    'original_error': str(error),
                    'error_type': error.__class__.__name__
                }
            )
            # Log security event for potential tampering
            log_security_event(
                event_type='file_integrity_violation',
                description="Critical file integrity violation after server error",
                severity='critical',
                details={
                    'modified_files': modified_files,
                    'original_error': str(error)
                }
            )
    except Exception as e:
        # Don't let integrity checking cause further errors
        current_app.logger.warning(f"Failed to check file integrity: {e}")

def init_error_handlers(blueprint: Blueprint) -> Blueprint:
    """
    Initialize error handlers for the blueprint.

    This function registers error handlers for common HTTP status codes
    and configures metrics collection for error monitoring. It handles
    both API requests (returning JSON) and browser requests (returning HTML).

    Args:
        blueprint (Blueprint): The Flask blueprint to register handlers with

    Returns:
        Blueprint: The blueprint with error handlers registered

    Example:
        blueprint = Blueprint('main', __name__)
        init_error_handlers(blueprint)
    """
    # Register error metrics
    metrics.register_default(
        metrics.counter(
            'flask_error_total',
            'Total number of HTTP errors',
            labels={
                'code': lambda: request.view_args.get('code'),
                'path': lambda: request.path,
                'method': lambda: request.method,
                'user_id': lambda: session.get('user_id', 'anonymous')
            }
        )
    )

    metrics.register_default(
        metrics.histogram(
            'flask_error_response_time_seconds',
            'Error response time in seconds',
            labels={
                'code': lambda: request.view_args.get('code'),
                'path': lambda: request.path
            }
        )
    )

    @blueprint.errorhandler(400)
    def bad_request_error(error) -> tuple:
        """
        Handle Bad Request (400) errors.

        Handles invalid client requests, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'warning')
        if _is_api_request():
            return jsonify({
                'error': 'Bad request',
                'message': str(error),
                'code': 400
            }), 400
        return render_template('errors/400.html', error=error), 400

    @blueprint.errorhandler(401)
    def unauthorized_error(error) -> tuple:
        """
        Handle Unauthorized (401) errors.

        Handles authentication failures, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'warning', {
            'auth_header': request.headers.get('Authorization', None)
        })

        if _is_api_request():
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Authentication required',
                'code': 401
            }), 401
        return render_template('errors/401.html', error=error), 401

    @blueprint.errorhandler(403)
    def forbidden_error(error) -> tuple:
        """
        Handle Forbidden (403) errors.

        Handles authorization failures, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        user_id = getattr(g, 'user_id', None) or session.get('user_id', None)

        log_error(error, 'warning', {
            'user_id': user_id,
            'required_role': getattr(error, 'required_role', None)
        })

        # Log security event for access control failures
        try:
            log_security_event(
                event_type='permission_denied',
                description=f"Access denied to {request.path}",
                severity='warning',
                user_id=user_id,
                details={
                    'path': request.path,
                    'method': request.method,
                    'required_role': getattr(error, 'required_role', None)
                }
            )
        except Exception as e:
            current_app.logger.warning(f"Failed to log security event: {e}")

        if _is_api_request():
            return jsonify({
                'error': 'Forbidden',
                'message': 'You do not have permission to access this resource',
                'code': 403
            }), 403

        # Pass required_role to template if available
        template_params = {'error': error}
        if hasattr(error, 'required_role'):
            template_params['required_role'] = error.required_role

        return render_template('errors/403.html', **template_params), 403

    @blueprint.errorhandler(404)
    def not_found_error(error) -> tuple:
        """
        Handle Not Found (404) errors.

        Handles missing resource errors, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'warning')

        # Track 404 errors for security monitoring (potential path scanning)
        if not request.path.endswith(('.css', '.js', '.ico', '.png', '.jpg', '.gif')):
            metrics.info('not_found_errors', 1, labels={
                'path': request.path,
                'ip': request.remote_addr,
                'referer': request.referrer or 'none'
            })

        if _is_api_request():
            return jsonify({
                'error': 'Not found',
                'message': 'The requested resource does not exist',
                'code': 404
            }), 404
        return render_template('errors/404.html', error=error, path=request.path), 404

    @blueprint.errorhandler(405)
    def method_not_allowed_error(error) -> tuple:
        """
        Handle Method Not Allowed (405) errors.

        Handles requests with unsupported HTTP methods, returning appropriate
        format based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'warning', {
            'method': request.method,
            'allowed_methods': error.valid_methods if hasattr(error, 'valid_methods') else None
        })

        headers = {}
        if hasattr(error, 'valid_methods') and error.valid_methods:
            headers['Allow'] = ", ".join(error.valid_methods)

        if _is_api_request():
            return jsonify({
                'error': 'Method not allowed',
                'message': f'The {request.method} method is not allowed for this resource',
                'allowed_methods': error.valid_methods if hasattr(error, 'valid_methods') else None,
                'code': 405
            }), 405, headers
        return render_template('errors/405.html', error=error), 405, headers

    @blueprint.errorhandler(429)
    def too_many_requests_error(error) -> tuple:
        """
        Handle Too Many Requests (429) errors.

        Handles rate limiting errors, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'warning', {
            'ip': request.remote_addr
        })

        # Include standard rate limiting headers
        headers = {
            'Retry-After': '60'  # 60 seconds
        }

        # Log potential abuse for high-volume rate limit violations
        try:
            log_security_event(
                event_type='rate_limit_exceeded',
                description=f"Rate limit exceeded for {request.path}",
                severity='warning',
                details={
                    'path': request.path,
                    'method': request.method,
                    'ip': request.remote_addr
                }
            )
        except Exception:
            pass

        if _is_api_request():
            return jsonify({
                'error': 'Too many requests',
                'message': 'Rate limit exceeded. Please try again later.',
                'retry_after': 60,
                'code': 429
            }), 429, headers
        return render_template('errors/429.html', error=error, retry=60), 429, headers

    @blueprint.errorhandler(500)
    def internal_error(error) -> tuple:
        """
        Handle Internal Server Error (500) errors.

        Handles server-side errors, returning appropriate format
        based on whether the request expects JSON or HTML. Also
        performs database transaction rollback for safety.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'error')

        # Safely rollback any pending database transactions
        try:
            db.session.rollback()
        except Exception as rollback_error:
            current_app.logger.error(f"Error during rollback: {rollback_error}")

        # Generate a unique error reference for support inquiries
        error_ref = _generate_error_reference()

        if _is_api_request():
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred',
                'reference': error_ref,
                'code': 500
            }), 500
        return render_template('errors/500.html',
                             error=error,
                             error_reference=error_ref), 500

    @blueprint.errorhandler(502)
    def bad_gateway_error(error) -> tuple:
        """
        Handle Bad Gateway (502) errors.

        Handles errors from upstream services, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'error')

        if _is_api_request():
            return jsonify({
                'error': 'Bad gateway',
                'message': 'Received an invalid response from an upstream server',
                'code': 502
            }), 502
        return render_template('errors/502.html', error=error), 502

    @blueprint.errorhandler(503)
    def service_unavailable_error(error) -> tuple:
        """
        Handle Service Unavailable (503) errors.

        Handles temporary unavailability, returning appropriate format
        based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'error')
        if _is_api_request():
            return jsonify({
                'error': 'Service unavailable',
                'message': 'The service is temporarily unavailable',
                'code': 503
            }), 503
        return render_template('errors/503.html'), 503

    @blueprint.errorhandler(504)
    def gateway_timeout_error(error) -> tuple:
        """
        Handle Gateway Timeout (504) errors.

        Handles timeout errors from upstream services, returning appropriate
        format based on whether the request expects JSON or HTML.

        Args:
            error: The error object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'error')

        # Include standard timeout headers
        headers = {
            'Retry-After': '120'  # 2 minutes
        }

        if _is_api_request():
            return jsonify({
                'error': 'Gateway timeout',
                'message': 'The server timed out while waiting for an upstream service',
                'retry_after': 120,
                'code': 504
            }), 504, headers
        return render_template('errors/504.html', retry=120), 504, headers

    @blueprint.errorhandler(SQLAlchemyError)
    def database_error(error) -> tuple:
        """
        Handle SQLAlchemy database errors.

        Provides specific handling for database-related errors with
        appropriate rollbacks and user-friendly messages.

        Args:
            error: The database error object

        Returns:
            tuple: Response and status code
        """
        # Handle database error with rollback and logging
        log_error(error, 'error')
        try:
            db.session.rollback()
        except Exception as rollback_error:
            current_app.logger.error(f"Error during rollback: {rollback_error}")

        if _is_api_request():
            return jsonify({
                'error': 'Database error',
                'message': 'An error occurred while processing your request',
                'code': 500
            }), 500
        return render_template('errors/500.html', error=error), 500

    @blueprint.errorhandler(Exception)
    def unhandled_exception(error) -> tuple:
        """
        Handle all unhandled exceptions.

        This is a catch-all handler for any exceptions not handled by
        more specific handlers, providing graceful degradation.

        Args:
            error: The exception object

        Returns:
            tuple: Response and status code
        """
        log_error(error, 'critical', {
            'exception_type': error.__class__.__name__,
            'stack_trace': traceback.format_exc()
        })

        # Check file integrity
        _verify_integrity_after_error(error)

        # Generate a unique error reference for support inquiries
        error_ref = _generate_error_reference()

        if _is_api_request():
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred',
                'reference': error_ref,
                'code': 500
            }), 500
        return render_template('errors/500.html',
                              error=error,
                              error_reference=error_ref), 500

    return blueprint


def _generate_error_reference() -> str:
    """
    Generate a unique error reference for support inquiries.

    This function creates a unique, readable error reference code
    that can be used for support tickets and error tracking.

    Returns:
        str: Unique error reference code
    """
    # Generate a timestamp component in format YYMMDD-HHMMSS
    timestamp = datetime.utcnow().strftime('%y%m%d-%H%M%S')

    # Generate a random component (4 characters)
    alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'  # Removed confusing characters
    random_part = ''.join(random.choice(alphabet) for _ in range(4))

    # Build the reference with a prefix
    return f"ERR-{timestamp}-{random_part}"


def handle_api_error_response(error: Exception, status_code: int = 500,
                             headers: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, Any], int, Dict[str, str]]:
    """
    Create a standardized API error response.

    This function generates a consistent JSON error response for API endpoints,
    following the project's API standards.

    Args:
        error: The error that occurred
        status_code: HTTP status code to return (default: 500)
        headers: Optional additional headers

    Returns:
        tuple: Tuple containing (response_dict, status_code, headers)

    Example:
        return handle_api_error_response(error, 400, {'X-Custom': 'Value'})
    """
    # Default headers if none provided
    if headers is None:
        headers = {}

    # Create a standardized error response
    response = {
        'status': 'error',
        'error': {
            'code': status_code,
            'message': str(error),
            'type': error.__class__.__name__,
            'timestamp': datetime.utcnow().isoformat()
        }
    }

    # Add request ID if available
    if hasattr(g, 'request_id'):
        response['error']['request_id'] = g.request_id

    # Add error reference for server errors
    if status_code >= 500:
        response['error']['reference'] = _generate_error_reference()

    # Add retry information for certain status codes
    if status_code in (429, 503, 504):
        retry_seconds = headers.get('Retry-After', '60')
        response['retry_after'] = int(retry_seconds)

    return jsonify(response), status_code, headers


def register_custom_error_handlers(app) -> None:
    """
    Register custom error handlers for application-specific exceptions.

    This function registers handlers for custom exceptions beyond the
    standard HTTP errors, allowing for graceful handling of business
    logic exceptions.

    Args:
        app: Flask application instance

    Example:
        register_custom_error_handlers(app)
    """
    # Import here to avoid circular imports
    from core.exceptions import (
        ValidationError, ResourceNotFoundError,
        AuthorizationError, RateLimitExceededError,
        ConfigurationError, ServiceUnavailableError
    )

    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle validation errors."""
        log_error(error, 'warning')
        if _is_api_request():
            return handle_api_error_response(error, 400)
        return render_template('errors/400.html', error=error), 400

    @app.errorhandler(ResourceNotFoundError)
    def handle_not_found_error(error):
        """Handle resource not found errors."""
        log_error(error, 'warning')
        if _is_api_request():
            return handle_api_error_response(error, 404)
        return render_template('errors/404.html', error=error), 404

    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(error):
        """Handle authorization errors."""
        log_error(error, 'warning')
        if _is_api_request():
            return handle_api_error_response(error, 403)
        return render_template('errors/403.html', error=error), 403

    @app.errorhandler(RateLimitExceededError)
    def handle_rate_limit_error(error):
        """Handle rate limit exceeded errors."""
        log_error(error, 'warning')
        headers = {'Retry-After': str(error.retry_after) if hasattr(error, 'retry_after') else '60'}
        if _is_api_request():
            return handle_api_error_response(error, 429, headers)
        return render_template('errors/429.html', error=error, retry=headers['Retry-After']), 429, headers

    @app.errorhandler(ConfigurationError)
    def handle_configuration_error(error):
        """Handle application configuration errors."""
        log_error(error, 'critical')
        if _is_api_request():
            return handle_api_error_response(error, 500)
        return render_template('errors/500.html', error=error), 500

    @app.errorhandler(ServiceUnavailableError)
    def handle_service_unavailable_error(error):
        """Handle service unavailable errors."""
        log_error(error, 'error')
        headers = {'Retry-After': '60'}
        if _is_api_request():
            return handle_api_error_response(error, 503, headers)
        return render_template('errors/503.html', retry=60), 503, headers


def track_error_analytics(error: Exception, code: int) -> None:
    """
    Track error analytics for monitoring and improvement.

    This function records error occurrences for analysis to help
    identify trends and areas for improvement in the application.

    Args:
        error: The error that occurred
        code: HTTP status code associated with the error

    Example:
        track_error_analytics(error, 500)
    """
    try:
        # Record basic error metrics
        error_type = error.__class__.__name__
        endpoint = request.endpoint or 'unknown'

        metrics.info('error_tracking', 1, labels={
            'type': error_type,
            'code': code,
            'endpoint': endpoint,
            'path': request.path,
            'method': request.method
        })

        # Track in Redis for real-time analytics if available
        redis_client = current_app.extensions.get('redis')
        if redis_client:
            day_key = datetime.utcnow().strftime('analytics:errors:%Y-%m-%d')

            # Increment error counters
            redis_client.hincrby(day_key, f'total', 1)
            redis_client.hincrby(day_key, f'code:{code}', 1)
            redis_client.hincrby(day_key, f'type:{error_type}', 1)
            redis_client.hincrby(day_key, f'endpoint:{endpoint}', 1)

            # Set expiration for analytics keys (7 days)
            redis_client.expire(day_key, 60 * 60 * 24 * 7)

            # Add to real-time error monitoring list (limited to 100 entries)
            if code >= 500:
                error_data = json.dumps({
                    'time': datetime.utcnow().isoformat(),
                    'type': error_type,
                    'code': code,
                    'path': request.path,
                    'message': str(error)[:200]  # Limit message length
                })
                redis_client.lpush('monitoring:recent_errors', error_data)
                redis_client.ltrim('monitoring:recent_errors', 0, 99)  # Keep only 100 most recent
    except Exception as e:
        # Don't let analytics tracking cause failures
        current_app.logger.warning(f"Error tracking analytics: {e}")
