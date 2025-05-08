"""
Main application blueprint for myproject.

This blueprint provides the primary user interface and core application functionality,
including the home page, cloud services dashboard, ICS application interface, and user
profile management. It serves as the central blueprint for end-user interaction with
the application.

The blueprint implements:
- Primary navigation routes (home, about, cloud dashboard)
- Common layout and template inheritance
- Request tracking and performance monitoring
- Response header management for security and caching
- Centralized error handling for consistent user experience

Request metrics are automatically captured, and responses are enhanced with security
headers, caching directives, and compression for improved performance and security.
"""

from datetime import datetime
import gzip
import uuid
from flask import Blueprint, g, request, session, Response, current_app
from extensions import metrics, db
from .errors import init_error_handlers

# Create the blueprint with proper configuration
main_bp = Blueprint(
    'main',
    __name__,
    template_folder='templates',
    static_folder='static'
)

@main_bp.before_request
def before_request() -> None:
    """
    Set up request context and tracking for main routes.

    This function runs before each request to the main blueprint. It:
    - Records the request start time for performance measurement
    - Assigns a unique request ID for request tracing
    - Increments request metrics counters in Prometheus

    The timing and request ID data are stored in Flask's g object for access
    by other middleware and route handlers.

    Returns:
        None: This function sets up request context as a side effect
    """
    g.start_time = datetime.utcnow()
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))

    # Using the correct method from PrometheusMetrics
    metrics.info('main_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })


@main_bp.after_request
def after_request(response: Response) -> Response:
    """
    Process responses for main routes.

    This function runs after each request to the main blueprint. It:
    - Adds performance metrics about response timing
    - Sets security headers to protect against common web vulnerabilities
    - Adds response metadata (request ID, timing) for debugging
    - Compresses large responses for faster transmission

    Args:
        response (Response): The Flask response object

    Returns:
        Response: The modified response with additional headers and compression
    """
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        # Use info method instead of timing for PrometheusMetrics
        metrics.info('main_response_time', duration, labels={
            'endpoint': request.endpoint,
            'status': response.status_code
        })

        # Add security headers one by one instead of using update
        response.headers['X-Request-ID'] = g.request_id
        response.headers['X-Response-Time'] = f'{duration:.3f}s'

    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # Compress large responses
    if (response.content_length is not None and
        response.content_length > 1024 and
        'gzip' in request.headers.get('Accept-Encoding', '')):
        response.data = gzip.compress(response.data)
        response.headers['Content-Encoding'] = 'gzip'

    return response


@main_bp.teardown_request
def teardown_request(exc) -> None:
    """
    Clean up after request completion.

    This function runs after each request to the main blueprint, regardless of whether
    an exception occurred. It:
    - Rolls back any uncommitted database changes if an error occurred
    - Records metrics about any errors that happened
    - Logs error details for troubleshooting
    - Ensures proper database session cleanup

    Args:
        exc: Exception that was raised during request handling, or None if no exception

    Returns:
        None: This function performs cleanup as a side effect
    """
    if exc is not None:
        try:
            db.session.rollback()
        except Exception as rollback_error:
            current_app.logger.error(f"Error during session rollback: {rollback_error}")

        # Record error metrics
        metrics.info('main_errors_total', 1, labels={
            'type': exc.__class__.__name__,
            'endpoint': request.endpoint or 'unknown'
        })

        # Log error with appropriate context
        current_app.logger.error(
            f"Request error: {exc}",
            extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'path': request.path,
                'method': request.method,
                'error_type': exc.__class__.__name__
            }
        )

    # Always ensure session cleanup
    try:
        db.session.remove()
    except Exception as remove_error:
        current_app.logger.error(f"Error during session cleanup: {remove_error}")


# Initialize error handlers
init_error_handlers(main_bp)


# For improved debugging in development
if current_app and current_app.debug:
    @main_bp.route('/debug-info')
    def debug_info():
        """Return debug information (only available in debug mode)"""
        from flask import jsonify

        # Don't leak sensitive information
        safe_config = {k: v for k, v in current_app.config.items()
                      if not k.startswith(('SECRET', 'API_KEY', 'PASSWORD'))}

        return jsonify({
            'blueprint': main_bp.name,
            'endpoints': list(main_bp.url_map.iter_rules()),
            'version': current_app.config.get('VERSION', 'unknown'),
            'environment': current_app.config.get('ENVIRONMENT', 'development'),
            'debug': current_app.debug,
            'config': safe_config
        })


# Import routes at the bottom to avoid circular imports
from . import routes

# Export module members
__all__ = ['main_bp']
