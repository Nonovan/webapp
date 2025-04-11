"""
Middleware module for request and response processing.

This module provides middleware functions for processing HTTP requests and responses
in the Flask application. It handles cross-cutting concerns such as:

- Security headers for browser protection
- Request tracking and logging
- Response compression and metadata
- API version validation
- Request context management

The middleware functions are registered with the Flask application during initialization
and execute for every request/response cycle, ensuring consistent handling across
all endpoints without duplicating code in individual route handlers.
"""

from datetime import datetime
import gzip
import uuid
from flask import g, request, current_app, abort

def setup_security_headers(response):
    """
    Apply security headers to HTTP responses.

    This middleware adds various security-related HTTP headers to all responses
    to improve browser security and protect against common web vulnerabilities
    including XSS, clickjacking, and MIME type confusion.

    Args:
        response: Flask response object to modify

    Returns:
        The modified response object with security headers

    Example:
        @app.after_request
        def add_security_headers(response):
            return setup_security_headers(response)
    """
    response.headers.update({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-same-origin',
        'Permissions-Policy': 'geolocation=(), camera=()',
        'Access-Control-Allow-Origin': current_app.config.get('ALLOWED_ORIGINS', '*'),
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    })
    return response

def setup_request_context() -> None:
    """
    Initialize request context data.

    This middleware runs at the beginning of each request and sets up
    request-specific context information in Flask's g object, including
    a unique request ID and timing information for performance tracking.

    Returns:
        None: This function modifies the Flask g object as a side effect

    Example:
        @app.before_request
        def before_request():
            setup_request_context()
    """
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()
    g.api_version = request.headers.get('X-API-Version', 'v1')

    # Validate API version
    if not g.api_version in current_app.config['API_VERSIONS']:
        abort(400, 'Invalid API version')

    current_app.logger.info(f'Request {g.request_id}: {request.method} {request.path}')

def setup_response_context(response):
    """
    Process and enhance HTTP responses.

    This middleware runs after a response has been generated but before it's sent
    to the client. It adds response metadata headers, optionally compresses the
    response data, and logs information about the completed request.

    Args:
        response: Flask response object to modify

    Returns:
        The modified response object with additional headers and possibly compression

    Example:
        @app.after_request
        def after_request(response):
            return setup_response_context(response)
    """
    if hasattr(g, 'start_time'):
        elapsed = datetime.utcnow() - g.start_time
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{elapsed.total_seconds():.3f}s',
            'X-API-Version': g.api_version
        })

        # Compression for large responses
        if (response.content_length and response.content_length > 1024
            and 'gzip' in request.headers.get('Accept-Encoding', '')):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

        current_app.logger.info(
            f'Response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)'
        )
    return response
