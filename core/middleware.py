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

import base64
import os
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
    """
    # Define a comprehensive Content Security Policy
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://cdn.plot.ly", 
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
        "frame-src 'self' https://www.google.com/recaptcha/",
        "connect-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "integrity-src 'self'"
    ]

    # Add nonce to script-src directive if available
    if hasattr(g, 'csp_nonce'):
        csp_directives[1] = f"script-src 'self' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://cdn.plot.ly 'nonce-{g.csp_nonce}'"

    # Combine directives and set as one header
    csp_header = '; '.join(csp_directives)

    response.headers.update({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': csp_header,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-same-origin',
        'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=()',
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
    
    # Generate a CSP nonce for each request
    g.csp_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')

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
        request_id = getattr(g, 'request_id', str(uuid.uuid4()))
        api_version = getattr(g, 'api_version', 'v1')
        
        # Add standard headers
        response.headers.update({
            'X-Request-ID': request_id,
            'X-Response-Time': f'{elapsed.total_seconds():.3f}s',
            'X-API-Version': api_version
        })

        # Record response metrics
        if hasattr(current_app, 'extensions') and 'prometheus_metrics' in current_app.extensions:
            metrics = current_app.extensions['prometheus_metrics']
            metrics.info('response_time_seconds', elapsed.total_seconds(), labels={
                'endpoint': request.endpoint or 'unknown',
                'method': request.method,
                'status': response.status_code
            })
            
            # Track response sizes
            if response.content_length:
                metrics.info('response_size_bytes', response.content_length, labels={
                    'endpoint': request.endpoint or 'unknown',
                    'method': request.method
                })

        # Compression for large responses
        if (response.content_length and response.content_length > 1024
            and 'gzip' in request.headers.get('Accept-Encoding', '')):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

        # Log successful responses at INFO level, errors at appropriate levels
        if response.status_code >= 500:
            log_level = 'error'
            from models.audit_log import AuditLog
            # Record server errors in audit log
            try:
                AuditLog.create(
                    event_type='server_error',
                    description=f"Server error {response.status_code} on {request.method} {request.path}",
                    user_id=g.get('user_id'),
                    ip_address=request.remote_addr,
                    severity='error'
                )
            except (ValueError, RuntimeError) as e:
                current_app.logger.error(f"Failed to log server error to audit log: {e}")
                
        elif response.status_code >= 400:
            log_level = 'warning'
        else:
            log_level = 'info'
        
        # Log with appropriate level
        getattr(current_app.logger, log_level)(
            f'Response {request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)',
            extra={
                'request_id': request_id,
                'status_code': response.status_code,
                'response_time': elapsed.total_seconds(),
                'endpoint': request.endpoint,
                'path': request.path,
                'user_id': g.get('user_id'),
                'ip_address': request.remote_addr
            }
        )
        
        # Add timing information to security monitoring
        if 'monitoring_bp' in current_app.blueprints and response.status_code >= 400:
            try:
                # Track unusual response patterns
                from models.audit_log import AuditLog
                if response.status_code == 401:
                    # Unauthorized access attempts
                    AuditLog.create(
                        event_type=AuditLog.EVENT_PERMISSION_DENIED,
                        description=f"Unauthorized access attempt to {request.path}",
                        user_id=g.get('user_id'),
                        ip_address=request.remote_addr,
                        severity='warning'
                    )
                elif response.status_code == 403:
                    # Forbidden access attempts
                    AuditLog.create(
                        event_type=AuditLog.EVENT_PERMISSION_DENIED,
                        description=f"Forbidden access attempt to {request.path}",
                        user_id=g.get('user_id'),
                        ip_address=request.remote_addr,
                        severity='warning'
                    )
                elif response.status_code == 429:
                    # Rate limit exceeded
                    AuditLog.create(
                        event_type='rate_limit_exceeded',
                        description=f"Rate limit exceeded for {request.path}",
                        user_id=g.get('user_id'),
                        ip_address=request.remote_addr,
                        severity='warning'
                    )
            except (ValueError, RuntimeError) as e:
                current_app.logger.error(f"Failed to create audit log for response: {e}")
    
    return response
