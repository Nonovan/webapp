"""
Middleware module for request and response processing.

This module provides middleware functions for processing HTTP requests and responses
in the Flask application. It handles cross-cutting concerns such as:

- Security headers for browser protection
- Request tracking and logging
- Response compression and metadata
- API version validation
- Request context management
- Security monitoring and anomaly detection
- Attack mitigation measures
- ICS/SCADA traffic monitoring

The middleware functions are registered with the Flask application during initialization
and execute for every request/response cycle, ensuring consistent handling across
all endpoints without duplicating code in individual route handlers.
"""

import base64
import os
import time
import gzip
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import g, request, current_app, abort, session
from werkzeug.useragents import UserAgent

from core.security_utils import log_security_event
from models.audit_log import AuditLog


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
    # Check if CSP nonce is in the global context
    csp_nonce = getattr(g, 'csp_nonce', None)
    nonce_directive = f" 'nonce-{csp_nonce}'" if csp_nonce else ""

    # Define a comprehensive Content Security Policy
    csp_directives = [
        "default-src 'self'",
        f"script-src 'self' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://cdn.plot.ly{nonce_directive}", 
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
        "frame-src 'self' https://www.google.com/recaptcha/",
        "connect-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",  # Stronger than X-Frame-Options
        "object-src 'none'",
        "require-trusted-types-for 'script'",  # Modern browsers only
        "upgrade-insecure-requests",
    ]

    # Apply security headers
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

    # HSTS: Strict Transport Security - only in production and if using HTTPS
    if not current_app.debug and not current_app.testing and request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    # Add Cache-Control directives for security-sensitive pages
    if request.path.startswith(('/admin', '/profile', '/account', '/auth', '/api/auth')):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    elif not response.cache_control:
        # Default cache control for static assets
        response.headers["Cache-Control"] = "public, max-age=86400"  # 24 hours

    # Clear legacy headers that might be set elsewhere
    response.headers.pop("Server", None)  # Remove server identification
    response.headers.pop("X-Powered-By", None)  # Remove framework identification

    return response


def generate_csp_nonce():
    """
    Generate a random nonce for Content Security Policy.
    
    This generates a unique nonce for each request, which allows specific
    inline scripts to be authorized by the Content Security Policy.
    
    Returns:
        str: Base64-encoded nonce string
    """
    nonce_bytes = os.urandom(16)
    nonce = base64.b64encode(nonce_bytes).decode('utf-8')
    g.csp_nonce = nonce
    return nonce


def track_request_timing():
    """
    Track request timing and store in Flask g object.
    
    This middleware records the start time of each request for calculating
    request duration metrics, which are useful for performance monitoring
    and identifying potential DoS vectors.
    """
    g.request_start_time = time.time()
    g.request_id = str(uuid.uuid4())

    # Store current timestamp in UTC
    g.request_timestamp = datetime.now(timezone.utc)

    # Make request ID available in templates
    if hasattr(g, 'request_id'):
        g.template_context = {
            'request_id': g.request_id,
            'csp_nonce': getattr(g, 'csp_nonce', generate_csp_nonce())
        }


def check_security_risks():
    """
    Check for security risks in the request.
    
    This middleware examines incoming requests for signs of attacks or abuse,
    including SQL injection attempts, XSS, path traversal, and other common
    web attack vectors.
    
    Raises:
        Abort: 403 error if potential attack is detected
    """
    # Skip checks for static files to improve performance
    if request.path.startswith(('/static/', '/favicon.ico')):
        return

    # Define patterns that might indicate attacks
    sql_injection_patterns = ['SELECT ', 'UNION ', 'INSERT ', 'DELETE ', 'DROP ', '--', '/*', '*/']
    xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', 'eval(']
    path_traversal_patterns = ['../', '..\\', '/etc/passwd', '/proc/self']

    # Check URL parameters
    args = request.args.to_dict()
    for key, value in args.items():
        if not isinstance(value, str):
            continue

        value_lower = value.lower()

        # Check for SQL injection
        if any(pattern.lower() in value_lower for pattern in sql_injection_patterns):
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                description="Potential SQL injection attempt detected",
                severity="critical",
                ip_address=request.remote_addr,
                details=f"Suspicious parameter: {key}={value}"
            )
            abort(403)

        # Check for XSS attempts
        if any(pattern.lower() in value_lower for pattern in xss_patterns):
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                description="Potential XSS attempt detected",
                severity="critical",
                ip_address=request.remote_addr,
                details=f"Suspicious parameter: {key}={value}"
            )
            abort(403)

        # Check for path traversal
        if any(pattern.lower() in value_lower for pattern in path_traversal_patterns):
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                description="Potential path traversal attempt detected",
                severity="critical",
                ip_address=request.remote_addr,
                details=f"Suspicious parameter: {key}={value}"
            )
            abort(403)

    # Check referer for CSRF risk (when not using the CSRF protection)
    # This is a secondary check in addition to CSRF tokens
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        referer = request.headers.get('Referer')
        if referer:
            parsed_referer = urlparse(referer)
            parsed_host = urlparse(request.host_url)
            if parsed_referer.netloc and parsed_referer.netloc != parsed_host.netloc:
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                    description="Potential CSRF attempt detected",
                    severity="warning",
                    ip_address=request.remote_addr,
                    details=f"Suspicious referer: {referer}, Host: {request.host_url}"
                )
                # We don't abort here as the CSRF protection will handle it
                # This is just for logging suspicious activity


def track_user_for_metrics():
    """
    Track user metrics for the current request.
    
    This middleware captures information about the user and client for metrics
    collection, including anonymous vs. authenticated users, client platform,
    and API vs. web interface usage.
    """
    # Track if the user is authenticated
    g.is_authenticated = 'user_id' in session

    # Record user agent details
    user_agent = UserAgent(request.user_agent.string)
    g.user_agent = {
        'browser': user_agent.browser,
        'platform': user_agent.platform,
        'is_mobile': user_agent.platform in ['android', 'iphone', 'ipad']
    }

    # Determine if request is for API or web interface
    g.is_api_request = request.path.startswith('/api/')

    # Check if this is an AJAX/fetch request
    g.is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def compress_response(response):
    """
    Compress HTTP responses to reduce bandwidth usage.
    
    This middleware compresses responses if the client supports compression
    and the response isn't already compressed, which improves performance for
    clients, especially on slower connections.
    
    Args:
        response: Flask response object
        
    Returns:
        The compressed response if applicable, or the original response
    """
    # Skip compression for certain conditions
    if (response.status_code < 200 or
        response.status_code >= 300 or
        'Content-Encoding' in response.headers or
        not response.data or
        len(response.data) < 500):  # Don't compress small responses
        return response

    # Check if client accepts gzip
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding.lower():
        return response

    # Compress the response
    compressed_data = gzip.compress(response.data)

    # Only use compressed data if it's actually smaller
    if len(compressed_data) < len(response.data):
        response.data = compressed_data
        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Content-Length'] = str(len(compressed_data))
        response.headers['Vary'] = 'Accept-Encoding'

    return response


def check_ics_traffic():
    """
    Specialized industrial control system (ICS) traffic monitoring.
    
    This middleware monitors and controls access to ICS-related endpoints,
    enforcing stricter security measures for these sensitive operations.
    """
    # Only apply to ICS-related endpoints
    if not request.path.startswith('/ics/') and '/api/ics/' not in request.path:
        return

    # Validate authorization for ICS operations
    if 'user_id' not in session:
        log_security_event(
            event_type=AuditLog.EVENT_PERMISSION_DENIED,
            description="Unauthorized ICS access attempt",
            severity="error",
            ip_address=request.remote_addr,
            details=f"Anonymous user attempted to access ICS endpoint: {request.path}"
        )
        abort(403)

    # Check user role for ICS operations
    user_role = session.get('role', '')
    if user_role not in ['admin', 'operator']:
        log_security_event(
            event_type=AuditLog.EVENT_PERMISSION_DENIED,
            description="Insufficient privileges for ICS access",
            severity="error",
            user_id=session.get('user_id'),
            ip_address=request.remote_addr,
            details=f"User with role {user_role} attempted to access ICS endpoint: {request.path}"
        )
        abort(403)

    # Log ICS access as a security event
    log_security_event(
        event_type=AuditLog.EVENT_ICS_ACCESS,
        description=f"ICS endpoint accessed: {request.path}",
        severity="info",
        user_id=session.get('user_id'),
        ip_address=request.remote_addr
    )


def log_request_completion(response):
    """
    Log request completion with timing information.
    
    This middleware calculates the request duration and logs details about
    completed requests, which is useful for performance monitoring, debugging,
    and identifying slow endpoints.
    
    Args:
        response: Flask response object
    
    Returns:
        The unchanged response object
    """
    # Skip logging for static files
    if request.path.startswith(('/static/', '/favicon.ico')):
        return response

    # Calculate request duration
    start_time = getattr(g, 'request_start_time', None)
    if start_time:
        duration_ms = int((time.time() - start_time) * 1000)

        # Log slow requests for investigation
        if duration_ms > 500:  # More than 500ms is considered slow
            current_app.logger.warning(
                f"Slow request: {request.method} {request.path} took {duration_ms}ms",
                extra={
                    'duration_ms': duration_ms,
                    'method': request.method,
                    'path': request.path,
                    'user_id': getattr(g, 'user_id', None),
                    'request_id': getattr(g, 'request_id', None)
                }
            )

        # Add timing header for the client (useful for debugging)
        response.headers['X-Request-Time-Ms'] = str(duration_ms)

    return response


def init_middleware(app):
    """
    Initialize and register all middleware with the Flask application.
    
    This function sets up before_request, after_request, and template_context_processor
    handlers to apply the middleware functions at the appropriate points in the
    request/response lifecycle.
    
    Args:
        app: Flask application instance
    """
    @app.before_request
    def before_request_middleware():
        # Generate CSP nonce for this request
        generate_csp_nonce()

        # Record request timing information
        track_request_timing()

        # Security checks
        check_security_risks()

        # Monitor ICS traffic
        check_ics_traffic()

        # Track user metrics
        track_user_for_metrics()

    @app.after_request
    def after_request_middleware(response):
        # Apply security headers
        response = setup_security_headers(response)

        # Compress response if applicable
        response = compress_response(response)

        # Log request completion
        response = log_request_completion(response)

        return response

    @app.context_processor
    def inject_template_context():
        """Inject variables into template context."""
        context = getattr(g, 'template_context', {})
        # Always provide CSP nonce for templates
        if 'csp_nonce' not in context:
            context['csp_nonce'] = getattr(g, 'csp_nonce', '')
        return context
