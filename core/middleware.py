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
- File integrity verification
- Access control enforcement
- Audit logging for security events

The middleware functions are registered with the Flask application during initialization
and execute for every request/response cycle, ensuring consistent handling across
all endpoints without duplicating code in individual route handlers.
"""

import base64
import os
import time
import gzip
import uuid
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple, List, Pattern

from flask import g, request, current_app, abort, session, has_app_context, has_request_context
from werkzeug.useragents import UserAgent
from werkzeug.wrappers import Response

# Use the newer security imports following recent changes
try:
    from core.security import (
        log_security_event, generate_csp_nonce as security_generate_csp_nonce,
        check_critical_file_integrity, apply_security_headers,
        detect_suspicious_activity
    )
    USE_SECURITY_MODULE = True
except ImportError:
    # Fall back to legacy import if security module isn't fully available
    from core.security import log_security_event
    USE_SECURITY_MODULE = False

# Import audit log model
try:
    from models.security import AuditLog
except ImportError:
    # Fall back to older path structure
    try:
        from models.security import AuditLog
    except ImportError:
        # Create stub class if unavailable
        class AuditLog:
            EVENT_SECURITY_BREACH_ATTEMPT = "security_breach_attempt"
            EVENT_PERMISSION_DENIED = "permission_denied"
            EVENT_ICS_ACCESS = "ics_access"
            EVENT_FILE_INTEGRITY = "file_integrity"
            EVENT_SUSPICIOUS_ACTIVITY = "suspicious_activity"
            EVENT_API_ABUSE = "api_abuse"


# Precompile regular expressions for performance
SQL_INJECTION_PATTERNS = [
    re.compile(r'(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)'),
    re.compile(r'(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:))'),
    re.compile(r'(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))'),
    re.compile(r'(?i)select\s+.*\s+from'),
    re.compile(r'(?i)insert\s+into\s+.*\s+values'),
    re.compile(r'(?i)delete\s+from'),
    re.compile(r'(?i)drop\s+(table|database)'),
    re.compile(r'(?i)union\s+select')
]

XSS_PATTERNS = [
    re.compile(r'(?i)<[^\w<>]*script'),
    re.compile(r'(?i)javascript\s*:'),
    re.compile(r'(?i)on\w+\s*='),
    re.compile(r'(?i)(?:document|window)\s*\.'),
    re.compile(r'(?i)(alert|confirm|prompt)\s*\('),
    re.compile(r'(?i)eval\s*\(')
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'(?i)\.{2,}[\/\\]'),
    re.compile(r'(?i)\/etc\/(passwd|shadow|hosts)'),
    re.compile(r'(?i)c:\\windows\\system32'),
    re.compile(r'(?i)\/proc\/(self|cpuinfo|meminfo)'),
    re.compile(r'(?i)\/dev\/(null|zero|random)')
]


def setup_security_headers(response: Response) -> Response:
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
    # Use the dedicated security module if available
    if USE_SECURITY_MODULE and has_app_context():
        try:
            return apply_security_headers(response)
        except Exception:
            # Fall back to local implementation if the security module fails
            pass

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
    if has_app_context() and not current_app.debug and not current_app.testing and request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    # Add Cache-Control directives for security-sensitive pages
    if request.path.startswith(('/admin', '/profile', '/account', '/auth', '/api/auth', '/settings')):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    elif not response.cache_control:
        # Default cache control for static assets
        response.headers["Cache-Control"] = "public, max-age=86400"  # 24 hours

    # Clear legacy headers that might be set elsewhere
    response.headers.pop("Server", None)  # Remove server identification
    response.headers.pop("X-Powered-By", None)  # Remove framework identification

    return response


def generate_csp_nonce() -> str:
    """
    Generate a random nonce for Content Security Policy.

    This generates a unique nonce for each request, which allows specific
    inline scripts to be authorized by the Content Security Policy.

    Returns:
        str: Base64-encoded nonce string
    """
    # Use dedicated security function if available
    if USE_SECURITY_MODULE:
        try:
            return security_generate_csp_nonce()
        except Exception:
            # Fall back to local implementation
            pass

    nonce_bytes = os.urandom(16)
    nonce = base64.b64encode(nonce_bytes).decode('utf-8')
    g.csp_nonce = nonce
    return nonce


def generate_request_id() -> str:
    """
    Generate a unique request ID for tracking and security monitoring.

    This function creates a unique identifier that combines:
    - UUID v4 for global uniqueness
    - Timestamp component for chronological sorting
    - Process ID to differentiate between application instances
    - Host identifier to track across distributed systems

    The resulting ID is useful for:
    - Request tracing across microservices
    - Security event correlation
    - Log analysis and filtering
    - Performance monitoring
    - Distributed tracing in cloud environments

    Returns:
        str: Unique request ID in format: 'req-{timestamp}-{uuid}-{host}-{pid}'
    """
    timestamp = int(time.time() * 1000)  # Millisecond precision
    unique_id = uuid.uuid4().hex[:12]    # Use first 12 chars of UUID for brevity
    process_id = os.getpid() % 10000     # Include process ID (truncated)

    # Get a host identifier (first 4 chars of hostname hash)
    try:
        import socket
        hostname = socket.gethostname()
        host_id = hashlib.md5(hostname.encode()).hexdigest()[:4]
    except (OSError, ImportError):
        host_id = "0000"  # Fallback if hostname can't be retrieved

    # Format: req-{timestamp}-{uuid}-{host}-{pid}
    # Example: req-1635789042513-a7de31f8b4c2-1a2b-3478
    request_id = f"req-{timestamp}-{unique_id}-{host_id}-{process_id}"

    return request_id


def track_request_timing() -> None:
    """
    Track request timing and store in Flask g object.

    This middleware records the start time of each request for calculating
    request duration metrics, which are useful for performance monitoring
    and identifying potential DoS vectors.

    The function stores:
    - A unique request ID with embedded timestamp and host information
    - Request start time for performance tracking
    - UTC timestamp for chronological analysis
    - Template context variables for consistent rendering
    """
    # Record timing information
    g.request_start_time = time.time()

    # Use enhanced request ID that includes timestamp, host and process info
    g.request_id = generate_request_id()

    # Store current timestamp in UTC
    g.request_timestamp = datetime.now(timezone.utc)

    # Make request ID available in templates
    g.template_context = {
        'request_id': g.request_id,
        'csp_nonce': getattr(g, 'csp_nonce', generate_csp_nonce())
    }


def _check_pattern_match(value: str, patterns: List[Pattern], key: str, pattern_name: str) -> bool:
    """
    Check if a string matches any of the given patterns.

    Args:
        value: The string to check
        patterns: List of compiled regex patterns
        key: Parameter name for logging
        pattern_name: Type of pattern for logging (e.g. "SQL injection")

    Returns:
        bool: True if a pattern is matched (and security event is logged), False otherwise
    """
    for pattern in patterns:
        if pattern.search(value):
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                description=f"Potential {pattern_name} attempt detected",
                severity="critical",
                ip_address=request.remote_addr,
                details={
                    "parameter": key,
                    "pattern": pattern.pattern,
                    "path": request.path,
                    "method": request.method
                }
            )
            return True
    return False


def check_security_risks() -> None:
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

    # Check URL parameters
    args = request.args.to_dict()
    for key, value in args.items():
        if not isinstance(value, str):
            continue

        # Check for various attack patterns
        if (_check_pattern_match(value, SQL_INJECTION_PATTERNS, key, "SQL injection") or
            _check_pattern_match(value, XSS_PATTERNS, key, "XSS") or
            _check_pattern_match(value, PATH_TRAVERSAL_PATTERNS, key, "path traversal")):
            abort(403)

    # Check form data for POST requests
    if request.method == 'POST' and request.form:
        form_data = request.form.to_dict()
        for key, value in form_data.items():
            # Skip password fields, tokens, and non-string values
            if not isinstance(value, str) or key in ('password', 'token', 'csrf_token', 'new_password', 'current_password'):
                continue

            # Check for SQL injection in form data
            if _check_pattern_match(value, SQL_INJECTION_PATTERNS, key, "SQL injection in form data"):
                abort(403)

    # Check referer for CSRF risk (secondary check in addition to CSRF tokens)
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
                    details={
                        "referer": referer,
                        "host": request.host_url,
                        "path": request.path,
                        "method": request.method
                    }
                )
                # We don't abort here as the CSRF protection will handle it
                # This is just for logging suspicious activity

    # Look for other suspicious activity patterns
    if USE_SECURITY_MODULE and hasattr(detect_suspicious_activity, '__call__'):
        try:
            is_suspicious, activity_type, details = detect_suspicious_activity(request)
            if is_suspicious:
                log_security_event(
                    event_type=AuditLog.EVENT_SUSPICIOUS_ACTIVITY,
                    description=f"Suspicious activity detected: {activity_type}",
                    severity="warning",
                    ip_address=request.remote_addr,
                    details=details
                )
        except Exception:
            # Ignore errors in suspicious activity detection
            pass


def track_user_for_metrics() -> None:
    """
    Track user metrics for the current request.

    This middleware captures information about the user and client for metrics
    collection, including anonymous vs. authenticated users, client platform,
    and API vs. web interface usage.
    """
    # Track if the user is authenticated
    g.is_authenticated = 'user_id' in session

    if g.is_authenticated:
        # Store user ID in g for easier access in other middleware
        g.user_id = session.get('user_id')

        # Track user role if available
        if 'role' in session:
            g.user_role = session.get('role')

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

    # Track request source IP and add to global context
    if request.headers.get('X-Forwarded-For'):
        # If behind proxy, get real client IP
        g.client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        g.client_ip = request.remote_addr

    # Track API version if specified
    if g.is_api_request and 'X-API-Version' in request.headers:
        g.api_version = request.headers.get('X-API-Version')


def compress_response(response: Response) -> Response:
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
        not hasattr(response, 'data') or
        not response.data or
        len(response.data) < 500):  # Don't compress small responses
        return response

    # Check if client accepts gzip
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding.lower():
        return response

    # Compress the response
    try:
        compressed_data = gzip.compress(response.data, compresslevel=6)  # More efficient compression level
    except Exception:
        # Skip compression if any errors occur
        return response

    # Only use compressed data if it's actually smaller
    if len(compressed_data) < len(response.data):
        response.data = compressed_data
        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Content-Length'] = str(len(compressed_data))
        response.headers['Vary'] = 'Accept-Encoding'

    return response


def check_ics_traffic() -> None:
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
            details={"path": request.path, "method": request.method}
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
            details={"path": request.path, "role": user_role, "method": request.method}
        )
        abort(403)

    # Check source IP constraints for production
    if has_app_context() and not current_app.debug and not current_app.testing:
        # Get allowed ICS IPs from config, default to empty list
        allowed_ips = current_app.config.get('ICS_RESTRICTED_IPS', [])

        # If IP restrictions are in place and client IP isn't in the allowed list
        if allowed_ips and request.remote_addr not in allowed_ips:
            log_security_event(
                event_type=AuditLog.EVENT_PERMISSION_DENIED,
                description="Unauthorized IP for ICS access",
                severity="critical",
                user_id=session.get('user_id'),
                ip_address=request.remote_addr,
                details={"path": request.path, "role": user_role, "method": request.method}
            )
            abort(403)

    # Check if MFA is required for ICS operations in production or staging
    if has_app_context() and current_app.config.get('ENVIRONMENT') in ['production', 'staging']:
        if not session.get('mfa_verified', False):
            log_security_event(
                event_type=AuditLog.EVENT_PERMISSION_DENIED,
                description="MFA required for ICS access",
                severity="warning",
                user_id=session.get('user_id'),
                ip_address=request.remote_addr,
                details={"path": request.path, "role": user_role, "method": request.method}
            )
            # Determine if this is an API or web request for appropriate response
            if getattr(g, 'is_api_request', False):
                abort(403, description="MFA verification required for ICS access")
            else:
                from flask import redirect, url_for, flash
                try:
                    flash("Multi-factor authentication required for ICS access", "warning")
                except RuntimeError:
                    pass
                # Store the original URL to redirect back after MFA
                session['mfa_redirect'] = request.full_path
                abort(redirect(url_for('auth.mfa_verify')))

    # Log ICS access as a security event
    log_security_event(
        event_type=AuditLog.EVENT_ICS_ACCESS,
        description=f"ICS endpoint accessed: {request.path}",
        severity="info",
        user_id=session.get('user_id'),
        ip_address=request.remote_addr
    )


def check_file_integrity() -> None:
    """
    Verify file integrity of critical files.

    This middleware periodically checks file integrity to detect unauthorized
    modifications to system files, which could indicate a security breach.
    The check runs on a subset of requests to minimize performance impact.
    """
    # Only check on a small percentage of requests to reduce performance impact
    if not has_app_context() or not current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY', True):
        return

    # Skip for static files, API calls, and AJAX requests to reduce overhead
    if (request.path.startswith(('/static/', '/favicon.ico')) or
        getattr(g, 'is_api_request', False) or
        getattr(g, 'is_ajax', False)):
        return

    # Only check every Nth request (configurable) to reduce performance impact
    check_frequency = current_app.config.get('FILE_INTEGRITY_CHECK_FREQUENCY', 100)

    # Use a pseudo-random approach based on request ID
    request_id_int = int(getattr(g, 'request_id', uuid.uuid4()).hex[:8], 16)
    if request_id_int % check_frequency != 0:
        return

    # Use the security module's integrity checking if available
    if USE_SECURITY_MODULE:
        try:
            integrity_ok, changes = check_critical_file_integrity()
            if not integrity_ok:
                # File integrity violation detected
                log_security_event(
                    event_type=AuditLog.EVENT_FILE_INTEGRITY,
                    description=f"File integrity check failed: {len(changes)} issues detected",
                    severity="critical",
                    details={"changes": changes[:5]}  # Include only first 5 for brevity
                )

                # Update metrics if available
                if has_app_context() and hasattr(current_app, 'metrics'):
                    try:
                        current_app.metrics.gauge('security.integrity.violations', len(changes))
                        current_app.metrics.gauge('security.integrity.status', 0)  # 0 = bad
                    except Exception:
                        pass
            # Don't interfere with the request, just log the event
        except Exception as e:
            # Log errors but don't interrupt the request
            if current_app.logger:
                current_app.logger.error(f"Error during integrity check: {str(e)}")
    else:
        # Fall back to Config class method if security module not available
        try:
            from core.config import Config
            integrity_status = Config.verify_integrity()
            if integrity_status and any(not status for status in integrity_status.values()):
                # File integrity violation detected
                log_security_event(
                    event_type=AuditLog.EVENT_FILE_INTEGRITY,
                    description="File integrity check failed",
                    severity="critical",
                    details={"files": [file for file, status in integrity_status.items() if not status]}
                )
        except ImportError:
            # If no integrity verification is available, skip silently
            pass


def log_request_completion(response: Response) -> Response:
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

        # Add timing header for the client (useful for debugging)
        response.headers['X-Request-Time-Ms'] = str(duration_ms)

        # Log slow requests for investigation with threshold from config
        if has_app_context():
            slow_threshold = current_app.config.get('SLOW_REQUEST_THRESHOLD_MS', 500)
            if duration_ms > slow_threshold:
                # Get user information for context
                user_id = getattr(g, 'user_id', None)
                if not user_id and 'user_id' in session:
                    user_id = session.get('user_id')

                # Create detailed log entry for slow requests
                current_app.logger.warning(
                    f"Slow request: {request.method} {request.path} took {duration_ms}ms",
                    extra={
                        'duration_ms': duration_ms,
                        'method': request.method,
                        'path': request.path,
                        'user_id': user_id,
                        'request_id': getattr(g, 'request_id', None),
                        'status_code': response.status_code
                    }
                )

            # Add response metrics for monitoring
            if hasattr(current_app, 'metrics'):
                try:
                    endpoint = request.endpoint or 'unknown'

                    # Track response time metrics
                    current_app.metrics.histogram(
                        'http.response.time_ms',
                        duration_ms,
                        tags={
                            'path': request.path,
                            'method': request.method,
                            'status': response.status_code,
                            'endpoint': endpoint
                        }
                    )

                    # Track response status code counts
                    current_app.metrics.counter(
                        'http.responses_total',
                        1,
                        tags={
                            'status': response.status_code,
                            'method': request.method,
                            'endpoint': endpoint
                        }
                    )

                except Exception:
                    # Silently ignore metrics errors
                    pass

    return response


def check_api_rate_limits() -> None:
    """
    Check and enforce rate limits for API requests.

    This middleware tracks API usage patterns and triggers alerts or blocks
    requests when abnormal usage patterns are detected.

    Raises:
        Abort: 429 error if rate limit is exceeded
    """
    # Only apply to API requests
    if not getattr(g, 'is_api_request', False):
        return

    # Skip if rate limiting is disabled
    if has_app_context() and not current_app.config.get('API_RATE_LIMIT_ENABLED', True):
        return

    # Get client IP and authenticated user (if available)
    client_ip = getattr(g, 'client_ip', request.remote_addr)
    user_id = getattr(g, 'user_id', None)

    # Check if Redis is available for sophisticated rate limiting
    if has_app_context() and hasattr(current_app, 'redis'):
        try:
            redis_client = current_app.redis

            # Define API endpoint category (for more granular limits)
            path_parts = request.path.strip('/').split('/')
            api_category = path_parts[1] if len(path_parts) > 1 else 'general'

            # Check window-based rate limits (1 minute and 1 hour)
            minute_key = f"ratelimit:1m:{client_ip}:{api_category}"
            hour_key = f"ratelimit:1h:{client_ip}:{api_category}"

            # Get current counts
            minute_count = int(redis_client.get(minute_key) or 0)
            hour_count = int(redis_client.get(hour_key) or 0)

            # Get limits from config or use defaults
            minute_limit = current_app.config.get(f'API_RATE_LIMIT_{api_category.upper()}_MINUTE', 60)
            hour_limit = current_app.config.get(f'API_RATE_LIMIT_{api_category.upper()}_HOUR', 1000)

            # Check if limits exceeded
            if minute_count >= minute_limit or hour_count >= hour_limit:
                # Log rate limit violation
                log_security_event(
                    event_type=AuditLog.EVENT_API_ABUSE,
                    description=f"API rate limit exceeded for {api_category}",
                    severity="warning",
                    user_id=user_id,
                    ip_address=client_ip,
                    details={
                        'minute_count': minute_count,
                        'minute_limit': minute_limit,
                        'hour_count': hour_count,
                        'hour_limit': hour_limit,
                        'path': request.path,
                        'method': request.method
                    }
                )

                # Update metrics
                if hasattr(current_app, 'metrics'):
                    try:
                        current_app.metrics.counter(
                            'security.api.rate_limit_violations',
                            1,
                            tags={
                                'api_category': api_category,
                                'client_ip': client_ip
                            }
                        )
                    except Exception:
                        pass

                # Return 429 Too Many Requests with retry-after header
                response = {
                    'error': 'Too many requests',
                    'message': 'API rate limit exceeded',
                    'retry_after': 60  # seconds
                }
                abort(429, description=response)

            # Increment counters
            pipeline = redis_client.pipeline()
            pipeline.incr(minute_key)
            pipeline.incr(hour_key)

            # Set expiration if keys are new
            pipeline.expire(minute_key, 60)  # 1 minute
            pipeline.expire(hour_key, 3600)  # 1 hour
            pipeline.execute()

        except Exception:
            # If Redis fails, don't block the request
            pass


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
        # Generate CSP nonce for this request (must be first for security)
        generate_csp_nonce()

        # Record request timing information
        track_request_timing()

        # Check for security risks and attacks
        check_security_risks()

        # Enforce API rate limits
        check_api_rate_limits()

        # Monitor ICS traffic
        check_ics_traffic()

        # Track user metrics
        track_user_for_metrics()

        # Periodically check file integrity
        check_file_integrity()

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
