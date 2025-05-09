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
- Real-time file integrity monitoring for critical resources
- Adaptive security controls based on threat environment
- Context-aware performance optimization

Request metrics are automatically captured, and responses are enhanced with security
headers, caching directives, and compression for improved performance and security.
"""

import logging
from datetime import datetime
import gzip
import json
import os
import uuid
from typing import Optional, Dict, Any, Union, Tuple

from flask import Blueprint, g, request, session, Response, current_app, abort
from werkzeug.local import LocalProxy

from extensions import metrics, db, cache, limiter
from core.security.cs_authentication import is_authenticated, get_current_user_id
from core.security.cs_monitoring import register_route_monitoring
from core.security.cs_utils import get_client_ip, sanitize_header
from .errors import init_error_handlers

# Initialize logger
logger = logging.getLogger(__name__)

# Create the blueprint with proper configuration
main_bp = Blueprint(
    'main',
    __name__,
    template_folder='templates',
    static_folder='static'
)

# Track security context across requests
security_context = LocalProxy(lambda: getattr(g, 'security_context', {}))

@main_bp.before_request
def before_request() -> None:
    """
    Set up request context and tracking for main routes.

    This function runs before each request to the main blueprint. It:
    - Records the request start time for performance measurement
    - Assigns a unique request ID for request tracing
    - Increments request metrics counters in Prometheus
    - Sets up security context for the request
    - Performs basic request validation
    - Updates user activity timestamp if authenticated

    The timing and request ID data are stored in Flask's g object for access
    by other middleware and route handlers.

    Returns:
        None: This function sets up request context as a side effect
    """
    # Basic request setup
    g.start_time = datetime.utcnow()

    # Use existing request ID from headers if present (for tracing across services)
    # Otherwise generate a new one
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))

    # Determine user for metrics labeling
    user_id = get_current_user_id()
    g.user_id = user_id

    # Using info method from PrometheusMetrics for metrics
    metrics.info('main_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint or 'unknown',
        'user_id': str(user_id) if user_id else 'anonymous',
        'path': request.path.split('/')[1] or 'root'  # First path segment for aggregation
    })

    # Set up security context for the request
    g.security_context = {
        'ip_address': get_client_ip(),
        'user_agent': sanitize_header(request.user_agent.string if request.user_agent else 'unknown'),
        'referrer': sanitize_header(request.referrer) if request.referrer else 'direct',
        'is_authenticated': is_authenticated(),
        'is_secure': request.is_secure,
        'timestamp': datetime.utcnow().isoformat()
    }

    # Check for suspicious user agent patterns
    if _contains_suspicious_patterns(request):
        metrics.info('suspicious_request_total', 1, labels={'reason': 'pattern_match'})
        logger.warning(
            "Suspicious request pattern detected",
            extra={
                'request_id': g.request_id,
                'ip': g.security_context['ip_address'],
                'path': request.path,
                'ua': g.security_context['user_agent'][:100]  # Truncate long user agents
            }
        )

    # Update user's last activity timestamp if authenticated
    if is_authenticated():
        _update_user_activity()


@main_bp.after_request
def after_request(response: Response) -> Response:
    """
    Process responses for main routes.

    This function runs after each request to the main blueprint. It:
    - Adds performance metrics about response timing
    - Sets security headers to protect against common web vulnerabilities
    - Adds response metadata (request ID, timing) for debugging
    - Compresses large responses for faster transmission
    - Implements cache control based on content type and route
    - Adds content security policy nonce if available
    - Ensures proper content type headers

    Args:
        response (Response): The Flask response object

    Returns:
        Response: The modified response with additional headers and compression
    """
    # Performance metrics
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()

        # Track response time
        metrics.info('main_response_time', duration, labels={
            'endpoint': request.endpoint or 'unknown',
            'status': response.status_code,
            'content_type': response.content_type.split(';')[0] if response.content_type else 'unknown'
        })

        # Add timing info to response for debugging
        response.headers['X-Request-ID'] = g.request_id
        response.headers['X-Response-Time'] = f'{duration:.3f}s'

        # Additional performance tracking for slow responses (>500ms)
        if duration > 0.5:
            metrics.info('slow_response_total', 1, labels={
                'endpoint': request.endpoint or 'unknown'
            })
            logger.info(f"Slow response: {request.path} took {duration:.3f}s")

    # Add comprehensive security headers
    _add_security_headers(response)

    # Add cache control headers based on content type and route
    _add_cache_headers(response)

    # Add Referrer-Policy header for privacy
    if 'Referrer-Policy' not in response.headers:
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Add Permissions-Policy header to limit browser features
    if 'Permissions-Policy' not in response.headers:
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=()'
        )

    # Add Feature-Policy as a legacy header for older browsers
    if 'Feature-Policy' not in response.headers:
        response.headers['Feature-Policy'] = (
            'camera none; microphone none; geolocation none; payment none'
        )

    # Set CSP nonce if available in the context
    if hasattr(g, 'csp_nonce'):
        current_csp = response.headers.get('Content-Security-Policy', "default-src 'self'")
        if "'nonce-" not in current_csp:
            # Add nonce to script-src and style-src if they exist
            if 'script-src' in current_csp:
                current_csp = current_csp.replace(
                    'script-src', f"script-src 'nonce-{g.csp_nonce}'"
                )
            if 'style-src' in current_csp:
                current_csp = current_csp.replace(
                    'style-src', f"style-src 'nonce-{g.csp_nonce}'"
                )
            response.headers['Content-Security-Policy'] = current_csp

    # Ensure proper content type for HTML responses
    if response.content_type and 'text/html' in response.content_type:
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Check if charset is specified, add if missing
        if 'charset=' not in response.content_type:
            response.headers['Content-Type'] = response.content_type + '; charset=utf-8'

    # Compress large responses for bandwidth optimization
    if (response.content_length is not None and
        response.content_length > 1024 and
        'gzip' in request.headers.get('Accept-Encoding', '') and
        not response.headers.get('Content-Encoding')):

        # Don't compress already compressed content types
        if response.content_type and not any(t in response.content_type for t in
                                           ['image/', 'video/', 'audio/', 'application/zip']):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

            # Update content length after compression
            response.headers['Content-Length'] = len(response.data)

    # Track response by status code category
    status_category = response.status_code // 100
    metrics.info(f'http_responses_total', 1, labels={
        'status_category': f'{status_category}xx',
        'method': request.method
    })

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
    - Checks file integrity if a server error occurred
    - Sends appropriate alerts for critical errors

    Args:
        exc: Exception that was raised during request handling, or None if no exception

    Returns:
        None: This function performs cleanup as a side effect
    """
    if exc is not None:
        # Roll back uncommitted database changes
        try:
            db.session.rollback()
        except Exception as rollback_error:
            logger.error(f"Error during session rollback: {rollback_error}")

        # Get error details for logging
        error_type = exc.__class__.__name__
        error_path = request.path
        error_method = request.method
        user_id = getattr(g, 'user_id', None) or session.get('user_id', 'anonymous')

        # Record error metrics
        metrics.info('main_errors_total', 1, labels={
            'type': error_type,
            'endpoint': request.endpoint or 'unknown',
            'status_code': getattr(exc, 'code', 500),
            'method': error_method
        })

        # Define error severity based on exception type and context
        severity = _determine_error_severity(exc)

        # Log error with appropriate context
        logger.log(
            logging.ERROR if severity >= 2 else logging.WARNING,
            f"Request error: {exc}",
            extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'path': error_path,
                'method': error_method,
                'error_type': error_type,
                'user_id': user_id,
                'severity': severity,
                'client_ip': getattr(g, 'security_context', {}).get('ip_address', 'unknown')
            }
        )

        # For server errors (5xx), verify file integrity
        status_code = getattr(exc, 'code', 500)
        if status_code >= 500 and severity >= 3:
            _check_integrity_after_error()

    # Always ensure session cleanup
    try:
        db.session.remove()
    except Exception as remove_error:
        logger.error(f"Error during session cleanup: {remove_error}")


# Initialize error handlers
init_error_handlers(main_bp)


# File integrity status endpoint for admin monitoring
@main_bp.route('/file-integrity-status')
@limiter.limit("10/minute")
def file_integrity_status() -> Union[Tuple[Dict[str, Any], int], Tuple[str, int]]:
    """
    Provide file integrity status for monitoring.

    This endpoint allows admins to check the current file integrity status
    to identify any potential security issues.

    Returns:
        Union[Tuple[Dict[str, Any], int], Tuple[str, int]]:
            JSON response with file integrity status or error message
    """
    if not _is_authorized_for_integrity_check():
        # Don't reveal the existence of this endpoint to unauthorized users
        abort(404)

    try:
        from core.security.cs_file_integrity import check_integrity, get_integrity_summary

        # Get integrity status from the security module
        status, details = check_integrity(verify_critical=True)

        # Get summary information
        summary = get_integrity_summary()

        # Prepare the response
        response = {
            'status': 'valid' if status else 'invalid',
            'violations': summary.get('violations', 0),
            'last_check': summary.get('last_check'),
            'critical_violations': summary.get('critical_violations', 0),
            'high_violations': summary.get('high_violations', 0)
        }

        # Only include violation details for admins
        if _is_admin_user() and not status:
            # Include limited details about violations (first 5 only)
            response['details'] = details[:5] if isinstance(details, list) else []

        return response, 200

    except ImportError:
        # Fallback to config-based integrity check if module not available
        try:
            if current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
                from config.base import Config
                status_info = Config.baseline_status(current_app)
                return status_info, 200
            else:
                return {'status': 'disabled'}, 200

        except Exception as e:
            logger.error(f"Error checking file integrity: {str(e)}")
            return {'status': 'error', 'message': 'Could not retrieve integrity status'}, 500

    except Exception as e:
        logger.error(f"Error in file integrity status endpoint: {str(e)}")
        return {'status': 'error', 'message': 'Could not retrieve integrity status'}, 500


# Register blueprint monitoring (if available)
try:
    register_route_monitoring(main_bp, interval=60)
    logger.debug("Route monitoring registered for main blueprint")
except (ImportError, AttributeError):
    logger.debug("Route monitoring not available")


# Debug route - only enabled in development
if os.environ.get('FLASK_ENV') == 'development':
    @main_bp.route('/debug-info')
    def debug_info():
        """Return debug information (only available in development)"""
        from flask import jsonify

        # Don't leak sensitive information
        safe_config = {k: v for k, v in current_app.config.items()
                      if not k.startswith(('SECRET', 'API_KEY', 'PASSWORD'))}

        return jsonify({
            'blueprint': main_bp.name,
            'endpoints': [str(rule) for rule in main_bp.url_map.iter_rules()],
            'version': current_app.config.get('VERSION', 'unknown'),
            'environment': current_app.config.get('ENVIRONMENT', 'development'),
            'debug': current_app.debug,
            'uptime': str(datetime.utcnow() - current_app.uptime) if hasattr(current_app, 'uptime') else 'unknown',
            'config': safe_config
        })


# ---- Helper Functions ---- #

def _add_security_headers(response: Response) -> None:
    """
    Add security headers to HTTP response.

    Args:
        response: Flask response object to modify
    """
    # Basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Content Security Policy - base policy
    if 'Content-Security-Policy' not in response.headers:
        csp_directives = [
            "default-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "style-src 'self' 'unsafe-inline'",  # 'unsafe-inline' needed for Bootstrap
            "script-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]

        # If we have a CSP nonce, use it for scripts
        if hasattr(g, 'csp_nonce'):
            csp_directives[4] = f"script-src 'self' 'nonce-{g.csp_nonce}'"

        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)


def _add_cache_headers(response: Response) -> None:
    """
    Set appropriate cache headers based on content type and route.

    Args:
        response: Flask response object to modify
    """
    # Don't cache API responses or authenticated pages by default
    if _is_api_request() or is_authenticated():
        if 'Cache-Control' not in response.headers:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            return

    # Set cache policy based on content type
    if response.content_type:
        if any(static_type in response.content_type for static_type in
              ['image/', 'text/css', 'application/javascript']):
            # Cache static assets for 1 week
            if 'Cache-Control' not in response.headers:
                response.headers['Cache-Control'] = 'public, max-age=604800'
        elif 'text/html' in response.content_type:
            # Set to private cache for HTML content
            if 'Cache-Control' not in response.headers:
                response.headers['Cache-Control'] = 'private, max-age=0'


def _contains_suspicious_patterns(req) -> bool:
    """
    Check for suspicious patterns in the request.

    Args:
        req: Flask request object

    Returns:
        bool: True if suspicious patterns detected
    """
    # Get user agent string safely
    ua_string = req.user_agent.string if req.user_agent else ''

    # List of suspicious patterns
    suspicious_patterns = [
        'sqlmap', 'nikto', 'nessus', 'vulnerability', 'dirbuster',
        'wpscan', 'aggressive', 'scanner', 'acunetix', 'qualys'
    ]

    # Check user agent string for scanner patterns
    if any(pattern in ua_string.lower() for pattern in suspicious_patterns):
        return True

    # Check for suspicious query patterns
    query_string = req.query_string.decode('utf-8', errors='ignore').lower()
    suspicious_queries = [
        'union+select', 'exec(', 'eval(', '../../', '<script>',
        'document.cookie', 'onload=', 'javascript:', 'fromcharcode'
    ]

    if any(pattern in query_string for pattern in suspicious_queries):
        return True

    return False


def _update_user_activity() -> None:
    """Update the user's last activity timestamp if needed."""
    # Only update periodically to reduce database load
    update_interval = current_app.config.get('USER_ACTIVITY_UPDATE_INTERVAL', 300)  # 5 minutes

    user_id = get_current_user_id()
    if not user_id:
        return

    last_update = session.get('last_activity_update')
    now = datetime.utcnow()

    # Update if first request or interval has passed
    if not last_update or (now - datetime.fromisoformat(last_update)).total_seconds() > update_interval:
        try:
            # Try to update user's last activity timestamp
            from models.auth.user import User
            user = User.query.get(user_id)
            if user:
                user.last_active = now
                db.session.commit()
                session['last_activity_update'] = now.isoformat()
        except Exception as e:
            # Log but don't fail the request for activity tracking errors
            logger.debug(f"Failed to update user activity: {str(e)}")


def _determine_error_severity(exc) -> int:
    """
    Determine the severity of an error based on its type and context.

    Args:
        exc: The exception that occurred

    Returns:
        int: Severity level (1=low, 2=medium, 3=high, 4=critical)
    """
    # Default to medium severity
    severity = 2

    error_type = exc.__class__.__name__

    # Critical errors
    if error_type in ['SecurityViolation', 'IntegrityError', 'DatabaseCorruption']:
        return 4

    # High severity errors
    if error_type in ['SQLAlchemyError', 'OperationalError', 'TimeoutError',
                     'ConnectionError', 'MemoryError']:
        return 3

    # Low severity errors
    if error_type in ['NotFound', 'ValidationError', 'BadRequest']:
        return 1

    # Check status code if available
    status_code = getattr(exc, 'code', 500)
    if status_code >= 500:
        severity = max(severity, 3)  # At least high severity for 5xx errors

    return severity


def _check_integrity_after_error() -> None:
    """
    Verify file integrity after a server error to detect potential tampering.
    """
    # Skip if integrity monitoring is disabled
    if not current_app.config.get('VERIFY_INTEGRITY_AFTER_ERROR', True):
        return

    try:
        # Import integrity checking functions
        from core.security.cs_file_integrity import check_integrity
        from core.security import log_security_event

        # Perform integrity check of critical files
        valid, violations = check_integrity(verify_critical=True, detailed=True)

        if not valid:
            critical_violations = sum(1 for v in violations if v.get('severity') == 'critical')
            high_violations = sum(1 for v in violations if v.get('severity') == 'high')

            # Log security event for integrity failures
            log_security_event(
                event_type='integrity_violation_after_error',
                description=f"File integrity violations detected after server error: {len(violations)} total violations",
                severity='critical' if critical_violations > 0 else 'high',
                details={
                    'critical_violations': critical_violations,
                    'high_violations': high_violations,
                    'total_violations': len(violations),
                    'request_path': request.path,
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'client_ip': getattr(g, 'security_context', {}).get('ip_address', 'unknown')
                }
            )

            logger.critical(
                f"SECURITY ALERT: File integrity violations detected after server error. "
                f"Critical: {critical_violations}, High: {high_violations}, Total: {len(violations)}"
            )
    except ImportError:
        logger.debug("File integrity checking not available")
    except Exception as e:
        logger.error(f"Error during integrity check after server error: {str(e)}")


def _is_api_request() -> bool:
    """
    Check if the current request is an API request.

    Returns:
        bool: True if this is an API request
    """
    if request.path.startswith('/api/'):
        return True

    if request.headers.get('Accept') == 'application/json':
        return True

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True

    return False


def _is_authorized_for_integrity_check() -> bool:
    """
    Check if the current user is authorized to check file integrity status.

    Returns:
        bool: True if authorized
    """
    # Only allow authenticated users with admin role
    if not is_authenticated():
        return False

    try:
        from auth.decorators import current_user_has_role
        return current_user_has_role('admin')
    except ImportError:
        # If role checking isn't available, rely on admin flag
        return _is_admin_user()


def _is_admin_user() -> bool:
    """
    Check if the current user is an admin.

    Returns:
        bool: True if current user is an admin
    """
    if not is_authenticated():
        return False

    # Check for admin flag in session
    if session.get('is_admin', False):
        return True

    # Check user object if available
    if hasattr(g, 'user') and hasattr(g.user, 'is_admin'):
        return bool(g.user.is_admin)

    return False


# Import routes at the bottom to avoid circular imports
from . import routes

# Export module members
__all__ = ['main_bp']
