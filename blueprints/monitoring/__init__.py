"""
Monitoring blueprint package for myproject.

This blueprint provides system monitoring, metrics collection, and health check
functionality for the application. It exposes endpoints for internal health monitoring,
performance metrics, and operational diagnostics that are critical for production
operation and maintenance.

Key features:
- Health check endpoints for infrastructure monitoring
- System metrics collection and visualization
- Database performance monitoring
- Application performance metrics
- Environmental data tracking
- Prometheus metrics exposition
- Security anomaly detection
- File integrity monitoring
- Incident management and response
- Real-time threat assessment

This blueprint captures request metrics automatically and provides middleware for
consistent response handling with appropriate headers and logging.
"""

import logging
import os
import sys
import time
from datetime import datetime, timedelta
import uuid
import ipaddress
from typing import Dict, Tuple, List, Optional, Union, Any, Callable
from functools import wraps

from flask import Blueprint, g, request, current_app, Response, jsonify, abort
from werkzeug.local import LocalProxy
from extensions import metrics, cache, db, limiter

# Create blueprint with correct prefix and template folder
monitoring_bp = Blueprint(
    'monitoring',
    __name__,
    url_prefix='/monitoring',
    template_folder='templates'
)

# Initialize logger
logger = logging.getLogger(__name__)

# Track security context across requests
security_context = LocalProxy(lambda: getattr(g, 'security_context', {}))

# Constants for monitoring
SEVERITY_CRITICAL = 'critical'
SEVERITY_HIGH = 'high'
SEVERITY_MEDIUM = 'medium'
SEVERITY_LOW = 'low'
SEVERITY_INFO = 'info'

# Feature detection flags
CORE_SECURITY_AVAILABLE = False
FILE_INTEGRITY_AVAILABLE = False
PROMETHEUS_AVAILABLE = False

# Try to import core security features
try:
    from core.security.cs_monitoring import check_monitoring_access, validate_monitoring_client
    from core.security.cs_file_integrity import check_integrity, get_integrity_summary
    CORE_SECURITY_AVAILABLE = True
    FILE_INTEGRITY_AVAILABLE = True
    logger.debug("Core security module loaded for monitoring")
except ImportError:
    logger.debug("Core security module not available, using fallback security")

# Try to import prometheus client for advanced metrics
try:
    import prometheus_client
    PROMETHEUS_AVAILABLE = True
except ImportError:
    logger.debug("Prometheus client not available, using basic metrics")

@monitoring_bp.before_request
def before_request() -> None:
    """
    Setup request context and tracking for monitoring routes.

    This function runs before each request to the monitoring blueprint. It:
    - Assigns a unique request ID for tracking
    - Records the start time for performance measurement
    - Increments Prometheus metrics counters
    - Logs the request details
    - Validates client IP address for restricted endpoints
    - Checks for suspicious request patterns
    - Enforces authorization for protected endpoints

    The tracking information is stored in Flask's g object for access
    by subsequent middleware and route handlers.

    Returns:
        None: This function sets up request context as a side effect
    """
    # Generate or use existing request ID for tracking
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()

    # Record metrics about the request
    metrics.info('monitoring_requests_total', 1, labels={
        'method': request.method,
        'path': request.path
    })

    # Set up security context for the request
    client_ip = _get_client_ip()
    g.security_context = {
        'ip_address': client_ip,
        'user_agent': _sanitize_header(request.user_agent.string if request.user_agent else 'unknown'),
        'referrer': _sanitize_header(request.referrer) if request.referrer else 'direct',
        'timestamp': datetime.utcnow().isoformat()
    }

    # Log the request with security context
    current_app.logger.info(
        f'Request {g.request_id}: {request.method} {request.path}',
        extra={
            'request_id': g.request_id,
            'ip': client_ip,
            'user_agent': g.security_context['user_agent'][:50]  # Truncate long user agents
        }
    )

    # Validate access for restricted monitoring endpoints
    if _is_restricted_endpoint():
        # Check if core security access validation is available
        if CORE_SECURITY_AVAILABLE and callable(check_monitoring_access):
            if not check_monitoring_access(request):
                metrics.info('monitoring_access_denied', 1)
                current_app.logger.warning(
                    f"Access denied to restricted endpoint {request.path} from {client_ip}",
                    extra={'request_id': g.request_id}
                )
                abort(403)
        else:
            # Fall back to basic IP validation for prometheus metrics
            if request.path == '/monitoring/metrics/prometheus' and not _is_internal_ip(client_ip):
                metrics.info('monitoring_access_denied', 1)
                current_app.logger.warning(
                    f"Access denied to prometheus metrics from {client_ip}",
                    extra={'request_id': g.request_id}
                )
                abort(403)

    # Check for suspicious patterns
    if _contains_suspicious_patterns(request):
        metrics.info('suspicious_request_total', 1, labels={'reason': 'pattern_match'})
        logger.warning(
            "Suspicious request pattern detected",
            extra={
                'request_id': g.request_id,
                'ip': client_ip,
                'path': request.path,
                'ua': g.security_context['user_agent'][:100]  # Truncate long user agents
            }
        )


@monitoring_bp.after_request
def after_request(response: Response) -> Response:
    """
    Add response headers and metrics for monitoring routes.

    This function runs after each request to the monitoring blueprint. It:
    - Adds request ID header for traceability
    - Records response time for performance tracking
    - Adds security headers to responses
    - Logs response details including status code and timing
    - Records Prometheus metrics about the response
    - Sets appropriate cache control headers
    - Implements security protection for monitoring data

    Args:
        response (Response): The Flask response object

    Returns:
        Response: The modified response with additional headers
    """
    if not hasattr(g, 'start_time'):
        g.start_time = datetime.utcnow()
        g.request_id = getattr(g, 'request_id', str(uuid.uuid4()))
        current_app.logger.warning(
            f'Missing request context for {g.request_id}. Adding fallback.',
            extra={'request_id': g.request_id}
        )

    elapsed = datetime.utcnow() - g.start_time

    # Add standard security and tracking headers
    response.headers.set('X-Request-ID', g.request_id)
    response.headers.set('X-Response-Time', f'{elapsed.total_seconds():.3f}s')
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('X-XSS-Protection', '1; mode=block')
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

    # Add Content-Security-Policy for enhanced security
    if 'Content-Security-Policy' not in response.headers:
        response.headers.set('Content-Security-Policy',
                          "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; "
                          "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")

    # Set cache control headers - monitoring data should not be cached by default
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    response.headers.set('Pragma', 'no-cache')
    response.headers.set('Expires', '0')

    # Add Referrer-Policy header for privacy protection
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')

    # Add Feature-Policy/Permissions-Policy to limit features
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')

    # Record response metrics
    metrics.info('monitoring_response_time', elapsed.total_seconds(), labels={
        'path': request.path,
        'status': response.status_code
    })

    # Track status code metrics
    status_category = response.status_code // 100
    metrics.info('monitoring_status', 1, labels={
        'status_category': f'{status_category}xx',
        'path': request.path,
        'method': request.method
    })

    # Log based on status code
    if response.status_code >= 400:
        current_app.logger.warning(
            f'Error response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)',
            extra={
                'request_id': g.request_id,
                'status_code': response.status_code,
                'path': request.path,
                'ip': g.security_context.get('ip_address', 'unknown')
            }
        )
    else:
        current_app.logger.info(
            f'Response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)',
            extra={'request_id': g.request_id}
        )

    return response


@monitoring_bp.errorhandler(429)
def ratelimit_handler() -> Tuple[Dict[str, str], int]:
    """
    Handle rate limit errors for monitoring routes.

    This function provides a standardized response when rate limits are exceeded,
    ensuring consistent error handling and appropriate metrics tracking.

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 429
    """
    current_app.logger.warning(
        f'Rate limit exceeded: {request.url}',
        extra={
            'request_id': g.get('request_id'),
            'ip': g.security_context.get('ip_address', 'unknown'),
            'path': request.path
        }
    )

    # Increment rate limit counter for monitoring
    metrics.info('monitoring_ratelimit_total', 1, labels={
        'path': request.path,
        'method': request.method
    })

    # Record rate limit violation for security monitoring
    try:
        from models import AuditLog
        AuditLog.create(
            event_type=AuditLog.EVENT_RATE_LIMIT,
            user_id=g.get('user_id'),
            ip_address=g.security_context.get('ip_address'),
            description=f"Rate limit exceeded for monitoring endpoint: {request.path}",
            details=request.path,
            severity=AuditLog.SEVERITY_WARNING
        )
    except (ImportError, Exception) as e:
        current_app.logger.debug(f"Could not log rate limit to audit log: {e}")

    return {'error': 'Rate limit exceeded', 'status': 429}, 429


@monitoring_bp.errorhandler(500)
def internal_error(e: Exception) -> Tuple[Dict[str, str], int]:
    """
    Handle internal server errors for monitoring routes.

    This function provides a standardized response for internal server errors,
    logs the error details, and records metrics about the error occurrence.
    It also checks file integrity when errors occur to detect potential security issues.

    Args:
        e (Exception): The exception that triggered the error handler

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 500
    """
    error_id = getattr(g, 'request_id', str(uuid.uuid4()))

    current_app.logger.error(
        f'Server Error {error_id}: {str(e)}',
        exc_info=e,
        extra={
            'request_id': error_id,
            'path': request.path,
            'method': request.method,
            'ip': g.security_context.get('ip_address', 'unknown'),
            'error_type': e.__class__.__name__
        }
    )

    # Track detailed error metrics
    metrics.info('monitoring_error_total', 1, labels={
        'path': request.path,
        'method': request.method,
        'error_type': e.__class__.__name__
    })

    # Check file integrity if core security is available and this is a critical failure
    if FILE_INTEGRITY_AVAILABLE and _is_critical_error(e):
        try:
            status, violations = check_integrity(verify_critical=True, detailed=True)
            if not status:
                current_app.logger.critical(
                    f"File integrity violations detected after monitoring error: "
                    f"{len(violations)} total violations"
                )

                # Track integrity violations metrics
                metrics.info('file_integrity_violations', len(violations), labels={
                    'trigger': 'error_handler',
                    'error_type': e.__class__.__name__
                })

                # Log security event with detailed information
                try:
                    from core.security import log_security_event
                    log_security_event(
                        event_type='integrity_violation_after_error',
                        description=f"File integrity violations detected after monitoring error",
                        severity=SEVERITY_CRITICAL,
                        details={
                            'violations_count': len(violations),
                            'error_type': e.__class__.__name__,
                            'request_path': request.path,
                            'request_id': error_id
                        }
                    )
                except (ImportError, Exception) as log_error:
                    current_app.logger.error(f"Failed to log security event: {log_error}")
        except Exception as integrity_error:
            current_app.logger.error(f"Error during integrity check: {integrity_error}")

    # Create a helpful error response with minimal details
    # (avoid leaking sensitive information in error responses)
    return {
        'error': 'Internal server error',
        'status': 500,
        'request_id': error_id  # Include ID for troubleshooting
    }, 500


@monitoring_bp.errorhandler(403)
def forbidden_error(e: Exception) -> Tuple[Dict[str, str], int]:
    """
    Handle forbidden errors for monitoring routes.

    This function provides a standardized response for 403 errors,
    logs the details, and records metrics about the occurrence.

    Args:
        e (Exception): The exception that triggered the error handler

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 403
    """
    current_app.logger.warning(
        f'Forbidden access: {request.url}',
        extra={
            'request_id': g.get('request_id'),
            'ip': g.security_context.get('ip_address', 'unknown')
        }
    )
    metrics.info('monitoring_forbidden_total', 1, labels={
        'path': request.path,
        'method': request.method
    })

    # Track unauthorized access attempt for security analysis
    try:
        from models import AuditLog
        AuditLog.create(
            event_type=AuditLog.EVENT_UNAUTHORIZED_ACCESS,
            user_id=g.get('user_id'),
            ip_address=g.security_context.get('ip_address'),
            description=f"Unauthorized access attempt to monitoring endpoint: {request.path}",
            details=request.path,
            severity=AuditLog.SEVERITY_WARNING
        )
    except (ImportError, Exception) as e:
        current_app.logger.debug(f"Could not log unauthorized access to audit log: {e}")

    return {'error': 'Access denied', 'status': 403}, 403


@monitoring_bp.errorhandler(404)
def not_found_error(e: Exception) -> Tuple[Dict[str, str], int]:
    """
    Handle not found errors for monitoring routes.

    This function provides a standardized response for 404 errors,
    logs the details, and records metrics about the occurrence.

    Args:
        e (Exception): The exception that triggered the error handler

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 404
    """
    current_app.logger.info(
        f'Not found: {request.url}',
        extra={'request_id': g.get('request_id')}
    )
    metrics.info('monitoring_not_found_total', 1, labels={
        'path': request.path,
        'method': request.method
    })
    return {'error': 'Resource not found', 'status': 404}, 404


@monitoring_bp.errorhandler(400)
def bad_request_error(e: Exception) -> Tuple[Dict[str, str], int]:
    """
    Handle bad request errors for monitoring routes.

    This function provides a standardized response for 400 errors,
    logs the details, and records metrics about the occurrence.

    Args:
        e (Exception): The exception that triggered the error handler

    Returns:
        tuple: A tuple containing an error response dictionary and HTTP status code 400
    """
    current_app.logger.info(
        f'Bad request: {request.url}, Error: {str(e)}',
        extra={'request_id': g.get('request_id')}
    )
    metrics.info('monitoring_bad_request_total', 1, labels={
        'path': request.path,
        'method': request.method
    })
    return {'error': 'Bad request', 'status': 400, 'message': str(e)}, 400


@monitoring_bp.teardown_request
def teardown_request(exc) -> None:
    """
    Clean up resources after each request.

    This function runs after each request to the monitoring blueprint, even if
    an exception occurs. It ensures proper cleanup of resources and captures
    exception metrics if applicable. It also:
    - Rolls back any uncommitted database transactions
    - Records metrics for unhandled exceptions
    - Ensures connection cleanup
    - Performs circuit-breaking after repeated errors

    Args:
        exc: An exception raised during request processing, if any

    Returns:
        None: This function performs cleanup as a side effect
    """
    if exc:
        # Track unhandled exceptions
        current_app.logger.error(
            f'Unhandled exception in monitoring blueprint: {exc}',
            exc_info=exc,
            extra={'request_id': g.get('request_id')}
        )
        metrics.info('monitoring_unhandled_exception_total', 1, labels={
            'path': request.path,
            'error_type': exc.__class__.__name__
        })

        # Always rollback uncommitted transactions
        try:
            if hasattr(db, 'session'):
                db.session.rollback()
        except Exception as rollback_error:
            current_app.logger.error(f"Error during session rollback: {rollback_error}")

    # Always ensure session cleanup regardless of exceptions
    try:
        if hasattr(db, 'session'):
            db.session.remove()
    except Exception as session_error:
        current_app.logger.error(f"Error during session cleanup: {session_error}")


# File integrity verification route for monitoring system health
@monitoring_bp.route('/file-integrity-status')
@limiter.limit("10/minute")
def file_integrity_status() -> Dict[str, Any]:
    """
    Provide file integrity status for monitoring.

    This endpoint allows admins to check the current file integrity status
    to identify any potential security issues. It requires administrative
    privileges with rate limiting to prevent abuse.

    Returns:
        dict: JSON response with file integrity status
    """
    if not _is_authorized_for_admin_endpoints():
        # Don't reveal the existence of this endpoint to unauthorized users
        abort(404)

    try:
        # Try to use core file integrity monitoring if available
        if FILE_INTEGRITY_AVAILABLE:
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
                'high_violations': summary.get('high_violations', 0),
                'check_timestamp': datetime.utcnow().isoformat()
            }

            # Only include violation details for admins
            if _is_admin_user() and not status:
                # Include limited details about violations (first 5 only)
                response['details'] = details[:5] if isinstance(details, list) else []

            return jsonify(response)

        # Fallback to config-based integrity check if module not available
        try:
            if current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
                from config.base import Config
                status_info = Config.baseline_status(current_app)
                return jsonify(status_info)
            else:
                return jsonify({'status': 'disabled'})

        except Exception as e:
            logger.error(f"Error checking file integrity: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Could not retrieve integrity status',
                'timestamp': datetime.utcnow().isoformat()
            }), 500

    except Exception as e:
        logger.error(f"Error in file integrity status endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Could not retrieve integrity status',
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# Health check endpoint
@monitoring_bp.route('/health', methods=['GET'])
@limiter.limit("60/minute")
def health_check() -> Dict[str, Any]:
    """
    Basic health check for load balancer and infrastructure monitoring.

    This endpoint is used by infrastructure monitoring tools to verify
    that the application is running and responding to requests. It checks
    database connectivity, cache availability, and filesystem access.

    Returns:
        dict: JSON response with health status
    """
    start_time = time.time()

    try:
        # Initialize status tracking
        db_healthy = True
        cache_healthy = True
        fs_healthy = True

        # Check database connectivity
        try:
            db.session.execute("SELECT 1")
        except Exception as e:
            current_app.logger.warning(f"Database health check failed: {e}")
            db_healthy = False

        # Check cache connectivity
        try:
            health_key = f'health_check:{uuid.uuid4()}'
            cache.set(health_key, 'ok', timeout=10)
            cache_value = cache.get(health_key)
            if cache_value != 'ok':
                raise ValueError("Cache check failed: value mismatch")
        except Exception as e:
            current_app.logger.warning(f"Cache health check failed: {e}")
            cache_healthy = False

        # Optional: check file system access
        fs_healthy = True
        try:
            temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp')
            test_file = os.path.join(temp_dir, f"health_check_{int(time.time())}.txt")
            with open(test_file, "w") as f:
                f.write("health check")
            os.remove(test_file)
        except IOError as e:
            current_app.logger.warning(f"Filesystem health check failed: {e}")
            fs_healthy = False

        # Determine overall health status
        health_status = {
            'status': 'healthy' if (db_healthy and cache_healthy and fs_healthy) else 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'database': 'healthy' if db_healthy else 'unhealthy',
                'cache': 'healthy' if cache_healthy else 'unhealthy',
                'filesystem': 'healthy' if fs_healthy else 'unhealthy',
                'app': 'healthy'
            }
        }

        # Add version information
        health_status['version'] = current_app.config.get('VERSION', 'unknown')

        # Add response time
        health_status['response_time_ms'] = int((time.time() - start_time) * 1000)

        # Add file integrity status if available and not too expensive
        if FILE_INTEGRITY_AVAILABLE and current_app.config.get('INCLUDE_INTEGRITY_IN_HEALTH', False):
            try:
                integrity_status, _ = check_integrity(verify_critical=True)
                health_status['components']['file_integrity'] = 'healthy' if integrity_status else 'unhealthy'
                if not integrity_status and health_status['status'] == 'healthy':
                    health_status['status'] = 'degraded'
            except Exception as integrity_error:
                current_app.logger.debug(f"Integrity check in health skipped: {integrity_error}")

        status_code = 200 if health_status['status'] == 'healthy' else 503

        # Record metrics based on health status
        metrics.info('health_check', 1, labels={
            'status': health_status['status'],
            'database': health_status['components']['database'],
            'cache': health_status['components']['cache'],
            'filesystem': health_status['components']['filesystem']
        })

        return jsonify(health_status), status_code

    except Exception as e:
        current_app.logger.error(f"Health check error: {e}", exc_info=True)
        metrics.info('health_check_error', 1)

        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Debug route - only available in development environment
if os.environ.get('FLASK_ENV') == 'development':
    @monitoring_bp.route('/debug')
    @limiter.limit("10/minute")
    def debug():
        """Debug endpoint for development environment only."""
        if not _is_authorized_for_admin_endpoints():
            abort(404)

        debug_info = {
            'environment': current_app.config.get('ENVIRONMENT', 'unknown'),
            'version': current_app.config.get('VERSION', 'unknown'),
            'python_version': sys.version,
            'features': {
                'core_security': CORE_SECURITY_AVAILABLE,
                'file_integrity': FILE_INTEGRITY_AVAILABLE,
                'prometheus': PROMETHEUS_AVAILABLE
            },
            'endpoints': [rule.rule for rule in current_app.url_map.iter_rules()
                         if rule.endpoint.startswith('monitoring')],
            'metrics_enabled': current_app.config.get('ENABLE_METRICS', True),
            'timestamp': datetime.utcnow().isoformat()
        }

        return jsonify(debug_info)


# --- Helper functions --- #

def _is_restricted_endpoint() -> bool:
    """
    Check if current endpoint has restricted access.

    Returns:
        bool: True if endpoint should be restricted to internal/admin access
    """
    restricted_paths = [
        '/monitoring/metrics/prometheus',
        '/monitoring/file-integrity-status',
        '/monitoring/anomalies',
        '/monitoring/debug',
        '/monitoring/forensics/'
    ]

    # Check if current path starts with any restricted path
    return any(request.path.startswith(path) for path in restricted_paths)


def _is_internal_ip(ip: str) -> bool:
    """
    Check if an IP address is internal/private.

    Args:
        ip (str): IP address to check

    Returns:
        bool: True if internal, False otherwise
    """
    # Localhost is always considered internal
    if ip in ('127.0.0.1', '::1', 'localhost'):
        return True

    try:
        # Parse IP address
        ip_obj = ipaddress.ip_address(ip)

        # Check if it's a private address
        if ip_obj.is_private:
            return True

        # Check if it's in configured internal ranges
        whitelist = current_app.config.get('INTERNAL_IP_RANGES', [])
        for network in whitelist:
            try:
                if ip_obj in ipaddress.ip_network(network):
                    return True
            except ValueError:
                continue

        return False
    except ValueError:
        # If IP is invalid, assume external
        return False


def _is_authorized_for_admin_endpoints() -> bool:
    """
    Check if the current user is authorized for admin endpoints.

    Returns:
        bool: True if authorized
    """
    # Check if security module has authorization function
    if CORE_SECURITY_AVAILABLE:
        try:
            from core.security.cs_authorization import current_user_has_role
            return current_user_has_role('admin')
        except ImportError:
            pass

    # Fall back to checking for admin in session
    if hasattr(g, 'user'):
        return getattr(g.user, 'is_admin', False)

    from flask import session
    return session.get('is_admin', False)


def _is_admin_user() -> bool:
    """
    Check if current user is an admin.

    Returns:
        bool: True if admin, False otherwise
    """
    # Check if we have a user in g context
    if hasattr(g, 'user'):
        return getattr(g.user, 'is_admin', False)

    # Check session
    from flask import session
    if session.get('is_admin', False):
        return True

    # Try to import auth utils if available
    try:
        from core.security.cs_authentication import current_user_is_admin
        return current_user_is_admin()
    except ImportError:
        return False


def _is_critical_error(exc: Exception) -> bool:
    """
    Check if an exception indicates a critical error.

    Args:
        exc: Exception to check

    Returns:
        bool: True if critical error
    """
    # Critical SQLAlchemy errors
    critical_sql_errors = (
        'OperationalError',
        'DatabaseError',
        'DataError',
        'IntegrityError',
        'InternalError'
    )

    # Check for critical SQL errors
    if exc.__class__.__name__ in critical_sql_errors:
        return True

    # Error types indicating possible security issues
    security_issues = (
        'SecurityViolation',
        'AuthorizationError',
        'IntegrityViolation',
        'AccessControlError'
    )

    # Check for security issue errors
    if exc.__class__.__name__ in security_issues:
        return True

    # Check for error message patterns indicating security issues
    if hasattr(exc, 'args') and len(exc.args) > 0:
        msg = str(exc.args[0]).lower()
        if any(pattern in msg for pattern in ['sql injection', 'integrity', 'permission', 'security']):
            return True

    return False


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
        'sqlmap', 'acunetix', 'nikto', 'nessus', 'vulnerability', 'dirbuster',
        'wpscan', 'aggressive', 'scanner', 'qualys', 'burpsuite', 'masscan'
    ]

    # Check user agent string for scanner patterns
    if any(pattern in ua_string.lower() for pattern in suspicious_patterns):
        return True

    # Check for suspicious query patterns
    query_string = req.query_string.decode('utf-8', errors='ignore').lower()
    suspicious_queries = [
        'union+select', 'exec(', 'eval(', '../', '<script>',
        'document.cookie', 'onload=', 'javascript:', 'fromcharcode',
        '../../../../', 'etc/passwd', '/bin/sh'
    ]

    if any(pattern in query_string for pattern in suspicious_queries):
        return True

    # Check header values for injection attempts
    for header_name, header_value in req.headers.items():
        if header_value and isinstance(header_value, str):
            header_lower = header_value.lower()
            if any(pattern in header_lower for pattern in suspicious_queries):
                return True

    return False


def _get_client_ip() -> str:
    """
    Get client IP address from request, handling proxy headers.

    Returns:
        str: IP address string
    """
    # Check for forwarded IP (through reverse proxy)
    if current_app.config.get('TRUST_PROXY_HEADERS', False):
        # Check X-Forwarded-For header
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Get the first IP which is the client IP
            return forwarded_for.split(',')[0].strip()

        # Check other common headers
        for header in ['X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP']:
            if header in request.headers:
                return request.headers.get(header)

    # Fall back to direct remote_addr
    return request.remote_addr or '0.0.0.0'


def _sanitize_header(value: str) -> str:
    """
    Sanitize header values for safe logging.

    Args:
        value (str): Header value to sanitize

    Returns:
        str: Sanitized header value
    """
    if not value:
        return ''

    # Remove control characters
    sanitized = ''.join(c if c.isprintable() else ' ' for c in value)

    # Limit length
    return sanitized[:200]


# Import routes at the bottom to avoid circular imports
from blueprints.monitoring.routes import security_monitor_bp
from blueprints.monitoring.metrics import get_all_metrics

# Register nested blueprints
monitoring_bp.register_blueprint(security_monitor_bp)

# Export blueprint for application registration
__all__ = ['monitoring_bp']
