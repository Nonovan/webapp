"""
Authentication blueprint package for myproject.

This blueprint handles all authentication-related functionality including:
- User login and logout flows
- Session management and protection
- Authentication error handling and audit logging
- Security metrics collection and anomaly detection
- MFA enforcement and verification
- Access control and permission management

The package provides the auth_bp Blueprint with request hooks for security
monitoring, metrics tracking, and proper cleanup after each request. It implements
appropriate error handlers for authentication-related HTTP status codes such as
401 Unauthorized and 403 Forbidden to provide consistent error responses.

Request metrics are automatically collected to track authentication attempts,
failures, and patterns for security monitoring purposes.
"""

import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, Union, List

from flask import Blueprint, current_app, request, session, g, jsonify, render_template
from werkzeug.exceptions import Unauthorized, Forbidden, BadRequest
from werkzeug.user_agent import UserAgent

from extensions import metrics, db, cache, limiter
from extensions.circuit_breaker import CircuitOpenError, RateLimitExceededError
from core.security import log_security_event, verify_token_signature
from core.security.cs_authentication import is_request_secure
from core import generate_request_id
from models.security import AuditLog

# Initialize module-level logger
logger = logging.getLogger(__name__)

# Security constants
MAX_SUSPICIOUS_HEADERS = 5
CACHE_TIMEOUT = 300  # 5 minutes
SESSION_ACTIVITY_TIMEOUT = 30  # minutes
AUTH_FEATURE_FLAGS = {}  # Feature flags for auth functionality

# Create Blueprint with correct configuration
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
    - Detects suspicious authentication patterns
    - Verifies CSRF tokens for state-changing operations
    - Validates session integrity and timeout

    Returns:
        None: This function modifies the Flask g object as a side effect

    Raises:
        Unauthorized: If request contains suspicious security headers or session is invalid
        BadRequest: If CSRF token is invalid for state-changing operations
    """
    g.start_time = datetime.utcnow()

    # Generate or retrieve request ID for tracing
    request_id = request.headers.get('X-Request-ID')
    g.request_id = request_id if request_id else generate_request_id()

    # Add context for security logging
    g.security_context = {
        'ip_address': _get_client_ip(),
        'user_agent': request.user_agent.string if request.user_agent else 'unknown',
        'referrer': request.referrer or 'direct',
        'is_secure': request.is_secure,
        'is_xhr': request.is_xhr,
        'request_id': g.request_id
    }

    # Record additional user context if available
    user_id = session.get('user_id', 'anonymous')
    g.user_id = user_id

    # Track metrics for this request
    endpoint_name = request.endpoint.split('.')[-1] if request.endpoint else 'unknown'
    metrics.info('auth_requests_total', 1, labels={
        'method': request.method,
        'endpoint': endpoint_name,
        'user_id': user_id
    })

    # Enforce HTTPS in production
    if current_app.config.get('ENV') == 'production' and not is_request_secure(request):
        logger.warning(
            'Insecure authentication request rejected',
            extra={'url': request.url, 'ip': g.security_context['ip_address']}
        )
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_ERROR,
            description="Insecure authentication request rejected",
            severity=AuditLog.SEVERITY_WARNING,
            ip_address=g.security_context['ip_address'],
            details={
                'url': request.url,
                'method': request.method
            }
        )
        raise Unauthorized("Authentication requires secure connection")

    # Validate session integrity
    if 'user_id' in session and not _is_public_endpoint():
        if not _validate_session_integrity():
            session.clear()
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_INVALID,
                description="Session integrity check failed",
                severity=AuditLog.SEVERITY_WARNING,
                ip_address=g.security_context['ip_address'],
                details={'endpoint': request.endpoint}
            )
            # Instead of raising Unauthorized, redirect to login
            # since the user experience is better
            return redirect(url_for('auth.login'))

        # Check for session timeout
        if _is_session_timed_out():
            session.clear()
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_TIMEOUT,
                description="Session timed out due to inactivity",
                severity=AuditLog.SEVERITY_INFO,
                user_id=user_id,
                ip_address=g.security_context['ip_address']
            )
            # Don't raise exception, redirect to login with message
            flash('Your session has expired due to inactivity. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

    # Check for suspicious patterns
    if _is_suspicious_request():
        # Check rate limit for suspicious requests from this IP
        cache_key = f'suspicious_auth_ip:{g.security_context["ip_address"]}'
        suspicious_count = cache.get(cache_key) or 0

        if suspicious_count >= MAX_SUSPICIOUS_HEADERS:
            metrics.info('auth_blocked_suspicious_ip_total', 1)
            log_security_event(
                event_type=AuditLog.EVENT_SUSPICIOUS_IP_BLOCKED,
                description=f"Blocked suspicious IP after multiple suspicious auth requests",
                severity=AuditLog.SEVERITY_WARNING,
                ip_address=g.security_context['ip_address'],
                details={'count': suspicious_count, 'path': request.path}
            )
            # Return 403 instead of raising exception for better metrics tracking
            return jsonify({
                'error': 'Forbidden',
                'message': 'Access denied'
            }), 403
        else:
            # Increment counter
            cache.set(cache_key, suspicious_count + 1, timeout=3600)  # 1 hour timeout

        log_security_event(
            event_type=AuditLog.EVENT_SUSPICIOUS_REQUEST,
            description=f"Suspicious authentication request detected",
            severity=AuditLog.SEVERITY_WARNING,
            user_id=user_id,
            ip_address=g.security_context['ip_address'],
            details={
                'headers': {k: v for k, v in request.headers.items()
                           if k.lower() not in ('cookie', 'authorization')},
                'path': request.path,
                'method': request.method,
                'user_agent': g.security_context['user_agent'][:200]  # Limit length
            }
        )
        metrics.info('auth_suspicious_request_total', 1, labels={
            'method': request.method,
            'endpoint': endpoint_name
        })

    # CSRF protection for state-changing operations
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and not _is_csrf_exempt():
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not csrf_token or not _validate_csrf_token(csrf_token):
            log_security_event(
                event_type=AuditLog.EVENT_CSRF_FAILURE,
                description="CSRF validation failed",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=user_id,
                ip_address=g.security_context['ip_address'],
                details={
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'referrer': g.security_context['referrer']
                }
            )
            metrics.info('auth_csrf_failures_total', 1)
            raise BadRequest("CSRF validation failed")


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
        lambda h: any(x in h.get('User-Agent', '').lower() for x in
                    ['sqlmap', 'nikto', 'nessus', 'burp', 'openvas', 'dirbuster', 'gobuster',
                     'metasploit', 'masscan', 'hydra', 'brutus', 'backbox']),

        # Unusual or missing Host header
        lambda h: not h.get('Host') or '.' not in h.get('Host', ''),

        # Headers often used in bypass techniques
        lambda h: any(header in h for header in [
            'X-Remote-User', 'X-Authenticated-User', 'X-Admin-Override',
            'X-Original-URL', 'X-Rewrite-URL', 'X-Override-URL'
        ]),

        # XSS payload in headers
        lambda h: any(('<script>' in v.lower() or 'javascript:' in v.lower() or 'onerror=' in v.lower())
                     for v in h.values())
    ]

    return any(pattern(headers) for pattern in suspicious_patterns)


def _is_suspicious_request() -> bool:
    """
    Check if the current request contains suspicious indicators.

    This function evaluates multiple aspects of the request to determine
    if it might be malicious or part of an attack pattern.

    Returns:
        bool: True if the request is suspicious, False otherwise
    """
    # Check headers for suspicious patterns
    if _contains_suspicious_headers(request.headers):
        return True

    # Check for authentication/authorization header inconsistencies
    if 'Authorization' in request.headers and 'Cookie' in request.headers:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer ') and 'session' in request.headers.get('Cookie', ''):
            # Using both token and session auth simultaneously is suspicious
            return True

    # Check for unusual query parameters
    query_string = request.query_string.decode('utf-8', errors='ignore').lower()
    suspicious_params = ['union+select', 'exec(', 'eval(', '../', '<script>',
                      'document.cookie', 'onload=', 'javascript:', 'fromcharcode']

    if any(param in query_string for param in suspicious_params):
        return True

    # Check for suspicious session access patterns
    if _is_session_pattern_suspicious():
        return True

    # Check user agent for common attack tools or unusual patterns
    ua = request.user_agent.string.lower() if request.user_agent else ''
    if not ua or len(ua) < 10:
        return True

    # All checks passed
    return False


def _is_session_pattern_suspicious() -> bool:
    """
    Detect suspicious session access patterns.

    Returns:
        bool: True if suspicious session activity is detected
    """
    # This endpoint should never have BOTH session and special header
    if request.endpoint == 'auth.token' and 'user_id' in session and 'X-API-Key' in request.headers:
        return True

    # User shouldn't be attempting logout without a session
    if request.endpoint == 'auth.logout' and 'user_id' not in session:
        return True

    # MFA verification shouldn't be attempted if not in pending MFA state
    if request.endpoint == 'auth.mfa_verify' and not session.get('awaiting_mfa', False):
        return True

    # Session jumping detection (rapid geographic changes)
    current_ip = g.security_context['ip_address']
    last_ip = session.get('ip_address')

    if 'user_id' in session and last_ip and current_ip != last_ip:
        # Get geo locations and compare
        if _is_geographic_shift_suspicious(last_ip, current_ip):
            return True

    return False


def _is_geographic_shift_suspicious(last_ip: str, current_ip: str) -> bool:
    """
    Check if there's a suspicious geographic shift between IP addresses.

    Args:
        last_ip: Previous IP address
        current_ip: Current IP address

    Returns:
        bool: True if the shift is suspicious
    """
    # For now, implement a basic check (consider integrating GeoIP in production)
    # Check if IPs are in completely different IP ranges
    try:
        if last_ip.split('.')[0] != current_ip.split('.')[0]:
            # Different class A networks in a short time period
            last_auth_time = session.get('last_active')
            if last_auth_time:
                last_auth = datetime.fromisoformat(last_auth_time)
                time_diff = (datetime.utcnow() - last_auth).total_seconds()
                # If less than 10 minutes between auth attempts from different networks
                if time_diff < 600:
                    return True
    except (IndexError, ValueError):
        # If we can't parse the IPs, better to be safe
        return True

    return False


def _validate_session_integrity() -> bool:
    """
    Validate session integrity by checking critical session attributes.

    Returns:
        bool: True if the session passes integrity checks
    """
    # Check for required session fields
    required_fields = ['user_id', 'session_id']
    if not all(field in session for field in required_fields):
        logger.warning("Session missing required fields")
        return False

    # Check if session ID was signed and is valid
    if 'session_id' in session:
        stored_session_id = session.get('session_id')
        if not verify_token_signature(stored_session_id, current_app.config.get('SECRET_KEY')):
            logger.warning("Session ID signature validation failed")
            return False

    # Verify user agent consistency if we're tracking it
    if 'user_agent' in session:
        current_ua = request.user_agent.string if request.user_agent else 'unknown'
        stored_ua = session.get('user_agent')

        # Only validate user agent string up to 50 chars to handle minor UA updates
        if stored_ua[:50] != current_ua[:50]:
            logger.warning(f"User agent mismatch: {stored_ua[:20]} vs {current_ua[:20]}")
            return False

    return True


def _is_session_timed_out() -> bool:
    """
    Check if the current session has timed out due to inactivity.

    Returns:
        bool: True if session has timed out
    """
    last_active_str = session.get('last_active')
    if not last_active_str:
        return False  # No activity timestamp, can't determine timeout

    try:
        last_active = datetime.fromisoformat(last_active_str)
        timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', SESSION_ACTIVITY_TIMEOUT)

        # Check if the session has exceeded the timeout period
        if datetime.utcnow() - last_active > timedelta(minutes=timeout_minutes):
            return True
    except (ValueError, TypeError) as e:
        logger.warning(f"Error parsing session timestamp: {e}")
        return True  # If we can't parse the timestamp, consider it timed out

    # Update last active timestamp
    session['last_active'] = datetime.utcnow().isoformat()
    session.modified = True

    return False


def _is_csrf_exempt() -> bool:
    """
    Check if the current request should be exempt from CSRF protection.

    Returns:
        bool: True if the request is exempt from CSRF checks
    """
    # API token endpoints are exempt
    if request.endpoint == 'auth.token':
        return True

    # OAuth callbacks are exempt
    if request.endpoint in ['auth.oauth_callback', 'auth.oauth_authorized']:
        return True

    # Exempt if using token-based authentication (API)
    if 'Authorization' in request.headers and request.headers.get('Authorization', '').startswith('Bearer '):
        return True

    # Exempt if this is a JSON request with API key
    if request.is_json and request.headers.get('X-API-Key'):
        return True

    return False


def _validate_csrf_token(token: str) -> bool:
    """
    Validate a CSRF token against the session token.

    Args:
        token: The CSRF token to validate

    Returns:
        bool: True if token is valid
    """
    if not token or not session.get('csrf_token'):
        return False

    # Use constant time comparison to prevent timing attacks
    return secrets.compare_digest(token, session.get('csrf_token', ''))


def _get_client_ip() -> str:
    """
    Get the client IP address, respecting proxy headers if configured.

    Returns:
        str: Client IP address
    """
    # Check for X-Forwarded-For header if trusted proxies are configured
    if current_app.config.get('TRUSTED_PROXIES', False):
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Get the leftmost IP which is the client IP
            return forwarded_for.split(',')[0].strip()

    # Fall back to remote_addr
    return request.remote_addr


def _is_public_endpoint() -> bool:
    """
    Check if the current endpoint is a public endpoint that doesn't require authentication.

    Returns:
        bool: True if this is a public endpoint
    """
    public_endpoints = [
        'auth.login',
        'auth.register',
        'auth.forgot_password',
        'auth.reset_password',
        'auth.oauth_login',
        'auth.verify_email'
    ]

    return request.endpoint in public_endpoints


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

    # Add request ID to response headers for traceability
    response.headers['X-Request-ID'] = g.request_id

    # Add Content-Security-Policy header if not present
    if 'Content-Security-Policy' not in response.headers:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        ).format(nonce=g.get('nonce', 'no-nonce'))

    # Add cache control directives for sensitive auth pages
    if request.endpoint in ['auth.login', 'auth.reset_password', 'auth.mfa_verify',
                          'auth.register', 'auth.change_password', 'auth.confirm_password']:
        response.headers['Cache-Control'] = 'no-store, max-age=0, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    # Add timing information if we have it
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        response.headers['X-Response-Time'] = f'{duration:.3f}s'

    # Refresh CSRF token in session if needed
    if 'user_id' in session and request.method != 'OPTIONS' and not session.get('csrf_token'):
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.modified = True

    # Track response status
    status_category = response.status_code // 100
    metrics.info('auth_responses_total', 1, labels={
        'status_category': f'{status_category}xx',
        'endpoint': request.endpoint or 'unknown',
        'method': request.method
    })

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
            'ip': g.security_context.get('ip_address', request.remote_addr),
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
        ip_address=g.security_context.get('ip_address', request.remote_addr),
        details={
            'url': request.path,
            'method': request.method,
            'user_agent': g.security_context.get('user_agent'),
        },
        category=AuditLog.EVENT_CATEGORY_AUTH
    )

    metrics.info('auth_unauthorized_total', 1)

    # Return appropriate response format based on request
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Unauthorized access',
            'code': 401,
            'message': 'Authentication is required to access this resource',
            'request_id': g.get('request_id', 'unknown')
        }), 401
    else:
        return render_template('auth/errors/401.html',
                             request_id=g.get('request_id', 'unknown')), 401


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
            'ip': g.security_context.get('ip_address', request.remote_addr),
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
        ip_address=g.security_context.get('ip_address', request.remote_addr),
        details={
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path,
            'required_role': getattr(_error, 'required_role', None)
        },
        category=AuditLog.EVENT_CATEGORY_ACCESS
    )

    metrics.info('auth_forbidden_total', 1, labels={
        'endpoint': request.endpoint or 'unknown'
    })

    # Return appropriate response format based on request
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Forbidden access',
            'code': 403,
            'message': 'You do not have permission to access this resource',
            'request_id': g.get('request_id', 'unknown')
        }), 403
    else:
        # Pass required role to template if available
        template_params = {
            'request_id': g.get('request_id', 'unknown')
        }

        if hasattr(_error, 'required_role'):
            template_params['required_role'] = _error.required_role

        if hasattr(_error, 'description'):
            template_params['description'] = _error.description

        return render_template('auth/errors/403.html', **template_params), 403


@auth_bp.app_errorhandler(400)
def bad_request_error(error) -> Union[Tuple[Dict[str, Any], int], Tuple[str, int]]:
    """
    Handle bad request errors (HTTP 400).

    This handler processes 400 Bad Request responses, which typically occur
    due to invalid parameters or malformed requests.

    Args:
        error: The error that triggered this handler

    Returns:
        tuple: Response and status code
    """
    current_app.logger.info(
        f'Bad request: {str(error)}',
        extra={
            'url': request.url,
            'ip': g.security_context.get('ip_address', request.remote_addr),
            'request_id': g.get('request_id', 'unknown')
        }
    )

    metrics.info('auth_bad_request_total', 1, labels={
        'endpoint': request.endpoint or 'unknown'
    })

    # Return appropriate response format
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Bad Request',
            'code': 400,
            'message': str(error),
            'request_id': g.get('request_id', 'unknown')
        }), 400
    else:
        return render_template('auth/errors/400.html',
                             error=error,
                             request_id=g.get('request_id', 'unknown')), 400


@auth_bp.errorhandler(CircuitOpenError)
def handle_circuit_open_error(error):
    """
    Handle circuit breaker errors to provide user-friendly responses.

    When a circuit breaker is open due to repeated failures, this handler
    provides a graceful degradation of service and prevents cascading failures.

    Args:
        error: The CircuitOpenError exception

    Returns:
        Response: Rendered error template with proper message
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
            "error": str(error),
            "request_id": g.get('request_id', 'unknown')
        }
    )

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Service temporarily unavailable',
            'code': 503,
            'retry_after': 60,  # Suggest retry after 1 minute
            'request_id': g.get('request_id', 'unknown')
        }), 503, {'Retry-After': '60'}

    flash_message = "The authentication service is temporarily unavailable. Please try again later."

    # Special case handling for MFA verification
    if 'awaiting_mfa' in session and session.get('awaiting_mfa'):
        flash(flash_message, 'danger')
        return redirect(url_for('auth.login'))

    return render_template('auth/errors/service_unavailable.html',
                          message=flash_message,
                          request_id=g.get('request_id', 'unknown'),
                          retry_seconds=60), 503, {'Retry-After': '60'}


@auth_bp.errorhandler(RateLimitExceededError)
def handle_rate_limit_exceeded_error(error):
    """
    Handle rate limit exceeded errors to provide user-friendly responses.

    This handler processes rate limiting errors and provides standardized
    responses with appropriate retry information.

    Args:
        error: The RateLimitExceededError exception

    Returns:
        Response: Rendered error template with proper message
    """
    current_app.logger.warning(f"Rate limit exceeded: {str(error)}")
    metrics.info('auth_rate_limit_exceeded_total', 1, labels={
        'endpoint': request.endpoint or 'unknown'
    })

    # Extract retry_after information if available
    retry_after = getattr(error, 'retry_after', 60)

    # Add to security audit log
    log_security_event(
        event_type=AuditLog.EVENT_RATE_LIMIT,
        description=f"Rate limit exceeded on auth endpoint: {request.endpoint}",
        severity=AuditLog.SEVERITY_WARNING,
        ip_address=g.security_context.get('ip_address', request.remote_addr),
        details={
            'endpoint': request.endpoint,
            'method': request.method,
            'retry_after': retry_after,
            'request_id': g.get('request_id', 'unknown')
        },
        category=AuditLog.EVENT_CATEGORY_SECURITY
    )

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'error': 'Rate limit exceeded',
            'code': 429,
            'retry_after': retry_after,
            'request_id': g.get('request_id', 'unknown')
        }), 429, {'Retry-After': str(retry_after)}

    flash_message = "You've made too many requests. Please wait a moment before trying again."
    return render_template('auth/errors/rate_limit.html',
                          message=flash_message,
                          retry_seconds=retry_after,
                          request_id=g.get('request_id', 'unknown')), 429, {'Retry-After': str(retry_after)}


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
                ip_address=g.security_context.get('ip_address', request.remote_addr),
                details={
                    'exception_type': exc.__class__.__name__,
                    'endpoint': request.endpoint,
                    'request_id': g.get('request_id', 'unknown')
                },
                category=AuditLog.EVENT_CATEGORY_AUTH
            )

    # Always remove db session
    db.session.remove()

    # Calculate and record request duration
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.info('auth_request_duration_seconds', duration, labels={
            'endpoint': request.endpoint or 'unknown',
            'method': request.method,
            'status': 'error' if exc else 'success'
        })


# Initialize authentication feature flags from configuration
def _load_feature_flags() -> Dict[str, bool]:
    """
    Load authentication feature flags from application configuration.

    This function initializes feature flags for dynamic authentication behavior.

    Returns:
        Dict[str, bool]: Dictionary of feature flags
    """
    global AUTH_FEATURE_FLAGS

    flags = {
        'mfa_enabled': current_app.config.get('ENABLE_MFA', True),
        'password_strength_check': current_app.config.get('ENFORCE_PASSWORD_STRENGTH', True),
        'social_auth_enabled': current_app.config.get('ENABLE_SOCIAL_AUTH', False),
        'recaptcha_enabled': current_app.config.get('ENABLE_RECAPTCHA', False),
        'session_ip_binding': current_app.config.get('SESSION_IP_BINDING', True),
        'session_ua_binding': current_app.config.get('SESSION_UA_BINDING', True),
        'secure_cookies': current_app.config.get('SESSION_COOKIE_SECURE', True),
        'password_breach_check': current_app.config.get('CHECK_BREACHED_PASSWORDS', False),
        'audit_logging': current_app.config.get('ENABLE_AUTH_AUDIT_LOG', True),
        'rate_limiting': current_app.config.get('ENABLE_AUTH_RATE_LIMITING', True),
    }

    AUTH_FEATURE_FLAGS.update(flags)
    return AUTH_FEATURE_FLAGS


# Initialize feature flags when blueprint is registered
@auth_bp.record_once
def on_blueprint_init(state):
    """
    Initialize blueprint with application context.

    Args:
        state: Blueprint state from registration
    """
    # Set up feature flags
    with state.app.app_context():
        _load_feature_flags()


# Ensure Flask imports available to routes
from flask import flash, redirect, url_for
import flask
import json

# For consistency and type safety
__all__ = ['auth_bp']
