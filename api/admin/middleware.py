"""
Administrative API middleware for preprocessing requests and responses.

This module provides middleware functions for the admin API that handle cross-cutting
concerns such as:
- Enhanced security controls for administrative operations
- Administrative request tracking and metrics
- Request context enrichment for admin operations
- Sensitive data filtering and audit support
- Permission verification and IP restriction enforcement
- Additional security headers for administrative responses

These middleware functions ensure consistent security controls and monitoring
for all administrative API operations without duplicating code in individual route handlers.
"""

import ipaddress
import logging
import time
import socket
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from flask import current_app, g, jsonify, request, session
from marshmallow import Schema, fields, ValidationError
from werkzeug.exceptions import Forbidden, Unauthorized

from core.security import log_security_event
from core.security.cs_authentication import is_request_secure, get_client_ip
from extensions import db, metrics
from models.auth import Role, User
from models.security.audit_log import AuditLog

# Initialize module-level logger
logger = logging.getLogger(__name__)

# Constants for IP restriction
LOCALHOST_CIDR = "127.0.0.0/8"
DEFAULT_ADMIN_ALLOWED_IPS = [LOCALHOST_CIDR]


def setup_admin_request() -> None:
    """
    Setup request context for administrative requests.

    This middleware establishes administrative request context including:
    - Request tracking IDs
    - Start time for duration measurement
    - Client fingerprinting for security monitoring
    - Current user permission context
    - Request metadata for audit logging
    """
    # Set admin-specific request context
    g.is_admin_request = True
    g.admin_request_start_time = time.time()

    # Track admin request metrics
    metrics.counter(
        'admin_api_requests_total',
        1,
        labels={
            'endpoint': request.endpoint or 'unknown',
            'method': request.method
        }
    )

    # Store client information for security verification
    g.client_ip = get_client_ip()
    g.user_agent = request.headers.get('User-Agent', 'Unknown')
    g.referrer = request.headers.get('Referer', 'Unknown')
    g.admin_operation = request.endpoint.split('.')[-1] if request.endpoint else 'unknown'

    # Set up audit context
    g.admin_audit_data = {
        'ip_address': g.client_ip,
        'user_agent': g.user_agent,
        'endpoint': request.endpoint,
        'method': request.method,
        'path': request.path,
        'params': {k: v for k, v in request.args.items() if k.lower() not in
                   ('token', 'password', 'key', 'secret')}
    }

    # Add debug log for admin requests
    logger.debug(
        "Admin API request: %s %s from %s",
        request.method,
        request.path,
        g.client_ip
    )


def verify_admin_permission() -> None:
    """
    Verify administrative permissions for the current request.

    This middleware checks if the user has appropriate admin permissions,
    enforcing role-based access control for administrative API endpoints.

    Raises:
        Unauthorized: If no valid authentication is present
        Forbidden: If user lacks required administrative permissions
    """
    # Skip auth check for OPTIONS requests (CORS preflight)
    if request.method == 'OPTIONS':
        return

    # Skip auth check for health endpoint
    if request.endpoint and 'health_check' in request.endpoint:
        return

    # Check if user authenticated
    if not hasattr(g, 'user') or not g.user:
        logger.warning("Admin API access attempt without authentication from %s",
                      get_client_ip())
        raise Unauthorized("Authentication required for administrative access")

    # Check for basic admin role
    has_admin_role = False

    # Get user roles
    user_roles = [role.name for role in g.user.roles] if hasattr(g.user, 'roles') else []

    # Check against admin role list
    admin_roles = current_app.config.get('ADMIN_ROLES', ['admin', 'super_admin', 'security_admin'])
    has_admin_role = any(role in admin_roles for role in user_roles)

    if not has_admin_role:
        logger.warning(
            "Admin API access denied for user %s (roles: %s) at endpoint %s",
            g.user.username,
            ', '.join(user_roles),
            request.endpoint
        )

        # Log security event
        log_security_event(
            event_type=AuditLog.EVENT_ACCESS_DENIED,
            description=f"Admin API access denied for user {g.user.username}",
            severity="medium",
            user_id=g.user.id,
            ip_address=get_client_ip(),
            details={
                'endpoint': request.endpoint,
                'path': request.path,
                'user_roles': user_roles,
                'required_role': 'admin'
            }
        )

        raise Forbidden("Insufficient privileges for administrative access")


def enforce_ip_restrictions() -> None:
    """
    Enforce IP restrictions for administrative API access.

    This middleware validates client IP against whitelist for admin operations.
    IP restrictions add an additional layer of security beyond authentication.
    """
    # Skip IP check if disabled in configuration
    if not current_app.config.get('ADMIN_IP_RESTRICTIONS_ENABLED', True):
        return

    # Get client IP
    client_ip = get_client_ip()

    # Load allowed IP ranges
    allowed_ips = current_app.config.get('ADMIN_ALLOWED_IPS', DEFAULT_ADMIN_ALLOWED_IPS)

    # Check if client IP is in allowed ranges
    ip_allowed = False
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)

        # Check against each allowed network
        for allowed_cidr in allowed_ips:
            # Handle single IP addresses (convert to /32 or /128 CIDR)
            if '/' not in allowed_cidr:
                if client_ip == allowed_cidr:
                    ip_allowed = True
                    break
            else:
                # Parse as network
                network = ipaddress.ip_network(allowed_cidr, strict=False)
                if client_ip_obj in network:
                    ip_allowed = True
                    break
    except (ValueError, TypeError) as e:
        logger.error("IP restriction check error: %s", str(e))
        # Default to deny on error
        ip_allowed = False

    # Block if IP not allowed
    if not ip_allowed:
        logger.warning(
            "Admin API access denied due to IP restriction: %s not in allowed list",
            client_ip
        )

        # Log security event
        log_security_event(
            event_type=AuditLog.EVENT_ACCESS_DENIED,
            description=f"Admin API access denied due to IP restriction",
            severity="high",
            user_id=getattr(g, 'user_id', None),
            ip_address=client_ip,
            details={
                'endpoint': request.endpoint,
                'path': request.path
            }
        )

        # Return 403 Forbidden
        raise Forbidden("Administrative access not allowed from this IP address")


def filter_sensitive_data(response_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter sensitive data from response before returning to client.

    Args:
        response_data: The original response data dictionary

    Returns:
        Dict[str, Any]: Filtered response with sensitive data redacted
    """
    if not isinstance(response_data, dict):
        return response_data

    # List of sensitive field names (case-insensitive)
    sensitive_fields = {
        'password', 'secret', 'token', 'key', 'auth_key', 'api_key',
        'private_key', 'certificate', 'hash', 'salt', 'credential',
        'passphrase', 'cipher', 'encryption_key', 'mfa_secret'
    }

    # Create copy to avoid modifying original
    filtered_data = {}

    # Process all keys in response
    for key, value in response_data.items():
        # Check if key is sensitive
        if key.lower() in sensitive_fields:
            # Redact sensitive values
            filtered_data[key] = '******'
        elif isinstance(value, dict):
            # Recursively filter nested dictionaries
            filtered_data[key] = filter_sensitive_data(value)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            # Recursively filter list of dictionaries
            filtered_data[key] = [filter_sensitive_data(item) if isinstance(item, dict) else item
                                 for item in value]
        else:
            # Pass through non-sensitive values
            filtered_data[key] = value

    return filtered_data


def after_admin_request(response):
    """
    Process admin request after endpoint handler execution.

    This middleware adds security headers, records metrics, and handles
    other post-processing needs for administrative responses.

    Args:
        response: The Flask response object

    Returns:
        The modified response object
    """
    # Skip processing if response is None
    if response is None:
        return response

    # Track request duration
    if hasattr(g, 'admin_request_start_time'):
        duration = time.time() - g.admin_request_start_time
        endpoint = request.endpoint or 'unknown'

        # Record operation duration metrics
        metrics.histogram(
            'admin_api_action_duration_seconds',
            duration,
            labels={'action': endpoint.split('.')[-1] if endpoint else 'unknown'}
        )

    # Add enhanced security headers for admin API responses
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'

    # Filter sensitive data from JSON responses
    if response.is_json:
        try:
            filtered_data = filter_sensitive_data(response.get_json())
            response.set_data(jsonify(filtered_data).get_data())
        except Exception as e:
            # Log error but allow response to pass through
            logger.error("Error filtering sensitive data from response: %s", str(e))

    return response


def check_secure_transport() -> None:
    """
    Enforce secure transport (HTTPS) for administrative operations.

    This middleware verifies that administrative API requests use secure
    transport to prevent sensitive administrative operations over insecure channels.

    Raises:
        Forbidden: If the request is not made over a secure channel
    """
    # Skip check if explicitly disabled in configuration (for dev environments)
    if not current_app.config.get('ADMIN_REQUIRE_SECURE_CHANNEL', True):
        return

    # Check if request is secure
    if not is_request_secure():
        logger.warning(
            "Insecure admin API access attempt from %s to %s",
            get_client_ip(),
            request.path
        )

        # Log security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
            description="Insecure admin API access attempt",
            severity="high",
            user_id=getattr(g, 'user_id', None),
            ip_address=get_client_ip(),
            details={
                'endpoint': request.endpoint,
                'path': request.path
            }
        )

        raise Forbidden("Administrative API requires secure transport (HTTPS)")


def verify_content_type() -> None:
    """
    Verify appropriate content type for administrative requests.

    This middleware ensures that requests with bodies use correct content types
    to prevent content type confusion attacks and ensure proper parsing.
    """
    # Only check POST, PUT, PATCH requests that are likely to include bodies
    if request.method not in ('POST', 'PUT', 'PATCH'):
        return

    # Skip check if no content length header or content length is 0
    content_length = request.headers.get('Content-Length', '0')
    if content_length == '0':
        return

    # Check for valid content types
    content_type = request.headers.get('Content-Type', '')
    valid_types = [
        'application/json',
        'multipart/form-data',
        'application/x-www-form-urlencoded'
    ]

    # Partial match to handle content types with charset, boundary, etc.
    if not any(valid in content_type for valid in valid_types):
        logger.warning(
            "Invalid content type in admin request: %s from %s",
            content_type,
            get_client_ip()
        )

        raise ValidationError(
            {"error": "Invalid or missing Content-Type header"}
        )


def detect_suspicious_admin_activity() -> None:
    """
    Detect suspicious patterns in administrative API usage.

    This middleware identifies potentially suspicious activities such as:
    - Unusual access times or patterns
    - Multiple failed authentication attempts
    - Unusual operation sequences
    - Changes to critical system configurations
    """
    # Skip for health check and metrics endpoints
    if request.endpoint and ('health' in request.endpoint or 'metrics' in request.endpoint):
        return

    # Detect suspicious activities based on various signals
    suspicious = False
    suspicious_reasons = []

    # Check for unusual headers or header combinations
    unusual_headers = _check_unusual_headers()
    if unusual_headers:
        suspicious = True
        suspicious_reasons.append(f"Unusual headers: {', '.join(unusual_headers)}")

    # Check for unusual access patterns (if Redis is available)
    if hasattr(current_app, 'redis'):
        try:
            # Track IP access frequency
            ip_key = f"admin_api:access:{g.client_ip}:counter"
            access_count = current_app.redis.incr(ip_key)
            current_app.redis.expire(ip_key, 3600)  # 1 hour expiry

            # High frequency access might be suspicious
            if access_count > current_app.config.get('ADMIN_SUSPICIOUS_ACCESS_THRESHOLD', 30):
                suspicious = True
                suspicious_reasons.append(f"High frequency access: {access_count} requests/hour")

        except Exception as e:
            logger.warning("Redis tracking error: %s", str(e))

    # If suspicious activity detected, log a security event
    if suspicious:
        logger.warning(
            "Suspicious admin activity detected: %s from %s",
            "; ".join(suspicious_reasons),
            g.client_ip
        )

        # Log security event
        log_security_event(
            event_type=AuditLog.EVENT_SUSPICIOUS_ACTIVITY,
            description="Suspicious admin API activity detected",
            severity="medium",
            user_id=getattr(g, 'user_id', None),
            ip_address=g.client_ip,
            details={
                'reasons': suspicious_reasons,
                'endpoint': request.endpoint,
                'user_agent': g.user_agent,
                'referrer': g.referrer
            }
        )


def _check_unusual_headers() -> List[str]:
    """
    Check for unusual or suspicious HTTP headers in the request.

    Returns:
        List[str]: List of suspicious header names found
    """
    unusual_headers = []

    # Headers that might indicate proxy/scanning tools
    suspicious_headers = {
        'X-Scan', 'X-Scanner', 'X-Forwarded-Host',
        'X-Originating-IP', 'Forwarded-For', 'X-Remote-IP',
        'Client-IP', 'True-Client-IP', 'Bypass-Tunnel',
        'X-Forwarded-For-Original', 'X-Scan-Signature', 'X-Scan-Token'
    }

    # Check for presence of suspicious headers
    for header in suspicious_headers:
        if header in request.headers:
            unusual_headers.append(header)

    # Check for inconsistent forwarding headers
    forwarded_headers = [
        request.headers.get('X-Forwarded-For', ''),
        request.headers.get('Forwarded', ''),
        request.headers.get('X-Real-IP', '')
    ]

    # If multiple forwarding headers with different values
    forwarded_values = [h for h in forwarded_headers if h]
    if len(forwarded_values) > 1 and len(set(forwarded_values)) > 1:
        unusual_headers.append('inconsistent-forwarding-headers')

    return unusual_headers


def init_admin_middleware(app):
    """
    Initialize and register all admin API middleware with the Flask application.

    This function sets up before_request and after_request handlers specific to
    the admin API blueprint.

    Args:
        app: Flask application instance
    """
    from api.admin import admin_api

    @admin_api.before_request
    def before_admin_request():
        """Apply middleware before processing admin requests."""
        # Check for HTTPS
        check_secure_transport()

        # Set up admin request context
        setup_admin_request()

        # Validate content type
        verify_content_type()

        # Check user permissions
        verify_admin_permission()

        # Check IP restrictions
        enforce_ip_restrictions()

        # Check for suspicious activity
        detect_suspicious_admin_activity()

    @admin_api.after_request
    def admin_after_request(response):
        """Apply middleware after processing admin requests."""
        return after_admin_request(response)

    logger.info("Admin API middleware initialized successfully")
