"""
Error handling module for the Administrative API.

This module provides centralized error handling for the admin API, ensuring
consistent error responses across different routes and error types. It implements
specialized error classes, standardized error formatting, and comprehensive
logging for administrative operations.

Key features:
- Standardized JSON error responses
- Detailed error information for troubleshooting
- Automatic security event logging for critical errors
- Request ID inclusion for error tracking
- Metrics collection for monitoring error patterns
- Sanitized error messages to prevent information leakage
- Role-specific error details based on user permissions
"""

import json
import logging
import traceback
from typing import Dict, Any, Optional, Tuple, List, Union, Type

from flask import jsonify, g, request, current_app, Response
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from werkzeug.exceptions import HTTPException, Forbidden, NotFound, BadRequest, Unauthorized
from werkzeug.http import HTTP_STATUS_CODES

from core.security import log_security_event
from extensions import metrics, db
from models.security.audit_log import AuditLog


# Initialize logger
logger = logging.getLogger(__name__)

# Configure metrics for admin error tracking
admin_error_counter = metrics.counter(
    'admin_api_errors_total',
    'Total number of Administrative API errors',
    labels=['error_type', 'status_code', 'endpoint']
)

admin_database_error_counter = metrics.counter(
    'admin_api_database_errors_total',
    'Total number of Administrative API database errors',
    labels=['operation', 'entity']
)


class AdminError(Exception):
    """Base exception class for administrative API errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str = "admin_error",
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class AdminValidationError(AdminError):
    """Exception raised for input validation errors."""

    def __init__(
        self,
        message: str = "Invalid input parameters",
        details: Optional[Dict[str, Any]] = None,
        error_code: str = "validation_error"
    ):
        super().__init__(
            message=message,
            status_code=400,
            error_code=error_code,
            details=details
        )


class AdminResourceNotFoundError(AdminError):
    """Exception raised when a requested resource is not found."""

    def __init__(
        self,
        resource_type: str = "Resource",
        resource_id: Optional[str] = None,
        error_code: str = "resource_not_found"
    ):
        message = f"{resource_type} not found"
        if resource_id:
            message += f": {resource_id}"

        super().__init__(
            message=message,
            status_code=404,
            error_code=error_code,
            details={"resource_type": resource_type, "resource_id": resource_id}
        )


class AdminPermissionError(AdminError):
    """Exception raised for permission-related errors."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        required_role: Optional[str] = None,
        required_permission: Optional[str] = None,
        error_code: str = "permission_denied"
    ):
        details = {}
        if required_role:
            details["required_role"] = required_role
        if required_permission:
            details["required_permission"] = required_permission

        super().__init__(
            message=message,
            status_code=403,
            error_code=error_code,
            details=details
        )


class AdminAuthenticationError(AdminError):
    """Exception raised for authentication failures."""

    def __init__(
        self,
        message: str = "Authentication required",
        error_code: str = "authentication_error"
    ):
        super().__init__(
            message=message,
            status_code=401,
            error_code=error_code
        )


class AdminIntegrityError(AdminError):
    """Exception raised when a database integrity constraint is violated."""

    def __init__(
        self,
        message: str = "Data integrity constraint violated",
        details: Optional[Dict[str, Any]] = None,
        error_code: str = "integrity_error"
    ):
        super().__init__(
            message=message,
            status_code=409,
            error_code=error_code,
            details=details
        )


class AdminConfigurationError(AdminError):
    """Exception raised for configuration-related errors."""

    def __init__(
        self,
        message: str = "Configuration error",
        details: Optional[Dict[str, Any]] = None,
        error_code: str = "configuration_error"
    ):
        super().__init__(
            message=message,
            status_code=500,
            error_code=error_code,
            details=details
        )


class AdminRateLimitError(AdminError):
    """Exception raised when rate limits are exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        limit: Optional[str] = None,
        reset_time: Optional[int] = None,
        error_code: str = "rate_limit_exceeded"
    ):
        details = {}
        if limit:
            details["limit"] = limit
        if reset_time:
            details["reset_time"] = reset_time

        super().__init__(
            message=message,
            status_code=429,
            error_code=error_code,
            details=details
        )


class AdminServiceUnavailableError(AdminError):
    """Exception raised when a required service is unavailable."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        service_name: Optional[str] = None,
        retry_after: Optional[int] = None,
        error_code: str = "service_unavailable"
    ):
        details = {}
        if service_name:
            details["service_name"] = service_name
        if retry_after:
            details["retry_after"] = retry_after

        super().__init__(
            message=message,
            status_code=503,
            error_code=error_code,
            details=details
        )


class AdminMFARequiredError(AdminError):
    """Exception raised when MFA verification is required for an operation."""

    def __init__(
        self,
        message: str = "Multi-factor authentication required for this action",
        error_code: str = "mfa_required"
    ):
        super().__init__(
            message=message,
            status_code=403,
            error_code=error_code,
            details={"mfa_required": True}
        )


class AdminApprovalRequiredError(AdminError):
    """Exception raised when additional approval is required for an operation."""

    def __init__(
        self,
        message: str = "Additional approval required for this action",
        approval_type: str = "standard",
        error_code: str = "approval_required"
    ):
        super().__init__(
            message=message,
            status_code=403,
            error_code=error_code,
            details={"approval_type": approval_type}
        )


def format_error_response(error: Union[AdminError, Exception], status_code: int = 500) -> Dict[str, Any]:
    """
    Format an error into a standardized response dictionary.

    Args:
        error: The exception to format
        status_code: HTTP status code for the response

    Returns:
        Dictionary with formatted error details
    """
    if isinstance(error, AdminError):
        status_code = error.status_code
        error_code = error.error_code
        details = error.details
        message = error.message
    else:
        error_code = "server_error"
        message = str(error) if status_code < 500 else "An unexpected error occurred"
        details = {}

    response = {
        "error": HTTP_STATUS_CODES.get(status_code, "Unknown Error"),
        "error_code": error_code,
        "status_code": status_code,
        "message": message
    }

    # Add request ID if available
    if hasattr(g, 'request_id'):
        response["request_id"] = g.request_id

    # Add documentation URL for common errors
    if status_code in (400, 401, 403, 404, 422, 429):
        response["documentation_url"] = f"https://docs.example.com/api/errors/{status_code}"

    # Include error details if available and not an internal server error
    if details and status_code < 500:
        response["details"] = details

    # For 500-level errors, include a reference ID for support
    if status_code >= 500:
        import uuid
        trace_id = str(uuid.uuid4())
        response["trace_id"] = trace_id

        # Log the full error with trace ID for later lookup
        logger.error(
            f"Admin API Error [{trace_id}]: {str(error)}",
            extra={
                'trace_id': trace_id,
                'error_type': error.__class__.__name__,
                'endpoint': request.endpoint,
                'path': request.path
            },
            exc_info=True
        )

    return response


def handle_admin_error(
    error: Union[AdminError, Exception],
    status_code: int = 500,
    log_security_event_on_error: bool = True
) -> Tuple[Response, int]:
    """
    Handle an exception raised during admin API processing.

    Args:
        error: The exception to handle
        status_code: Default HTTP status code if not an AdminError
        log_security_event_on_error: Whether to log a security event for this error

    Returns:
        Tuple with JSON response and status code
    """
    # Determine actual status code
    if isinstance(error, AdminError):
        status_code = error.status_code
    elif isinstance(error, HTTPException):
        status_code = error.code

    # Increment error metrics
    admin_error_counter.inc(labels={
        'error_type': error.__class__.__name__,
        'status_code': status_code,
        'endpoint': request.endpoint or 'unknown'
    })

    # Format the error response
    response = format_error_response(error, status_code)

    # Determine severity based on status code
    if status_code >= 500:
        severity = "high"
        log_level = logging.ERROR
    elif status_code >= 400:
        severity = "medium"
        log_level = logging.WARNING
    else:
        severity = "low"
        log_level = logging.INFO

    # Log the error
    if log_level >= logging.ERROR:
        logger.log(log_level, f"Admin API Error: {str(error)}", exc_info=True)
    else:
        logger.log(log_level, f"Admin API Error: {str(error)}")

    # Log security event for significant errors
    if log_security_event_on_error and status_code >= 400:
        try:
            # Determine event type based on error
            if status_code == 401:
                event_type = AuditLog.EVENT_AUTHENTICATION_FAILURE
            elif status_code == 403:
                event_type = AuditLog.EVENT_ACCESS_DENIED
            elif status_code >= 500:
                event_type = AuditLog.EVENT_SYSTEM_ERROR
            else:
                event_type = AuditLog.EVENT_API_ERROR

            # Log security event with sanitized details
            log_security_event(
                event_type=event_type,
                description=f"Admin API error: {response['message']}",
                severity=severity,
                user_id=getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None,
                ip_address=request.remote_addr,
                details={
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "status_code": status_code,
                    "error_type": error.__class__.__name__,
                    "request_id": response.get("request_id")
                }
            )
        except Exception as e:
            # Don't let security event logging itself cause failures
            logger.warning(f"Failed to log security event for admin error: {e}")

    # Return the formatted error response
    return jsonify(response), status_code


def register_error_handlers(blueprint):
    """
    Register error handlers for the admin API blueprint.

    Args:
        blueprint: The Flask blueprint to register handlers on
    """
    @blueprint.errorhandler(AdminError)
    def handle_admin_api_error(error):
        """Handle custom AdminError exceptions with structured response."""
        return handle_admin_error(error)

    @blueprint.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle schema validation errors."""
        return handle_admin_error(
            AdminValidationError(message=str(error), details=getattr(error, 'messages', None))
        )

    @blueprint.errorhandler(Forbidden)
    def handle_forbidden_error(error):
        """Handle permission errors."""
        return handle_admin_error(
            AdminPermissionError(
                message=str(error) or "You do not have permission to access this resource",
                required_role=getattr(error, 'description', None)
            )
        )

    @blueprint.errorhandler(Unauthorized)
    def handle_unauthorized_error(error):
        """Handle authentication errors."""
        return handle_admin_error(
            AdminAuthenticationError(
                message=str(error) or "Authentication required"
            )
        )

    @blueprint.errorhandler(NotFound)
    def handle_not_found_error(error):
        """Handle resource not found errors."""
        return handle_admin_error(
            AdminResourceNotFoundError(
                resource_type="Resource",
                resource_id=request.path
            )
        )

    @blueprint.errorhandler(BadRequest)
    def handle_bad_request_error(error):
        """Handle bad request errors."""
        return handle_admin_error(
            AdminValidationError(
                message=str(error) or "Invalid request parameters"
            )
        )

    @blueprint.errorhandler(IntegrityError)
    def handle_integrity_error(error):
        """Handle database integrity errors."""
        db.session.rollback()

        # Log the specific database error details
        logger.error(f"Database integrity error in admin API: {str(error)}")

        # Increment specific database error metric
        admin_database_error_counter.inc(labels={
            'operation': request.method,
            'entity': request.endpoint.split('.')[-1] if request.endpoint else 'unknown'
        })

        # Create sanitized error response
        return handle_admin_error(
            AdminIntegrityError(
                message="The requested change conflicts with existing data",
                details={"constraint_violation": True}
            )
        )

    @blueprint.errorhandler(SQLAlchemyError)
    def handle_database_error(error):
        """Handle database errors."""
        db.session.rollback()
        logger.error(f"Database error in admin API: {str(error)}")
        return handle_admin_error(error, 500)

    @blueprint.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle unexpected errors."""
        logger.error(f"Unexpected error in admin API: {str(error)}", exc_info=True)
        return handle_admin_error(error, 500)


def parse_error_details(error: Exception) -> Dict[str, Any]:
    """
    Parse detailed information from an exception for logging and reporting.

    Args:
        error: The exception to parse

    Returns:
        Dictionary with error details
    """
    error_details = {
        "error_type": error.__class__.__name__,
        "error_message": str(error),
    }

    # Add exception attributes that aren't private
    for attr in dir(error):
        if not attr.startswith('_') and not callable(getattr(error, attr)):
            try:
                value = getattr(error, attr)
                # Only include simple types that can be JSON serialized
                if isinstance(value, (str, int, float, bool, list, dict)) and attr not in error_details:
                    error_details[attr] = value
            except Exception:
                pass

    return error_details


def sanitize_error_message(message: str) -> str:
    """
    Sanitize error messages to prevent information leakage.

    Removes potentially sensitive information from error messages
    before returning them to clients.

    Args:
        message: Original error message

    Returns:
        Sanitized error message
    """
    # List of patterns to sanitize
    patterns = [
        # SQL query fragments
        (r"SELECT\s+.*\s+FROM\s+\w+", "SQL query"),
        (r"INSERT\s+INTO\s+\w+", "SQL insert"),
        (r"UPDATE\s+\w+\s+SET", "SQL update"),
        # File paths
        (r"/[/\w\.-]+\.py", "internal file"),
        # Stack traces
        (r"File\s+\".*\"", "file reference"),
        # Connection strings
        (r"mysql://[^@]+@", "database connection"),
        (r"postgresql://[^@]+@", "database connection"),
        # IP addresses
        (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address")
    ]

    # Don't sanitize for DEBUG mode
    if current_app.debug:
        return message

    sanitized = message
    for pattern, replacement in patterns:
        import re
        sanitized = re.sub(pattern, replacement, sanitized)

    # If significant sanitization occurred or message is very long, use generic message
    if sanitized != message or len(message) > 200:
        if "database" in message.lower() or "sql" in message.lower():
            return "A database error occurred"
        return "An internal server error occurred"

    return sanitized


# Export common HTTP status codes for convenience
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_ERROR = 500
HTTP_SERVICE_UNAVAILABLE = 503

# Export these symbols for use in other modules
__all__ = [
    # Error classes
    'AdminError',
    'AdminValidationError',
    'AdminResourceNotFoundError',
    'AdminPermissionError',
    'AdminAuthenticationError',
    'AdminIntegrityError',
    'AdminConfigurationError',
    'AdminRateLimitError',
    'AdminServiceUnavailableError',
    'AdminMFARequiredError',
    'AdminApprovalRequiredError',

    # Functions
    'handle_admin_error',
    'format_error_response',
    'register_error_handlers',
    'parse_error_details',
    'sanitize_error_message',

    # HTTP status codes
    'HTTP_OK',
    'HTTP_CREATED',
    'HTTP_NO_CONTENT',
    'HTTP_BAD_REQUEST',
    'HTTP_UNAUTHORIZED',
    'HTTP_FORBIDDEN',
    'HTTP_NOT_FOUND',
    'HTTP_CONFLICT',
    'HTTP_UNPROCESSABLE_ENTITY',
    'HTTP_TOO_MANY_REQUESTS',
    'HTTP_INTERNAL_ERROR',
    'HTTP_SERVICE_UNAVAILABLE'
]
