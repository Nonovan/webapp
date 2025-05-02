"""
Centralized Error Handling Utilities for Administrative Tools.

This module provides standardized error classes and handling functions
for use across administrative CLI tools and scripts. It ensures consistent
logging, reporting, and exit codes for administrative errors.
"""

import logging
import sys
import traceback
import time
import random
from typing import Optional, Dict, Any, Tuple, List, Union, Callable, Type, TypeVar
from datetime import timezone, datetime
from functools import wraps

# Attempt to import admin-specific logging and core logging
try:
    from core.loggings import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback basic logger if core logging is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core logging module not found, using basic logging.")

try:
    # Import admin audit logging if available
    from admin.utils.audit_utils import log_admin_action
except ImportError:
    logger.warning("Admin audit logging utility not found. Audit logs for errors will be skipped.")
    # Define a dummy function if audit logging is unavailable
    def log_admin_action(*args, **kwargs) -> None:
        pass

# Type variable for decorator return type preservation
F = TypeVar('F', bound=Callable[..., Any])

# --- Standard Exit Codes (Consistent with admin CLI tools) ---
EXIT_SUCCESS = 0
EXIT_ERROR = 1  # General/unexpected error
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3  # e.g., File not found, User not found
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_CONFIGURATION_ERROR = 6
EXIT_OPERATION_CANCELLED = 7
EXIT_CONNECTIVITY_ERROR = 8  # Network/connectivity issues
EXIT_TIMEOUT_ERROR = 9       # Operation timed out
EXIT_EXTERNAL_SERVICE_ERROR = 10  # Error in external service

# --- Error Severity Levels ---
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

# --- Custom Admin Exception Classes ---

class AdminError(Exception):
    """Base class for all administrative tool errors."""
    def __init__(self, message: str, exit_code: int = EXIT_ERROR, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.details = details or {}

    def __str__(self) -> str:
        return self.message

class AdminAuthenticationError(AdminError):
    """Raised for authentication failures."""
    def __init__(self, message: str = "Authentication failed.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, EXIT_AUTHENTICATION_ERROR, details)

class AdminPermissionError(AdminError):
    """Raised for authorization failures."""
    def __init__(self, message: str = "Permission denied.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, EXIT_PERMISSION_ERROR, details)

class AdminValidationError(AdminError):
    """Raised for input validation errors."""
    def __init__(self, message: str = "Invalid input provided.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, EXIT_VALIDATION_ERROR, details)

class AdminResourceNotFoundError(AdminError):
    """Raised when a required resource (file, user, etc.) is not found."""
    def __init__(self, resource_type: str = "Resource", identifier: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"{resource_type} not found"
        if identifier:
            message += f": {identifier}"
        super().__init__(message, EXIT_RESOURCE_ERROR, details)

class AdminConfigurationError(AdminError):
    """Raised for configuration-related errors."""
    def __init__(self, message: str = "Configuration error.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, EXIT_CONFIGURATION_ERROR, details)

class AdminOperationCancelledError(AdminError):
    """Raised when an operation is cancelled by the user."""
    def __init__(self, message: str = "Operation cancelled by user.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, EXIT_OPERATION_CANCELLED, details)

class AdminConnectivityError(AdminError):
    """Raised for network or connectivity issues."""
    def __init__(
        self, message: str = "Network or connectivity error.",
        service: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        if service:
            message = f"Connection error to {service}: {message}"
        enhanced_details = {"service": service} if service else {}
        if details:
            enhanced_details.update(details)
        super().__init__(message, EXIT_CONNECTIVITY_ERROR, enhanced_details)

class AdminTimeoutError(AdminError):
    """Raised when an operation times out."""
    def __init__(
        self, message: str = "Operation timed out.",
        operation: Optional[str] = None,
        timeout: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        enhanced_message = message
        if operation:
            enhanced_message = f"{operation} {enhanced_message}"
        enhanced_details = {}
        if timeout is not None:
            enhanced_details["timeout"] = timeout
        if details:
            enhanced_details.update(details)
        super().__init__(enhanced_message, EXIT_TIMEOUT_ERROR, enhanced_details)

class AdminExternalServiceError(AdminError):
    """Raised when an external service returns an error."""
    def __init__(
        self, message: str = "External service error.",
        service: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        enhanced_message = message
        if service:
            enhanced_message = f"{service} service error: {message}"
        enhanced_details = {}
        if status_code is not None:
            enhanced_details["status_code"] = status_code
        if details:
            enhanced_details.update(details)
        super().__init__(enhanced_message, EXIT_EXTERNAL_SERVICE_ERROR, enhanced_details)


# --- Error Handling Functions ---

def handle_admin_error(
    error: Exception,
    context: Optional[str] = None,
    log_audit: bool = True,
    exit_on_error: bool = True,
    collect_diagnostics: bool = False
) -> Tuple[str, int]:
    """
    Handles exceptions caught in administrative tools.

    Logs the error, optionally logs an admin audit event, prints a
    user-friendly message, and optionally exits with an appropriate code.

    Args:
        error: The exception object caught.
        context: Optional string describing the context where the error occurred.
        log_audit: Whether to log this error as a failed admin action.
        exit_on_error: Whether to exit the script after handling the error.
        collect_diagnostics: Whether to collect additional system diagnostics.

    Returns:
        A tuple containing the formatted error message and the exit code.
    """
    if isinstance(error, AdminError):
        error_message = error.message
        exit_code = error.exit_code
        details = error.details

        # Determine log level based on error type
        if exit_code in [EXIT_VALIDATION_ERROR, EXIT_OPERATION_CANCELLED]:
            log_level = logging.WARNING
        elif exit_code in [EXIT_CONNECTIVITY_ERROR, EXIT_TIMEOUT_ERROR]:
            log_level = logging.ERROR
        elif exit_code == EXIT_EXTERNAL_SERVICE_ERROR:
            log_level = logging.ERROR
        else:
            log_level = logging.ERROR
    else:
        # Handle unexpected errors
        error_message = f"An unexpected error occurred: {str(error)}"
        exit_code = EXIT_ERROR
        details = {"exception_type": error.__class__.__name__}
        log_level = logging.CRITICAL  # Use critical for unexpected errors

    full_context = f"Context: {context} | Error: {error_message}" if context else f"Error: {error_message}"

    # Add diagnostics if requested
    if collect_diagnostics and (exit_code in [EXIT_ERROR, EXIT_CONNECTIVITY_ERROR, EXIT_TIMEOUT_ERROR, EXIT_EXTERNAL_SERVICE_ERROR]):
        diagnostic_info = _collect_error_diagnostics(error)
        if details is None:
            details = {}
        details["diagnostics"] = diagnostic_info

    # Log the error using standard logger
    if log_level >= logging.ERROR:
        # Include exception info for more severe errors
        logger.log(log_level, full_context, exc_info=(exit_code == EXIT_ERROR))
    else:
        logger.log(log_level, full_context)

    # Determine error severity for audit logs
    severity = _map_exit_code_to_severity(exit_code)

    # Log admin action failure if requested and applicable
    if log_audit and exit_code != EXIT_OPERATION_CANCELLED:
        try:
            action_context = context or "admin_operation"
            # Sanitize action name for audit log
            action_name = action_context.lower().replace(" ", "_").replace(":", "_")
            log_admin_action(
                action=f"error.{action_name}",
                status="failure",
                severity=severity,
                details={
                    "error_message": str(error),
                    "error_type": error.__class__.__name__,
                    "exit_code": exit_code,
                    **(details or {})
                }
            )
        except Exception as audit_log_error:
            logger.error(f"Failed to log admin audit event for error: {audit_log_error}")

    # Prepare user-facing message
    user_message = f"Error: {error_message}"
    if exit_code == EXIT_ERROR:  # Add more info for unexpected errors
        user_message += " Please check logs for details."
    elif exit_code == EXIT_CONNECTIVITY_ERROR:
        user_message += " Please check your network connectivity and try again."

    # Print to stderr for CLI tools
    print(user_message, file=sys.stderr)

    if exit_on_error:
        sys.exit(exit_code)

    return user_message, exit_code


def _map_exit_code_to_severity(exit_code: int) -> str:
    """
    Maps exit codes to severity levels for audit logging.

    Args:
        exit_code: The exit code to map

    Returns:
        Severity level string
    """
    severity_map = {
        EXIT_ERROR: SEVERITY_ERROR,
        EXIT_PERMISSION_ERROR: SEVERITY_WARNING,
        EXIT_RESOURCE_ERROR: SEVERITY_WARNING,
        EXIT_VALIDATION_ERROR: SEVERITY_INFO,
        EXIT_AUTHENTICATION_ERROR: SEVERITY_WARNING,
        EXIT_CONFIGURATION_ERROR: SEVERITY_ERROR,
        EXIT_OPERATION_CANCELLED: SEVERITY_INFO,
        EXIT_CONNECTIVITY_ERROR: SEVERITY_WARNING,
        EXIT_TIMEOUT_ERROR: SEVERITY_WARNING,
        EXIT_EXTERNAL_SERVICE_ERROR: SEVERITY_WARNING
    }
    return severity_map.get(exit_code, SEVERITY_ERROR)


def _collect_error_diagnostics(error: Exception) -> Dict[str, Any]:
    """
    Collects system and environment diagnostics to help with troubleshooting.

    Args:
        error: The exception that occurred

    Returns:
        Dictionary with diagnostic information
    """
    diagnostics = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_info": {
            "platform": sys.platform,
            "python_version": sys.version,
            "pid": os.getpid() if "os" in sys.modules else "unknown"
        }
    }

    # Add error attributes if present
    error_attrs = {}
    for attr in dir(error):
        if not attr.startswith("_") and attr not in ["args", "with_traceback"]:
            try:
                value = getattr(error, attr)
                if not callable(value):
                    error_attrs[attr] = str(value)
            except Exception:
                pass

    if error_attrs:
        diagnostics["error_attributes"] = error_attrs

    # Try to add network info for connectivity errors
    if isinstance(error, AdminConnectivityError) or "ConnectionError" in error.__class__.__name__:
        try:
            import socket
            diagnostics["network_info"] = {
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn()
            }

            # Try to get public IP (without making external requests)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))  # Connect to a public DNS
                diagnostics["network_info"]["local_ip"] = s.getsockname()[0]
                s.close()
            except Exception:
                pass

        except ImportError:
            pass

    return diagnostics


def format_error_for_output(
    error: Exception,
    output_format: str = "text",
    include_traceback: bool = False
) -> str:
    """
    Formats an error for different output formats.

    Args:
        error: The exception object to format.
        output_format: The desired output format ('text', 'json', 'csv', 'table').
        include_traceback: Whether to include the exception traceback.

    Returns:
        Formatted error message in the requested format.
    """
    import json
    import csv
    import io
    from datetime import datetime

    error_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": error.__class__.__name__,
        "message": str(error),
    }

    # Add exit code and details for admin errors
    if isinstance(error, AdminError):
        error_data["exit_code"] = error.exit_code
        error_data["details"] = error.details

    # Add traceback if requested
    if include_traceback:
        tb_lines = traceback.format_exception(type(error), error, error.__traceback__)
        error_data["traceback"] = "".join(tb_lines)

    # Format based on requested output
    if output_format == "json":
        return json.dumps(error_data, indent=2)

    elif output_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        # Write header row
        writer.writerow(error_data.keys())
        # Write data row, handling nested dictionaries by converting them to strings
        row = []
        for val in error_data.values():
            if isinstance(val, dict):
                row.append(json.dumps(val))
            else:
                row.append(val)
        writer.writerow(row)
        return output.getvalue()

    elif output_format == "table":
        result = "\n" + "=" * 50 + "\n"
        result += f"ERROR DETAILS\n"
        result += "=" * 50 + "\n"
        for key, value in error_data.items():
            if key == "traceback":
                result += f"\n{key}:\n{value}"
            elif isinstance(value, dict):
                result += f"{key}:\n"
                for k, v in value.items():
                    result += f"  {k}: {v}\n"
            else:
                result += f"{key}: {value}\n"
        return result

    # Default to text format
    else:
        if include_traceback and "traceback" in error_data:
            return f"Error: {error_data['message']} ({error_data['error_type']})\n\nTraceback:\n{error_data['traceback']}"
        return f"Error: {error_data['message']} ({error_data['error_type']})"


def validate_and_sanitize_input(
    input_data: Dict[str, Any],
    required_fields: List[str] = None,
    field_validators: Dict[str, Callable[[Any], Union[bool, str]]] = None
) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Validates and sanitizes input data against requirements.

    Args:
        input_data: Dictionary containing input data.
        required_fields: List of field names that must be present and non-empty.
        field_validators: Dictionary mapping field names to validator functions.

    Returns:
        Tuple of (is_valid, errors_by_field) where errors_by_field is a dictionary
        of field names to lists of error messages.
    """
    is_valid = True
    errors: Dict[str, List[str]] = {}

    # Check for required fields
    if required_fields:
        for field in required_fields:
            if field not in input_data or input_data[field] is None or input_data[field] == "":
                is_valid = False
                errors[field] = errors.get(field, []) + [f"Field '{field}' is required"]

    # Apply field-specific validators
    if field_validators:
        for field, validator in field_validators.items():
            if field in input_data and input_data[field] is not None:
                try:
                    result = validator(input_data[field])
                    if result is not True:  # Validator returned an error message
                        is_valid = False
                        errors[field] = errors.get(field, []) + [
                            result if isinstance(result, str) else f"Validation failed for field '{field}'"
                        ]
                except Exception as e:
                    is_valid = False
                    errors[field] = errors.get(field, []) + [f"Validation error: {str(e)}"]

    return is_valid, errors


def handle_common_exceptions(func):
    """
    Decorator to handle common exceptions in administrative functions.

    Wraps a function with standardized error handling for various
    common exceptions, translating them to appropriate admin errors.

    Example:
        @handle_common_exceptions
        def update_config(config_path, values):
            # This function can now raise FileNotFoundError and it will
            # be translated to AdminResourceNotFoundError automatically
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FileNotFoundError as e:
            resource_path = str(e).replace("[Errno 2] No such file or directory: ", "")
            raise AdminResourceNotFoundError("File", resource_path)
        except PermissionError as e:
            raise AdminPermissionError(f"Permission denied: {e}")
        except (KeyError, IndexError) as e:
            raise AdminResourceNotFoundError("Resource", str(e))
        except ValueError as e:
            raise AdminValidationError(str(e))
        except (ImportError, ModuleNotFoundError) as e:
            raise AdminConfigurationError(f"Missing dependency: {e}")
        except NotImplementedError as e:
            raise AdminConfigurationError(f"Feature not implemented: {e}")
        except ConnectionError as e:
            raise AdminConnectivityError(str(e))
        except TimeoutError as e:
            raise AdminTimeoutError(str(e))
        except Exception as e:
            # Don't wrap AdminError exceptions
            if isinstance(e, AdminError):
                raise
            # Let other exceptions pass through to be handled by the caller
            raise
    return wrapper


class ExponentialBackoff:
    """
    Implements exponential backoff for retries with jitter.

    Attributes:
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        max_retries: Maximum number of retries
        backoff_factor: Multiplier for each retry
        jitter: Whether to add random jitter
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """
        Calculate the delay for a specific retry attempt.

        Args:
            attempt: The current attempt number (0-based)

        Returns:
            Delay time in seconds
        """
        if attempt <= 0:
            return 0

        # Calculate exponential delay
        delay = min(self.max_delay, self.base_delay * (self.backoff_factor ** (attempt - 1)))

        # Add jitter if enabled (up to 25% of the delay)
        if self.jitter:
            jitter_amount = delay * 0.25
            delay = delay - jitter_amount + (random.random() * jitter_amount * 2)

        return delay


def retry_operation(
    max_attempts: int = 3,
    retry_exceptions: Tuple[Type[Exception], ...] = (
        ConnectionError,
        TimeoutError
    ),
    exclude_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    on_retry_callback: Optional[Callable[[Exception, int, float], None]] = None
) -> Callable[[F], F]:
    """
    Decorator for retrying functions with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        retry_exceptions: Tuple of exception types to retry on
        exclude_exceptions: Tuple of exception types to exclude from retries
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        backoff_factor: Multiplier for the delay after each retry
        jitter: Whether to add random jitter to the delay
        on_retry_callback: Optional function to call before each retry

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            backoff = ExponentialBackoff(
                base_delay=base_delay,
                max_delay=max_delay,
                max_retries=max_attempts-1,
                backoff_factor=backoff_factor,
                jitter=jitter
            )

            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Don't retry if the exception should be excluded
                    if exclude_exceptions and isinstance(e, exclude_exceptions):
                        raise

                    # Only retry for specified exceptions
                    if not isinstance(e, retry_exceptions):
                        raise

                    last_exception = e

                    # Break if this was the last attempt
                    if attempt >= max_attempts - 1:
                        break

                    # Calculate delay for this attempt
                    delay = backoff.get_delay(attempt + 1)

                    # Call retry callback if provided
                    if on_retry_callback:
                        try:
                            on_retry_callback(e, attempt + 1, delay)
                        except Exception as callback_error:
                            logger.warning(f"Error in retry callback: {callback_error}")

                    # Log the retry
                    logger.warning(
                        f"Retry {attempt+1}/{max_attempts} after error: {e}. "
                        f"Retrying in {delay:.2f} seconds."
                    )

                    # Wait before the next attempt
                    time.sleep(delay)

            # If we get here, we've exhausted our retries
            if isinstance(last_exception, ConnectionError):
                raise AdminConnectivityError(str(last_exception), details={
                    "attempts": max_attempts,
                    "original_error": str(last_exception)
                })
            elif isinstance(last_exception, TimeoutError):
                raise AdminTimeoutError(str(last_exception), details={
                    "attempts": max_attempts,
                    "original_error": str(last_exception)
                })
            else:
                # Re-raise the last exception
                if last_exception is not None:
                    raise last_exception
                else:
                    raise RuntimeError("Retry operation failed without capturing an exception.")

        return wrapper
    return decorator


def with_error_boundary(
    boundary_name: str = "operation",
    reraise: bool = True,
    log_level: str = SEVERITY_ERROR,
    error_mapper: Optional[Dict[Type[Exception], Type[AdminError]]] = None
) -> Callable[[F], F]:
    """
    Creates a boundary around operations for consolidated error handling.

    Useful for grouping related operations and providing consistent
    error handling patterns across multiple functions.

    Args:
        boundary_name: Name of the boundary for logging and context
        reraise: Whether to re-raise caught exceptions
        log_level: Severity level for logging errors
        error_mapper: Dictionary mapping exception types to admin error types

    Returns:
        Decorated function with error boundary
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.debug(f"Entering error boundary: {boundary_name}")

            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Handle the exception
                logger_method = getattr(logger, log_level.lower(), logger.error)
                logger_method(f"Error in {boundary_name}: {str(e)}", exc_info=True)

                # Transform the error if a mapper is provided
                if error_mapper and isinstance(e, tuple(error_mapper.keys())):
                    error_class = error_mapper[type(e)]
                    transformed_error = error_class(str(e))

                    # Add original exception as cause
                    transformed_error.__cause__ = e

                    # Re-raise transformed error if requested
                    if reraise:
                        raise transformed_error

                    return None

                # Re-raise original exception if requested
                if reraise:
                    raise

                return None
            finally:
                logger.debug(f"Exiting error boundary: {boundary_name}")

        return wrapper
    return decorator


def categorize_error(error: Exception) -> Dict[str, Any]:
    """
    Categorizes an error for consistent reporting and handling.

    Analyzes the error type and content to determine its category,
    severity, and relevant attributes for structured logging and
    error handling.

    Args:
        error: The exception to categorize

    Returns:
        Dictionary with error category information
    """
    result = {
        "type": error.__class__.__name__,
        "message": str(error),
        "category": "unknown",
        "severity": SEVERITY_ERROR
    }

    # Categorize by error type
    if isinstance(error, AdminError):
        result["category"] = "admin"
        result["exit_code"] = error.exit_code
        result["details"] = error.details
        result["severity"] = _map_exit_code_to_severity(error.exit_code)
    elif isinstance(error, (PermissionError, OSError)) or "Permission" in error.__class__.__name__:
        result["category"] = "permission"
        result["severity"] = SEVERITY_WARNING
    elif isinstance(error, FileNotFoundError) or "NotFound" in error.__class__.__name__:
        result["category"] = "not_found"
        result["severity"] = SEVERITY_WARNING
    elif isinstance(error, (ValueError, TypeError, KeyError)) or "Value" in error.__class__.__name__:
        result["category"] = "validation"
        result["severity"] = SEVERITY_WARNING
    elif isinstance(error, (ConnectionError, TimeoutError)) or any(net_err in error.__class__.__name__
                                                                for net_err in ["Connection", "Timeout", "Socket"]):
        result["category"] = "connectivity"
        result["severity"] = SEVERITY_ERROR
    elif "Configuration" in error.__class__.__name__:
        result["category"] = "configuration"
        result["severity"] = SEVERITY_ERROR

    # Extract additional attributes
    try:
        # Include HTTP status code if available
        if hasattr(error, "status_code"):
            result["status_code"] = error.status_code
        elif hasattr(error, "code"):
            result["status_code"] = error.code

        # Include response data if available
        if hasattr(error, "response"):
            try:
                result["response"] = error.response
            except:
                pass

    except Exception:
        pass

    return result

# Standard import for better IDE support and proper module exports
import os
import json
