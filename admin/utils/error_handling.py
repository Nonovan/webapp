"""
Centralized Error Handling Utilities for Administrative Tools.

This module provides standardized error classes and handling functions
for use across administrative CLI tools and scripts. It ensures consistent
logging, reporting, and exit codes for administrative errors.
"""

import logging
import sys
import traceback
from typing import Optional, Dict, Any, Tuple, List, Union, Callable
from datetime import timezone

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

# --- Standard Exit Codes (Consistent with admin CLI tools) ---
EXIT_SUCCESS = 0
EXIT_ERROR = 1  # General/unexpected error
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3  # e.g., File not found, User not found
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_CONFIGURATION_ERROR = 6
EXIT_OPERATION_CANCELLED = 7

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


# --- Error Handling Functions ---

def handle_admin_error(
    error: Exception,
    context: Optional[str] = None,
    log_audit: bool = True,
    exit_on_error: bool = True
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

    Returns:
        A tuple containing the formatted error message and the exit code.
    """
    if isinstance(error, AdminError):
        error_message = error.message
        exit_code = error.exit_code
        details = error.details
        log_level = logging.WARNING if exit_code in [EXIT_VALIDATION_ERROR, EXIT_OPERATION_CANCELLED] else logging.ERROR
    else:
        # Handle unexpected errors
        error_message = f"An unexpected error occurred: {str(error)}"
        exit_code = EXIT_ERROR
        details = {"exception_type": error.__class__.__name__}
        log_level = logging.CRITICAL  # Use critical for unexpected errors

    full_context = f"Context: {context} | Error: {error_message}" if context else f"Error: {error_message}"

    # Log the error using standard logger
    if log_level >= logging.ERROR:
        # Include exception info for more severe errors
        logger.log(log_level, full_context, exc_info=(exit_code == EXIT_ERROR))
    else:
        logger.log(log_level, full_context)

    # Log admin action failure if requested and applicable
    if log_audit and exit_code != EXIT_OPERATION_CANCELLED:
        try:
            action_context = context or "admin_operation"
            # Sanitize action name for audit log
            action_name = action_context.lower().replace(" ", "_").replace(":", "_")
            log_admin_action(
                action=f"error.{action_name}",
                status="failure",
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

    # Print to stderr for CLI tools
    print(user_message, file=sys.stderr)

    if exit_on_error:
        sys.exit(exit_code)

    return user_message, exit_code


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
        except Exception as e:
            # Don't wrap AdminError exceptions
            if isinstance(e, AdminError):
                raise
            # Let other exceptions pass through to be handled by the caller
            raise
    return wrapper
