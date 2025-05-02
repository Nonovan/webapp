"""
Administrative Utilities Package

This package contains utility modules that provide common functionality for the
administrative tools in the Cloud Infrastructure Platform. These utilities ensure
consistent behavior, proper security controls, and platform standards across all
administrative components.

Key functionality includes:
- Authentication and authorization for administrative operations
- Audit logging of administrative actions
- Configuration validation with schema support
- Secure credential handling
- Standardized error handling
- Performance metrics collection
- Password generation and validation

The utilities are designed to be imported and used by CLI tools, scripts,
and other administrative components of the platform.
"""

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable, Tuple

# Setup package logging
logger = logging.getLogger(__name__)

# Version information
__version__ = '0.1.1'
__author__ = 'Cloud Infrastructure Platform Team'
__email__ = 'platform-team@example.com'

# Initialize availability flags
ADMIN_AUTH_AVAILABLE = False
AUDIT_UTILS_AVAILABLE = False
CONFIG_VALIDATION_AVAILABLE = False
ERROR_HANDLING_AVAILABLE = False
ENCRYPTION_UTILS_AVAILABLE = False
METRICS_UTILS_AVAILABLE = False
SECURE_CREDENTIALS_AVAILABLE = False
PASSWORD_UTILS_AVAILABLE = False

# Try importing admin_auth utilities
try:
    from .admin_auth import (
        authenticate_admin,
        check_permission,
        require_permission,
        require_mfa,
        get_admin_session,
        verify_mfa_token,
        AdminAuthenticationError,
        AdminPermissionError
    )
    ADMIN_AUTH_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin auth utilities not available: {e}")

# Try importing audit utilities
try:
    from .audit_utils import (
        log_admin_action,
        get_admin_audit_logs,
        export_admin_audit_logs,
        detect_admin_anomalies,
        verify_audit_log_integrity,
        SEVERITY_INFO,
        SEVERITY_WARNING,
        SEVERITY_ERROR,
        SEVERITY_CRITICAL,
        STATUS_SUCCESS,
        STATUS_FAILURE,
        ADMIN_ACTION_CATEGORY,
        ADMIN_EVENT_PREFIX
    )
    AUDIT_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin audit utilities not available: {e}")

# Try importing config validation utilities
try:
    from .config_validation import (
        validate_config,
        load_schema,
        ValidationResult,
        ValidationError
    )
    CONFIG_VALIDATION_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Config validation utilities not available: {e}")

# Try importing error handling utilities
try:
    from .error_handling import (
        handle_admin_error,
        handle_common_exceptions,
        AdminError,
        AdminConfigurationError,
        AdminResourceNotFoundError,
        AdminValidationError
    )
    ERROR_HANDLING_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Error handling utilities not available: {e}")

# Try importing encryption utilities
try:
    from .encryption_utils import (
        encrypt_data,
        decrypt_data,
        generate_key,
        secure_hash,
        compare_hashes,
        secure_random_string
    )
    ENCRYPTION_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Encryption utilities not available: {e}")

# Try importing metrics utilities
try:
    from .metrics_utils import (
        track_operation,
        record_metric,
        get_metrics,
        export_metrics
    )
    METRICS_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Metrics utilities not available: {e}")

# Try importing secure credential utilities
try:
    from .secure_credentials import (
        get_credential,
        store_credential,
        delete_credential,
        secure_credential,
        rotate_credential
    )
    SECURE_CREDENTIALS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Secure credential utilities not available: {e}")

# Try importing password utilities
try:
    from .password_utils import (
        generate_password,
        validate_password_strength,
        check_password_history,
        PASSWORD_MIN_LENGTH
    )
    PASSWORD_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Password utilities not available: {e}")

def get_available_utilities() -> Dict[str, bool]:
    """
    Returns a dictionary of available utility modules in this package.

    Returns:
        Dict[str, bool]: Dictionary with utility names and availability flags
    """
    return {
        "admin_auth": ADMIN_AUTH_AVAILABLE,
        "audit_utils": AUDIT_UTILS_AVAILABLE,
        "config_validation": CONFIG_VALIDATION_AVAILABLE,
        "error_handling": ERROR_HANDLING_AVAILABLE,
        "encryption_utils": ENCRYPTION_UTILS_AVAILABLE,
        "metrics_utils": METRICS_UTILS_AVAILABLE,
        "secure_credentials": SECURE_CREDENTIALS_AVAILABLE,
        "password_utils": PASSWORD_UTILS_AVAILABLE
    }

# Define public exports - only include symbols from available modules
__all__ = [
    # Package info
    "__version__",
    "__author__",
    "__email__",

    # Package utilities
    "get_available_utilities"
]

# Conditionally add exports based on available modules
if ADMIN_AUTH_AVAILABLE:
    __all__.extend([
        "authenticate_admin",
        "check_permission",
        "require_permission",
        "require_mfa",
        "get_admin_session",
        "verify_mfa_token",
        "AdminAuthenticationError",
        "AdminPermissionError"
    ])

if AUDIT_UTILS_AVAILABLE:
    __all__.extend([
        "log_admin_action",
        "get_admin_audit_logs",
        "export_admin_audit_logs",
        "detect_admin_anomalies",
        "verify_audit_log_integrity",
        "SEVERITY_INFO",
        "SEVERITY_WARNING",
        "SEVERITY_ERROR",
        "SEVERITY_CRITICAL",
        "STATUS_SUCCESS",
        "STATUS_FAILURE",
        "ADMIN_ACTION_CATEGORY",
        "ADMIN_EVENT_PREFIX"
    ])

if CONFIG_VALIDATION_AVAILABLE:
    __all__.extend([
        "validate_config",
        "load_schema",
        "ValidationResult",
        "ValidationError"
    ])

if ERROR_HANDLING_AVAILABLE:
    __all__.extend([
        "handle_admin_error",
        "handle_common_exceptions",
        "AdminError",
        "AdminConfigurationError",
        "AdminResourceNotFoundError",
        "AdminValidationError"
    ])

if ENCRYPTION_UTILS_AVAILABLE:
    __all__.extend([
        "encrypt_data",
        "decrypt_data",
        "generate_key",
        "secure_hash",
        "compare_hashes",
        "secure_random_string"
    ])

if METRICS_UTILS_AVAILABLE:
    __all__.extend([
        "track_operation",
        "record_metric",
        "get_metrics",
        "export_metrics"
    ])

if SECURE_CREDENTIALS_AVAILABLE:
    __all__.extend([
        "get_credential",
        "store_credential",
        "delete_credential",
        "secure_credential",
        "rotate_credential"
    ])

if PASSWORD_UTILS_AVAILABLE:
    __all__.extend([
        "generate_password",
        "validate_password_strength",
        "check_password_history",
        "PASSWORD_MIN_LENGTH"
    ])

# Log initialization status
logger.debug(f"Admin utils package initialized with: {', '.join([k for k, v in get_available_utilities().items() if v])}")
