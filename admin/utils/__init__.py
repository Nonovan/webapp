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
- File integrity baseline management

The utilities are designed to be imported and used by CLI tools, scripts,
and other administrative components of the platform.
"""

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable, Tuple
import sys

# Setup package logging
logger = logging.getLogger(__name__)

# Version information
__version__ = '0.1.1'
__author__ = 'Cloud Infrastructure Platform Team'
__email__ = 'platform-team@example.com'

# Constants availability flags
ADMIN_CONSTANTS_AVAILABLE = False
AUDIT_CONSTANTS_AVAILABLE = False

# Utility modules availability flags
ADMIN_AUTH_AVAILABLE = False
AUDIT_UTILS_AVAILABLE = False
CONFIG_VALIDATION_AVAILABLE = False
ERROR_HANDLING_AVAILABLE = False
ENCRYPTION_UTILS_AVAILABLE = False
METRICS_UTILS_AVAILABLE = False
SECURE_CREDENTIALS_AVAILABLE = False
PASSWORD_UTILS_AVAILABLE = False
FILE_INTEGRITY_AVAILABLE = False
SECURITY_UTILS_AVAILABLE = False

# Try importing admin constants
try:
    from .admin_constants import (
        # Exit codes
        EXIT_SUCCESS,
        EXIT_ERROR,
        EXIT_PERMISSION_ERROR,
        EXIT_RESOURCE_ERROR,
        EXIT_VALIDATION_ERROR,
        EXIT_AUTHENTICATION_ERROR,
        EXIT_CONFIGURATION_ERROR,
        EXIT_OPERATION_CANCELLED,
        EXIT_CONNECTIVITY_ERROR,
        EXIT_TIMEOUT_ERROR,
        EXIT_EXTERNAL_SERVICE_ERROR,

        # Standard timeouts
        DEFAULT_OPERATION_TIMEOUT,
        DEFAULT_NETWORK_TIMEOUT,
        DEFAULT_API_REQUEST_TIMEOUT,
        DEFAULT_DATABASE_OPERATION_TIMEOUT,
        DEFAULT_LOCK_TIMEOUT,
        DEFAULT_SESSION_TIMEOUT,

        # Resource limits
        DEFAULT_API_RATE_LIMIT,
        DEFAULT_BATCH_SIZE,
        DEFAULT_MAX_RETRIES,
        DEFAULT_RETRY_DELAY,
        DEFAULT_MAX_RESULTS,

        # Security settings
        DEFAULT_PASSWORD_MIN_LENGTH,
        DEFAULT_MFA_TIMEOUT,
        DEFAULT_TOKEN_EXPIRY,
        DEFAULT_EMERGENCY_ACCESS_DURATION
    )
    ADMIN_CONSTANTS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin constants not available: {e}")

# Try importing audit constants
try:
    from .audit_constants import (
        # Audit categories
        ADMIN_ACTION_CATEGORY,
        ADMIN_EVENT_PREFIX,

        # Severity levels
        SEVERITY_INFO,
        SEVERITY_WARNING,
        SEVERITY_ERROR,
        SEVERITY_CRITICAL,

        # Action statuses
        STATUS_SUCCESS,
        STATUS_FAILURE,
        STATUS_ATTEMPTED,
        STATUS_CANCELLED,

        # Action types
        ACTION_USER_CREATE,
        ACTION_USER_UPDATE,
        ACTION_USER_DELETE,
        ACTION_ROLE_ASSIGN,
        ACTION_ROLE_REVOKE,
        ACTION_PERMISSION_GRANT,
        ACTION_PERMISSION_REVOKE,
        ACTION_CONFIG_CHANGE,
        ACTION_SYSTEM_CHANGE,
        ACTION_SECURITY_CHANGE,
        ACTION_EMERGENCY_ACCESS,
        ACTION_EMERGENCY_DEACTIVATE,
        ACTION_DATA_EXPORT,
        ACTION_AUDIT_ACCESS,
        ACTION_API_KEY_CREATE,
        ACTION_API_KEY_REVOKE
    )
    AUDIT_CONSTANTS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Audit constants not available: {e}")

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
        verify_audit_log_integrity
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
        AdminValidationError,
        AdminPermissionError,
        AdminConnectivityError,
        AdminTimeoutError
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

# Try importing security utilities
try:
    from .security_utils import (
        generate_api_token,
        compute_hash
    )
    SECURITY_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Security utilities not available: {e}")

# Try importing file integrity utilities - first check for local implementation
try:
    from .file_integrity import (
        update_file_integrity_baseline,
        verify_file_integrity,
        calculate_file_hash,
        get_baseline_status,
        validate_baseline_update,
        check_critical_file_integrity,
        create_file_hash_baseline,
        detect_file_changes,
        verify_file_signature,
        get_last_integrity_status,
        log_file_integrity_event,
        initialize_file_monitoring
    )
    FILE_INTEGRITY_AVAILABLE = True
except ImportError as e:
    # If local implementation not available, try to import from core
    try:
        from core.security.cs_file_integrity import (
            update_file_integrity_baseline,
            check_critical_file_integrity,
            detect_file_changes,
            verify_file_signature,
            calculate_file_hash,
            create_file_hash_baseline,
            get_last_integrity_status,
            log_file_integrity_event
        )

        # Define aliases for consistent API if names differ
        validate_baseline_update = getattr(
            sys.modules.get('core.security.cs_file_integrity'),
            'verify_baseline_update',
            None
        )
        verify_file_integrity = getattr(
            sys.modules.get('core.security.cs_file_integrity'),
            'verify_file_integrity',
            None
        )
        get_baseline_status = getattr(
            sys.modules.get('core.security.cs_file_integrity'),
            'get_baseline_status',
            None
        )
        initialize_file_monitoring = getattr(
            sys.modules.get('core.security.cs_file_integrity'),
            'initialize_file_monitoring',
            None
        )

        FILE_INTEGRITY_AVAILABLE = True
        logger.debug("Using core security file integrity implementation")
    except ImportError:
        # As a last resort, check if the forensics utilities have this functionality
        try:
            from admin.security.forensics.utils import update_file_integrity_baseline
            from admin.security.forensics.utils.crypto import (
                calculate_file_hash,
                verify_file_hash as verify_file_integrity
            )
            FILE_INTEGRITY_AVAILABLE = True
            logger.debug("Using forensics utilities for file integrity functions")
        except ImportError:
            logger.debug("File integrity utilities not available from any source")

def get_available_utilities() -> Dict[str, bool]:
    """
    Returns a dictionary of available utility modules in this package.

    Returns:
        Dict[str, bool]: Dictionary with utility names and availability flags
    """
    return {
        "admin_constants": ADMIN_CONSTANTS_AVAILABLE,
        "audit_constants": AUDIT_CONSTANTS_AVAILABLE,
        "admin_auth": ADMIN_AUTH_AVAILABLE,
        "audit_utils": AUDIT_UTILS_AVAILABLE,
        "config_validation": CONFIG_VALIDATION_AVAILABLE,
        "error_handling": ERROR_HANDLING_AVAILABLE,
        "encryption_utils": ENCRYPTION_UTILS_AVAILABLE,
        "metrics_utils": METRICS_UTILS_AVAILABLE,
        "secure_credentials": SECURE_CREDENTIALS_AVAILABLE,
        "password_utils": PASSWORD_UTILS_AVAILABLE,
        "file_integrity": FILE_INTEGRITY_AVAILABLE,
        "security_utils": SECURITY_UTILS_AVAILABLE
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
if ADMIN_CONSTANTS_AVAILABLE:
    __all__.extend([
        # Exit codes
        "EXIT_SUCCESS",
        "EXIT_ERROR",
        "EXIT_PERMISSION_ERROR",
        "EXIT_RESOURCE_ERROR",
        "EXIT_VALIDATION_ERROR",
        "EXIT_AUTHENTICATION_ERROR",
        "EXIT_CONFIGURATION_ERROR",
        "EXIT_OPERATION_CANCELLED",
        "EXIT_CONNECTIVITY_ERROR",
        "EXIT_TIMEOUT_ERROR",
        "EXIT_EXTERNAL_SERVICE_ERROR",

        # Common timeouts
        "DEFAULT_OPERATION_TIMEOUT",
        "DEFAULT_NETWORK_TIMEOUT",
        "DEFAULT_API_REQUEST_TIMEOUT",
        "DEFAULT_DATABASE_OPERATION_TIMEOUT",
        "DEFAULT_LOCK_TIMEOUT",
        "DEFAULT_SESSION_TIMEOUT",

        # Resource limits
        "DEFAULT_API_RATE_LIMIT",
        "DEFAULT_BATCH_SIZE",
        "DEFAULT_MAX_RETRIES",
        "DEFAULT_RETRY_DELAY",
        "DEFAULT_MAX_RESULTS",

        # Security settings
        "DEFAULT_PASSWORD_MIN_LENGTH",
        "DEFAULT_MFA_TIMEOUT",
        "DEFAULT_TOKEN_EXPIRY",
        "DEFAULT_EMERGENCY_ACCESS_DURATION"
    ])

if AUDIT_CONSTANTS_AVAILABLE:
    __all__.extend([
        # Audit categories
        "ADMIN_ACTION_CATEGORY",
        "ADMIN_EVENT_PREFIX",

        # Severity levels
        "SEVERITY_INFO",
        "SEVERITY_WARNING",
        "SEVERITY_ERROR",
        "SEVERITY_CRITICAL",

        # Action statuses
        "STATUS_SUCCESS",
        "STATUS_FAILURE",
        "STATUS_ATTEMPTED",
        "STATUS_CANCELLED",

        # Action types
        "ACTION_USER_CREATE",
        "ACTION_USER_UPDATE",
        "ACTION_USER_DELETE",
        "ACTION_ROLE_ASSIGN",
        "ACTION_ROLE_REVOKE",
        "ACTION_PERMISSION_GRANT",
        "ACTION_PERMISSION_REVOKE",
        "ACTION_CONFIG_CHANGE",
        "ACTION_SYSTEM_CHANGE",
        "ACTION_SECURITY_CHANGE",
        "ACTION_EMERGENCY_ACCESS",
        "ACTION_EMERGENCY_DEACTIVATE",
        "ACTION_DATA_EXPORT",
        "ACTION_AUDIT_ACCESS",
        "ACTION_API_KEY_CREATE",
        "ACTION_API_KEY_REVOKE"
    ])

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
        "verify_audit_log_integrity"
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
        "AdminValidationError",
        "AdminPermissionError",
        "AdminConnectivityError",
        "AdminTimeoutError"
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

if SECURITY_UTILS_AVAILABLE:
    __all__.extend([
        "generate_api_token",
        "compute_hash"
    ])

if FILE_INTEGRITY_AVAILABLE:
    file_integrity_exports = []
    # Only add functions that are actually available
    if 'update_file_integrity_baseline' in locals():
        file_integrity_exports.append("update_file_integrity_baseline")
    if 'verify_file_integrity' in locals():
        file_integrity_exports.append("verify_file_integrity")
    if 'calculate_file_hash' in locals():
        file_integrity_exports.append("calculate_file_hash")
    if 'get_baseline_status' in locals():
        file_integrity_exports.append("get_baseline_status")
    if 'validate_baseline_update' in locals():
        file_integrity_exports.append("validate_baseline_update")
    if 'check_critical_file_integrity' in locals():
        file_integrity_exports.append("check_critical_file_integrity")
    if 'create_file_hash_baseline' in locals():
        file_integrity_exports.append("create_file_hash_baseline")
    if 'detect_file_changes' in locals():
        file_integrity_exports.append("detect_file_changes")
    if 'verify_file_signature' in locals():
        file_integrity_exports.append("verify_file_signature")
    if 'get_last_integrity_status' in locals():
        file_integrity_exports.append("get_last_integrity_status")
    if 'log_file_integrity_event' in locals():
        file_integrity_exports.append("log_file_integrity_event")
    if 'initialize_file_monitoring' in locals():
        file_integrity_exports.append("initialize_file_monitoring")

    __all__.extend(file_integrity_exports)

# Log initialization status
logger.debug(f"Admin utils package initialized with: {', '.join([k for k, v in get_available_utilities().items() if v])}")
