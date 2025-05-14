#!/usr/bin/env python3
"""
Common security checker utilities for the Cloud Infrastructure Platform.

This package provides a standardized framework for security checks implementation,
including result formatting, evidence collection, compliance mapping, and remediation
guidance in a consistent manner across all security checks.
"""

import os
import logging
from enum import Enum
from typing import Dict, List, Any, Optional, Union

# Configure package-level logger
logger = logging.getLogger("security.audit.checker")

# Import core functionality from modules
try:
    from .check_result import (
        # Core classes
        CheckResult,
        CheckResultSet,
        Severity,

        # Constants
        DEFAULT_RESULT_FORMAT,
        SEVERITY_COLOR_MAP,

        # Result formatting methods
        format_severity,
        format_evidence
    )

    from .check_utils import (
        # Core functions
        load_baseline,
        get_file_permissions,
        check_file_ownership,
        secure_execute,
        compute_file_hash,
        find_files_with_pattern,

        # System information
        get_os_info,
        get_environment,
        find_process_by_name,
        check_port_listening,

        # Permission checks
        is_world_writable,
        is_world_readable,
        is_suid_set,
        is_sgid_set,

        # Validation functions
        sanitize_string,
        is_valid_ip_address,
        is_valid_port,
        compare_versions,

        # Configuration handling
        parse_config_file,
        get_compliance_requirements,

        # Display helpers
        convert_to_human_readable,

        # Enums and constants
        ComplianceFramework,
        DEFAULT_BASELINE_DIR,
        DEFAULT_CONFIG_DIR,
        DEFAULT_TIMEOUT
    )

    from .check_helper import (
        # Helper functions
        run_check,
        apply_baseline,
        normalize_path,
        validate_check_config,
        collect_evidence,
        map_to_compliance,
        generate_remediation,
        merge_results,
        filter_results,

        # Resource management
        set_resource_limits,
        with_timeout,

        # Error handling
        handle_check_error,
        safe_check
    )

    # Package version
    __version__ = '1.0.0'

except ImportError as e:
    # Log import errors but don't fail - individual modules can still be imported
    logger.warning(f"Error importing check components: {e}")
    logger.debug("Some check functionality may be unavailable")


# Define availability flags
UTILS_AVAILABLE = 'check_utils' in locals()
RESULT_AVAILABLE = 'CheckResult' in locals()
HELPER_AVAILABLE = 'run_check' in locals()


def get_version() -> str:
    """Return the version of the common checker utilities."""
    return __version__


def is_fully_initialized() -> bool:
    """Check if all components are properly initialized."""
    return all([UTILS_AVAILABLE, RESULT_AVAILABLE, HELPER_AVAILABLE])


def check_environment() -> Dict[str, Any]:
    """
    Perform basic environment checks to verify that the checkers can run properly.

    Returns:
        Dictionary with environment status information
    """
    status = {
        "initialized": is_fully_initialized(),
        "version": __version__,
        "components": {
            "utils": UTILS_AVAILABLE,
            "results": RESULT_AVAILABLE,
            "helpers": HELPER_AVAILABLE
        }
    }

    # Add environment info if available
    if UTILS_AVAILABLE:
        try:
            status["environment"] = get_environment()
            status["os_info"] = get_os_info()
        except Exception as e:
            logger.error(f"Error getting environment info: {e}")
            status["environment_error"] = str(e)

    return status


def run_basic_system_check() -> Dict[str, Any]:
    """
    Run a basic system check to verify that the security environment is correctly set up.

    Returns:
        Dictionary with check results
    """
    results = {"success": False, "errors": []}

    try:
        # Skip if not fully initialized
        if not is_fully_initialized():
            results["errors"].append("Checker components not fully initialized")
            return results

        # Check baseline directory
        if not os.path.exists(DEFAULT_BASELINE_DIR):
            results["errors"].append(f"Baseline directory not found: {DEFAULT_BASELINE_DIR}")

        # Check basic file operations
        try:
            permissions = get_file_permissions(__file__)
            results["self_permissions"] = oct(permissions)
        except Exception as e:
            results["errors"].append(f"Failed to check file permissions: {str(e)}")

        # Set success flag if no errors
        if not results["errors"]:
            results["success"] = True

    except Exception as e:
        results["errors"].append(f"Unexpected error in basic system check: {str(e)}")

    return results


# Simplified interface functions for users of this package
def create_check_result(severity: Union[str, Severity, int],
                      title: str,
                      description: str,
                      remediation: str,
                      **kwargs) -> CheckResult:
    """
    Create a check result with standard format.

    Args:
        severity: The severity level (can be string, enum or int)
        title: Short title describing the finding
        description: Detailed description of the issue
        remediation: Action steps to resolve the issue
        **kwargs: Additional arguments for CheckResult

    Returns:
        CheckResult object
    """
    # Convert severity string to enum if needed
    if isinstance(severity, str):
        severity = Severity[severity.upper()]

    # Create and return result
    return CheckResult(
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        **kwargs
    )


# Simplified access to key severity levels
CRITICAL = Severity.CRITICAL
HIGH = Severity.HIGH
MEDIUM = Severity.MEDIUM
LOW = Severity.LOW
INFO = Severity.INFO

# Export key elements at package level
__all__ = [
    # Core classes
    'CheckResult',
    'CheckResultSet',
    'Severity',
    'ComplianceFramework',

    # Constants and formats
    'DEFAULT_RESULT_FORMAT',
    'SEVERITY_COLOR_MAP',
    'DEFAULT_BASELINE_DIR',
    'DEFAULT_CONFIG_DIR',
    'DEFAULT_TIMEOUT',

    # Simplified interface
    'create_check_result',
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',

    # Core functionality - Check Utils
    'load_baseline',
    'get_file_permissions',
    'secure_execute',
    'compute_file_hash',
    'is_world_writable',
    'is_world_readable',
    'is_suid_set',
    'is_sgid_set',
    'check_file_ownership',
    'find_files_with_pattern',

    # System information functions
    'get_os_info',
    'get_environment',
    'find_process_by_name',
    'check_port_listening',

    # Validation functions
    'sanitize_string',
    'is_valid_ip_address',
    'is_valid_port',
    'compare_versions',
    'parse_config_file',
    'get_compliance_requirements',
    'convert_to_human_readable',

    # Result formatting
    'format_severity',
    'format_evidence',

    # Core functionality - Check Helper
    'run_check',
    'apply_baseline',
    'normalize_path',
    'validate_check_config',
    'collect_evidence',
    'map_to_compliance',
    'generate_remediation',
    'merge_results',
    'filter_results',

    # Resource management
    'set_resource_limits',
    'with_timeout',

    # Error handling
    'handle_check_error',
    'safe_check',

    # Package information
    '__version__',
    'get_version',
    'check_environment',
    'run_basic_system_check'
]
