"""
Administrative Scripts Package

This package contains command-line scripts for administrative tasks in the Cloud Infrastructure
Platform. These scripts provide system administrators with utilities for auditing, emergency
access management, privilege management, system security operations, and health verification.

Key components include:
- Administrative action auditing
- Emergency access management
- Privilege control management
- System security hardening
- Health and compliance checking
- Backup verification

All scripts implement appropriate security controls, including authentication,
authorization, and comprehensive logging of all actions.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Setup package logging
logger = logging.getLogger(__name__)

# Version information
__version__ = '0.1.1'
__author__ = 'Cloud Infrastructure Platform Team'
__email__ = 'admin-team@example.com'

# Determine script base path
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent

# Initialize availability flags
ADMIN_AUDIT_AVAILABLE = False
EMERGENCY_ACCESS_AVAILABLE = False
PRIVILEGE_MANAGEMENT_AVAILABLE = False
SYSTEM_LOCKDOWN_AVAILABLE = False
HEALTH_CHECK_AVAILABLE = False
COMPLIANCE_REPORTING_AVAILABLE = False
BACKUP_VERIFICATION_AVAILABLE = False

# Try importing admin_audit functionality
try:
    from .admin_audit import (
        # Core functions
        fetch_admin_logs,
        run_anomaly_detection,
        run_integrity_checks,

        # Helper functions
        get_time_range,
        format_report_data,
        write_output,
        display_review,

        # Constants
        SUPPORTED_FORMATS,
        DEFAULT_LIMIT
    )
    ADMIN_AUDIT_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin audit script not fully available: {e}")

# Try importing emergency_access functionality
try:
    from .emergency_access import (
        activate_emergency_access,
        approve_emergency_request,
        deactivate_emergency_access,
        list_emergency_requests,
        get_request_details,

        # Helper functions
        format_output,
        setup_arg_parser,

        # Classes
        EmergencyAccessManager,
        AccessStatus,
        EmergencyAccessError,
        ValidationError,
        AuthorizationError,
        ApprovalError,
        ResourceError,

        # Constants
        EXIT_SUCCESS,
        EXIT_ERROR,
        EXIT_VALIDATION_ERROR,
        EXIT_AUTHENTICATION_ERROR,
        EXIT_AUTHORIZATION_ERROR,
        EXIT_RESOURCE_ERROR,
        EXIT_APPROVAL_ERROR,
        EXIT_ARGUMENT_ERROR,
        NOTIFIERS
    )
    EMERGENCY_ACCESS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Emergency access script not fully available: {e}")

# Try importing privilege_management functionality
try:
    from .privilege_management import (
        grant_permission,
        revoke_permission,
        list_permissions,
        check_permission,
        delegate_permission,
        list_delegations,
        revoke_delegation,
        export_permissions,

        # Exception classes
        PrivilegeManagementError,
        ValidationError,
        ResourceNotFoundError,
        AuthenticationError
    )
    PRIVILEGE_MANAGEMENT_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Privilege management script not fully available: {e}")

# Try importing system_lockdown functionality
try:
    from .system_lockdown import (
        # Core functions
        apply_security_controls,
        verify_security_controls,

        # Classes
        SystemLockdown,
        ValidationResult,
        Severity,

        # Constants
        DEFAULT_ENVIRONMENT,
        DEFAULT_SECURITY_LEVEL
    )
    SYSTEM_LOCKDOWN_AVAILABLE = True
except ImportError as e:
    logger.debug(f"System lockdown script not fully available: {e}")

# Try importing system_health_check functionality
try:
    from .system_health_check import (
        run_health_check,
        generate_health_report,
        check_system_resources,
        verify_services_status,
        check_security_compliance,

        # Helper functions
        check_tcp_connection,
        check_endpoint,
        check_dns_resolution,

        # Classes
        HealthChecker,
        Status,

        # Constants
        DEFAULT_TIMEOUT,
        DEFAULT_DISK_THRESHOLD,
        DEFAULT_MEMORY_THRESHOLD,
        DEFAULT_CPU_THRESHOLD,
        DEFAULT_REPORT_FORMAT,
    )
    HEALTH_CHECK_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Health check script not fully available: {e}")

# Try importing compliance_report_generator functionality
try:
    from .compliance_report_generator import (
        generate_compliance_report,
        validate_compliance,
        get_compliance_status,
        export_compliance_evidence,
        check_regulatory_requirements,

        # Helper functions
        parse_arguments,
        generate_report_filename,
        ensure_output_directory,
        load_compliance_mapping,
        generate_pdf_from_html,
        enhance_report_with_remediation,
        append_evidence_to_report,
        log_compliance_report_generation,

        # Constants
        DEFAULT_OUTPUT_DIR,
        SUPPORTED_FRAMEWORKS,
        SUPPORTED_FORMATS as COMPLIANCE_SUPPORTED_FORMATS,
        REGULATORY_AUTHORITIES
    )
    COMPLIANCE_REPORTING_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Compliance reporting script not fully available: {e}")

# Try importing backup_verification functionality
try:
    from .backup_verification import (
        # Core verification functions
        verify_backup_integrity,
        test_backup_restore,
        verify_backup_encryption,
        generate_verification_report,
        check_backup_completeness,

        # Helper functions
        detect_backup_format,
        verify_backup_checksum,
        verify_backup_structure,

        # Classes
        VerificationStatus,
        BackupFormat,

        # Constants
        BACKUP_DIR,
        TEST_RESTORE_DIR,
        DEFAULT_REPORT_DIR,
        SUPPORTED_FORMATS as BACKUP_SUPPORTED_FORMATS,
        DEFAULT_TEST_DB_NAME,
        DEFAULT_VERIFICATION_TIMEOUT,
        main
    )
    BACKUP_VERIFICATION_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Backup verification script not fully available: {e}")

def get_available_scripts() -> Dict[str, bool]:
    """Returns a dictionary of available scripts within this package."""
    return {
        "admin_audit": ADMIN_AUDIT_AVAILABLE,
        "emergency_access": EMERGENCY_ACCESS_AVAILABLE,
        "privilege_management": PRIVILEGE_MANAGEMENT_AVAILABLE,
        "system_lockdown": SYSTEM_LOCKDOWN_AVAILABLE,
        "health_check": HEALTH_CHECK_AVAILABLE,
        "compliance_reporting": COMPLIANCE_REPORTING_AVAILABLE,
        "backup_verification": BACKUP_VERIFICATION_AVAILABLE
    }

# Define public exports - symbols that can be imported from this package
__all__ = [
    # Package information
    "__version__",
    "__author__",
    "__email__",

    # Package utilities
    "get_available_scripts",
    "SCRIPT_DIR"
]

# Conditionally add exports based on available script modules
if ADMIN_AUDIT_AVAILABLE:
    __all__.extend([
        # Core functions
        "fetch_admin_logs",
        "run_anomaly_detection",
        "run_integrity_checks",

        # Helper functions
        "get_time_range",
        "format_report_data",
        "write_output",
        "display_review",

        # Constants
        "SUPPORTED_FORMATS",
        "DEFAULT_LIMIT"
    ])

if EMERGENCY_ACCESS_AVAILABLE:
    __all__.extend([
        # Core functions
        "activate_emergency_access",
        "approve_emergency_request",
        "deactivate_emergency_access",
        "list_emergency_requests",
        "get_request_details",

        # Helper functions
        "format_output",
        "setup_arg_parser",

        # Classes
        "EmergencyAccessManager",
        "AccessStatus",
        "EmergencyAccessError",
        "ValidationError",
        "AuthorizationError",
        "ApprovalError",
        "ResourceError",

        # Constants
        "EXIT_SUCCESS",
        "EXIT_ERROR",
        "EXIT_VALIDATION_ERROR",
        "EXIT_AUTHENTICATION_ERROR",
        "EXIT_AUTHORIZATION_ERROR",
        "EXIT_RESOURCE_ERROR",
        "EXIT_APPROVAL_ERROR",
        "EXIT_ARGUMENT_ERROR",
        "NOTIFIERS"
    ])

if PRIVILEGE_MANAGEMENT_AVAILABLE:
    __all__.extend([
        # Core functions from privilege_management.py
        "grant_permission",
        "revoke_permission",
        "list_permissions",
        "check_permission",
        "delegate_permission",
        "list_delegations",
        "revoke_delegation",
        "export_permissions",

        # Exception classes from privilege_management.py
        "PrivilegeManagementError",
        "ValidationError",
        "ResourceNotFoundError",
        "AuthenticationError"
    ])

if SYSTEM_LOCKDOWN_AVAILABLE:
    __all__.extend([
        # Core functions
        "apply_security_controls",
        "verify_security_controls",

        # Classes
        "SystemLockdown",
        "ValidationResult",
        "Severity",

        # Constants
        "DEFAULT_ENVIRONMENT",
        "DEFAULT_SECURITY_LEVEL"
    ])

if HEALTH_CHECK_AVAILABLE:
    __all__.extend([
        # Core functions
        "run_health_check",
        "generate_health_report",
        "check_system_resources",
        "verify_services_status",
        "check_security_compliance",

        # Helper functions
        "check_tcp_connection",
        "check_endpoint",
        "check_dns_resolution",

        # Classes
        "HealthChecker",
        "Status",

        # Constants
        "DEFAULT_TIMEOUT",
        "DEFAULT_DISK_THRESHOLD",
        "DEFAULT_MEMORY_THRESHOLD",
        "DEFAULT_CPU_THRESHOLD",
        "DEFAULT_REPORT_FORMAT",
    ])

if COMPLIANCE_REPORTING_AVAILABLE:
    __all__.extend([
        # Core verification functions
        "generate_compliance_report",
        "validate_compliance",
        "get_compliance_status",
        "export_compliance_evidence",
        "check_regulatory_requirements",

        # Helper functions
        "parse_arguments",
        "generate_report_filename",
        "ensure_output_directory",
        "load_compliance_mapping",
        "generate_pdf_from_html",
        "enhance_report_with_remediation",
        "append_evidence_to_report",
        "log_compliance_report_generation",

        # Constants
        "DEFAULT_OUTPUT_DIR",
        "SUPPORTED_FRAMEWORKS",
        "COMPLIANCE_SUPPORTED_FORMATS",
        "REGULATORY_AUTHORITIES"
    ])

if BACKUP_VERIFICATION_AVAILABLE:
    __all__.extend([
        # Core verification functions
        "verify_backup_integrity",
        "test_backup_restore",
        "verify_backup_encryption",
        "generate_verification_report",
        "check_backup_completeness",

        # Helper functions
        "detect_backup_format",
        "verify_backup_checksum",
        "verify_backup_structure",

        # Classes
        "VerificationStatus",
        "BackupFormat",

        # Constants
        "BACKUP_DIR",
        "TEST_RESTORE_DIR",
        "DEFAULT_REPORT_DIR",
        "BACKUP_SUPPORTED_FORMATS",
        "DEFAULT_TEST_DB_NAME",
        "DEFAULT_VERIFICATION_TIMEOUT"
    ])

# Log initialization status
active_scripts = [name for name, available in get_available_scripts().items() if available]
if active_scripts:
    logger.debug(f"Admin scripts package initialized with: {', '.join(active_scripts)}")
else:
    logger.debug("Admin scripts package initialized with no active script modules.")
