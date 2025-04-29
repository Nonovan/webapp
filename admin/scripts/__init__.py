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
__version__ = '1.0.0'
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
        display_review,
        fetch_admin_logs,
        format_report_data,
        generate_report,
        get_time_range,
        run_anomaly_detection,
        run_integrity_checks,
        write_output
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
        list_emergency_requests
    )
    EMERGENCY_ACCESS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Emergency access script not fully available: {e}")

# Try importing privilege_management functionality
try:
    from .privilege_management import (
        grant_privileges,
        revoke_privileges,
        list_privileges
    )
    PRIVILEGE_MANAGEMENT_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Privilege management script not fully available: {e}")

# Try importing system_lockdown functionality
try:
    from .system_lockdown import (
        apply_security_controls,
        verify_security_controls
    )
    SYSTEM_LOCKDOWN_AVAILABLE = True
except ImportError as e:
    logger.debug(f"System lockdown script not fully available: {e}")

# Add imports for other script modules as needed

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
        "fetch_admin_logs",
        "format_report_data",
        "generate_report",
        "display_review",
        "run_anomaly_detection",
        "run_integrity_checks"
    ])

if EMERGENCY_ACCESS_AVAILABLE:
    __all__.extend([
        "activate_emergency_access",
        "approve_emergency_request",
        "deactivate_emergency_access",
        "list_emergency_requests"
    ])

if PRIVILEGE_MANAGEMENT_AVAILABLE:
    __all__.extend([
        "grant_privileges",
        "revoke_privileges",
        "list_privileges"
    ])

if SYSTEM_LOCKDOWN_AVAILABLE:
    __all__.extend([
        "apply_security_controls",
        "verify_security_controls"
    ])

# Log initialization status
active_scripts = [name for name, available in get_available_scripts().items() if available]
if active_scripts:
    logger.debug(f"Admin scripts package initialized with: {', '.join(active_scripts)}")
else:
    logger.debug("Admin scripts package initialized with no active script modules.")
