"""
Recovery Module for Incident Response

This module provides tools and utilities for the recovery phase of security incident
response following the NIST SP 800-61 framework. It includes components for service
restoration, security hardening, and system verification after incident containment
and eradication.

The module is designed to ensure that recovered systems meet security requirements
while minimizing business disruption during the recovery process.
"""

import logging
import os
from pathlib import Path

# Initialize module logging
logger = logging.getLogger(__name__)

# Determine module base path
RECOVERY_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Import service restoration components
try:
    from .service_restoration import (
        restore_service, restore_service_main, perform_validation,
        validate_dependencies, run_verification_script,
        backup_file, attempt_rollback, generate_summary_report
    )
    SERVICE_RESTORATION_AVAILABLE = True
    logger.debug("Service restoration module loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import service_restoration module: {e}")
    SERVICE_RESTORATION_AVAILABLE = False

    def restore_service(*args, **kwargs):
        raise NotImplementedError("Service restoration module not available")

# Import security hardening components
try:
    from .security_hardening import (
        harden_system, apply_control, load_hardening_profile,
        execute_command
    )
    SECURITY_HARDENING_AVAILABLE = True
    logger.debug("Security hardening module loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import security_hardening module: {e}")
    SECURITY_HARDENING_AVAILABLE = False

    def harden_system(*args, **kwargs):
        raise NotImplementedError("Security hardening module not available")

# Constants for restoration templates and profiles
RESOURCES_DIR = RECOVERY_DIR / "resources"
HARDENING_PROFILES_DIR = RESOURCES_DIR / "hardening_profiles"
RESTORATION_TEMPLATES_DIR = RESOURCES_DIR / "restoration_templates"
VERIFICATION_SCRIPTS_DIR = RESOURCES_DIR / "verification_scripts"

# Define exceptions
class RecoveryError(Exception):
    """Base exception for recovery errors."""
    pass

class ServiceRestorationError(RecoveryError):
    """Error during service restoration."""
    pass

class SecurityHardeningError(RecoveryError):
    """Error during security hardening."""
    pass

class VerificationError(RecoveryError):
    """Error during system verification."""
    pass

class ProfileNotFoundError(RecoveryError):
    """Requested hardening profile not found."""
    pass

# Public exports
__all__ = [
    # Main functions
    'restore_service',
    'harden_system',

    # Secondary functions
    'perform_validation',
    'validate_dependencies',
    'apply_control',
    'load_hardening_profile',
    'run_verification_script',
    'backup_file',
    'attempt_rollback',
    'execute_command',
    'generate_summary_report',

    # Constants
    'RECOVERY_DIR',
    'RESOURCES_DIR',
    'HARDENING_PROFILES_DIR',
    'RESTORATION_TEMPLATES_DIR',
    'VERIFICATION_SCRIPTS_DIR',

    # Availability flags
    'SERVICE_RESTORATION_AVAILABLE',
    'SECURITY_HARDENING_AVAILABLE',

    # Exceptions
    'RecoveryError',
    'ServiceRestorationError',
    'SecurityHardeningError',
    'VerificationError',
    'ProfileNotFoundError'
]
