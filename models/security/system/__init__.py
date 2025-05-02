"""
System-level security models for Cloud Infrastructure Platform.

This package contains database models related to system-level security functionalities:
- AuditLog: Comprehensive security event logging
- SystemConfig: Security-related configuration management
- SecurityBaseline: Security standard definitions and compliance tracking
- SecurityScan: Security scanning configuration and results

These models provide the foundation for security governance, configuration management,
compliance verification, and security monitoring across the platform.
"""

import logging
from typing import Dict, Any, List, Optional, Union

# Configure package logger
logger = logging.getLogger(__name__)

# Import models explicitly to control public API
from .audit_log import AuditLog
from .system_config import SystemConfig
from .security_baseline import SecurityBaseline
from .security_scan import SecurityScan

# Handle optional models
try:
    from .compliance_check import ComplianceCheck
    __all__ = [
        "AuditLog",
        "SystemConfig",
        "SecurityBaseline",
        "SecurityScan",
        "ComplianceCheck"
    ]
except ImportError:
    logger.debug("ComplianceCheck model not available")
    __all__ = [
        "AuditLog",
        "SystemConfig",
        "SecurityBaseline",
        "SecurityScan"
    ]

# Track initialization for diagnostics
logger.debug(f"Security system models initialized: {', '.join(__all__)}")
