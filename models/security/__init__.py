"""
Security models for Cloud Infrastructure Platform.

This package contains database models related to security functionalities:
- SecurityIncident: Security incident tracking and management
- Vulnerability: Modern vulnerability management
- ThreatIndicator: Threat intelligence data management
- AuditLog: Security event logging
- SystemConfig: Security configuration management
- Other system-level security components

These models provide the foundation for security operations, incident response,
vulnerability management, and compliance tracking across the platform.
"""

import logging
from typing import Dict, Any, List, Optional, Union

# Configure package logger
logger = logging.getLogger(__name__)

# Import core security models
from .security_incident import SecurityIncident
from .vulnerability import Vulnerability
from .circuit_breaker import (
    CircuitBreaker, CircuitBreakerState, CircuitOpenError,
    RateLimiter, RateLimitExceededError
)
from .login_attempt import LoginAttempt

# Extract incident phase and status constants from SecurityIncident for use elsewhere
SECURITY_INCIDENT_PHASES = {
    'IDENTIFICATION': SecurityIncident.PHASE_IDENTIFICATION,
    'CONTAINMENT': SecurityIncident.PHASE_CONTAINMENT,
    'ERADICATION': SecurityIncident.PHASE_ERADICATION,
    'RECOVERY': SecurityIncident.PHASE_RECOVERY,
    'LESSONS_LEARNED': SecurityIncident.PHASE_LESSONS_LEARNED
}

SECURITY_INCIDENT_STATUSES = {
    'OPEN': SecurityIncident.STATUS_OPEN,
    'INVESTIGATING': SecurityIncident.STATUS_INVESTIGATING,
    'RESOLVED': SecurityIncident.STATUS_RESOLVED,
    'CLOSED': SecurityIncident.STATUS_CLOSED,
    'MERGED': SecurityIncident.STATUS_MERGED
}

SECURITY_INCIDENT_SEVERITIES = {
    'CRITICAL': SecurityIncident.SEVERITY_CRITICAL,
    'HIGH': SecurityIncident.SEVERITY_HIGH,
    'MEDIUM': SecurityIncident.SEVERITY_MEDIUM,
    'LOW': SecurityIncident.SEVERITY_LOW
}

# Import incident response models
try:
    from .incident_response import (
        Incident, IncidentStatus, IncidentPhase,
        IncidentSeverity, IncidentType,
        PHASE_STATUS_MAPPING, STATUS_TRANSITIONS
    )
    INCIDENT_RESPONSE_AVAILABLE = True
    logger.debug("Incident response models successfully imported")
except ImportError:
    INCIDENT_RESPONSE_AVAILABLE = False
    logger.debug("Incident response models not available")

# Import from system sub-package
from .system import AuditLog, SecurityBaseline, SecurityScan, SystemConfig

# Define exports explicitly for better control over the public API
__all__ = [
    # Core security models
    "SecurityIncident",
    "AuditLog",
    "SystemConfig",
    "LoginAttempt",
    "Vulnerability",
    "SecurityBaseline",
    "SecurityScan",

    # Circuit breaker components
    "CircuitBreaker",
    "CircuitBreakerState",
    "CircuitOpenError",
    "RateLimiter",
    "RateLimitExceededError",

    # Security incident constants
    "SECURITY_INCIDENT_PHASES",
    "SECURITY_INCIDENT_STATUSES",
    "SECURITY_INCIDENT_SEVERITIES"
]

# Add incident response components if available
if INCIDENT_RESPONSE_AVAILABLE:
    __all__.extend([
        "Incident",
        "IncidentStatus",
        "IncidentPhase",
        "IncidentSeverity",
        "IncidentType",
        "PHASE_STATUS_MAPPING",
        "STATUS_TRANSITIONS"
    ])

# Try to import additional models that might not be available in all deployments
try:
    from .threat_intelligence import ThreatIndicator, ThreatFeed, ThreatEvent
    __all__.extend(["ThreatIndicator", "ThreatFeed", "ThreatEvent"])
    logger.debug("ThreatIntelligence models successfully imported")
except ImportError:
    logger.debug("ThreatIntelligence models not available")

# Try to import compliance models
try:
    from .system.compliance_check import (
        ComplianceCheck,
        ComplianceStatus,
        ComplianceSeverity
    )
    __all__.extend(["ComplianceCheck", "ComplianceStatus", "ComplianceSeverity"])
    logger.debug("ComplianceCheck model successfully imported")
except ImportError:
    logger.debug("ComplianceCheck model not available")

# Track initialization for diagnostics
logger.debug(f"Security models initialized: {', '.join(__all__)}")
