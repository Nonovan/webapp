"""
Security models package.

This package contains models related to security operations including
incident management, vulnerability tracking, and security auditing.

It provides core security features for tracking and managing security
events within the application.
"""

import logging
from typing import List

# Setup package logging
logger = logging.getLogger(__name__)

# Import directly accessible models (what the package exposes)
from .system import AuditLog, SystemConfig
from .login_attempt import LoginAttempt
from .security_incident import SecurityIncident
from .vulnerability import Vulnerability

# Import circuit breaker functionality
try:
    from .circuit_breaker import (
        CircuitBreaker,
        CircuitBreakerState,
        CircuitOpenError,
        RateLimiter,
        RateLimitExceededError
    )
    CIRCUIT_BREAKER_AVAILABLE = True
    logger.debug("Circuit breaker functionality successfully imported")
except ImportError:
    CIRCUIT_BREAKER_AVAILABLE = False
    logger.debug("Circuit breaker functionality not available")

# Try to import incident response constants
try:
    from ...admin.security.incident_response_kit.incident_constants import (
        IncidentStatus,
        IncidentPhase,
        IncidentSeverity,
        IncidentType,
        PHASE_STATUS_MAPPING,
        STATUS_TRANSITIONS
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
