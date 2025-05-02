"""
Security models package for the Cloud Infrastructure Platform.

This package contains models related to security management including:
- SecurityIncident: For tracking and managing security incidents
- AuditLog: For comprehensive security auditing and compliance reporting
- SystemConfig: For security-related configuration management
- LoginAttempt: For tracking authentication attempts and preventing brute force attacks
- Vulnerability: For tracking and managing security vulnerabilities
- SecurityBaseline: For defining and managing security standards and configurations
- SecurityScan: For tracking security scans and their findings
- ThreatIntelligence: For managing threat intelligence data
- ComplianceCheck: For compliance verification and reporting
- CircuitBreaker: For preventing cascading failures through service protection

These models provide the foundation for the security features of the platform,
enabling incident response, vulnerability management, compliance auditing,
audit trail maintenance, secure configuration management, service resilience,
and protection against authentication-based attacks.
"""

import logging
from typing import Dict, Any, List, Optional, Union

# Configure package logger
logger = logging.getLogger(__name__)

# Import core security models
from .circuit_breaker import (
    CircuitBreaker, CircuitBreakerState, CircuitOpenError,
    RateLimiter, RateLimitExceededError
)
from .login_attempt import LoginAttempt
from .security_incident import SecurityIncident
from .vulnerability import Vulnerability

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
    "RateLimitExceededError"
]

# Try to import additional models that might not be available in all deployments
try:
    from .threat_intelligence import ThreatIndicator, ThreatFeed
    __all__.extend(["ThreatIndicator", "ThreatFeed"])
    logger.debug("ThreatIntelligence models successfully imported")
except ImportError:
    logger.debug("ThreatIntelligence models not available")

try:
    from .compliance_check import ComplianceCheck
    __all__.append("ComplianceCheck")
    logger.debug("ComplianceCheck model successfully imported")
except ImportError:
    logger.debug("ComplianceCheck model not available")

# Try to import system-level models if not already imported
try:
    from .system import (
        SecurityBaseline as SystemSecurityBaseline,
        SecurityScan as SystemSecurityScan
    )
    logger.debug("System-level security models imported")
except ImportError:
    logger.debug("System-level security models not available as separate imports")

# Version tracking for package
__version__ = '0.1.1'  # Updated version to reflect addition of circuit breaker

# Log initialization status
logger.debug(f"Security models package initialized with {len(__all__)} components, version {__version__}")
