"""
Security models package for the Cloud Infrastructure Platform.

This package contains models related to security management including:
- SecurityIncident: For tracking and managing security incidents
- AuditLog: For comprehensive security auditing and compliance reporting
- SystemConfig: For security-related configuration management
- LoginAttempt: For tracking authentication attempts and preventing brute force attacks
- VulnerabilityRecord: For tracking and managing security vulnerabilities
- SecurityBaseline: For defining and managing security standards and configurations
- SecurityScan: For tracking security scans and their findings
- ThreatIntelligence: For managing threat intelligence data
- ComplianceCheck: For compliance verification and reporting

These models provide the foundation for the security features of the platform,
enabling incident response, vulnerability management, compliance auditing,
audit trail maintenance, secure configuration management with version tracking,
and protection against authentication-based attacks.
"""

# Import core security models
from .security_incident import SecurityIncident
from .audit_log import AuditLog
from .system_config import SystemConfig
from .login_attempt import LoginAttempt
from .vulnerability_record import VulnerabilityRecord
from .security_baseline import SecurityBaseline
from .security_scan import SecurityScan

# Define exports explicitly for better control over the public API
__all__ = [
    "SecurityIncident",
    "AuditLog",
    "SystemConfig",
    "LoginAttempt",
    "VulnerabilityRecord",
    "SecurityBaseline",
    "SecurityScan"
]

# Try to import additional models that might not be available in all deployments
try:
    from .threat_intelligence import ThreatIndicator, ThreatFeed
    __all__.extend(["ThreatIndicator", "ThreatFeed"])
except ImportError:
    pass

try:
    from .compliance_check import ComplianceCheck
    __all__.append("ComplianceCheck")
except ImportError:
    pass

# Version tracking for package
__version__ = '0.1.0'
