"""
Security models package for the Cloud Infrastructure Platform.

This package contains models related to security management including:
- SecurityIncident: For tracking and managing security incidents
- AuditLog: For comprehensive security auditing and compliance reporting
- SystemConfig: For security-related configuration management
- LoginAttempt: For tracking authentication attempts and preventing brute force attacks

These models provide the foundation for the security features of the platform,
enabling incident response, compliance auditing, audit trail maintenance,
secure configuration management with version tracking, and protection against
authentication-based attacks.
"""

# Import core security models
from .security_incident import SecurityIncident
from .audit_log import AuditLog
from .system_config import SystemConfig
from .login_attempt import LoginAttempt

# Define exports explicitly for better control over the public API
__all__ = [
    "SecurityIncident",
    "AuditLog",
    "SystemConfig",
    "LoginAttempt"
]

# Version tracking for package
__version__ = '0.0.0'
