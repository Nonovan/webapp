"""
Security Incident Constants

This module defines common constants used throughout the incident response toolkit
and incident management systems. It follows the NIST SP 800-61 incident handling
framework and provides standard definitions for incident status, phases, severity,
and types.

These constants ensure consistent categorization and status tracking across all
incident response activities and maintain a single source of truth for incident
metadata.
"""

from typing import Dict, List, Any

# ======= Status Constants =======

class IncidentStatus:
    """Constants defining the possible status values for a security incident."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    CLOSED = "closed"
    MERGED = "merged"

    # All valid statuses
    VALID_STATUSES = [OPEN, INVESTIGATING, CONTAINED, ERADICATED,
                      RECOVERING, RESOLVED, CLOSED, MERGED]

    # Status categories
    ACTIVE_STATUSES = [OPEN, INVESTIGATING, CONTAINED, ERADICATED, RECOVERING]
    TERMINAL_STATUSES = [RESOLVED, CLOSED, MERGED]


# ======= Phase Constants =======

class IncidentPhase:
    """Constants defining the phases of the security incident response lifecycle."""
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"

    # All valid phases
    VALID_PHASES = [IDENTIFICATION, CONTAINMENT, ERADICATION, RECOVERY, LESSONS_LEARNED]


# ======= Severity Constants =======

class IncidentSeverity:
    """Constants defining the severity levels for security incidents."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    # All valid severity levels
    VALID_SEVERITIES = [CRITICAL, HIGH, MEDIUM, LOW]

    # SLA hours by severity
    SLA_HOURS = {
        CRITICAL: 1,    # 1 hour
        HIGH: 4,        # 4 hours
        MEDIUM: 24,     # 24 hours
        LOW: 72         # 72 hours
    }


# ======= Incident Type Constants =======

class IncidentType:
    """Constants defining the types of security incidents."""
    MALWARE = "malware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    WEB_APPLICATION_ATTACK = "web_application_attack"
    ACCOUNT_COMPROMISE = "account_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"

    # All valid incident types
    VALID_TYPES = [
        MALWARE, DATA_BREACH, UNAUTHORIZED_ACCESS, DENIAL_OF_SERVICE,
        WEB_APPLICATION_ATTACK, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION,
        INSIDER_THREAT, RANSOMWARE, PHISHING
    ]

    # Categorization of incident types
    CATEGORIES = {
        "malicious_code": [MALWARE, RANSOMWARE],
        "unauthorized_access": [UNAUTHORIZED_ACCESS, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION],
        "availability": [DENIAL_OF_SERVICE],
        "web_attacks": [WEB_APPLICATION_ATTACK],
        "data_security": [DATA_BREACH],
        "internal_threats": [INSIDER_THREAT],
        "social_engineering": [PHISHING]
    }


# ======= Phase-Status Mapping =======

# Mapping between incident phases and allowed statuses
PHASE_STATUS_MAPPING: Dict[str, List[str]] = {
    IncidentPhase.IDENTIFICATION: [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING],
    IncidentPhase.CONTAINMENT: [IncidentStatus.CONTAINED, IncidentStatus.INVESTIGATING],
    IncidentPhase.ERADICATION: [IncidentStatus.ERADICATED, IncidentStatus.CONTAINED],
    IncidentPhase.RECOVERY: [IncidentStatus.RECOVERING, IncidentStatus.RESOLVED],
    IncidentPhase.LESSONS_LEARNED: [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]
}

# Status progression (allowed transitions)
STATUS_TRANSITIONS: Dict[str, List[str]] = {
    IncidentStatus.OPEN: [IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.INVESTIGATING: [IncidentStatus.CONTAINED, IncidentStatus.OPEN, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.CONTAINED: [IncidentStatus.ERADICATED, IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.ERADICATED: [IncidentStatus.RECOVERING, IncidentStatus.CONTAINED, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.RECOVERING: [IncidentStatus.RESOLVED, IncidentStatus.ERADICATED, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.RESOLVED: [IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING, IncidentStatus.MERGED],
    IncidentStatus.CLOSED: [IncidentStatus.INVESTIGATING],  # Can be reopened if needed
    IncidentStatus.MERGED: []  # Terminal state, cannot transition out
}

# Module exports
__all__ = [
    'IncidentStatus',
    'IncidentPhase',
    'IncidentSeverity',
    'IncidentType',
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS'
]
