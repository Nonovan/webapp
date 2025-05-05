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

from typing import Dict, List, Any, Set

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

    # Status display names (for UI presentation)
    DISPLAY_NAMES = {
        OPEN: "Open",
        INVESTIGATING: "Under Investigation",
        CONTAINED: "Contained",
        ERADICATED: "Eradicated",
        RECOVERING: "Recovering",
        RESOLVED: "Resolved",
        CLOSED: "Closed",
        MERGED: "Merged"
    }


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

    # Phase display names (for UI presentation)
    DISPLAY_NAMES = {
        IDENTIFICATION: "Identification & Analysis",
        CONTAINMENT: "Containment",
        ERADICATION: "Eradication",
        RECOVERY: "Recovery",
        LESSONS_LEARNED: "Post-Incident Review"
    }

    # Phase descriptions
    DESCRIPTIONS = {
        IDENTIFICATION: "Identifying and analyzing the incident scope and impact",
        CONTAINMENT: "Limiting the damage and isolating affected systems",
        ERADICATION: "Removing the threat from the environment",
        RECOVERY: "Restoring systems to normal operation",
        LESSONS_LEARNED: "Reviewing the incident and improving processes"
    }


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

    # Severity display names (for UI presentation)
    DISPLAY_NAMES = {
        CRITICAL: "Critical",
        HIGH: "High",
        MEDIUM: "Medium",
        LOW: "Low"
    }

    # Severity descriptions
    DESCRIPTIONS = {
        CRITICAL: "Severe business impact requiring immediate response",
        HIGH: "Significant business impact requiring urgent response",
        MEDIUM: "Moderate business impact requiring timely response",
        LOW: "Minor business impact requiring standard response"
    }

    # Escalation thresholds - time before raising to the next severity level
    ESCALATION_THRESHOLDS = {
        LOW: 48,      # 48 hours without resolution escalates from Low to Medium
        MEDIUM: 12,   # 12 hours without resolution escalates from Medium to High
        HIGH: 2       # 2 hours without resolution escalates from High to Critical
    }


# ======= Incident Type Constants =======

class IncidentType:
    """Constants defining the types of security incidents."""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    WEB_APPLICATION_ATTACK = "web_application_attack"
    ACCOUNT_COMPROMISE = "account_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    SYSTEM_COMPROMISE = "system_compromise"
    NETWORK_ANOMALY = "network_anomaly"
    POLICY_VIOLATION = "policy_violation"
    CONFIGURATION_ERROR = "configuration_error"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

    # All valid incident types
    VALID_TYPES = [
        MALWARE, RANSOMWARE, DATA_BREACH, UNAUTHORIZED_ACCESS, DENIAL_OF_SERVICE,
        WEB_APPLICATION_ATTACK, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION,
        INSIDER_THREAT, PHISHING, SYSTEM_COMPROMISE, NETWORK_ANOMALY,
        POLICY_VIOLATION, CONFIGURATION_ERROR, SUSPICIOUS_ACTIVITY
    ]

    # Categorization of incident types
    CATEGORIES = {
        "malicious_code": [MALWARE, RANSOMWARE],
        "unauthorized_access": [UNAUTHORIZED_ACCESS, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION],
        "availability": [DENIAL_OF_SERVICE],
        "web_attacks": [WEB_APPLICATION_ATTACK],
        "data_security": [DATA_BREACH],
        "internal_threats": [INSIDER_THREAT, POLICY_VIOLATION],
        "social_engineering": [PHISHING],
        "system_issues": [SYSTEM_COMPROMISE, CONFIGURATION_ERROR],
        "network_issues": [NETWORK_ANOMALY],
        "other": [SUSPICIOUS_ACTIVITY]
    }

    # Type display names (for UI presentation)
    DISPLAY_NAMES = {
        MALWARE: "Malware",
        RANSOMWARE: "Ransomware",
        DATA_BREACH: "Data Breach",
        UNAUTHORIZED_ACCESS: "Unauthorized Access",
        DENIAL_OF_SERVICE: "Denial of Service",
        WEB_APPLICATION_ATTACK: "Web Application Attack",
        ACCOUNT_COMPROMISE: "Account Compromise",
        PRIVILEGE_ESCALATION: "Privilege Escalation",
        INSIDER_THREAT: "Insider Threat",
        PHISHING: "Phishing",
        SYSTEM_COMPROMISE: "System Compromise",
        NETWORK_ANOMALY: "Network Anomaly",
        POLICY_VIOLATION: "Policy Violation",
        CONFIGURATION_ERROR: "Configuration Error",
        SUSPICIOUS_ACTIVITY: "Suspicious Activity"
    }


# ======= Source Constants =======

class IncidentSource:
    """Constants defining the source of incident detection."""
    SYSTEM = "system"
    USER_REPORT = "user_report"
    SECURITY_SCAN = "security_scan"
    ALERT = "alert"
    MONITORING = "monitoring"
    SIEM = "siem"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_SCAN = "vulnerability_scan"

    # All valid sources
    VALID_SOURCES = [
        SYSTEM, USER_REPORT, SECURITY_SCAN, ALERT,
        MONITORING, SIEM, THREAT_INTELLIGENCE, VULNERABILITY_SCAN
    ]

    # Source display names (for UI presentation)
    DISPLAY_NAMES = {
        SYSTEM: "System Detection",
        USER_REPORT: "User Report",
        SECURITY_SCAN: "Security Scan",
        ALERT: "Security Alert",
        MONITORING: "System Monitoring",
        SIEM: "SIEM Detection",
        THREAT_INTELLIGENCE: "Threat Intelligence",
        VULNERABILITY_SCAN: "Vulnerability Scan"
    }


# ======= Evidence Type Constants =======

class EvidenceType:
    """Constants defining types of evidence collected during incident response."""
    LOG_FILE = "log_file"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    NETWORK_CAPTURE = "network_capture"
    SCREENSHOT = "screenshot"
    CONFIGURATION = "configuration"
    MALWARE_SAMPLE = "malware_sample"
    SYSTEM_STATE = "system_state"
    USER_INTERVIEW = "user_interview"
    EMAIL = "email"

    # All valid evidence types
    VALID_TYPES = [
        LOG_FILE, MEMORY_DUMP, DISK_IMAGE, NETWORK_CAPTURE,
        SCREENSHOT, CONFIGURATION, MALWARE_SAMPLE, SYSTEM_STATE,
        USER_INTERVIEW, EMAIL
    ]

    # Evidence display names
    DISPLAY_NAMES = {
        LOG_FILE: "Log File",
        MEMORY_DUMP: "Memory Dump",
        DISK_IMAGE: "Disk Image",
        NETWORK_CAPTURE: "Network Capture",
        SCREENSHOT: "Screenshot",
        CONFIGURATION: "Configuration File",
        MALWARE_SAMPLE: "Malware Sample",
        SYSTEM_STATE: "System State",
        USER_INTERVIEW: "User Interview",
        EMAIL: "Email"
    }


# ======= Action Constants =======

class ActionType:
    """Constants defining action types taken during incident response."""
    CONTAINMENT = "containment"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    NOTIFICATION = "notification"
    MITIGATION = "mitigation"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    DOCUMENTATION = "documentation"

    # All valid action types
    VALID_TYPES = [
        CONTAINMENT, EVIDENCE_COLLECTION, ANALYSIS, NOTIFICATION,
        MITIGATION, ERADICATION, RECOVERY, DOCUMENTATION
    ]


# ======= Relationship Mappings =======

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

# Required actions per phase
PHASE_REQUIRED_ACTIONS: Dict[str, List[str]] = {
    IncidentPhase.IDENTIFICATION: [ActionType.EVIDENCE_COLLECTION, ActionType.ANALYSIS, ActionType.NOTIFICATION],
    IncidentPhase.CONTAINMENT: [ActionType.CONTAINMENT, ActionType.EVIDENCE_COLLECTION],
    IncidentPhase.ERADICATION: [ActionType.ERADICATION, ActionType.MITIGATION],
    IncidentPhase.RECOVERY: [ActionType.RECOVERY],
    IncidentPhase.LESSONS_LEARNED: [ActionType.DOCUMENTATION]
}

# Recommended evidence by incident type
INCIDENT_TYPE_RECOMMENDED_EVIDENCE: Dict[str, List[str]] = {
    IncidentType.MALWARE: [EvidenceType.MEMORY_DUMP, EvidenceType.LOG_FILE, EvidenceType.MALWARE_SAMPLE],
    IncidentType.RANSOMWARE: [EvidenceType.DISK_IMAGE, EvidenceType.MEMORY_DUMP, EvidenceType.MALWARE_SAMPLE],
    IncidentType.DATA_BREACH: [EvidenceType.LOG_FILE, EvidenceType.NETWORK_CAPTURE],
    IncidentType.UNAUTHORIZED_ACCESS: [EvidenceType.LOG_FILE, EvidenceType.SYSTEM_STATE],
    IncidentType.DENIAL_OF_SERVICE: [EvidenceType.NETWORK_CAPTURE, EvidenceType.LOG_FILE],
    # Additional mapping can be added for other incident types
}

# Required notifications by severity
SEVERITY_REQUIRED_NOTIFICATIONS: Dict[str, Set[str]] = {
    IncidentSeverity.CRITICAL: {"ir-manager", "ciso", "legal", "executive-team"},
    IncidentSeverity.HIGH: {"ir-manager", "ciso", "security-team"},
    IncidentSeverity.MEDIUM: {"ir-manager", "security-team"},
    IncidentSeverity.LOW: {"security-team"}
}

# Module exports
__all__ = [
    # Classes
    'IncidentStatus',
    'IncidentPhase',
    'IncidentSeverity',
    'IncidentType',
    'IncidentSource',
    'EvidenceType',
    'ActionType',

    # Mappings
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS',
    'PHASE_REQUIRED_ACTIONS',
    'INCIDENT_TYPE_RECOMMENDED_EVIDENCE',
    'SEVERITY_REQUIRED_NOTIFICATIONS'
]
