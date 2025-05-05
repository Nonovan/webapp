"""
Incident Response Constants

This module defines constants and default values used throughout the Incident Response Toolkit.
Centralizing these values ensures consistency across the toolkit and simplifies configuration
management.

The constants defined here include:
- Default file paths and directories
- Security permissions
- Evidence collection settings
- Timeouts and thresholds
- Status and severity values
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Any, FrozenSet

# Initialize module logger
logger = logging.getLogger(__name__)

# ---------- File System Paths and Permissions ----------

# Base directories
DEFAULT_EVIDENCE_DIR = "/secure/evidence"
DEFAULT_LOG_DIR = "/var/log/incident-response"
DEFAULT_TEMP_DIR = "/tmp/ir-toolkit"
DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent / "config"
DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# File permissions (UNIX-style)
SECURE_DIR_PERMS = 0o700  # rwx------ (owner only)
SECURE_FILE_PERMS = 0o600  # rw------- (owner only)
READ_ONLY_FILE_PERMS = 0o400  # r-------- (owner read only)
EVIDENCE_DIR_PERMS = 0o700  # rwx------ (owner only)
EVIDENCE_FILE_PERMS = 0o400  # r-------- (owner read only)
LOG_FILE_PERMS = 0o600  # rw------- (owner only)

# ---------- Evidence Collection Settings ----------

# Evidence file formats
EVIDENCE_FORMATS = {
    "memory": ["raw", "lime", "aff4"],
    "disk": ["dd", "raw", "e01", "aff4"],
    "logs": ["txt", "json", "evtx", "csv"],
    "network": ["pcap", "pcapng"]
}

# Hash algorithms for evidence verification
HASH_ALGORITHMS = ["sha256", "sha1", "md5"]
PRIMARY_HASH_ALGORITHM = "sha256"

# Evidence metadata fields
REQUIRED_METADATA_FIELDS = [
    "case_id",
    "evidence_id",
    "examiner",
    "acquisition_date",
    "evidence_type"
]

OPTIONAL_METADATA_FIELDS = [
    "description",
    "source_system",
    "acquisition_method",
    "acquisition_tool",
    "acquisition_tool_version",
    "operating_system",
    "timezone",
    "notes"
]

# Default evidence retention period (days)
DEFAULT_EVIDENCE_RETENTION_DAYS = 180

# ---------- Timeouts and Thresholds ----------

# Operation timeouts (seconds)
DEFAULT_COMMAND_TIMEOUT = 300  # 5 minutes
MEMORY_ACQUISITION_TIMEOUT = 1800  # 30 minutes
NETWORK_ACQUISITION_TIMEOUT = 600  # 10 minutes
VOLATILE_DATA_TIMEOUT = 300  # 5 minutes
ISOLATION_TIMEOUT = 120  # 2 minutes
API_REQUEST_TIMEOUT = 30  # 30 seconds
LOCKFILE_TIMEOUT = 30  # 30 seconds

# Retry settings
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# Size thresholds
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4GB max file size
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks for file operations
MAX_MEMORY_SIZE = 64 * 1024 * 1024 * 1024  # 64GB max memory size
MAX_LOG_SIZE = 500 * 1024 * 1024  # 500MB max log size
MAX_PCAP_SIZE = 2 * 1024 * 1024 * 1024  # 2GB max pcap file size

# ---------- Status and Phase Mappings ----------

# Mapping between incident phases and allowed statuses
PHASE_STATUS_MAPPING: Dict[str, List[str]] = {
    "identification": ["open", "investigating"],
    "containment": ["investigating", "contained"],
    "eradication": ["contained", "eradicated"],
    "recovery": ["eradicated", "recovering", "resolved"],
    "lessons_learned": ["resolved", "closed"]
}

# Status progression (allowed transitions)
STATUS_TRANSITIONS: Dict[str, List[str]] = {
    "open": ["investigating", "closed", "merged"],
    "investigating": ["contained", "open", "closed", "merged"],
    "contained": ["eradicated", "investigating", "closed", "merged"],
    "eradicated": ["recovering", "contained", "closed", "merged"],
    "recovering": ["resolved", "eradicated", "closed", "merged"],
    "resolved": ["closed", "open", "merged"],
    "closed": ["open"],
    "merged": []  # Terminal state, cannot transition out
}

# Severity levels with numeric values for comparison
SEVERITY_LEVELS: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0
}

# Incident types with categories
INCIDENT_CATEGORIES: Dict[str, List[str]] = {
    "malicious_code": [
        "malware",
        "ransomware",
        "virus",
        "trojan",
        "worm"
    ],
    "unauthorized_access": [
        "unauthorized_access",
        "account_compromise",
        "credential_theft",
        "privilege_escalation"
    ],
    "data_breach": [
        "data_breach",
        "data_theft",
        "data_leak",
        "unintended_disclosure"
    ],
    "availability": [
        "denial_of_service",
        "ddos",
        "sabotage",
        "resource_depletion"
    ],
    "web_attacks": [
        "web_application_attack",
        "sql_injection",
        "xss",
        "csrf",
        "api_attack"
    ],
    "social_engineering": [
        "phishing",
        "spear_phishing",
        "business_email_compromise",
        "vishing",
        "smishing"
    ],
    "other": [
        "insider_threat",
        "physical_security",
        "misuse",
        "unknown"
    ]
}

# ---------- Response Templates ----------

# Default notification templates
NOTIFICATION_TEMPLATES = {
    "incident_created": "templates/notifications/incident_created.txt",
    "status_changed": "templates/notifications/status_changed.txt",
    "evidence_collected": "templates/notifications/evidence_collected.txt",
    "containment_action": "templates/notifications/containment_action.txt",
    "incident_closed": "templates/notifications/incident_closed.txt"
}

# Default document templates
DOCUMENT_TEMPLATES = {
    "incident_report": "templates/reports/incident_report.md",
    "evidence_log": "templates/evidence/evidence_log.md",
    "chain_of_custody": "templates/evidence/chain_of_custody.md",
    "communication_plan": "templates/coordination/communication_plan.md",
    "remediation_plan": "templates/recovery/remediation_plan.md",
    "executive_briefing": "templates/reports/executive_briefing.md"
}

# ---------- Logs & Audit Settings ----------

# Log levels with numeric values for comparison
LOG_LEVELS: Dict[str, int] = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
    "critical": 50
}

DEFAULT_LOG_LEVEL = "info"
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_AUDIT_LOG = DEFAULT_LOG_DIR + "/ir_audit.log"

# Maximum history items to track
MAX_HISTORY_ITEMS = 100  # Maximum number of history items to keep per incident
MAX_NOTES_ITEMS = 200    # Maximum number of notes to keep per incident
MAX_CACHED_INCIDENTS = 50  # Maximum number of incidents to keep in memory cache

# ---------- File Patterns ----------

# Patterns for evidence files
EVIDENCE_FILE_PATTERNS: Dict[str, List[str]] = {
    "memory_dumps": ["*.raw", "*.lime", "*.mem", "*.dmp", "*.dump", "*.img"],
    "disk_images": ["*.dd", "*.raw", "*.img", "*.e01", "*.aff", "*.vhd", "*.vmdk"],
    "network_captures": ["*.pcap", "*.pcapng", "*.cap"],
    "logs": ["*.log", "*.evt", "*.evtx", "*_log.txt"],
    "registry": ["NTUSER.DAT", "*.hive", "*.reg"],
    "volatile_data": ["*proc*.txt", "*net*.txt", "*conn*.txt", "*svc*.txt"],
    "filesystem_metadata": ["*timeline*.csv", "*mactime*.txt", "*fls*.txt"],
    "user_artifacts": ["*browser*", "*history*", "*cache*", "*cookie*"]
}

# Patterns for critical system files to protect
CRITICAL_SYSTEM_PATTERNS: List[str] = [
    "/bin/*", "/sbin/*", "/usr/bin/*", "/usr/sbin/*",
    "/boot/*", "/etc/passwd", "/etc/shadow", "/etc/group",
    "/etc/hosts", "/etc/resolv.conf", "/etc/ssh/*key*",
    "C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*",
    "C:\\Program Files\\*", "C:\\Program Files (x86)\\*"
]

# File extensions that should be write-protected
EXECUTABLE_EXTENSIONS: FrozenSet[str] = frozenset([
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".msi", ".sh", ".py", ".rb", ".jar", ".war", ".php"
])

# Load configuration-specific constants if available
try:
    config_file = DEFAULT_CONFIG_DIR / "response_config.json"
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)

        # Override defaults with configuration values
        if "evidence_collection" in config:
            evidence_config = config.get("evidence_collection", {})
            if "base_dir" in evidence_config:
                DEFAULT_EVIDENCE_DIR = evidence_config.get("base_dir")
            if "retention_days" in evidence_config:
                DEFAULT_EVIDENCE_RETENTION_DAYS = evidence_config.get("retention_days")

        if "logging" in config:
            log_config = config.get("logging", {})
            if "level" in log_config:
                DEFAULT_LOG_LEVEL = log_config.get("level")
            if "file" in log_config:
                DEFAULT_AUDIT_LOG = log_config.get("file")

except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError) as e:
    logger.warning(f"Failed to load configuration file: {e}")
    # Continue with default values

# ---------- Regulations and Compliance ----------

# Mapping between regulatory frameworks and mandatory fields
REGULATORY_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "gdpr": {
        "max_notification_hours": 72,
        "required_fields": [
            "nature_of_breach",
            "categories_of_data",
            "approximate_affected_count",
            "contact_person",
            "likely_consequences",
            "measures_taken"
        ],
        "documentation_required": True
    },
    "hipaa": {
        "max_notification_hours": 60,
        "required_fields": [
            "protected_health_information_involved",
            "unauthorized_persons",
            "acquisition_or_access_details",
            "risk_mitigation_steps"
        ],
        "documentation_required": True
    },
    "pci_dss": {
        "max_notification_hours": 24,
        "required_fields": [
            "cardholder_data_compromised",
            "accounts_affected",
            "containment_status",
            "forensic_investigator"
        ],
        "documentation_required": True
    }
}

# Module exports - define what should be accessible when importing
__all__ = [
    # File system paths
    'DEFAULT_EVIDENCE_DIR',
    'DEFAULT_LOG_DIR',
    'DEFAULT_TEMP_DIR',
    'DEFAULT_CONFIG_DIR',
    'DEFAULT_TEMPLATES_DIR',

    # Permissions
    'SECURE_DIR_PERMS',
    'SECURE_FILE_PERMS',
    'READ_ONLY_FILE_PERMS',
    'EVIDENCE_DIR_PERMS',
    'EVIDENCE_FILE_PERMS',
    'LOG_FILE_PERMS',

    # Evidence collection
    'EVIDENCE_FORMATS',
    'HASH_ALGORITHMS',
    'PRIMARY_HASH_ALGORITHM',
    'REQUIRED_METADATA_FIELDS',
    'OPTIONAL_METADATA_FIELDS',
    'DEFAULT_EVIDENCE_RETENTION_DAYS',

    # Timeouts and thresholds
    'DEFAULT_COMMAND_TIMEOUT',
    'MEMORY_ACQUISITION_TIMEOUT',
    'NETWORK_ACQUISITION_TIMEOUT',
    'VOLATILE_DATA_TIMEOUT',
    'ISOLATION_TIMEOUT',
    'API_REQUEST_TIMEOUT',
    'LOCKFILE_TIMEOUT',
    'MAX_RETRIES',
    'RETRY_DELAY',
    'MAX_FILE_SIZE',
    'CHUNK_SIZE',
    'MAX_MEMORY_SIZE',
    'MAX_LOG_SIZE',
    'MAX_PCAP_SIZE',

    # Status and phase
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS',
    'SEVERITY_LEVELS',
    'INCIDENT_CATEGORIES',

    # Templates
    'NOTIFICATION_TEMPLATES',
    'DOCUMENT_TEMPLATES',

    # Logs and audit
    'LOG_LEVELS',
    'DEFAULT_LOG_LEVEL',
    'DEFAULT_LOG_FORMAT',
    'DEFAULT_AUDIT_LOG',
    'MAX_HISTORY_ITEMS',
    'MAX_NOTES_ITEMS',
    'MAX_CACHED_INCIDENTS',

    # File patterns
    'EVIDENCE_FILE_PATTERNS',
    'CRITICAL_SYSTEM_PATTERNS',
    'EXECUTABLE_EXTENSIONS',

    # Regulatory
    'REGULATORY_REQUIREMENTS'
]
