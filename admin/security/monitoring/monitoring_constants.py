"""
Security Monitoring Constants

This module defines constants used across the security monitoring tools,
ensuring consistency in configuration, severity levels, categorization,
and output formats. These constants support event normalization, anomaly detection,
integrity monitoring, and other security monitoring functions.
"""

import os
from pathlib import Path
from typing import Dict, List, Set, Final, FrozenSet, Any, Optional

# --- Environment & Directory Constants ---
PROJECT_ROOT = Path(__file__).resolve().parents[3]
MONITORING_DIR = Path(__file__).parent.resolve()    # .../admin/security/monitoring/
CONFIG_DIR = MONITORING_DIR / "config"
BASELINE_DIR = CONFIG_DIR / "baseline"
DETECTION_RULES_DIR = CONFIG_DIR / "detection_rules"
TEMPLATES_DIR = MONITORING_DIR / "templates"
UTILS_DIR = MONITORING_DIR / "utils"

# Use environment variables with fallbacks for log and report directories
LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
REPORT_DIR = Path(os.environ.get("SECURITY_REPORT_DIR", "/var/www/reports/security"))
CACHE_DIR = Path(os.environ.get("SECURITY_CACHE_DIR", "/var/cache/cloud-platform/security"))

# --- Version Information ---
VERSION = "1.0.0"
AUTHOR = "Security Team"
DESCRIPTION = "Security monitoring tools for threat detection and incident response"

# --- Severity Levels ---
class SEVERITY:
    """Severity level constants for consistent risk categorization."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Numeric mapping (useful for sorting and comparisons)
    LEVELS = {
        INFO: 0,
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
    }

    # Display colors for reports
    COLORS = {
        INFO: "#377eb8",       # Blue
        LOW: "#4daf4a",        # Green
        MEDIUM: "#ffcc00",     # Yellow
        HIGH: "#ff7f00",       # Orange
        CRITICAL: "#e41a1c"    # Red
    }

    # Icons for HTML reports
    ICONS = {
        INFO: "info",
        LOW: "info-circle",
        MEDIUM: "exclamation",
        HIGH: "exclamation-triangle",
        CRITICAL: "exclamation-triangle-fill"
    }

# --- Event Categorization ---
class EVENT_CATEGORIES:
    """Event category constants for consistent event classification."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    DATA_ACCESS = "data_access"
    NETWORK = "network"
    RESOURCE = "resource"
    SECURITY = "security"
    SYSTEM = "system"
    UNKNOWN = "unknown"

    # List of all categories
    ALL = [AUTHENTICATION, AUTHORIZATION, CONFIGURATION, DATA_ACCESS,
           NETWORK, RESOURCE, SECURITY, SYSTEM, UNKNOWN]

# --- Event Types ---
class EVENT_TYPES:
    """Specific event type constants within categories."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"

    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGE = "permission_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Security events
    FILE_INTEGRITY_VIOLATION = "file_integrity_violation"
    MALWARE_DETECTED = "malware_detected"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE = "brute_force"

    # System events
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    CRASH = "crash"
    SERVICE_CHANGE = "service_change"

    # Resource events
    RESOURCE_CREATED = "resource_created"
    RESOURCE_MODIFIED = "resource_modified"
    RESOURCE_DELETED = "resource_deleted"
    RESOURCE_ACCESS = "resource_access"

    # Alert events
    ALERT_GENERATED = "alert_generated"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_RESOLVED = "alert_resolved"
    ALERT_DISMISSED = "alert_dismissed"

# --- Log Sources ---
class LOG_SOURCES:
    """Log source types for event normalization."""
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    CLOUD_TRAIL = "cloud_trail"
    FIREWALL = "firewall"
    IDS = "ids"
    WEB_SERVER = "web_server"
    DATABASE = "database"
    APPLICATION = "application"
    CUSTOM = "custom"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    AUTHENTICATION_SERVICE = "auth_service"
    API_GATEWAY = "api_gateway"
    LOAD_BALANCER = "load_balancer"

    # List of all sources for validation
    ALL_SOURCES = [SYSLOG, WINDOWS_EVENT, CLOUD_TRAIL, FIREWALL, IDS, WEB_SERVER,
                  DATABASE, APPLICATION, CUSTOM, CONTAINER, KUBERNETES,
                  AUTHENTICATION_SERVICE, API_GATEWAY, LOAD_BALANCER]

# --- Output Formats ---
class OUTPUT_FORMATS:
    """Output format options for reports and exported data."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"
    TEXT = "text"
    XML = "xml"
    PDF = "pdf"
    EXCEL = "excel"

    ALL = [JSON, CSV, HTML, MARKDOWN, TEXT, XML, PDF, EXCEL]

# --- Detection Rule Types ---
class RULE_TYPES:
    """Types of detection rules."""
    SIGNATURE = "signature"
    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    CORRELATION = "correlation"
    PATTERN = "pattern"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    BEHAVIOR = "behavior"
    STATISTICAL = "statistical"
    MACHINE_LEARNING = "ml"

    # Group rule types by complexity
    SIMPLE_RULES = [SIGNATURE, WHITELIST, BLACKLIST]
    INTERMEDIATE_RULES = [THRESHOLD, PATTERN, CORRELATION]
    ADVANCED_RULES = [ANOMALY, BEHAVIOR, STATISTICAL, MACHINE_LEARNING]

# --- Detection Thresholds ---
DEFAULT_DETECTION_THRESHOLDS = {
    # Authentication thresholds
    "failed_login_threshold": 5,
    "brute_force_time_window": 300,  # seconds
    "session_duration_avg": 28800,  # seconds (8 hours)
    "auth_time_deviation": 7200,  # seconds (2 hours)

    # API usage thresholds
    "api_requests_per_minute": {
        "normal_range": [10, 1000],
        "alert_threshold": 2000
    },

    # Database access thresholds
    "sensitive_table_access": {
        "per_hour": 20,
        "alert_threshold": 50
    },

    # Resource access thresholds
    "resource_creation_rate": {
        "per_hour": 10,
        "alert_threshold": 25
    },

    # File system thresholds
    "file_changes_per_hour": {
        "normal_range": [0, 30],
        "alert_threshold": 50
    },

    # Network thresholds
    "connection_error_rate": {
        "normal_range": [0.0, 0.05],
        "alert_threshold": 0.15
    }
}

# --- Anomaly Detection Sensitivity Levels ---
class DETECTION_SENSITIVITY:
    """Sensitivity levels for anomaly detection."""
    LOW = "low"          # Less sensitive (fewer alerts, higher confidence)
    MEDIUM = "medium"    # Balanced approach
    HIGH = "high"        # More sensitive (more alerts, may include false positives)

    # Numeric thresholds by sensitivity (lower = more sensitive)
    THRESHOLDS = {
        LOW: 0.9,
        MEDIUM: 0.75,
        HIGH: 0.6
    }

    # Standard deviations to consider as anomalous by sensitivity
    STD_DEVIATIONS = {
        LOW: 3.0,        # 3 standard deviations (99.7%)
        MEDIUM: 2.5,     # 2.5 standard deviations (98.8%)
        HIGH: 2.0        # 2 standard deviations (95.4%)
    }

    # Values for comparative monitoring approaches
    MULTIPLIERS = {
        LOW: 2.0,        # Threshold multiplier for low sensitivity
        MEDIUM: 1.5,     # Threshold multiplier for medium sensitivity
        HIGH: 1.2        # Threshold multiplier for high sensitivity
    }

# --- File Integrity Monitoring ---
class INTEGRITY_MONITORING:
    """File integrity monitoring constants."""
    # File categories by priority
    CRITICAL_FILES = [
        "core/security/*.py",
        "core/middleware.py",
        "core/auth.py",
        "models/security/*.py",
        "config/security.ini",
        "app.py",
        "wsgi.py"
    ]

    HIGH_PRIORITY_FILES = [
        "api/*.py",
        "models/*.py",
        "core/*.py",
        "config/*.ini",
        "config/*.json",
        "config/*.yaml"
    ]

    MEDIUM_PRIORITY_FILES = [
        "blueprints/*.py",
        "services/*.py",
        "templates/*.html",
        "static/js/*.js"
    ]

    LOW_PRIORITY_FILES = [
        "static/css/*.css",
        "static/img/*",
        "docs/*"
    ]

    # Paths to exclude from monitoring
    EXCLUDE_PATTERNS = [
        "*.pyc",
        "*.pyo",
        "__pycache__/*",
        "logs/*",
        "tmp/*",
        ".git/*",
        ".vscode/*",
        "*.log"
    ]

    # Severity by change type
    CHANGE_SEVERITY = {
        "missing": SEVERITY.HIGH,
        "modified": SEVERITY.HIGH,
        "permission": SEVERITY.CRITICAL,
        "world_writable": SEVERITY.HIGH,
        "world_writable_sensitive": SEVERITY.CRITICAL,
        "world_executable": SEVERITY.MEDIUM,
        "new_critical_file": SEVERITY.MEDIUM,
        "signature_invalid": SEVERITY.HIGH,
        "recent_change": SEVERITY.MEDIUM,
        "permission_changed": SEVERITY.MEDIUM,
        "suspicious_content": SEVERITY.HIGH
    }

    # Default hash algorithm for integrity checking
    DEFAULT_HASH_ALGORITHM = "sha256"
    SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

    # Check frequencies
    CHECK_INTERVALS = {
        "critical": 3600,        # 1 hour
        "high": 86400,           # 24 hours
        "medium": 604800,        # 7 days
        "low": 2592000           # 30 days
    }

    # Override flags
    AUTO_UPDATE_BASELINE = False
    VERIFY_SIGNATURES = True
    ALERT_ON_CHANGE = True

# --- Event Normalization ---
class FIELD_MAPPINGS:
    """Field mappings for event normalization by source type."""
    SYSLOG = {
        "timestamp": "timestamp",
        "hostname": "host",
        "severity": "priority",
        "facility": "facility",
        "message": "content"
    }

    WINDOWS_EVENT = {
        "timestamp": "TimeCreated",
        "hostname": "Computer",
        "severity": "Level",
        "event_id": "EventID",
        "message": "Message"
    }

    CLOUD_TRAIL = {
        "timestamp": "eventTime",
        "user": "userIdentity.userName",
        "source_ip": "sourceIPAddress",
        "event_name": "eventName",
        "event_type": "eventType"
    }

    FIREWALL = {
        "timestamp": "time",
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "source_port": "src_port",
        "destination_port": "dst_port",
        "action": "action"
    }

    IDS = {
        "timestamp": "timestamp",
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "signature_id": "sig_id",
        "signature_name": "sig_name",
        "severity": "severity"
    }

    KUBERNETES = {
        "timestamp": "ts",
        "namespace": "kubernetes.namespace",
        "pod": "kubernetes.pod.name",
        "container": "kubernetes.container.name",
        "message": "log"
    }

    API_GATEWAY = {
        "timestamp": "timestamp",
        "request_id": "requestId",
        "method": "httpMethod",
        "path": "resource",
        "client_ip": "identity.sourceIp",
        "status": "status",
        "latency": "responseLatency"
    }

# --- Timestamp Formats ---
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",           # ISO8601 with microseconds
    "%Y-%m-%dT%H:%M:%SZ",              # ISO8601
    "%Y-%m-%d %H:%M:%S.%f",            # Database timestamp with microseconds
    "%Y-%m-%d %H:%M:%S",               # Standard datetime
    "%b %d %H:%M:%S",                  # Syslog (without year)
    "%Y/%m/%d %H:%M:%S",               # Date with slashes
    "%d/%b/%Y:%H:%M:%S %z"             # Apache/Nginx log format
]

# --- Threat Intelligence ---
class THREAT_INTEL:
    """Threat intelligence constants."""
    # IOC (Indicator of Compromise) types
    IOC_IP = "ip"
    IOC_DOMAIN = "domain"
    IOC_URL = "url"
    IOC_FILE_HASH = "file_hash"
    IOC_EMAIL = "email"
    IOC_REGEX = "regex"

    # All IOC types
    IOC_TYPES = [IOC_IP, IOC_DOMAIN, IOC_URL, IOC_FILE_HASH, IOC_EMAIL, IOC_REGEX]

    # Match confidence levels
    CONFIDENCE_HIGH = "high"       # 90-100% confidence
    CONFIDENCE_MEDIUM = "medium"   # 70-89% confidence
    CONFIDENCE_LOW = "low"         # 50-69% confidence

    # Match thresholds
    MATCH_THRESHOLD = 0.8          # Default threshold for considering a match
    MIN_MATCH_THRESHOLD = 0.5      # Minimum threshold for fuzzy matches

    # Cache settings
    CACHE_TTL = 3600              # Cache expiry in seconds (1 hour)
    MAX_CACHE_ENTRIES = 10000     # Maximum entries in indicator cache

    # Feed update settings
    UPDATE_INTERVAL = 86400        # Default update interval in seconds (24 hours)
    RETENTION_DAYS = 90            # Number of days to retain threat intel data

    # IOC validation rules
    MIN_DOMAIN_LENGTH = 4          # Minimum length for valid domain
    MIN_IP_MATCHES = 3             # Minimum number of octets to match for partial IP match
    MIN_HASH_LENGTH = 32           # Minimum length for file hash (MD5)

# --- Alert Formatting ---
class ALERT_FORMAT:
    """Alert formatting constants."""
    # Severity to color mapping
    SEVERITY_COLORS = {
        SEVERITY.INFO: "#377eb8",      # Blue
        SEVERITY.LOW: "#4daf4a",       # Green
        SEVERITY.MEDIUM: "#ffcc00",    # Yellow
        SEVERITY.HIGH: "#ff7f00",      # Orange
        SEVERITY.CRITICAL: "#e41a1c",  # Red
        "unknown": "#999999"           # Gray
    }

    # Severity to icon mapping
    SEVERITY_ICONS = {
        SEVERITY.INFO: "info",
        SEVERITY.LOW: "info-circle",
        SEVERITY.MEDIUM: "exclamation",
        SEVERITY.HIGH: "exclamation-triangle",
        SEVERITY.CRITICAL: "exclamation-triangle-fill",
        "unknown": "question-circle"
    }

    # Redaction settings
    REDACT_FIELDS = [
        "password", "token", "api_key", "secret", "credential", "private",
        "auth", "access_key", "key", "cert", "signature"
    ]

    PARTIAL_REDACT_FIELDS = [
        "ip", "email", "address", "phone", "user", "account"
    ]

    # Default date format
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S %Z"  # 2023-06-15 14:30:45 UTC

# --- Dashboard Configuration ---
class DASHBOARD_CONFIG:
    """Security dashboard display configuration."""
    DEFAULT_TIMEFRAME = 24                     # Default timeframe in hours
    MAX_EVENTS = 100                           # Maximum events to display
    REFRESH_INTERVAL = 300                     # Automatic refresh interval in seconds
    INCLUDE_RAW_DATA = False                   # Whether to include raw data in dashboard
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"          # Date format for display
    DEFAULT_TEMPLATE = "dashboard.html"        # Default dashboard template
    DEFAULT_THEME = "light"                    # Default theme (light or dark)
    AUTO_REFRESH = True                        # Enable auto-refresh by default

    # Chart colors
    CHART_COLORS = [
        "#4285F4", "#EA4335", "#FBBC05", "#34A853",  # Google colors
        "#3498DB", "#E74C3C", "#2ECC71", "#F39C12",  # Flat UI colors
        "#9C27B0", "#673AB7", "#3F51B5", "#00BCD4"   # Material colors
    ]

    # Default widgets
    DEFAULT_WIDGETS = [
        "severity_summary",
        "recent_alerts",
        "category_distribution",
        "timeline_chart",
        "top_sources",
        "system_health"
    ]

# --- Log Parser Configuration ---
class LOG_PARSER_CONFIG:
    """Log parser configuration constants."""
    # Maximum log file size to process in one go
    MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB

    # Chunk size for processing large logs
    CHUNK_SIZE = 10000  # process 10k lines at a time

    # Maximum number of parsing errors before failing
    MAX_PARSE_ERRORS = 100

    # Log formats known to the parser
    FORMATS = {
        "syslog": r'<(\d+)>(\w+ \d+ \d+:\d+:\d+) (\S+) (\S+)(|\[\d+\]): (.*)',
        "json": None,  # No regex pattern for JSON
        "cef": r'CEF:\d+\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',
        "leef": r'LEEF:(\d+\.\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',
        "apache": r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-)'
    }

    # Default fields for logs that can't be parsed
    DEFAULT_FIELDS = ["timestamp", "source", "level", "message"]

# --- System Components ---
MONITORING_COMPONENTS = {
    "anomaly_detector": "Behavioral anomaly detection system",
    "integrity_monitor": "Enhanced file integrity monitoring system",
    "privilege_audit": "Administrative privilege monitoring",
    "security_dashboard": "Administrative security dashboard generator",
    "security_event_correlator": "Security event correlation engine",
    "threat_intelligence": "Threat intelligence integration tool",
    "utils": "Security monitoring utility functions"
}

# --- Public API ---
__all__ = [
    # Directory constants
    "PROJECT_ROOT", "MONITORING_DIR", "CONFIG_DIR", "BASELINE_DIR",
    "DETECTION_RULES_DIR", "TEMPLATES_DIR", "UTILS_DIR", "LOG_DIR",
    "REPORT_DIR", "CACHE_DIR",

    # Version information
    "VERSION", "AUTHOR", "DESCRIPTION",

    # Classes
    "SEVERITY", "EVENT_CATEGORIES", "EVENT_TYPES", "LOG_SOURCES",
    "OUTPUT_FORMATS", "RULE_TYPES", "DETECTION_SENSITIVITY",
    "INTEGRITY_MONITORING", "FIELD_MAPPINGS", "THREAT_INTEL",
    "DASHBOARD_CONFIG", "ALERT_FORMAT", "LOG_PARSER_CONFIG",

    # Global constants
    "DEFAULT_DETECTION_THRESHOLDS", "TIMESTAMP_FORMATS",
    "MONITORING_COMPONENTS"
]
