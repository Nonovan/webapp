"""
Service Constants for Cloud Infrastructure Platform.

This module defines constants, configuration defaults, and enumerations used
across the service layer. Centralizing these values ensures consistency
throughout the application and simplifies future updates.
"""

import os
from enum import Enum, auto
from typing import Dict, Any, List, Optional, Set, FrozenSet, Tuple
from pathlib import Path

# ============================================================================
# Service Versioning
# ============================================================================

__version__ = '0.1.1'
__author__ = 'Cloud Infrastructure Platform Team'
__description__ = 'Service Layer for Cloud Infrastructure Platform'

# ============================================================================
# Service Status Codes
# ============================================================================

class ServiceStatus(Enum):
    """Status values for service operations."""
    SUCCESS = auto()
    ERROR = auto()
    WARNING = auto()
    PENDING = auto()
    UNAVAILABLE = auto()
    UNAUTHORIZED = auto()
    FORBIDDEN = auto()
    NOT_FOUND = auto()
    TIMEOUT = auto()
    CONFLICT = auto()
    TOO_MANY_REQUESTS = auto()
    RESOURCE_EXHAUSTED = auto()

# ============================================================================
# Notification Constants
# ============================================================================

# Notification channels
CHANNEL_IN_APP = 'in_app'
CHANNEL_EMAIL = 'email'
CHANNEL_SMS = 'sms'
CHANNEL_WEBHOOK = 'webhook'

# Notification categories
NOTIFICATION_CATEGORY_SYSTEM = 'system'          # System-level notifications
NOTIFICATION_CATEGORY_SECURITY = 'security'      # Security-related notifications
NOTIFICATION_CATEGORY_USER = 'user'             # User-specific notifications
NOTIFICATION_CATEGORY_ADMIN = 'admin'           # Administrative notifications
NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance' # Maintenance notifications
NOTIFICATION_CATEGORY_MONITORING = 'monitoring'  # System monitoring notifications
NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'  # Compliance-related notifications
NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'    # File integrity notifications
NOTIFICATION_CATEGORY_AUDIT = 'audit'           # Audit-related notifications
NOTIFICATION_CATEGORY_SCAN = 'scan'             # Security scan notifications
NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'  # Vulnerability notifications
NOTIFICATION_CATEGORY_INCIDENT = 'incident'     # Security incident notifications

# Notification priorities
class NotificationPriority(Enum):
    """Priority levels for notifications."""
    LOW = 10
    NORMAL = 20
    HIGH = 30
    URGENT = 40
    CRITICAL = 50

# Notification preferences - matches NotificationPreference model
NOTIFICATION_PRIORITY_THRESHOLD_LOW = 'low'
NOTIFICATION_PRIORITY_THRESHOLD_MEDIUM = 'medium'
NOTIFICATION_PRIORITY_THRESHOLD_HIGH = 'high'
NOTIFICATION_PRIORITY_THRESHOLD_CRITICAL = 'critical'

NOTIFICATION_VALID_PRIORITY_THRESHOLDS = [
    NOTIFICATION_PRIORITY_THRESHOLD_LOW,
    NOTIFICATION_PRIORITY_THRESHOLD_MEDIUM,
    NOTIFICATION_PRIORITY_THRESHOLD_HIGH,
    NOTIFICATION_PRIORITY_THRESHOLD_CRITICAL
]

# Communication preferences - matches CommunicationPreference model
COMMUNICATION_DIGEST_FREQUENCY_DAILY = 'daily'
COMMUNICATION_DIGEST_FREQUENCY_WEEKLY = 'weekly'
COMMUNICATION_DIGEST_FREQUENCY_MONTHLY = 'monthly'
COMMUNICATION_DIGEST_FREQUENCY_NEVER = 'never'

COMMUNICATION_VALID_DIGEST_FREQUENCIES = [
    COMMUNICATION_DIGEST_FREQUENCY_DAILY,
    COMMUNICATION_DIGEST_FREQUENCY_WEEKLY,
    COMMUNICATION_DIGEST_FREQUENCY_MONTHLY,
    COMMUNICATION_DIGEST_FREQUENCY_NEVER
]

COMMUNICATION_FORMAT_HTML = 'html'
COMMUNICATION_FORMAT_TEXT = 'text'
COMMUNICATION_VALID_FORMATS = [COMMUNICATION_FORMAT_HTML, COMMUNICATION_FORMAT_TEXT]

# ============================================================================
# Security Service Constants
# ============================================================================

# Default file integrity monitoring settings
DEFAULT_HASH_ALGORITHM = 'sha256'
DEFAULT_BASELINE_FILE_PATH = Path('instance/security/baseline.json')
DEFAULT_BACKUP_PATH_TEMPLATE = 'instance/security/baseline_backups/{timestamp}.json'
DEFAULT_FILE_INTEGRITY_CHECK_INTERVAL = 3600  # 1 hour in seconds
MAX_BASELINE_UPDATE_FILES = 100
AUTO_UPDATE_LIMIT = 10
DEFAULT_BASELINE_BACKUP_COUNT = 5

# File integrity change status values
INTEGRITY_STATUS_UNCHANGED = 'unchanged'
INTEGRITY_STATUS_CHANGED = 'changed'
INTEGRITY_STATUS_MISSING = 'missing'
INTEGRITY_STATUS_NEW = 'new'
INTEGRITY_STATUS_ERROR = 'error'

# File integrity severity levels
INTEGRITY_SEVERITY_CRITICAL = 'critical'
INTEGRITY_SEVERITY_HIGH = 'high'
INTEGRITY_SEVERITY_MEDIUM = 'medium'
INTEGRITY_SEVERITY_LOW = 'low'

# File change severity mappings
FILE_CHANGE_SEVERITY_MAP: Dict[str, str] = {
    'missing': INTEGRITY_SEVERITY_HIGH,
    'changed': INTEGRITY_SEVERITY_HIGH,
    'modified': INTEGRITY_SEVERITY_HIGH,
    'new': INTEGRITY_SEVERITY_MEDIUM,
    'permission': INTEGRITY_SEVERITY_CRITICAL,
    'owner': INTEGRITY_SEVERITY_HIGH,
    'timestamp': INTEGRITY_SEVERITY_LOW,
    'checksum': INTEGRITY_SEVERITY_HIGH,
}

# Critical file patterns - files that need extra verification
CRITICAL_FILE_PATTERNS: List[str] = [
    'app.py',
    'wsgi.py',
    'config/*.py',
    'config/*.ini',
    'config/*.json',
    'core/security/*.py',
    'core/middleware.py',
    'services/security_service.py',
    'services/scanning_service.py'
]

# File Integrity Validation Constants
FILE_INTEGRITY_CONSTANTS = {
    'MAX_HASH_RETRIES': 3,
    'HASH_BUFFER_SIZE': 65536,  # 64kb chunks for hashing
    'MAX_VERIFICATION_TIME': 300,  # 5 min timeout for verification
    'REQUIRED_PERMISSIONS': 0o644  # Default secure file permissions
}

# File integrity notification settings
FILE_INTEGRITY_NOTIFICATION_SETTINGS = {
    'NOTIFY_ON_CRITICAL': True,           # Always notify on critical changes
    'NOTIFY_ON_HIGH_SEVERITY': True,      # Always notify on high severity changes
    'NOTIFY_ON_MEDIUM_SEVERITY': False,   # Only notify on medium severity with other context
    'CRITICAL_THRESHOLD': 1,              # Notify if ≥ 1 critical change
    'HIGH_SEVERITY_THRESHOLD': 3,         # Notify if ≥ 3 high severity changes
    'MEDIUM_SEVERITY_THRESHOLD': 5,       # Notify if ≥ 5 medium severity changes
    'BULK_CHANGE_THRESHOLD': 10,          # Notify if ≥ 10 total changes
    'NOTIFICATION_COOLDOWN': 3600,        # Seconds between notifications for same issue (1 hour)
    'STAKEHOLDER_ROLES': ['security_admin', 'system_admin', 'compliance_officer']
}

# File integrity baseline update strategies
FILE_INTEGRITY_UPDATE_STRATEGIES = {
    'AUTO_APPROVE_NON_CRITICAL': True,    # Auto-approve updates for non-critical files
    'APPROVAL_REQUIRED_FOR_CRITICAL': True, # Require approval for critical files
    'MAX_AUTO_APPROVED_CHANGES': 50,      # Maximum number of auto-approved changes
    'REQUIRE_CHANGE_JUSTIFICATION': True, # Require justification for changes in production
    'KEEP_PREVIOUS_HASHES': 3,            # Number of previous hashes to keep
    'UPDATE_NOTIFICATION_THRESHOLD': 'high', # Notify on updates to files with severity >= threshold
}

# ============================================================================
# Scanning Service Constants
# ============================================================================

# Scan status values
SCAN_STATUS_PENDING = 'pending'
SCAN_STATUS_RUNNING = 'running'
SCAN_STATUS_COMPLETED = 'completed'
SCAN_STATUS_FAILED = 'failed'
SCAN_STATUS_CANCELLED = 'cancelled'
SCAN_STATUS_TIMEOUT = 'timeout'

# Scan types
SCAN_TYPE_VULNERABILITY = 'vulnerability'
SCAN_TYPE_CONFIGURATION = 'configuration'
SCAN_TYPE_COMPLIANCE = 'compliance'
SCAN_TYPE_POSTURE = 'posture'
SCAN_TYPE_CODE = 'code'
SCAN_TYPE_CONTAINER = 'container'
SCAN_TYPE_NETWORK = 'network'
SCAN_TYPE_WEB = 'web'
SCAN_TYPE_IAM = 'iam'
SCAN_TYPE_PENETRATION = 'penetration'

# Scan profiles with default configurations
DEFAULT_SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "standard": {
        "id": "standard",
        "name": "Standard Scan",
        "description": "Balanced security scan with moderate depth",
        "scan_types": [SCAN_TYPE_VULNERABILITY, SCAN_TYPE_CONFIGURATION, SCAN_TYPE_COMPLIANCE],
        "intensity": "standard",
        "is_default": True,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 3600,
            "non_invasive": True
        }
    },
    "quick": {
        "id": "quick",
        "name": "Quick Scan",
        "description": "Fast scan with limited depth for critical vulnerabilities",
        "scan_types": [SCAN_TYPE_VULNERABILITY, SCAN_TYPE_CONFIGURATION],
        "intensity": "low",
        "is_default": False,
        "parameters": {
            "depth": "low",
            "parallel_checks": 6,
            "timeout": 1800,
            "non_invasive": True,
            "critical_only": True
        }
    },
    "full": {
        "id": "full",
        "name": "Full Scan",
        "description": "Comprehensive deep scan across all security dimensions",
        "scan_types": [SCAN_TYPE_VULNERABILITY, SCAN_TYPE_CONFIGURATION, SCAN_TYPE_COMPLIANCE,
                     SCAN_TYPE_POSTURE, SCAN_TYPE_CODE],
        "intensity": "high",
        "is_default": False,
        "parameters": {
            "depth": "high",
            "parallel_checks": 2,
            "timeout": 7200,
            "non_invasive": False,
            "follow_dependencies": True
        }
    },
    "compliance": {
        "id": "compliance",
        "name": "Compliance Scan",
        "description": "Focused on regulatory compliance requirements",
        "scan_types": [SCAN_TYPE_COMPLIANCE, SCAN_TYPE_CONFIGURATION, SCAN_TYPE_IAM],
        "intensity": "standard",
        "is_default": False,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 3600,
            "frameworks": ["pci-dss", "hipaa", "gdpr", "iso27001"]
        }
    },
    "code": {
        "id": "code",
        "name": "Code Security Scan",
        "description": "Static analysis of source code for security vulnerabilities",
        "scan_types": [SCAN_TYPE_CODE],
        "intensity": "standard",
        "is_default": False,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 1800,
            "languages": ["python", "javascript", "typescript", "java", "go"],
            "include_dependencies": True
        }
    },
    "container": {
        "id": "container",
        "name": "Container Security Scan",
        "description": "Scans container images for vulnerabilities and misconfigurations",
        "scan_types": [SCAN_TYPE_CONTAINER, SCAN_TYPE_VULNERABILITY],
        "intensity": "standard",
        "is_default": False,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 2,
            "timeout": 1200,
            "scan_layers": True,
            "check_base_images": True
        }
    }
}

# Maximum number of concurrent scans
MAX_CONCURRENT_SCANS = 5

# Scan severity levels
SCAN_SEVERITY_CRITICAL = 'critical'
SCAN_SEVERITY_HIGH = 'high'
SCAN_SEVERITY_MEDIUM = 'medium'
SCAN_SEVERITY_LOW = 'low'
SCAN_SEVERITY_INFO = 'info'

# Scan Failure Thresholds
SCAN_FAILURE_THRESHOLDS = {
    'MAX_CONSECUTIVE_FAILURES': 3,
    'FAILURE_WINDOW_HOURS': 24,
    'MAX_RETRY_COUNT': 2
}

# User communication preference settings for scan notifications
SCAN_COMMUNICATION_SETTINGS = {
    'DEFAULT_NOTIFICATION_THRESHOLD': SCAN_SEVERITY_HIGH,
    'NOTIFY_ON_SCAN_START': False,
    'NOTIFY_ON_SCAN_COMPLETE': True,
    'NOTIFY_ON_SCAN_FAILURE': True,
    'INCLUDE_FINDING_DETAILS': True,
    'MAX_FINDINGS_IN_NOTIFICATION': 10,
    'INCLUDE_REMEDIATION_INFO': True
}

# ============================================================================
# Webhook Service Constants
# ============================================================================

# Webhook event types
WEBHOOK_EVENT_SECURITY_SCAN_STARTED = 'security.scan.started'
WEBHOOK_EVENT_SECURITY_SCAN_COMPLETED = 'security.scan.completed'
WEBHOOK_EVENT_SECURITY_SCAN_FAILED = 'security.scan.failed'
WEBHOOK_EVENT_SECURITY_FINDING = 'security.finding'
WEBHOOK_EVENT_SECURITY_INCIDENT = 'security.incident'
WEBHOOK_EVENT_FILE_INTEGRITY_VIOLATION = 'security.file_integrity.violation'
WEBHOOK_EVENT_BASELINE_UPDATED = 'security.baseline.updated'
WEBHOOK_EVENT_COMMUNICATION_PREFERENCE_UPDATED = 'user.communication_preference.updated'
WEBHOOK_EVENT_NOTIFICATION_PREFERENCE_UPDATED = 'user.notification_preference.updated'

# Webhook signature header
WEBHOOK_SIGNATURE_HEADER = 'X-Cloud-Platform-Signature'

# Webhook delivery statuses
WEBHOOK_DELIVERY_SUCCESS = 'success'
WEBHOOK_DELIVERY_FAILED = 'failed'
WEBHOOK_DELIVERY_PENDING = 'pending'
WEBHOOK_DELIVERY_RETRYING = 'retrying'

# ============================================================================
# Email Service Constants
# ============================================================================

# Email templates
EMAIL_TEMPLATE_DIR = 'templates/email'
EMAIL_TEMPLATE_SECURITY_ALERT = 'security_alert.html'
EMAIL_TEMPLATE_SCAN_REPORT = 'scan_report.html'
EMAIL_TEMPLATE_INTEGRITY_VIOLATION = 'integrity_violation.html'
EMAIL_TEMPLATE_WELCOME = 'welcome.html'
EMAIL_TEMPLATE_PASSWORD_RESET = 'password_reset.html'
EMAIL_TEMPLATE_VERIFICATION = 'verification.html'
EMAIL_TEMPLATE_BASELINE_UPDATED = 'baseline_updated.html'
EMAIL_TEMPLATE_PREFERENCE_CONFIRMATION = 'preference_confirmation.html'
EMAIL_TEMPLATE_DIGEST = 'notification_digest.html'

# ============================================================================
# Monitoring Service Constants
# ============================================================================

# Health check status values
HEALTH_STATUS_HEALTHY = 'healthy'
HEALTH_STATUS_DEGRADED = 'degraded'
HEALTH_STATUS_UNHEALTHY = 'unhealthy'
HEALTH_STATUS_UNKNOWN = 'unknown'

# Health check types
HEALTH_CHECK_DATABASE = 'database'
HEALTH_CHECK_CACHE = 'cache'
HEALTH_CHECK_STORAGE = 'storage'
HEALTH_CHECK_API = 'api'
HEALTH_CHECK_SECURITY = 'security'

# Default resource thresholds
DEFAULT_CPU_WARNING_THRESHOLD = 80.0  # Percent
DEFAULT_MEMORY_WARNING_THRESHOLD = 85.0  # Percent
DEFAULT_DISK_WARNING_THRESHOLD = 90.0  # Percent
DEFAULT_OPEN_FILES_WARNING_THRESHOLD = 85.0  # Percent of max

# ============================================================================
# Rate Limiting Constants
# ============================================================================

# Default rate limits for various operations
RATE_LIMIT_DEFAULT = '100 per minute'
RATE_LIMIT_AUTHENTICATION = '10 per minute'
RATE_LIMIT_SECURITY_SCAN = '5 per hour'
RATE_LIMIT_FILE_INTEGRITY_CHECK = '12 per hour'
RATE_LIMIT_BASELINE_UPDATE = '6 per hour'
RATE_LIMIT_PREFERENCE_UPDATE = '20 per hour'  # New rate limit for preference updates

# API Rate Limit Thresholds
API_LIMIT_THRESHOLDS = {
    'MAX_FAILURES_PER_HOUR': 100,
    'LOCKOUT_DURATION': 3600,  # 1 hour
    'WARNING_THRESHOLD': 80  # Percent of limit
}

# ============================================================================
# Metric Names
# ============================================================================

# Security metrics
METRIC_SECURITY_SCAN_STARTED = 'security.scan.started'
METRIC_SECURITY_SCAN_COMPLETED = 'security.scan.completed'
METRIC_SECURITY_SCAN_FAILED = 'security.scan.failed'
METRIC_SECURITY_FINDING_DETECTED = 'security.finding.detected'
METRIC_FILE_INTEGRITY_CHECK = 'security.file_integrity.check'
METRIC_FILE_INTEGRITY_VIOLATION = 'security.file_integrity.violation'
METRIC_BASELINE_UPDATE = 'security.baseline.update'

# Notification metrics
METRIC_NOTIFICATION_SENT = 'notification.sent'
METRIC_NOTIFICATION_FAILED = 'notification.failed'

# Webhook metrics
METRIC_WEBHOOK_DELIVERED = 'webhook.delivered'
METRIC_WEBHOOK_FAILED = 'webhook.failed'

# User preference metrics
METRIC_PREFERENCE_UPDATED = 'user.preference.updated'
METRIC_PREFERENCE_ACCESSED = 'user.preference.accessed'
METRIC_EMAIL_PREFERENCE_OPT_OUT = 'user.preference.email_opt_out'
METRIC_EMAIL_PREFERENCE_OPT_IN = 'user.preference.email_opt_in'

# ============================================================================
# Cache Keys and Timeouts
# ============================================================================

# Cache key prefixes
CACHE_KEY_PREFIX_SCAN = 'scan:'
CACHE_KEY_PREFIX_FILE_INTEGRITY = 'file_integrity:'
CACHE_KEY_PREFIX_SECURITY = 'security:'
CACHE_KEY_PREFIX_USER_PREFERENCE = 'user_pref:'  # New prefix for user preferences

# Cache timeouts (in seconds)
CACHE_TIMEOUT_SHORT = 300  # 5 minutes
CACHE_TIMEOUT_MEDIUM = 1800  # 30 minutes
CACHE_TIMEOUT_LONG = 86400  # 24 hours
CACHE_TIMEOUT_USER_PREFERENCE = 600  # 10 minutes, specific to user preferences

# ============================================================================
# Other Constants
# ============================================================================

# Maximum number of audit log items to return by default
DEFAULT_AUDIT_LOG_LIMIT = 100

# Audit Log Settings
AUDIT_LOG_SETTINGS = {
    'MAX_AGE_DAYS': 90,
    'BATCH_SIZE': 1000,
    'REQUIRED_FIELDS': ['timestamp', 'actor', 'action', 'target']
}

# Default timeout values (in seconds)
DEFAULT_REQUEST_TIMEOUT = 60
DEFAULT_WEBHOOK_TIMEOUT = 10
DEFAULT_SCAN_TIMEOUT = 3600
DEFAULT_LONG_OPERATION_TIMEOUT = 300

# User notification expiry (in days)
NOTIFICATION_EXPIRY_DAYS = 30

# Default limiting parameters
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

# Default file size limits (in bytes)
MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_BASELINE_FILE_SIZE = 10 * 1024 * 1024  # 10MB
SMALL_FILE_THRESHOLD = 10240  # 10KB (small files can use different hashing strategy)

# Communication preference integration settings
USER_PREFERENCE_SETTINGS = {
    'HONOR_USER_PREFERENCES': True,  # Whether to respect user preferences or not
    'DEFAULT_LANGUAGE': 'en',        # Default language for communications
    'AVAILABLE_LANGUAGES': ['en', 'es', 'fr', 'de', 'ja', 'zh'],
    'REQUIRE_OPT_IN_FOR_MARKETING': True, # Require explicit opt-in for marketing emails
    'ALLOW_PREFERENCE_SELF_SERVICE': True, # Allow users to update their own preferences
    'CACHE_TIMEOUT': CACHE_TIMEOUT_USER_PREFERENCE,
    'AUTO_CREATE_PREFERENCES': True  # Automatically create preferences for new users
}

# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    # Version Info
    '__version__',
    '__author__',
    '__description__',

    # Enums
    'ServiceStatus',
    'NotificationPriority',

    # Notification Constants
    'CHANNEL_IN_APP', 'CHANNEL_EMAIL', 'CHANNEL_SMS', 'CHANNEL_WEBHOOK',
    'NOTIFICATION_CATEGORY_SYSTEM', 'NOTIFICATION_CATEGORY_SECURITY',
    'NOTIFICATION_CATEGORY_USER', 'NOTIFICATION_CATEGORY_ADMIN',
    'NOTIFICATION_CATEGORY_MAINTENANCE', 'NOTIFICATION_CATEGORY_MONITORING',
    'NOTIFICATION_CATEGORY_COMPLIANCE', 'NOTIFICATION_CATEGORY_INTEGRITY',
    'NOTIFICATION_CATEGORY_AUDIT', 'NOTIFICATION_CATEGORY_SCAN',
    'NOTIFICATION_CATEGORY_VULNERABILITY', 'NOTIFICATION_CATEGORY_INCIDENT',

    # Notification preference constants
    'NOTIFICATION_PRIORITY_THRESHOLD_LOW', 'NOTIFICATION_PRIORITY_THRESHOLD_MEDIUM',
    'NOTIFICATION_PRIORITY_THRESHOLD_HIGH', 'NOTIFICATION_PRIORITY_THRESHOLD_CRITICAL',
    'NOTIFICATION_VALID_PRIORITY_THRESHOLDS',

    # Communication preference constants
    'COMMUNICATION_DIGEST_FREQUENCY_DAILY', 'COMMUNICATION_DIGEST_FREQUENCY_WEEKLY',
    'COMMUNICATION_DIGEST_FREQUENCY_MONTHLY', 'COMMUNICATION_DIGEST_FREQUENCY_NEVER',
    'COMMUNICATION_VALID_DIGEST_FREQUENCIES',
    'COMMUNICATION_FORMAT_HTML', 'COMMUNICATION_FORMAT_TEXT', 'COMMUNICATION_VALID_FORMATS',

    # Security Service Constants
    'DEFAULT_HASH_ALGORITHM', 'DEFAULT_BASELINE_FILE_PATH', 'DEFAULT_BACKUP_PATH_TEMPLATE',
    'DEFAULT_FILE_INTEGRITY_CHECK_INTERVAL', 'MAX_BASELINE_UPDATE_FILES',
    'AUTO_UPDATE_LIMIT', 'DEFAULT_BASELINE_BACKUP_COUNT',
    'INTEGRITY_STATUS_UNCHANGED', 'INTEGRITY_STATUS_CHANGED',
    'INTEGRITY_STATUS_MISSING', 'INTEGRITY_STATUS_NEW', 'INTEGRITY_STATUS_ERROR',
    'INTEGRITY_SEVERITY_CRITICAL', 'INTEGRITY_SEVERITY_HIGH',
    'INTEGRITY_SEVERITY_MEDIUM', 'INTEGRITY_SEVERITY_LOW',
    'FILE_CHANGE_SEVERITY_MAP', 'CRITICAL_FILE_PATTERNS',
    'FILE_INTEGRITY_CONSTANTS', 'FILE_INTEGRITY_NOTIFICATION_SETTINGS',
    'FILE_INTEGRITY_UPDATE_STRATEGIES',

    # Scanning Service Constants
    'SCAN_STATUS_PENDING', 'SCAN_STATUS_RUNNING', 'SCAN_STATUS_COMPLETED',
    'SCAN_STATUS_FAILED', 'SCAN_STATUS_CANCELLED', 'SCAN_STATUS_TIMEOUT',
    'SCAN_TYPE_VULNERABILITY', 'SCAN_TYPE_CONFIGURATION', 'SCAN_TYPE_COMPLIANCE',
    'SCAN_TYPE_POSTURE', 'SCAN_TYPE_CODE', 'SCAN_TYPE_CONTAINER',
    'SCAN_TYPE_NETWORK', 'SCAN_TYPE_WEB', 'SCAN_TYPE_IAM', 'SCAN_TYPE_PENETRATION',
    'DEFAULT_SCAN_PROFILES', 'MAX_CONCURRENT_SCANS',
    'SCAN_SEVERITY_CRITICAL', 'SCAN_SEVERITY_HIGH',
    'SCAN_SEVERITY_MEDIUM', 'SCAN_SEVERITY_LOW', 'SCAN_SEVERITY_INFO',
    'SCAN_FAILURE_THRESHOLDS', 'SCAN_COMMUNICATION_SETTINGS',

    # Webhook Service Constants
    'WEBHOOK_EVENT_SECURITY_SCAN_STARTED', 'WEBHOOK_EVENT_SECURITY_SCAN_COMPLETED',
    'WEBHOOK_EVENT_SECURITY_SCAN_FAILED', 'WEBHOOK_EVENT_SECURITY_FINDING',
    'WEBHOOK_EVENT_SECURITY_INCIDENT', 'WEBHOOK_EVENT_FILE_INTEGRITY_VIOLATION',
    'WEBHOOK_EVENT_BASELINE_UPDATED', 'WEBHOOK_EVENT_COMMUNICATION_PREFERENCE_UPDATED',
    'WEBHOOK_EVENT_NOTIFICATION_PREFERENCE_UPDATED',
    'WEBHOOK_SIGNATURE_HEADER',
    'WEBHOOK_DELIVERY_SUCCESS', 'WEBHOOK_DELIVERY_FAILED',
    'WEBHOOK_DELIVERY_PENDING', 'WEBHOOK_DELIVERY_RETRYING',

    # Email Service Constants
    'EMAIL_TEMPLATE_DIR', 'EMAIL_TEMPLATE_SECURITY_ALERT',
    'EMAIL_TEMPLATE_SCAN_REPORT', 'EMAIL_TEMPLATE_INTEGRITY_VIOLATION',
    'EMAIL_TEMPLATE_WELCOME', 'EMAIL_TEMPLATE_PASSWORD_RESET',
    'EMAIL_TEMPLATE_VERIFICATION', 'EMAIL_TEMPLATE_BASELINE_UPDATED',
    'EMAIL_TEMPLATE_PREFERENCE_CONFIRMATION', 'EMAIL_TEMPLATE_DIGEST',

    # Monitoring Service Constants
    'HEALTH_STATUS_HEALTHY', 'HEALTH_STATUS_DEGRADED',
    'HEALTH_STATUS_UNHEALTHY', 'HEALTH_STATUS_UNKNOWN',
    'HEALTH_CHECK_DATABASE', 'HEALTH_CHECK_CACHE',
    'HEALTH_CHECK_STORAGE', 'HEALTH_CHECK_API', 'HEALTH_CHECK_SECURITY',
    'DEFAULT_CPU_WARNING_THRESHOLD', 'DEFAULT_MEMORY_WARNING_THRESHOLD',
    'DEFAULT_DISK_WARNING_THRESHOLD', 'DEFAULT_OPEN_FILES_WARNING_THRESHOLD',

    # Rate Limiting Constants
    'RATE_LIMIT_DEFAULT', 'RATE_LIMIT_AUTHENTICATION',
    'RATE_LIMIT_SECURITY_SCAN', 'RATE_LIMIT_FILE_INTEGRITY_CHECK',
    'RATE_LIMIT_BASELINE_UPDATE', 'RATE_LIMIT_PREFERENCE_UPDATE',
    'API_LIMIT_THRESHOLDS',

    # Metric Names
    'METRIC_SECURITY_SCAN_STARTED', 'METRIC_SECURITY_SCAN_COMPLETED',
    'METRIC_SECURITY_SCAN_FAILED', 'METRIC_SECURITY_FINDING_DETECTED',
    'METRIC_FILE_INTEGRITY_CHECK', 'METRIC_FILE_INTEGRITY_VIOLATION',
    'METRIC_BASELINE_UPDATE', 'METRIC_NOTIFICATION_SENT',
    'METRIC_NOTIFICATION_FAILED', 'METRIC_WEBHOOK_DELIVERED',
    'METRIC_WEBHOOK_FAILED', 'METRIC_PREFERENCE_UPDATED',
    'METRIC_PREFERENCE_ACCESSED', 'METRIC_EMAIL_PREFERENCE_OPT_OUT',
    'METRIC_EMAIL_PREFERENCE_OPT_IN',

    # Cache Keys and Timeouts
    'CACHE_KEY_PREFIX_SCAN', 'CACHE_KEY_PREFIX_FILE_INTEGRITY',
    'CACHE_KEY_PREFIX_SECURITY', 'CACHE_KEY_PREFIX_USER_PREFERENCE',
    'CACHE_TIMEOUT_SHORT', 'CACHE_TIMEOUT_MEDIUM', 'CACHE_TIMEOUT_LONG',
    'CACHE_TIMEOUT_USER_PREFERENCE',

    # Other Constants
    'DEFAULT_AUDIT_LOG_LIMIT', 'AUDIT_LOG_SETTINGS', 'DEFAULT_REQUEST_TIMEOUT',
    'DEFAULT_WEBHOOK_TIMEOUT', 'DEFAULT_SCAN_TIMEOUT',
    'DEFAULT_LONG_OPERATION_TIMEOUT', 'NOTIFICATION_EXPIRY_DAYS',
    'DEFAULT_PAGE_SIZE', 'MAX_PAGE_SIZE',
    'MAX_SCAN_FILE_SIZE', 'MAX_BASELINE_FILE_SIZE', 'SMALL_FILE_THRESHOLD',
    'USER_PREFERENCE_SETTINGS'
]
