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
    PENDING = auto()
    WARNING = auto()
    NOT_FOUND = auto()
    UNAUTHORIZED = auto()
    INVALID_REQUEST = auto()
    UNAVAILABLE = auto()
    TIMEOUT = auto()
    RATE_LIMITED = auto()

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
NOTIFICATION_CATEGORY_USER = 'user'              # User-related notifications
NOTIFICATION_CATEGORY_ADMIN = 'admin'            # Administrative notifications
NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance'# Scheduled maintenance notices
NOTIFICATION_CATEGORY_MONITORING = 'monitoring'  # Monitoring alerts and metrics
NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'  # Compliance-related notifications
NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'    # File integrity monitoring alerts
NOTIFICATION_CATEGORY_AUDIT = 'audit'            # Audit log related notifications
NOTIFICATION_CATEGORY_SCAN = 'scan'              # Security scan notifications
NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'  # Vulnerability notifications
NOTIFICATION_CATEGORY_INCIDENT = 'incident'      # Security incident notifications

# Define how long notifications are kept before automatic deletion/archiving
NOTIFICATION_EXPIRY_DAYS = 30  # Notifications older than this are archived

# ============================================================================
# SMS Service Constants
# ============================================================================

# SMS default region - used for phone number parsing when region is not specified
SMS_DEFAULT_REGION = 'US'

# Maximum SMS message length (standard SMS limit)
SMS_MAX_LENGTH = 160

# Default number of retry attempts for failed SMS deliveries
SMS_RETRY_COUNT = 3

# SMS priority levels
SMS_CRITICAL_PRIORITY = 'critical'  # Highest priority, for critical alerts
SMS_HIGH_PRIORITY = 'high'          # High priority, for urgent notifications
SMS_MEDIUM_PRIORITY = 'medium'      # Medium priority, for normal notifications
SMS_LOW_PRIORITY = 'low'            # Low priority, for informational notifications

# Rate limiting settings
SMS_RATE_LIMIT_WINDOW = 300          # Rate limit window in seconds (5 minutes)
SMS_RATE_LIMIT_MAX_PER_USER = 5      # Maximum messages per user in the window

# List of allowed domains for SMS communications (empty list = no restriction)
SMS_ALLOWED_DOMAINS = []

# SMS delivery status codes (normalized across providers)
SMS_STATUS_QUEUED = 'queued'         # Message is queued for delivery
SMS_STATUS_SENDING = 'sending'       # Message is being sent
SMS_STATUS_SENT = 'sent'             # Message has been sent to provider
SMS_STATUS_DELIVERED = 'delivered'   # Message delivered to recipient
SMS_STATUS_FAILED = 'failed'         # Message delivery failed
SMS_STATUS_UNDELIVERABLE = 'undeliverable' # Message cannot be delivered
SMS_STATUS_UNKNOWN = 'unknown'       # Status is unknown

# Provider-specific integration settings
SMS_PROVIDER_SETTINGS = {
    'twilio': {
        'use_messaging_service': True,  # Whether to use messaging service for high priority
        'status_check_interval': 60,    # Seconds between status checks
        'max_concurrent_requests': 10,  # Max parallel API requests
        'verify_ssl': True              # Whether to verify SSL certificates
    },
    'aws_sns': {
        'promotional_limit': 100,       # Daily limit for promotional messages
        'transactional_limit': 200,     # Daily limit for transactional messages
        'attributes_per_message': 10,   # Maximum number of attributes per message
    },
    'messagebird': {
        'datacoding': 'auto',           # Either 'plain', 'unicode', or 'auto'
        'validity': 86400,              # Message validity period in seconds (24 hours)
        'gateway': 0                    # MessageBird gateway to use (0 = default)
    },
    'vonage': {
        'account_ref': '',              # Account reference for billing
        'callback_url': '',             # URL for delivery receipts
        'message_class': 1              # Message class (0-3)
    }
}

# Notification preference - priority threshold constants
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
MAX_BASELINE_UPDATE_FILES = 1000
AUTO_UPDATE_LIMIT = 10  # Maximum number of files to auto-update in one check
DEFAULT_BASELINE_BACKUP_COUNT = 5  # Number of backups to keep

# File integrity status codes
INTEGRITY_STATUS_UNCHANGED = 'unchanged'  # File matches the baseline
INTEGRITY_STATUS_CHANGED = 'changed'      # File has been modified
INTEGRITY_STATUS_MISSING = 'missing'      # File in baseline is missing
INTEGRITY_STATUS_NEW = 'new'              # File exists but not in baseline
INTEGRITY_STATUS_ERROR = 'error'          # Error checking file

# File integrity violation severity levels
INTEGRITY_SEVERITY_CRITICAL = 'critical'
INTEGRITY_SEVERITY_HIGH = 'high'
INTEGRITY_SEVERITY_MEDIUM = 'medium'
INTEGRITY_SEVERITY_LOW = 'low'

# Map directory/file patterns to severity levels
FILE_CHANGE_SEVERITY_MAP = {
    # Critical files
    'config/security/*.py': INTEGRITY_SEVERITY_CRITICAL,
    'core/security/*.py': INTEGRITY_SEVERITY_CRITICAL,
    'services/security_service.py': INTEGRITY_SEVERITY_CRITICAL,
    'services/file_integrity_service.py': INTEGRITY_SEVERITY_CRITICAL,

    # High severity
    'config/*.py': INTEGRITY_SEVERITY_HIGH,
    'core/*.py': INTEGRITY_SEVERITY_HIGH,
    'services/*.py': INTEGRITY_SEVERITY_HIGH,
    'models/*.py': INTEGRITY_SEVERITY_HIGH,
    'app.py': INTEGRITY_SEVERITY_HIGH,

    # Medium severity
    'api/*.py': INTEGRITY_SEVERITY_MEDIUM,
    'blueprints/*.py': INTEGRITY_SEVERITY_MEDIUM,

    # Low severity - everything else
    '*': INTEGRITY_SEVERITY_LOW
}

# Patterns for critical files that should never change unexpectedly
CRITICAL_FILE_PATTERNS = [
    'config/security/*.py',
    'core/security/*.py',
    'app.py',
    'services/security_service.py',
    'services/file_integrity_service.py'
]

# File integrity monitoring constants
FILE_INTEGRITY_CONSTANTS = {
    'MAX_FILE_SIZE': 50 * 1024 * 1024,  # Maximum size of files to check (50MB)
    'IGNORE_PATTERNS': [                # File patterns to ignore
        '__pycache__/*',
        '*.pyc',
        '*.log',
        'logs/*',
        'instance/tmp/*',
        '.git/*'
    ],
    'REQUIRE_CHANGE_JUSTIFICATION': True, # Require justification for changes in production
    'KEEP_PREVIOUS_HASHES': 3,            # Number of previous hashes to keep
    'UPDATE_NOTIFICATION_THRESHOLD': 'high', # Notify on updates to files with severity >= threshold
    'EXPORT_FORMATS': ['json', 'yaml', 'csv'] # Supported export formats for baseline
}

# File integrity notification settings
FILE_INTEGRITY_NOTIFICATION_SETTINGS = {
    'NOTIFY_ON_CRITICAL': True,           # Always notify on critical file changes
    'NOTIFY_ON_HIGH': True,               # Always notify on high severity changes
    'NOTIFY_ON_MULTIPLE_MEDIUM': True,    # Notify when multiple medium severity changes
    'MEDIUM_THRESHOLD': 3,                # Threshold for multiple medium changes
    'BATCH_NOTIFICATIONS': True,          # Group notifications for multiple changes
    'NOTIFICATION_CHANNEL': CHANNEL_EMAIL # Default notification channel
}

# File integrity update strategies for different environments
FILE_INTEGRITY_UPDATE_STRATEGIES = {
    'development': {
        'AUTO_UPDATE': True,              # Automatically update baselines in development
        'REQUIRE_APPROVAL': False,        # Don't require approval in development
        'UPDATE_LIMIT': 50,               # Higher limit for development
        'BACKUP_ENABLED': True,           # Always create backups before updates
        'ALLOW_BATCH_UPDATES': True,      # Allow updating multiple files at once
        'VERIFICATION_REQUIRED': False    # Don't require verification after update
    },
    'staging': {
        'AUTO_UPDATE': False,             # No auto-updates in staging
        'REQUIRE_APPROVAL': True,         # Require approval in staging
        'UPDATE_LIMIT': 20,               # Moderate limit for staging
        'BACKUP_ENABLED': True,           # Always create backups before updates
        'ALLOW_BATCH_UPDATES': True,      # Allow updating multiple files at once
        'VERIFICATION_REQUIRED': True     # Require verification after update
    },
    'production': {
        'AUTO_UPDATE': False,             # No auto-updates in production
        'REQUIRE_APPROVAL': True,         # Always require approval in production
        'UPDATE_LIMIT': 10,               # Low limit for production
        'BACKUP_ENABLED': True,           # Always create backups before updates
        'ALLOW_BATCH_UPDATES': False,     # Only allow single file updates for safety
        'VERIFICATION_REQUIRED': True     # Always verify after update
    }
}

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
        "description": "In-depth security analysis across all systems",
        "scan_types": [
            SCAN_TYPE_VULNERABILITY, SCAN_TYPE_CONFIGURATION,
            SCAN_TYPE_COMPLIANCE, SCAN_TYPE_POSTURE, SCAN_TYPE_CONTAINER
        ],
        "intensity": "high",
        "is_default": False,
        "parameters": {
            "depth": "high",
            "parallel_checks": 2,
            "timeout": 7200,
            "non_invasive": False
        }
    },
    "compliance": {
        "id": "compliance",
        "name": "Compliance Scan",
        "description": "Focused scan for regulatory compliance",
        "scan_types": [SCAN_TYPE_COMPLIANCE, SCAN_TYPE_CONFIGURATION],
        "intensity": "standard",
        "is_default": False,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 5400,
            "non_invasive": True,
            "compliance_frameworks": ["PCI-DSS", "HIPAA", "GDPR", "SOC2"]
        }
    }
}

# Maximum number of concurrent scans allowed
MAX_CONCURRENT_SCANS = 5

# Scan finding severity levels
SCAN_SEVERITY_CRITICAL = 'critical'
SCAN_SEVERITY_HIGH = 'high'
SCAN_SEVERITY_MEDIUM = 'medium'
SCAN_SEVERITY_LOW = 'low'
SCAN_SEVERITY_INFO = 'info'

# Configure failure thresholds for scan severity levels
SCAN_FAILURE_THRESHOLDS = {
    'production': {
        SCAN_SEVERITY_CRITICAL: 0,  # Any critical finding fails the scan
        SCAN_SEVERITY_HIGH: 5,      # More than 5 high findings fails the scan
        SCAN_SEVERITY_MEDIUM: 20,   # More than 20 medium findings fails the scan
    },
    'staging': {
        SCAN_SEVERITY_CRITICAL: 2,  # More than 2 critical findings fails the scan
        SCAN_SEVERITY_HIGH: 10,     # More than 10 high findings fails the scan
    },
    'development': {
        SCAN_SEVERITY_CRITICAL: 5,  # More than 5 critical findings fails the scan
    }
}

# Scan communication settings for notifications
SCAN_COMMUNICATION_SETTINGS = {
    'NOTIFY_ON_START': True,
    'NOTIFY_ON_COMPLETION': True,
    'NOTIFY_ON_FAILURE': True,
    'SUMMARY_EMAIL_TEMPLATE': 'scan_summary.html',
    'DETAILED_REPORT_TEMPLATE': 'scan_detailed_report.html',
    'INCLUDE_FULL_REPORT': True
}

# Webhook event types
WEBHOOK_EVENT_SECURITY_SCAN_STARTED = 'security.scan.started'
WEBHOOK_EVENT_SECURITY_SCAN_COMPLETED = 'security.scan.completed'
WEBHOOK_EVENT_SECURITY_SCAN_FAILED = 'security.scan.failed'
WEBHOOK_EVENT_SECURITY_FINDING = 'security.finding'
WEBHOOK_EVENT_SECURITY_INCIDENT = 'security.incident'
WEBHOOK_EVENT_FILE_INTEGRITY_VIOLATION = 'security.file_integrity.violation'
WEBHOOK_EVENT_BASELINE_UPDATED = 'security.baseline.updated'
WEBHOOK_EVENT_BASELINE_EXPORTED = 'security.baseline.exported'
WEBHOOK_EVENT_BASELINE_VERIFIED = 'security.baseline.verified'
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
EMAIL_TEMPLATE_BASELINE_EXPORTED = 'baseline_exported.html'
EMAIL_TEMPLATE_PREFERENCE_CONFIRMATION = 'preference_confirmation.html'
EMAIL_TEMPLATE_DIGEST = 'digest.html'

# ============================================================================
# Monitoring Service Constants
# ============================================================================

# Health check status codes
HEALTH_STATUS_HEALTHY = 'healthy'
HEALTH_STATUS_DEGRADED = 'degraded'
HEALTH_STATUS_UNHEALTHY = 'unhealthy'
HEALTH_STATUS_UNKNOWN = 'unknown'

# Health check component identifiers
HEALTH_CHECK_DATABASE = 'database'
HEALTH_CHECK_CACHE = 'cache'
HEALTH_CHECK_STORAGE = 'storage'
HEALTH_CHECK_API = 'api'
HEALTH_CHECK_SECURITY = 'security'

# Default warning thresholds for system resources
DEFAULT_CPU_WARNING_THRESHOLD = 80  # Percent
DEFAULT_MEMORY_WARNING_THRESHOLD = 85  # Percent
DEFAULT_DISK_WARNING_THRESHOLD = 90  # Percent
DEFAULT_OPEN_FILES_WARNING_THRESHOLD = 85  # Percent

# ============================================================================
# Cache Timeout Constants
# ============================================================================

# Cache timeout values (in seconds)
CACHE_TIMEOUT_SHORT = 60  # 1 minute
CACHE_TIMEOUT_MEDIUM = 300  # 5 minutes
CACHE_TIMEOUT_LONG = 3600  # 1 hour
CACHE_TIMEOUT_USER_PREFERENCE = 1800  # 30 minutes

# ============================================================================
# Miscellaneous Constants
# ============================================================================

# Default limit for audit log retrieval
DEFAULT_AUDIT_LOG_LIMIT = 100

# Settings for audit logging
AUDIT_LOG_SETTINGS = {
    'RETENTION_DAYS': 90,  # Number of days to retain audit logs
    'ROTATION_SIZE': 10485760,  # 10MB before log rotation
    'BACKUP_COUNT': 10,  # Number of rotated files to keep
    'SECURE_BACKUP': True  # Whether to securely store backups
}

# Default timeouts
DEFAULT_REQUEST_TIMEOUT = 30  # seconds
DEFAULT_WEBHOOK_TIMEOUT = 10  # seconds
DEFAULT_SCAN_TIMEOUT = 3600  # 1 hour
DEFAULT_LONG_OPERATION_TIMEOUT = 7200  # 2 hours

# Pagination defaults
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100

# File size limits
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
# File Integrity Baseline Constants
# ============================================================================

# File formats supported for baseline export
BASELINE_EXPORT_FORMATS = ['json', 'yaml', 'csv', 'html']

# Permissions mode for baseline storage directories on POSIX systems
BASELINE_DIR_PERMISSION_MODE = 0o750  # rwxr-x---

# File baseline actions
BASELINE_ACTION_CREATE = 'create'
BASELINE_ACTION_UPDATE = 'update'
BASELINE_ACTION_VERIFY = 'verify'
BASELINE_ACTION_EXPORT = 'export'
BASELINE_ACTION_IMPORT = 'import'

# File baseline status values
BASELINE_STATUS_CONSISTENT = 'consistent'
BASELINE_STATUS_INCONSISTENT = 'inconsistent'
BASELINE_STATUS_VALID = 'valid'
BASELINE_STATUS_INVALID = 'invalid'
BASELINE_STATUS_EMPTY = 'empty'
BASELINE_STATUS_NOT_FOUND = 'not_found'
BASELINE_STATUS_ERROR = 'error'

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

    # File Integrity Baseline Constants
    'BASELINE_EXPORT_FORMATS', 'BASELINE_DIR_PERMISSION_MODE',
    'BASELINE_ACTION_CREATE', 'BASELINE_ACTION_UPDATE', 'BASELINE_ACTION_VERIFY',
    'BASELINE_ACTION_EXPORT', 'BASELINE_ACTION_IMPORT',
    'BASELINE_STATUS_CONSISTENT', 'BASELINE_STATUS_INCONSISTENT',
    'BASELINE_STATUS_VALID', 'BASELINE_STATUS_INVALID',
    'BASELINE_STATUS_EMPTY', 'BASELINE_STATUS_NOT_FOUND', 'BASELINE_STATUS_ERROR',

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
    'WEBHOOK_EVENT_BASELINE_UPDATED', 'WEBHOOK_EVENT_BASELINE_EXPORTED',
    'WEBHOOK_EVENT_BASELINE_VERIFIED', 'WEBHOOK_EVENT_COMMUNICATION_PREFERENCE_UPDATED',
    'WEBHOOK_EVENT_NOTIFICATION_PREFERENCE_UPDATED',
    'WEBHOOK_SIGNATURE_HEADER',
    'WEBHOOK_DELIVERY_SUCCESS', 'WEBHOOK_DELIVERY_FAILED',
    'WEBHOOK_DELIVERY_PENDING', 'WEBHOOK_DELIVERY_RETRYING',

    # Email Service Constants
    'EMAIL_TEMPLATE_DIR', 'EMAIL_TEMPLATE_SECURITY_ALERT',
    'EMAIL_TEMPLATE_SCAN_REPORT', 'EMAIL_TEMPLATE_INTEGRITY_VIOLATION',
    'EMAIL_TEMPLATE_WELCOME', 'EMAIL_TEMPLATE_PASSWORD_RESET',
    'EMAIL_TEMPLATE_VERIFICATION', 'EMAIL_TEMPLATE_BASELINE_UPDATED',
    'EMAIL_TEMPLATE_BASELINE_EXPORTED', 'EMAIL_TEMPLATE_PREFERENCE_CONFIRMATION',
    'EMAIL_TEMPLATE_DIGEST',

    # Monitoring Service Constants
    'HEALTH_STATUS_HEALTHY', 'HEALTH_STATUS_DEGRADED',
    'HEALTH_STATUS_UNHEALTHY', 'HEALTH_STATUS_UNKNOWN',
    'HEALTH_CHECK_DATABASE', 'HEALTH_CHECK_CACHE',
    'HEALTH_CHECK_STORAGE', 'HEALTH_CHECK_API', 'HEALTH_CHECK_SECURITY',
    'DEFAULT_CPU_WARNING_THRESHOLD', 'DEFAULT_MEMORY_WARNING_THRESHOLD',
    'DEFAULT_DISK_WARNING_THRESHOLD', 'DEFAULT_OPEN_FILES_WARNING_THRESHOLD',

    # Cache Timeouts
    'CACHE_TIMEOUT_SHORT', 'CACHE_TIMEOUT_MEDIUM', 'CACHE_TIMEOUT_LONG',
    'CACHE_TIMEOUT_USER_PREFERENCE',

    # Other Constants
    'DEFAULT_AUDIT_LOG_LIMIT', 'AUDIT_LOG_SETTINGS', 'DEFAULT_REQUEST_TIMEOUT',
    'DEFAULT_WEBHOOK_TIMEOUT', 'DEFAULT_SCAN_TIMEOUT',
    'DEFAULT_LONG_OPERATION_TIMEOUT', 'NOTIFICATION_EXPIRY_DAYS',
    'DEFAULT_PAGE_SIZE', 'MAX_PAGE_SIZE',
    'MAX_SCAN_FILE_SIZE', 'MAX_BASELINE_FILE_SIZE', 'SMALL_FILE_THRESHOLD',
    'USER_PREFERENCE_SETTINGS',

    # SMS Service Constants
    'SMS_DEFAULT_REGION', 'SMS_MAX_LENGTH', 'SMS_RETRY_COUNT',
    'SMS_CRITICAL_PRIORITY', 'SMS_HIGH_PRIORITY', 'SMS_MEDIUM_PRIORITY', 'SMS_LOW_PRIORITY',
    'SMS_RATE_LIMIT_WINDOW', 'SMS_RATE_LIMIT_MAX_PER_USER', 'SMS_ALLOWED_DOMAINS',
    'SMS_STATUS_QUEUED', 'SMS_STATUS_SENDING', 'SMS_STATUS_SENT',
    'SMS_STATUS_DELIVERED', 'SMS_STATUS_FAILED', 'SMS_STATUS_UNDELIVERABLE',
    'SMS_STATUS_UNKNOWN', 'SMS_PROVIDER_SETTINGS'
]
