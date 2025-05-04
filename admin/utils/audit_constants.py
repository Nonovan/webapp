"""
Administrative Audit Constants.

This module defines constants used by the administrative audit logging system,
including severity levels, status indicators, and standard event types. These
constants ensure consistent categorization and formatting of audit events
across the administrative tools.
"""

# Admin audit categories
ADMIN_ACTION_CATEGORY = "admin"
ADMIN_EVENT_PREFIX = "admin."

# Severity levels
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

# Common action statuses
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_ATTEMPTED = "attempted"
STATUS_CANCELLED = "cancelled"

# Standard admin action types
ACTION_USER_CREATE = "user.create"
ACTION_USER_UPDATE = "user.update"
ACTION_USER_DELETE = "user.delete"
ACTION_ROLE_ASSIGN = "role.assign"
ACTION_ROLE_REVOKE = "role.revoke"
ACTION_PERMISSION_GRANT = "permission.grant"
ACTION_PERMISSION_REVOKE = "permission.revoke"
ACTION_CONFIG_CHANGE = "config.change"
ACTION_SYSTEM_CHANGE = "system.change"
ACTION_SECURITY_CHANGE = "security.change"
ACTION_EMERGENCY_ACCESS = "emergency.access"
ACTION_EMERGENCY_DEACTIVATE = "emergency.deactivate"
ACTION_DATA_EXPORT = "data.export"
ACTION_AUDIT_ACCESS = "audit.access"
ACTION_API_KEY_CREATE = "api_key.create"
ACTION_API_KEY_REVOKE = "api_key.revoke"

# Default thresholds for anomaly detection
DEFAULT_ANOMALY_THRESHOLDS = {
    'low': {
        'action_frequency': 30,  # Actions per hour by same user
        'failed_attempts': 5,    # Failed attempts in a row
        'time_window': 60,       # Seconds between related actions
        'unusual_hour_factor': 3 # Factor more actions than usual for the hour
    },
    'medium': {
        'action_frequency': 20,
        'failed_attempts': 3,
        'time_window': 120,
        'unusual_hour_factor': 2
    },
    'high': {
        'action_frequency': 10,
        'failed_attempts': 2,
        'time_window': 300,
        'unusual_hour_factor': 1.5
    }
}

# Event types considered sensitive or requiring additional scrutiny
PRIVILEGED_EVENT_TYPES = [
    ACTION_PERMISSION_GRANT,
    ACTION_ROLE_ASSIGN,
    ACTION_EMERGENCY_ACCESS,
    ACTION_USER_CREATE,
    ACTION_CONFIG_CHANGE,
    ACTION_SECURITY_CHANGE,
]

# Default audit log configuration
DEFAULT_ADMIN_AUDIT_LOG_RETENTION_DAYS = 365
DEFAULT_ADMIN_AUDIT_LOG_FORMAT = "json"
DEFAULT_ADMIN_AUDIT_LOG_LEVEL = SEVERITY_INFO
