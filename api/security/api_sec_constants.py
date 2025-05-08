"""
Security API Constants for Cloud Infrastructure Platform.

This module defines constants used across security API endpoints including
severity levels, status values, rate limits, event types, and classification
taxonomies. These constants ensure consistent categorization and behavior
across all security API endpoints.
"""

from typing import Dict, Any, List, Final, FrozenSet

# API version information
API_VERSION: str = '0.1.1'

# Severity levels for security items
SEVERITY_CRITICAL: str = 'critical'
SEVERITY_HIGH: str = 'high'
SEVERITY_MEDIUM: str = 'medium'
SEVERITY_LOW: str = 'low'
SEVERITY_INFO: str = 'info'

# Security status values
STATUS_OPEN: str = 'open'
STATUS_IN_PROGRESS: str = 'in_progress'
STATUS_RESOLVED: str = 'resolved'
STATUS_CLOSED: str = 'closed'
STATUS_DECLINED: str = 'declined'

# Valid severity levels
SEVERITIES: List[str] = [
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
]

# Valid status values
STATUSES: List[str] = [
    STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_RESOLVED, STATUS_CLOSED, STATUS_DECLINED
]

# SLA response times (in hours) by severity
SLA_RESPONSE_HOURS: Dict[str, int] = {
    SEVERITY_CRITICAL: 1,
    SEVERITY_HIGH: 4,
    SEVERITY_MEDIUM: 24,
    SEVERITY_LOW: 72
}

# Rate limiting constants
RATELIMIT_DEFAULT: str = '60 per minute'
RATELIMIT_SCAN: str = '10 per hour'
RATELIMIT_INCIDENT_CREATE: str = '30 per minute'
RATELIMIT_BASELINE_UPDATE: str = '5 per hour'
RATELIMIT_BASELINE_CHECK: str = '30 per minute'

# Event types for security events
EVENT_FILE_INTEGRITY_BASELINE_UPDATED: str = 'security_baseline_updated'
EVENT_FILE_INTEGRITY_BASELINE_UPDATE_FAILED: str = 'security_baseline_update_failed'
EVENT_INCIDENT_CREATED: str = 'security_incident_created'
EVENT_INCIDENT_UPDATED: str = 'security_incident_updated'
EVENT_VULNERABILITY_CREATED: str = 'security_vulnerability_created'
EVENT_THREAT_DETECTED: str = 'security_threat_detected'
EVENT_SECURITY_SCAN_STARTED: str = 'security_scan_started'
EVENT_SECURITY_SCAN_COMPLETED: str = 'security_scan_completed'
EVENT_CRITICAL_ENDPOINT_ACCESS: str = 'security_critical_endpoint_access'

# Critical security endpoints that require special monitoring
CRITICAL_ENDPOINTS: FrozenSet[str] = frozenset([
    'update_file_integrity_baseline',
    'update_security_config',
    'create_security_incident',
    'bulk_update_vulnerabilities'
])

# File integrity related constants
FILE_HASH_ALGORITHM: str = 'sha256'
BASELINE_MAX_CHANGES_PER_UPDATE: int = 100
AUTO_UPDATE_LIMIT: int = 10

# Default timeout for cached security data (in seconds)
CACHE_TIMEOUT_SHORT: int = 300      # 5 minutes
CACHE_TIMEOUT_MEDIUM: int = 3600    # 1 hour
CACHE_TIMEOUT_LONG: int = 86400     # 1 day

# Security scan types
SCAN_TYPE_VULNERABILITY: str = 'vulnerability'
SCAN_TYPE_COMPLIANCE: str = 'compliance'
SCAN_TYPE_CONFIGURATION: str = 'configuration'
SCAN_TYPE_WEB_APPLICATION: str = 'web_application'
SCAN_TYPE_NETWORK: str = 'network'
SCAN_TYPE_CONTAINER: str = 'container'
SCAN_TYPE_CODE: str = 'code'
SCAN_TYPE_SECURITY_POSTURE: str = 'security_posture'
SCAN_TYPE_PENETRATION: str = 'penetration'
SCAN_TYPE_IAM: str = 'iam'

SCAN_TYPES: List[str] = [
    SCAN_TYPE_VULNERABILITY,
    SCAN_TYPE_COMPLIANCE,
    SCAN_TYPE_CONFIGURATION,
    SCAN_TYPE_WEB_APPLICATION,
    SCAN_TYPE_NETWORK,
    SCAN_TYPE_CONTAINER,
    SCAN_TYPE_CODE,
    SCAN_TYPE_SECURITY_POSTURE,
    SCAN_TYPE_PENETRATION,
    SCAN_TYPE_IAM
]

# Security component status indicators
STATUS_HEALTHY: str = 'healthy'
STATUS_WARNING: str = 'warning'
STATUS_ERROR: str = 'error'
STATUS_CRITICAL: str = 'critical'
STATUS_UNKNOWN: str = 'unknown'

# Security metrics labels
METRIC_LABEL_SEVERITY: str = 'severity'
METRIC_LABEL_STATUS: str = 'status'
METRIC_LABEL_TYPE: str = 'type'

# Cache keys for commonly used security data
CACHE_KEY_BASELINE_STATUS: str = 'security_baseline_status'
CACHE_KEY_INTEGRITY_CHECK: str = 'last_integrity_check'
CACHE_KEY_SECURITY_METRICS: str = 'security_metrics_summary'
CACHE_KEY_SECURITY_STATUS: str = 'security_status_overview'

# Default paths for security resources
DEFAULT_BASELINE_PATH: str = 'instance/security/baseline.json'
DEFAULT_BACKUP_PATH_TEMPLATE: str = 'instance/security/baseline_backups/{timestamp}.json'

# Export all constants
__all__ = [
    # Version information
    'API_VERSION',

    # Severity levels
    'SEVERITY_CRITICAL',
    'SEVERITY_HIGH',
    'SEVERITY_MEDIUM',
    'SEVERITY_LOW',
    'SEVERITY_INFO',
    'SEVERITIES',

    # Status values
    'STATUS_OPEN',
    'STATUS_IN_PROGRESS',
    'STATUS_RESOLVED',
    'STATUS_CLOSED',
    'STATUS_DECLINED',
    'STATUSES',

    # SLA times
    'SLA_RESPONSE_HOURS',

    # Rate limiting
    'RATELIMIT_DEFAULT',
    'RATELIMIT_SCAN',
    'RATELIMIT_INCIDENT_CREATE',
    'RATELIMIT_BASELINE_UPDATE',
    'RATELIMIT_BASELINE_CHECK',

    # Event types
    'EVENT_FILE_INTEGRITY_BASELINE_UPDATED',
    'EVENT_FILE_INTEGRITY_BASELINE_UPDATE_FAILED',
    'EVENT_INCIDENT_CREATED',
    'EVENT_INCIDENT_UPDATED',
    'EVENT_VULNERABILITY_CREATED',
    'EVENT_THREAT_DETECTED',
    'EVENT_SECURITY_SCAN_STARTED',
    'EVENT_SECURITY_SCAN_COMPLETED',
    'EVENT_CRITICAL_ENDPOINT_ACCESS',

    # Critical endpoints
    'CRITICAL_ENDPOINTS',

    # File integrity constants
    'FILE_HASH_ALGORITHM',
    'BASELINE_MAX_CHANGES_PER_UPDATE',
    'AUTO_UPDATE_LIMIT',

    # Cache timeouts
    'CACHE_TIMEOUT_SHORT',
    'CACHE_TIMEOUT_MEDIUM',
    'CACHE_TIMEOUT_LONG',

    # Scan types
    'SCAN_TYPE_VULNERABILITY',
    'SCAN_TYPE_COMPLIANCE',
    'SCAN_TYPE_CONFIGURATION',
    'SCAN_TYPE_WEB_APPLICATION',
    'SCAN_TYPE_NETWORK',
    'SCAN_TYPE_CONTAINER',
    'SCAN_TYPE_CODE',
    'SCAN_TYPE_SECURITY_POSTURE',
    'SCAN_TYPE_PENETRATION',
    'SCAN_TYPE_IAM',
    'SCAN_TYPES',

    # Component status indicators
    'STATUS_HEALTHY',
    'STATUS_WARNING',
    'STATUS_ERROR',
    'STATUS_CRITICAL',
    'STATUS_UNKNOWN',

    # Metric labels
    'METRIC_LABEL_SEVERITY',
    'METRIC_LABEL_STATUS',
    'METRIC_LABEL_TYPE',

    # Cache keys
    'CACHE_KEY_BASELINE_STATUS',
    'CACHE_KEY_INTEGRITY_CHECK',
    'CACHE_KEY_SECURITY_METRICS',
    'CACHE_KEY_SECURITY_STATUS',

    # Default paths
    'DEFAULT_BASELINE_PATH',
    'DEFAULT_BACKUP_PATH_TEMPLATE'
]
