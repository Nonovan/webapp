"""
Administrative System Constants.

This module defines global constants used across the administrative utilities,
including error codes, timeout values, and system-wide defaults. These constants
ensure consistent behavior across all administrative components.
"""

# Exit codes for CLI tools and scripts
EXIT_SUCCESS = 0
EXIT_ERROR = 1  # Generic error
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_CONFIGURATION_ERROR = 6
EXIT_OPERATION_CANCELLED = 7
EXIT_CONNECTIVITY_ERROR = 8
EXIT_TIMEOUT_ERROR = 9
EXIT_EXTERNAL_SERVICE_ERROR = 10

# Standard timeouts (in seconds)
DEFAULT_OPERATION_TIMEOUT = 60
DEFAULT_NETWORK_TIMEOUT = 30
DEFAULT_API_REQUEST_TIMEOUT = 15
DEFAULT_DATABASE_OPERATION_TIMEOUT = 10
DEFAULT_LOCK_TIMEOUT = 30
DEFAULT_SESSION_TIMEOUT = 3600  # 1 hour

# Resource limits
DEFAULT_API_RATE_LIMIT = 100  # Requests per minute
DEFAULT_BATCH_SIZE = 1000
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0  # Base delay in seconds
DEFAULT_MAX_RESULTS = 10000

# File paths
DEFAULT_CONFIG_PATH = "/etc/cloud-platform/admin"
DEFAULT_LOG_PATH = "/var/log/cloud-platform/admin"
DEFAULT_BACKUP_PATH = "/var/backups/cloud-platform/admin"
DEFAULT_TEMP_PATH = "/tmp/cloud-platform/admin"

# Security settings
DEFAULT_PASSWORD_MIN_LENGTH = 12
DEFAULT_MFA_TIMEOUT = 300  # 5 minutes
DEFAULT_TOKEN_EXPIRY = 86400  # 24 hours in seconds
DEFAULT_EMERGENCY_ACCESS_DURATION = 3600  # 1 hour

# Default formats
DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_ISO_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_DATE_FORMAT = "%Y-%m-%d"

# Retry strategy
RETRY_BACKOFF_FACTOR = 2.0
RETRY_MAX_BACKOFF = 30.0  # Maximum backoff in seconds
RETRY_JITTER_FACTOR = 0.1  # Random jitter to add to retry delay
