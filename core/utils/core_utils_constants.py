"""
Core Utility Constants for Cloud Infrastructure Platform.

This module centralizes constants used across utility modules within the core/utils
package, providing consistent values for file operations, validations, timeouts,
formatting options, and other common utility operations.

These constants ensure consistent behavior across all utility functions and
simplify future updates by providing a single source of truth for configuration values.
"""

import os
import re
from typing import Dict, FrozenSet, List, Tuple, Final, Pattern

# ============================================================================
# Version Information
# ============================================================================

__version__ = "0.1.1"
__author__ = "Cloud Infrastructure Platform Team"
__description__ = "Core Utility Constants for Cloud Infrastructure Platform"

# ============================================================================
# File Operation Constants
# ============================================================================

# Default chunk size for reading files
DEFAULT_CHUNK_SIZE: Final[int] = 8192  # 8KB

# File permissions (POSIX)
DEFAULT_FILE_PERMS: Final[int] = 0o644  # Owner read/write, group/others read
DEFAULT_DIR_PERMS: Final[int] = 0o755   # Owner read/write/execute, group/others read/execute
SECURE_FILE_PERMS: Final[int] = 0o600   # Owner read/write only
SECURE_DIR_PERMS: Final[int] = 0o700    # Owner read/write/execute only
LOG_FILE_PERMS: Final[int] = 0o640      # Owner read/write, group read
LOG_DIR_PERMS: Final[int] = 0o750       # Owner read/write/execute, group read/execute
TEMP_DIR_PERMS: Final[int] = 0o700      # Secure temporary directories
CONFIG_FILE_PERMS: Final[int] = 0o640   # Config files: owner r/w, group read
CERT_FILE_PERMS: Final[int] = 0o400     # Certificate files: owner read only

# File size limits
SMALL_FILE_THRESHOLD: Final[int] = 10240  # 10KB
DEFAULT_MAX_FILE_SIZE: Final[int] = 50 * 1024 * 1024  # 50MB
MAX_CONFIG_FILE_SIZE: Final[int] = 10 * 1024 * 1024   # 10MB
MAX_LOG_FILE_SIZE: Final[int] = 100 * 1024 * 1024     # 100MB
MAX_UPLOAD_SIZE: Final[int] = 16 * 1024 * 1024        # 16MB - Common upload limit

# Backup and rotation
DEFAULT_BACKUP_COUNT: Final[int] = 5
MAX_BACKUP_COUNT: Final[int] = 10       # Maximum number of backups to keep
DEFAULT_LOG_ROTATION_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB
BACKUP_TIMESTAMP_FORMAT: Final[str] = "%Y%m%d%H%M%S"
MAX_BASELINE_BACKUPS: Final[int] = 10

# File patterns
FILE_INTEGRITY_PATTERNS: Final[Dict[str, List[str]]] = {
    'critical': [
        'core/security/*.py',
        'app.py',
        'config.py',
        'core/middleware.py'
    ],
    'high': [
        'api/*.py',
        'models/*.py',
        'core/*.py',
        'config/*.ini',
        'config/*.json',
        'config/*.yaml'
    ],
    'medium': [
        'blueprints/*.py',
        'services/*.py',
        'templates/*.html',
        'static/js/*.js'
    ],
    'low': [
        'static/css/*.css',
        'static/img/*',
        'docs/*'
    ]
}

EXCLUDED_PATTERNS: Final[List[str]] = [
    '*.pyc',
    '__pycache__/*',
    '*.log',
    '*.tmp',
    '.git/*',
    'venv/*',
    'node_modules/*',
    '*.bak',
    '*.swp'
]

# ============================================================================
# Cryptography Constants
# ============================================================================

# Hashing algorithms
DEFAULT_HASH_ALGORITHM: Final[str] = "sha256"
LEGACY_HASH_ALGORITHM: Final[str] = "sha1"  # For backwards compatibility only
SUPPORTED_HASH_ALGORITHMS: Final[List[str]] = ["sha256", "sha384", "sha512", "blake2b"]
HASH_ALGORITHM_SECURITY: Final[Dict[str, int]] = {
    "md5": 0,       # Insecure
    "sha1": 1,      # Deprecated
    "sha256": 3,    # Recommended minimum
    "sha384": 4,    # Strong
    "sha512": 5,    # Very strong
    "blake2b": 5    # Very strong
}

# Hmac settings
HMAC_ALGORITHM: Final[str] = "sha256"
HMAC_DIGEST_SIZE: Final[int] = 32  # bytes

# Entropy sources
DEFAULT_ENTROPY_BITS: Final[int] = 256
DEFAULT_TOKEN_LENGTH: Final[int] = 32
SECURE_TOKEN_LENGTH: Final[int] = 64
SESSION_TOKEN_LENGTH: Final[int] = 32
API_KEY_LENGTH: Final[int] = 48

# Encryption constants
DEFAULT_KEY_SIZE: Final[int] = 32     # AES-256
DEFAULT_IV_SIZE: Final[int] = 16      # 128 bits
DEFAULT_SALT_SIZE: Final[int] = 16    # 128 bits
AES_BLOCK_SIZE: Final[int] = 16       # 128 bits
DEFAULT_PBKDF2_ITERATIONS: Final[int] = 600000  # OWASP recommended minimum

# ============================================================================
# Date and Time Constants
# ============================================================================

# Default format strings
DEFAULT_DATE_FORMAT: Final[str] = "%Y-%m-%d"
DEFAULT_TIME_FORMAT: Final[str] = "%H:%M:%S"
DEFAULT_DATETIME_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
ISO_DATETIME_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"
LOG_TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S.%f%z"
FILENAME_TIMESTAMP_FORMAT: Final[str] = "%Y%m%d%H%M%S"
HUMAN_READABLE_FORMAT: Final[str] = "%B %d, %Y at %H:%M"
HTTP_DATE_FORMAT: Final[str] = "%a, %d %b %Y %H:%M:%S GMT"  # RFC 7231 format

# Default timezone
DEFAULT_TIMEZONE: Final[str] = "UTC"

# Time intervals in seconds
SECONDS_PER_MINUTE: Final[int] = 60
SECONDS_PER_HOUR: Final[int] = 3600
SECONDS_PER_DAY: Final[int] = 86400
SECONDS_PER_WEEK: Final[int] = 604800
SECONDS_PER_MONTH: Final[int] = 2592000  # 30 days
SECONDS_PER_YEAR: Final[int] = 31536000  # 365 days

# Common durations
DEFAULT_SESSION_DURATION: Final[int] = 3600        # 1 hour
DEFAULT_TOKEN_EXPIRY: Final[int] = 86400           # 24 hours
DEFAULT_REFRESH_TOKEN_EXPIRY: Final[int] = 2592000 # 30 days
DEFAULT_CACHE_DURATION: Final[int] = 300           # 5 minutes
DEFAULT_SHORT_CACHE_DURATION: Final[int] = 60      # 1 minute
DEFAULT_LONG_CACHE_DURATION: Final[int] = 3600     # 1 hour

# ============================================================================
# Validation Constants
# ============================================================================

# Length validation
MAX_PATH_LENGTH: Final[int] = 4096
MAX_FILENAME_LENGTH: Final[int] = 255
MAX_URL_LENGTH: Final[int] = 2083
MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_PASSWORD_LENGTH: Final[int] = 128
MAX_INPUT_LENGTH: Final[int] = 1048576  # 1MB for general inputs
MAX_USERNAME_LENGTH: Final[int] = 64
MIN_USERNAME_LENGTH: Final[int] = 3
MAX_EMAIL_LENGTH: Final[int] = 254      # RFC 5321 SMTP limit

# Pattern Constants - many of these are already imported from validation.py
EMAIL_PATTERN: Final[str] = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
URL_PATTERN: Final[str] = r'^https?://(?:[\w-]+\.)+[a-z]{2,}(?:/[\w.-]*)*/?$'
HOSTNAME_PATTERN: Final[str] = r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
UUID_PATTERN: Final[str] = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SLUG_PATTERN: Final[str] = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
SAFE_FILENAME_PATTERN: Final[str] = r'^[a-zA-Z0-9][a-zA-Z0-9\._\-]+$'
IPV4_PATTERN: Final[str] = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
STRONG_PASSWORD_PATTERN: Final[str] = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?]).{12,}$'
API_KEY_PATTERN: Final[str] = r'^[A-Za-z0-9_-]{32,}$'
USERNAME_PATTERN: Final[str] = r'^[a-zA-Z0-9_][a-zA-Z0-9_.-]{2,63}$'
DOMAIN_PATTERN: Final[str] = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

# Common file patterns for filename matching
PYTHON_FILES: Final[str] = "*.py"
CONFIG_FILES: Final[List[str]] = ["*.ini", "*.json", "*.yaml", "*.yml", "*.toml", "*.xml", "*.env"]
SCRIPT_FILES: Final[List[str]] = ["*.sh", "*.bash", "*.py", "*.pl", "*.rb"]
EXCLUDED_FILES: Final[List[str]] = ["*.pyc", "*.pyo", "__pycache__/*", "*.log", "*.tmp", "*.bak", "*.swp", "*.~"]

# Allowed and safe extensions
ALLOWED_IMAGE_EXTENSIONS: Final[FrozenSet[str]] = frozenset(['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp'])
ALLOWED_DOCUMENT_EXTENSIONS: Final[FrozenSet[str]] = frozenset(['.pdf', '.txt', '.md', '.csv', '.xlsx', '.docx', '.pptx'])
DANGEROUS_EXTENSIONS: Final[FrozenSet[str]] = frozenset(['.exe', '.dll', '.bat', '.sh', '.com', '.js', '.php', '.py'])

# Sensitive fields for data masking - to be used with obfuscate_sensitive_data
SENSITIVE_FIELDS: Final[FrozenSet[str]] = frozenset([
    'password', 'passwd', 'secret', 'token', 'api_key', 'key', 'auth',
    'credential', 'cred', 'private', 'access_token', 'refresh_token',
    'secret_key', 'jwt', 'certificate', 'passphrase', 'salt', 'hash',
    'pin', 'ssn', 'credit_card', 'cc_number', 'cvv', 'social_security',
    'bank_account', 'routing_number', 'address', 'dob', 'birth_date'
])

# ============================================================================
# Logging Constants
# ============================================================================

# Log levels
LOG_LEVEL_DEBUG: Final[str] = "DEBUG"
LOG_LEVEL_INFO: Final[str] = "INFO"
LOG_LEVEL_WARNING: Final[str] = "WARNING"
LOG_LEVEL_ERROR: Final[str] = "ERROR"
LOG_LEVEL_CRITICAL: Final[str] = "CRITICAL"

# Default log formats
DEFAULT_LOG_FORMAT: Final[str] = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
SIMPLE_LOG_FORMAT: Final[str] = '%(levelname)s: %(message)s'
JSON_LOG_FORMAT: Final[Dict[str, str]] = {
    'timestamp': '%(asctime)s',
    'level': '%(levelname)s',
    'module': '%(module)s',
    'message': '%(message)s',
    'logger': '%(name)s',
    'file': '%(pathname)s',
    'line': '%(lineno)d',
    'function': '%(funcName)s',
}
CLI_LOG_FORMAT: Final[str] = '[%(asctime)s] %(levelname)s: %(message)s'
SECURITY_LOG_FORMAT: Final[str] = '[%(asctime)s] SECURITY %(levelname)s: %(message)s'

# Log categories
SECURITY_LOG_CATEGORY: Final[str] = "security"
AUDIT_LOG_CATEGORY: Final[str] = "audit"
SYSTEM_LOG_CATEGORY: Final[str] = "system"
FILE_INTEGRITY_LOG_CATEGORY: Final[str] = "file_integrity"
PERFORMANCE_LOG_CATEGORY: Final[str] = "performance"
ACCESS_LOG_CATEGORY: Final[str] = "access"
ERROR_LOG_CATEGORY: Final[str] = "error"

# Audit event types
AUDIT_EVENT_LOGIN: Final[str] = "user_login"
AUDIT_EVENT_LOGOUT: Final[str] = "user_logout"
AUDIT_EVENT_LOGIN_FAILED: Final[str] = "login_failed"
AUDIT_EVENT_PASSWORD_CHANGE: Final[str] = "password_change"
AUDIT_EVENT_USER_CREATE: Final[str] = "user_create"
AUDIT_EVENT_USER_UPDATE: Final[str] = "user_update"
AUDIT_EVENT_USER_DELETE: Final[str] = "user_delete"
AUDIT_EVENT_PERMISSION_CHANGE: Final[str] = "permission_change"
AUDIT_EVENT_RESOURCE_ACCESS: Final[str] = "resource_access"
AUDIT_EVENT_RESOURCE_CREATE: Final[str] = "resource_create"
AUDIT_EVENT_RESOURCE_UPDATE: Final[str] = "resource_update"
AUDIT_EVENT_RESOURCE_DELETE: Final[str] = "resource_delete"
AUDIT_EVENT_CONFIG_CHANGE: Final[str] = "config_change"
AUDIT_EVENT_SECURITY_CHANGE: Final[str] = "security_change"

# File integrity events
INTEGRITY_EVENT_BASELINE_CREATED: Final[str] = "baseline_created"
INTEGRITY_EVENT_BASELINE_UPDATED: Final[str] = "baseline_updated"
INTEGRITY_EVENT_FILE_CHANGED: Final[str] = "file_changed"
INTEGRITY_EVENT_FILE_MISSING: Final[str] = "file_missing"
INTEGRITY_EVENT_NEW_FILE: Final[str] = "new_file"
INTEGRITY_EVENT_PERMISSION_CHANGED: Final[str] = "permission_changed"

# ============================================================================
# Collection Operation Constants
# ============================================================================

# Collection operations
DEFAULT_BATCH_SIZE: Final[int] = 1000
DEFAULT_PAGE_SIZE: Final[int] = 25
MAX_PAGE_SIZE: Final[int] = 100
UNLIMITED_DEPTH: Final[int] = -1
DEFAULT_RECURSION_LIMIT: Final[int] = 100
MAX_DICT_DEPTH: Final[int] = 50
DEFAULT_LIST_LIMIT: Final[int] = 1000

# Dictionary paths
PATH_SEPARATOR: Final[str] = "."
ARRAY_INDEX_PATTERN: Final[Pattern] = re.compile(r'^(\w+)\[(\d+)\]$')

# Serialization
SAFE_JSON_SPECIAL_TYPES: Final[Dict[str, str]] = {
    "<class 'datetime.datetime'>": "datetime",
    "<class 'datetime.date'>": "date",
    "<class 'uuid.UUID'>": "uuid",
    "<class 'bytes'>": "bytes",
    "<class 'set'>": "set",
    "<class 'frozenset'>": "frozenset"
}

# Output formats
OUTPUT_FORMAT_JSON: Final[str] = "json"
OUTPUT_FORMAT_YAML: Final[str] = "yaml"
OUTPUT_FORMAT_CSV: Final[str] = "csv"
OUTPUT_FORMAT_TABLE: Final[str] = "table"
OUTPUT_FORMAT_TEXT: Final[str] = "text"

# ============================================================================
# System Operation Constants
# ============================================================================

# Default timeouts (seconds)
DEFAULT_TIMEOUT: Final[int] = 30
DEFAULT_CONNECT_TIMEOUT: Final[int] = 5
DEFAULT_READ_TIMEOUT: Final[int] = 30
DEFAULT_PROCESS_TIMEOUT: Final[int] = 60
DEFAULT_LOCK_TIMEOUT: Final[int] = 10
DEFAULT_API_TIMEOUT: Final[int] = 10
DEFAULT_DATABASE_TIMEOUT: Final[int] = 30
DEFAULT_CACHE_TIMEOUT: Final[int] = 5
DEFAULT_RECOVERY_TIMEOUT: Final[int] = 300  # 5 minutes for recovery operations

# Resource limits
DEFAULT_MAX_PROCESSES: Final[int] = 10
DEFAULT_MAX_THREADS: Final[int] = 20
DEFAULT_MAX_CONNECTIONS: Final[int] = 100
DEFAULT_MAX_OPEN_FILES: Final[int] = 1000
DEFAULT_MAX_RETRIES: Final[int] = 3
DEFAULT_BACKOFF_FACTOR: Final[float] = 0.5
DEFAULT_RETRY_DELAY: Final[int] = 1  # 1 second initial retry delay
DEFAULT_MAX_RETRY_DELAY: Final[int] = 30  # Maximum retry delay in seconds
DEFAULT_JITTER_FACTOR: Final[float] = 0.1  # Add 10% jitter to retry times

# Performance thresholds
CPU_WARNING_THRESHOLD: Final[float] = 80.0  # percentage
MEMORY_WARNING_THRESHOLD: Final[float] = 85.0  # percentage
DISK_WARNING_THRESHOLD: Final[float] = 90.0  # percentage
OPEN_FILES_WARNING_THRESHOLD: Final[float] = 85.0  # percentage
CPU_CRITICAL_THRESHOLD: Final[float] = 90.0  # percentage
MEMORY_CRITICAL_THRESHOLD: Final[float] = 95.0  # percentage
DISK_CRITICAL_THRESHOLD: Final[float] = 95.0  # percentage

# Monitoring intervals
DEFAULT_MONITOR_INTERVAL: Final[int] = 60  # seconds
DEFAULT_SLOW_THRESHOLD: Final[float] = 1.0  # seconds for slow operations
DEFAULT_VERY_SLOW_THRESHOLD: Final[float] = 5.0  # seconds for very slow operations

# Health check constants
HEALTH_STATUS_HEALTHY: Final[str] = "healthy"
HEALTH_STATUS_DEGRADED: Final[str] = "degraded"
HEALTH_STATUS_UNHEALTHY: Final[str] = "unhealthy"
HEALTH_STATUS_UNKNOWN: Final[str] = "unknown"

# ============================================================================
# String Operation Constants
# ============================================================================

# String operations
DEFAULT_TRUNCATE_LENGTH: Final[int] = 100
DEFAULT_EXCERPT_LENGTH: Final[int] = 150
DEFAULT_RANDOM_STRING_LENGTH: Final[int] = 16
DEFAULT_RANDOM_STRING_CHARS: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SECURE_RANDOM_STRING_CHARS: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?`~"
DEFAULT_TRUNCATE_SUFFIX: Final[str] = "..."
DEFAULT_SLUG_SEPARATOR: Final[str] = "-"
DEFAULT_SLUG_LOWERCASE: Final[bool] = True
DEFAULT_SLUG_STRIP_DIACRITICS: Final[bool] = True

# HTML-related constants
DEFAULT_ALLOWED_TAGS: Final[List[str]] = ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'code']
DEFAULT_ALLOWED_ATTRIBUTES: Final[Dict[str, List[str]]] = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'div': ['class', 'id'],
    'span': ['class', 'id'],
    'p': ['class', 'id'],
    'pre': ['class', 'id'],
    'code': ['class', 'id'],
    '*': ['class', 'id']
}

# Character sets
ASCII_LOWERCASE: Final[str] = 'abcdefghijklmnopqrstuvwxyz'
ASCII_UPPERCASE: Final[str] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ASCII_LETTERS: Final[str] = ASCII_LOWERCASE + ASCII_UPPERCASE
DIGITS: Final[str] = '0123456789'
HEXDIGITS: Final[str] = '0123456789abcdefABCDEF'
ALPHANUMERIC: Final[str] = ASCII_LETTERS + DIGITS
PUNCTUATION: Final[str] = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

# ============================================================================
# Cloud Provider Constants
# ============================================================================

# Common cloud patterns
AWS_REGION_PATTERN: Final[str] = r'^(us|eu|ap|sa|ca|me|af)-(north|south|east|west|central)-\d$'
AZURE_REGION_PATTERN: Final[str] = r'^(eastus|westus|centralus|northcentralus|southcentralus|westcentralus|eastus2|westus2|westus3|australiaeast|australiasoutheast|brazilsouth|canadacentral|canadaeast|centralindia|eastasia|japaneast|japanwest|koreacentral|northeurope|southeastasia|southindia|uksouth|ukwest|westeurope|francecentral|germanywestcentral|norwayeast|switzerlandnorth|uaenorth|southafricanorth|swedencentral)$'
GCP_REGION_PATTERN: Final[str] = r'^(asia|australia|europe|northamerica|southamerica|us|africa)-(east|west|north|south|central|northeast|southeast|northwest|southwest)\d$'
ONPREM_REGION_PATTERN: Final[str] = r'^(datacenter|dc|region)-[a-z0-9]+$'

AWS_RESOURCE_ID_PATTERN: Final[str] = r'^(i|vpc|subnet|sg|ami|vol|snap|eni|eip|rtb|acl|igw|vgw|nat|dopt|pcx|vpn)-[0-9a-f]{8}$'
AZURE_RESOURCE_ID_PATTERN: Final[str] = r'^/subscriptions/[\w-]+/resourceGroups/[\w-]+/providers/[^/]+/[^/]+/[\w-]+$'
GCP_RESOURCE_ID_PATTERN: Final[str] = r'^projects/[^/]+/[^/]+/[^/]+/[\w-]+$'
SERVICE_NAME_PATTERN: Final[str] = r'^[a-z][a-z0-9-]{3,63}$'

# ============================================================================
# Exit Code Constants
# ============================================================================

# Standard exit codes
EXIT_SUCCESS: Final[int] = 0
EXIT_ERROR: Final[int] = 1
EXIT_PERMISSION_ERROR: Final[int] = 2
EXIT_VALIDATION_ERROR: Final[int] = 3
EXIT_RESOURCE_ERROR: Final[int] = 4
EXIT_CONFIGURATION_ERROR: Final[int] = 5
EXIT_OPERATION_CANCELLED: Final[int] = 6
EXIT_DEPENDENCY_ERROR: Final[int] = 7
EXIT_CONNECTIVITY_ERROR: Final[int] = 8
EXIT_TIMEOUT_ERROR: Final[int] = 9
EXIT_SECURITY_ERROR: Final[int] = 10

# ============================================================================
# Environment Constants
# ============================================================================

# Environment names
ENVIRONMENT_DEVELOPMENT: Final[str] = "development"
ENVIRONMENT_TESTING: Final[str] = "testing"
ENVIRONMENT_STAGING: Final[str] = "staging"
ENVIRONMENT_PRODUCTION: Final[str] = "production"
ENVIRONMENT_DR_RECOVERY: Final[str] = "dr-recovery"

# ============================================================================
# Export Constants
# ============================================================================

__all__ = [
    # Version information
    '__version__',
    '__author__',
    '__description__',

    # File operation constants
    'DEFAULT_CHUNK_SIZE',
    'DEFAULT_FILE_PERMS',
    'DEFAULT_DIR_PERMS',
    'SECURE_FILE_PERMS',
    'SECURE_DIR_PERMS',
    'LOG_FILE_PERMS',
    'LOG_DIR_PERMS',
    'TEMP_DIR_PERMS',
    'CONFIG_FILE_PERMS',
    'CERT_FILE_PERMS',
    'SMALL_FILE_THRESHOLD',
    'DEFAULT_MAX_FILE_SIZE',
    'MAX_CONFIG_FILE_SIZE',
    'MAX_LOG_FILE_SIZE',
    'MAX_UPLOAD_SIZE',
    'DEFAULT_BACKUP_COUNT',
    'MAX_BACKUP_COUNT',
    'DEFAULT_LOG_ROTATION_SIZE',
    'BACKUP_TIMESTAMP_FORMAT',
    'MAX_BASELINE_BACKUPS',
    'FILE_INTEGRITY_PATTERNS',
    'EXCLUDED_PATTERNS',

    # Cryptography constants
    'DEFAULT_HASH_ALGORITHM',
    'LEGACY_HASH_ALGORITHM',
    'SUPPORTED_HASH_ALGORITHMS',
    'HASH_ALGORITHM_SECURITY',
    'HMAC_ALGORITHM',
    'HMAC_DIGEST_SIZE',
    'DEFAULT_ENTROPY_BITS',
    'DEFAULT_TOKEN_LENGTH',
    'SECURE_TOKEN_LENGTH',
    'SESSION_TOKEN_LENGTH',
    'API_KEY_LENGTH',
    'DEFAULT_KEY_SIZE',
    'DEFAULT_IV_SIZE',
    'DEFAULT_SALT_SIZE',
    'AES_BLOCK_SIZE',
    'DEFAULT_PBKDF2_ITERATIONS',

    # Date and time constants
    'DEFAULT_DATE_FORMAT',
    'DEFAULT_TIME_FORMAT',
    'DEFAULT_DATETIME_FORMAT',
    'ISO_DATETIME_FORMAT',
    'LOG_TIMESTAMP_FORMAT',
    'FILENAME_TIMESTAMP_FORMAT',
    'HUMAN_READABLE_FORMAT',
    'HTTP_DATE_FORMAT',
    'DEFAULT_TIMEZONE',
    'SECONDS_PER_MINUTE',
    'SECONDS_PER_HOUR',
    'SECONDS_PER_DAY',
    'SECONDS_PER_WEEK',
    'SECONDS_PER_MONTH',
    'SECONDS_PER_YEAR',
    'DEFAULT_SESSION_DURATION',
    'DEFAULT_TOKEN_EXPIRY',
    'DEFAULT_REFRESH_TOKEN_EXPIRY',
    'DEFAULT_CACHE_DURATION',
    'DEFAULT_SHORT_CACHE_DURATION',
    'DEFAULT_LONG_CACHE_DURATION',

    # Validation constants
    'MAX_PATH_LENGTH',
    'MAX_FILENAME_LENGTH',
    'MAX_URL_LENGTH',
    'MIN_PASSWORD_LENGTH',
    'MAX_PASSWORD_LENGTH',
    'MAX_INPUT_LENGTH',
    'MAX_USERNAME_LENGTH',
    'MIN_USERNAME_LENGTH',
    'MAX_EMAIL_LENGTH',
    'EMAIL_PATTERN',
    'URL_PATTERN',
    'HOSTNAME_PATTERN',
    'UUID_PATTERN',
    'SLUG_PATTERN',
    'SAFE_FILENAME_PATTERN',
    'IPV4_PATTERN',
    'STRONG_PASSWORD_PATTERN',
    'API_KEY_PATTERN',
    'USERNAME_PATTERN',
    'DOMAIN_PATTERN',
    'PYTHON_FILES',
    'CONFIG_FILES',
    'SCRIPT_FILES',
    'EXCLUDED_FILES',
    'ALLOWED_IMAGE_EXTENSIONS',
    'ALLOWED_DOCUMENT_EXTENSIONS',
    'DANGEROUS_EXTENSIONS',
    'SENSITIVE_FIELDS',

    # Logging constants
    'LOG_LEVEL_DEBUG',
    'LOG_LEVEL_INFO',
    'LOG_LEVEL_WARNING',
    'LOG_LEVEL_ERROR',
    'LOG_LEVEL_CRITICAL',
    'DEFAULT_LOG_FORMAT',
    'SIMPLE_LOG_FORMAT',
    'JSON_LOG_FORMAT',
    'CLI_LOG_FORMAT',
    'SECURITY_LOG_FORMAT',
    'SECURITY_LOG_CATEGORY',
    'AUDIT_LOG_CATEGORY',
    'SYSTEM_LOG_CATEGORY',
    'FILE_INTEGRITY_LOG_CATEGORY',
    'PERFORMANCE_LOG_CATEGORY',
    'ACCESS_LOG_CATEGORY',
    'ERROR_LOG_CATEGORY',
    'AUDIT_EVENT_LOGIN',
    'AUDIT_EVENT_LOGOUT',
    'AUDIT_EVENT_LOGIN_FAILED',
    'AUDIT_EVENT_PASSWORD_CHANGE',
    'AUDIT_EVENT_USER_CREATE',
    'AUDIT_EVENT_USER_UPDATE',
    'AUDIT_EVENT_USER_DELETE',
    'AUDIT_EVENT_PERMISSION_CHANGE',
    'AUDIT_EVENT_RESOURCE_ACCESS',
    'AUDIT_EVENT_RESOURCE_CREATE',
    'AUDIT_EVENT_RESOURCE_UPDATE',
    'AUDIT_EVENT_RESOURCE_DELETE',
    'AUDIT_EVENT_CONFIG_CHANGE',
    'AUDIT_EVENT_SECURITY_CHANGE',
    'INTEGRITY_EVENT_BASELINE_CREATED',
    'INTEGRITY_EVENT_BASELINE_UPDATED',
    'INTEGRITY_EVENT_FILE_CHANGED',
    'INTEGRITY_EVENT_FILE_MISSING',
    'INTEGRITY_EVENT_NEW_FILE',
    'INTEGRITY_EVENT_PERMISSION_CHANGED',

    # Collection operation constants
    'DEFAULT_BATCH_SIZE',
    'DEFAULT_PAGE_SIZE',
    'MAX_PAGE_SIZE',
    'UNLIMITED_DEPTH',
    'DEFAULT_RECURSION_LIMIT',
    'MAX_DICT_DEPTH',
    'DEFAULT_LIST_LIMIT',
    'PATH_SEPARATOR',
    'ARRAY_INDEX_PATTERN',
    'SAFE_JSON_SPECIAL_TYPES',
    'OUTPUT_FORMAT_JSON',
    'OUTPUT_FORMAT_YAML',
    'OUTPUT_FORMAT_CSV',
    'OUTPUT_FORMAT_TABLE',
    'OUTPUT_FORMAT_TEXT',

    # System operation constants
    'DEFAULT_TIMEOUT',
    'DEFAULT_CONNECT_TIMEOUT',
    'DEFAULT_READ_TIMEOUT',
    'DEFAULT_PROCESS_TIMEOUT',
    'DEFAULT_LOCK_TIMEOUT',
    'DEFAULT_API_TIMEOUT',
    'DEFAULT_DATABASE_TIMEOUT',
    'DEFAULT_CACHE_TIMEOUT',
    'DEFAULT_RECOVERY_TIMEOUT',
    'DEFAULT_MAX_PROCESSES',
    'DEFAULT_MAX_THREADS',
    'DEFAULT_MAX_CONNECTIONS',
    'DEFAULT_MAX_OPEN_FILES',
    'DEFAULT_MAX_RETRIES',
    'DEFAULT_BACKOFF_FACTOR',
    'DEFAULT_RETRY_DELAY',
    'DEFAULT_MAX_RETRY_DELAY',
    'DEFAULT_JITTER_FACTOR',
    'CPU_WARNING_THRESHOLD',
    'MEMORY_WARNING_THRESHOLD',
    'DISK_WARNING_THRESHOLD',
    'OPEN_FILES_WARNING_THRESHOLD',
    'CPU_CRITICAL_THRESHOLD',
    'MEMORY_CRITICAL_THRESHOLD',
    'DISK_CRITICAL_THRESHOLD',
    'DEFAULT_MONITOR_INTERVAL',
    'DEFAULT_SLOW_THRESHOLD',
    'DEFAULT_VERY_SLOW_THRESHOLD',
    'HEALTH_STATUS_HEALTHY',
    'HEALTH_STATUS_DEGRADED',
    'HEALTH_STATUS_UNHEALTHY',
    'HEALTH_STATUS_UNKNOWN',

    # String operation constants
    'DEFAULT_TRUNCATE_LENGTH',
    'DEFAULT_EXCERPT_LENGTH',
    'DEFAULT_RANDOM_STRING_LENGTH',
    'DEFAULT_RANDOM_STRING_CHARS',
    'SECURE_RANDOM_STRING_CHARS',
    'DEFAULT_TRUNCATE_SUFFIX',
    'DEFAULT_SLUG_SEPARATOR',
    'DEFAULT_SLUG_LOWERCASE',
    'DEFAULT_SLUG_STRIP_DIACRITICS',
    'DEFAULT_ALLOWED_TAGS',
    'DEFAULT_ALLOWED_ATTRIBUTES',
    'ASCII_LOWERCASE',
    'ASCII_UPPERCASE',
    'ASCII_LETTERS',
    'DIGITS',
    'HEXDIGITS',
    'ALPHANUMERIC',
    'PUNCTUATION',

    # Cloud provider constants
    'AWS_REGION_PATTERN',
    'AZURE_REGION_PATTERN',
    'GCP_REGION_PATTERN',
    'ONPREM_REGION_PATTERN',
    'AWS_RESOURCE_ID_PATTERN',
    'AZURE_RESOURCE_ID_PATTERN',
    'GCP_RESOURCE_ID_PATTERN',
    'SERVICE_NAME_PATTERN',

    # Exit code constants
    'EXIT_SUCCESS',
    'EXIT_ERROR',
    'EXIT_PERMISSION_ERROR',
    'EXIT_VALIDATION_ERROR',
    'EXIT_RESOURCE_ERROR',
    'EXIT_CONFIGURATION_ERROR',
    'EXIT_OPERATION_CANCELLED',
    'EXIT_DEPENDENCY_ERROR',
    'EXIT_CONNECTIVITY_ERROR',
    'EXIT_TIMEOUT_ERROR',
    'EXIT_SECURITY_ERROR',

    # Environment constants
    'ENVIRONMENT_DEVELOPMENT',
    'ENVIRONMENT_TESTING',
    'ENVIRONMENT_STAGING',
    'ENVIRONMENT_PRODUCTION',
    'ENVIRONMENT_DR_RECOVERY',
]
