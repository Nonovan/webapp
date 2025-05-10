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

__version__ = "0.1.0"
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

# File size limits
SMALL_FILE_THRESHOLD: Final[int] = 10240  # 10KB
DEFAULT_MAX_FILE_SIZE: Final[int] = 50 * 1024 * 1024  # 50MB
MAX_CONFIG_FILE_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB

# Backup and rotation
DEFAULT_BACKUP_COUNT: Final[int] = 5
DEFAULT_LOG_ROTATION_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB
BACKUP_TIMESTAMP_FORMAT: Final[str] = "%Y%m%d%H%M%S"
MAX_BASELINE_BACKUPS: Final[int] = 10

# ============================================================================
# Cryptography Constants
# ============================================================================

# Hashing algorithms
DEFAULT_HASH_ALGORITHM: Final[str] = "sha256"
LEGACY_HASH_ALGORITHM: Final[str] = "sha1"  # For backwards compatibility only
SUPPORTED_HASH_ALGORITHMS: Final[List[str]] = ["sha256", "sha384", "sha512", "blake2b"]

# Hmac settings
HMAC_ALGORITHM: Final[str] = "sha256"
HMAC_DIGEST_SIZE: Final[int] = 32  # bytes

# Entropy sources
DEFAULT_ENTROPY_BITS: Final[int] = 256
DEFAULT_TOKEN_LENGTH: Final[int] = 32

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

# Default timezone
DEFAULT_TIMEZONE: Final[str] = "UTC"

# Time intervals
SECONDS_PER_MINUTE: Final[int] = 60
SECONDS_PER_HOUR: Final[int] = 3600
SECONDS_PER_DAY: Final[int] = 86400
SECONDS_PER_WEEK: Final[int] = 604800
SECONDS_PER_MONTH: Final[int] = 2592000  # 30 days
SECONDS_PER_YEAR: Final[int] = 31536000  # 365 days

# ============================================================================
# Validation Constants
# ============================================================================

# Length validation
MAX_PATH_LENGTH: Final[int] = 4096
MAX_FILENAME_LENGTH: Final[int] = 255
MAX_URL_LENGTH: Final[int] = 2083
MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_INPUT_LENGTH: Final[int] = 1048576  # 1MB for general inputs

# Pattern Constants - many of these are already imported from validation.py
EMAIL_PATTERN: Final[str] = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
URL_PATTERN: Final[str] = r'^https?://(?:[\w-]+\.)+[a-z]{2,}(?:/[\w.-]*)*/?$'
HOSTNAME_PATTERN: Final[str] = r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
UUID_PATTERN: Final[str] = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SLUG_PATTERN: Final[str] = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
SAFE_FILENAME_PATTERN: Final[str] = r'^[a-zA-Z0-9][a-zA-Z0-9\._\-]+$'

# Common file patterns for filename matching
PYTHON_FILES: Final[str] = "*.py"
CONFIG_FILES: Final[List[str]] = ["*.ini", "*.json", "*.yaml", "*.yml", "*.toml", "*.xml"]
SCRIPT_FILES: Final[List[str]] = ["*.sh", "*.bash", "*.py", "*.pl", "*.rb"]
EXCLUDED_FILES: Final[List[str]] = ["*.pyc", "*.pyo", "__pycache__/*", "*.log", "*.tmp"]

# Sensitive fields for data masking - to be used with obfuscate_sensitive_data
SENSITIVE_FIELDS: Final[FrozenSet[str]] = frozenset([
    'password', 'passwd', 'secret', 'token', 'api_key', 'key', 'auth',
    'credential', 'cred', 'private', 'access_token', 'refresh_token',
    'secret_key', 'jwt', 'certificate', 'passphrase', 'salt', 'hash',
    'pin', 'ssn', 'credit_card', 'cc_number', 'cvv', 'social_security'
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

# Log categories
SECURITY_LOG_CATEGORY: Final[str] = "security"
AUDIT_LOG_CATEGORY: Final[str] = "audit"
SYSTEM_LOG_CATEGORY: Final[str] = "system"
FILE_INTEGRITY_LOG_CATEGORY: Final[str] = "file_integrity"

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

# ============================================================================
# System Operation Constants
# ============================================================================

# Default timeouts (seconds)
DEFAULT_TIMEOUT: Final[int] = 30
DEFAULT_CONNECT_TIMEOUT: Final[int] = 5
DEFAULT_READ_TIMEOUT: Final[int] = 30
DEFAULT_PROCESS_TIMEOUT: Final[int] = 60
DEFAULT_LOCK_TIMEOUT: Final[int] = 10

# Resource limits
DEFAULT_MAX_PROCESSES: Final[int] = 10
DEFAULT_MAX_THREADS: Final[int] = 20
DEFAULT_MAX_CONNECTIONS: Final[int] = 100
DEFAULT_MAX_OPEN_FILES: Final[int] = 1000

# Performance thresholds
CPU_WARNING_THRESHOLD: Final[float] = 80.0  # percentage
MEMORY_WARNING_THRESHOLD: Final[float] = 85.0  # percentage
DISK_WARNING_THRESHOLD: Final[float] = 90.0  # percentage
OPEN_FILES_WARNING_THRESHOLD: Final[float] = 85.0  # percentage

# Monitoring intervals
DEFAULT_MONITOR_INTERVAL: Final[int] = 60  # seconds
DEFAULT_SLOW_THRESHOLD: Final[float] = 1.0  # seconds for slow operations

# ============================================================================
# String Operation Constants
# ============================================================================

# String operations
DEFAULT_TRUNCATE_LENGTH: Final[int] = 100
DEFAULT_EXCERPT_LENGTH: Final[int] = 150
DEFAULT_RANDOM_STRING_LENGTH: Final[int] = 16
DEFAULT_RANDOM_STRING_CHARS: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SECURE_RANDOM_STRING_CHARS: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?`~"

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
    'SMALL_FILE_THRESHOLD',
    'DEFAULT_MAX_FILE_SIZE',
    'MAX_CONFIG_FILE_SIZE',
    'DEFAULT_BACKUP_COUNT',
    'DEFAULT_LOG_ROTATION_SIZE',
    'BACKUP_TIMESTAMP_FORMAT',
    'MAX_BASELINE_BACKUPS',

    # Cryptography constants
    'DEFAULT_HASH_ALGORITHM',
    'LEGACY_HASH_ALGORITHM',
    'SUPPORTED_HASH_ALGORITHMS',
    'HMAC_ALGORITHM',
    'HMAC_DIGEST_SIZE',
    'DEFAULT_ENTROPY_BITS',
    'DEFAULT_TOKEN_LENGTH',

    # Date and time constants
    'DEFAULT_DATE_FORMAT',
    'DEFAULT_TIME_FORMAT',
    'DEFAULT_DATETIME_FORMAT',
    'ISO_DATETIME_FORMAT',
    'LOG_TIMESTAMP_FORMAT',
    'FILENAME_TIMESTAMP_FORMAT',
    'HUMAN_READABLE_FORMAT',
    'DEFAULT_TIMEZONE',
    'SECONDS_PER_MINUTE',
    'SECONDS_PER_HOUR',
    'SECONDS_PER_DAY',
    'SECONDS_PER_WEEK',
    'SECONDS_PER_MONTH',
    'SECONDS_PER_YEAR',

    # Validation constants
    'MAX_PATH_LENGTH',
    'MAX_FILENAME_LENGTH',
    'MAX_URL_LENGTH',
    'MIN_PASSWORD_LENGTH',
    'MAX_INPUT_LENGTH',
    'EMAIL_PATTERN',
    'URL_PATTERN',
    'HOSTNAME_PATTERN',
    'UUID_PATTERN',
    'SLUG_PATTERN',
    'SAFE_FILENAME_PATTERN',
    'PYTHON_FILES',
    'CONFIG_FILES',
    'SCRIPT_FILES',
    'EXCLUDED_FILES',
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
    'SECURITY_LOG_CATEGORY',
    'AUDIT_LOG_CATEGORY',
    'SYSTEM_LOG_CATEGORY',
    'FILE_INTEGRITY_LOG_CATEGORY',

    # Collection operation constants
    'DEFAULT_BATCH_SIZE',
    'DEFAULT_PAGE_SIZE',
    'MAX_PAGE_SIZE',
    'UNLIMITED_DEPTH',
    'DEFAULT_RECURSION_LIMIT',
    'MAX_DICT_DEPTH',
    'PATH_SEPARATOR',
    'ARRAY_INDEX_PATTERN',
    'SAFE_JSON_SPECIAL_TYPES',

    # System operation constants
    'DEFAULT_TIMEOUT',
    'DEFAULT_CONNECT_TIMEOUT',
    'DEFAULT_READ_TIMEOUT',
    'DEFAULT_PROCESS_TIMEOUT',
    'DEFAULT_LOCK_TIMEOUT',
    'DEFAULT_MAX_PROCESSES',
    'DEFAULT_MAX_THREADS',
    'DEFAULT_MAX_CONNECTIONS',
    'DEFAULT_MAX_OPEN_FILES',
    'CPU_WARNING_THRESHOLD',
    'MEMORY_WARNING_THRESHOLD',
    'DISK_WARNING_THRESHOLD',
    'OPEN_FILES_WARNING_THRESHOLD',
    'DEFAULT_MONITOR_INTERVAL',
    'DEFAULT_SLOW_THRESHOLD',

    # String operation constants
    'DEFAULT_TRUNCATE_LENGTH',
    'DEFAULT_EXCERPT_LENGTH',
    'DEFAULT_RANDOM_STRING_LENGTH',
    'DEFAULT_RANDOM_STRING_CHARS',
    'SECURE_RANDOM_STRING_CHARS',
    'DEFAULT_ALLOWED_TAGS',
    'DEFAULT_ALLOWED_ATTRIBUTES',
    'ASCII_LOWERCASE',
    'ASCII_UPPERCASE',
    'ASCII_LETTERS',
    'DIGITS',
    'HEXDIGITS',
]
