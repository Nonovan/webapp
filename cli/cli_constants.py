"""
CLI Constants for Cloud Infrastructure Platform.

This module centralizes constants used throughout the CLI components,
providing a single source of truth for command behaviors, error codes,
naming conventions, and security settings. Using these centralized
constants ensures consistent behavior across all CLI commands and
helps standardize the user experience.
"""

import os
from pathlib import Path
from typing import Dict, List, FrozenSet, Set, Any, Optional

#=====================================================================
# Environment Constants
#=====================================================================

# Environment names
ENVIRONMENT_DEVELOPMENT = 'development'
ENVIRONMENT_TESTING = 'testing'
ENVIRONMENT_STAGING = 'staging'
ENVIRONMENT_PRODUCTION = 'production'
ENVIRONMENT_DR_RECOVERY = 'dr-recovery'

# Set of allowed environments
ALLOWED_ENVIRONMENTS: FrozenSet[str] = frozenset([
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY
])

# Default environment
DEFAULT_ENVIRONMENT = ENVIRONMENT_DEVELOPMENT

#=====================================================================
# Exit Codes
#=====================================================================

# Standard exit codes for consistent CLI behavior
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2
EXIT_PERMISSION_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_RESOURCE_ERROR = 5
EXIT_CONFIGURATION_ERROR = 6
EXIT_CONNECTIVITY_ERROR = 7
EXIT_TIMEOUT_ERROR = 8
EXIT_OPERATION_CANCELLED = 9
EXIT_DEPENDENCY_ERROR = 10

#=====================================================================
# File and Directory Paths
#=====================================================================

# Base directories
CLI_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = CLI_DIR.parent

# Config directories
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/cloudplatform")
DEFAULT_CONFIG_FILE = "cli_config.json"
CONFIG_TEMPLATE_DIR = PROJECT_ROOT / "config" / "templates"

# Output directories
DEFAULT_OUTPUT_DIR = "./output"
DEFAULT_TEMP_DIR = "./tmp"
DEFAULT_BACKUP_DIR = "./backups"
DEFAULT_LOG_DIR = "./logs"

# File permission masks
CONFIG_FILE_PERMISSIONS = 0o600  # rw-------
LOG_FILE_PERMISSIONS = 0o640     # rw-r-----
BACKUP_DIR_PERMISSIONS = 0o700   # rwx------

#=====================================================================
# Security Constants
#=====================================================================

# Sensitive field names that should be masked in logs and outputs
SENSITIVE_FIELDS: Set[str] = {
    'password', 'token', 'secret', 'key', 'credential', 'auth',
    'api_key', 'private_key', 'certificate', 'passphrase',
    'access_key', 'access_token'
}

# File security settings
FILE_SECURITY_SETTINGS: Dict[str, Any] = {
    'MAX_FILE_SIZE': 100 * 1024 * 1024,  # 100 MB max file size
    'SECURE_UMASK': 0o077,               # Default umask for secure operations
    'MAX_PATH_LENGTH': 4096,             # Maximum safe path length
    'ALLOW_SYMLINKS': False,             # Whether to follow symlinks in file operations
    'SAFE_PATHS': [                      # Default safe paths for command execution
        '/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin'
    ],
    'UNSAFE_ENV_VARS': [                 # Environment variables that could be used for exploits
        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'DYLD_INSERT_LIBRARIES'
    ]
}

# File integrity settings
FILE_INTEGRITY_SETTINGS: Dict[str, Any] = {
    'HASH_ALGORITHM': 'sha256',          # Default hash algorithm
    'VERIFY_PERMISSIONS': True,          # Check file permissions during integrity checks
    'BASELINE_PATH': 'data/security/baseline.json',   # Default baseline path
    'UPDATE_MAX_AGE': 86400,             # Maximum age (seconds) for auto-updating files
    'AUTO_UPDATE': False,                # Whether to auto-update baseline
}

#=====================================================================
# Operation Constants
#=====================================================================

# Operation timeouts (seconds)
DEFAULT_TIMEOUT = 30
DEFAULT_API_TIMEOUT = 15
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_DB_OPERATION_TIMEOUT = 10
DEFAULT_DEPLOY_TIMEOUT = 300

# Operation limits
MAX_RETRY_ATTEMPTS = 3
DEFAULT_BATCH_SIZE = 100
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

# Database constants
DATABASE_BACKUP_FORMATS = ['sql', 'custom', 'plain']
DATABASE_BACKUP_COMPRESSION = 9  # Maximum compression

#=====================================================================
# Format Constants
#=====================================================================

# Output formats
OUTPUT_FORMAT_TEXT = 'text'
OUTPUT_FORMAT_JSON = 'json'
OUTPUT_FORMAT_YAML = 'yaml'
OUTPUT_FORMAT_CSV = 'csv'
OUTPUT_FORMAT_TABLE = 'table'
OUTPUT_FORMAT_HTML = 'html'

DEFAULT_OUTPUT_FORMAT = OUTPUT_FORMAT_TEXT

SUPPORTED_OUTPUT_FORMATS: List[str] = [
    OUTPUT_FORMAT_TEXT,
    OUTPUT_FORMAT_JSON,
    OUTPUT_FORMAT_YAML,
    OUTPUT_FORMAT_CSV,
    OUTPUT_FORMAT_TABLE
]

# Date and time formats
DEFAULT_DATE_FORMAT = '%Y-%m-%d'
DEFAULT_TIME_FORMAT = '%H:%M:%S'
DEFAULT_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
ISO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

#=====================================================================
# Command Group Names
#=====================================================================

# Application management command groups
COMMAND_GROUP_USER = 'user'
COMMAND_GROUP_DB = 'db'
COMMAND_GROUP_SYSTEM = 'system'
COMMAND_GROUP_SECURITY = 'security'
COMMAND_GROUP_MAINTENANCE = 'maintenance'
COMMAND_GROUP_INIT = 'init'

# Deployment command groups
COMMAND_GROUP_DEPLOY = 'deploy'
COMMAND_GROUP_AWS = 'aws'
COMMAND_GROUP_AZURE = 'azure'
COMMAND_GROUP_GCP = 'gcp'
COMMAND_GROUP_K8S = 'k8s'
COMMAND_GROUP_DOCKER = 'docker'

# Command categories
COMMAND_CATEGORY_APP = 'application'
COMMAND_CATEGORY_DEPLOY = 'deployment'
COMMAND_CATEGORY_SYSTEM = 'system'
COMMAND_CATEGORY_SECURITY = 'security'
COMMAND_CATEGORY_DATA = 'data'
COMMAND_CATEGORY_MONITOR = 'monitoring'
COMMAND_CATEGORY_CONFIG = 'configuration'
COMMAND_CATEGORY_USER = 'user'

#=====================================================================
# Default Configuration Settings
#=====================================================================

# Default CLI configuration
DEFAULT_CLI_CONFIG: Dict[str, Any] = {
    'default_environment': ENVIRONMENT_DEVELOPMENT,
    'environments': {
        ENVIRONMENT_DEVELOPMENT: {
            'api_url': 'http://localhost:5000/api',
            'timeout': 30
        },
        ENVIRONMENT_TESTING: {
            'api_url': 'http://localhost:5100/api',
            'timeout': 10
        },
        ENVIRONMENT_STAGING: {
            'api_url': 'https://staging-api.example.com/api',
            'timeout': 45
        },
        ENVIRONMENT_PRODUCTION: {
            'api_url': 'https://api.example.com/api',
            'timeout': 60
        }
    },
    'output_format': DEFAULT_OUTPUT_FORMAT,
    'debug': False,
    'security': {
        'mask_secrets': True,
        'verify_integrity': True,
        'auto_update_baseline': False
    }
}

#=====================================================================
# Version Information
#=====================================================================

# Version components
VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 1

# Package information
__version__ = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"
__author__ = "Cloud Infrastructure Platform Team"

#=====================================================================
# Module Exports
#=====================================================================

__all__ = [
    # Environment constants
    'ENVIRONMENT_DEVELOPMENT',
    'ENVIRONMENT_TESTING',
    'ENVIRONMENT_STAGING',
    'ENVIRONMENT_PRODUCTION',
    'ENVIRONMENT_DR_RECOVERY',
    'ALLOWED_ENVIRONMENTS',
    'DEFAULT_ENVIRONMENT',

    # Exit codes
    'EXIT_SUCCESS',
    'EXIT_ERROR',
    'EXIT_AUTH_ERROR',
    'EXIT_PERMISSION_ERROR',
    'EXIT_VALIDATION_ERROR',
    'EXIT_RESOURCE_ERROR',
    'EXIT_CONFIGURATION_ERROR',
    'EXIT_CONNECTIVITY_ERROR',
    'EXIT_TIMEOUT_ERROR',
    'EXIT_OPERATION_CANCELLED',
    'EXIT_DEPENDENCY_ERROR',

    # File and directory paths
    'CLI_DIR',
    'PROJECT_ROOT',
    'DEFAULT_CONFIG_DIR',
    'DEFAULT_CONFIG_FILE',
    'CONFIG_TEMPLATE_DIR',
    'DEFAULT_OUTPUT_DIR',
    'DEFAULT_TEMP_DIR',
    'DEFAULT_BACKUP_DIR',
    'DEFAULT_LOG_DIR',
    'CONFIG_FILE_PERMISSIONS',
    'LOG_FILE_PERMISSIONS',
    'BACKUP_DIR_PERMISSIONS',

    # Security constants
    'SENSITIVE_FIELDS',
    'FILE_SECURITY_SETTINGS',
    'FILE_INTEGRITY_SETTINGS',

    # Operation constants
    'DEFAULT_TIMEOUT',
    'DEFAULT_API_TIMEOUT',
    'DEFAULT_CONNECT_TIMEOUT',
    'DEFAULT_DB_OPERATION_TIMEOUT',
    'DEFAULT_DEPLOY_TIMEOUT',
    'MAX_RETRY_ATTEMPTS',
    'DEFAULT_BATCH_SIZE',
    'DEFAULT_PAGE_SIZE',
    'MAX_PAGE_SIZE',
    'DATABASE_BACKUP_FORMATS',
    'DATABASE_BACKUP_COMPRESSION',

    # Format constants
    'OUTPUT_FORMAT_TEXT',
    'OUTPUT_FORMAT_JSON',
    'OUTPUT_FORMAT_YAML',
    'OUTPUT_FORMAT_CSV',
    'OUTPUT_FORMAT_TABLE',
    'OUTPUT_FORMAT_HTML',
    'DEFAULT_OUTPUT_FORMAT',
    'SUPPORTED_OUTPUT_FORMATS',
    'DEFAULT_DATE_FORMAT',
    'DEFAULT_TIME_FORMAT',
    'DEFAULT_DATETIME_FORMAT',
    'ISO_DATETIME_FORMAT',

    # Command group names
    'COMMAND_GROUP_USER',
    'COMMAND_GROUP_DB',
    'COMMAND_GROUP_SYSTEM',
    'COMMAND_GROUP_SECURITY',
    'COMMAND_GROUP_MAINTENANCE',
    'COMMAND_GROUP_INIT',
    'COMMAND_GROUP_DEPLOY',
    'COMMAND_GROUP_AWS',
    'COMMAND_GROUP_AZURE',
    'COMMAND_GROUP_GCP',
    'COMMAND_GROUP_K8S',
    'COMMAND_GROUP_DOCKER',
    'COMMAND_CATEGORY_APP',
    'COMMAND_CATEGORY_DEPLOY',
    'COMMAND_CATEGORY_SYSTEM',
    'COMMAND_CATEGORY_SECURITY',
    'COMMAND_CATEGORY_DATA',
    'COMMAND_CATEGORY_MONITOR',
    'COMMAND_CATEGORY_CONFIG',
    'COMMAND_CATEGORY_USER',

    # Default configurations
    'DEFAULT_CLI_CONFIG',

    # Version information
    '__version__',
    '__author__',
    'VERSION_MAJOR',
    'VERSION_MINOR',
    'VERSION_PATCH'
]
