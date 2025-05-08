"""
Configuration constants for Cloud Infrastructure Platform.

This module centralizes configuration constants used throughout the application,
providing a single source of truth for default values, environment-specific settings,
and configuration schemas. These constants are used by the configuration classes
in config/base.py and core/config.py.

Using these centralized constants ensures consistency across environments
and makes configuration management more maintainable by avoiding duplication.
"""

from datetime import timedelta
from typing import Dict, Any, List, Set, FrozenSet

#=====================================================================
# Environment Constants
#=====================================================================

# Environment names
ENVIRONMENT_DEVELOPMENT = 'development'
ENVIRONMENT_TESTING = 'testing'
ENVIRONMENT_STAGING = 'staging'
ENVIRONMENT_PRODUCTION = 'production'
ENVIRONMENT_DR_RECOVERY = 'dr-recovery'
ENVIRONMENT_CI = 'ci'

# Set of allowed environments
ALLOWED_ENVIRONMENTS: FrozenSet[str] = frozenset([
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY,
    ENVIRONMENT_CI
])

# Set of environments requiring secure settings
SECURE_ENVIRONMENTS: FrozenSet[str] = frozenset([
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY
])

#=====================================================================
# Required Configuration Variables
#=====================================================================

# Required environment variables for all environments
REQUIRED_ENV_VARS: List[str] = [
    'SECRET_KEY',
    'DATABASE_URL',
    'JWT_SECRET_KEY',
    'CSRF_SECRET_KEY',
    'SESSION_KEY'
]

# Additional required variables for production environments
REQUIRED_PROD_ENV_VARS: List[str] = [
    'REDIS_URL',
    'SENTRY_DSN'
]

#=====================================================================
# Default Configuration Values
#=====================================================================

# Default values for optional environment settings
DEFAULT_ENV_VALUES: Dict[str, Any] = {
    'ENVIRONMENT': ENVIRONMENT_DEVELOPMENT,
    'DEBUG': False,
    'TESTING': False,
    'SERVER_NAME': None,
    'APPLICATION_ROOT': '/',
    'PREFERRED_URL_SCHEME': 'https',
}

# Database configuration defaults
DEFAULT_DB_CONFIG: Dict[str, Any] = {
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_ENGINE_OPTIONS': {
        'pool_recycle': 280,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20
    }
}

# Security configuration defaults
DEFAULT_SECURITY_CONFIG: Dict[str, Any] = {
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': timedelta(days=1),
    'REMEMBER_COOKIE_DURATION': timedelta(days=14),
    'REMEMBER_COOKIE_SECURE': True,
    'REMEMBER_COOKIE_HTTPONLY': True,
    'REMEMBER_COOKIE_SAMESITE': 'Lax',
}

# Security headers configuration
DEFAULT_SECURITY_HEADERS: Dict[str, Any] = {
    'SECURITY_HEADERS_ENABLED': True,
    'SECURITY_CSP_REPORT_URI': None,
    'SECURITY_HSTS_MAX_AGE': 31536000,  # 1 year
    'SECURITY_INCLUDE_SUBDOMAINS': True,
    'SECURITY_PRELOAD': True,
}

# CSRF protection configuration
DEFAULT_CSRF_CONFIG: Dict[str, Any] = {
    'WTF_CSRF_ENABLED': True,
    'WTF_CSRF_TIME_LIMIT': 3600,  # 1 hour
}

# Rate limiting configuration
DEFAULT_RATE_LIMIT_CONFIG: Dict[str, Any] = {
    'RATELIMIT_DEFAULT': '200 per day, 50 per hour',
    'RATELIMIT_STORAGE_URL': 'memory://',
    'RATELIMIT_HEADERS_ENABLED': True,
    'RATELIMIT_STRATEGY': 'fixed-window',
}

# JWT configuration
DEFAULT_JWT_CONFIG: Dict[str, Any] = {
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=15),
    'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),
    'JWT_BLACKLIST_ENABLED': True,
    'JWT_BLACKLIST_TOKEN_CHECKS': ['access', 'refresh'],
}

# Cache configuration
DEFAULT_CACHE_CONFIG: Dict[str, Any] = {
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300,
}

# ICS system configuration
DEFAULT_ICS_CONFIG: Dict[str, Any] = {
    'ICS_ENABLED': False,
    'ICS_RESTRICTED_IPS': [],
    'ICS_MONITOR_INTERVAL': 60,  # seconds
    'ICS_ALERT_THRESHOLD': 0.8,  # 80%
}

# Cloud provider configuration
DEFAULT_CLOUD_CONFIG: Dict[str, Any] = {
    'CLOUD_PROVIDERS': ['aws', 'azure', 'gcp'],
    'CLOUD_METRICS_INTERVAL': 300,  # 5 minutes
    'CLOUD_RESOURCES_CACHE_TTL': 600,  # 10 minutes
}

# Monitoring configuration
DEFAULT_MONITORING_CONFIG: Dict[str, Any] = {
    'METRICS_ENABLED': True,
    'SENTRY_TRACES_SAMPLE_RATE': 0.2,
    'LOG_LEVEL': 'INFO',
    'SECURITY_LOG_LEVEL': 'WARNING',
}

# File security configuration
DEFAULT_FILE_SECURITY_CONFIG: Dict[str, Any] = {
    'SECURITY_CHECK_FILE_INTEGRITY': True,
    'SECURITY_CRITICAL_FILES': [
        'app.py',
        'config.py',
        'core/security_utils.py',
        'core/middleware.py'
    ],
    'ALLOWED_EXTENSIONS': {'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx'},
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB
}

#=====================================================================
# File Integrity Monitoring Configuration
#=====================================================================

# File integrity monitoring configuration
DEFAULT_FILE_INTEGRITY_CONFIG: Dict[str, Any] = {
    'ENABLE_FILE_INTEGRITY_MONITORING': True,
    'FILE_HASH_ALGORITHM': 'sha256',
    'FILE_INTEGRITY_CHECK_INTERVAL': 3600,  # 1 hour
    'AUTO_UPDATE_BASELINE': False,
    'CRITICAL_FILES_PATTERN': [
        "*.py",                 # Python source files
        "config/*.ini",         # Configuration files
        "config/*.json",        # JSON configuration
        "config/*.yaml",        # YAML configuration
        "config/*.yml",         # YAML configuration (alt)
    ],
    'CHECK_FILE_SIGNATURES': True,  # Verify file signatures where applicable
}

# File integrity baseline update configuration
FILE_INTEGRITY_BASELINE_CONFIG: Dict[str, Any] = {
    'BASELINE_UPDATE_MAX_FILES': 50,             # Maximum files to update in one operation
    'BASELINE_UPDATE_CRITICAL_THRESHOLD': 5,     # Maximum critical files to update at once
    'BASELINE_BACKUP_ENABLED': True,             # Create backups before baseline updates
    'BASELINE_UPDATE_RETENTION': 5,              # Number of baseline backups to retain
    'BASELINE_UPDATE_APPROVAL_REQUIRED': True,   # Whether updates require approval in production
    'BASELINE_AUTO_UPDATE_PATTERN': [            # Patterns eligible for automatic updates
        "*.css",
        "*.js",
        "static/*",
        "templates/*.html"
    ],
    'BASELINE_NEVER_AUTO_UPDATE': [              # Patterns never eligible for automatic updates
        "core/security/*.py",
        "app.py",
        "wsgi.py",
        "config/*.py"
    ],
    'BASELINE_PATH_TEMPLATE': 'instance/security/baseline_{environment}.json',
    'BASELINE_BACKUP_PATH_TEMPLATE': 'instance/security/baseline_backups/{timestamp}_{environment}.json',
}

# Security severity mapping for file changes
FILE_INTEGRITY_SEVERITY_MAPPING: Dict[str, str] = {
    'missing': 'high',        # File is missing
    'modified': 'high',       # File is modified
    'permission': 'critical', # File permissions changed
    'signature': 'critical',  # File signature invalid
    'unexpected': 'medium',   # Unexpected file found
    'added': 'medium',        # New file added
    'checksum': 'high',       # Checksum mismatch
    'metadata': 'low',        # Metadata changed
    'owner': 'high',          # Owner changed
    'timestamp': 'low',       # Timestamp changed
}

#=====================================================================
# Content Security Policy Configuration
#=====================================================================

# CSP (Content Security Policy) configuration
DEFAULT_CSP_CONFIG: Dict[str, Any] = {
    'CSP_DEFAULT_SRC': ["'self'"],
    'CSP_SCRIPT_SRC': ["'self'", "'unsafe-inline'"],
    'CSP_STYLE_SRC': ["'self'", "'unsafe-inline'"],
    'CSP_IMG_SRC': ["'self'", "data:"],
    'CSP_CONNECT_SRC': ["'self'"],
    'CSP_FONT_SRC': ["'self'"],
    'CSP_OBJECT_SRC': ["'none'"],
    'CSP_MEDIA_SRC': ["'self'"],
    'CSP_FRAME_SRC': ["'self'"],
    'CSP_FRAME_ANCESTORS': ["'self'"],
    'CSP_FORM_ACTION': ["'self'"],
    'CSP_BASE_URI': ["'self'"],
    'CSP_REPORT_TO': "default",
}

#=====================================================================
# Audit Configuration
#=====================================================================

# Audit logging configuration
DEFAULT_AUDIT_CONFIG: Dict[str, Any] = {
    'AUDIT_LOG_ENABLED': True,
    'AUDIT_LOG_EVENTS': ['authentication', 'authorization', 'data_access', 'configuration_change'],
    'AUDIT_LOG_RETENTION_DAYS': 90,
}

#=====================================================================
# Feature Flag Configuration
#=====================================================================

# Feature flag configuration
DEFAULT_FEATURE_FLAGS: Dict[str, bool] = {
    'FEATURE_DARK_MODE': True,
    'FEATURE_ICS_CONTROL': True,
    'FEATURE_CLOUD_MANAGEMENT': True,
    'FEATURE_MFA': True,
}

#=====================================================================
# Disaster Recovery Configuration
#=====================================================================

# Disaster recovery configuration
DEFAULT_DR_CONFIG: Dict[str, Any] = {
    'DR_MODE': True,
    'DR_ENHANCED_LOGGING': True,
    'DR_LOG_PATH': '/var/log/cloud-platform/dr-events.log',
    'DR_COORDINATOR_EMAIL': 'dr-coordinator@example.com',
    'DR_NOTIFICATION_ENABLED': True,
    'METRICS_DR_MODE': True,
    'RECOVERY_MODE': True,
    'SENTRY_ENVIRONMENT': 'dr-recovery',
    'SENTRY_TRACES_SAMPLE_RATE': 0.5,  # Higher sampling rate during DR
    'DR_RECOVERY_PRIORITIES': {
        'critical': ['authentication', 'authorization', 'core_services'],
        'high': ['data_access', 'api_endpoints', 'monitoring'],
        'medium': ['reporting', 'notifications', 'batch_jobs'],
        'low': ['ui_customization', 'analytics', 'non_critical_features']
    }
}

#=====================================================================
# Environment-Specific Overrides
#=====================================================================

# Development environment overrides
DEV_OVERRIDES: Dict[str, Any] = {
    'DEBUG': True,
    'SESSION_COOKIE_SECURE': False,
    'REMEMBER_COOKIE_SECURE': False,
    'WTF_CSRF_ENABLED': True,
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
    'SECURITY_HEADERS_ENABLED': True,
    'METRICS_ENABLED': True,
    'LOG_LEVEL': 'DEBUG',
    'SECURITY_LOG_LEVEL': 'DEBUG',
    'API_REQUIRE_HTTPS': False,  # Allow HTTP in dev for easier testing
    'AUTO_UPDATE_BASELINE': True,  # Auto-update baseline in dev
    'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
    'DEBUG_TB_ENABLED': True,
    'DEBUG_TB_INTERCEPT_REDIRECTS': False,
    'ICS_ENABLED': True,
    'ICS_RESTRICTED_IPS': ['127.0.0.1'],
    'EXPLAIN_TEMPLATE_LOADING': True,
}

# Test environment overrides
TEST_OVERRIDES: Dict[str, Any] = {
    'TESTING': True,
    'DEBUG': False,
    'WTF_CSRF_ENABLED': False,
    'SERVER_NAME': 'localhost',
    'METRICS_ENABLED': False,
    'SECURITY_CHECK_FILE_INTEGRITY': False,
    'ENABLE_FILE_INTEGRITY_MONITORING': False,
    'AUDIT_LOG_ENABLED': False,  # Disable audit logging in tests
    'PRESERVE_CONTEXT_ON_EXCEPTION': False,
    'TRAP_HTTP_EXCEPTIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
}

# DR recovery environment overrides
DR_OVERRIDES: Dict[str, Any] = {
    'DEBUG': False,
    'LOG_LEVEL': 'WARNING',
    'AUTO_UPDATE_BASELINE': False,
    'DR_MODE': True,
    'DR_ENHANCED_LOGGING': True,
    'RECOVERY_MODE': True,
    'METRICS_DR_MODE': True,
    'SENTRY_ENVIRONMENT': 'dr-recovery',
    'SENTRY_TRACES_SAMPLE_RATE': 0.5,
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'REMEMBER_COOKIE_SECURE': True,
    'REMEMBER_COOKIE_HTTPONLY': True,
    'API_REQUIRE_HTTPS': True,
    'SECURITY_CHECK_FILE_INTEGRITY': True,
    'ENABLE_FILE_INTEGRITY_MONITORING': True,
    'SECURITY_LOG_LEVEL': 'WARNING',
}

# CI environment overrides
CI_OVERRIDES: Dict[str, Any] = {
    'TESTING': True,
    'DEBUG': False,
    'WTF_CSRF_ENABLED': False,
    'METRICS_ENABLED': False,
    'LOG_LEVEL': 'ERROR',
    'SECURITY_CHECK_FILE_INTEGRITY': False,
    'ENABLE_FILE_INTEGRITY_MONITORING': False,
    'BASELINE_BACKUP_ENABLED': False,
    'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
    'CI_SKIP_INTEGRITY_CHECK': True,
    'SCHEDULER_ENABLED': False,
    'CHECK_FILE_SIGNATURES': False,
}

#=====================================================================
# Security Requirements
#=====================================================================

# Production security requirements (these must be enabled in production)
PROD_SECURITY_REQUIREMENTS: List[str] = [
    'SESSION_COOKIE_SECURE',
    'SESSION_COOKIE_HTTPONLY',
    'REMEMBER_COOKIE_SECURE',
    'REMEMBER_COOKIE_HTTPONLY',
    'WTF_CSRF_ENABLED',
    'SECURITY_HEADERS_ENABLED',
    'API_REQUIRE_HTTPS',
    'JWT_BLACKLIST_ENABLED',
    'AUDIT_LOG_ENABLED',
]

#=====================================================================
# File Integrity Monitoring Patterns
#=====================================================================

# File integrity monitoring patterns by priority level
FILE_INTEGRITY_MONITORED_PATTERNS: Dict[str, List[str]] = {
    'critical': [
        'core/security/*.py',
        'core/middleware.py',
        'core/auth.py',
        'models/security/*.py',
        'config/security.ini',
        'app.py',
        'wsgi.py'
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

# Security-sensitive fields for automatic redaction in logs
SENSITIVE_FIELDS: Set[str] = {
    'password', 'token', 'secret', 'key', 'auth', 'cred', 'private',
    'cookie', 'session', 'hash', 'sign', 'certificate', 'salt'
}

#=====================================================================
# Miscellaneous Constants
#=====================================================================

# Constants for file hash calculation
SMALL_FILE_THRESHOLD = 10240  # 10KB
DEFAULT_HASH_ALGORITHM = 'sha256'

#=====================================================================
# Module Exports
#=====================================================================

# Define a mapping for providing a single-import solution for common settings
__all__ = [
    # Environment names
    'ENVIRONMENT_DEVELOPMENT',
    'ENVIRONMENT_TESTING',
    'ENVIRONMENT_STAGING',
    'ENVIRONMENT_PRODUCTION',
    'ENVIRONMENT_DR_RECOVERY',
    'ENVIRONMENT_CI',
    'ALLOWED_ENVIRONMENTS',
    'SECURE_ENVIRONMENTS',

    # Configuration variables
    'REQUIRED_ENV_VARS',
    'REQUIRED_PROD_ENV_VARS',
    'DEFAULT_ENV_VALUES',
    'DEFAULT_DB_CONFIG',
    'DEFAULT_SECURITY_CONFIG',
    'DEFAULT_SECURITY_HEADERS',
    'DEFAULT_CSRF_CONFIG',
    'DEFAULT_RATE_LIMIT_CONFIG',
    'DEFAULT_JWT_CONFIG',
    'DEFAULT_CACHE_CONFIG',
    'DEFAULT_ICS_CONFIG',
    'DEFAULT_CLOUD_CONFIG',
    'DEFAULT_MONITORING_CONFIG',
    'DEFAULT_FILE_SECURITY_CONFIG',
    'DEFAULT_FILE_INTEGRITY_CONFIG',
    'FILE_INTEGRITY_BASELINE_CONFIG',
    'FILE_INTEGRITY_SEVERITY_MAPPING',
    'DEFAULT_CSP_CONFIG',
    'DEFAULT_AUDIT_CONFIG',
    'DEFAULT_FEATURE_FLAGS',
    'DEFAULT_DR_CONFIG',

    # Environment overrides
    'DEV_OVERRIDES',
    'TEST_OVERRIDES',
    'DR_OVERRIDES',
    'CI_OVERRIDES',
    'PROD_SECURITY_REQUIREMENTS',

    # File integrity monitoring
    'FILE_INTEGRITY_MONITORED_PATTERNS',
    'FILE_INTEGRITY_BASELINE_CONFIG',
    'FILE_INTEGRITY_SEVERITY_MAPPING',
    'SENSITIVE_FIELDS',
    'SMALL_FILE_THRESHOLD',
    'DEFAULT_HASH_ALGORITHM',
]
