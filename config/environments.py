"""
Environment-specific configurations for Cloud Infrastructure Platform.

This module defines configuration classes for different environments (development,
testing, staging, production, etc.) with appropriate settings for each context.
It also provides utility functions for environment detection and management.
"""

import os
from typing import Dict, Any, Optional, Type, Set
from .base import Config
from .config_constants import (
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_CI,
    ENVIRONMENT_DR_RECOVERY,
    DEV_OVERRIDES,
    TEST_OVERRIDES,
    DR_OVERRIDES
)

# Environment groups
ALLOWED_ENVIRONMENTS: Set[str] = {
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_CI,
    ENVIRONMENT_DR_RECOVERY
}

# Environments with stricter security requirements
SECURE_ENVIRONMENTS: Set[str] = {
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY
}


class DevelopmentConfig(Config):
    """
    Development environment configuration.

    Enables debugging tools and relaxes certain security restrictions to
    facilitate development while maintaining appropriate security controls.
    """
    DEBUG = True
    ENV = ENVIRONMENT_DEVELOPMENT
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    DEBUG_TB_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    LOG_LEVEL = 'DEBUG'
    SECURITY_LOG_LEVEL = 'DEBUG'  # Enhanced security logging in development
    CACHE_TYPE = 'SimpleCache'
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = ['127.0.0.1']

    # File integrity settings for development
    SECURITY_CHECK_FILE_INTEGRITY = True  # Enable but don't enforce
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = True  # Auto-update baseline for development

    # Simplified file integrity settings for faster development
    BASELINE_UPDATE_APPROVAL_REQUIRED = False
    CRITICAL_FILES_PATTERN = [
        "*.py",                  # Python source files
        "config/*.py",           # Configuration files
        "core/security/*.py"     # Core security components
    ]

    # Allow HTTP in development
    API_REQUIRE_HTTPS = False

    # Disable DR mode in development
    DR_MODE = False
    DR_ENHANCED_LOGGING = False
    RECOVERY_MODE = False

    # Extended JWT expiration for development convenience
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with development configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # Set up development-specific paths
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_dev.json'
        )
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'development')

        # Enable specific development features
        app.config['SECURITY_LOG_TO_CONSOLE'] = True
        app.config['EXPLAIN_TEMPLATE_LOADING'] = True


class ProductionConfig(Config):
    """
    Production environment configuration.

    Enforces strict security controls, disables debugging features, and
    optimizes for performance and reliability in production environments.
    """
    ENV = ENVIRONMENT_PRODUCTION
    DEBUG = False
    LOG_LEVEL = 'WARNING'

    # Strict security settings for production
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    SECURITY_LOG_LEVEL = 'WARNING'
    AUTO_UPDATE_BASELINE = False
    BASELINE_UPDATE_APPROVAL_REQUIRED = True

    # Secure cookie settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True

    # Security headers
    SECURITY_HEADERS_ENABLED = True
    API_REQUIRE_HTTPS = True

    # Enhanced alerting settings
    ALERT_ON_INTEGRITY_FAILURE = True
    ALERT_ON_SUSPICIOUS_ACTIVITY = True

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with production configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # Set up production-specific paths
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_prod.json'
        )
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'production')

        # Set advanced protection measures
        app.config['ENFORCE_MFA_FOR_ADMIN'] = True
        app.config['API_RATE_LIMITING'] = True
        app.config['SESSION_PERMANENT'] = False


class TestingConfig(Config):
    """
    Testing environment configuration.

    Optimized for automated testing with in-memory databases, disabled security
    features that might interfere with testing, and minimal logging.
    """
    TESTING = True
    ENV = ENVIRONMENT_TESTING
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SERVER_NAME = 'localhost'
    METRICS_ENABLED = False

    # Disable integrity checks during tests to avoid interference
    SECURITY_CHECK_FILE_INTEGRITY = False
    ENABLE_FILE_INTEGRITY_MONITORING = False

    # Use in-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Disable audit logging in tests
    AUDIT_LOG_ENABLED = False

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with testing configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # Configure test-specific settings
        app.config['TESTING'] = True
        app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False
        app.config['TRAP_HTTP_EXCEPTIONS'] = False

        # Use temporary directories for testing
        import tempfile
        temp_folder = tempfile.mkdtemp()
        app.config['UPLOAD_FOLDER'] = os.path.join(temp_folder, 'uploads')
        app.config['FILE_BASELINE_PATH'] = os.path.join(temp_folder, 'baseline.json')


class StagingConfig(Config):
    """
    Staging environment configuration.

    Mirrors production settings but with additional logging and monitoring
    to facilitate pre-production validation and testing.
    """
    ENV = ENVIRONMENT_STAGING
    DEBUG = False
    LOG_LEVEL = 'INFO'

    # Security settings - production-like with more monitoring
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False

    # Monitoring and observability
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2

    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    API_REQUIRE_HTTPS = True

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with staging configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # Set up staging-specific paths
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_staging.json'
        )
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'staging')

        # Enhanced logging for staging
        app.config['AUDIT_LOG_LEVEL'] = 'INFO'
        app.config['SECURITY_LOG_LEVEL'] = 'INFO'


class CIConfig(Config):
    """
    CI environment configuration.

    Optimized for continuous integration with minimal dependencies,
    complete test coverage, and quick execution.
    """
    ENV = ENVIRONMENT_CI
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False

    # Disable metrics and monitoring in CI to speed up tests
    METRICS_ENABLED = False

    # Enable all feature flags for comprehensive testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True

    # CI-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'

    # Disable security features that might interfere with tests
    SECURITY_CHECK_FILE_INTEGRITY = False
    ENABLE_FILE_INTEGRITY_MONITORING = False

    # File integrity settings appropriate for CI
    BASELINE_BACKUP_ENABLED = False
    BASELINE_UPDATE_APPROVAL_REQUIRED = False

    # Minimal set of critical files to check in CI
    CRITICAL_FILES_PATTERN = [
        "app.py",
        "core/security/*.py",
        "config/*.py"
    ]

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with CI configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # Configure CI-specific paths
        app.config['CI_SKIP_INTEGRITY_CHECK'] = True
        app.config['SCHEDULER_ENABLED'] = False

        # Configure temporary paths for CI environment
        if 'CI_TEMP_DIR' in os.environ:
            app.config['UPLOAD_FOLDER'] = os.path.join(os.environ['CI_TEMP_DIR'], 'uploads')
            app.config['FILE_BASELINE_PATH'] = os.path.join(os.environ['CI_TEMP_DIR'], 'baseline.json')


class DRRecoveryConfig(Config):
    """
    Disaster recovery environment configuration.

    Designed for use in disaster recovery scenarios with enhanced logging,
    specialized monitoring, and appropriate security controls for recovery operations.
    """
    ENV = ENVIRONMENT_DR_RECOVERY
    DEBUG = False
    LOG_LEVEL = 'WARNING'

    # Security settings - production-level security during DR
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    SECURITY_LOG_LEVEL = 'WARNING'
    AUTO_UPDATE_BASELINE = False

    # Secure cookie settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    API_REQUIRE_HTTPS = True

    # Enhanced logging for DR activities
    DR_ENHANCED_LOGGING = True
    DR_LOG_PATH = '/var/log/cloud-platform/dr-events.log'

    # Recovery-specific settings
    DR_MODE = True
    DR_COORDINATOR_EMAIL = 'dr-coordinator@example.com'
    DR_NOTIFICATION_ENABLED = True

    # Monitoring configuration
    METRICS_ENABLED = True
    METRICS_DR_MODE = True
    SENTRY_ENVIRONMENT = 'dr-recovery'
    SENTRY_TRACES_SAMPLE_RATE = 0.5  # Higher sampling rate during DR

    # Recovery mode - used by services to determine behavior
    RECOVERY_MODE = True

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with DR recovery configuration.

        Args:
            app: Flask application instance
        """
        super().init_app(app)

        # DR-specific initialization
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_dr.json'
        )

        # Configure DR log directory
        dr_log_path = app.config.get('DR_LOG_PATH')
        if dr_log_path:
            dr_log_dir = os.path.dirname(dr_log_path)
            try:
                if not os.path.exists(dr_log_dir):
                    os.makedirs(dr_log_dir, mode=0o750)
            except OSError as e:
                app.logger.error(f"Failed to create DR log directory: {e}")

        # Set up recovery prioritization
        app.config['DR_RECOVERY_PRIORITIES'] = {
            'critical': ['authentication', 'authorization', 'core_services'],
            'high': ['data_access', 'api_endpoints', 'monitoring'],
            'medium': ['reporting', 'notifications', 'batch_jobs'],
            'low': ['ui_customization', 'analytics', 'non_critical_features']
        }


def detect_environment() -> str:
    """
    Detect current environment based on environment variables.

    The function checks for FLASK_ENV, ENVIRONMENT, or APP_ENV environment variables
    in that order. If none are found, it defaults to development.

    Returns:
        str: The current environment name (development, production, etc.)
    """
    # Check various environment variables
    for env_var in ['FLASK_ENV', 'ENVIRONMENT', 'APP_ENV']:
        env = os.environ.get(env_var)
        if env:
            env = env.lower()
            if env in ALLOWED_ENVIRONMENTS:
                return env

    # Default to development if no environment is specified
    return ENVIRONMENT_DEVELOPMENT


def get_environment_config(environment: Optional[str] = None) -> Type[Config]:
    """
    Get configuration class for a specific environment.

    Args:
        environment: The environment name (development, production, etc.)
                    If None, detect from environment variables

    Returns:
        Config: The environment-specific configuration class

    Raises:
        ValueError: If an invalid environment name is provided
    """
    if environment is None:
        environment = detect_environment()

    environment = environment.lower()

    config_classes = {
        ENVIRONMENT_DEVELOPMENT: DevelopmentConfig,
        ENVIRONMENT_PRODUCTION: ProductionConfig,
        ENVIRONMENT_TESTING: TestingConfig,
        ENVIRONMENT_STAGING: StagingConfig,
        ENVIRONMENT_CI: CIConfig,
        ENVIRONMENT_DR_RECOVERY: DRRecoveryConfig
    }

    if environment not in config_classes:
        valid_envs = ", ".join(sorted(config_classes.keys()))
        raise ValueError(f"Unknown environment: {environment}. Must be one of: {valid_envs}")

    return config_classes[environment]


def is_secure_environment(environment: Optional[str] = None) -> bool:
    """
    Check if the environment requires secure settings.

    Args:
        environment: Environment name to check (uses current environment if None)

    Returns:
        bool: True if the environment requires secure settings
    """
    if environment is None:
        environment = detect_environment()

    return environment.lower() in SECURE_ENVIRONMENTS


def environment_supports_feature(feature: str, environment: Optional[str] = None) -> bool:
    """
    Check if a specific feature is supported in the current environment.

    Args:
        feature: Feature name to check (e.g., 'file_integrity', 'mfa', 'dr_mode')
        environment: Environment to check (uses current environment if None)

    Returns:
        bool: True if the feature is supported in the specified environment
    """
    if environment is None:
        environment = detect_environment()

    env_config = get_environment_config(environment)()

    # Map feature names to config keys
    feature_map = {
        'file_integrity': 'ENABLE_FILE_INTEGRITY_MONITORING',
        'auto_update_baseline': 'AUTO_UPDATE_BASELINE',
        'mfa': 'FEATURE_MFA',
        'dark_mode': 'FEATURE_DARK_MODE',
        'dr_mode': 'DR_MODE',
        'recovery_mode': 'RECOVERY_MODE',
        'ics_control': 'FEATURE_ICS_CONTROL',
        'cloud_management': 'FEATURE_CLOUD_MANAGEMENT',
    }

    config_key = feature_map.get(feature.lower())
    if not config_key:
        return False

    return getattr(env_config, config_key, False)
