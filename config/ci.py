"""
CI environment configuration for Cloud Infrastructure Platform.

This module defines the configuration settings specifically for
the continuous integration environment. It disables certain features
that would interfere with automated testing while enabling others
that facilitate comprehensive test coverage.
"""

import os
from .base import Config
from .config_constants import ENVIRONMENT_CI, DEV_OVERRIDES, TEST_OVERRIDES

class CIConfig(Config):
    """Configuration for continuous integration environment.

    This configuration is optimized for automated testing in CI pipelines,
    with settings that promote test isolation, deterministic behavior,
    and comprehensive feature testing without external dependencies.
    """

    DEBUG = False
    TESTING = True
    ENV = ENVIRONMENT_CI

    # Database settings - use in-memory SQLite for speed and isolation
    SQLALCHEMY_DATABASE_URI = os.environ.get('CI_DATABASE_URL', 'sqlite:///:memory:')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Disable security features that interfere with automated tests
    WTF_CSRF_ENABLED = False
    SECURITY_HEADERS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False

    # Disable session security requirements for testing
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Simple in-memory cache for CI
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 60

    # Disable rate limiting to prevent test throttling
    RATELIMIT_ENABLED = False

    # Disable metrics collection to avoid side effects
    METRICS_ENABLED = False

    # Disable error reporting during tests
    SENTRY_DSN = None
    SENTRY_ENVIRONMENT = 'ci'

    # Enable all feature flags for comprehensive testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True

    # CI-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'

    # ICS settings for CI - disabled by default
    ICS_ENABLED = False

    # JWT settings optimized for testing
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 minutes

    # Smaller file size limits for test uploads
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    # File integrity monitoring - disabled in CI to prevent test interference
    ENABLE_FILE_INTEGRITY_MONITORING = False
    AUTO_UPDATE_BASELINE = False

    # Disaster recovery - disabled in CI
    DR_MODE = False
    RECOVERY_MODE = False
    DR_ENHANCED_LOGGING = False

    # CI environment doesn't need baseline backups
    BASELINE_BACKUP_ENABLED = False

    # Skip approval requirements for baseline updates in CI
    BASELINE_UPDATE_APPROVAL_REQUIRED = False

    # Use minimal set of file integrity patterns in CI for better performance
    CRITICAL_FILES_PATTERN = [
        "app.py",
        "core/security/*.py",
        "config/*.py"
    ]

    # Skip file signature verification in CI
    CHECK_FILE_SIGNATURES = False

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with CI configuration.

        Args:
            app: Flask application instance
        """
        # Initialize with parent configuration
        super().init_app(app)

        # CI-specific initialization
        app.logger.info("Initializing application in CI environment")

        # Disable certain security features that might interfere with testing
        app.config['SECURITY_HEADERS_ENABLED'] = False
        app.config['AUDIT_LOG_ENABLED'] = False

        # Disable file integrity monitoring to prevent test failures
        app.config['ENABLE_FILE_INTEGRITY_MONITORING'] = False

        # Ensure dependency integrity checks can be bypassed in CI
        app.config['CI_SKIP_INTEGRITY_CHECK'] = os.environ.get('CI_SKIP_INTEGRITY_CHECK', 'false').lower() == 'true'

        # Configure temporary paths for CI environment
        if 'CI_TEMP_DIR' in os.environ:
            app.config['UPLOAD_FOLDER'] = os.path.join(os.environ['CI_TEMP_DIR'], 'uploads')
            app.config['FILE_BASELINE_PATH'] = os.path.join(os.environ['CI_TEMP_DIR'], 'baseline.json')

        # Disable scheduled tasks in CI to prevent background operations during tests
        app.config['SCHEDULER_ENABLED'] = False
