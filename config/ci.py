"""
CI environment configuration for Cloud Infrastructure Platform.

This module defines the configuration settings specifically for
the continuous integration environment. It disables certain features
that would interfere with automated testing while enabling others
that facilitate comprehensive test coverage.
"""

import os
import tempfile
from .base import Config
from .config_constants import (
    ENVIRONMENT_CI,
    CI_OVERRIDES,
    FILE_INTEGRITY_MONITORED_PATTERNS
)

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
    SECURITY_LOG_LEVEL = 'ERROR'
    EXPLAIN_TEMPLATE_LOADING = False

    # ICS settings for CI - disabled by default
    ICS_ENABLED = False
    ICS_RESTRICTED_IPS = ['127.0.0.1']

    # JWT settings optimized for testing
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 minutes
    JWT_REFRESH_TOKEN_EXPIRES = 900  # 15 minutes
    JWT_BLACKLIST_ENABLED = False

    # Smaller file size limits for test uploads
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    # File integrity monitoring - disabled in CI to prevent test interference
    ENABLE_FILE_INTEGRITY_MONITORING = False
    AUTO_UPDATE_BASELINE = False
    SECURITY_CHECK_FILE_INTEGRITY = False

    # Disaster recovery - disabled in CI
    DR_MODE = False
    RECOVERY_MODE = False
    DR_ENHANCED_LOGGING = False
    DR_BASELINE_FROZEN = False

    # CI environment doesn't need baseline backups
    BASELINE_BACKUP_ENABLED = False
    BASELINE_UPDATE_RETENTION = 1

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

    # Special CI configurations
    CI_SKIP_INTEGRITY_CHECK = True
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    TRAP_HTTP_EXCEPTIONS = False

    # Audit logging disabled in CI
    AUDIT_LOG_ENABLED = False
    AUDIT_LOG_RETENTION_DAYS = 1

    # Disable scheduler in CI
    SCHEDULER_ENABLED = False

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
        app.config['SECURITY_CHECK_FILE_INTEGRITY'] = False

        # Ensure dependency integrity checks can be bypassed in CI
        app.config['CI_SKIP_INTEGRITY_CHECK'] = os.environ.get('CI_SKIP_INTEGRITY_CHECK', 'true').lower() == 'true'

        # Configure temporary paths for CI environment
        if 'CI_TEMP_DIR' in os.environ:
            temp_dir = os.environ['CI_TEMP_DIR']
        else:
            # Create a temporary directory if CI_TEMP_DIR is not set
            temp_dir = tempfile.mkdtemp(prefix="ci_test_")
            app.config['CI_TEMP_DIR'] = temp_dir

        # Set up various temporary directories for CI
        app.config['UPLOAD_FOLDER'] = os.path.join(temp_dir, 'uploads')
        app.config['FILE_BASELINE_PATH'] = os.path.join(temp_dir, 'baseline.json')
        app.config['TEMP_DIR'] = os.path.join(temp_dir, 'tmp')
        app.config['LOG_DIR'] = os.path.join(temp_dir, 'logs')

        # Create necessary directories
        for directory in [app.config['UPLOAD_FOLDER'], app.config['TEMP_DIR'], app.config['LOG_DIR']]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

        # Disable scheduled tasks in CI to prevent background operations during tests
        app.config['SCHEDULER_ENABLED'] = False

        # Set specific Content Security Policy for CI
        app.config['CSP_DEFAULT_SRC'] = ["'self'", "'unsafe-inline'"]
        app.config['CSP_SCRIPT_SRC'] = ["'self'", "'unsafe-inline'", "'unsafe-eval'"]

        # Configure minimal logging for tests
        from logging import FileHandler
        log_file = os.path.join(app.config['LOG_DIR'], 'ci_test.log')
        file_handler = FileHandler(log_file)
        file_handler.setLevel(app.config['LOG_LEVEL'])
        app.logger.addHandler(file_handler)

        # Add custom CI test headers to help with test identification
        @app.after_request
        def add_ci_headers(response):
            """Add CI-specific headers to HTTP responses."""
            response.headers['X-Environment'] = 'CI'
            response.headers['X-Testing'] = 'True'
            return response
