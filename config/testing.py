"""
Testing environment configuration for Cloud Infrastructure Platform.

This module defines configuration settings for the testing environment,
optimized for automated testing with deterministic behavior, isolated test
data, and performance-focused settings.
"""

import os
import tempfile
from .base import Config
from .config_constants import (
    ENVIRONMENT_TESTING,
    TEST_OVERRIDES,
    SMALL_FILE_THRESHOLD
)

class TestingConfig(Config):
    """
    Configuration for testing environment.

    Optimized for automated testing with in-memory databases, disabled security
    features that might interfere with testing, and minimal logging.
    """

    DEBUG = False
    TESTING = True
    ENV = ENVIRONMENT_TESTING

    # Test database (in-memory SQLite by default)
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')

    # Disable CSRF protection during testing
    WTF_CSRF_ENABLED = False

    # Disable security features that might interfere with tests
    SECURITY_HEADERS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False
    ENABLE_FILE_INTEGRITY_MONITORING = False

    # Simple in-memory cache for testing
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 60  # Shorter timeout for testing

    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False

    # Disable metrics in testing
    METRICS_ENABLED = False

    # Disable audit logging in tests for cleaner test output
    AUDIT_LOG_ENABLED = False

    # Auto-update baseline should be disabled in test environment
    AUTO_UPDATE_BASELINE = False

    # Disable baseline backup during tests for performance
    BASELINE_BACKUP_ENABLED = False

    # Session and cookie security settings for testing
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Allow HTTP in testing environment
    API_REQUIRE_HTTPS = False

    # Enable all features for testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True
    ICS_ENABLED = True

    # Testing-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'

    # Much smaller file size limits for test file uploads
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB

    # Minimum set of critical files to check in testing (if enabled)
    CRITICAL_FILES_PATTERN = [
        "app.py",
        "config/*.py"
    ]

    # Testing-specific file integrity settings
    FILE_HASH_ALGORITHM = 'sha256'
    SMALL_FILE_THRESHOLD = 1024  # Smaller threshold for testing

    # Disaster recovery mode disabled during testing
    DR_MODE = False
    DR_ENHANCED_LOGGING = False
    RECOVERY_MODE = False
    DR_BASELINE_FROZEN = False

    # Skip interference with server responses
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    TRAP_HTTP_EXCEPTIONS = False

    # JWT settings optimized for testing
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 minutes
    JWT_REFRESH_TOKEN_EXPIRES = 600  # 10 minutes

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with testing configuration.

        Args:
            app: Flask application instance
        """
        # Initialize with parent configuration
        super().init_app(app)

        # Configure test-specific settings
        app.config['TESTING'] = True
        app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False
        app.config['TRAP_HTTP_EXCEPTIONS'] = False

        # Use temporary directories for testing
        temp_folder = tempfile.mkdtemp(prefix="cloud_platform_test_")
        app.config['UPLOAD_FOLDER'] = os.path.join(temp_folder, 'uploads')
        app.config['FILE_BASELINE_PATH'] = os.path.join(temp_folder, 'baseline.json')
        app.config['TEMP_DIR'] = temp_folder

        # Create upload folder
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        except OSError:
            pass

        # Configure test-specific ICS settings
        if app.config.get('ICS_ENABLED', False):
            app.config['ICS_MONITOR_INTERVAL'] = 5  # Very short interval for testing
            app.config['ICS_RESTRICTED_IPS'] = ['127.0.0.1']

        # Configure minimal trusted proxies
        app.config['TRUSTED_PROXIES'] = ['127.0.0.1']

        # Disable background tasks in testing
        app.config['SCHEDULER_ENABLED'] = False

        # Skip file signature verification in tests
        app.config['CHECK_FILE_SIGNATURES'] = False

        # Set up minimal logging for tests
        app.logger.setLevel(app.config['LOG_LEVEL'])
