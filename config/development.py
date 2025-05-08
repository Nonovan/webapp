"""
Development environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config
from .config_constants import ENVIRONMENT_DEVELOPMENT, DEV_OVERRIDES

class DevelopmentConfig(Config):
    """
    Configuration for development environment.

    This configuration enables debugging features and relaxes certain security
    settings to facilitate development, while still maintaining appropriate
    security controls for sensitive operations.
    """

    DEBUG = True
    TESTING = False
    ENV = ENVIRONMENT_DEVELOPMENT

    # Security settings relaxed for development
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Enable debug toolbar in development
    DEBUG_TB_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    # Development-specific logging
    LOG_LEVEL = 'DEBUG'
    SECURITY_LOG_LEVEL = 'DEBUG'  # Higher logging level for security events in development

    # In-memory cache for development
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

    # ICS development settings
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = ['127.0.0.1']

    # File integrity monitoring settings for development
    SECURITY_CHECK_FILE_INTEGRITY = True  # Enable integrity checking
    ENABLE_FILE_INTEGRITY_MONITORING = True

    # Auto-update baseline for non-critical file changes in development
    AUTO_UPDATE_BASELINE = True

    # File integrity baseline configuration
    BASELINE_UPDATE_APPROVAL_REQUIRED = False  # Simplify development by not requiring approval
    BASELINE_BACKUP_ENABLED = True  # Still maintain backups even in development

    # Use a smaller set of critical files to monitor for faster startup
    CRITICAL_FILES_PATTERN = [
        "*.py",                  # Python source files
        "config/*.py",           # Python configuration files
        "config/*.ini",          # Configuration files
        "core/security/*.py"     # Core security components
    ]

    # Allow HTTP in development for easier testing
    API_REQUIRE_HTTPS = False

    # Disable disaster recovery mode in development
    DR_MODE = False
    DR_ENHANCED_LOGGING = False
    RECOVERY_MODE = False

    # Extended JWT expiration time for easier development
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

    # Enable all feature flags in development
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True

    # Development metrics settings
    METRICS_ENABLED = True
    METRICS_DR_MODE = False
    SENTRY_ENVIRONMENT = 'development'
    SENTRY_TRACES_SAMPLE_RATE = 0.5  # Higher trace rate in development for better debugging

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with development configuration.

        Args:
            app: Flask application instance
        """
        # Initialize with parent configuration
        super().init_app(app)

        # Development-specific initialization
        app.logger.info("Initializing application in development environment")

        # Development path handling - use local paths for easier debugging
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'development')
        app.config['LOG_DIR'] = os.path.join(app.root_path, 'logs', 'development')

        # Enable console logging for all security events in development
        app.config['SECURITY_LOG_TO_CONSOLE'] = True

        # Configure development-specific file integrity settings
        app.config['FILE_BASELINE_PATH'] = os.path.join(app.root_path, 'instance', 'security', 'baseline_dev.json')
