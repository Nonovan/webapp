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
    BASELINE_UPDATE_RETENTION = 3  # Keep fewer baseline backups in dev than production

    # Use a smaller set of critical files to monitor for faster startup
    CRITICAL_FILES_PATTERN = [
        "*.py",                  # Python source files
        "config/*.py",           # Python configuration files
        "config/*.ini",          # Configuration files
        "core/security/*.py"     # Core security components
    ]

    # Skip signature verification in development for faster performance
    CHECK_FILE_SIGNATURES = False

    # Allow HTTP in development for easier testing
    API_REQUIRE_HTTPS = False

    # Disable disaster recovery mode in development
    DR_MODE = False
    DR_ENHANCED_LOGGING = False
    RECOVERY_MODE = False
    DR_BASELINE_FROZEN = False  # Allow baseline updates in development

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

    # Development-specific baseline patterns that can be auto-updated
    BASELINE_AUTO_UPDATE_PATTERN = [
        "*.css",
        "*.js",
        "static/*",
        "templates/*.html",
        "*.py",  # In development, allow Python files to be auto-updated
        "tests/*"  # Test files can change frequently in development
    ]

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
        app.config['TEMP_DIR'] = os.path.join(app.root_path, 'tmp', 'development')

        # Create temp directory if it doesn't exist
        if not os.path.exists(app.config['TEMP_DIR']):
            os.makedirs(app.config['TEMP_DIR'], exist_ok=True)

        # Enable console logging for all security events in development
        app.config['SECURITY_LOG_TO_CONSOLE'] = True
        app.config['EXPLAIN_TEMPLATE_LOADING'] = True

        # Configure development-specific file integrity settings
        app.config['FILE_BASELINE_PATH'] = os.path.join(app.root_path, 'instance', 'security', 'baseline_dev.json')

        # Set higher threshold for file updates in development
        app.config['BASELINE_UPDATE_MAX_FILES'] = 100  # Allow more files to be updated at once in dev

        # Set development-specific backup path template with timestamp for easy identification
        app.config['BASELINE_BACKUP_PATH_TEMPLATE'] = 'instance/security/baseline_backups/dev_{timestamp}.json'

        # Enable file integrity monitoring debug mode in development
        app.config['FILE_INTEGRITY_DEBUG'] = True

        # Ensure critical directories exist
        baseline_dir = os.path.dirname(app.config['FILE_BASELINE_PATH'])
        if not os.path.exists(baseline_dir):
            os.makedirs(baseline_dir, exist_ok=True)
