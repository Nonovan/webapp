"""
Staging environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config
from .config_constants import (
    ENVIRONMENT_STAGING,
    FILE_INTEGRITY_MONITORED_PATTERNS,
    PROD_SECURITY_REQUIREMENTS
)

class StagingConfig(Config):
    """
    Configuration for staging environment.

    Mirrors production-like settings with additional logging and observability
    features to facilitate pre-production validation and testing while
    maintaining strong security controls.
    """

    DEBUG = False
    TESTING = False
    ENV = ENVIRONMENT_STAGING

    # Security settings for staging (same as production)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # API security
    API_REQUIRE_HTTPS = True

    # JWT settings - similar to production
    JWT_ACCESS_TOKEN_EXPIRES = 900  # 15 minutes
    JWT_BLACKLIST_ENABLED = True

    # Staging-specific database
    SQLALCHEMY_DATABASE_URI = os.environ.get('STAGING_DATABASE_URL')

    # Redis for caching in staging
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('STAGING_REDIS_URL')
    RATELIMIT_STORAGE_URL = os.environ.get('STAGING_REDIS_URL')

    # Session storage
    SESSION_TYPE = 'redis'

    # Logging settings - more verbose than production
    LOG_LEVEL = 'INFO'
    SECURITY_LOG_LEVEL = 'WARNING'
    EXPLAIN_TEMPLATE_LOADING = False

    # Sentry error reporting for staging
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2

    # File integrity monitoring settings - production-like with more logging
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False
    BASELINE_UPDATE_APPROVAL_REQUIRED = True
    BASELINE_BACKUP_ENABLED = True
    BASELINE_UPDATE_RETENTION = 7  # Keep baseline backups for a week in staging
    FILE_HASH_ALGORITHM = 'sha256'
    CHECK_FILE_SIGNATURES = True

    # Comprehensive monitoring patterns for staging
    # Use both critical and high priority patterns (like production)
    CRITICAL_FILES_PATTERN = FILE_INTEGRITY_MONITORED_PATTERNS.get('critical', []) + \
                            FILE_INTEGRITY_MONITORED_PATTERNS.get('high', [])

    # Rate limiting - slightly higher than production to account for testing
    RATELIMIT_DEFAULT = '250 per day, 60 per hour'
    RATELIMIT_ENABLED = True

    # Auditing - enabled but with shorter retention
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_RETENTION_DAYS = 180  # 6 months vs 1 year in production

    # Disable disaster recovery features in staging
    DR_MODE = False
    DR_ENHANCED_LOGGING = False
    DR_BASELINE_FROZEN = False
    RECOVERY_MODE = False

    # Feature flags - all enabled for full testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with staging configuration.

        Args:
            app: Flask application instance
        """
        # Initialize with parent configuration
        super().init_app(app)

        # Add staging-specific initialization
        app.logger.info("Initializing application in STAGING mode")

        # Set staging-specific paths
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_staging.json'
        )
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'staging')
        app.config['BASELINE_BACKUP_PATH_TEMPLATE'] = 'instance/security/baseline_backups/staging_{timestamp}.json'

        # Enhanced logging for staging environment
        app.config['AUDIT_LOG_LEVEL'] = 'INFO'
        app.config['SECURITY_LOG_TO_CONSOLE'] = True

        # Verify production security requirements in staging
        missing_requirements = []
        for requirement in PROD_SECURITY_REQUIREMENTS:
            if not app.config.get(requirement, False):
                missing_requirements.append(requirement)

        if missing_requirements:
            app.logger.warning(f"Missing security requirements in staging: {', '.join(missing_requirements)}")

        # Set staging-specific headers
        @app.after_request
        def add_staging_headers(response):
            """Add staging environment headers to HTTP responses."""
            response.headers['X-Environment'] = 'Staging'
            return response

        # Initialize file integrity monitoring if enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            try:
                # Ensure baseline directory exists
                baseline_dir = os.path.dirname(app.config['FILE_BASELINE_PATH'])
                if not os.path.exists(baseline_dir):
                    os.makedirs(baseline_dir, exist_ok=True)

                # Check for baseline file integrity on application startup for staging
                from core.security.cs_file_integrity import check_critical_file_integrity
                is_valid, violations = check_critical_file_integrity(app)

                if not is_valid:
                    app.logger.warning(
                        f"File integrity check found {len(violations)} violations in staging environment"
                    )
                else:
                    app.logger.info("File integrity verification passed on staging startup")

            except ImportError:
                app.logger.warning("File integrity monitoring module not available in staging environment")

        # Configure Content Security Policy for staging (similar to production but allows more sources for testing)
        app.config['CSP_DEFAULT_SRC'] = ["'self'"]
        app.config['CSP_SCRIPT_SRC'] = ["'self'", "'unsafe-inline'"]  # Allow inline for testing tools
        app.config['CSP_STYLE_SRC'] = ["'self'", "'unsafe-inline'"]   # Allow inline for testing tools
        app.config['CSP_IMG_SRC'] = ["'self'", "data:"]
        app.config['CSP_OBJECT_SRC'] = ["'none'"]
