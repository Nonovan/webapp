"""
Production environment configuration for Cloud Infrastructure Platform.

This module defines the configuration settings for the production environment,
enforcing strict security controls, optimizing performance, and enabling
comprehensive monitoring and integrity verification.
"""

import os
from .base import Config
from .config_constants import (
    ENVIRONMENT_PRODUCTION,
    FILE_INTEGRITY_MONITORED_PATTERNS,
    PROD_SECURITY_REQUIREMENTS
)

class ProductionConfig(Config):
    """
    Configuration for production environment.

    Enforces strict security controls, disables debugging features, and
    optimizes for performance and reliability in production environments.
    """

    DEBUG = False
    TESTING = False
    ENV = ENVIRONMENT_PRODUCTION

    # Strict security settings for production
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True

    # Production database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

    # Redis for caching, rate limiting and sessions in production
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
    SESSION_TYPE = 'redis'

    # Sentry error reporting
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'production'
    SENTRY_TRACES_SAMPLE_RATE = 0.1

    # File integrity monitoring - strict settings for production
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False  # Never auto-update baseline in production
    BASELINE_UPDATE_APPROVAL_REQUIRED = True
    BASELINE_BACKUP_ENABLED = True
    BASELINE_UPDATE_RETENTION = 10  # Keep more baseline backups in production
    FILE_HASH_ALGORITHM = 'sha256'
    CHECK_FILE_SIGNATURES = True

    # Use comprehensive monitored patterns for production
    CRITICAL_FILES_PATTERN = FILE_INTEGRITY_MONITORED_PATTERNS.get('critical', []) + \
                            FILE_INTEGRITY_MONITORED_PATTERNS.get('high', [])

    # Security logging and headers
    SECURITY_LOG_LEVEL = 'WARNING'
    SECURITY_HEADERS_ENABLED = True
    API_REQUIRE_HTTPS = True

    # Production logging level
    LOG_LEVEL = 'WARNING'

    # Industrial Control Systems (ICS) security settings
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = os.environ.get('ICS_RESTRICTED_IPS', '').split(',')
    ICS_MONITOR_INTERVAL = 30  # More frequent monitoring in production

    # Enhanced security for production
    WTF_CSRF_ENABLED = True
    JWT_BLACKLIST_ENABLED = True
    METRICS_ENABLED = True

    # Audit logging configuration
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_RETENTION_DAYS = 365  # Keep audit logs for at least a year in production

    # Disaster Recovery configuration
    DR_BASELINE_FROZEN = True  # Prevent baseline changes during DR
    DR_NOTIFICATION_ENABLED = True
    DR_COORDINATOR_EMAIL = os.environ.get('DR_COORDINATOR_EMAIL')

    # Feature flags - ensure critical security features are enabled
    FEATURE_MFA = True  # Always require MFA in production

    @classmethod
    def init_app(cls, app):
        """
        Initialize application with production configuration.

        Args:
            app: Flask application instance
        """
        # Initialize with parent configuration
        super().init_app(app)

        # Production-specific initialization
        app.logger.info("Initializing application in PRODUCTION mode")

        # Set up production-specific paths
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_prod.json'
        )
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'production')

        # Verify that all required security settings are properly configured
        missing_security_settings = []
        for setting in PROD_SECURITY_REQUIREMENTS:
            if not app.config.get(setting, False):
                missing_security_settings.append(setting)

        if missing_security_settings:
            app.logger.error(f"Missing required security settings in production: {', '.join(missing_security_settings)}")

        # Register production-specific error handlers
        if hasattr(app, 'errorhandler'):
            @app.errorhandler(500)
            def internal_server_error(e):
                # Log detailed information about the error internally
                app.logger.error("%s", e)

                # Return a generic message to users to avoid exposing internals
                return "An internal server error occurred", 500

        # Set up session timeout for security (15 minutes of inactivity)
        app.config['PERMANENT_SESSION_LIFETIME'] = 900

        # Set advanced protection measures
        app.config['ENFORCE_MFA_FOR_ADMIN'] = True
        app.config['API_RATE_LIMITING'] = True
        app.config['SESSION_PERMANENT'] = False

        # Ensure file integrity monitoring is properly configured
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            try:
                # Try to use the file integrity verification on startup
                from core.security.cs_file_integrity import check_critical_file_integrity
                is_valid, violations = check_critical_file_integrity(app)

                if not is_valid:
                    app.logger.error(
                        f"File integrity verification failed on startup with {len(violations)} violations. "
                        "This may indicate a security breach."
                    )
                else:
                    app.logger.info("File integrity verification passed on startup.")
            except ImportError:
                app.logger.warning("File integrity monitoring module not available.")

        # Configure Content Security Policy
        app.config['CSP_DEFAULT_SRC'] = ["'self'"]
        app.config['CSP_SCRIPT_SRC'] = ["'self'"]  # No unsafe-inline in production
        app.config['CSP_STYLE_SRC'] = ["'self'"]   # No unsafe-inline in production
        app.config['CSP_IMG_SRC'] = ["'self'", "data:"]
        app.config['CSP_OBJECT_SRC'] = ["'none'"]

        # Configure additional security headers
        app.config['SECURITY_HSTS_MAX_AGE'] = 31536000  # 1 year
        app.config['SECURITY_INCLUDE_SUBDOMAINS'] = True
        app.config['SECURITY_PRELOAD'] = True
