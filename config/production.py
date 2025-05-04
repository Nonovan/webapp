"""
Production environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config
from .config_constants import ENVIRONMENT_PRODUCTION

class ProductionConfig(Config):
    """Configuration for production environment."""

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

    # Redis for caching in production
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')

    # Rate limiting with Redis in production
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')

    # Sessions with Redis in production
    SESSION_TYPE = 'redis'

    # Sentry error reporting
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'production'
    SENTRY_TRACES_SAMPLE_RATE = 0.1

    # Enable strict file integrity checking in production
    SECURITY_CHECK_FILE_INTEGRITY = True
    SECURITY_LOG_LEVEL = 'WARNING'

    # File integrity monitoring - prevent auto updates in production
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False

    # Enforce strict CSP and security headers
    SECURITY_HEADERS_ENABLED = True
    API_REQUIRE_HTTPS = True

    # Production logging level
    LOG_LEVEL = 'WARNING'

    # ICS security settings
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = os.environ.get('ICS_RESTRICTED_IPS', '').split(',')

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

        # Register production-specific error handlers if available
        if hasattr(app, 'errorhandler'):
            @app.errorhandler(500)
            def internal_server_error(e):
                # Log detailed information about the error internally
                app.logger.error("%s", e)

                # Return a generic message to users to avoid exposing internals
                return "An internal server error occurred", 500
