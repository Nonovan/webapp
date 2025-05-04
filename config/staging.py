"""
Staging environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config
from .config_constants import ENVIRONMENT_STAGING

class StagingConfig(Config):
    """Configuration for staging environment."""

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

    # Staging-specific database
    SQLALCHEMY_DATABASE_URI = os.environ.get('STAGING_DATABASE_URL')

    # Redis for caching in staging
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('STAGING_REDIS_URL')
    RATELIMIT_STORAGE_URL = os.environ.get('STAGING_REDIS_URL')

    # Session storage
    SESSION_TYPE = 'redis'

    # Logging settings
    LOG_LEVEL = 'INFO'
    SECURITY_LOG_LEVEL = 'WARNING'

    # Sentry error reporting for staging
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2

    # File integrity monitoring settings
    SECURITY_CHECK_FILE_INTEGRITY = True
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False

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

        # Set staging-specific headers
        @app.after_request
        def add_staging_headers(response):
            """Add staging environment headers to HTTP responses."""
            response.headers['X-Environment'] = 'Staging'
            return response
