"""
Disaster Recovery configuration for Cloud Infrastructure Platform.

This module provides configuration settings specific to the disaster recovery
environment, optimized for system restoration after an incident or during
DR exercises. It inherits from the base Config class and applies DR-specific
overrides and security settings.
"""

from .base import Config
from .config_constants import ENVIRONMENT_DR_RECOVERY

class DRRecoveryConfig(Config):
    """
    Disaster recovery environment configuration.

    This configuration is designed for use in disaster recovery scenarios,
    maintaining production-level security while providing necessary flexibility
    for recovery operations. It ensures that appropriate security controls
    remain in place during the recovery process.
    """

    ENV = ENVIRONMENT_DR_RECOVERY
    DEBUG = False
    LOG_LEVEL = 'WARNING'

    # Security settings - keep production-level security during DR
    SECURITY_CHECK_FILE_INTEGRITY = True
    SECURITY_LOG_LEVEL = 'WARNING'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    API_REQUIRE_HTTPS = True

    # File integrity monitoring - prevent auto updates in DR environment
    AUTO_UPDATE_BASELINE = False

    # Enhanced logging for DR activities
    DR_ENHANCED_LOGGING = True
    DR_LOG_PATH = '/var/log/cloud-platform/dr-events.log'

    # Recovery-specific settings
    DR_MODE = True
    DR_COORDINATOR_EMAIL = 'dr-coordinator@example.com'
    DR_NOTIFICATION_ENABLED = True

    # DR monitoring configuration
    METRICS_ENABLED = True
    METRICS_DR_MODE = True
    SENTRY_ENVIRONMENT = 'dr-recovery'
    SENTRY_TRACES_SAMPLE_RATE = 0.5  # Higher sampling rate during DR

    # Recovery mode - used by services to determine behavior
    RECOVERY_MODE = True

    @classmethod
    def init_app(cls, app):
        """
        Initialize Flask application with DR recovery configuration.

        Args:
            app: The Flask application instance
        """
        # Initialize with parent configuration first
        super().init_app(app)

        # DR-specific initialization
        app.logger.info("Initializing application in DR RECOVERY mode")

        # Configure DR-specific middleware if available
        if hasattr(app, 'wsgi_app') and hasattr(app, 'response_class'):
            from core.middleware import init_dr_middleware
            try:
                init_dr_middleware(app)
                app.logger.info("DR recovery middleware initialized")
            except ImportError:
                app.logger.warning("DR recovery middleware not available")

        # Set up recovery-specific headers
        @app.after_request
        def add_dr_headers(response):
            """Add DR mode headers to HTTP responses."""
            response.headers['X-DR-Mode'] = 'Active'
            return response

        # Register DR-specific error handlers
        from core.factory import register_dr_error_handlers
        try:
            register_dr_error_handlers(app)
        except ImportError:
            app.logger.warning("DR error handlers not available")

        app.logger.info("DR recovery configuration complete")
