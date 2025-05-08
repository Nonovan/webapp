"""
Disaster Recovery configuration for Cloud Infrastructure Platform.

This module provides configuration settings specific to the disaster recovery
environment, optimized for system restoration after an incident or during
DR exercises. It inherits from the base Config class and applies DR-specific
overrides and security settings.
"""

import os
from typing import Dict, Any
from .base import Config
from .config_constants import (
    ENVIRONMENT_DR_RECOVERY,
    DEFAULT_DR_CONFIG,
    DR_OVERRIDES,
    FILE_INTEGRITY_SEVERITY_MAPPING
)

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
    ENABLE_FILE_INTEGRITY_MONITORING = True
    AUTO_UPDATE_BASELINE = False
    BASELINE_UPDATE_APPROVAL_REQUIRED = True
    DR_BASELINE_FROZEN = True  # Prevent baseline changes during DR

    # Enhanced logging for DR activities
    DR_ENHANCED_LOGGING = True
    DR_LOG_PATH = '/var/log/cloud-platform/dr-events.log'
    SECURITY_LOG_TO_CONSOLE = True  # Also log security events to console for visibility

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

    # File integrity monitoring patterns - focus on critical files during recovery
    CRITICAL_FILES_PATTERN = [
        "*.py",                  # Python source files
        "config/*.py",           # Python configuration files
        "config/*.ini",          # Configuration files
        "core/security/*.py",    # Core security components
        "models/security/*.py",  # Security models
        "api/security/*.py",     # Security API endpoints
        "scripts/deployment/dr/*.sh"  # DR scripts
    ]

    # Recovery priorities based on service types
    DR_RECOVERY_PRIORITIES = {
        'critical': ['authentication', 'authorization', 'core_services'],
        'high': ['data_access', 'api_endpoints', 'monitoring'],
        'medium': ['reporting', 'notifications', 'batch_jobs'],
        'low': ['ui_customization', 'analytics', 'non_critical_features']
    }

    # Validation settings for DR mode
    STRICT_VALIDATION = True
    VERIFICATION_TIMEOUT = 120  # Longer timeout for verification operations

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

        # Ensure DR log directory exists and has proper permissions
        dr_log_path = app.config.get('DR_LOG_PATH')
        if dr_log_path:
            dr_log_dir = os.path.dirname(dr_log_path)
            try:
                if not os.path.exists(dr_log_dir):
                    os.makedirs(dr_log_dir, mode=0o750)
                    app.logger.info(f"Created DR log directory: {dr_log_dir}")
            except OSError as e:
                app.logger.error(f"Failed to create DR log directory: {dr_log_dir} - {str(e)}")

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

        # Set up file integrity monitoring
        app.config['FILE_BASELINE_PATH'] = os.path.join(
            app.root_path, 'instance', 'security', 'baseline_dr.json'
        )

        # Initialize file integrity monitoring if available
        try:
            from core.security.cs_file_integrity import initialize_file_monitoring
            basedir = app.root_path
            patterns = app.config.get('CRITICAL_FILES_PATTERN')
            interval = app.config.get('FILE_INTEGRITY_CHECK_INTERVAL', 3600)
            initialize_file_monitoring(app, basedir, patterns, interval, from_dr=True)
            app.logger.info("DR file integrity monitoring initialized")
        except ImportError:
            app.logger.warning("File integrity monitoring not available in DR mode")

        # Initialize incident response kit integration if available
        try:
            from admin.security.incident_response_kit.recovery import initialize_dr_integration
            initialize_dr_integration(app)
            app.logger.info("Incident response kit integration initialized")
        except (ImportError, AttributeError):
            app.logger.warning("Incident response kit integration not available")

        # Set up baseline verification
        try:
            from core.security.cs_file_integrity import verify_critical_files
            result = verify_critical_files(app)
            if not result:
                app.logger.warning("Critical file verification failed in DR mode")
            else:
                app.logger.info("Critical file verification completed successfully")
        except ImportError:
            app.logger.warning("Critical file verification not available")

        # Verify DR recovery setup
        from config import verify_dr_recovery_setup
        is_valid, issues = verify_dr_recovery_setup(app)
        if not is_valid:
            app.logger.warning(f"DR recovery setup has issues: {', '.join(issues)}")
        else:
            app.logger.info("DR recovery setup validation passed")

        # Log DR mode activation
        try:
            from core.security.cs_audit import log_security_event
            log_data = {
                'environment': ENVIRONMENT_DR_RECOVERY,
                'dr_coordinator': app.config.get('DR_COORDINATOR_EMAIL')
            }
            log_security_event('dr_mode_activated', 'notice', log_data)
        except ImportError:
            app.logger.warning("Security audit logging not available")

        app.logger.info("DR recovery configuration complete")
