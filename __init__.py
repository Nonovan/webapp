"""
The myproject application package.

This module serves as the entry point for the myproject Flask application,
providing the application factory pattern for proper application initialization.
It coordinates the core configuration, blueprint registration, and error handling
to create a fully configured Flask instance.

Key components:
- Application factory function that assembles all app components
- Version tracking for deployment management
- Blueprint registration for modular feature organization
- Error handling and logging configuration
- Security monitoring initialization
- Enhanced file integrity verification with notification capabilities
- SMS notification integration for critical security events
- Automatic baseline management for development environments

The application follows Flask best practices with a modular structure,
separation of concerns, and dependency injection to facilitate testing
and maintenance.
"""

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from flask import Flask, g, request
from core.factory import create_app as core_create_app
from core import generate_request_id
from views import register_blueprints
from services import (
    check_integrity, SECURITY_SERVICE_AVAILABLE, SMS_SERVICE_AVAILABLE,
    update_file_integrity_baseline_with_notifications, validate_baseline_consistency
)

__version__ = '1.0.0'

# Configure logger early for initialization errors
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """
    Create and configure the Flask application.

    This function implements the application factory pattern, creating a new Flask
    instance with all the necessary configuration, extensions, and blueprints. It
    separates application creation from usage to enable better testability
    and configuration flexibility.

    The factory handles:
    - Core configuration loading
    - Blueprint registration
    - Extension initialization
    - Error handling setup
    - Security monitoring initialization
    - File integrity verification
    - Notification service setup
    - Baseline management with notifications

    Returns:
        Flask: A fully configured Flask application instance ready to serve requests

    Raises:
        Exception: If application initialization fails, with detailed error logging
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Create base app
        app = Flask(__name__)

        # Configure via core factory
        app = core_create_app(None)

        # Register blueprints
        register_blueprints(app)

        # Set version
        app.config['VERSION'] = __version__

        # Store application startup time for uptime tracking
        app.uptime = datetime.utcnow()

        # Set up request tracking middleware
        @app.before_request
        def set_request_context():
            """Set up context for request tracking and monitoring."""
            # Generate unique request ID
            g.request_id = request.headers.get('X-Request-ID', generate_request_id())
            g.start_time = datetime.utcnow()

            # Make CSP nonce available for this request
            g.csp_nonce = os.urandom(16).hex()

        # Set up file integrity monitoring if enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            # Check if SecurityService is available (via services package)
            if SECURITY_SERVICE_AVAILABLE:
                # Verify baseline consistency before running integrity checks
                if app.config.get('VERIFY_BASELINE_CONSISTENCY', True):
                    try:
                        # Validate the structure and format of the baseline
                        is_consistent, consistency_issues = validate_baseline_consistency(
                            app.config.get('FILE_BASELINE_PATH')
                        )
                        if not is_consistent:
                            app.logger.warning(
                                "Baseline consistency check failed: %s",
                                consistency_issues.get('message', 'Unknown issue')
                            )
                            # Don't automatically repair in production/staging
                            if app.config.get('ENVIRONMENT') == 'development' and app.config.get('AUTO_REPAIR_BASELINE', False):
                                app.logger.info("Attempting to repair baseline inconsistencies")
                                # Logic for repairing baseline would be implemented here
                    except Exception as consistency_err:
                        app.logger.error(f"Error during baseline consistency check: {consistency_err}")

                # Perform initial integrity check
                integrity_status, changes = check_integrity()

                # Log results appropriately
                if not integrity_status:
                    # Categorize changes by severity for appropriate handling
                    critical_changes = [c for c in changes if c.get('severity') == 'critical']
                    high_changes = [c for c in changes if c.get('severity') == 'high']
                    medium_changes = [c for c in changes if c.get('severity') == 'medium']
                    low_changes = [c for c in changes if c.get('severity', 'low') == 'low']

                    # Process critical integrity violations
                    if critical_changes and app.config.get('ENVIRONMENT') in ['production', 'staging']:
                        app.logger.critical(
                            "Critical integrity violations detected during startup (%d changes)",
                            len(critical_changes)
                        )

                        # Notify security team about critical violations via SMS if available
                        if SMS_SERVICE_AVAILABLE and app.config.get('NOTIFY_CRITICAL_VIOLATIONS', True):
                            try:
                                from services import send_sms
                                security_phone = app.config.get('SECURITY_ALERT_PHONE')
                                if security_phone:
                                    # Enhanced message with more details
                                    critical_files = ", ".join([c.get('path', 'unknown') for c in critical_changes[:3]])
                                    if len(critical_changes) > 3:
                                        critical_files += f" and {len(critical_changes) - 3} more"

                                    send_sms(
                                        to=security_phone,
                                        message=(
                                            f"CRITICAL: File integrity violations on {app.config.get('ENVIRONMENT')} - "
                                            f"{len(critical_changes)} critical files affected: {critical_files}. "
                                            f"Immediate action required."
                                        ),
                                        priority="critical",
                                        category="security"
                                    )
                                    app.logger.info("SMS security alert sent successfully")
                            except Exception as sms_err:
                                app.logger.error(f"Failed to send SMS notification: {sms_err}")

                        # Abort startup in production/staging unless explicitly ignored
                        if not app.config.get('IGNORE_INTEGRITY_FAILURES', False):
                            app.logger.critical("Application startup aborted due to integrity violations")
                            sys.exit(1)

                    # Process high severity violations
                    elif high_changes:
                        app.logger.error(
                            "High severity integrity violations detected (%d changes)",
                            len(high_changes)
                        )

                        # Consider auto-updating baseline in development environment
                        if (app.config.get('ENVIRONMENT') == 'development' and
                            app.config.get('AUTO_UPDATE_BASELINE', False)):
                            try:
                                # Update baseline with notifications for development environment
                                baseline_path = app.config.get('FILE_BASELINE_PATH')

                                # Skip critical and high severity changes - only auto-update medium and low risk files
                                update_changes = medium_changes + low_changes

                                # Verify updates don't exceed configured limits
                                max_files = app.config.get('BASELINE_UPDATE_MAX_FILES', 50)
                                if len(update_changes) > max_files:
                                    app.logger.warning(
                                        f"Auto-update would modify {len(update_changes)} files, "
                                        f"exceeding limit of {max_files}. Trimming to limit."
                                    )
                                    # Truncated to limit, with medium severity first, then low
                                    update_changes = sorted(
                                        update_changes,
                                        key=lambda x: 0 if x.get('severity') == 'medium' else 1
                                    )[:max_files]

                                # Only update if we have changes to apply
                                if update_changes:
                                    app.logger.info(f"Auto-updating baseline with {len(update_changes)} non-critical changes")

                                    # We'll log excluded high severity files for reference
                                    if high_changes:
                                        high_files = ", ".join([c.get('path', 'unknown') for c in high_changes[:3]])
                                        if len(high_changes) > 3:
                                            high_files += f" and {len(high_changes) - 3} more"
                                        app.logger.info(f"Skipping {len(high_changes)} high severity files: {high_files}")

                                    # Perform the update with notifications
                                    success, message, stats = update_file_integrity_baseline_with_notifications(
                                        baseline_path=baseline_path,
                                        changes=update_changes,
                                        remove_missing=True,
                                        notify=app.config.get('FILE_INTEGRITY_NOTIFY_ON_UPDATE', True),
                                        audit=app.config.get('AUDIT_BASELINE_UPDATES', True),
                                        severity_threshold=app.config.get('NOTIFICATION_THRESHOLD', 'medium'),
                                        update_limit=max_files
                                    )

                                    # Log results with detailed stats
                                    if success:
                                        app.logger.info(
                                            f"Baseline auto-updated: {message} "
                                            f"({stats.get('changes_applied', 0)} changes applied, "
                                            f"{stats.get('removed_entries', 0)} entries removed)"
                                        )
                                    else:
                                        app.logger.warning(f"Baseline auto-update failed: {message}")
                                else:
                                    app.logger.info("No appropriate changes to auto-update")
                            except Exception as e:
                                app.logger.error(f"Error during baseline auto-update: {e}")

                    # Handle medium/low severity violations
                    else:
                        app.logger.warning(
                            "File integrity check failed with %d changes detected",
                            len(changes)
                        )

                        # For development environments, consider auto-updating even these changes
                        if (app.config.get('ENVIRONMENT') == 'development' and
                            app.config.get('AUTO_UPDATE_MINOR_CHANGES', True)):
                            try:
                                # Similar auto-update logic but with lower risk threshold
                                baseline_path = app.config.get('FILE_BASELINE_PATH')
                                if changes:
                                    success, message, stats = update_file_integrity_baseline_with_notifications(
                                        baseline_path=baseline_path,
                                        changes=changes,
                                        remove_missing=True,
                                        notify=False,  # No notifications for minor changes
                                        audit=True,
                                        severity_threshold='low',
                                        update_limit=app.config.get('BASELINE_UPDATE_MAX_FILES', 50)
                                    )
                                    if success:
                                        app.logger.info(f"Baseline silently updated with minor changes: {message}")
                                    else:
                                        app.logger.debug(f"Minor baseline update failed: {message}")
                            except Exception as minor_err:
                                app.logger.debug(f"Error during minor baseline update: {minor_err}")
                else:
                    app.logger.info("File integrity check passed")
            else:
                # Fall back to basic file integrity checks
                from core.config import Config
                app.config = Config.initialize_file_hashes(
                    app.config,
                    os.path.dirname(os.path.abspath(__file__))
                )
                app.logger.info("Basic file integrity monitoring initialized")

        # Calculate and log initialization time
        init_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        app.logger.info(
            "Application initialized successfully in %.2f seconds (version: %s)",
            init_duration,
            __version__
        )

        return app

    except Exception as e:
        # Log critical error
        logging.critical("Failed to create application: %s", e)
        raise
