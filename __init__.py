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

The application follows Flask best practices with a modular structure,
separation of concerns, and dependency injection to facilitate testing
and maintenance.
"""

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, g, request
from core.factory import create_app as core_create_app
from core.utils import generate_request_id
from views import register_blueprints
from services import check_integrity, SECURITY_SERVICE_AVAILABLE

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
                # Perform initial integrity check
                integrity_status, changes = check_integrity()

                # Log results appropriately
                if not integrity_status:
                    critical_changes = [c for c in changes if c.get('severity') == 'critical']
                    high_changes = [c for c in changes if c.get('severity') == 'high']

                    if critical_changes and app.config.get('ENVIRONMENT') in ['production', 'staging']:
                        app.logger.critical(
                            "Critical integrity violations detected during startup (%d changes)",
                            len(critical_changes)
                        )
                        if not app.config.get('IGNORE_INTEGRITY_FAILURES', False):
                            app.logger.critical("Application startup aborted due to integrity violations")
                            sys.exit(1)
                    elif high_changes:
                        app.logger.error(
                            "High severity integrity violations detected (%d changes)",
                            len(high_changes)
                        )
                    else:
                        app.logger.warning(
                            "File integrity check failed with %d changes detected",
                            len(changes)
                        )
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
