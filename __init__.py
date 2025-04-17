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
from datetime import datetime
from flask import Flask, g, request
from core.factory import create_app as core_create_app
from core.utils import generate_request_id
from views import register_blueprints

__version__ = '1.0.0'

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
            from core.config import Config
            app.config = Config.initialize_file_hashes(
                app.config, 
                os.path.dirname(os.path.abspath(__file__))
            )
            app.logger.info("File integrity monitoring initialized")

        return app

    except Exception as e:
        # Log critical error
        logging.critical("Failed to create application: %s", e)
        raise
