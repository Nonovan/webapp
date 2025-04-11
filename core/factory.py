"""
Application factory module for myproject.

This module provides the central application factory function that creates and
configures Flask application instances. It implements the factory pattern to
enable flexible application creation with different configurations for various
environments including development, testing, and production.

The factory handles all aspects of application initialization:
- Configuration loading and validation
- Extension initialization (database, cache, CSRF, etc.)
- Middleware setup for request/response processing
- Error handling and logging configuration
- Route registration
- Health check endpoints

This architecture allows for better testing isolation, prevents circular
imports, and provides a single entry point for application configuration.
"""

import logging
from datetime import datetime
from typing import Optional
from flask import Flask
from extensions import db, migrate, csrf, cache, limiter, session, metrics
from core.config import Config
from core.loggings import setup_app_loggings, get_logger
from core.middleware import (
    setup_security_headers,
    setup_request_context,
    setup_response_context
)

logger = get_logger(Flask(__name__))

def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Create and configure a Flask application instance.

    This factory function is the central point for creating application instances.
    It handles all aspects of application initialization including configuration
    loading, extension setup, middleware registration, and error handling.

    Args:
        config_name (Optional[str]): Name of specific configuration to load
                                    ('development', 'production', 'testing')

    Returns:
        Flask: A fully configured Flask application instance

    Raises:
        Exception: If application initialization fails, with detailed error logging

    Example:
        # Create an application with default configuration
        app = create_app()

        # Create an application with testing configuration
        test_app = create_app('testing')
    """
    try:
        app = Flask(__name__)

        # Load and validate configuration
        config = Config.load()
        if config_name:
            config.update(Config.load_from_name(config_name))
        app.config.update(config)

        # Track application metadata
        app.uptime = datetime.utcnow()
        app.version = config.get('VERSION', '1.0.0')

        # Setup core services
        setup_app_loggings(app)

        # Setup request handling
        app.before_request(setup_request_context)
        app.after_request(setup_security_headers)
        app.after_request(setup_response_context)

        # Initialize extensions with error handling
        try:
            db.init_app(app)
            migrate.init_app(app, db)
            csrf.init_app(app)
            cache.init_app(app)
            limiter.init_app(app)
            session.init_app(app)
            metrics.init_app(app)
        except Exception as e:
            logger.error("Failed to initialize extensions: %s", e)
            raise

        # Register health check
        @app.route('/health')
        def health_check():
            return {
                'status': 'healthy',
                'uptime': str(datetime.utcnow() - app.uptime),
                'version': app.version
            }

        return app

    except Exception as e:
        logging.critical("Failed to create application: %s", e)
        raise
