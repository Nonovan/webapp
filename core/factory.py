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
- Security monitoring and compliance
- ICS system integration

This architecture allows for better testing isolation, prevents circular
imports, and provides a single entry point for application configuration.
"""

import os
import platform
import sys
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from jinja2 import TemplateNotFound
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from blueprints import register_all_blueprints
from extensions import jwt, init_extensions
from core.config import Config
from core.loggings import setup_app_logging, get_security_logger
from core.middleware import init_middleware
from core.utils import generate_sri_hash
from core.health import register_health_endpoints
from api import register_api


logger = get_security_logger()

def create_app(config_object=None):
    """
    Create and configure a Flask application instance.

    This factory function is the central point for creating application instances.
    It handles all aspects of application initialization including configuration
    loading, extension setup, middleware registration, and error handling.

    Args:
        config_object (Optional[object]): Configuration object or path to load

    Returns:
        Flask: Configured Flask application instance
    """
    # Create the Flask application instance
    app = Flask(__name__)

    # Configure the application
    configure_app(app, config_object)

    # Initialize logging first so other init functions can log
    setup_app_logging(app)

    # Register all components
    register_extensions(app)
    register_error_handlers(app)
    register_context_processors(app)
    register_all_blueprints(app)
    register_api(app)
    register_health_endpoints(app)

    # Initialize middleware (security headers, request tracking, etc.)
    init_middleware(app)

    # Log application startup
    log_startup_info(app)

    return app


def configure_app(app, config_object=None):
    """
    Configure the Flask application with appropriate settings.
    
    Args:
        app (Flask): The Flask application instance
        config_object: Configuration object or string path
    """
    # Load default configuration
    app.config.from_object(Config)

    # Override with instance config if it exists
    instance_config = os.path.join(app.instance_path, 'config.py')
    if os.path.exists(instance_config):
        app.config.from_pyfile(instance_config)

    # Override with provided config if any
    if config_object:
        if isinstance(config_object, str):
            app.config.from_pyfile(config_object)
        else:
            app.config.from_object(config_object)

    # Override with environment variables (highest priority)
    app.config.from_prefixed_env(prefix="MYAPP")

    # Validate required configuration
    validate_configuration(app)

    # Configure application version and environment info
    app.config.setdefault('VERSION', '1.0.0')
    app.config.setdefault('BUILD_TIMESTAMP', datetime.now(timezone.utc).isoformat())

    # Set up template functions
    app.jinja_env.globals['sri_hash'] = generate_sri_hash


def register_extensions(app):
    """
    Initialize and register Flask extensions with the application.
    
    Args:
        app (Flask): The Flask application instance
    """
    # Initialize all extensions with a helper function from extensions package
    init_extensions(app)

    # Register JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'status': 'error',
            'message': 'Token has expired',
            'code': 'token_expired'
        }), 401


def register_error_handlers(app):
    """
    Register error handlers for different types of exceptions.
    
    Args:
        app (Flask): The Flask application instance
    """
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Handle CSRF validation errors."""
        app.logger.warning(f"CSRF error: {e.description}", extra={
            'http_status': 400,
            'error_type': 'csrf_error',
            'ip_address': request.remote_addr
        })

        if request.is_xhr or request.path.startswith('/api/'):
            return jsonify({
                'status': 'error',
                'message': 'CSRF validation failed',
                'code': 'csrf_error'
            }), 400

        return render_template('errors/400.html', error=e.description), 400

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Handle all HTTP exceptions."""
        app.logger.info(f"HTTP {e.code}: {e.description}", extra={
            'http_status': e.code,
            'path': request.path
        })

        if request.is_xhr or request.path.startswith('/api/'):
            return jsonify({
                'status': 'error',
                'message': e.description,
                'code': str(e.code)
            }), e.code

        # Try to load specific error template
        try:
            return render_template(f'errors/{e.code}.html', error=e.description), e.code
        except TemplateNotFound:
            # If specific template doesn't exist, use generic one
            return render_template('errors/generic.html', error=e, code=e.code), e.code

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle all unhandled exceptions."""
        # Log the full exception with traceback
        app.logger.exception("Unhandled exception occurred", extra={
            'error': str(e),
            'error_type': e.__class__.__name__,
            'path': request.path if request else 'No request context'
        })

        # Return appropriate response based on request type
        if request and (request.is_xhr or request.path.startswith('/api/')):
            return jsonify({
                'status': 'error',
                'message': 'An unexpected error occurred',
                'code': 'server_error'
            }), 500

        # Load error template
        try:
            return render_template('errors/500.html', error=str(e)), 500
        except TemplateNotFound:
            # Fallback for when template rendering fails
            app.logger.error("Template rendering failed: Template not found")
            return "A server error occurred. Please try again later.", 500

def register_context_processors(app):
    """
    Register template context processors to make variables available in templates.
    
    Args:
        app (Flask): The Flask application instance
    """
    @app.context_processor
    def inject_globals():
        """Make common variables available to all templates."""
        return {
            'now': datetime.now(timezone.utc),
            'version': app.config.get('VERSION', '1.0.0'),
            'environment': app.config.get('ENV', 'production'),
            'app_name': app.config.get('APP_NAME', 'MyProject')
        }

    @app.context_processor
    def inject_user():
        """Make current user available to all templates."""
        from flask import session
        user_id = session.get('user_id')
        if user_id:
            try:
                from models.user import User
                user = User.query.get(user_id)
                if user:
                    return {'current_user': user}
            except (AttributeError, KeyError, ImportError) as e:
                app.logger.warning(f"Error fetching user: {e}")
        return {'current_user': None}

def validate_configuration(app):
    """
    Validate that all required configuration values are set.
    
    Args:
        app (Flask): The Flask application instance
    
    Raises:
        ValueError: If a required configuration value is missing
    """
    required_configs = [
        'SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI',
    ]

    missing = [key for key in required_configs if not app.config.get(key)]

    if missing:
        raise ValueError(f"Missing required configuration values: {', '.join(missing)}")

    # Check for insecure configuration in production
    if app.config.get('ENV') == 'production':
        if app.config.get('DEBUG'):
            raise ValueError("DEBUG should be False in production")
        if app.config.get('TESTING'):
            raise ValueError("TESTING should be False in production")
        if app.config.get('SECRET_KEY') == 'dev':
            raise ValueError("Use a secure SECRET_KEY in production")

def log_startup_info(app):
    """
    Log application startup information.
    
    Args:
        app (Flask): The Flask application instance
    """
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    app.logger.info(f"Starting {app.config.get('APP_NAME', 'MyProject')} v{app.config.get('VERSION', '1.0.0')}", extra={
        'environment': app.config.get('ENV'),
        'debug': app.config.get('DEBUG'),
        'python_version': python_version,
        'platform': platform.platform(),
        'server_name': app.config.get('SERVER_NAME', 'localhost')
    })

    # Log configuration for development environments
    if app.config.get('ENV') == 'development':
        config_items = {
            key: app.config[key] for key in sorted(app.config.keys())
            if not key.startswith('_') and key != 'SECRET_KEY'
        }
        app.logger.debug("Application configuration", extra={
            'config': config_items
        })
