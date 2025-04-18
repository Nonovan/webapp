"""
Cloud Infrastructure Management Platform entry point.

This module provides the application factory function for creating Flask application
instances with the appropriate configuration and extension setup.
"""

import os
import platform
import sys
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from jinja2 import TemplateNotFound
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from blueprints import register_blueprints
from extensions import jwt, init_extensions
from core.config import Config
from core.loggings import setup_app_logging, get_security_logger
from core.middleware import init_middleware
from core.utils import generate_sri_hash
from core.health import register_health_endpoints
from api import register_api_routes
from config import get_config
from cli import register_cli_commands


logger = get_security_logger()

def create_app(config_name=None):
    """Create Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    
    # Load configuration
    config_obj = get_config(config_name)
    config_obj.init_app(app)
    
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass
    
    # Initialize extensions
    init_extensions(app)
    
    # Register blueprints and API routes
    register_blueprints(app)
    register_api_routes(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Initialize middleware
    init_middleware(app)
    
    # Register CLI commands
    register_cli_commands(app)
    
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
