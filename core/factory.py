"""
Cloud Infrastructure Management Platform entry point.

This module provides the application factory function for creating Flask application
instances with the appropriate configuration and extension setup. It implements
a flexible application initialization flow that ensures security features like
file integrity monitoring are properly enabled during startup.
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

# Get security logger for application-level security events
logger = get_security_logger()

def create_app(config_name=None) -> Flask:
    """
    Create and configure a Flask application instance.

    This factory function creates a new Flask application instance with the appropriate
    configuration based on the environment. It sets up all necessary components including
    extensions, blueprints, error handlers, middleware, and health checks.

    Args:
        config_name (str, optional): Name of the configuration to use ('development',
                                     'production', 'testing'). Defaults to None.

    Returns:
        Flask: Configured Flask application instance ready to serve requests
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    config_obj = get_config(config_name)
    config_obj.init_app(app)

    # Ensure instance folder exists with proper permissions
    try:
        os.makedirs(app.instance_path, mode=0o750, exist_ok=True)
    except OSError as e:
        logger.warning(f"Could not create instance folder: {e}")

    # Set up logging early to capture initialization issues
    setup_app_logging(app)

    # Initialize extensions
    init_extensions(app)

    # Register blueprints and API routes
    register_blueprints(app)
    register_api_routes(app)

    # Register error handlers
    register_error_handlers(app)

    # Register health check endpoints
    register_health_endpoints(app)

    # Register template context processors
    register_context_processors(app)

    # Initialize middleware (should happen after error handlers for proper exception handling)
    init_middleware(app)

    # Register CLI commands
    register_cli_commands(app)

    # Log startup information
    log_startup_info(app)

    return app


def configure_app(app: Flask, config_object=None) -> None:
    """
    Configure the Flask application with appropriate settings.

    This function applies configuration settings to the Flask application in a
    prioritized order. Environment variables take highest priority, followed by
    explicit configuration objects, then instance configuration, and finally
    default values.

    Args:
        app (Flask): The Flask application instance
        config_object: Configuration object or string path to configuration file
    """
    # Load default configuration
    app.config.from_object(Config)

    # Override with instance config if it exists
    instance_config = os.path.join(app.instance_path, 'config.py')
    if os.path.exists(instance_config):
        app.config.from_pyfile(instance_config)
        logger.info(f"Loaded instance configuration from {instance_config}")

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

    # Ensure CSP nonce generation is available in templates
    app.jinja_env.globals['csp_nonce'] = lambda: app.config.get('_CSP_NONCE', '')


def register_extensions(app: Flask) -> None:
    """
    Initialize and register Flask extensions with the application.

    This function initializes all extensions and sets up any extension-specific
    configuration or error handlers.

    Args:
        app (Flask): The Flask application instance
    """
    # Initialize all extensions with a helper function from extensions package
    init_extensions(app)

    # Register JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        # Log the event
        logger.info("JWT token expired", extra={
            'user_id': jwt_payload.get('sub'),
            'token_type': jwt_payload.get('type')
        })

        return jsonify({
            'status': 'error',
            'message': 'Token has expired',
            'code': 'token_expired'
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        # Log the security event with higher severity as it may indicate tampering
        logger.warning("Invalid JWT token", extra={
            'error': error,
            'ip_address': request.remote_addr if request else 'unknown'
        })

        return jsonify({
            'status': 'error',
            'message': 'Invalid token',
            'code': 'invalid_token'
        }), 401

    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        return jsonify({
            'status': 'error',
            'message': 'Missing authorization token',
            'code': 'missing_token'
        }), 401


def register_error_handlers(app: Flask) -> None:
    """
    Register error handlers for different types of exceptions.

    This function sets up handlers for common HTTP exceptions, CSRF errors,
    and uncaught exceptions to ensure consistent error responses across the
    application.

    Args:
        app (Flask): The Flask application instance
    """
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Handle CSRF validation errors."""
        # Use security logger for CSRF errors as they may indicate an attack
        logger.warning(f"CSRF error: {e.description}", extra={
            'http_status': 400,
            'error_type': 'csrf_error',
            'ip_address': request.remote_addr,
            'path': request.path,
            'method': request.method
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
        # Use severity-appropriate logging based on status code
        if e.code >= 500:
            app.logger.error(f"HTTP {e.code}: {e.description}", extra={
                'http_status': e.code,
                'path': request.path,
                'method': request.method
            })
        elif e.code >= 400:
            app.logger.warning(f"HTTP {e.code}: {e.description}", extra={
                'http_status': e.code,
                'path': request.path,
                'method': request.method
            })
        else:
            app.logger.info(f"HTTP {e.code}: {e.description}", extra={
                'http_status': e.code,
                'path': request.path,
                'method': request.method
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
            try:
                return render_template('errors/generic.html', error=e, code=e.code), e.code
            except TemplateNotFound:
                # Ultimate fallback for complete template system failure
                return f"Error {e.code}: {e.description}", e.code

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle all unhandled exceptions."""
        # Log the full exception with traceback
        app.logger.exception("Unhandled exception occurred", extra={
            'error': str(e),
            'error_type': e.__class__.__name__,
            'path': request.path if request else 'No request context'
        })

        # Check for file integrity issues if it's an unexpected error
        try:
            # Import here to avoid circular import
            from core.security import check_critical_file_integrity

            # Only check for critical failures that might indicate tampering
            integrity_status, changes = check_critical_file_integrity(app)

            if not integrity_status and changes:
                # Found integrity issues - log them at critical level
                critical_changes = [c for c in changes if c.get('severity') == 'critical']
                if critical_changes:
                    logger.critical(
                        "File integrity violation detected after exception",
                        extra={
                            'changes': critical_changes,
                            'error': str(e),
                            'error_type': e.__class__.__name__
                        }
                    )
        except (ImportError, Exception) as integrity_error:
            # Log but don't let this cause additional errors
            app.logger.error(f"Failed to check file integrity after exception: {integrity_error}")

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


def register_context_processors(app: Flask) -> None:
    """
    Register template context processors to make variables available in templates.

    This function sets up context processors that provide commonly used values
    to templates without having to pass them explicitly from each route.

    Args:
        app (Flask): The Flask application instance
    """
    @app.context_processor
    def inject_globals():
        """Make common variables available to all templates."""
        return {
            'now': datetime.now(timezone.utc),
            'version': app.config.get('VERSION', '1.0.0'),
            'environment': app.config.get('ENVIRONMENT', 'production'),
            'app_name': app.config.get('APP_NAME', 'Cloud Infrastructure Platform'),
            'is_debug': app.debug,
            'build_timestamp': app.config.get('BUILD_TIMESTAMP')
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

    @app.context_processor
    def inject_security_features():
        """Make security feature flags available to templates."""
        return {
            'feature_mfa': app.config.get('FEATURE_MFA', False),
            'feature_dark_mode': app.config.get('FEATURE_DARK_MODE', False),
            'feature_ics_control': app.config.get('FEATURE_ICS_CONTROL', False),
            'feature_cloud_management': app.config.get('FEATURE_CLOUD_MANAGEMENT', False)
        }


def validate_configuration(app: Flask) -> None:
    """
    Validate that all required configuration values are set.

    This function checks that all required configuration values are present
    and properly formatted, raising errors for critical configuration problems.

    Args:
        app (Flask): The Flask application instance

    Raises:
        ValueError: If a required configuration value is missing or invalid
    """
    required_configs = [
        'SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI',
    ]

    missing = [key for key in required_configs if not app.config.get(key)]

    if missing:
        error_msg = f"Missing required configuration values: {', '.join(missing)}"
        logger.critical(error_msg)
        raise ValueError(error_msg)

    # Check for insecure configuration in production
    environment = app.config.get('ENVIRONMENT', '').lower()
    if environment in Config.SECURE_ENVIRONMENTS:
        # Check security-critical settings in production/staging
        insecure_settings = []

        if app.config.get('DEBUG'):
            insecure_settings.append('DEBUG should be False')

        if app.config.get('TESTING'):
            insecure_settings.append('TESTING should be False')

        if app.config.get('SECRET_KEY') in ('dev', 'development', 'secret', 'changeme'):
            insecure_settings.append('SECRET_KEY is using a default/insecure value')

        if not app.config.get('SESSION_COOKIE_SECURE', True):
            insecure_settings.append('SESSION_COOKIE_SECURE should be True')

        if not app.config.get('REMEMBER_COOKIE_SECURE', True):
            insecure_settings.append('REMEMBER_COOKIE_SECURE should be True')

        if not app.config.get('SESSION_COOKIE_HTTPONLY', True):
            insecure_settings.append('SESSION_COOKIE_HTTPONLY should be True')

        if app.config.get('AUTO_UPDATE_BASELINE', False):
            insecure_settings.append('AUTO_UPDATE_BASELINE should be False in production')

        if not app.config.get('WTF_CSRF_ENABLED', True):
            insecure_settings.append('WTF_CSRF_ENABLED should be True')

        if not app.config.get('API_REQUIRE_HTTPS', True):
            insecure_settings.append('API_REQUIRE_HTTPS should be True')

        # If any insecure settings are found, log and raise an error
        if insecure_settings:
            error_msg = f"Insecure configuration in {environment} environment: {', '.join(insecure_settings)}"
            logger.critical(error_msg)
            raise ValueError(error_msg)


def log_startup_info(app: Flask) -> None:
    """
    Log application startup information.

    This function logs important information about the application environment
    during startup to provide context for subsequent logs.

    Args:
        app (Flask): The Flask application instance
    """
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    app.logger.info(f"Starting {app.config.get('APP_NAME', 'Cloud Infrastructure Platform')} v{app.config.get('VERSION', '1.0.0')}", extra={
        'environment': app.config.get('ENVIRONMENT'),
        'debug': app.config.get('DEBUG'),
        'python_version': python_version,
        'platform': platform.platform(),
        'server_name': app.config.get('SERVER_NAME', 'localhost'),
        'file_integrity_enabled': app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True),
        'audit_logging_enabled': app.config.get('AUDIT_LOG_ENABLED', True)
    })

    # Log security feature status
    logger.info("Security features status", extra={
        'file_integrity_enabled': app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True),
        'csrf_enabled': app.config.get('WTF_CSRF_ENABLED', True),
        'security_headers_enabled': app.config.get('SECURITY_HEADERS_ENABLED', True),
        'mfa_feature_enabled': app.config.get('FEATURE_MFA', False),
        'auto_update_baseline': app.config.get('AUTO_UPDATE_BASELINE', False),
    })

    # Log configuration for development environments only
    if app.config.get('ENVIRONMENT') == 'development':
        # Filter out sensitive keys and non-serializable values
        safe_keys = [
            key for key in sorted(app.config.keys())
            if not key.startswith('_') and key not in (
                'SECRET_KEY', 'JWT_SECRET_KEY', 'CSRF_SECRET_KEY', 'SESSION_KEY',
                'DATABASE_URL', 'SQLALCHEMY_DATABASE_URI'
            )
        ]

        # Create sanitized config dict
        config_items = {}
        for key in safe_keys:
            try:
                # Skip complex objects that might not serialize well in logs
                value = app.config[key]
                if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
                    config_items[key] = value
            except Exception:
                pass

        app.logger.debug("Application configuration", extra={
            'config': config_items
        })
