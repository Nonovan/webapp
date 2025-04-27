"""
Blueprint package for the myproject Flask application.

This package organizes the application's routes and views into logical modules
using Flask's Blueprint functionality. Each blueprint encapsulates a specific
feature area of the application with its own routes, templates, and error handlers,
promoting modular design and separation of concerns.

The package includes the following blueprints:
- auth: Authentication flows including login, registration, and password management
- main: Primary application routes for the core user interface
- monitoring: System health monitoring and performance metrics

Blueprint organization follows best practices:
1. Each blueprint has its own directory with routes, templates, and static files
2. Templates are namespaced to avoid collisions
3. Common functionality is shared through utility modules
4. Each blueprint has specific error handlers for consistent responses

This modular structure enhances maintainability by isolating feature implementations
and enables better testing by allowing components to be tested independently.
"""

import logging
from typing import Dict, List, Tuple, Optional
from flask import Flask, Blueprint, current_app

# Initialize package logger
logger = logging.getLogger(__name__)

# Import blueprints - using try/except to handle potential import errors gracefully
try:
    from api import api_bp
except ImportError as e:
    logger.warning(f"Could not import API blueprint: {e}")
    api_bp = None

try:
    from .auth.routes import auth_bp
except ImportError as e:
    logger.warning(f"Could not import Auth blueprint: {e}")
    auth_bp = None

try:
    from .main.routes import main_bp
except ImportError as e:
    logger.warning(f"Could not import Main blueprint: {e}")
    main_bp = None

try:
    from .monitoring.routes import monitoring_bp
except ImportError as e:
    logger.warning(f"Could not import Monitoring blueprint: {e}")
    monitoring_bp = None

# Define blueprint configuration - each entry specifies the blueprint object and its URL prefix
blueprint_configs = []

# Only add blueprints that were successfully imported
if auth_bp:
    blueprint_configs.append((auth_bp, '/auth'))

if main_bp:
    blueprint_configs.append((main_bp, '/'))  # Main blueprint at root level

if monitoring_bp:
    blueprint_configs.append((monitoring_bp, '/monitoring'))

# Create a dictionary of blueprint objects for reference
blueprints: Dict[str, Blueprint] = {}
if auth_bp:
    blueprints['auth'] = auth_bp
if main_bp:
    blueprints['main'] = main_bp
if monitoring_bp:
    blueprints['monitoring'] = monitoring_bp

def register_all_blueprints(app: Flask) -> None:
    """
    Register all application blueprints with the Flask application.

    This function is the central registration point for all blueprints in the application.
    It registers each blueprint with its appropriate URL prefix and applies any
    blueprint-specific configuration.

    Args:
        app (Flask): The Flask application instance

    Returns:
        None: This function modifies the app instance in-place

    Example:
        from flask import Flask
        from blueprints import register_all_blueprints

        app = Flask(__name__)
        register_all_blueprints(app)
    """
    # Register API blueprints if available
    if api_bp:
        try:
            app.register_blueprint(api_bp, url_prefix='/api')
            app.logger.info("Registered API blueprint")
        except Exception as e:
            app.logger.error(f"Failed to register API blueprint: {str(e)}")

    # Track registration success count
    success_count = 0

    # Register each blueprint with its configured URL prefix
    for blueprint, url_prefix in blueprint_configs:
        try:
            app.register_blueprint(blueprint, url_prefix=url_prefix)
            app.logger.info(f"Registered blueprint: {blueprint.name} with prefix: {url_prefix}")
            success_count += 1
        except Exception as e:
            app.logger.error(f"Failed to register blueprint {getattr(blueprint, 'name', 'unknown')}: {str(e)}")

    # Log registration summary with security implications
    total = len(blueprint_configs)
    if success_count < total:
        app.logger.warning(
            f"Only {success_count}/{total} blueprints registered successfully. This may impact application functionality."
        )
    else:
        app.logger.info(f"All {total} blueprints registered successfully")

# Export package members
__all__ = ['register_all_blueprints', 'blueprints']

# Add blueprint objects to exports only if they exist
if auth_bp:
    __all__.append('auth_bp')
if main_bp:
    __all__.append('main_bp')
if monitoring_bp:
    __all__.append('monitoring_bp')
