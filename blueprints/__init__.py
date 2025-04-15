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

from typing import Dict
from flask import Flask, Blueprint

from api import api_bp
from .auth.routes import auth_bp
from .main.routes import main_bp
from .monitoring.routes import monitoring_bp


# Define blueprint configuration - each entry specifies the blueprint object and its URL prefix
blueprint_configs = [
    (auth_bp, '/auth'),
    (main_bp, '/'),  # Main blueprint at root level
    (monitoring_bp, '/monitoring')
]

# Create a dictionary of blueprint objects for reference
blueprints: Dict[str, Blueprint] = {
    'auth': auth_bp,
    'main': main_bp,
    'monitoring': monitoring_bp
}

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
    try:
        app.register_blueprint(api_bp, url_prefix='/api')
        app.logger.info("Registered API blueprint")
    except (ImportError, AttributeError) as e:
        app.logger.warning(f"API blueprint not available: {str(e)}")
    
    # Register each blueprint with its configured URL prefix
    for blueprint, url_prefix in blueprint_configs:
        app.register_blueprint(blueprint, url_prefix=url_prefix)
        app.logger.info(f"Registered blueprint: {blueprint.name} with prefix: {url_prefix}")
    
    app.logger.info(f"Total blueprints registered: {len(blueprint_configs)}")

# Export package members
__all__ = ['auth_bp', 'main_bp', 'monitoring_bp', 'blueprints', 'register_all_blueprints']