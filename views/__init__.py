"""
Blueprint registration module for the myproject application.

This module centralizes the registration of all application blueprints, providing
a clean separation between the core application factory and route definitions.
It serves as the integration point for different functional areas of the application
including authentication, main application routes, and monitoring features.

The blueprint structure enables:
- Modular code organization by feature area
- Isolation of route definitions for better maintainability
- Separate URL prefixes and template folders for each component
- Independent error handling for different application sections

All blueprints are imported here and registered with the application instance
through the register_blueprints function, which is called during app initialization.
"""

from flask import Flask
from blueprints import register_all_blueprints


def register_blueprints(app: Flask) -> None:
    """
    Register application blueprints with the Flask application instance.

    This function attaches all blueprints to the application, organizing routes
    into logical groups with appropriate URL prefixes. The blueprint registration
    process establishes the routing structure of the entire application.

    Blueprint organization:
    - auth_bp: Authentication routes with /auth prefix
    - main_bp: Core application routes at the root level
    - monitoring_bp: System monitoring endpoints with /monitoring prefix

    Args:
        app (Flask): The Flask application instance to register blueprints with

    Returns:
        None: This function modifies the app instance in-place

    Example:
        from flask import Flask
        from views import register_blueprints

        app = Flask(__name__)
        register_blueprints(app)
    """
    register_all_blueprints(app)