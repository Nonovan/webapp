import logging
from flask import Flask
from core.factory import create_app as core_create_app
from views import register_blueprints

__version__ = '1.0.0'

def create_app() -> Flask:
    """
    Application factory function.
    
    Args:
        
    Returns:
        Flask application instance
    """
    try:
        # Create base app
        app = Flask(__name__)
        
        # Configure via core factory
        app = core_create_app(app)
        
        # Register blueprints
        register_blueprints(app)
        
        # Set version
        app.config['VERSION'] = __version__
        
        return app
        
    except Exception as e:
        # Log critical error
        logging.critical("Failed to create application: %s", e)
        raise