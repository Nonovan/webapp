from flask import Flask
from core.factory import create_app
from views import register_blueprints

def create_app(config_name='default'):
    """Application factory function."""
    app = Flask(__name__)
    
    # Let core factory handle config and extensions
    app = create_app(config_name)
    
    # Register blueprints
    register_blueprints(app)

    return app

__version__ = '1.0.0'
