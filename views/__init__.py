from flask import Flask
from blueprints.auth import auth_bp
from blueprints.main import main_bp 
from blueprints.monitoring import monitoring_bp

def register_blueprints(app: Flask) -> None:
    """Register application blueprints."""
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(monitoring_bp, url_prefix='/monitoring')
