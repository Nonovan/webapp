from datetime import datetime
from typing import Optional
from flask import Flask
from extensions import db, migrate, csrf, cache, limiter, session
from .config import Config
from .logging import setup_app_logging
from .middleware import setup_security_headers, setup_request_context, setup_response_context


def create_app(config_name: Optional[str] = None) -> Flask:
    """Centralized application factory"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.update(Config.load(config_name))
    
    # Track application uptime
    app.uptime = datetime.utcnow()
    
    # Setup core services
    setup_app_logging(app)
    
    # Setup request handling
    app.before_request(setup_request_context)
    app.after_request(setup_security_headers)
    app.after_request(setup_response_context)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    cache.init_app(app)
    limiter.init_app(app)
    session.init_app(app)
    
    return app
