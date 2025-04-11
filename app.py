"""
Main application entry point for the myproject Flask application.

This module handles the application initialization, configuration loading,
and environment validation. It serves as the WSGI entry point and provides
CLI commands for administrative tasks.

The application uses a factory pattern for initialization to allow for
proper extension setup and blueprint registration. Security checks are
performed before initialization to ensure proper configuration.

Key responsibilities:
- Environment validation for security-critical variables
- Application logging setup
- Blueprint registration for routing
- Database initialization commands
- Application startup sequence
"""

import logging
import os
from flask import Flask
import click
from sqlalchemy.exc import SQLAlchemyError

from core.factory import create_app
from blueprints.monitoring.routes import monitoring_bp
from blueprints.auth.routes import auth_bp
from blueprints.main.routes import main_bp
from extensions import db

# Security constants
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
    'JWT_SECRET_KEY',
    'CSRF_SECRET_KEY',
    'SESSION_KEY'
]

def validate_environment() -> None:
    """
    Validate required environment variables are set.
    Raises RuntimeError if any required variables are missing.
    """
    missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing security variables: {', '.join(missing)}")

def setup_logging(flask_app: Flask) -> None:
    """
    Configure application logging with formatting and handlers.
    Args:
        flask_app: Flask application instance
    """
    formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    flask_app.logger.handlers = [handler]
    flask_app.logger.setLevel(flask_app.config['LOG_LEVEL'])

def register_blueprints(flask_app: Flask) -> None:
    """
    Register Flask blueprints for application routes.
    Args:
        flask_app: Flask application instance
    """
    flask_app.register_blueprint(monitoring_bp)
    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(main_bp)

# Initialize application
try:
    validate_environment()
    app = create_app()
except SQLAlchemyError as e:
    logging.critical("Application initialization failed: %s", e)
    raise

@app.cli.command()
def init_db() -> None:
    """Initialize database tables and indexes."""
    try:
        db.create_all()
        click.echo('Database initialized successfully')
    except SQLAlchemyError as e:
        app.logger.error("Database initialization failed: %s", exc_info=e)
        click.echo(f'Database initialization failed: {e}', err=True)
        exit(1)

if __name__ == '__main__':
    app.run()
