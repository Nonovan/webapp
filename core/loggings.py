"""
Logging configuration module for myproject.

This module provides a comprehensive logging system for the application with
features such as structured JSON logging, log rotation, security event tracking,
and integration with error monitoring services like Sentry.

The logging system is designed to facilitate application monitoring, debugging,
and auditing by capturing detailed contextual information with each log entry,
including request IDs, user IDs, IP addresses, and timestamps with proper timezone
information.

Key features include:
- Structured JSON logs for machine parsing and analysis
- Console output for development environments
- File-based logging with size-based rotation
- Separate error and security event logs
- Integration with Sentry for error tracking
- Request context enrichment
"""

import logging
import logging.handlers
import json
import os
from datetime import datetime
from typing import Any, Dict
from flask import Flask, request, g
import sentry_sdk

def setup_app_loggings(app: Flask) -> None:
    """
    Configure centralized application logging.

    This function sets up a comprehensive logging system for the Flask application,
    including file handlers with rotation, console output, structured JSON formatting,
    and Sentry integration for error tracking.

    Args:
        app (Flask): The Flask application instance to configure logging for

    Returns:
        None: This function configures the application's logging system in-place

    Example:
        app = Flask(__name__)
        setup_app_loggings(app)
        app.logger.info("Application logging initialized")
    """
    # Create logs directory
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    class JsonFormatter(logging.Formatter):
        """
        Custom formatter that outputs log records as JSON objects.

        This formatter converts log records to structured JSON format with
        additional context information from the current request and application
        state, enabling better log parsing and analysis.
        """
        def format(self, record) -> str:
            """
            Format log record as JSON string.

            Args:
                record: The log record to format

            Returns:
                str: JSON-formatted log entry
            """
            log_data: Dict[str, Any] = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'logger': record.name,
                'request_id': getattr(g, 'request_id', None),
                'user_id': getattr(g, 'user_id', None),
                'path': request.path if request else None,
                'method': request.method if request else None,
                'ip': request.remote_addr if request else None,
                'user_agent': request.user_agent.string if request and request.user_agent else None,
                'environment': app.config.get('ENV', 'production'),
                'version': app.config.get('VERSION', '1.0.0')
            }

            # Add error info if present
            if record.exc_info:
                log_data['error'] = {
                    'type': record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None,
                    'message': str(record.exc_info[1]),
                    'traceback': self.formatException(record.exc_info)
                }

            return json.dumps(log_data)

    # Configure handlers with size-based rotation
    handlers = [
        # Console output
        logging.StreamHandler(),

        # Main log file
        logging.handlers.RotatingFileHandler(
            filename=f'{log_dir}/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=10,
            encoding='utf-8'
        ),

        # Error-specific log
        logging.handlers.RotatingFileHandler(
            filename=f'{log_dir}/error.log',
            maxBytes=10485760,
            backupCount=10,
            encoding='utf-8'
        ),

        # Security events log
        logging.handlers.RotatingFileHandler(
            filename=f'{log_dir}/security.log',
            maxBytes=10485760,
            backupCount=10,
            encoding='utf-8'
        )
    ]

    # Create and configure error handler separately
    error_handler = logging.handlers.RotatingFileHandler(
        filename=f'{log_dir}/error.log',
        maxBytes=10485760,
        backupCount=10,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)  # Set level correctly on the handler

    # Configure formatters
    console_formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    json_formatter = JsonFormatter()

    # Apply configuration
    app.logger.handlers = []

    for handler in handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setFormatter(console_formatter)
        else:
            handler.setFormatter(json_formatter)
        app.logger.addHandler(handler)

    # Add error handler separately
    error_handler.setFormatter(json_formatter)
    app.logger.addHandler(error_handler)

    app.logger.setLevel(app.config['LOG_LEVEL'])

    # Configure Sentry if DSN provided
    if app.config.get('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=app.config['SENTRY_DSN'],
            environment=app.config['ENV'],
            traces_sample_rate=1.0
        )

def get_logger(app: Flask) -> logging.Logger:
    """
    Get configured application logger.

    Provides access to the properly configured logger for the application,
    ensuring consistent logging format and behavior throughout the codebase.

    Args:
        app (Flask): Flask application instance

    Returns:
        logging.Logger: Configured application logger

    Example:
        app = Flask(__name__)
        logger = get_logger(app)
        logger.info("Application started")
    """
    return app.logger

def get_sentry_client() -> sentry_sdk.Client:
    """
    Get configured Sentry client.

    Provides access to the Sentry client for additional error reporting
    or configuration at runtime.

    Returns:
        sentry_sdk.Client: Current Sentry client instance or None if not configured

    Raises:
        RuntimeError: If Sentry is not properly configured

    Example:
        client = get_sentry_client()
        client.capture_message("Error occurred")
    """
    return sentry_sdk.Hub.current.client
