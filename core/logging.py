import logging
import logging.handlers
import json
import os
from datetime import datetime
import sentry_sdk
from flask import Flask, request

def setup_app_logging(app: Flask) -> None:
    """Centralized logging configuration"""

    # Create logs directory
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    # JSON Formatter
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'request_id': getattr(request, 'request_id', None),
                'path': getattr(request, 'path', None),
                'method': getattr(request, 'method', None),
                'ip': getattr(request, 'remote_addr', None)
            }
            return json.dumps(log_data)

    # Configure handlers
    handlers = [
        # Console handler
        logging.StreamHandler(),

        # File handler with rotation
        logging.handlers.RotatingFileHandler(
            filename=f'{log_dir}/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        ),

        # Error file handler
        logging.handlers.RotatingFileHandler(
            filename=f'{log_dir}/error.log',
            maxBytes=10485760,
            backupCount=10,
            level=logging.ERROR
        )
    ]

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

    app.logger.setLevel(app.config['LOG_LEVEL'])

    # Configure Sentry if DSN provided
    if app.config.get('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=app.config['SENTRY_DSN'],
            environment=app.config['ENV'],
            traces_sample_rate=1.0
        )

def get_logger(app: Flask)  -> None:
    return app.logger

def get_sentry_client():
    return sentry_sdk.Hub.current.client
