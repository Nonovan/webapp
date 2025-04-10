import logging
import logging.handlers
import json
import os
from datetime import datetime
from typing import Any, Dict
from flask import Flask, request, g
import sentry_sdk

def setup_app_logging(app: Flask) -> None:
    """Configure centralized application logging."""

    # Create logs directory
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    class JsonFormatter(logging.Formatter):
        def format(self, record) -> str:
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
            level=logging.ERROR,
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

def get_sentry_client() -> sentry_sdk.Client:
    return sentry_sdk.Hub.current.client
