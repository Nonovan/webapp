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
import sys
import socket
import traceback
from datetime import datetime, timezone
from typing import Optional
from flask import Flask, request, g, has_request_context
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration


class SecurityAwareJsonFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging with security context.
    
    This formatter generates structured JSON logs that include application
    context, request details, and security information when available.
    """
    def __init__(self, include_sensitive: bool = False):
        """
        Initialize the JSON formatter.
        
        Args:
            include_sensitive: Whether to include potentially sensitive details like 
                              full URLs and headers. Should be False in production.
        """
        super().__init__()
        self.include_sensitive = include_sensitive
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON with additional context."""
        # Base log data
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "host": self.hostname
        }

        # Add process and thread info for diagnosing concurrency issues
        log_data["process"] = record.process
        log_data["process_name"] = record.processName
        log_data["thread"] = record.thread
        log_data["thread_name"] = record.threadName

        # Include exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None,
                "value": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }

        # Add Flask request context if available
        if has_request_context():
            log_data["request"] = {
                "id": getattr(g, 'request_id', 'unknown'),
                "method": request.method,
                "endpoint": request.endpoint,
                "path": request.path,
                "remote_addr": request.remote_addr,
                "user_agent": request.user_agent.string
            }

            # Include user ID if authenticated
            if hasattr(g, 'user_id'):
                log_data["user_id"] = g.user_id

            # Include sensitive information only if explicitly enabled
            if self.include_sensitive:
                log_data["request"]["url"] = request.url
                log_data["request"]["args"] = dict(request.args)
                # Don't include form/JSON data as it may contain credentials

        # Include any additional attributes added to the record
        for key, value in record.__dict__.items():
            if key not in ["args", "asctime", "created", "exc_info", "exc_text", 
                           "filename", "funcName", "id", "levelname", "levelno", 
                           "lineno", "module", "msecs", "message", "msg", "name", 
                           "pathname", "process", "processName", "relativeCreated", 
                           "stack_info", "thread", "threadName"]:
                log_data[key] = value

        return json.dumps(log_data)


def setup_app_logging(app: Flask) -> None:
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
        setup_app_logging(app)
        app.logger.info("Application logging initialized")
    """
    # Create logs directory
    log_dir = os.path.join(app.root_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Clear existing handlers to avoid duplicates when reloading in development
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Determine if this is a development environment
    is_dev = app.config.get('ENV', 'production').lower() == 'development'

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if is_dev:
        # Use a more readable format for development
        console_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
        ))
    else:
        # Use structured JSON in production for better parsing
        console_handler.setFormatter(SecurityAwareJsonFormatter())

    # Set appropriate level
    console_handler.setLevel(logging.DEBUG if is_dev else logging.INFO)
    root_logger.addHandler(console_handler)

    # Create file handlers with rotation
    # Main application log - 10MB files, keep 10 backups
    app_log_path = os.path.join(log_dir, 'application.log')
    app_handler = logging.handlers.RotatingFileHandler(
        app_log_path, maxBytes=10*1024*1024, backupCount=10
    )
    app_handler.setFormatter(SecurityAwareJsonFormatter())
    app_handler.setLevel(logging.INFO)
    root_logger.addHandler(app_handler)

    # Error log - separate for critical errors, 5MB files, keep 20 backups
    error_log_path = os.path.join(log_dir, 'error.log')
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_path, maxBytes=5*1024*1024, backupCount=20
    )
    error_handler.setFormatter(SecurityAwareJsonFormatter())
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)

    # Security log - for security-specific events, 10MB files, keep 30 backups
    security_log_path = os.path.join(log_dir, 'security.log')
    security_handler = logging.handlers.RotatingFileHandler(
        security_log_path, maxBytes=10*1024*1024, backupCount=30
    )
    security_handler.setFormatter(SecurityAwareJsonFormatter())
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)

    # Make security logger propagate to root logger
    security_logger.propagate = True

    # Set Flask app logger level
    app.logger.setLevel(logging.DEBUG if is_dev else logging.INFO)

    # Configure Sentry for error reporting in production
    if not is_dev and app.config.get('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=app.config.get('SENTRY_DSN'),
            integrations=[
                FlaskIntegration(),
                SqlalchemyIntegration(),
                RedisIntegration()
            ],
            environment=app.config.get('ENV'),
            release=app.config.get('VERSION', 'unknown'),
            send_default_pii=False,  # Don't send PII by default
            traces_sample_rate=app.config.get('SENTRY_TRACES_SAMPLE_RATE', 0.1)
        )
        app.logger.info("Sentry error reporting initialized")

    # Log the configuration
    app.logger.info("Application logging initialized", extra={
        "log_dir": log_dir,
        "environment": app.config.get('ENV'),
        "level": "DEBUG" if is_dev else "INFO"
    })

def get_security_logger() -> logging.Logger:
    """
    Get the security logger instance.
    
    Returns:
        logging.Logger: The security logger instance
    """
    return logging.getLogger('security')

def log_security_event(event_type: str, description: str, severity: str = 'info',
                      user_id: Optional[int] = None, ip_address: Optional[str] = None,
                      details: Optional[str] = None) -> None:
    """
    Log a security-related event.
    
    This function logs security events to both the security log file and the
    audit log database table for searchability and compliance.
    
    Args:
        event_type: Type of security event (login_attempt, permission_change, etc.)
        description: Human-readable description of the event
        severity: Severity level (info, warning, error, critical)
        user_id: ID of the user who performed the action (if known)
        ip_address: IP address where the action originated
        details: Additional details about the event
    """
    # Get context info if not provided
    if has_request_context():
        ip_address = ip_address or request.remote_addr
        user_id = user_id or getattr(g, 'user_id', None)

    # Log to the security logger
    logger = get_security_logger()
    log_level = {
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }.get(severity.lower(), logging.INFO)

    logger.log(log_level, description, extra={
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': details,
        'security_event': True  # Flag for filtering
    })

    # Also record in the database audit log
    # Import here to avoid circular imports
    from models.audit_log import AuditLog
    from extensions import db
    try:

        # Map severity to AuditLog severity constants
        severity_map = {
            'info': AuditLog.SEVERITY_INFO,
            'warning': AuditLog.SEVERITY_WARNING,
            'error': AuditLog.SEVERITY_ERROR,
            'critical': AuditLog.SEVERITY_CRITICAL
        }

        # Create audit log entry
        log_entry = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=details,
            severity=severity_map.get(severity.lower(), AuditLog.SEVERITY_INFO),
            created_at=datetime.now(timezone.utc)
        )

        # Add user agent if available
        if has_request_context():
            log_entry.user_agent = request.user_agent.string

        # Save to database
        db.session.add(log_entry)
        db.session.commit()

    except (db.exc.SQLAlchemyError, AttributeError) as e:
        # Don't let a database failure stop the application, but log it
        logging.getLogger('security').error(
            "Failed to write security event to database: %s", str(e),
            exc_info=True
        )
