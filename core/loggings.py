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
- File integrity monitoring events
- Security audit logging
- Integration with metrics system
"""

import logging
import logging.handlers
import json
import os
import sys
import socket
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union, List
from flask import Flask, request, g, has_request_context, current_app, has_app_context
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration

# Create a module-level logger
logger = logging.getLogger(__name__)


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
                "value": str(record.exc_info[1]) if record.exc_info and record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info) if record.exc_info else None
            }

        # Add Flask request context if available
        if has_request_context():
            log_data["request"] = {
                "id": getattr(g, 'request_id', 'unknown'),
                "method": request.method,
                "endpoint": request.endpoint,
                "path": request.path,
                "remote_addr": request.remote_addr,
                "user_agent": request.user_agent.string if request.user_agent else None
            }

            # Include user ID if authenticated
            if hasattr(g, 'user_id'):
                log_data["user_id"] = g.user_id

            # Include sensitive information only if explicitly enabled
            if self.include_sensitive:
                log_data["request"]["url"] = request.url
                log_data["request"]["args"] = dict(request.args)
                # Don't include form/JSON data as it may contain credentials

        # Handle security event specific context
        if hasattr(record, 'security_event') and record.security_event:
            # Add security-specific fields to make filtering and analysis easier
            log_data["security"] = {
                "event_type": getattr(record, 'event_type', 'unknown'),
                "severity": record.levelname,
                "user_id": getattr(record, 'user_id', None),
                "ip_address": getattr(record, 'ip_address', None),
            }

            # Add any file integrity details if present
            if hasattr(record, 'file_integrity') and record.file_integrity:
                log_data["security"]["file_integrity"] = record.file_integrity

        # Include any additional attributes added to the record
        # Skip internal logging attributes and those already processed
        skip_attributes = {
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "id", "levelname", "levelno", "lineno", "module",
            "msecs", "message", "msg", "name", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread",
            "threadName", "security_event", "security"
        }

        for key, value in record.__dict__.items():
            if key not in skip_attributes:
                # Handle special case for details which might be JSON string
                if key == 'details' and isinstance(value, str):
                    try:
                        # Try to parse as JSON if it's a string
                        log_data[key] = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        log_data[key] = value
                else:
                    log_data[key] = value

        return json.dumps(log_data, default=str)


class FileIntegrityAwareHandler(logging.Handler):
    """
    Custom log handler that tracks file integrity events.

    This handler processes file integrity related events specifically,
    storing them for monitoring and providing metrics.
    """
    def __init__(self, level=logging.INFO):
        super().__init__(level)
        self.integrity_events = []
        self.max_events = 100  # Store only last 100 events

    def emit(self, record):
        # Process only file integrity events
        if not hasattr(record, 'event_type') or record.event_type != 'file_integrity':
            return

        try:
            # Extract integrity event details
            event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'details': getattr(record, 'details', None)
            }

            # Keep only recent events
            self.integrity_events.append(event)
            if len(self.integrity_events) > self.max_events:
                self.integrity_events.pop(0)

            # Update metrics if available
            if has_app_context() and hasattr(current_app, 'metrics'):
                try:
                    severity = getattr(record, 'severity', 'info').lower()
                    current_app.metrics.increment('security.file_integrity.events',
                                                labels={'severity': severity})
                except Exception:
                    pass

        except Exception:
            self.handleError(record)

    def get_recent_events(self, limit=10):
        """Get most recent file integrity events"""
        return self.integrity_events[-limit:] if self.integrity_events else []


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
    # Create logs directory with secure permissions
    log_dir = os.path.join(app.root_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Set secure permissions on log directory (0o750 = rwxr-x---)
    try:
        os.chmod(log_dir, 0o750)
    except (IOError, OSError, PermissionError):
        pass  # Continue even if chmod fails (might be running without permissions)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Clear existing handlers to avoid duplicates when reloading in development
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Determine if this is a development environment
    is_dev = app.config.get('ENV', 'production').lower() == 'development'
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()

    # Set numeric log level
    numeric_level = getattr(logging, log_level, logging.INFO)
    root_logger.setLevel(numeric_level)

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
    console_handler.setLevel(logging.DEBUG if is_dev else numeric_level)
    root_logger.addHandler(console_handler)

    # Create file handlers with rotation
    # Main application log - 10MB files, keep 10 backups
    app_log_path = os.path.join(log_dir, 'application.log')
    app_handler = logging.handlers.RotatingFileHandler(
        app_log_path, maxBytes=10*1024*1024, backupCount=10
    )
    app_handler.setFormatter(SecurityAwareJsonFormatter())
    app_handler.setLevel(numeric_level)
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

    # Add file integrity tracking handler
    integrity_handler = FileIntegrityAwareHandler(level=logging.INFO)
    security_logger.addHandler(integrity_handler)

    # Store handler in app for accessing file integrity events
    app.file_integrity_handler = integrity_handler

    # Make security logger propagate to root logger
    security_logger.propagate = True

    # Set Flask app logger level
    app.logger.setLevel(logging.DEBUG if is_dev else numeric_level)

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
        "level": log_level,
        "file_integrity_monitoring": app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True)
    })


def get_security_logger() -> logging.Logger:
    """
    Get the security logger instance.

    Returns:
        logging.Logger: The security logger instance
    """
    return logging.getLogger('security')


def get_file_integrity_events(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get recent file integrity events from the logging system.

    Args:
        limit: Maximum number of events to return

    Returns:
        List of file integrity events with timestamps and details
    """
    if has_app_context() and hasattr(current_app, 'file_integrity_handler'):
        return current_app.file_integrity_handler.get_recent_events(limit)
    return []


def log_security_event(
    event_type: str,
    description: str,
    severity: str = 'info',
    user_id: Optional[Union[int, str]] = None,
    ip_address: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> None:
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
        details: Additional details about the event (dict or JSON string)
        object_type: Type of object affected (user, file, config, etc.)
        object_id: ID of the object affected
    """
    # Get context info if not provided
    if has_request_context():
        ip_address = ip_address or request.remote_addr
        user_id = user_id or getattr(g, 'user_id', None)

    # Normalize details to ensure it's serializable
    normalized_details = _normalize_log_details(details)

    # Log to the security logger
    logger = get_security_logger()
    log_level = {
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }.get(severity.lower(), logging.INFO)

    # Build extra data dictionary
    extra_data = {
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': normalized_details,
        'security_event': True,  # Flag for filtering
        'severity': severity,
    }

    # Add object information if provided
    if object_type:
        extra_data['object_type'] = object_type
    if object_id:
        extra_data['object_id'] = object_id

    # Add file integrity flag for relevant events
    if event_type == 'file_integrity':
        extra_data['file_integrity'] = True

    # Log the event with all the extra context
    logger.log(log_level, description, extra=extra_data)

    # Also record in the database audit log
    _record_to_audit_log(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        ip_address=ip_address,
        details=normalized_details,
        object_type=object_type,
        object_id=object_id
    )


def log_file_integrity_event(
    file_path: str,
    status: str,
    severity: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[Union[int, str]] = None
) -> None:
    """
    Log a file integrity specific event.

    This is a specialized wrapper around log_security_event for file integrity events.

    Args:
        file_path: Path to the file with integrity issues
        status: Status of the integrity issue (modified, missing, etc.)
        severity: Severity level (info, warning, error, critical)
        details: Additional details about the event
        user_id: User ID if available (for tracking who made changes)
    """
    # Format description based on status
    descriptions = {
        'modified': f"File modified: {os.path.basename(file_path)}",
        'missing': f"File missing: {os.path.basename(file_path)}",
        'permission_changed': f"File permissions changed: {os.path.basename(file_path)}",
        'new': f"New file detected: {os.path.basename(file_path)}",
        'suspicious': f"Suspicious file detected: {os.path.basename(file_path)}",
        'unexpected_owner': f"Unexpected file owner: {os.path.basename(file_path)}",
    }
    description = descriptions.get(status, f"File integrity issue: {file_path} ({status})")

    # Build comprehensive details
    event_details = details or {}
    event_details.update({
        'path': file_path,
        'status': status,
        'severity': severity,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

    # Log through main security event logger
    log_security_event(
        event_type='file_integrity',
        description=description,
        severity=severity,
        user_id=user_id,
        details=event_details,
        object_type='file',
        object_id=file_path
    )


def _record_to_audit_log(
    event_type: str,
    description: str,
    severity: str,
    user_id: Optional[Union[int, str]] = None,
    ip_address: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> None:
    """
    Record a security event to the database audit log.

    Args:
        event_type: Type of security event
        description: Human-readable description of the event
        severity: Severity level (info, warning, error, critical)
        user_id: ID of the user who performed the action
        ip_address: IP address where the action originated
        details: Additional details about the event
        object_type: Type of object affected
        object_id: ID of the object affected
    """
    try:
        # Import here to avoid circular imports
        from models.audit_log import AuditLog
        from extensions import db

        # Check if Redis fallback is needed due to database issues
        use_redis_fallback = False

        # Map severity to AuditLog severity constants
        severity_map = {
            'info': AuditLog.SEVERITY_INFO,
            'warning': AuditLog.SEVERITY_WARNING,
            'error': AuditLog.SEVERITY_ERROR,
            'critical': AuditLog.SEVERITY_CRITICAL
        }
        db_severity = severity_map.get(severity.lower(), AuditLog.SEVERITY_INFO)

        # Prepare details for database storage
        if details:
            if isinstance(details, dict):
                details_json = json.dumps(details)
            else:
                details_json = details
        else:
            details_json = None

        # Create audit log entry
        log_entry = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=details_json,
            severity=db_severity,
            created_at=datetime.now(timezone.utc)
        )

        # Add object information if provided
        if object_type:
            log_entry.object_type = object_type
        if object_id:
            log_entry.object_id = str(object_id)

        # Add user agent if available
        if has_request_context():
            log_entry.user_agent = request.user_agent.string

        # Save to database
        db.session.add(log_entry)
        db.session.commit()

    except Exception as e:
        # Use Redis-based fallback if available
        if use_redis_fallback:
            _store_audit_event_in_redis(
                event_type=event_type,
                description=description,
                severity=severity,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                object_type=object_type,
                object_id=object_id
            )

        # Don't let a database failure stop the application, but log it
        logging.getLogger('security').error(
            "Failed to write security event to database: %s", str(e),
            exc_info=True
        )


def _store_audit_event_in_redis(
    event_type: str,
    description: str,
    severity: str,
    user_id: Optional[Union[int, str]] = None,
    ip_address: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> bool:
    """
    Store a security event in Redis as a fallback when the database is unavailable.

    Args:
        event_type: Type of security event
        description: Human-readable description of the event
        severity: Severity level (info, warning, error, critical)
        user_id: ID of the user who performed the action
        ip_address: IP address where the action originated
        details: Additional details about the event
        object_type: Type of object affected
        object_id: ID of the object affected

    Returns:
        bool: True if successfully stored, False otherwise
    """
    try:
        # Get Redis connection
        if not has_app_context():
            return False

        if not hasattr(current_app, 'redis'):
            return False

        redis_client = current_app.redis

        # Create event data
        event_data = {
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details,
            'object_type': object_type,
            'object_id': object_id if object_id is None else str(object_id),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Serialize to JSON
        event_json = json.dumps(event_data, default=str)

        # Store in Redis list with TTL
        redis_key = 'security:fallback_events'
        redis_client.lpush(redis_key, event_json)
        redis_client.expire(redis_key, 86400)  # 24 hour expiry

        # Only keep latest 1000 events to prevent memory issues
        redis_client.ltrim(redis_key, 0, 999)

        return True
    except Exception as e:
        logger.error(f"Failed to store audit event in Redis: {str(e)}")
        return False


def _normalize_log_details(details: Optional[Union[Dict[str, Any], str]]) -> Optional[str]:
    """
    Normalize log details to ensure they are in a consistent format.

    Args:
        details: Details to normalize, can be dict or JSON string

    Returns:
        Normalized details as a JSON string or None
    """
    if details is None:
        return None

    if isinstance(details, str):
        # Check if it's already valid JSON
        try:
            json.loads(details)
            return details
        except (TypeError, ValueError):
            # Not valid JSON, convert to JSON string
            return json.dumps({'message': details})

    # Convert dict to JSON string
    try:
        return json.dumps(details, default=str)
    except (TypeError, ValueError):
        # Fallback for non-serializable objects
        return json.dumps({'error': 'Unserializable details'})


# Initialize module-level loggers
def initialize_module_logging():
    """Set up basic module logging when not in Flask context"""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))

    module_logger = logging.getLogger(__name__)
    module_logger.addHandler(handler)
    module_logger.setLevel(logging.INFO)

    security_logger = logging.getLogger('security')
    security_logger.addHandler(handler)
    security_logger.setLevel(logging.INFO)


# Initialize module logging if not in app context
if not has_app_context():
    initialize_module_logging()
