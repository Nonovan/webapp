"""
Logging utilities for the Cloud Infrastructure Platform.

This module provides a comprehensive logging system with features for security,
auditability, and proper log handling across development and production environments.
The system captures detailed contextual information with each log entry to facilitate
monitoring, debugging, and compliance requirements.

Key features include:
- Structured JSON logs for machine parsing and analysis
- Console output with configurable formatting for development
- File-based logging with size-based rotation and secure permissions
- Separate error and security event logs
- Integration with Sentry for error tracking and monitoring
- Request context enrichment with request IDs, user IDs, and IP addresses
- File integrity monitoring events and tracking
- Security audit logging with database integration
- Metrics system integration for monitoring and alerting
- Fallback mechanisms for logging during database outages
"""

import logging
import logging.handlers
import json
import os
import sys
import socket
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Union, List
from flask import Flask, request, g, has_request_context, current_app, has_app_context
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration

# Create a module-level logger
logger = logging.getLogger(__name__)

# Constants for log levels
LOG_LEVEL_DEBUG = logging.DEBUG
LOG_LEVEL_INFO = logging.INFO
LOG_LEVEL_WARNING = logging.WARNING
LOG_LEVEL_ERROR = logging.ERROR
LOG_LEVEL_CRITICAL = logging.CRITICAL

# Default log format strings
DEFAULT_LOG_FORMAT = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
DEFAULT_CONSOLE_FORMAT = '%(levelname)s: %(message)s'
CLI_LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s'


# Export all public functions and constants
__all__ = [
    # Core logging setup functions
    'setup_app_logging',
    'setup_logging',
    'setup_cli_logging',

    # Logger retrieval functions
    'get_logger',
    'get_security_logger',
    'get_audit_logger',

    # Logging action functions
    'log_security_event',
    'log_critical',
    'log_error',
    'log_warning',
    'log_info',
    'log_debug',
    'log_file_integrity_event',

    # Utility functions
    'log_to_file',
    'sanitize_log_message',
    'obfuscate_sensitive_data',
    'get_file_integrity_events',
    'initialize_module_logging',

    # Formatter classes
    'SecurityAwareJsonFormatter',
    'FileIntegrityAwareHandler',

    # Constants
    'LOG_LEVEL_DEBUG',
    'LOG_LEVEL_INFO',
    'LOG_LEVEL_WARNING',
    'LOG_LEVEL_ERROR',
    'LOG_LEVEL_CRITICAL',
    'DEFAULT_LOG_FORMAT',
    'DEFAULT_CONSOLE_FORMAT',
    'CLI_LOG_FORMAT'
]


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


def setup_app_logging(app: Any = None,
                     level: Union[str, int] = logging.INFO,
                     log_file: Optional[str] = None) -> None:
    """
    Configure logging for Flask application.

    Args:
        app: Flask application instance
        level: Log level to use (name or number)
        log_file: Optional path to log file
    """
    # Convert string level name to numeric value if needed
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Configure Flask app logger if provided
    if app:
        # Use Flask's logger configuration mechanism
        app.logger.setLevel(level)

        # Remove default handler if adding a custom one
        if log_file and app.logger.handlers:
            for handler in app.logger.handlers:
                app.logger.removeHandler(handler)

        formatter = logging.Formatter(DEFAULT_LOG_FORMAT)

        # Add file handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            app.logger.addHandler(file_handler)

        # Make sure we have at least one handler
        if not app.logger.handlers:
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            app.logger.addHandler(stream_handler)

    # Also configure the root logger
    logging.basicConfig(
        level=level,
        format=DEFAULT_LOG_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def setup_logging(level: Union[str, int] = logging.INFO,
                 log_file: Optional[str] = None,
                 log_format: Optional[str] = None,
                 include_timestamp: bool = True,
                 json_format: bool = False,
                 max_bytes: int = 10*1024*1024,
                 backup_count: int = 5) -> None:
    """
    Set up general-purpose logging configuration.

    This function configures logging for general use cases, providing a middle ground
    between the application-specific setup_app_logging and CLI-oriented setup_cli_logging.
    It configures both console and file logging with appropriate formatting.

    Args:
        level: Log level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL) or
               as a logging constant
        log_file: Optional path to log file. If None, logs only to console
        log_format: Optional custom log format. If None, uses DEFAULT_LOG_FORMAT
        include_timestamp: Whether to include timestamps in log output
        json_format: Whether to use JSON formatting for log file output
        max_bytes: Maximum size in bytes before log rotation
        backup_count: Number of rotated log files to keep

    Example:
        ```python
        from core.utils.logging_utils import setup_logging

        # Basic setup with console output
        setup_logging()

        # Setup with file output and JSON formatting
        setup_logging(level='INFO', log_file='/var/log/myapp.log', json_format=True)
        ```
    """
    # Get root logger
    root_logger = logging.getLogger()

    # Clear existing handlers to avoid duplicates when reloading
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Set log level
    if isinstance(level, str):
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        log_level = level

    root_logger.setLevel(log_level)

    # Determine log format
    if not log_format:
        log_format = DEFAULT_LOG_FORMAT if include_timestamp else DEFAULT_CONSOLE_FORMAT

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            # Set secure permissions on log directory
            if log_dir:
                try:
                    os.chmod(log_dir, 0o750)
                except (OSError, PermissionError):
                    pass

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )

            # Use JSON formatting or standard formatting
            if json_format:
                try:
                    # Try to use SecurityAwareJsonFormatter
                    if hasattr(logging.getLogger(), 'handlers') and isinstance(logging.getLogger().handlers[0], SecurityAwareJsonFormatter):
                        file_handler.setFormatter(SecurityAwareJsonFormatter())
                    else:
                        # Fall back to standard formatter
                        file_formatter = logging.Formatter(log_format)
                        file_handler.setFormatter(file_formatter)
                except Exception:
                    # Fall back to standard formatter
                    file_formatter = logging.Formatter(log_format)
                    file_handler.setFormatter(file_formatter)
            else:
                file_formatter = logging.Formatter(log_format)
                file_handler.setFormatter(file_formatter)

            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)

            # Secure the log file with appropriate permissions
            try:
                os.chmod(log_file, 0o640)
            except (OSError, PermissionError):
                pass

        except (IOError, OSError) as e:
            # Log to console if file setup fails
            root_logger.error(f"Failed to set up file logging: {e}")

    # Set up security logger with the same configuration
    security_logger = logging.getLogger('security')
    security_logger.setLevel(log_level)
    security_logger.propagate = False  # Prevent duplication

    # Add current log configuration to the security logger if it has no handlers
    if not security_logger.handlers:
        for handler in root_logger.handlers:
            security_logger.addHandler(handler)

    # Log initialization at debug level
    if log_level <= logging.DEBUG:
        root_logger.debug(f"Logging initialized (level: {logging.getLevelName(log_level)}, file: {log_file or 'none'})")


def setup_cli_logging(log_file: Optional[str] = None,
                     level: Union[str, int] = logging.INFO,
                     include_timestamp: bool = True,
                     json_format: bool = False) -> None:
    """
    Set up logging specifically for CLI applications.

    Configures logging for command-line interface tools with appropriate
    formatting and output options. This creates a more user-friendly output
    focused on readability while still maintaining proper structured logging
    when needed.

    Args:
        log_file: Optional path to log file. If None, logs only to console.
        level: Log level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL) or
               as a logging constant.
        include_timestamp: Whether to include timestamps in console output
        json_format: Whether to use JSON formatting for log file output

    Example:
        ```python
        from core.utils.logging_utils import setup_cli_logging

        # Basic setup with console output only
        setup_cli_logging()

        # Setup with file output and custom level
        setup_cli_logging('/var/log/myapp/cli.log', level='DEBUG')
        ```
    """
    # Get root logger
    root_logger = logging.getLogger()

    # Clear existing handlers to avoid duplicates when reloading
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Set numeric log level
    if isinstance(level, str):
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        log_level = level

    root_logger.setLevel(log_level)

    # Create console handler with appropriate formatting
    console_handler = logging.StreamHandler(sys.stdout)

    # Use a more readable format for CLI
    if include_timestamp:
        console_format = CLI_LOG_FORMAT
    else:
        console_format = DEFAULT_CONSOLE_FORMAT

    console_formatter = logging.Formatter(console_format)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            # Set secure permissions on log directory
            if log_dir:
                try:
                    os.chmod(log_dir, 0o750)
                except (OSError, PermissionError):
                    pass

            # Create the file handler with rotation
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file, maxBytes=5*1024*1024, backupCount=5
            )

            # Use JSON formatting or standard formatting
            if json_format:
                try:
                    # Try to use the platform's JSON formatter if available
                    from core.utils.json_log_formatter import JsonFormatter
                    file_handler.setFormatter(JsonFormatter())
                except ImportError:
                    # Fall back to standard formatter
                    file_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
                    file_handler.setFormatter(file_formatter)
            else:
                file_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
                file_handler.setFormatter(file_formatter)

            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)

            # Secure the log file with appropriate permissions
            try:
                os.chmod(log_file, 0o640)
            except (OSError, PermissionError):
                pass

        except (IOError, OSError) as e:
            # Log to console if file setup fails
            root_logger.error(f"Failed to set up file logging for CLI: {e}")

    # Set up CLI module logger
    cli_logger = logging.getLogger('cli')
    cli_logger.setLevel(log_level)

    # Report setup completion if debug level
    if log_level <= logging.DEBUG:
        root_logger.debug(f"CLI logging initialized (level: {logging.getLevelName(log_level)}, file: {log_file or 'none'})")


def get_logger(module_name: str, level: Union[str, int] = None) -> logging.Logger:
    """
    Get a logger instance with proper configuration for a module.

    Creates or retrieves a logger for a specific module with appropriate
    configuration to ensure consistent logging behavior.

    Args:
        module_name: Name of the module requesting a logger
        level: Optional specific log level for this logger

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(module_name)

    # Set level if specified
    if level is not None:
        if isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)
        logger.setLevel(level)

    return logger


def log_to_file(message: str,
               level: Union[str, int] = logging.INFO,
               log_file: str = None,
               include_timestamp: bool = True) -> bool:
    """
    Log a message to a specific file.

    Directly writes a log message to a specified file without going through
    the logging system. Useful for dedicated logs like audit logs.

    Args:
        message: The message to log
        level: The log level (name or numeric constant)
        log_file: Path to the log file
        include_timestamp: Whether to include timestamp in the message

    Returns:
        True if successful, False otherwise
    """
    if not log_file:
        return False

    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # Format the level if it's a number
        if isinstance(level, int):
            level_name = logging.getLevelName(level)
        else:
            level_name = level.upper()

        # Format the message with timestamp if requested
        if include_timestamp:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            formatted_message = f"[{timestamp}] {level_name}: {message}\n"
        else:
            formatted_message = f"{level_name}: {message}\n"

        # Write to file
        with open(log_file, 'a') as f:
            f.write(formatted_message)

        return True
    except Exception as e:
        # Log to standard logger if file logging fails
        logger.error(f"Failed to log to file {log_file}: {e}")
        return False


def sanitize_log_message(message: str) -> str:
    """
    Sanitize a message before logging to prevent log injection.

    Removes potentially dangerous characters from log messages that could be used
    for log injection attacks.

    Args:
        message: The message to sanitize

    Returns:
        Sanitized message string
    """
    # Replace newlines and carriage returns with spaces
    sanitized = message.replace("\n", " ").replace("\r", " ")

    # Filter out control characters
    sanitized = "".join(ch for ch in sanitized if ch >= ' ' or ch in ['\t'])

    # Truncate very long messages
    if len(sanitized) > 8192:
        sanitized = sanitized[:8189] + "..."

    return sanitized


def obfuscate_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask sensitive data in dictionary for safe logging.

    Args:
        data: Dictionary potentially containing sensitive data

    Returns:
        Dictionary with sensitive values masked
    """
    if not isinstance(data, dict):
        return data

    sensitive_patterns = [
        "password", "secret", "token", "key", "credential",
        "api_key", "private", "access_key", "secret_key"
    ]

    masked_data = {}
    for key, value in data.items():
        if any(pattern in key.lower() for pattern in sensitive_patterns):
            masked_data[key] = "******" if value else value
        elif isinstance(value, dict):
            masked_data[key] = obfuscate_sensitive_data(value)
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            masked_data[key] = [obfuscate_sensitive_data(item) for item in value]
        else:
            masked_data[key] = value

    return masked_data


def log_critical(message: str) -> None:
    """Log a critical message using the appropriate logger."""
    if has_app_context():
        current_app.logger.critical(message)
    else:
        logger.critical(message)


def log_error(message: str) -> None:
    """Log an error message using the appropriate logger."""
    if has_app_context():
        current_app.logger.error(message)
    else:
        logger.error(message)


def log_warning(message: str) -> None:
    """Log a warning message using the appropriate logger."""
    if has_app_context():
        current_app.logger.warning(message)
    else:
        logger.warning(message)


def log_info(message: str) -> None:
    """Log an info message using the appropriate logger."""
    if has_app_context():
        current_app.logger.info(message)
    else:
        logger.info(message)


def log_debug(message: str) -> None:
    """Log a debug message using the appropriate logger."""
    if has_app_context():
        current_app.logger.debug(message)
    else:
        logger.debug(message)


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for the specified name.

    This function returns a logger that's properly configured with the application's
    logging settings, including appropriate formatters and handlers. When called
    within a Flask application context, it will use the application's logging
    configuration. Otherwise, it will use a basic configuration that sends logs
    to stdout.

    Args:
        name: The name for the logger, typically __name__ of the calling module

    Returns:
        logging.Logger: A configured logger instance

    Example:
        # At the top level of a module:
        logger = get_logger(__name__)

        # Later in the code:
        logger.info("Operation completed successfully")
        logger.error("An error occurred: %s", str(error))
    """
    logger = logging.getLogger(name)

    # If we're in a Flask app context, we assume logging is already configured
    # by setup_app_logging
    if not has_app_context() and not logger.handlers:
        # If we're not in a Flask app context, configure basic logging
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(name)s: %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Get appropriate log level, defaulting to INFO
        log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
        numeric_level = getattr(logging, log_level, logging.INFO)
        logger.setLevel(numeric_level)

    return logger


def get_security_logger() -> logging.Logger:
    """
    Get the security logger instance.

    Returns:
        logging.Logger: The security logger instance
    """
    return logging.getLogger('security')


def get_audit_logger() -> logging.Logger:
    """
    Get a logger specifically for audit events.

    This logger is configured to handle audit events with appropriate formatting
    and routing. It ensures that all audit-related activities are properly tracked
    and can be easily filtered from other log entries.

    Returns:
        logging.Logger: An instance of the audit logger
    """
    audit_logger = logging.getLogger('audit')

    # If in Flask context, ensure proper configuration
    if has_app_context():
        # If the handler hasn't been set up yet, add one
        if not audit_logger.handlers:
            # Check if a specific audit log path is defined in config
            log_dir = current_app.config.get('LOG_DIR', 'logs')
            audit_log_path = os.path.join(log_dir, 'audit.log')

            try:
                # Ensure directory exists
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                    try:
                        os.chmod(log_dir, 0o750)
                    except (OSError, PermissionError):
                        pass

                # Create rotating file handler for audit log
                audit_handler = logging.handlers.RotatingFileHandler(
                    audit_log_path, maxBytes=10*1024*1024, backupCount=20
                )
                audit_handler.setFormatter(SecurityAwareJsonFormatter())
                audit_handler.setLevel(logging.INFO)
                audit_logger.addHandler(audit_handler)

                # Set secure permissions on the log file
                try:
                    os.chmod(audit_log_path, 0o640)
                except (OSError, PermissionError):
                    pass

                # Make audit logger propagate to root
                audit_logger.propagate = True
            except (IOError, OSError) as e:
                logger.error(f"Failed to set up audit logging: {e}")

    return audit_logger


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
