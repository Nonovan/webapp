#!/usr/bin/env python3
# filepath: scripts/core/logger.py
"""
Standardized Logging Interface for Cloud Infrastructure Platform.

This module provides a comprehensive logging system with configurable handlers,
formatters, and log levels. It ensures consistent logging across all platform
components and integrates with monitoring systems for alerting on critical events.

Key features:
- Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Configurable log destinations (console, file, syslog)
- Log rotation and management
- Structured logging format with context tracking
- Integration with monitoring systems
- Secure handling of sensitive data in logs
"""

import logging
import logging.handlers
import json
import os
import sys
import socket
import traceback
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Tuple

# Constants
DEFAULT_LOG_FORMAT = '[%(asctime)s] %(levelname)s in %(name)s: %(message)s'
DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
SIMPLE_LOG_FORMAT = '%(levelname)s: %(message)s'
JSON_LOG_FORMAT = {
    'timestamp': '%(asctime)s',
    'level': '%(levelname)s',
    'name': '%(name)s',
    'message': '%(message)s',
    'location': '%(pathname)s:%(lineno)d',
    'function': '%(funcName)s'
}
CLI_LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s'
SECURITY_LOG_FORMAT = '[%(asctime)s] SECURITY %(levelname)s: %(message)s'

# Log categories
SECURITY_LOG_CATEGORY = "security"
AUDIT_LOG_CATEGORY = "audit"
SYSTEM_LOG_CATEGORY = "system"
FILE_INTEGRITY_LOG_CATEGORY = "file_integrity"

# Default log levels
LOG_LEVEL_DEBUG = logging.DEBUG
LOG_LEVEL_INFO = logging.INFO
LOG_LEVEL_WARNING = logging.WARNING
LOG_LEVEL_ERROR = logging.ERROR
LOG_LEVEL_CRITICAL = logging.CRITICAL

# Default paths
DEFAULT_LOG_DIR = '/var/log/cloud-platform'
DEFAULT_LOG_FILE = 'app.log'
DEFAULT_SECURITY_LOG_FILE = 'security.log'
DEFAULT_AUDIT_LOG_FILE = 'audit.log'

# Defaults for log rotation
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_LOG_BACKUP_COUNT = 5

# Pattern to detect potentially sensitive data
SENSITIVE_DATA_PATTERNS = [
    r'password\s*[=:]\s*[^\s,;]+',
    r'key\s*[=:]\s*[^\s,;]+',
    r'secret\s*[=:]\s*[^\s,;]+',
    r'token\s*[=:]\s*[^\s,;]+',
    r'credential\s*[=:]\s*[^\s,;]+',
    r'"(password|secret|key|token)"\s*:\s*"[^"]+"',
]


class SensitiveDataFilter(logging.Filter):
    """
    Filter that removes sensitive data from log records.
    """

    def __init__(self):
        super().__init__()
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in SENSITIVE_DATA_PATTERNS]

    def filter(self, record):
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.patterns:
                msg = pattern.sub(r'\1: [REDACTED]', msg)
            record.msg = msg

        # Handle extra attributes that might contain sensitive data
        if hasattr(record, 'extra') and isinstance(record.extra, dict):
            for key, value in record.extra.items():
                if any(re.search(p, key, re.IGNORECASE) for p in
                      ['password', 'secret', 'key', 'token', 'credential']):
                    record.extra[key] = '[REDACTED]'

        return True


class SecurityAwareJsonFormatter(logging.Formatter):
    """
    JSON formatter for logs that handles security context and sensitive data.
    """

    def __init__(self, fmt=None, datefmt=None):
        self.fmt_dict = fmt if fmt else JSON_LOG_FORMAT
        if isinstance(self.fmt_dict, str):
            self.fmt_dict = json.loads(self.fmt_dict)
        super().__init__(fmt=None, datefmt=datefmt or DEFAULT_DATE_FORMAT)

    def format(self, record):
        log_data = {}
        for key, fmt_pattern in self.fmt_dict.items():
            try:
                log_data[key] = fmt_pattern % record.__dict__
            except (KeyError, TypeError):
                log_data[key] = fmt_pattern

        # Add extra attributes
        if hasattr(record, 'extra') and record.extra:
            for key, value in record.extra.items():
                if key not in log_data:
                    log_data[key] = value

        # Add exception info if available
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }

        # Add hostname
        log_data['hostname'] = socket.gethostname()

        # Add process and thread info
        log_data['process'] = {
            'id': record.process,
            'name': record.processName
        }
        log_data['thread'] = {
            'id': record.thread,
            'name': record.threadName
        }

        return json.dumps(log_data)


class Logger:
    """
    Main logger class for Cloud Infrastructure Platform.
    Provides standardized logging functionality with configurable behavior.
    """

    # Store logger instances for reuse
    _loggers = {}

    @classmethod
    def get_logger(cls, name: str, level: Union[int, str] = None,
                  log_file: str = None, json_format: bool = False) -> logging.Logger:
        """
        Get a configured logger instance.

        Args:
            name: Logger name (usually __name__ of the calling module)
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (if None, logs to console only)
            json_format: Whether to format logs as JSON

        Returns:
            Configured logging.Logger instance
        """
        # Return existing logger if already configured
        if name in cls._loggers:
            return cls._loggers[name]

        # Create new logger
        logger = logging.getLogger(name)

        # Set log level
        if level is None:
            # Use environment variable or default to INFO
            level_name = os.environ.get('LOG_LEVEL', 'INFO')
            level = getattr(logging, level_name.upper(), logging.INFO)
        elif isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)

        logger.setLevel(level)

        # Add console handler if no handlers are configured
        if not logger.handlers:
            console_handler = logging.StreamHandler()
            if json_format:
                formatter = SecurityAwareJsonFormatter()
            else:
                formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

            # Add sensitive data filter
            sensitive_filter = SensitiveDataFilter()
            console_handler.addFilter(sensitive_filter)

        # Add file handler if specified
        if log_file:
            cls._add_file_handler(logger, log_file, level, json_format)

        # Store logger for reuse
        cls._loggers[name] = logger
        return logger

    @classmethod
    def get_security_logger(cls, level: Union[int, str] = None,
                           log_file: str = None) -> logging.Logger:
        """
        Get a logger configured for security events.

        Args:
            level: Log level (defaults to INFO if not specified)
            log_file: Path to security log file (defaults to security.log)

        Returns:
            Configured logging.Logger for security events
        """
        if log_file is None:
            log_dir = os.environ.get('LOG_DIR', DEFAULT_LOG_DIR)
            log_file = os.path.join(log_dir, DEFAULT_SECURITY_LOG_FILE)

        security_logger = cls.get_logger(SECURITY_LOG_CATEGORY, level, log_file, json_format=True)
        return security_logger

    @classmethod
    def get_audit_logger(cls, level: Union[int, str] = None,
                        log_file: str = None) -> logging.Logger:
        """
        Get a logger configured for audit events.

        Args:
            level: Log level (defaults to INFO if not specified)
            log_file: Path to audit log file (defaults to audit.log)

        Returns:
            Configured logging.Logger for audit events
        """
        if log_file is None:
            log_dir = os.environ.get('LOG_DIR', DEFAULT_LOG_DIR)
            log_file = os.path.join(log_dir, DEFAULT_AUDIT_LOG_FILE)

        audit_logger = cls.get_logger(AUDIT_LOG_CATEGORY, level, log_file, json_format=True)
        return audit_logger

    @staticmethod
    def _add_file_handler(logger: logging.Logger, log_file: str,
                         level: Union[int, str] = None, json_format: bool = False) -> None:
        """
        Add a file handler to the logger.

        Args:
            logger: Logger to add handler to
            log_file: Path to log file
            level: Log level for this handler
            json_format: Whether to use JSON formatting
        """
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                pass  # Fall back to console logging if directory creation fails

        try:
            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=DEFAULT_LOG_MAX_BYTES,
                backupCount=DEFAULT_LOG_BACKUP_COUNT,
                delay=True  # Delay file creation until first log message
            )

            # Set formatter
            if json_format:
                formatter = SecurityAwareJsonFormatter()
            else:
                formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT)
            file_handler.setFormatter(formatter)

            # Set log level
            if level is not None:
                file_handler.setLevel(level)

            # Add filters
            sensitive_filter = SensitiveDataFilter()
            file_handler.addFilter(sensitive_filter)

            # Add handler to logger
            logger.addHandler(file_handler)

            # Set secure permissions for log file if possible
            try:
                if os.path.exists(log_file):
                    os.chmod(log_file, 0o640)
            except OSError:
                pass  # Permission error shouldn't prevent logging

        except (OSError, IOError):
            # Fall back to console logging if file logging fails
            pass

    @staticmethod
    def setup_root_logger(level: Union[int, str] = None,
                         log_file: str = None,
                         json_format: bool = False) -> None:
        """
        Configure the root logger for the entire application.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (if None, logs to console only)
            json_format: Whether to format logs as JSON
        """
        # Reset root logger
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Set log level
        if level is None:
            level_name = os.environ.get('LOG_LEVEL', 'INFO')
            level = getattr(logging, level_name.upper(), logging.INFO)
        elif isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)

        root_logger.setLevel(level)

        # Add console handler
        console_handler = logging.StreamHandler()
        if json_format:
            formatter = SecurityAwareJsonFormatter()
        else:
            formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        root_logger.addHandler(console_handler)

        # Add file handler if specified
        if log_file:
            Logger._add_file_handler(root_logger, log_file, level, json_format)

    @staticmethod
    def log_to_file(message: str, level: Union[str, int] = logging.INFO,
                   log_file: str = None, include_timestamp: bool = True) -> bool:
        """
        Log a message directly to a file without using a logger.

        Args:
            message: Message to log
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file
            include_timestamp: Whether to include timestamp in the log message

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
                timestamp = datetime.now().strftime(DEFAULT_DATE_FORMAT)
                formatted_message = f"[{timestamp}] {level_name}: {message}\n"
            else:
                formatted_message = f"{level_name}: {message}\n"

            # Write to file
            with open(log_file, 'a') as f:
                f.write(formatted_message)

            # Set secure permissions on the log file
            try:
                os.chmod(log_file, 0o640)
            except (OSError, PermissionError):
                pass  # Permission error shouldn't prevent logging

            return True
        except Exception:
            # Failed to log to file
            return False

    @staticmethod
    def log_event(event_type: str, description: str, severity: str = "info",
                 logger: logging.Logger = None, details: Dict[str, Any] = None,
                 log_file: str = None) -> None:
        """
        Log a structured event with standard fields.

        Args:
            event_type: Type of event (categorizes the event)
            description: Human-readable description of the event
            severity: Severity level (info, warning, error, critical)
            logger: Logger to use (if None, gets a new security logger)
            details: Additional details to include in the log
            log_file: Path to log file (if different from logger's handlers)
        """
        if logger is None:
            logger = Logger.get_security_logger()

        # Map severity string to log level
        level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }
        level = level_map.get(severity.lower(), logging.INFO)

        # Prepare extra data
        extra_data = {
            "event_type": event_type,
            "severity": severity,
        }

        # Add details if provided
        if details:
            # Sanitize details to prevent sensitive data leakage
            sanitized_details = {}
            for k, v in details.items():
                if any(s in k.lower() for s in ["password", "secret", "key", "token", "credential"]):
                    sanitized_details[k] = "[REDACTED]"
                else:
                    sanitized_details[k] = v
            extra_data["details"] = sanitized_details

        # Log the event with extra context
        logger.log(level, description, extra=extra_data)

        # Also log to file if specified (useful for audit trails)
        if log_file:
            try:
                event_data = {
                    "timestamp": datetime.now().strftime(DEFAULT_DATE_FORMAT),
                    "event_type": event_type,
                    "description": description,
                    "severity": severity,
                    "details": details if details else {}
                }
                with open(log_file, 'a') as f:
                    json.dump(event_data, f)
                    f.write('\n')
            except Exception:
                # Fall back to standard logging if file logging fails
                logger.warning(f"Failed to write event to log file: {log_file}")


def setup_logging(level: Union[int, str] = None, log_file: str = None,
                 json_format: bool = False) -> logging.Logger:
    """
    Configure logging for an application or script.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, logs to console only)
        json_format: Whether to format logs as JSON

    Returns:
        Root logger instance
    """
    # Configure root logger
    Logger.setup_root_logger(level, log_file, json_format)

    # Get the root logger
    root_logger = logging.getLogger()

    # Log setup completion at debug level
    root_logger.debug(f"Logging initialized (level: {logging.getLevelName(root_logger.level)}, "
                     f"file: {log_file or 'none'})")

    return root_logger


def setup_cli_logging(log_file: str = None, level: Union[str, int] = None,
                     include_timestamp: bool = True, json_format: bool = False) -> logging.Logger:
    """
    Configure logging specifically for command-line interface scripts.

    Args:
        log_file: Path to log file (if None, logs to console only)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        include_timestamp: Whether to include timestamp in console logs
        json_format: Whether to format logs as JSON

    Returns:
        Root logger instance
    """
    # Reset root logger
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Set log level
    if level is None:
        level_name = os.environ.get('LOG_LEVEL', 'INFO')
        level = getattr(logging, level_name.upper(), logging.INFO)
    elif isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    root_logger.setLevel(level)

    # Add console handler with CLI-friendly formatting
    console_handler = logging.StreamHandler(sys.stdout)
    if include_timestamp:
        formatter = logging.Formatter(CLI_LOG_FORMAT, DEFAULT_DATE_FORMAT)
    else:
        formatter = logging.Formatter(SIMPLE_LOG_FORMAT)

    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        Logger._add_file_handler(root_logger, log_file, level, json_format)

    # Get CLI module logger
    cli_logger = logging.getLogger('cli')
    cli_logger.setLevel(level)

    # Log setup completion at debug level
    root_logger.debug(f"CLI logging initialized (level: {logging.getLevelName(level)}, "
                     f"file: {log_file or 'none'})")

    return root_logger


# Convenience functions
def get_logger(name: str, level: Union[int, str] = None,
              log_file: str = None, json_format: bool = False) -> logging.Logger:
    """
    Get a configured logger instance (wrapper for Logger.get_logger).

    Args:
        name: Logger name (usually __name__ of the calling module)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, logs to console only)
        json_format: Whether to format logs as JSON

    Returns:
        Configured logging.Logger instance
    """
    return Logger.get_logger(name, level, log_file, json_format)


def get_security_logger(level: Union[int, str] = None, log_file: str = None) -> logging.Logger:
    """
    Get a logger configured for security events (wrapper for Logger.get_security_logger).

    Args:
        level: Log level (defaults to INFO if not specified)
        log_file: Path to security log file (defaults to security.log)

    Returns:
        Configured logging.Logger for security events
    """
    return Logger.get_security_logger(level, log_file)


def get_audit_logger(level: Union[int, str] = None, log_file: str = None) -> logging.Logger:
    """
    Get a logger configured for audit events (wrapper for Logger.get_audit_logger).

    Args:
        level: Log level (defaults to INFO if not specified)
        log_file: Path to audit log file (defaults to audit.log)

    Returns:
        Configured logging.Logger for audit events
    """
    return Logger.get_audit_logger(level, log_file)


def log_event(event_type: str, description: str, severity: str = "info",
             logger: logging.Logger = None, details: Dict[str, Any] = None,
             log_file: str = None) -> None:
    """
    Log a structured event with standard fields (wrapper for Logger.log_event).

    Args:
        event_type: Type of event (categorizes the event)
        description: Human-readable description of the event
        severity: Severity level (info, warning, error, critical)
        logger: Logger to use (if None, gets a new security logger)
        details: Additional details to include in the log
        log_file: Path to log file (if different from logger's handlers)
    """
    Logger.log_event(event_type, description, severity, logger, details, log_file)


# Module-level functions for direct use
def log_critical(message: str) -> None:
    """
    Log a critical message using the root logger.

    Args:
        message: Message to log
    """
    logging.critical(message)


def log_error(message: str) -> None:
    """
    Log an error message using the root logger.

    Args:
        message: Message to log
    """
    logging.error(message)


def log_warning(message: str) -> None:
    """
    Log a warning message using the root logger.

    Args:
        message: Message to log
    """
    logging.warning(message)


def log_info(message: str) -> None:
    """
    Log an info message using the root logger.

    Args:
        message: Message to log
    """
    logging.info(message)


def log_debug(message: str) -> None:
    """
    Log a debug message using the root logger.

    Args:
        message: Message to log
    """
    logging.debug(message)


# If this module is run directly, perform a simple test
if __name__ == "__main__":
    # Configure logging
    setup_logging(level="DEBUG")

    # Get a logger for this module
    logger = get_logger(__name__)

    # Log test messages at different levels
    logger.debug("This is a DEBUG message")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    logger.critical("This is a CRITICAL message")

    # Log with additional context
    logger.info("Operation completed", extra={"operation": "test", "duration_ms": 150})

    # Log a security event
    security_logger = get_security_logger()
    security_logger.warning("Potential security issue detected",
                          extra={"source_ip": "192.168.1.100", "user_agent": "curl/7.68.0"})

    # Log an event with the helper function
    log_event("user.login", "User login successful",
             details={"username": "jdoe", "ip_address": "192.168.1.100"})

    # Test sensitive data filtering
    logger.info("Connection string: password=Secret123! and api_key=abcd1234")

    print("\nLogging test complete. Check the output above for the log messages.")
