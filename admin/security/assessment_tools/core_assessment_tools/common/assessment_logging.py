"""
Secure logging functionality for security assessment tools.

This module provides specialized logging utilities for security assessment operations,
ensuring proper audit trails, sensitive data protection, and secure log handling.
"""

import datetime
import json
import logging
import logging.handlers
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union, cast

# Set up module-level logger with null handler to prevent no-handler warnings
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Define constants
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
DEFAULT_LOG_DIR = "logs"
SENSITIVE_PATTERNS = [
    r'password\s*[=:]\s*\S+',
    r'token\s*[=:]\s*\S+',
    r'secret\s*[=:]\s*\S+',
    r'key\s*[=:]\s*\S+',
    r'auth\s*[=:]\s*\S+',
    r'credential\s*[=:]\s*\S+',
    r'ssh-rsa\s+\S+',
]


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """A secure rotating file handler with proper permissions."""

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0,
                 encoding=None, delay=False, errors=None):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay, errors)

        # Set secure file permissions (0o600 = owner read/write only)
        try:
            os.chmod(filename, 0o600)
        except OSError:
            pass  # Handle cases when we can't set permissions


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive information from logs."""

    def __init__(self, patterns: Optional[List[str]] = None):
        super().__init__()
        self.patterns = patterns or SENSITIVE_PATTERNS
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern in self.compiled_patterns:
                record.msg = pattern.sub(r'\1=***REDACTED***', record.msg)

        return True


class AssessmentJsonFormatter(logging.Formatter):
    """JSON formatter for structured assessment logs."""

    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record, self.datefmt or DEFAULT_LOG_DATE_FORMAT),
            'level': record.levelname,
            'name': record.name,
            'message': super().format(record),
            'module': record.module,
            'lineno': record.lineno,
            'process': record.process,
            'thread': record.thread,
            'hostname': socket.gethostname()
        }

        # Add extra context if available
        if hasattr(record, 'assessment_id'):
            log_data['assessment_id'] = record.assessment_id

        if hasattr(record, 'target_id'):
            log_data['target_id'] = record.target_id

        # Add any other attributes from record.__dict__
        # Skip internal attributes and already processed ones
        skip_attrs = {'args', 'asctime', 'created', 'exc_info', 'exc_text',
                      'filename', 'funcName', 'id', 'levelname', 'levelno',
                      'lineno', 'module', 'msecs', 'message', 'msg', 'name',
                      'pathname', 'process', 'processName', 'relativeCreated',
                      'stack_info', 'thread', 'threadName'}

        for key, value in record.__dict__.items():
            if key not in skip_attrs and not key.startswith('_'):
                try:
                    # Attempt to serialize the value as JSON
                    json.dumps({key: value})
                    log_data[key] = value
                except (TypeError, OverflowError):
                    # If value is not JSON serializable, use string representation
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


def setup_logging(module_name: str, log_level: Optional[str] = None) -> logging.Logger:
    """
    Set up a logger with basic configuration.

    Args:
        module_name: Name of the module for the logger
        log_level: Optional log level override

    Returns:
        Configured logger instance
    """
    # Parse log level
    level_name = log_level or os.environ.get('LOG_LEVEL', 'INFO')
    level = getattr(logging, level_name.upper(), DEFAULT_LOG_LEVEL)

    # Create logger
    logger = logging.getLogger(module_name)
    logger.setLevel(level)

    # Add a console handler if no handlers are configured
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Add sensitive data filter
        sensitive_filter = SensitiveDataFilter()
        console_handler.addFilter(sensitive_filter)

    return logger


def setup_assessment_logging(assessment_name: str, log_dir: Optional[str] = None,
                           log_level: Optional[str] = None,
                           assessment_id: Optional[str] = None) -> logging.Logger:
    """
    Set up logging specifically for assessment operations.

    Args:
        assessment_name: Name of the assessment module
        log_dir: Directory to store log files
        log_level: Optional log level override
        assessment_id: Optional assessment ID for correlation

    Returns:
        Configured logger for the assessment
    """
    # Parse log level
    level_name = log_level or os.environ.get('LOG_LEVEL', 'INFO')
    level = getattr(logging, level_name.upper(), DEFAULT_LOG_LEVEL)

    # Create logger
    logger = logging.getLogger(f"assessment.{assessment_name}")
    logger.setLevel(level)

    # Don't add handlers if they already exist
    if logger.handlers:
        return logger

    # Set up console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Set up file handler if log directory is provided
    if log_dir is None:
        # Default to logs directory in assessment tools directory
        log_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            DEFAULT_LOG_DIR
        )

    try:
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, mode=0o750, exist_ok=True)

        # Create assessment-specific log file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        assessment_id_str = f"_{assessment_id}" if assessment_id else ""
        log_file = os.path.join(
            log_dir,
            f"{assessment_name}{assessment_id_str}_{timestamp}.log"
        )

        # Set up secure file handler with rotation
        file_handler = SecureRotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setLevel(level)

        # Use JSON formatter for structured logging to file
        file_formatter = AssessmentJsonFormatter()
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Add sensitive data filter to both handlers
        sensitive_filter = SensitiveDataFilter()
        console_handler.addFilter(sensitive_filter)
        file_handler.addFilter(sensitive_filter)

        logger.info(f"Assessment logging initialized: {log_file}")
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to set up file logging: {str(e)}")
        logger.warning("Continuing with console logging only")

    return logger


def get_assessment_logger(name: str) -> logging.Logger:
    """
    Get a logger for assessment operations.

    Args:
        name: Name for the logger

    Returns:
        Logger with the specified name
    """
    return logging.getLogger(f"assessment.{name}")


def log_assessment_event(
    logger: logging.Logger,
    event_type: str,
    message: str,
    assessment_id: Optional[str] = None,
    target_id: Optional[str] = None,
    severity: str = "info",
    details: Optional[Dict[str, Any]] = None,
    evidence_path: Optional[str] = None
) -> None:
    """
    Log an assessment event with proper context.

    Args:
        logger: Logger to use
        event_type: Type of event (e.g., 'initialization', 'finding', 'error')
        message: Event message
        assessment_id: ID of the assessment
        target_id: ID of the target system
        severity: Event severity (info, warning, error, critical)
        details: Additional event details
        evidence_path: Path to related evidence, if any
    """
    log_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }.get(severity.lower(), logging.INFO)

    # Create extra context
    extra = {
        'event_type': event_type,
        'timestamp': datetime.datetime.now().isoformat()
    }

    if assessment_id:
        extra['assessment_id'] = assessment_id

    if target_id:
        extra['target_id'] = target_id

    if details:
        extra['details'] = details

    if evidence_path:
        extra['evidence_path'] = evidence_path

    # Log with extra context
    logger.log(log_level, message, extra=extra)


def log_security_finding(
    logger: logging.Logger,
    finding_id: str,
    title: str,
    description: str,
    severity: str,
    assessment_id: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    evidence_paths: Optional[List[str]] = None
) -> None:
    """
    Log a security finding from an assessment.

    Args:
        logger: Logger to use
        finding_id: Unique ID of the finding
        title: Short finding title
        description: Detailed finding description
        severity: Finding severity (low, medium, high, critical)
        assessment_id: ID of the assessment
        target_id: ID of the target system
        details: Additional finding details
        evidence_paths: Paths to related evidence files
    """
    log_level = {
        "low": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.ERROR,
        "critical": logging.CRITICAL
    }.get(severity.lower(), logging.WARNING)

    # Create finding details
    finding_details = {
        'finding_id': finding_id,
        'title': title,
        'severity': severity
    }

    if assessment_id:
        finding_details['assessment_id'] = assessment_id

    if target_id:
        finding_details['target_id'] = target_id

    if details:
        finding_details['additional_details'] = details

    if evidence_paths:
        finding_details['evidence_paths'] = evidence_paths

    # Log with extra context
    logger.log(log_level, f"Finding: {title}", extra={
        'event_type': 'security_finding',
        'finding': finding_details,
        'timestamp': datetime.datetime.now().isoformat()
    })


def configure_file_logging(
    logger: logging.Logger,
    log_file: str,
    log_level: Optional[str] = None,
    max_size: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    use_json_format: bool = True
) -> None:
    """
    Configure file logging for an existing logger.

    Args:
        logger: Logger to configure
        log_file: Path to the log file
        log_level: Log level for the file handler
        max_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        use_json_format: Whether to use JSON formatting
    """
    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, mode=0o750, exist_ok=True)

        # Set log level
        level_name = log_level or os.environ.get('LOG_LEVEL', 'INFO')
        level = getattr(logging, level_name.upper(), DEFAULT_LOG_LEVEL)

        # Create handler
        file_handler = SecureRotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setLevel(level)

        # Set formatter
        if use_json_format:
            formatter = AssessmentJsonFormatter()
        else:
            formatter = logging.Formatter(DEFAULT_LOG_FORMAT)

        file_handler.setFormatter(formatter)

        # Add sensitive data filter
        file_handler.addFilter(SensitiveDataFilter())

        # Add handler to logger
        logger.addHandler(file_handler)
        logger.info(f"File logging configured: {log_file}")

    except (OSError, PermissionError) as e:
        logger.error(f"Failed to configure file logging: {str(e)}")


def sanitize_sensitive_data(data: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
    """
    Sanitize potentially sensitive data for logging.

    Args:
        data: Input data to sanitize

    Returns:
        Sanitized data with sensitive information redacted
    """
    if isinstance(data, str):
        for pattern in SENSITIVE_PATTERNS:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            data = compiled_pattern.sub(r'\1=***REDACTED***', data)
        return data

    elif isinstance(data, dict):
        sanitized = {}
        sensitive_keys = {'password', 'token', 'secret', 'key', 'auth', 'credential', 'apikey', 'api_key'}

        for key, value in data.items():
            # Check if this is a sensitive key
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            # Recursively sanitize nested dictionaries
            elif isinstance(value, dict):
                sanitized[key] = sanitize_sensitive_data(value)
            # Sanitize strings that may contain sensitive data
            elif isinstance(value, str):
                sanitized[key] = sanitize_sensitive_data(value)
            # Other types can be included as-is
            else:
                sanitized[key] = value

        return sanitized

    # Return unchanged for other types
    return data
