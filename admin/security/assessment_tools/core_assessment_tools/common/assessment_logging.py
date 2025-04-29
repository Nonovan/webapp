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


class EncryptedFileHandler(logging.FileHandler):
    """Handler that encrypts log entries before writing to file."""

    def __init__(self, filename, public_key_path, mode='a', encoding=None):
        super().__init__(filename, mode, encoding, delay=True)
        self.public_key_path = public_key_path
        # Load public key on initialization
        self._load_encryption_key()

    def _load_encryption_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        try:
            with open(self.public_key_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        except Exception as e:
            logger.error(f"Failed to load encryption key: {str(e)}")
            raise

    def emit(self, record):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            msg = self.format(record)
            encrypted = self.public_key.encrypt(
                msg.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Write base64-encoded encrypted data
            import base64
            encrypted_b64 = base64.b64encode(encrypted).decode()
            self.stream.write(f"{encrypted_b64}\n")
            self.flush()
        except Exception as e:
            self.handleError(record)


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


def add_log_integrity_protection(log_file: str, integrity_file: Optional[str] = None) -> None:
    """
    Add integrity protection to log files by computing and storing cryptographic hashes.

    Args:
        log_file: Path to the log file to protect
        integrity_file: Optional path to store integrity information, defaults to log_file + '.integrity'
    """
    import hashlib
    import time

    if integrity_file is None:
        integrity_file = f"{log_file}.integrity"

    try:
        with open(log_file, 'rb') as f:
            log_contents = f.read()

        log_hash = hashlib.sha256(log_contents).hexdigest()
        timestamp = int(time.time())

        with open(integrity_file, 'a') as f:
            f.write(f"{timestamp}:{log_hash}:{os.path.basename(log_file)}\n")

        # Set secure permissions on the integrity file
        os.chmod(integrity_file, 0o400)  # Read-only by owner

        logger.info(f"Added integrity protection to {log_file}")
    except Exception as e:
        logger.error(f"Failed to add integrity protection: {str(e)}")


def validate_log_integrity(log_file: str, integrity_file: Optional[str] = None) -> bool:
    """
    Validate the integrity of a log file using stored hashes.

    Args:
        log_file: Path to the log file to validate
        integrity_file: Optional path to integrity file, defaults to log_file + '.integrity'

    Returns:
        Boolean indicating if log file integrity is intact
    """
    import hashlib

    if integrity_file is None:
        integrity_file = f"{log_file}.integrity"

    try:
        if not os.path.exists(integrity_file):
            logger.warning(f"Integrity file not found for {log_file}")
            return False

        with open(log_file, 'rb') as f:
            log_contents = f.read()

        current_hash = hashlib.sha256(log_contents).hexdigest()

        with open(integrity_file, 'r') as f:
            last_entry = f.readlines()[-1]

        timestamp, stored_hash, filename = last_entry.strip().split(':')

        if current_hash != stored_hash:
            logger.warning(f"Log integrity check failed for {log_file}")
            return False

        logger.info(f"Log integrity verified for {log_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to validate log integrity: {str(e)}")
        return False


def archive_logs_securely(log_dir: str, archive_dir: str, sign: bool = True) -> None:
    """
    Archive logs with optional digital signature for non-repudiation.

    Args:
        log_dir: Directory containing logs to archive
        archive_dir: Directory to store archives
        sign: Whether to digitally sign the archive
    """
    import shutil
    import tarfile
    import datetime

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    archive_name = f"security_logs_{timestamp}.tar.gz"
    archive_path = os.path.join(archive_dir, archive_name)

    try:
        os.makedirs(archive_dir, mode=0o750, exist_ok=True)

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(log_dir, arcname=os.path.basename(log_dir))

        # Set secure permissions on the archive
        os.chmod(archive_path, 0o400)  # Read-only by owner

        if sign:
            # Implement digital signature using organization's PKI
            # This is a placeholder for the actual implementation
            _sign_archive(archive_path, f"{archive_path}.sig")

        logger.info(f"Archived logs to {archive_path}")
        return archive_path
    except Exception as e:
        logger.error(f"Failed to archive logs: {str(e)}")
        return None


def configure_siem_forwarding(
    logger: logging.Logger,
    siem_url: str,
    api_key: str,
    log_level: str = "INFO",
    batch_size: int = 10,
    ssl_verify: bool = True
) -> None:
    """
    Configure forwarding of security logs to a SIEM system.

    Args:
        logger: Logger to configure
        siem_url: URL of the SIEM endpoint
        api_key: Authentication key for SIEM
        log_level: Minimum log level to forward
        batch_size: Number of logs to batch before sending
        ssl_verify: Whether to verify SSL certificates
    """
    class SIEMHandler(logging.Handler):
        def __init__(self, url, api_key, batch_size, ssl_verify):
            super().__init__()
            self.url = url
            self.api_key = api_key
            self.batch_size = batch_size
            self.ssl_verify = ssl_verify
            self.log_queue = []

        def emit(self, record):
            import requests

            self.log_queue.append(self.format(record))

            if len(self.log_queue) >= self.batch_size:
                try:
                    headers = {
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {self.api_key}'
                    }
                    response = requests.post(
                        self.url,
                        json={'logs': self.log_queue},
                        headers=headers,
                        verify=self.ssl_verify
                    )
                    response.raise_for_status()
                    self.log_queue = []
                except Exception as e:
                    logger.error(f"Failed to forward logs to SIEM: {str(e)}")

    level = getattr(logging, log_level.upper(), DEFAULT_LOG_LEVEL)

    # Create and add the SIEM handler
    siem_handler = SIEMHandler(siem_url, api_key, batch_size, ssl_verify)
    siem_handler.setLevel(level)
    siem_handler.setFormatter(AssessmentJsonFormatter())
    logger.addHandler(siem_handler)

    logger.info("SIEM log forwarding configured")


def add_trusted_timestamp(logger: logging.Logger) -> None:
    """
    Add a filter that includes cryptographically verifiable timestamps from a trusted source.

    Args:
        logger: Logger to configure with trusted timestamps
    """
    class TrustedTimestampFilter(logging.Filter):
        def filter(self, record):
            # In a production implementation, this would use a trusted timestamp service
            # For now, we'll simulate with a local timestamp and a hash
            import hashlib
            import time

            timestamp = time.time()
            record.trusted_timestamp = timestamp

            # Create a verifiable hash that includes the timestamp and log message
            content = f"{timestamp}:{record.getMessage()}"
            record.timestamp_hash = hashlib.sha256(content.encode()).hexdigest()

            return True

    timestamp_filter = TrustedTimestampFilter()

    # Add to all handlers
    for handler in logger.handlers:
        handler.addFilter(timestamp_filter)


def configure_log_retention(
    log_dir: str,
    retention_days: int = 90,
    compliance_mode: bool = True
) -> None:
    """
    Configure automatic log retention based on policy.

    Args:
        log_dir: Directory containing logs
        retention_days: Number of days to retain logs
        compliance_mode: If True, logs are archived before deletion for compliance
    """
    import time
    import glob

    log_files = glob.glob(os.path.join(log_dir, "*.log"))
    current_time = time.time()
    retention_seconds = retention_days * 86400  # days to seconds

    for log_file in log_files:
        file_mtime = os.path.getmtime(log_file)
        if current_time - file_mtime > retention_seconds:
            try:
                if compliance_mode:
                    # Archive before deletion
                    archive_dir = os.path.join(log_dir, "archived")
                    archived = archive_logs_securely([log_file], archive_dir)

                    if archived:
                        logger.info(f"Archived expired log: {log_file}")
                        os.remove(log_file)
                else:
                    # Direct deletion
                    os.remove(log_file)

                logger.info(f"Removed expired log: {log_file}")
            except Exception as e:
                logger.error(f"Failed to process expired log {log_file}: {str(e)}")
