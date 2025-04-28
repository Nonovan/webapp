"""
Secure Logging Utilities for the Forensic Analysis Toolkit.

This module provides functions for logging forensic activities in a secure,
consistent, and potentially tamper-evident manner. It ensures that actions
taken during an investigation are properly recorded for audit trails and
chain of custody documentation.

It integrates with the core application logging where possible but can also
write to dedicated forensic log files.
"""

import logging
import json
import os
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Union

# Attempt to import core logging components
try:
    from core.loggings import get_security_logger, SecurityAwareJsonFormatter
    CORE_LOGGING_AVAILABLE = True
    # Use the core security logger for high-level forensic events
    core_security_logger = get_security_logger()
except ImportError:
    CORE_LOGGING_AVAILABLE = False
    core_security_logger = None
    SecurityAwareJsonFormatter = logging.Formatter # Fallback

# Attempt to import forensic constants
try:
    from admin.security.forensics.utils.forensic_constants import (
        FORENSIC_LOG_OPERATION_PREFIX,
        DEFAULT_TIMESTAMP_FORMAT,
        DEFAULT_TIMEZONE
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values for logging.")
    FORENSIC_LOG_OPERATION_PREFIX_FALLBACK = "ForensicOperation"
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = "iso8601"
    DEFAULT_TIMEZONE_FALLBACK = "UTC" # Should ideally align with core system timezone

# --- Forensic Logger Setup ---

# Define a dedicated logger for detailed forensic operations
forensic_logger = logging.getLogger('forensic_operations')
forensic_logger.setLevel(logging.INFO) # Log INFO and above by default
forensic_logger.propagate = False # Prevent duplication if core logger is also used

# Configuration for the dedicated forensic log file
# In a real application, this path should be configurable and secured
FORENSIC_LOG_DIR = os.environ.get("FORENSIC_LOG_DIR", "/var/log/forensics")
FORENSIC_LOG_FILE = os.path.join(FORENSIC_LOG_DIR, "forensic_operations.log")
MAX_LOG_SIZE = 10 * 1024 * 1024 # 10 MB
BACKUP_COUNT = 5

# Ensure the forensic log directory exists with secure permissions
try:
    if not os.path.exists(FORENSIC_LOG_DIR):
        os.makedirs(FORENSIC_LOG_DIR, mode=0o700, exist_ok=True)
    else:
        # Ensure directory permissions are secure if it already exists
        os.chmod(FORENSIC_LOG_DIR, 0o700)

    # Create a rotating file handler for the forensic log
    forensic_handler = logging.handlers.RotatingFileHandler(
        FORENSIC_LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    # Set secure permissions on the log file itself
    forensic_handler.doRollover() # Ensure file exists for chmod
    os.chmod(FORENSIC_LOG_FILE, 0o600)

    # Use a JSON formatter for structured, machine-readable logs
    # Inherit from SecurityAwareJsonFormatter if available for consistency
    log_format = {
        'timestamp': '%(asctime)s',
        'level': '%(levelname)s',
        'logger': '%(name)s',
        'operation': '%(operation)s',
        'success': '%(success)s',
        'details': '%(details)s',
        'message': '%(message)s' # Include standard message field
    }
    formatter = SecurityAwareJsonFormatter(json.dumps(log_format))
    forensic_handler.setFormatter(formatter)

    # Add the handler to the forensic logger
    if not forensic_logger.handlers:
        forensic_logger.addHandler(forensic_handler)

except (OSError, PermissionError, ImportError) as e:
    logging.error(f"Failed to configure dedicated forensic file logging: {e}. Forensic logs might only go to standard output/core logger.")
    # Fallback: Log to console if file handler fails
    if not forensic_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(name)s: %(message)s'
        ))
        forensic_logger.addHandler(console_handler)

# --- Logging Function ---

def log_forensic_operation(
    operation: str,
    success: bool,
    details: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
    user_id: Optional[Union[int, str]] = None, # Optional user context
    case_id: Optional[str] = None # Optional case context
) -> None:
    """
    Logs a forensic operation event.

    Records the event to the dedicated forensic logger and potentially the
    core security logger. Includes structured details about the operation.

    Args:
        operation: Name of the forensic operation (e.g., "hash_calculation", "secure_copy").
        success: Boolean indicating if the operation was successful.
        details: Optional dictionary containing specific details about the operation
                 (e.g., file paths, hashes, parameters used).
        level: Logging level (e.g., logging.INFO, logging.WARNING, logging.ERROR).
               Defaults to INFO. ERROR is recommended for failures.
        user_id: Optional identifier for the user performing the action.
        case_id: Optional identifier for the forensic case associated with the operation.
    """
    if not isinstance(level, int):
        level = logging.INFO # Default to INFO if invalid level provided

    log_level_name = logging.getLevelName(level)
    timestamp = datetime.now(timezone.utc)

    # Prepare structured data for the forensic logger
    log_record_extra = {
        'operation': operation,
        'success': success,
        'details': details or {},
    }
    # Add context if available
    if user_id:
        log_record_extra['details']['user_id'] = user_id
    if case_id:
        log_record_extra['details']['case_id'] = case_id

    # Format the main message
    message = f"{FORENSIC_LOG_OPERATION_PREFIX or FORENSIC_LOG_OPERATION_PREFIX_FALLBACK}: {operation}, Status: {'Success' if success else 'Failure'}"
    if details:
        # Add a summary of details to the message for quick readability
        summary = {k: v for k, v in details.items() if isinstance(v, (str, int, float, bool))}
        if summary:
             message += f", Summary: {json.dumps(summary)}"


    # Log to the dedicated forensic logger using extra context
    try:
        forensic_logger.log(level, message, extra=log_record_extra)
    except Exception as e:
        # Fallback to standard logger if forensic logger fails unexpectedly
        logging.error(f"Failed to write to forensic logger: {e}. Falling back.")
        fallback_message = f"[FORENSIC FALLBACK] {message} | Full Details: {json.dumps(log_record_extra)}"
        logging.log(level, fallback_message)


    # Optionally, log significant events (especially failures) to the core security logger
    if CORE_LOGGING_AVAILABLE and core_security_logger and (not success or level >= logging.WARNING):
        try:
            core_event_type = f"forensic.{operation.replace(' ', '_').lower()}"
            core_severity = 'error' if not success else ('warning' if level == logging.WARNING else 'info')

            # Prepare details for core logger (might have different structure needs)
            core_details = {
                "forensic_operation": operation,
                "success": success,
                **(details or {})
            }
            if case_id:
                core_details['case_id'] = case_id

            core_security_logger.log(
                level, # Use the same level
                message, # Use the formatted message
                extra={
                    'event_type': core_event_type,
                    'severity': core_severity,
                    'user_id': user_id,
                    'details': core_details,
                    'security_event': True, # Mark as a security-relevant event
                    'forensic_event': True # Add specific forensic flag
                }
            )
        except Exception as e:
            logging.error(f"Failed to log forensic event to core security logger: {e}")


# --- Example Usage ---

if __name__ == "__main__":
    print("Testing Forensic Logging Utility...")
    print(f"Forensic log file configured at: {FORENSIC_LOG_FILE}")

    # Ensure console output for testing if file logging failed
    if not forensic_logger.handlers or isinstance(forensic_logger.handlers[0], logging.StreamHandler):
         if not any(isinstance(h, logging.StreamHandler) for h in forensic_logger.handlers):
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(name)s: %(message)s | %(details)s'))
            forensic_logger.addHandler(ch)
            forensic_logger.setLevel(logging.DEBUG) # Show all levels for testing
            print("Added console handler for testing.")


    # Example 1: Successful operation
    log_forensic_operation(
        operation="calculate_hash",
        success=True,
        details={"file": "/path/to/evidence.dd", "algorithm": "sha256", "hash": "a1b2c3d4..."},
        user_id="analyst1",
        case_id="CASE-001"
    )

    # Example 2: Failed operation
    log_forensic_operation(
        operation="secure_copy",
        success=False,
        details={"source": "/mnt/evidence/img.e01", "destination": "/case_files/img.e01", "error": "Disk full"},
        level=logging.ERROR, # Use ERROR level for failures
        user_id="analyst2",
        case_id="CASE-002"
    )

    # Example 3: Operation with minimal details
    log_forensic_operation(
        operation="verify_timestamp",
        success=True,
        details={"source": "system_log", "timestamp": "2023-10-27T10:30:00Z"},
        level=logging.INFO,
        case_id="CASE-001"
    )

    # Example 4: Warning level
    log_forensic_operation(
        operation="extract_metadata",
        success=True, # Operation succeeded, but with a caveat
        details={"file": "suspicious.pdf", "warning": "Metadata partially corrupted"},
        level=logging.WARNING,
        user_id="analyst1",
        case_id="CASE-003"
    )

    print("Forensic logging tests complete. Check log file and console output.")
