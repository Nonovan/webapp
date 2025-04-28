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
import logging.handlers
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Union, List, Tuple

# Attempt to import core logging components
try:
    from core.loggings import get_security_logger, SecurityAwareJsonFormatter
    CORE_LOGGING_AVAILABLE = True
    # Use the core security logger for high-level forensic events
    core_security_logger = get_security_logger()
except ImportError:
    CORE_LOGGING_AVAILABLE = False
    core_security_logger = None
    # Fallback formatter if core's SecurityAwareJsonFormatter isn't available
    class SecurityAwareJsonFormatter(logging.Formatter):
        """Basic JSON formatter for log records with security awareness."""
        def __init__(self, fmt=None, datefmt=None):
            super().__init__(fmt, datefmt)
            self.fmt_dict = json.loads(fmt) if fmt else {}

        def formatException(self, ei):
            """Format exception with traceback."""
            result = super().formatException(ei)
            return result

        def format(self, record):
            """Format log record as JSON."""
            log_data = {}

            # Add all items from the format dictionary
            for key, val in self.fmt_dict.items():
                if val.startswith('%(') and val.endswith(')s'):
                    attr_name = val[2:-2]
                    if hasattr(record, attr_name):
                        log_data[key] = getattr(record, attr_name)
                else:
                    log_data[key] = val

            # Add standard record attributes
            if 'timestamp' not in log_data:
                log_data['timestamp'] = self.formatTime(record)
            if 'level' not in log_data:
                log_data['level'] = record.levelname
            if 'logger' not in log_data:
                log_data['logger'] = record.name
            if 'message' not in log_data:
                log_data['message'] = record.getMessage()

            # Add exception info if present
            if record.exc_info:
                log_data['exception'] = self.formatException(record.exc_info)

            return json.dumps(log_data, default=str)

# Attempt to import forensic constants
try:
    from admin.security.forensics.utils.forensic_constants import (
        FORENSIC_LOG_OPERATION_PREFIX,
        DEFAULT_TIMESTAMP_FORMAT,
        DEFAULT_TIMEZONE,
        FORENSIC_LOG_DIR,
        FORENSIC_SECURE_LOG_DIR,
        FORENSIC_LOG_FILE,
        MAX_LOG_SIZE,
        LOG_BACKUP_COUNT
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    logging.warning("Forensic constants not found. Using default values for logging.")
    FORENSIC_LOG_OPERATION_PREFIX_FALLBACK = "ForensicOperation"
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = "iso8601"
    DEFAULT_TIMEZONE_FALLBACK = "UTC"  # Should ideally align with core system timezone

    # Define fallback constants for logging configuration
    FORENSIC_LOG_DIR = os.environ.get("FORENSIC_LOG_DIR", "/var/log/forensics")
    FORENSIC_SECURE_LOG_DIR_FALLBACK = os.environ.get("FORENSIC_SECURE_LOG_DIR", "/secure/forensics/logs")
    FORENSIC_LOG_FILE_FALLBACK = "forensic_operations.log"
    MAX_LOG_SIZE_FALLBACK = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT_FALLBACK = 10

# Set up the module-level logger
logger = logging.getLogger(__name__)

# --- Forensic Logger Setup ---

# Define a dedicated logger for detailed forensic operations
forensic_logger = logging.getLogger('forensic_operations')
forensic_logger.setLevel(logging.INFO)  # Log INFO and above by default
forensic_logger.propagate = False  # Prevent duplication if core logger is also used

# Use the appropriate log directory based on availability
log_dir = FORENSIC_SECURE_LOG_DIR if os.path.exists(FORENSIC_SECURE_LOG_DIR) else FORENSIC_LOG_DIR
log_file_path = os.path.join(log_dir, FORENSIC_LOG_FILE)

# Ensure the forensic log directory exists with secure permissions
try:
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
    else:
        # Ensure directory permissions are secure if it already exists
        os.chmod(log_dir, 0o700)

    # Create a rotating file handler for the forensic log
    forensic_handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=MAX_LOG_SIZE,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )

    # Ensure the log file exists before chmod
    if not os.path.exists(log_file_path):
        with open(log_file_path, 'a'):
            pass

    # Set secure permissions on the log file itself
    os.chmod(log_file_path, 0o600)

    # Use a JSON formatter for structured, machine-readable logs
    log_format = {
        'timestamp': '%(asctime)s',
        'level': '%(levelname)s',
        'logger': '%(name)s',
        'operation': '%(operation)s',
        'success': '%(success)s',
        'details': '%(details)s',
        'message': '%(message)s',  # Include standard message field
        'hostname': socket.gethostname(),
        'process_id': '%(process)d'
    }
    formatter = SecurityAwareJsonFormatter(json.dumps(log_format))
    forensic_handler.setFormatter(formatter)

    # Add the handler to the forensic logger
    if not forensic_logger.handlers:
        forensic_logger.addHandler(forensic_handler)

    logger.info(f"Forensic logger configured with log file: {log_file_path}")

except (OSError, PermissionError) as e:
    logger.error(f"Failed to configure dedicated forensic file logging: {e}. "
                f"Forensic logs might only go to standard output/core logger.")
    # Fallback: Log to console if file handler fails
    if not forensic_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(name)s: %(message)s'
        ))
        forensic_logger.addHandler(console_handler)


# --- Logging Functions ---

def log_forensic_operation(
    operation: str,
    success: bool,
    details: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
    user_id: Optional[Union[int, str]] = None,  # Optional user context
    case_id: Optional[str] = None  # Optional case context
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
        level = logging.INFO  # Default to INFO if invalid level provided

    log_level_name = logging.getLevelName(level)
    timestamp = datetime.now(timezone.utc)

    # Create a safe copy of details to avoid modifying the input
    details_copy = {} if details is None else details.copy()

    # Prepare structured data for the forensic logger
    log_record_extra = {
        'operation': operation,
        'success': success,
        'details': details_copy,
        'forensic_timestamp': timestamp.isoformat(),
    }

    # Add context if available
    if user_id:
        log_record_extra['details']['user_id'] = user_id
    if case_id:
        log_record_extra['details']['case_id'] = case_id

    # Add system information for traceability
    log_record_extra['details']['system_info'] = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python_version': platform.python_version()
    }

    # Format the main message
    prefix = FORENSIC_LOG_OPERATION_PREFIX if CONSTANTS_AVAILABLE else FORENSIC_LOG_OPERATION_PREFIX_FALLBACK
    message = f"{prefix}: {operation}, Status: {'Success' if success else 'Failure'}"

    # Add a summary of details to the message for quick readability
    if details:
        # Extract a limited set of fields for the summary to avoid excessive logs
        summary_fields = ['file', 'path', 'hash', 'source', 'destination', 'error', 'warning']
        summary = {k: v for k, v in details.items() if k in summary_fields and
                   isinstance(v, (str, int, float, bool))}
        if summary:
            message += f", Summary: {json.dumps(summary)}"

    # Log to the dedicated forensic logger using extra context
    try:
        forensic_logger.log(level, message, extra=log_record_extra)
    except Exception as e:
        # Fallback to standard logger if forensic logger fails unexpectedly
        logger.error(f"Failed to write to forensic logger: {e}. Falling back.")
        fallback_message = f"[FORENSIC FALLBACK] {message} | Full Details: {json.dumps(log_record_extra)}"
        logging.log(level, fallback_message)

    # Optionally, log significant events (especially failures) to the core security logger
    if CORE_LOGGING_AVAILABLE and core_security_logger and (not success or level >= logging.WARNING):
        try:
            # Convert operation name to a valid event type format
            core_event_type = f"forensic.{operation.replace(' ', '_').lower()}"

            # Map logging levels to severity for security events
            core_severity = 'info'
            if level >= logging.CRITICAL:
                core_severity = 'critical'
            elif level >= logging.ERROR:
                core_severity = 'error'
            elif level >= logging.WARNING:
                core_severity = 'warning'

            # Prepare details for core logger (might have different structure needs)
            core_details = {
                "forensic_operation": operation,
                "success": success,
                **(details or {})
            }
            if case_id:
                core_details['case_id'] = case_id

            core_security_logger.log(
                level,  # Use the same level
                message,  # Use the formatted message
                extra={
                    'event_type': core_event_type,
                    'severity': core_severity,
                    'user_id': user_id,
                    'details': core_details,
                    'security_event': True,  # Mark as a security-relevant event
                    'forensic_event': True  # Add specific forensic flag
                }
            )
        except Exception as e:
            logger.error(f"Failed to log forensic event to core security logger: {e}")


def get_forensic_logs(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    operation_type: Optional[str] = None,
    success_only: Optional[bool] = None,
    case_id: Optional[str] = None,
    user_id: Optional[Union[int, str]] = None,
    limit: int = 100,
    level: int = logging.INFO
) -> List[Dict[str, Any]]:
    """
    Retrieves forensic logs matching specified criteria.

    This is a helper function that reads the forensic log file and parses JSON entries
    to retrieve logs within the specified timeframe and matching the given criteria.

    Args:
        start_time: Optional start time for log filtering
        end_time: Optional end time for log filtering
        operation_type: Optional operation type to filter by
        success_only: If True, only return successful operations
        case_id: Optional case ID to filter by
        user_id: Optional user ID to filter by
        limit: Maximum number of log entries to return
        level: Minimum log level to include

    Returns:
        List of matching log entries as dictionaries
    """
    logs = []

    # Check if log file exists
    if not os.path.exists(log_file_path):
        logger.warning(f"Forensic log file not found: {log_file_path}")
        return logs

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    # Parse JSON log entry
                    log_entry = json.loads(line.strip())

                    # Apply filters
                    if level > _level_name_to_number(log_entry.get('level', 'INFO')):
                        continue

                    details = log_entry.get('details', {})

                    # Filter by timestamps if specified
                    timestamp = None
                    if 'timestamp' in log_entry:
                        timestamp = _parse_timestamp(log_entry['timestamp'])
                    elif 'forensic_timestamp' in details:
                        timestamp = _parse_timestamp(details['forensic_timestamp'])

                    if timestamp:
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue

                    # Filter by operation
                    if operation_type and log_entry.get('operation') != operation_type:
                        continue

                    # Filter by success
                    if success_only is not None and log_entry.get('success', False) != success_only:
                        continue

                    # Filter by case_id
                    if case_id and details.get('case_id') != case_id:
                        continue

                    # Filter by user_id
                    if user_id and details.get('user_id') != user_id:
                        continue

                    logs.append(log_entry)

                    # Apply limit
                    if len(logs) >= limit:
                        break

                except (json.JSONDecodeError, ValueError) as e:
                    logger.debug(f"Skipping invalid log entry: {e}")
                    continue

        return logs
    except Exception as e:
        logger.error(f"Error reading forensic logs: {e}")
        return []


def export_forensic_logs(
    output_path: str,
    format_type: str = 'json',
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    operation_type: Optional[str] = None,
    case_id: Optional[str] = None,
    user_id: Optional[Union[int, str]] = None,
    limit: int = 1000
) -> bool:
    """
    Exports forensic logs to a file in the specified format.

    Args:
        output_path: Path where the export file should be written
        format_type: Export format ('json', 'csv', or 'text')
        start_time: Optional start time for log filtering
        end_time: Optional end time for log filtering
        operation_type: Optional operation type to filter by
        case_id: Optional case ID to filter by
        user_id: Optional user ID to filter by
        limit: Maximum number of log entries to export

    Returns:
        True if export was successful, False otherwise
    """
    # Validate format type
    if format_type.lower() not in ('json', 'csv', 'text'):
        logger.error(f"Invalid export format: {format_type}")
        return False

    # Get logs matching criteria
    logs = get_forensic_logs(
        start_time=start_time,
        end_time=end_time,
        operation_type=operation_type,
        case_id=case_id,
        user_id=user_id,
        limit=limit
    )

    if not logs:
        logger.warning("No logs found matching the specified criteria")
        return False

    # Create parent directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, mode=0o700)
        except OSError as e:
            logger.error(f"Failed to create output directory: {e}")
            return False

    try:
        # Export in the specified format
        if format_type.lower() == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, default=str)

        elif format_type.lower() == 'csv':
            import csv

            # Get unique field names from all logs
            fieldnames = set(['timestamp', 'level', 'operation', 'success', 'message'])
            for log in logs:
                # Add main fields
                fieldnames.update(log.keys())
                # Add important fields from details if present
                if 'details' in log and isinstance(log['details'], dict):
                    details = log['details']
                    fieldnames.update([f"details_{k}" for k in details.keys()
                                      if not isinstance(details[k], dict)])

            # Write CSV file
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                writer.writeheader()

                for log in logs:
                    row = log.copy()
                    # Flatten details dict into prefixed fields
                    if 'details' in row and isinstance(row['details'], dict):
                        details = row.pop('details')
                        for k, v in details.items():
                            if not isinstance(v, dict):  # Skip nested objects
                                row[f"details_{k}"] = v
                    writer.writerow(row)

        elif format_type.lower() == 'text':
            with open(output_path, 'w', encoding='utf-8') as f:
                for log in logs:
                    timestamp = log.get('timestamp', '')
                    level = log.get('level', 'INFO')
                    operation = log.get('operation', '')
                    success = 'SUCCESS' if log.get('success', False) else 'FAILURE'
                    message = log.get('message', '')

                    f.write(f"[{timestamp}] [{level}] {operation} - {success}: {message}\n")

                    # Add details section if present
                    if 'details' in log and isinstance(log['details'], dict):
                        details = log['details']
                        f.write("  Details:\n")
                        for k, v in details.items():
                            if isinstance(v, dict):
                                f.write(f"    {k}:\n")
                                for sk, sv in v.items():
                                    f.write(f"      {sk}: {sv}\n")
                            else:
                                f.write(f"    {k}: {v}\n")
                        f.write("\n")

        # Set secure permissions on the output file
        os.chmod(output_path, 0o600)

        # Log this export operation
        export_details = {
            'output_path': output_path,
            'format': format_type,
            'log_count': len(logs),
        }
        if start_time:
            export_details['start_time'] = start_time.isoformat()
        if end_time:
            export_details['end_time'] = end_time.isoformat()
        if operation_type:
            export_details['operation_type'] = operation_type
        if case_id:
            export_details['case_id'] = case_id
        if user_id:
            export_details['user_id'] = user_id

        log_forensic_operation(
            operation="export_logs",
            success=True,
            details=export_details
        )

        return True

    except Exception as e:
        logger.error(f"Failed to export forensic logs: {e}")
        # Log failure
        log_forensic_operation(
            operation="export_logs",
            success=False,
            details={
                'output_path': output_path,
                'format': format_type,
                'error': str(e)
            },
            level=logging.ERROR
        )
        return False


def verify_log_integrity() -> Dict[str, Any]:
    """
    Verifies the integrity of the forensic log file.

    Checks for evidence of tampering such as:
    - Out-of-order timestamps
    - Missing sequence entries
    - Abnormal gaps in timestamps
    - Invalid JSON entries

    Returns:
        Dictionary with verification results
    """
    results = {
        'verified': False,
        'issues_found': [],
        'total_entries': 0,
        'invalid_entries': 0,
        'start_time': None,
        'end_time': None
    }

    if not os.path.exists(log_file_path):
        results['issues_found'].append(f"Log file not found: {log_file_path}")
        return results

    try:
        last_timestamp = None
        entry_count = 0
        invalid_count = 0
        timestamps = []

        # First pass: Verify validity and collect timestamps
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                try:
                    entry = json.loads(line.strip())
                    entry_count += 1

                    # Get timestamp
                    if 'timestamp' in entry:
                        timestamp = _parse_timestamp(entry['timestamp'])
                    elif 'details' in entry and isinstance(entry['details'], dict) and 'forensic_timestamp' in entry['details']:
                        timestamp = _parse_timestamp(entry['details']['forensic_timestamp'])
                    else:
                        results['issues_found'].append(f"Missing timestamp at line {line_num}")
                        continue

                    if timestamp:
                        timestamps.append(timestamp)

                        # Check for out-of-order timestamps
                        if last_timestamp and timestamp < last_timestamp:
                            results['issues_found'].append(
                                f"Out-of-order timestamp at line {line_num}: "
                                f"{timestamp.isoformat()} < {last_timestamp.isoformat()}"
                            )

                        last_timestamp = timestamp

                except json.JSONDecodeError as e:
                    invalid_count += 1
                    results['issues_found'].append(f"Invalid JSON at line {line_num}: {e}")

        # Update results
        results['total_entries'] = entry_count
        results['invalid_entries'] = invalid_count

        if timestamps:
            results['start_time'] = min(timestamps)
            results['end_time'] = max(timestamps)

            # Check for unusual gaps in timestamps (if at least 10 entries)
            if len(timestamps) >= 10:
                # Sort timestamps and calculate time differences
                sorted_timestamps = sorted(timestamps)
                diffs = [(sorted_timestamps[i+1] - sorted_timestamps[i]).total_seconds()
                        for i in range(len(sorted_timestamps)-1)]

                # Calculate median and upper quartile of time differences
                median_gap = sorted(diffs)[len(diffs)//2]
                upper_quartile = sorted(diffs)[int(len(diffs)*0.75)]

                # Flag unusually large gaps (5x upper quartile)
                threshold = max(upper_quartile * 5, 3600)  # At least 1 hour

                for i, diff in enumerate(diffs):
                    if diff > threshold:
                        results['issues_found'].append(
                            f"Unusual time gap of {diff:.1f} seconds between "
                            f"{sorted_timestamps[i].isoformat()} and {sorted_timestamps[i+1].isoformat()}"
                        )

        # Set verification result
        results['verified'] = invalid_count == 0 and len(results['issues_found']) == 0

        # Log the verification operation
        log_forensic_operation(
            operation="verify_log_integrity",
            success=results['verified'],
            details={
                'log_path': log_file_path,
                'total_entries': entry_count,
                'invalid_entries': invalid_count,
                'issues_count': len(results['issues_found']),
                'issues_sample': results['issues_found'][:5] if results['issues_found'] else []
            }
        )

        return results

    except Exception as e:
        logger.error(f"Error verifying log integrity: {e}")
        results['issues_found'].append(f"Verification error: {e}")

        # Log the verification failure
        log_forensic_operation(
            operation="verify_log_integrity",
            success=False,
            details={
                'log_path': log_file_path,
                'error': str(e)
            },
            level=logging.ERROR
        )

        return results


# --- Helper Functions ---

def _parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse a timestamp string to datetime object.

    Uses multiple parsing strategies with fallbacks to handle various timestamp formats.

    Args:
        timestamp_str: The timestamp string to parse

    Returns:
        Parsed datetime object or None if parsing fails
    """
    if not timestamp_str:
        return None

    # First try: Direct datetime.fromisoformat() for ISO 8601 compliance
    try:
        # Handle ISO format timestamps with 'Z' (replace with +00:00)
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'

        # Try ISO format parsing (Python 3.7+)
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError):
        pass  # Continue to next strategy if this fails

    # Second try: Use timestamp_utils if available (preferred internal implementation)
    try:
        from admin.security.forensics.utils.timestamp_utils import normalize_timestamp
        return normalize_timestamp(timestamp_str)
    except ImportError:
        pass  # Continue to next strategy if module not available

    # Third try: Use format_converter if available
    try:
        from admin.security.forensics.utils.format_converter import parse_datetime_string
        return parse_datetime_string(timestamp_str)
    except ImportError:
        pass  # Continue to next strategy if module not available

    # Fourth try: Try dateutil.parser as a last resort
    try:
        # Only import if needed (not in global imports)
        import dateutil.parser
        return dateutil.parser.parse(timestamp_str)
    except (ImportError, ValueError, TypeError, AttributeError):
        # ImportError: Package not installed
        # ValueError/TypeError: Invalid format
        # AttributeError: Unexpected module structure
        logger.debug(f"Failed to parse timestamp: {timestamp_str}")
        return None


def _level_name_to_number(level_name: str) -> int:
    """Convert a logging level name to its numeric value."""
    level_map = {
        'CRITICAL': logging.CRITICAL,
        'FATAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'WARN': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG,
        'NOTSET': logging.NOTSET
    }

    return level_map.get(level_name.upper(), logging.INFO)


# --- Example Usage ---

if __name__ == "__main__":
    print("Testing Forensic Logging Utility...")
    print(f"Forensic log file configured at: {log_file_path}")

    # Ensure console output for testing
    if not any(isinstance(h, logging.StreamHandler) for h in forensic_logger.handlers):
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(name)s: %(message)s | %(details)s'))
        forensic_logger.addHandler(ch)
        forensic_logger.setLevel(logging.DEBUG)  # Show all levels for testing
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
        level=logging.ERROR,  # Use ERROR level for failures
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
        success=True,  # Operation succeeded, but with a caveat
        details={"file": "suspicious.pdf", "warning": "Metadata partially corrupted"},
        level=logging.WARNING,
        user_id="analyst1",
        case_id="CASE-003"
    )

    # Example 5: Retrieve and export logs
    print("\nTesting log retrieval and export...")
    logs = get_forensic_logs(limit=10)
    print(f"Retrieved {len(logs)} log entries")

    if logs:
        # Example export to text file
        test_export_path = os.path.join(os.getcwd(), "forensic_logs_test_export.txt")
        export_result = export_forensic_logs(test_export_path, format_type='text', limit=10)
        print(f"Log export result: {'Success' if export_result else 'Failed'}")

        # Example log integrity verification
        integrity_result = verify_log_integrity()
        print(f"Log integrity verification: {'Passed' if integrity_result['verified'] else 'Failed'}")
        if not integrity_result['verified']:
            print(f"Issues found: {len(integrity_result['issues_found'])}")
            for issue in integrity_result['issues_found'][:3]:  # Show first 3 issues
                print(f"  - {issue}")

    print("\nForensic logging tests complete. Check log file and console output.")
