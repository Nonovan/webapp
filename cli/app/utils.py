"""
CLI application utility functions.

This module provides utility functions specifically for the CLI application,
complementing the more general utilities in cli.common. These utilities are
focused on application-specific operations that may be needed across multiple
command groups.

Functions in this module handle operations such as:
- Output formatting specific to CLI application commands
- Progress reporting tailored to CLI operations
- CLI-specific configuration and environment management
- Database operation helpers for CLI commands
- Security utility wrappers for CLI context

Security note: All functions that handle file paths or execute system commands
implement proper security controls for path validation and command injection
prevention.
"""

import logging
import os
import sys
import json
import hashlib
import datetime
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Callable, IO, TextIO

import click
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from core.utils import (
    get_logger,
    format_datetime,
    deep_get,
    sanitize_path,
    is_within_directory,
    is_safe_file_operation,
    safe_json_serialize
)
from core.security import (
    check_file_integrity,
    calculate_file_hash,
    audit_log
)
from extensions import db, metrics
from cli.common import (
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_RESOURCE_ERROR,
    handle_error,
    protect_sensitive_data
)

# Initialize logger
logger = get_logger(__name__)

# Constants
DEFAULT_OUTPUT_DIR = "./output"
TEMP_DIR = "./tmp"
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30  # seconds
SENSITIVE_FIELDS = ['password', 'token', 'secret', 'key', 'credential']

# Ensure necessary directories exist
os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)


def get_app_version() -> str:
    """
    Get current application version.

    Returns:
        str: Current application version string
    """
    if current_app:
        return current_app.config.get('VERSION', '0.1.0')
    return '0.1.0'


def get_env_info() -> Dict[str, str]:
    """
    Get environment information for diagnostics.

    Returns:
        Dict[str, str]: Dictionary with environment information
    """
    info = {
        'app_version': get_app_version(),
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'environment': get_environment(),
        'timestamp': format_datetime(datetime.datetime.now())
    }

    # Add Flask app info if available
    if current_app:
        info['flask_env'] = current_app.env
        info['debug_mode'] = str(current_app.debug)

    return info


def get_environment() -> str:
    """
    Get current application environment.

    Returns:
        str: Current environment (development, testing, staging, production)
    """
    if current_app:
        return current_app.config.get('ENV', 'development')
    return os.environ.get('FLASK_ENV', 'development')


def format_table(data: List[Dict[str, Any]],
                columns: Optional[List[str]] = None,
                show_header: bool = True) -> str:
    """
    Format data as an ASCII table for terminal display.

    Args:
        data: List of dictionaries to display
        columns: List of columns to include (default: all keys in first item)
        show_header: Whether to show column headers

    Returns:
        str: Formatted ASCII table
    """
    if not data:
        return "No data to display"

    # Determine columns to show
    if not columns and data:
        columns = list(data[0].keys())

    if not columns:
        return "No columns specified"

    # Calculate column widths
    widths = {col: len(str(col)) for col in columns}
    for row in data:
        for col in columns:
            if col in row:
                widths[col] = max(widths[col], len(str(row.get(col, ''))))

    # Build the table
    result = []

    # Add header
    if show_header:
        header = " | ".join(str(col).ljust(widths[col]) for col in columns)
        result.append(header)
        result.append("-" * len(header))

    # Add rows
    for row in data:
        line = " | ".join(str(row.get(col, '')).ljust(widths[col]) for col in columns)
        result.append(line)

    return "\n".join(result)


def save_output(data: Any,
               filename: str,
               directory: str = DEFAULT_OUTPUT_DIR,
               format_type: str = 'json') -> Tuple[bool, str]:
    """
    Save command output to a file with proper path validation.

    Args:
        data: Data to save
        filename: Output filename
        directory: Output directory
        format_type: Format to save (json, csv, text)

    Returns:
        Tuple[bool, str]: (success, message)
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)

        # Sanitize and validate file path
        safe_filename = Path(filename).name  # Extract filename component only
        output_path = os.path.join(directory, safe_filename)

        # Validate the path is within allowed directory
        abs_output_path = os.path.abspath(output_path)
        abs_directory = os.path.abspath(directory)

        if not is_within_directory(abs_output_path, [abs_directory]):
            return False, f"Invalid output path: {output_path}"

        # Write the file in the appropriate format
        if format_type == 'json':
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=safe_json_serialize)
        elif format_type == 'csv':
            if not data or not isinstance(data, list):
                return False, "CSV export requires list data"

            import csv
            with open(output_path, 'w', newline='') as f:
                if isinstance(data[0], dict):
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
                else:
                    writer = csv.writer(f)
                    writer.writerows(data)
        else:  # text
            with open(output_path, 'w') as f:
                if isinstance(data, (list, tuple)):
                    f.write('\n'.join(str(item) for item in data))
                else:
                    f.write(str(data))

        # Log for audit purposes, but mask any sensitive data
        safe_data = data
        if isinstance(data, dict):
            safe_data = protect_sensitive_data(json.dumps(data), SENSITIVE_FIELDS)

        try:
            audit_log(
                'cli',
                'file_export',
                details={
                    'filename': safe_filename,
                    'format': format_type,
                    'size_bytes': os.path.getsize(output_path)
                }
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        return True, f"Output saved to {output_path}"

    except Exception as e:
        logger.error(f"Error saving output: {e}", exc_info=True)
        return False, f"Error saving output: {str(e)}"


def execute_db_operation(operation_func: Callable,
                        operation_name: str,
                        retry_count: int = MAX_RETRIES) -> Tuple[bool, Any]:
    """
    Execute a database operation with proper transaction handling and retry logic.

    Args:
        operation_func: Function to execute the database operation
        operation_name: Name of the operation for logging
        retry_count: Number of retry attempts for transient errors

    Returns:
        Tuple[bool, Any]: (success, result or error message)
    """
    attempts = 0

    while attempts < retry_count:
        attempts += 1
        try:
            # Execute the operation
            with db.session.begin():
                result = operation_func()

            # Track the successful operation
            metrics.increment(f'cli.db.{operation_name}.success')

            return True, result

        except SQLAlchemyError as e:
            db.session.rollback()

            # Check if this is a retryable error
            if attempts < retry_count and is_retryable_error(e):
                logger.warning(f"Retrying {operation_name} after error: {e}")
                continue

            logger.error(f"Database error in {operation_name}: {e}")
            metrics.increment(f'cli.db.{operation_name}.error')
            return False, f"Database error: {str(e)}"

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in {operation_name}: {e}", exc_info=True)
            metrics.increment(f'cli.db.{operation_name}.error')
            return False, f"Operation failed: {str(e)}"

    return False, f"Operation failed after {retry_count} attempts"


def is_retryable_error(error: Exception) -> bool:
    """
    Check if a database error is retryable.

    Args:
        error: The exception to check

    Returns:
        bool: True if the error is retryable
    """
    # Common retryable error messages for PostgreSQL
    retryable_messages = [
        "deadlock detected",
        "could not serialize access",
        "connection timed out",
        "connection reset",
        "connection refused"
    ]

    error_str = str(error).lower()
    return any(msg in error_str for msg in retryable_messages)


def verify_environment_integrity() -> Tuple[bool, List[str]]:
    """
    Verify the integrity of the CLI application environment.

    Checks include:
    - Critical file integrity
    - Directory permissions
    - Environment variables
    - Database connectivity

    Returns:
        Tuple[bool, List[str]]: (is_valid, list of issues)
    """
    issues = []

    # Check file integrity
    try:
        integrity_result = check_file_integrity()
        if not integrity_result[0]:
            issues.append(f"File integrity check failed: {integrity_result[1]}")
    except Exception as e:
        issues.append(f"Error checking file integrity: {str(e)}")

    # Check directory permissions
    critical_dirs = ["./instance", "./logs", "./uploads"]
    for directory in critical_dirs:
        if os.path.exists(directory):
            try:
                # Check directory is not world-writable
                stats = os.stat(directory)
                if stats.st_mode & 0o002:  # Check if world-writable
                    issues.append(f"Directory has unsafe permissions: {directory}")
            except Exception as e:
                issues.append(f"Error checking permissions for {directory}: {str(e)}")

    # Check database connectivity if we have an app context
    if current_app:
        try:
            db.session.execute('SELECT 1')
        except Exception as e:
            issues.append(f"Database connectivity issue: {str(e)}")

    # Return True only if no issues were found
    return len(issues) == 0, issues


def generate_report(data: Dict[str, Any],
                   report_type: str = 'status',
                   output_format: str = 'text') -> str:
    """
    Generate a formatted report from the provided data.

    Args:
        data: The data to include in the report
        report_type: Type of report ('status', 'diagnostic', 'summary')
        output_format: Output format ('text', 'json', 'html')

    Returns:
        str: Formatted report
    """
    # Add report metadata
    report_data = {
        'generated_at': format_datetime(datetime.datetime.now()),
        'report_type': report_type,
        'environment': get_environment(),
        'app_version': get_app_version(),
        'data': data
    }

    if output_format == 'json':
        return json.dumps(report_data, indent=2, default=safe_json_serialize)

    elif output_format == 'html':
        # Generate simple HTML report
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<title>{report_type.title()} Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1 { color: #333; }",
            "table { border-collapse: collapse; width: 100%; }",
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            "pre { background-color: #f5f5f5; padding: 10px; overflow: auto; }",
            "</style>",
            "</head>",
            "<body>",
            f"<h1>{report_type.title()} Report</h1>",
            "<p><strong>Generated at:</strong> " + report_data['generated_at'] + "</p>",
            "<p><strong>Environment:</strong> " + report_data['environment'] + "</p>",
            "<p><strong>Version:</strong> " + report_data['app_version'] + "</p>",
            "<h2>Data</h2>"
        ]

        # Process the data
        html_parts.append(dict_to_html(data))

        # Close HTML
        html_parts.extend([
            "</body>",
            "</html>"
        ])

        return "\n".join(html_parts)

    else:  # text
        # Generate plain text report
        lines = [
            f"{report_type.upper()} REPORT",
            "=" * (len(report_type) + 7),
            f"Generated at: {report_data['generated_at']}",
            f"Environment: {report_data['environment']}",
            f"App Version: {report_data['app_version']}",
            "",
            "DATA:",
            "-----"
        ]

        # Process the data section
        lines.append(dict_to_text(data))

        return "\n".join(lines)


def dict_to_html(data: Any, depth: int = 0) -> str:
    """
    Convert a dictionary to an HTML representation.

    Args:
        data: The data to convert
        depth: Current nesting level

    Returns:
        str: HTML representation of the data
    """
    if isinstance(data, dict):
        if not data:
            return "<p><em>Empty dictionary</em></p>"

        html = "<table>\n<tr><th>Key</th><th>Value</th></tr>\n"
        for key, value in data.items():
            html += f"<tr><td><strong>{key}</strong></td><td>"
            html += dict_to_html(value, depth + 1) if isinstance(value, (dict, list)) else f"{value}"
            html += "</td></tr>\n"
        html += "</table>\n"
        return html

    elif isinstance(data, (list, tuple)):
        if not data:
            return "<p><em>Empty list</em></p>"

        html = "<ul>\n"
        for item in data:
            html += f"<li>{dict_to_html(item, depth + 1) if isinstance(item, (dict, list)) else item}</li>\n"
        html += "</ul>\n"
        return html

    else:
        return f"{data}"


def dict_to_text(data: Any, indent: int = 0) -> str:
    """
    Convert a dictionary to a text representation.

    Args:
        data: The data to convert
        indent: Current indentation level

    Returns:
        str: Text representation of the data
    """
    indent_str = "  " * indent

    if isinstance(data, dict):
        if not data:
            return f"{indent_str}(empty)"

        lines = []
        for key, value in data.items():
            if isinstance(value, (dict, list, tuple)):
                lines.append(f"{indent_str}{key}:")
                lines.append(dict_to_text(value, indent + 1))
            else:
                lines.append(f"{indent_str}{key}: {value}")
        return "\n".join(lines)

    elif isinstance(data, (list, tuple)):
        if not data:
            return f"{indent_str}(empty list)"

        lines = []
        for item in data:
            if isinstance(item, (dict, list, tuple)):
                lines.append(f"{indent_str}- ")
                lines.append(dict_to_text(item, indent + 1))
            else:
                lines.append(f"{indent_str}- {item}")
        return "\n".join(lines)

    else:
        return f"{indent_str}{data}"


def get_db_stats() -> Dict[str, Any]:
    """
    Get database statistics.

    Returns:
        Dict[str, Any]: Database statistics
    """
    stats = {
        'tables': {},
        'total_rows': 0,
        'size': {}
    }

    try:
        # Get list of tables
        result = db.session.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_type = 'BASE TABLE'
        """)
        tables = [row[0] for row in result]

        # Count rows in each table
        for table in tables:
            count = db.session.execute(f"SELECT COUNT(*) FROM \"{table}\"").scalar()
            stats['tables'][table] = count
            stats['total_rows'] += count

        # Get database size if possible
        try:
            result = db.session.execute("""
                SELECT pg_size_pretty(pg_database_size(current_database())) as size,
                       pg_database_size(current_database()) as bytes
            """)
            row = result.fetchone()
            stats['size'] = {
                'formatted': row[0],
                'bytes': row[1]
            }
        except:
            # This might fail depending on permissions
            stats['size'] = {'error': 'Could not determine database size'}

        # Get index statistics
        try:
            result = db.session.execute("""
                SELECT
                    indexrelname as index_name,
                    relname as table_name,
                    idx_scan as index_scans
                FROM pg_stat_user_indexes
                ORDER BY idx_scan DESC
                LIMIT 10
            """)
            stats['indexes'] = [dict(row) for row in result]
        except:
            stats['indexes'] = {'error': 'Could not retrieve index statistics'}

    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return {'error': str(e)}

    return stats


def execute_safe_command(command: List[str],
                        timeout: int = DEFAULT_TIMEOUT,
                        capture_output: bool = True) -> Tuple[int, str, str]:
    """
    Execute a system command with security controls and timeouts.

    Args:
        command: Command as a list of arguments
        timeout: Command timeout in seconds
        capture_output: Whether to capture and return command output

    Returns:
        Tuple[int, str, str]: Return code, stdout, stderr
    """
    # Validate command before execution - no shell=True which could enable injection
    try:
        # Log command execution for audit purposes (excluding sensitive args)
        safe_command = [arg if not any(s in arg.lower() for s in ['password', 'secret', 'key'])
                        else '[REDACTED]' for arg in command]

        logger.info(f"Executing command: {' '.join(safe_command)}")

        # Execute the command with timeout
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            shell=False  # Important: never use shell=True
        )

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout}s: {' '.join(safe_command)}")
        return 124, "", f"Command timed out after {timeout} seconds"

    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return 1, "", f"Error: {str(e)}"


# Exported module components
__all__ = [
    # Environment information
    'get_app_version',
    'get_env_info',
    'get_environment',
    'verify_environment_integrity',

    # Output formatting
    'format_table',
    'save_output',
    'generate_report',

    # Database operations
    'execute_db_operation',
    'is_retryable_error',
    'get_db_stats',

    # System commands
    'execute_safe_command',

    # Helper functions
    'dict_to_text',
    'dict_to_html',

    # Constants
    'DEFAULT_OUTPUT_DIR',
    'TEMP_DIR',
    'MAX_RETRIES',
    'DEFAULT_TIMEOUT',
    'SENSITIVE_FIELDS'
]
