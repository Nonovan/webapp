"""
Security Log Parsing Utilities

This module provides functions for parsing security logs in various formats
(syslog, JSON, CEF, LEEF) and extracting relevant fields. It's designed to
handle common security log formats while being extensible for custom formats.

Key functions:
- parse_security_log: Parse an entire log file with automatic format detection
- parse_log_line: Parse a single log line with specified format
- detect_log_format: Automatically detect the format of a log file
"""

import json
import logging
import re
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Callable, Pattern, TextIO

# Try importing monitoring constants
try:
    from ..monitoring_constants import LOG_PARSER_CONFIG, LOG_SOURCES
    CONSTANTS_AVAILABLE = True
except ImportError:
    # Fallback constants if monitoring_constants is not available
    CONSTANTS_AVAILABLE = False
    class LOG_PARSER_CONFIG:
        MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
        CHUNK_SIZE = 10000  # process 10k lines at a time
        MAX_PARSE_ERRORS = 100
        FORMATS = {
            "syslog": r'<(\d+)>(\w+ \d+ \d+:\d+:\d+) (\S+) (\S+)(|\[\d+\]): (.*)',
            "json": None,  # No regex pattern for JSON
            "cef": r'CEF:\d+\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',
            "leef": r'LEEF:(\d+\.\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)',
            "apache": r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-)'
        }
        DEFAULT_FIELDS = ["timestamp", "source", "level", "message"]

# Initialize module logger
logger = logging.getLogger(__name__)

# Precompile common log format regex patterns
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# Apache/Nginx access log format
ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[\w:/]+\s[+\-]\d{4})\] "(?P<request>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# CEF (Common Event Format) pattern
CEF_PATTERN = re.compile(r'CEF:\d+\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)')

# LEEF (Log Event Extended Format) pattern
LEEF_PATTERN = re.compile(r'LEEF:(\d+\.\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)')

# Format detection functions
def detect_log_format(file_path: Path) -> str:
    """
    Detect the format of a log file by examining a sample of lines.

    Args:
        file_path: Path to the log file

    Returns:
        String indicating the detected format ('syslog', 'json', 'cef', 'leef', 'apache', or 'unknown')
    """
    if not os.path.exists(file_path):
        logger.error(f"Log file {file_path} does not exist")
        return 'unknown'

    # Detect format by examining first 10 non-empty lines
    format_counts = {"json": 0, "syslog": 0, "cef": 0, "leef": 0, "apache": 0}

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = 0
            for line in f:
                if not line.strip():
                    continue

                line_format = _detect_line_format(line)
                if line_format in format_counts:
                    format_counts[line_format] += 1

                line_count += 1
                if line_count >= 10:
                    break

        if line_count == 0:
            logger.warning(f"Empty log file: {file_path}")
            return 'unknown'

        # Return the format with the highest count
        most_common_format = max(format_counts.items(), key=lambda x: x[1])
        # If most common format has zero occurrences, return 'unknown'
        if most_common_format[1] == 0:
            return 'unknown'

        logger.debug(f"Detected {most_common_format[0]} format for {file_path}")
        return most_common_format[0]

    except Exception as e:
        logger.error(f"Error detecting log format for {file_path}: {e}")
        return 'unknown'

def _detect_line_format(line: str) -> str:
    """
    Detect the format of a single log line.

    Args:
        line: Log line to analyze

    Returns:
        String indicating the detected format
    """
    line = line.strip()

    # Check if it's JSON
    if line.startswith('{') and line.endswith('}'):
        try:
            json.loads(line)
            return 'json'
        except json.JSONDecodeError:
            pass

    # Check if it's CEF
    if line.startswith('CEF:'):
        if CEF_PATTERN.match(line):
            return 'cef'

    # Check if it's LEEF
    if line.startswith('LEEF:'):
        if LEEF_PATTERN.match(line):
            return 'leef'

    # Check if it's Apache/Nginx access log
    if ACCESS_LOG_PATTERN.match(line):
        return 'apache'

    # Check if it's syslog
    if SYSLOG_PATTERN.match(line):
        return 'syslog'

    # Default to 'unknown'
    return 'unknown'

# Log parsing functions
def parse_security_log(
    log_file: Union[str, Path],
    format: Optional[str] = None,
    start_time: Optional[Union[str, datetime]] = None,
    end_time: Optional[Union[str, datetime]] = None,
    max_entries: int = 1000,
    include_raw: bool = True
) -> List[Dict[str, Any]]:
    """
    Parse a security log file and return structured data.

    Args:
        log_file: Path to the log file
        format: Log format (if None, auto-detection is used)
        start_time: Only include entries after this time
        end_time: Only include entries before this time
        max_entries: Maximum number of entries to return
        include_raw: Whether to include raw log lines

    Returns:
        List of parsed log entries as dictionaries
    """
    log_file = Path(log_file)
    if not log_file.exists():
        logger.error(f"Log file {log_file} does not exist")
        return []

    # Check file size to prevent processing very large files
    file_size = os.path.getsize(log_file)
    max_size = LOG_PARSER_CONFIG.MAX_LOG_SIZE if CONSTANTS_AVAILABLE else 50 * 1024 * 1024
    if file_size > max_size:
        logger.warning(f"Log file {log_file} exceeds maximum size ({file_size} > {max_size})")
        logger.warning("Consider using a more specific time range or increasing the limit")

    # Auto-detect format if not specified
    if not format or format == 'auto':
        format = detect_log_format(log_file)

    # Convert string timestamps to datetime objects for comparison
    start_dt = _parse_timestamp(start_time) if start_time else None
    end_dt = _parse_timestamp(end_time) if end_time else None

    # Get the appropriate parser function
    parser = get_log_parser_for_format(format)

    # Process the log file
    entries = []
    error_count = 0
    max_errors = LOG_PARSER_CONFIG.MAX_PARSE_ERRORS if CONSTANTS_AVAILABLE else 100

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    entry = parser(line)
                    if not entry:
                        continue

                    # Apply time filtering if specified
                    if entry.get('parsed_timestamp'):
                        if start_dt and entry['parsed_timestamp'] < start_dt:
                            continue
                        if end_dt and entry['parsed_timestamp'] > end_dt:
                            continue

                    # Add raw line if requested
                    if include_raw and 'raw_line' not in entry:
                        entry['raw_line'] = line.strip()

                    entries.append(entry)

                    # Check if we've reached the maximum number of entries
                    if len(entries) >= max_entries:
                        logger.debug(f"Reached maximum number of entries ({max_entries})")
                        break

                except Exception as e:
                    error_count += 1
                    if error_count <= 3:  # Log the first few errors in detail
                        logger.error(f"Error parsing log line: {e}")
                    elif error_count == 4:
                        logger.error("Additional parsing errors will be counted but not logged in detail")

                    if error_count >= max_errors:
                        logger.error(f"Too many parsing errors ({error_count}), aborting")
                        break

    except Exception as e:
        logger.error(f"Error reading log file {log_file}: {e}")

    logger.info(f"Parsed {len(entries)} entries from {log_file} (format: {format}, errors: {error_count})")
    return entries

def parse_log_line(line: str, format: str = 'auto') -> Optional[Dict[str, Any]]:
    """
    Parse a single log line into a structured dictionary.

    Args:
        line: The log line to parse
        format: Format of the log line ('auto', 'syslog', 'json', 'cef', 'leef', 'apache')

    Returns:
        Dictionary containing parsed log data or None if parsing fails
    """
    if not line or not line.strip():
        return None

    # Auto-detect format if not specified
    if format == 'auto':
        format = _detect_line_format(line)

    # Get the appropriate parser function
    parser = get_log_parser_for_format(format)

    # Parse the line
    try:
        return parser(line)
    except Exception as e:
        logger.debug(f"Error parsing {format} log line: {e}")
        return None

def get_log_parser_for_format(format: str) -> Callable[[str], Optional[Dict[str, Any]]]:
    """
    Get the appropriate parser function for a given log format.

    Args:
        format: Log format name

    Returns:
        Parser function that takes a log line and returns a parsed dictionary
    """
    format_parsers = {
        'json': parse_json_format,
        'syslog': parse_syslog_format,
        'cef': parse_cef_format,
        'leef': parse_leef_format,
        'apache': parse_apache_format
    }

    return format_parsers.get(format, parse_fallback_format)

# Format-specific parsers
def parse_json_format(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a JSON formatted log line.

    Args:
        line: JSON log line

    Returns:
        Parsed log data or None if parsing fails
    """
    try:
        data = json.loads(line)
        # Extract common fields and normalize
        if isinstance(data, dict):
            result = {"raw_data": data}

            # Try to extract timestamp
            for ts_field in ["timestamp", "time", "@timestamp", "date", "datetime", "created_at", "eventTime"]:
                if ts_field in data:
                    result["timestamp"] = str(data[ts_field])
                    try:
                        result["parsed_timestamp"] = _parse_timestamp(data[ts_field])
                    except ValueError:
                        pass
                    break

            # Try to extract message
            for msg_field in ["message", "msg", "log", "event", "description", "detail"]:
                if msg_field in data and data[msg_field]:
                    result["message"] = str(data[msg_field])
                    break

            # Try to extract level/severity
            for lvl_field in ["level", "severity", "loglevel", "log_level"]:
                if lvl_field in data:
                    result["level"] = str(data[lvl_field])
                    break

            # Try to extract source/hostname
            for src_field in ["source", "hostname", "host", "server"]:
                if src_field in data:
                    result["source"] = str(data[src_field])
                    break

            return result
        return None
    except json.JSONDecodeError:
        return None

def parse_syslog_format(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a syslog formatted log line.

    Args:
        line: Syslog line

    Returns:
        Parsed log data or None if parsing fails
    """
    match = SYSLOG_PATTERN.match(line)
    if match:
        data = match.groupdict()

        # Convert timestamp to standard format
        try:
            # Try ISO format first
            ts_str = data['timestamp']
            if 'T' in ts_str:  # ISO format
                timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            else:  # Syslog format
                current_year = datetime.now().year
                ts_str = f"{data['timestamp']} {current_year}"
                timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            data['parsed_timestamp'] = timestamp
        except ValueError:
            data['parsed_timestamp'] = None

        # Add raw line
        data['raw_line'] = line.strip()
        return data

    return None

def parse_apache_format(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse an Apache/Nginx access log line.

    Args:
        line: Apache/Nginx access log line

    Returns:
        Parsed log data or None if parsing fails
    """
    match = ACCESS_LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()

        # Convert Apache timestamp format
        try:
            timestamp_str = data['timestamp']
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            data['parsed_timestamp'] = timestamp
        except ValueError:
            data['parsed_timestamp'] = None

        # Add raw line
        data['raw_line'] = line
        return data

    return None

def parse_cef_format(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a CEF (Common Event Format) log line.

    Args:
        line: CEF log line

    Returns:
        Parsed log data or None if parsing fails
    """
    match = CEF_PATTERN.match(line)
    if not match:
        return None

    # CEF has a defined structure with 7 prefix fields and extension fields
    try:
        fields = match.groups()
        result = {
            'format': 'CEF',
            'version': fields[0],
            'device_vendor': fields[1],
            'device_product': fields[2],
            'device_version': fields[3],
            'signature_id': fields[4],
            'name': fields[5],
            'severity': fields[6],
            'raw_line': line
        }

        # Parse extension fields (key=value pairs)
        if len(fields) > 6:
            extensions_str = fields[6]
            # Simple key=value parsing (doesn't handle spaces in values correctly)
            extensions = {}
            for pair in extensions_str.split(' '):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    extensions[key] = value
            result['extensions'] = extensions

            # Try to extract timestamp from extensions
            if 'rt' in extensions:
                try:
                    # Standard CEF timestamp format is milliseconds since epoch
                    ts_millis = int(extensions['rt'])
                    result['parsed_timestamp'] = datetime.fromtimestamp(ts_millis / 1000, tz=timezone.utc)
                except (ValueError, TypeError):
                    pass
            elif 'end' in extensions:
                try:
                    # Sometimes timestamps are in human-readable format
                    result['parsed_timestamp'] = _parse_timestamp(extensions['end'])
                except ValueError:
                    pass

        return result
    except Exception:
        return None

def parse_leef_format(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a LEEF (Log Event Extended Format) log line.

    Args:
        line: LEEF log line

    Returns:
        Parsed log data or None if parsing fails
    """
    match = LEEF_PATTERN.match(line)
    if not match:
        return None

    try:
        fields = match.groups()
        result = {
            'format': 'LEEF',
            'version': fields[0],
            'vendor': fields[1],
            'product': fields[2],
            'version': fields[3],
            'raw_line': line
        }

        # Parse attributes (key=value pairs)
        if len(fields) > 4:
            attributes_str = fields[4]
            attributes = {}

            # LEEF uses tab as delimiter, but some implementations use spaces
            delimiter = '\t' if '\t' in attributes_str else ' '

            for pair in attributes_str.split(delimiter):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    attributes[key] = value

            result['attributes'] = attributes

            # Try to extract timestamp from attributes
            if 'devTime' in attributes:
                try:
                    result['parsed_timestamp'] = _parse_timestamp(attributes['devTime'])
                    result['timestamp'] = attributes['devTime']
                except ValueError:
                    pass

            # Extract message/details if available
            if 'msg' in attributes:
                result['message'] = attributes['msg']
            elif 'usrName' in attributes:
                action = attributes.get('action', 'unknown action')
                result['message'] = f"User {attributes['usrName']} performed {action}"

        return result
    except Exception:
        return None

def parse_fallback_format(line: str) -> Dict[str, Any]:
    """
    Fallback parser for unknown log formats.

    Args:
        line: Log line

    Returns:
        Basic dictionary with the raw line
    """
    return {
        'format': 'unknown',
        'message': line.strip(),
        'raw_line': line.strip()
    }

def extract_log_fields(log_entry: Dict[str, Any], field_mapping: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Extract standardized fields from a log entry using the provided field mapping.

    Args:
        log_entry: Parsed log entry
        field_mapping: Mapping from standard field names to source field names

    Returns:
        Dictionary with standardized field names
    """
    if not field_mapping:
        return log_entry

    result = {}

    for target_field, source_field in field_mapping.items():
        if source_field in log_entry:
            result[target_field] = log_entry[source_field]

    # Always include raw line if available
    if 'raw_line' in log_entry:
        result['raw_line'] = log_entry['raw_line']

    return result

# Helper functions
def _parse_timestamp(timestamp: Union[str, datetime]) -> datetime:
    """
    Parse a timestamp string into a datetime object.

    Args:
        timestamp: Timestamp string or datetime object

    Returns:
        Datetime object with timezone information
    """
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp

    if not isinstance(timestamp, str):
        raise ValueError(f"Expected string or datetime, got {type(timestamp)}")

    # Common timestamp formats to try
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",  # ISO8601 with timezone
        "%Y-%m-%dT%H:%M:%S.%f%z",  # ISO8601 with microseconds and timezone
        "%Y-%m-%dT%H:%M:%SZ",  # ISO8601 UTC
        "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO8601 UTC with microseconds
        "%Y-%m-%dT%H:%M:%S",  # ISO8601 without timezone
        "%Y-%m-%d %H:%M:%S",  # Simple datetime
        "%Y-%m-%d %H:%M:%S.%f",  # Simple datetime with microseconds
        "%Y-%m-%d",  # Date only
        "%m/%d/%Y %H:%M:%S",  # US format
        "%d/%b/%Y:%H:%M:%S %z",  # Apache log format
        "%b %d %H:%M:%S"  # Syslog format (no year)
    ]

    # Replace 'Z' with +00:00 for ISO8601 UTC
    if timestamp.endswith('Z'):
        timestamp = timestamp[:-1] + "+00:00"

    # Try each format
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp, fmt)
            # Add UTC timezone if not specified
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # For syslog format without year, add current year
    if re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', timestamp):
        current_year = datetime.now().year
        try:
            dt = datetime.strptime(f"{timestamp} {current_year}", "%b %d %H:%M:%S %Y")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    # If all parsing attempts fail
    raise ValueError(f"Could not parse timestamp: {timestamp}")

# Module initialization
if __name__ == "__main__":
    # Setup logging for standalone testing
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Example usage
    print("Log Parser Module - Test Mode")

    # Test log line detection
    test_lines = [
        '{"timestamp": "2023-07-15T12:34:56Z", "level": "INFO", "message": "User login successful"}',
        'Jul 15 12:34:56 server sshd[1234]: Failed password for user root from 192.168.1.1 port 12345 ssh2',
        'CEF:0|Vendor|Product|1.0|100|User Login|5|src=192.168.1.1 dst=192.168.1.2 suser=admin',
        'LEEF:1.0|Vendor|Product|1.0|LOGIN|src=192.168.1.1 dst=192.168.1.2 usrName=admin',
        '192.168.1.1 - user [15/Jul/2023:12:34:56 +0000] "GET /login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    ]

    for line in test_lines:
        format_type = _detect_line_format(line)
        parsed = parse_log_line(line, format_type)
        print(f"Format: {format_type}")
        if parsed:
            print(f"  Parsed: {parsed.get('message', '<no message>')}")
            if 'parsed_timestamp' in parsed:
                print(f"  Timestamp: {parsed['parsed_timestamp']}")
        else:
            print("  Failed to parse")
        print()
