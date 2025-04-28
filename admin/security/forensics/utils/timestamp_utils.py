"""
Timestamp Normalization and Handling Utilities for the Forensic Analysis Toolkit.

This module provides functions for parsing, converting, validating, and comparing
timestamps encountered during digital forensic investigations. It aims to standardize
timestamps, typically to UTC, to facilitate accurate timeline analysis and correlation
across different data sources and timezones.

Functions handle common formats like ISO 8601, Unix epoch, and Windows FILETIME,
and integrate with forensic logging.
"""

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger for timestamps.")
    FORENSIC_LOGGING_AVAILABLE = False
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    # Re-use conversion functions if available
    from admin.security.forensics.utils.format_converter import (
        epoch_to_datetime as fc_epoch_to_datetime,
        filetime_to_datetime as fc_filetime_to_datetime,
        mac_absolute_time_to_datetime as fc_mac_time_to_datetime
    )
    FORMAT_CONVERTER_AVAILABLE = True
except ImportError:
    logging.warning("Format converter utility not found. Defining basic timestamp conversions locally.")
    FORMAT_CONVERTER_AVAILABLE = False
    # Basic fallbacks if format_converter is missing
    def fc_epoch_to_datetime(epoch_seconds: Union[int, float]) -> datetime:
        try:
            return datetime.fromtimestamp(epoch_seconds, timezone.utc)
        except (TypeError, ValueError, OSError) as e:
            raise ValueError(f"Invalid epoch timestamp: {e}") from e

    def fc_filetime_to_datetime(filetime: int) -> datetime:
        EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
        HUNDREDS_OF_NANOSECONDS = 10000000
        try:
            epoch_seconds = (filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            return datetime.fromtimestamp(epoch_seconds, timezone.utc)
        except (TypeError, ValueError, OSError) as e:
            raise ValueError(f"Invalid FILETIME timestamp: {e}") from e

    def fc_mac_time_to_datetime(timestamp: int) -> datetime:
        """Converts Mac Absolute Time (seconds since 2001-01-01 UTC) to datetime."""
        MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
        try:
            return MAC_EPOCH + timedelta(seconds=timestamp)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid Mac Absolute Time: {e}") from e


try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_TIMESTAMP_FORMAT,
        DEFAULT_TIMEZONE,
        COMMON_TIMESTAMP_FORMATS,
        MAX_TIMESTAMP_SKEW
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    logging.warning("Forensic constants not found. Using default values for timestamps.")
    CONSTANTS_AVAILABLE = False
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = "iso8601"  # Corresponds to datetime.isoformat()
    DEFAULT_TIMEZONE_FALLBACK = "UTC"  # Should always be UTC for forensics
    MAX_TIMESTAMP_SKEW_FALLBACK = timedelta(minutes=10)  # Default maximum allowed time skew

logger = logging.getLogger(__name__)

# --- Constants ---

# Date/time format constants
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
MAC_ABSOLUTE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)  # Mac time reference date
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)  # WebKit/Chrome time reference date
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)  # Same as Mac Absolute Time
FAT_TIMESTAMP_MIN = datetime(1980, 1, 1, tzinfo=timezone.utc)  # Minimum FAT timestamp
FAT_TIMESTAMP_MAX = datetime(2107, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # Maximum FAT timestamp
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)  # Unix epoch reference

# Define timestamp formats to try when parsing ambiguous timestamps
# Order matters - try more specific/restrictive formats before more general ones
if CONSTANTS_AVAILABLE:
    # Use the imported constant if available
    pass  # COMMON_TIMESTAMP_FORMATS is already imported
else:
    # Define fallback timestamp formats if constants not available
    if 'COMMON_TIMESTAMP_FORMATS' not in globals():
        COMMON_TIMESTAMP_FORMATS.extend([
        # ISO 8601 formats
        "%Y-%m-%dT%H:%M:%S.%f%z",  # ISO 8601 with timezone offset and microseconds
        "%Y-%m-%dT%H:%M:%S.%fZ",   # ISO 8601 with Z (UTC) and microseconds
        "%Y-%m-%dT%H:%M:%S%z",     # ISO 8601 with timezone offset, no microseconds
        "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601 with Z (UTC), no microseconds

        # Common formats with space as separator
        "%Y-%m-%d %H:%M:%S.%f%z",  # Space separator with timezone and microseconds
        "%Y-%m-%d %H:%M:%S.%f Z",  # Space separator with Z (UTC) and microseconds
        "%Y-%m-%d %H:%M:%S%z",     # Space separator with timezone, no microseconds
        "%Y-%m-%d %H:%M:%S Z",     # Space separator with Z (UTC), no microseconds
        "%Y-%m-%d %H:%M:%S.%f",    # Space separator with microseconds, no timezone
        "%Y-%m-%d %H:%M:%S",       # Common date-time format, no timezone (assume UTC)

        # Date formats with different separators
        "%Y/%m/%d %H:%M:%S",       # Slash date separator
        "%d/%m/%Y %H:%M:%S",       # European format (day first)
        "%m/%d/%Y %H:%M:%S",       # US format (month first)
        "%Y.%m.%d %H:%M:%S",       # Dot date separator

        # Compact formats
        "%Y%m%d%H%M%S",            # Compact format (no separators)
        "%Y%m%dT%H%M%S",           # Compact ISO-like format

        # Formats with textual month representation
        "%d-%b-%Y %H:%M:%S",       # Day-abbreviated month-year
        "%d %b %Y %H:%M:%S",       # Day month year with spaces
        "%b %d %H:%M:%S %Y",       # Syslog format (month day time year)
        "%b %d %Y %H:%M:%S",       # Month day year time
        "%a %b %d %H:%M:%S %Y",    # Weekday month day time year (e.g., Fri Oct 27 10:30:00 2023)
        "%a, %d %b %Y %H:%M:%S %z", # RFC 2822 format (e.g., Fri, 27 Oct 2023 10:30:00 +0000)

        # Log formats
        "%d/%b/%Y:%H:%M:%S %z",    # Apache/Nginx access log format

        # Windows event log and other formats
        "%m/%d/%Y %I:%M:%S %p",    # US format with AM/PM
    ])

# Additional format patterns for special timestamp formats not easily handled by strptime
# Each pattern has a regex and a function to convert the match to a datetime
SPECIAL_TIMESTAMP_PATTERNS = [
    # Unix timestamp with milliseconds (e.g., "1698399000.123")
    {
        'pattern': r'^(\d{9,10})\.(\d{1,6})$',
        'converter': lambda match: datetime.fromtimestamp(
            float(f"{match.group(1)}.{match.group(2)}"),
            timezone.utc
        )
    },
    # Windows FILETIME as decimal string (e.g., "133428990001234560")
    {
        'pattern': r'^(1[3-9]\d{16,17})$',
        'converter': lambda match: fc_filetime_to_datetime(int(match.group(1)))
    },
    # Partial ISO format without seconds (e.g., "2023-10-27T09:30")
    {
        'pattern': r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$',
        'converter': lambda match: datetime(
            int(match.group(1)), int(match.group(2)), int(match.group(3)),
            int(match.group(4)), int(match.group(5)), 0,
            tzinfo=timezone.utc
        )
    },
    # JavaScript/Unix timestamp in milliseconds (e.g., "1698399000123")
    {
        'pattern': r'^(\d{13})$',
        'converter': lambda match: datetime.fromtimestamp(
            int(match.group(1)) / 1000,
            timezone.utc
        )
    }
]

# --- Core Time Normalization Functions ---

def get_current_utc_timestamp() -> datetime:
    """Returns the current time as a timezone-aware UTC datetime object."""
    return datetime.now(timezone.utc)

def normalize_timestamp(
    timestamp_input: Union[str, int, float, datetime],
    input_format: Optional[str] = None,
    assume_utc: bool = True
) -> Optional[datetime]:
    """
    Attempts to parse various timestamp formats and return a standardized UTC datetime object.

    Handles strings (using common formats or a specified format), epoch seconds,
    Windows FILETIME integers, and existing datetime objects.

    Args:
        timestamp_input: The timestamp string, epoch value, FILETIME, or datetime object.
        input_format: Specific format string for strptime if the format is known.
        assume_utc: If True and a parsed string timestamp has no timezone info, assume it's UTC.

    Returns:
        A timezone-aware datetime object in UTC, or None if parsing fails.
    """
    operation = "normalize_timestamp"
    details = {"input": str(timestamp_input)[:100], "input_format": input_format, "assume_utc": assume_utc}

    if isinstance(timestamp_input, datetime):
        # If already a datetime object, ensure it's UTC
        if timestamp_input.tzinfo is None:
            if assume_utc:
                dt_utc = timestamp_input.replace(tzinfo=timezone.utc)
                log_forensic_operation(operation, True, {**details, "status": "Assumed UTC for naive datetime"})
                return dt_utc
            else:
                logger.warning("Received naive datetime object and assume_utc is False. Cannot normalize.")
                log_forensic_operation(operation, False, {**details, "error": "Naive datetime received, assume_utc=False"})
                return None
        else:
            dt_utc = timestamp_input.astimezone(timezone.utc)
            log_forensic_operation(operation, True, {**details, "status": "Converted existing datetime to UTC"})
            return dt_utc

    elif isinstance(timestamp_input, (int, float)):
        # Determine what type of numeric timestamp based on magnitude
        try:
            # Categorize by value range
            if isinstance(timestamp_input, int) and timestamp_input > 10**17:
                # FILETIME (100ns since 1601-01-01)
                dt_utc = fc_filetime_to_datetime(timestamp_input)
                log_forensic_operation(operation, True, {**details, "status": "Interpreted as Windows FILETIME"})
                return dt_utc
            elif isinstance(timestamp_input, int) and timestamp_input > 10**12:
                # JavaScript timestamp (ms since epoch)
                dt_utc = fc_epoch_to_datetime(timestamp_input / 1000)
                log_forensic_operation(operation, True, {**details, "status": "Interpreted as JavaScript millisecond timestamp"})
                return dt_utc
            elif timestamp_input > 10**10 and timestamp_input < 10**12:
                # Mac Absolute Time (seconds since 2001-01-01)
                dt_utc = fc_mac_time_to_datetime(timestamp_input)
                log_forensic_operation(operation, True, {**details, "status": "Interpreted as Mac Absolute Time"})
                return dt_utc
            else:
                # Unix epoch (seconds since 1970-01-01)
                dt_utc = fc_epoch_to_datetime(timestamp_input)
                log_forensic_operation(operation, True, {**details, "status": "Interpreted as Unix epoch timestamp"})
                return dt_utc
        except ValueError as e:
            logger.error("Failed to interpret numeric timestamp %s: %s", timestamp_input, e)
            log_forensic_operation(operation, False, {**details, "error": f"Numeric conversion failed: {e}"})
            return None

    elif isinstance(timestamp_input, str):
        timestamp_str = timestamp_input.strip()

        # Handle empty strings
        if not timestamp_str:
            log_forensic_operation(operation, False, {**details, "error": "Empty timestamp string"})
            return None

        # Handle numeric strings - try to parse as int/float first
        if re.match(r'^[\d.]+$', timestamp_str):
            try:
                if '.' in timestamp_str:
                    return normalize_timestamp(float(timestamp_str), assume_utc=assume_utc)
                else:
                    return normalize_timestamp(int(timestamp_str), assume_utc=assume_utc)
            except (ValueError, OverflowError):
                # Continue with string parsing if numeric conversion fails
                pass

        # Handle 'Z' explicitly by replacing it for formats that expect offset
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'
        # Handle space before timezone offset/Z (which might have been replaced)
        if ' Z' in timestamp_str:
            timestamp_str = timestamp_str.replace(' Z', '+00:00')

        # Try special patterns that don't fit strptime formats
        for pattern_info in SPECIAL_TIMESTAMP_PATTERNS:
            match = re.match(pattern_info['pattern'], timestamp_str)
            if match:
                try:
                    dt = pattern_info['converter'](match)
                    log_forensic_operation(operation, True, {**details, "status": f"Matched special pattern: {pattern_info['pattern']}"})
                    return dt
                except (ValueError, OverflowError, OSError) as e:
                    # Log the error but continue trying other formats
                    logger.debug("Special pattern match failed for '%s': %s", timestamp_str, e)

        # Try specified format first
        parsed_dt = None
        if input_format:
            try:
                parsed_dt = datetime.strptime(timestamp_str, input_format)
            except ValueError:
                logger.debug("Timestamp '%s' did not match specified format '%s'", timestamp_str, input_format)
                # Fall through to try common formats if specified one fails

        # Try common formats
        if not parsed_dt:
            for fmt in COMMON_TIMESTAMP_FORMATS:
                try:
                    parsed_dt = datetime.strptime(timestamp_str, fmt)
                    details["matched_format"] = fmt  # Log which format worked
                    break  # Stop on first successful parse
                except ValueError:
                    continue  # Try next format

        # If we have a parsed datetime, handle timezone
        if parsed_dt:
            if parsed_dt.tzinfo is None:
                if assume_utc:
                    dt_utc = parsed_dt.replace(tzinfo=timezone.utc)
                    log_forensic_operation(operation, True, {**details, "status": "Parsed string and assumed UTC"})
                    return dt_utc
                else:
                    logger.warning("Parsed naive timestamp string '%s' and assume_utc is False.", timestamp_input)
                    log_forensic_operation(operation, False, {**details, "error": "Parsed naive string, assume_utc=False"})
                    return None  # Cannot normalize without timezone assumption
            else:
                # Convert timezone-aware datetime to UTC
                dt_utc = parsed_dt.astimezone(timezone.utc)
                log_forensic_operation(operation, True, {**details, "status": "Parsed string and converted to UTC"})
                return dt_utc

        # Try dateutil parser as a last resort if available
        try:
            import dateutil.parser
            dt = dateutil.parser.parse(timestamp_str)
            if dt.tzinfo is None and assume_utc:
                dt = dt.replace(tzinfo=timezone.utc)
            elif dt.tzinfo is None and not assume_utc:
                log_forensic_operation(operation, False, {**details, "error": "Parsed naive string with dateutil, assume_utc=False"})
                return None

            dt_utc = dt.astimezone(timezone.utc)
            log_forensic_operation(operation, True, {**details, "status": "Parsed with dateutil.parser"})
            return dt_utc
        except (ImportError, ValueError, AttributeError):
            # If dateutil isn't available or fails to parse
            pass

        logger.error("Failed to parse timestamp string: %s", timestamp_input)
        log_forensic_operation(operation, False, {**details, "error": "String parsing failed with all formats"})
        return None

    else:
        logger.error("Unsupported timestamp input type: %s", type(timestamp_input))
        log_forensic_operation(operation, False, {**details, "error": f"Unsupported type: {type(timestamp_input)}"})
        return None


def format_timestamp(
    dt_obj: datetime,
    output_format: str = DEFAULT_TIMESTAMP_FORMAT
) -> Optional[str]:
    """
    Formats a datetime object into a specified string format.

    Args:
        dt_obj: The datetime object to format (preferably timezone-aware).
        output_format: The desired output format string (e.g., "%Y-%m-%d %H:%M:%S")
                       or "iso8601", "epoch", "filetime", "javascript", "mac_time".

    Returns:
        The formatted timestamp string, or None if formatting fails.
    """
    operation = "format_timestamp"
    details = {"output_format": output_format}
    if not isinstance(dt_obj, datetime):
        logger.error("Input must be a datetime object.")
        log_forensic_operation(operation, False, {**details, "error": "Invalid input type"})
        return None

    # Ensure UTC if naive
    if dt_obj.tzinfo is None:
        logger.warning("Formatting a naive datetime object. Assuming UTC.")
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        details["warning"] = "Input datetime was naive, assumed UTC"

    # Ensure the datetime is in UTC before formatting epoch/filetime
    dt_utc = dt_obj.astimezone(timezone.utc)

    try:
        output_format_lower = output_format.lower()

        # Special format handling
        if output_format_lower == "iso8601":
            formatted = dt_utc.isoformat()
        elif output_format_lower == "epoch" or output_format_lower == "unix":
            formatted = str(dt_utc.timestamp())
        elif output_format_lower == "filetime" or output_format_lower == "windows":
            epoch_seconds = dt_utc.timestamp()
            filetime = int(epoch_seconds * HUNDREDS_OF_NANOSECONDS) + EPOCH_AS_FILETIME
            formatted = str(filetime)
        elif output_format_lower == "javascript" or output_format_lower == "js":
            formatted = str(int(dt_utc.timestamp() * 1000))
        elif output_format_lower == "mac_time" or output_format_lower == "mac_absolute":
            mac_seconds = (dt_utc - MAC_ABSOLUTE_EPOCH).total_seconds()
            formatted = str(int(mac_seconds))
        elif output_format_lower == "rfc2822":
            formatted = dt_utc.strftime("%a, %d %b %Y %H:%M:%S +0000")
        elif output_format_lower == "rfc3339":
            formatted = dt_utc.isoformat().replace('+00:00', 'Z')
        elif output_format_lower == "http":
            formatted = dt_utc.strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            # Standard strftime format
            formatted = dt_utc.strftime(output_format)

        log_forensic_operation(operation, True, details)
        return formatted
    except (ValueError, TypeError) as e:
        logger.error("Failed to format timestamp %s with format '%s': %s", dt_obj, output_format, e)
        log_forensic_operation(operation, False, {**details, "error": str(e)})
        return None


def validate_timestamp_string(
    timestamp_str: str,
    expected_format: Optional[str] = None,
    min_date: Optional[datetime] = None,
    max_date: Optional[datetime] = None
) -> bool:
    """
    Validates if a string represents a recognizable timestamp format and optionally
    if it falls within specified minimum and maximum dates.

    Args:
        timestamp_str: The string to validate.
        expected_format: An optional specific format string to check against.
        min_date: Optional minimum allowed date
        max_date: Optional maximum allowed date

    Returns:
        True if the string can be parsed as a timestamp and meets constraints, False otherwise.
    """
    normalized = normalize_timestamp(timestamp_str, input_format=expected_format)
    if normalized is None:
        log_forensic_operation(
            "validate_timestamp_string",
            False,
            {"input": timestamp_str[:100], "expected_format": expected_format, "error": "Failed to parse"}
        )
        return False

    # Check min/max constraints if provided
    if min_date and normalized < min_date:
        log_forensic_operation(
            "validate_timestamp_string",
            False,
            {
                "input": timestamp_str[:100],
                "parsed": normalized.isoformat(),
                "error": f"Date before minimum ({min_date.isoformat()})"
            }
        )
        return False

    if max_date and normalized > max_date:
        log_forensic_operation(
            "validate_timestamp_string",
            False,
            {
                "input": timestamp_str[:100],
                "parsed": normalized.isoformat(),
                "error": f"Date after maximum ({max_date.isoformat()})"
            }
        )
        return False

    log_forensic_operation(
        "validate_timestamp_string",
        True,
        {"input": timestamp_str[:100], "parsed": normalized.isoformat()}
    )
    return True


def compare_timestamps(
    ts1: Union[str, int, float, datetime],
    ts2: Union[str, int, float, datetime]
) -> Optional[int]:
    """
    Compares two timestamps after normalizing them to UTC.

    Args:
        ts1: The first timestamp.
        ts2: The second timestamp.

    Returns:
        -1 if ts1 < ts2
         0 if ts1 == ts2
         1 if ts1 > ts2
         None if either timestamp cannot be normalized.
    """
    dt1 = normalize_timestamp(ts1)
    dt2 = normalize_timestamp(ts2)

    if dt1 is None or dt2 is None:
        log_forensic_operation(
            "compare_timestamps",
            False,
            {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "error": "Normalization failed"}
        )
        return None

    if dt1 < dt2:
        result = -1
    elif dt1 > dt2:
        result = 1
    else:
        result = 0

    log_forensic_operation(
        "compare_timestamps",
        True,
        {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "result": result}
    )
    return result


def calculate_time_difference(
    ts1: Union[str, int, float, datetime],
    ts2: Union[str, int, float, datetime]
) -> Optional[timedelta]:
    """
    Calculates the time difference (ts2 - ts1) between two timestamps after normalization.

    Args:
        ts1: The earlier timestamp.
        ts2: The later timestamp.

    Returns:
        A timedelta object representing the difference, or None if normalization fails.
    """
    dt1 = normalize_timestamp(ts1)
    dt2 = normalize_timestamp(ts2)

    if dt1 is None or dt2 is None:
        log_forensic_operation(
            "calculate_time_difference",
            False,
            {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "error": "Normalization failed"}
        )
        return None

    difference = dt2 - dt1
    log_forensic_operation(
        "calculate_time_difference",
        True,
        {
            "ts1": str(ts1)[:50],
            "ts2": str(ts2)[:50],
            "difference_seconds": difference.total_seconds()
        }
    )
    return difference


# --- Additional Forensic Timestamp Functions ---

def is_timestamp_within_range(
    timestamp: Union[str, int, float, datetime],
    start_time: Union[str, int, float, datetime],
    end_time: Union[str, int, float, datetime]
) -> Optional[bool]:
    """
    Checks if a timestamp falls within a given range (inclusive).

    Args:
        timestamp: The timestamp to check
        start_time: The start of the range
        end_time: The end of the range

    Returns:
        True if timestamp is within range, False if not, None if normalization fails
    """
    dt = normalize_timestamp(timestamp)
    dt_start = normalize_timestamp(start_time)
    dt_end = normalize_timestamp(end_time)

    if dt is None or dt_start is None or dt_end is None:
        log_forensic_operation(
            "is_timestamp_within_range",
            False,
            {"timestamp": str(timestamp)[:50], "error": "Normalization failed"}
        )
        return None

    result = dt_start <= dt <= dt_end
    log_forensic_operation(
        "is_timestamp_within_range",
        True,
        {
            "timestamp": dt.isoformat(),
            "start": dt_start.isoformat(),
            "end": dt_end.isoformat(),
            "within_range": result
        }
    )
    return result


def normalize_timestamp_batch(
    timestamps: List[Union[str, int, float, datetime]],
    assume_utc: bool = True
) -> Tuple[List[datetime], List[Union[str, int, float]]]:
    """
    Process a batch of timestamps and normalize them all to UTC.

    Args:
        timestamps: List of timestamps to normalize
        assume_utc: If True and a parsed string timestamp has no timezone info, assume it's UTC

    Returns:
        Tuple containing (successful_conversions, failed_items)
    """
    successful = []
    failed = []

    for ts in timestamps:
        normalized = normalize_timestamp(ts, assume_utc=assume_utc)
        if normalized is not None:
            successful.append(normalized)
        else:
            failed.append(ts)

    log_forensic_operation(
        "normalize_timestamp_batch",
        len(failed) == 0,  # Success if no failures
        {
            "total_items": len(timestamps),
            "successful": len(successful),
            "failed": len(failed)
        }
    )

    return successful, failed


def extract_timestamps_from_text(
    text: str,
    timestamp_formats: Optional[List[str]] = None
) -> List[Tuple[datetime, str, int]]:
    """
    Extracts potential timestamps from text content.

    Args:
        text: The text content to scan for timestamps
        timestamp_formats: List of formats to try (defaults to COMMON_TIMESTAMP_FORMATS)

    Returns:
        List of tuples containing (normalized_datetime, matched_text, position)
    """
    if timestamp_formats is None:
        timestamp_formats = COMMON_TIMESTAMP_FORMATS

    results = []

    # First try pattern-based extraction
    # This includes ISO 8601-like formats, common log formats, etc.
    patterns = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', # ISO 8601
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # MM/DD/YYYY HH:MM:SS or DD/MM/YYYY HH:MM:SS
        r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',  # YYYY/MM/DD HH:MM:SS
        r'[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}(?: \d{4})?',  # Syslog format (e.g., Oct 27 10:30:00 2023)
        r'\d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2}',  # Day Month Year HH:MM:SS
        r'\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}',  # DD-Mon-YYYY HH:MM:SS
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text):
            potential_ts = match.group(0)
            position = match.start()
            normalized = normalize_timestamp(potential_ts)
            if normalized:
                results.append((normalized, potential_ts, position))

    # Extract and check unix timestamps (numbers that could be epoch seconds)
    for match in re.finditer(r'\b\d{9,10}(?:\.\d{1,6})?\b', text):
        potential_ts = match.group(0)
        position = match.start()
        # Check if it's a reasonable unix timestamp (between 1990 and 2050)
        try:
            value = float(potential_ts)
            if 631152000 <= value <= 2524608000:  # 1990-01-01 to 2050-01-01
                normalized = normalize_timestamp(value)
                if normalized:
                    results.append((normalized, potential_ts, position))
        except ValueError:
            pass

    log_forensic_operation(
        "extract_timestamps_from_text",
        True,
        {"text_length": len(text), "timestamps_found": len(results)}
    )

    # Sort by position in text
    return sorted(results, key=lambda x: x[2])


def validate_timestamp_integrity(
    timestamp: Union[str, int, float, datetime],
    reference_time: Optional[Union[str, int, float, datetime]] = None,
    max_skew: Optional[timedelta] = None,
    direction: str = "both"
) -> bool:
    """
    Validates a timestamp against a reference time to ensure it's within acceptable skew.

    Args:
        timestamp: The timestamp to validate
        reference_time: Time to compare against (defaults to current time)
        max_skew: Maximum allowed time difference (defaults to MAX_TIMESTAMP_SKEW)
        direction: Direction of comparison ("future", "past", or "both")

    Returns:
        True if timestamp is valid and within acceptable skew, False otherwise
    """
    dt = normalize_timestamp(timestamp)
    if dt is None:
        log_forensic_operation(
            "validate_timestamp_integrity",
            False,
            {"timestamp": str(timestamp)[:50], "error": "Failed to normalize timestamp"}
        )
        return False

    # Use provided reference time or current time
    if reference_time is None:
        ref_dt = get_current_utc_timestamp()
    else:
        ref_dt = normalize_timestamp(reference_time)
        if ref_dt is None:
            log_forensic_operation(
                "validate_timestamp_integrity",
                False,
                {"timestamp": str(timestamp)[:50], "error": "Failed to normalize reference time"}
            )
            return False

    # Use provided max skew or default
    if max_skew is None:
        max_skew = MAX_TIMESTAMP_SKEW

    time_diff = dt - ref_dt
    abs_diff = abs(time_diff)

    # Check if difference is within acceptable range based on direction
    if direction.lower() == "future":
        # Timestamp should not be too far in the future
        valid = time_diff <= max_skew
    elif direction.lower() == "past":
        # Timestamp should not be too far in the past
        valid = time_diff >= -max_skew
    else:  # both
        # Timestamp should be within skew in either direction
        valid = abs_diff <= max_skew

    details = {
        "timestamp": dt.isoformat(),
        "reference": ref_dt.isoformat(),
        "difference_seconds": time_diff.total_seconds(),
        "max_skew_seconds": max_skew.total_seconds(),
        "direction": direction,
        "valid": valid
    }

    log_forensic_operation("validate_timestamp_integrity", valid, details)
    return valid


def get_timezone_offset(dt: datetime) -> int:
    """
    Gets the UTC offset in seconds for a given datetime object.

    Args:
        dt: Datetime object (timezone-aware)

    Returns:
        Offset in seconds from UTC or 0 if datetime is naive
    """
    if dt.tzinfo is None:
        return 0
    return int(dt.utcoffset().total_seconds())


def detect_timestamp_type(timestamp: Union[str, int, float]) -> str:
    """
    Detects the likely type of timestamp based on its format or value range.

    Args:
        timestamp: The timestamp value or string

    Returns:
        String indicating the detected timestamp type
    """
    operation = "detect_timestamp_type"

    # Integers and floats can be categorized by range
    if isinstance(timestamp, (int, float)):
        details = {"value": timestamp}

        if isinstance(timestamp, int) and timestamp > 10**17:
            result = "windows_filetime"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if isinstance(timestamp, int) and timestamp > 10**12:
            result = "javascript_ms"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if timestamp > 10**10 and timestamp < 10**12:
            result = "mac_absolute_time"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if timestamp > 10**9 and timestamp < 2**32:
            result = "unix_epoch"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        result = "unknown_numeric"
        log_forensic_operation(operation, True, {**details, "type": result})
        return result

    # For strings, try to identify by pattern
    if isinstance(timestamp, str):
        timestamp = timestamp.strip()
        details = {"value": timestamp[:50]}

        # Try to match patterns
        if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", timestamp):
            result = "iso8601"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?", timestamp):
            result = "sql_datetime"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if re.match(r"[A-Za-z]{3}, \d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT", timestamp):
            result = "http_date"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        if re.match(r"[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}", timestamp):
            result = "unix_log_date"
            log_forensic_operation(operation, True, {**details, "type": result})
            return result

        # Try to interpret numeric strings
        if re.match(r"^\d+$", timestamp):
            try:
                return detect_timestamp_type(int(timestamp))
            except (ValueError, OverflowError):
                pass

        if re.match(r"^\d+\.\d+$", timestamp):
            try:
                return detect_timestamp_type(float(timestamp))
            except (ValueError, OverflowError):
                pass

    result = "unknown"
    log_forensic_operation(operation, True, {**details, "type": result})
    return result


def convert_between_timestamp_types(
    timestamp: Union[str, int, float, datetime],
    target_format: str
) -> Optional[Union[str, int, float, datetime]]:
    """
    Converts a timestamp from any recognized format to a specific target format.

    Args:
        timestamp: The input timestamp in any supported format
        target_format: The desired output format:
          - 'datetime': Python datetime object
          - 'iso8601': ISO 8601 string
          - 'epoch' or 'unix': Unix timestamp (seconds)
          - 'filetime' or 'windows': Windows FILETIME (100ns intervals)
          - 'javascript' or 'js': JavaScript timestamp (milliseconds)
          - 'mac_time': Mac Absolute Time (seconds since 2001)
          - Any strftime format string

    Returns:
        Converted timestamp in the requested format, or None if conversion fails
    """
    # First normalize to datetime
    dt = normalize_timestamp(timestamp)
    if dt is None:
        log_forensic_operation(
            "convert_between_timestamp_types",
            False,
            {"input": str(timestamp)[:50], "target_format": target_format, "error": "Failed to normalize timestamp"}
        )
        return None

    # Return datetime object if requested
    if target_format.lower() == 'datetime':
        log_forensic_operation(
            "convert_between_timestamp_types",
            True,
            {"input": str(timestamp)[:50], "target_format": target_format}
        )
        return dt

    # For other formats, use format_timestamp
    if target_format.lower() in ('epoch', 'unix', 'javascript', 'js',
                                 'filetime', 'windows', 'mac_time', 'iso8601',
                                 'rfc2822', 'rfc3339', 'http'):
        formatted = format_timestamp(dt, target_format)
        if formatted is not None:
            try:
                # Convert to appropriate numeric type for epoch/js/etc.
                if target_format.lower() in ('epoch', 'unix'):
                    result = float(formatted)
                    if result.is_integer():
                        result = int(result)
                    log_forensic_operation(
                        "convert_between_timestamp_types",
                        True,
                        {"input": str(timestamp)[:50], "target_format": target_format}
                    )
                    return result

                if target_format.lower() in ('javascript', 'js', 'filetime', 'windows', 'mac_time'):
                    result = int(formatted)
                    log_forensic_operation(
                        "convert_between_timestamp_types",
                        True,
                        {"input": str(timestamp)[:50], "target_format": target_format}
                    )
                    return result

                log_forensic_operation(
                    "convert_between_timestamp_types",
                    True,
                    {"input": str(timestamp)[:50], "target_format": target_format}
                )
                return formatted
            except (ValueError, TypeError):
                log_forensic_operation(
                    "convert_between_timestamp_types",
                    False,
                    {
                        "input": str(timestamp)[:50],
                        "target_format": target_format,
                        "error": "Failed to convert to numeric type"
                    }
                )
                return formatted  # Return as string if numeric conversion fails
    else:
        # Use as strftime format string
        formatted = format_timestamp(dt, target_format)
        log_forensic_operation(
            "convert_between_timestamp_types",
            formatted is not None,
            {"input": str(timestamp)[:50], "target_format": target_format}
        )
        return formatted


def format_time_human_readable(delta: timedelta) -> str:
    """
    Formats a time duration in a human-readable format.

    Args:
        delta: The time difference to format

    Returns:
        Human-readable string (e.g., "2 days 4 hours 25 minutes")
    """
    seconds = int(delta.total_seconds())

    if seconds < 0:
        sign = "-"
        seconds = abs(seconds)
    else:
        sign = ""

    # Calculate components
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    # Build output string
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0 or days > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0 or not parts:  # Always include seconds if no larger units
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return sign + " ".join(parts)


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Testing Timestamp Utilities ---")

    # Example Timestamps
    iso_ts = "2023-10-27T10:30:00.123456+01:00"
    iso_utc_ts = "2023-10-27T09:30:00.123456Z"
    simple_ts = "2023-10-27 09:30:00"
    epoch_ts = 1698399000.123456  # Corresponds to iso_utc_ts
    filetime_ts = 133428990001234560  # Corresponds to iso_utc_ts
    syslog_ts = "Oct 27 09:30:00 2023"
    invalid_ts = "not a timestamp"
    naive_dt = datetime(2023, 10, 27, 9, 30, 0)
    js_ts = 1698399000123  # JavaScript timestamp (milliseconds)

    timestamps_to_test = [
        iso_ts, iso_utc_ts, simple_ts, epoch_ts, filetime_ts, syslog_ts,
        invalid_ts, naive_dt, get_current_utc_timestamp(), js_ts
    ]

    print("\n--- Normalization ---")
    for ts in timestamps_to_test:
        normalized = normalize_timestamp(ts)
        print(f"Input: {str(ts):<40} | Normalized (UTC): {normalized}")

    print("\n--- Formatting ---")
    dt_to_format = normalize_timestamp(iso_utc_ts)
    if dt_to_format:
        print(f"Original DT: {dt_to_format}")
        print(f"  ISO8601: {format_timestamp(dt_to_format, 'iso8601')}")
        print(f"  Epoch:   {format_timestamp(dt_to_format, 'epoch')}")
        print(f"  FILETIME:{format_timestamp(dt_to_format, 'filetime')}")
        print(f"  JavaScript: {format_timestamp(dt_to_format, 'javascript')}")
        print(f"  Mac Time: {format_timestamp(dt_to_format, 'mac_time')}")
        print(f"  RFC2822: {format_timestamp(dt_to_format, 'rfc2822')}")
        print(f"  HTTP: {format_timestamp(dt_to_format, 'http')}")
        print(f"  Custom:  {format_timestamp(dt_to_format, '%Y/%m/%d %H:%M:%S %Z')}")
        print(f"  Invalid: {format_timestamp(dt_to_format, '%invalid')}")  # Test error handling

    print("\n--- Validation ---")
    print(f"Is '{iso_ts}' valid? {validate_timestamp_string(iso_ts)}")
    print(f"Is '{simple_ts}' valid? {validate_timestamp_string(simple_ts)}")
    print(f"Is '{invalid_ts}' valid? {validate_timestamp_string(invalid_ts)}")
    print(f"Is '2023-02-29' valid? {validate_timestamp_string('2023-02-29')}")  # Invalid date
    print(f"Is '2024-02-29' valid? {validate_timestamp_string('2024-02-29')}")  # Valid leap day

    print("\n--- Comparison ---")
    ts_a = "2023-10-27T10:00:00Z"
    ts_b = epoch_ts  # 09:30:00Z
    print(f"Compare '{ts_a}' and epoch {epoch_ts}: {compare_timestamps(ts_a, ts_b)}")
    print(f"Compare epoch {epoch_ts} and '{ts_a}': {compare_timestamps(ts_b, ts_a)}")
    print(f"Compare '{iso_utc_ts}' and epoch {epoch_ts}: {compare_timestamps(iso_utc_ts, ts_b)}")
    print(f"Compare '{ts_a}' and invalid '{invalid_ts}': {compare_timestamps(ts_a, invalid_ts)}")

    print("\n--- Difference ---")
    diff = calculate_time_difference(ts_b, ts_a)  # 10:00 - 09:30 = 30 mins
    print(f"Difference between epoch {epoch_ts} and '{ts_a}': {diff} (Total seconds: {diff.total_seconds() if diff else 'N/A'})")
    diff_invalid = calculate_time_difference(ts_a, invalid_ts)
    print(f"Difference between '{ts_a}' and invalid '{invalid_ts}': {diff_invalid}")

    print("\n--- Time Range Check ---")
    now = get_current_utc_timestamp()
    past = now - timedelta(days=1)
    future = now + timedelta(days=1)

    print(f"Is current time within yesterday to tomorrow? {is_timestamp_within_range(now, past, future)}")
    print(f"Is epoch timestamp within range? {is_timestamp_within_range(epoch_ts, past, future)}")

    print("\n--- Integrity Validation ---")
    print(f"Is current time valid against itself? {validate_timestamp_integrity(now, now)}")
    old_ts = now - timedelta(days=30)
    print(f"Is month-old timestamp valid? {validate_timestamp_integrity(old_ts, now, timedelta(minutes=10))}")
    print(f"Is month-old timestamp valid with 31-day allowance? {validate_timestamp_integrity(old_ts, now, timedelta(days=31))}")

    print("\n--- Timestamp Type Detection ---")
    print(f"ISO 8601 type: {detect_timestamp_type(iso_ts)}")
    print(f"Unix epoch type: {detect_timestamp_type(epoch_ts)}")
    print(f"FILETIME type: {detect_timestamp_type(filetime_ts)}")
    print(f"JavaScript type: {detect_timestamp_type(js_ts)}")

    print("\n--- Format Conversion ---")
    for fmt in ["datetime", "iso8601", "epoch", "javascript", "filetime", "mac_time", "rfc2822", "%Y-%m-%d"]:
        print(f"Convert '{iso_ts}' to {fmt}: {convert_between_timestamp_types(iso_ts, fmt)}")

    print("\n--- Extract Timestamps from Text ---")
    sample_text = """
    Log entry from 2023-10-27T09:30:00Z shows error code 500.
    Previous check at 1698399000 was successful.
    System booted on Oct 25 08:15:20 2023.
    Next maintenance scheduled for 2023/11/15 14:00:00.
    """

    timestamps = extract_timestamps_from_text(sample_text)
    for dt, text, pos in timestamps:
        print(f"Found: {text} at position {pos} -> {dt.isoformat()}")

    print("\n--- Human Readable Duration ---")
    durations = [
        timedelta(seconds=45),
        timedelta(minutes=5, seconds=15),
        timedelta(hours=3, minutes=20),
        timedelta(days=1, hours=8, minutes=30),
        timedelta(days=7, hours=4),
    ]

    for d in durations:
        print(f"{d} -> {format_time_human_readable(d)}")

    print("\n--- Timestamp Utilities Tests Complete ---")
