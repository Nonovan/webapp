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
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Tuple, Dict, Any
import re

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
        filetime_to_datetime as fc_filetime_to_datetime
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


try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_TIMESTAMP_FORMAT, DEFAULT_TIMEZONE
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values for timestamps.")
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = "iso8601" # Corresponds to datetime.isoformat()
    DEFAULT_TIMEZONE_FALLBACK = "UTC" # Should always be UTC for forensics

logger = logging.getLogger(__name__)

# --- Constants ---
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

# Common timestamp formats for parsing (order matters - try more specific first)
# Extended to handle variations like 'Z' for UTC, spaces, and different precision
COMMON_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",  # ISO 8601 with timezone offset
    "%Y-%m-%dT%H:%M:%S.%fZ",   # ISO 8601 with Z (UTC) and microseconds
    "%Y-%m-%dT%H:%M:%S%z",     # ISO 8601 without microseconds
    "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601 with Z (UTC) without microseconds
    "%Y-%m-%d %H:%M:%S.%f%z",  # Space separator with timezone
    "%Y-%m-%d %H:%M:%S.%f Z",  # Space separator with Z (UTC) - handle space
    "%Y-%m-%d %H:%M:%S%z",     # Space separator without microseconds
    "%Y-%m-%d %H:%M:%S Z",     # Space separator with Z (UTC) - handle space
    "%Y-%m-%d %H:%M:%S",       # Common format (assume UTC if no timezone)
    "%Y/%m/%d %H:%M:%S",       # Slash date separator
    "%m/%d/%Y %H:%M:%S",       # US format
    "%d/%m/%Y %H:%M:%S",       # European format
    "%Y%m%d%H%M%S",            # Compact format
    "%b %d %H:%M:%S %Y",       # Syslog format (e.g., Oct 27 10:30:00 2023) - Year at end
    "%b %d %Y %H:%M:%S",       # Syslog format - Year in middle
    "%a %b %d %H:%M:%S %Y",    # E.g., Fri Oct 27 10:30:00 2023
]

# --- Core Functions ---

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
        # Try interpreting as epoch seconds first (most common)
        try:
            # Heuristic: If it's a very large int, it might be FILETIME
            if isinstance(timestamp_input, int) and timestamp_input > 10**15: # Likely FILETIME
                 dt_utc = fc_filetime_to_datetime(timestamp_input)
                 log_forensic_operation(operation, True, {**details, "status": "Interpreted as FILETIME"})
                 return dt_utc
            else: # Assume epoch
                dt_utc = fc_epoch_to_datetime(timestamp_input)
                log_forensic_operation(operation, True, {**details, "status": "Interpreted as epoch"})
                return dt_utc
        except ValueError as e:
            logger.error("Failed to interpret numeric timestamp %s: %s", timestamp_input, e)
            log_forensic_operation(operation, False, {**details, "error": f"Numeric conversion failed: {e}"})
            return None

    elif isinstance(timestamp_input, str):
        timestamp_str = timestamp_input.strip()
        # Handle 'Z' explicitly by replacing it for formats that expect offset
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'
        # Handle space before timezone offset/Z (which might have been replaced)
        if ' Z' in timestamp_str:
             timestamp_str = timestamp_str.replace(' Z', '+00:00')

        parsed_dt = None
        if input_format:
            # Try specified format first
            try:
                parsed_dt = datetime.strptime(timestamp_str, input_format)
            except ValueError:
                logger.debug("Timestamp '%s' did not match specified format '%s'", timestamp_str, input_format)
                # Fall through to try common formats if specified one fails

        if not parsed_dt:
            # Try common formats
            for fmt in COMMON_TIMESTAMP_FORMATS:
                try:
                    parsed_dt = datetime.strptime(timestamp_str, fmt)
                    details["matched_format"] = fmt # Log which format worked
                    break # Stop on first successful parse
                except ValueError:
                    continue # Try next format

        if parsed_dt:
            if parsed_dt.tzinfo is None:
                if assume_utc:
                    dt_utc = parsed_dt.replace(tzinfo=timezone.utc)
                    log_forensic_operation(operation, True, {**details, "status": "Parsed string and assumed UTC"})
                    return dt_utc
                else:
                    logger.warning("Parsed naive timestamp string '%s' and assume_utc is False.", timestamp_input)
                    log_forensic_operation(operation, False, {**details, "error": "Parsed naive string, assume_utc=False"})
                    return None # Cannot normalize without timezone assumption
            else:
                # Convert timezone-aware datetime to UTC
                dt_utc = parsed_dt.astimezone(timezone.utc)
                log_forensic_operation(operation, True, {**details, "status": "Parsed string and converted to UTC"})
                return dt_utc
        else:
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
                       or "iso8601", "epoch", "filetime".

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
        if output_format.lower() == "iso8601":
            formatted = dt_utc.isoformat()
        elif output_format.lower() == "epoch":
            formatted = str(dt_utc.timestamp())
        elif output_format.lower() == "filetime":
            epoch_seconds = dt_utc.timestamp()
            filetime = int(epoch_seconds * HUNDREDS_OF_NANOSECONDS) + EPOCH_AS_FILETIME
            formatted = str(filetime)
        else:
            formatted = dt_utc.strftime(output_format)

        log_forensic_operation(operation, True, details)
        return formatted
    except (ValueError, TypeError) as e:
        logger.error("Failed to format timestamp %s with format '%s': %s", dt_obj, output_format, e)
        log_forensic_operation(operation, False, {**details, "error": str(e)})
        return None


def validate_timestamp_string(timestamp_str: str, expected_format: Optional[str] = None) -> bool:
    """
    Validates if a string represents a recognizable timestamp format.

    Args:
        timestamp_str: The string to validate.
        expected_format: An optional specific format string to check against.

    Returns:
        True if the string can be parsed as a timestamp, False otherwise.
    """
    normalized = normalize_timestamp(timestamp_str, input_format=expected_format)
    is_valid = normalized is not None
    log_forensic_operation("validate_timestamp_string", is_valid, {"input": timestamp_str[:100], "expected_format": expected_format})
    return is_valid


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
        log_forensic_operation("compare_timestamps", False, {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "error": "Normalization failed"})
        return None

    if dt1 < dt2:
        result = -1
    elif dt1 > dt2:
        result = 1
    else:
        result = 0

    log_forensic_operation("compare_timestamps", True, {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "result": result})
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
        log_forensic_operation("calculate_time_difference", False, {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "error": "Normalization failed"})
        return None

    difference = dt2 - dt1
    log_forensic_operation("calculate_time_difference", True, {"ts1": str(ts1)[:50], "ts2": str(ts2)[:50], "difference_seconds": difference.total_seconds()})
    return difference


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Testing Timestamp Utilities ---")

    # Example Timestamps
    iso_ts = "2023-10-27T10:30:00.123456+01:00"
    iso_utc_ts = "2023-10-27T09:30:00.123456Z"
    simple_ts = "2023-10-27 09:30:00"
    epoch_ts = 1698399000.123456 # Corresponds to iso_utc_ts
    filetime_ts = 133428990001234560 # Corresponds to iso_utc_ts
    syslog_ts = "Oct 27 09:30:00 2023"
    invalid_ts = "not a timestamp"
    naive_dt = datetime(2023, 10, 27, 9, 30, 0)

    timestamps_to_test = [
        iso_ts, iso_utc_ts, simple_ts, epoch_ts, filetime_ts, syslog_ts, invalid_ts, naive_dt, get_current_utc_timestamp()
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
        print(f"  Custom:  {format_timestamp(dt_to_format, '%Y/%m/%d %H:%M:%S %Z')}")
        print(f"  Invalid: {format_timestamp(dt_to_format, '%invalid')}") # Test error handling

    print("\n--- Validation ---")
    print(f"Is '{iso_ts}' valid? {validate_timestamp_string(iso_ts)}")
    print(f"Is '{simple_ts}' valid? {validate_timestamp_string(simple_ts)}")
    print(f"Is '{invalid_ts}' valid? {validate_timestamp_string(invalid_ts)}")

    print("\n--- Comparison ---")
    ts_a = "2023-10-27T10:00:00Z"
    ts_b = epoch_ts # 09:30:00Z
    print(f"Compare '{ts_a}' and epoch {epoch_ts}: {compare_timestamps(ts_a, ts_b)}")
    print(f"Compare epoch {epoch_ts} and '{ts_a}': {compare_timestamps(ts_b, ts_a)}")
    print(f"Compare '{iso_utc_ts}' and epoch {epoch_ts}: {compare_timestamps(iso_utc_ts, ts_b)}")
    print(f"Compare '{ts_a}' and invalid '{invalid_ts}': {compare_timestamps(ts_a, invalid_ts)}")

    print("\n--- Difference ---")
    diff = calculate_time_difference(ts_b, ts_a) # 10:00 - 09:30 = 30 mins
    print(f"Difference between epoch {epoch_ts} and '{ts_a}': {diff} (Total seconds: {diff.total_seconds() if diff else 'N/A'})")
    diff_invalid = calculate_time_difference(ts_a, invalid_ts)
    print(f"Difference between '{ts_a}' and invalid '{invalid_ts}': {diff_invalid}")

    print("\n--- Timestamp Utilities Tests Complete ---")
