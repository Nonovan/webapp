"""
Date and time utility functions for Cloud Infrastructure Platform.

This module provides standardized datetime handling operations including:
- Timezone aware conversions
- Formatting for various display contexts
- Duration calculations
- Date comparison and validation
- ISO 8601 handling

These utilities ensure consistent datetime handling across the application.
"""

import time
import datetime
from typing import Optional, Union, Tuple, List, Dict, Any
from datetime import datetime, timezone, timedelta

# Import centralized constants
from core.utils.core_utils_constants import (
    DEFAULT_DATE_FORMAT,
    DEFAULT_TIME_FORMAT,
    DEFAULT_DATETIME_FORMAT,
    ISO_DATETIME_FORMAT,
    LOG_TIMESTAMP_FORMAT,
    FILENAME_TIMESTAMP_FORMAT,
    HUMAN_READABLE_FORMAT,
    DEFAULT_TIMEZONE,
    SECONDS_PER_MINUTE,
    SECONDS_PER_HOUR,
    SECONDS_PER_DAY,
    SECONDS_PER_WEEK,
    SECONDS_PER_MONTH,
    SECONDS_PER_YEAR
)


def localnow() -> datetime:
    """
    Get current local datetime with timezone information.

    Returns:
        Current local datetime with local timezone
    """
    return datetime.now()


def utcnow() -> datetime:
    """
    Get current UTC datetime with timezone information.

    Returns:
        datetime: Current time in UTC with timezone info
    """
    return datetime.now(timezone.utc)


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format datetime as ISO 8601 string.

    Args:
        dt: Datetime to format (default: current time)

    Returns:
        ISO 8601 formatted timestamp string
    """
    if dt is None:
        dt = utcnow()

    # Ensure it has timezone info
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.isoformat()


def now_with_timezone(tz=None) -> datetime:
    """
    Get current datetime with specified timezone.

    If no timezone is specified, returns the current datetime with the system's
    local timezone.

    Args:
        tz: Timezone object (e.g., ZoneInfo('America/New_York')) or None for local

    Returns:
        Current datetime with the specified timezone

    Example:
        >>> from zoneinfo import ZoneInfo
        >>> now_with_timezone(ZoneInfo('Europe/London'))
        datetime.datetime(2023, 7, 15, 14, 30, 15, 123456, tzinfo=ZoneInfo('Europe/London'))
    """
    try:
        import zoneinfo
        if tz is None:
            # Try to get the system timezone
            try:
                system_tz = zoneinfo.ZoneInfo.from_system()
                return datetime.now(system_tz)
            except (zoneinfo.ZoneInfoNotFoundError, OSError):
                # Fall back to naive datetime if system timezone can't be determined
                return datetime.now()
        else:
            # Use the provided timezone
            return datetime.now(tz)
    except ImportError:
        # Fall back to UTC or naive time if zoneinfo is not available (Python < 3.9)
        if tz is None:
            return datetime.now()
        return datetime.now(tz)


def get_timezone(timezone_name: Optional[str] = None) -> Optional[timezone]:
    """
    Get a timezone object by name.

    Args:
        timezone_name: IANA timezone name (e.g., 'America/New_York') or None for system timezone

    Returns:
        Timezone object or None if the timezone name is invalid

    Example:
        >>> tz = get_timezone('Europe/London')
        >>> dt = datetime.now(tz)
    """
    if timezone_name is None:
        timezone_name = DEFAULT_TIMEZONE

    # First try zoneinfo from standard library (Python 3.9+)
    try:
        import zoneinfo

        if timezone_name is None:
            try:
                return zoneinfo.ZoneInfo.from_system()
            except (zoneinfo.ZoneInfoNotFoundError, OSError):
                return timezone.utc

        try:
            return zoneinfo.ZoneInfo(timezone_name)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            # Invalid timezone name
            return None
    except ImportError:
        # For Python < 3.9, try pytz as a fallback
        try:
            import pytz
            if timezone_name is None:
                # Local timezone detection with pytz is complex and often wrong
                return timezone.utc

            try:
                return pytz.timezone(timezone_name)
            except pytz.exceptions.UnknownTimeZoneError:
                return None
        except ImportError:
            # If neither zoneinfo nor pytz is available, return UTC
            # or None for invalid timezone names
            if timezone_name is None or timezone_name.upper() in ('UTC', 'GMT'):
                return timezone.utc
            return None


def convert_timezone(dt: datetime, target_timezone: Union[str, timezone]) -> datetime:
    """
    Convert datetime to a different timezone.

    Args:
        dt: Datetime object to convert
        target_timezone: Target timezone (name or timezone object)

    Returns:
        Datetime object in the target timezone

    Raises:
        ValueError: If the target timezone is invalid or datetime has no timezone

    Example:
        >>> dt_utc = datetime.now(timezone.utc)
        >>> dt_ny = convert_timezone(dt_utc, 'America/New_York')
    """
    # Ensure input datetime has a timezone
    if dt.tzinfo is None:
        raise ValueError("Input datetime must have timezone information")

    # Convert string timezone to timezone object if needed
    if isinstance(target_timezone, str):
        tz_obj = get_timezone(target_timezone)
        if tz_obj is None:
            raise ValueError(f"Invalid timezone name: {target_timezone}")
        target_timezone = tz_obj

    # Convert to target timezone
    return dt.astimezone(target_timezone)


def to_timestamp(dt: datetime) -> float:
    """
    Convert a datetime object to Unix timestamp (seconds since epoch).

    This function handles both timezone-aware and naive datetime objects.
    For naive datetime objects, it assumes UTC.

    Args:
        dt: Datetime object to convert

    Returns:
        Unix timestamp as float

    Example:
        >>> dt = datetime(2023, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
        >>> to_timestamp(dt)
        1689422400.0
    """
    if dt.tzinfo is None:
        # For naive datetime, assume it's in UTC
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()


def from_timestamp(timestamp: float, tz: Optional[timezone] = None) -> datetime:
    """
    Convert a Unix timestamp to a datetime object.

    Args:
        timestamp: Unix timestamp (seconds since epoch)
        tz: Target timezone (defaults to UTC if None)

    Returns:
        Datetime object with requested timezone

    Example:
        >>> from_timestamp(1689422400.0)
        datetime.datetime(2023, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
        >>> from_timestamp(1689422400.0, get_timezone('America/New_York'))
        datetime.datetime(2023, 7, 15, 8, 0, 0, tzinfo=ZoneInfo('America/New_York'))
    """
    if tz is None:
        tz = timezone.utc

    return datetime.fromtimestamp(timestamp, tz=tz)


def format_datetime(
    dt: datetime,
    format_str: str = None,
    use_utc: bool = False
) -> str:
    """
    Format datetime object using the specified format.

    Args:
        dt: Datetime to format
        format_str: Format string (defaults to DEFAULT_DATETIME_FORMAT)
        use_utc: Whether to convert to UTC first

    Returns:
        Formatted datetime string
    """
    if dt is None:
        return ""

    if format_str is None:
        format_str = DEFAULT_DATETIME_FORMAT

    if use_utc and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime(format_str)


def parse_datetime(
    date_string: str,
    format_str: str = None,
    assume_utc: bool = False
) -> datetime:
    """
    Parse string into datetime object.

    Args:
        date_string: Date string to parse
        format_str: Format of the string (defaults to DEFAULT_DATETIME_FORMAT)
        assume_utc: Whether to assume UTC timezone if no timezone info

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If the string cannot be parsed
    """
    if format_str is None:
        format_str = DEFAULT_DATETIME_FORMAT

    dt = datetime.strptime(date_string, format_str)

    if assume_utc and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def parse_iso_datetime(date_string: str, assume_utc: bool = True) -> datetime:
    """
    Parse ISO 8601 datetime string into datetime object.

    Args:
        date_string: ISO 8601 datetime string
        assume_utc: Whether to assume UTC timezone if timezone not specified

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If the string cannot be parsed as ISO format
    """
    try:
        # Handle 'Z' timezone indicator by converting to +00:00
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        # For Python < 3.7 or if fromisoformat fails
        import dateutil.parser
        dt = dateutil.parser.isoparse(date_string)

    # Apply UTC timezone if no timezone specified and assume_utc is True
    if assume_utc and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def to_iso_format(dt: datetime) -> str:
    """
    Convert datetime to ISO 8601 format.

    Args:
        dt: Datetime to convert

    Returns:
        ISO 8601 formatted string
    """
    return dt.isoformat()


def to_unix_timestamp(dt: datetime) -> float:
    """
    Convert datetime to Unix timestamp (seconds since epoch).

    Args:
        dt: Datetime to convert

    Returns:
        Unix timestamp as float
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def from_unix_timestamp(timestamp: float) -> datetime:
    """
    Convert Unix timestamp to datetime.

    Args:
        timestamp: Unix timestamp (seconds since epoch)

    Returns:
        Datetime object with UTC timezone
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def get_start_of_day(dt: datetime = None, use_utc: bool = False) -> datetime:
    """
    Get the start of the day for a given datetime.

    Args:
        dt: Input datetime (defaults to current datetime if None)
        use_utc: Whether to use UTC timezone

    Returns:
        Datetime representing the start of the day (00:00:00)
    """
    if dt is None:
        dt = utcnow() if use_utc else localnow()

    if use_utc and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)

    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def get_end_of_day(dt: datetime = None, use_utc: bool = False) -> datetime:
    """
    Get the end of the day for a given datetime.

    Args:
        dt: Input datetime (defaults to current datetime if None)
        use_utc: Whether to use UTC timezone

    Returns:
        Datetime representing the end of the day (23:59:59.999999)
    """
    if dt is None:
        dt = utcnow() if use_utc else localnow()

    if use_utc and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)

    return dt.replace(hour=23, minute=59, second=59, microsecond=999999)


def format_relative_time(dt: datetime, now: datetime = None) -> str:
    """
    Format datetime as relative time description.

    Args:
        dt: Target datetime
        now: Reference datetime (defaults to current time if None)

    Returns:
        Human-readable relative time string (e.g., "2 hours ago", "in 3 days")
    """
    if now is None:
        # Use UTC if dt has timezone, otherwise use naive datetime
        if dt.tzinfo is not None:
            now = utcnow()
        else:
            now = datetime.now()

    # Ensure both dt and now have compatible timezones
    if dt.tzinfo is not None and now.tzinfo is not None:
        # Both have timezone info, make sure they're in the same timezone
        dt = dt.astimezone(now.tzinfo)
    elif dt.tzinfo is not None and now.tzinfo is None:
        # dt has timezone but now doesn't, remove timezone from dt
        dt = dt.replace(tzinfo=None)
    elif dt.tzinfo is None and now.tzinfo is not None:
        # now has timezone but dt doesn't, use naive comparison
        now = now.replace(tzinfo=None)

    diff = now - dt
    is_past = diff.total_seconds() > 0
    abs_diff = abs(diff)

    # Decide the appropriate unit
    if abs_diff.days > 365:
        years = abs_diff.days // 365
        unit = f"{years} year{'s' if years > 1 else ''}"
    elif abs_diff.days > 30:
        months = abs_diff.days // 30
        unit = f"{months} month{'s' if months > 1 else ''}"
    elif abs_diff.days > 0:
        unit = f"{abs_diff.days} day{'s' if abs_diff.days > 1 else ''}"
    elif abs_diff.seconds >= SECONDS_PER_HOUR:
        hours = abs_diff.seconds // SECONDS_PER_HOUR
        unit = f"{hours} hour{'s' if hours > 1 else ''}"
    elif abs_diff.seconds >= SECONDS_PER_MINUTE:
        minutes = abs_diff.seconds // SECONDS_PER_MINUTE
        unit = f"{minutes} minute{'s' if minutes > 1 else ''}"
    else:
        unit = f"{abs_diff.seconds} second{'s' if abs_diff.seconds != 1 else ''}"

    return f"{unit} ago" if is_past else f"in {unit}"


def add_time_delta(
    dt: datetime,
    years: int = 0,
    months: int = 0,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
    seconds: int = 0
) -> datetime:
    """
    Add a time delta to a datetime object.

    Args:
        dt: The datetime to modify
        years: Years to add
        months: Months to add
        days: Days to add
        hours: Hours to add
        minutes: Minutes to add
        seconds: Seconds to add

    Returns:
        New datetime with delta applied
    """
    result = dt

    # Add years and months (special case because months have different lengths)
    if years or months:
        month = result.month - 1 + months
        year = result.year + years + month // 12
        month = month % 12 + 1

        # Get the last day of the target month
        if result.day > 28:
            last_day = (datetime(year, month + 1, 1) if month < 12 else datetime(year + 1, 1, 1)) - timedelta(days=1)
            day = min(result.day, last_day.day)
        else:
            day = result.day

        result = result.replace(year=year, month=month, day=day)

    # Add days, hours, minutes, seconds
    if days or hours or minutes or seconds:
        result += timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    return result


def is_same_day(dt1: datetime, dt2: datetime) -> bool:
    """
    Check if two datetimes are on the same day.

    Args:
        dt1: First datetime
        dt2: Second datetime

    Returns:
        True if same day, False otherwise
    """
    # Ensure both have compatible timezones for comparison
    if dt1.tzinfo is not None and dt2.tzinfo is not None:
        dt1 = dt1.astimezone(dt2.tzinfo)
    elif dt1.tzinfo is not None and dt2.tzinfo is None:
        dt1 = dt1.replace(tzinfo=None)
    elif dt1.tzinfo is None and dt2.tzinfo is not None:
        dt2 = dt2.replace(tzinfo=None)

    return (dt1.year == dt2.year and dt1.month == dt2.month and dt1.day == dt2.day)


def is_business_day(dt: datetime, holidays: List[datetime] = None) -> bool:
    """
    Check if a date is a business day (not weekend or holiday).

    Args:
        dt: Datetime to check
        holidays: List of holiday datetimes to exclude

    Returns:
        True if business day, False otherwise
    """
    # Check if it's a weekend
    if dt.weekday() >= 5:  # 5=Saturday, 6=Sunday
        return False

    # Check if it's a holiday
    if holidays:
        # Convert to date objects for comparison
        dt_date = dt.date()
        holiday_dates = [h.date() for h in holidays]
        if dt_date in holiday_dates:
            return False

    return True


def date_range(
    start_date: datetime,
    end_date: datetime,
    inclusive: bool = True,
    step_days: int = 1
) -> List[datetime]:
    """
    Generate a range of dates between start_date and end_date.

    Args:
        start_date: Start of the range
        end_date: End of the range
        inclusive: Whether to include end_date in the range
        step_days: Number of days between each date

    Returns:
        List of datetimes in the range
    """
    if start_date > end_date:
        return []

    result = []
    current = start_date

    while current < end_date or (inclusive and current <= end_date):
        result.append(current)
        current = add_time_interval(current, days=step_days)

    return result


def format_duration(seconds: float) -> str:
    """
    Format seconds into human-readable duration.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string (e.g., "2h 30m 15s", "45m 10s", "30s")
    """
    if seconds < 0:
        return "0s"

    # Break down into components
    days, remainder = divmod(int(seconds), SECONDS_PER_DAY)
    hours, remainder = divmod(remainder, SECONDS_PER_HOUR)
    minutes, seconds = divmod(remainder, SECONDS_PER_MINUTE)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")

    return ' '.join(parts[:2])  # Show at most 2 units


def format_timestamp_with_format(dt: Optional[datetime] = None, use_utc: bool = True) -> str:
    """
    Format datetime as ISO 8601 timestamp string.

    This function standardizes timestamp formatting throughout the application,
    ensuring all timestamps are consistently formatted with timezone information.
    It's particularly useful for audit logging, API responses, and data exports.

    Args:
        dt: Datetime to format (defaults to current time if None)
        use_utc: Whether to convert to UTC before formatting

    Returns:
        ISO 8601 formatted timestamp string with timezone information

    Example:
        >>> format_timestamp_with_format()  # Current time in UTC
        '2023-10-27T14:30:00.123456+00:00'
        >>> format_timestamp_with_format(datetime(2023, 10, 27, 14, 30), use_utc=True)
        '2023-10-27T14:30:00+00:00'
    """
    if dt is None:
        dt = utcnow() if use_utc else localnow()

    # Ensure datetime has timezone info
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc if use_utc else None)
    elif use_utc and dt.tzinfo is not timezone.utc:
        dt = dt.astimezone(timezone.utc)

    return dt.isoformat()


def calculate_time_difference(dt1: datetime, dt2: datetime) -> timedelta:
    """
    Calculate the time difference between two datetime objects.

    This function handles timezone differences by normalizing both
    datetimes to the same timezone before calculation.

    Args:
        dt1: First datetime
        dt2: Second datetime

    Returns:
        The time difference as a timedelta object

    Example:
        >>> start = datetime(2023, 1, 1, 10, 0, tzinfo=timezone.utc)
        >>> end = datetime(2023, 1, 1, 12, 30, tzinfo=timezone.utc)
        >>> diff = calculate_time_difference(start, end)
        >>> diff.total_seconds() / 3600  # hours
        2.5
    """
    # Make sure the datetimes have compatible timezones
    if dt1.tzinfo is not None and dt2.tzinfo is not None:
        # Both have timezone info, convert dt2 to dt1's timezone
        dt2 = dt2.astimezone(dt1.tzinfo)
    elif dt1.tzinfo is not None and dt2.tzinfo is None:
        # dt1 has timezone but dt2 doesn't, remove timezone info for comparison
        dt1 = dt1.replace(tzinfo=None)
    elif dt1.tzinfo is None and dt2.tzinfo is not None:
        # dt2 has timezone but dt1 doesn't, remove timezone info for comparison
        dt2 = dt2.replace(tzinfo=None)

    # Calculate difference
    return dt2 - dt1


def is_future_date(dt: datetime, reference_dt: Optional[datetime] = None) -> bool:
    """
    Check if a datetime is in the future.

    Args:
        dt: Datetime to check
        reference_dt: Reference datetime to compare against (default: current time)

    Returns:
        True if dt is in the future, False otherwise

    Example:
        >>> tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
        >>> is_future_date(tomorrow)
        True
    """
    if reference_dt is None:
        reference_dt = datetime.now(timezone.utc)

    # Ensure consistent timezone usage
    if dt.tzinfo is not None and reference_dt.tzinfo is not None:
        # Both have timezone info, normalize
        dt_tz = dt.astimezone(reference_dt.tzinfo)
        return dt_tz > reference_dt
    elif dt.tzinfo is None and reference_dt.tzinfo is not None:
        # Reference has timezone but dt doesn't, convert reference to naive
        reference_naive = reference_dt.replace(tzinfo=None)
        return dt > reference_naive
    elif dt.tzinfo is not None and reference_dt.tzinfo is None:
        # dt has timezone but reference doesn't, convert dt to naive
        dt_naive = dt.replace(tzinfo=None)
        return dt_naive > reference_dt
    else:
        # Both are naive
        return dt > reference_dt


def is_past_date(dt: datetime, reference_dt: Optional[datetime] = None) -> bool:
    """
    Check if a datetime is in the past.

    Args:
        dt: Datetime to check
        reference_dt: Reference datetime to compare against (default: current time)

    Returns:
        True if dt is in the past, False otherwise

    Example:
        >>> yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        >>> is_past_date(yesterday)
        True
    """
    if reference_dt is None:
        reference_dt = datetime.now(timezone.utc)

    # Ensure consistent timezone usage
    if dt.tzinfo is not None and reference_dt.tzinfo is not None:
        # Both have timezone info, normalize
        dt_tz = dt.astimezone(reference_dt.tzinfo)
        return dt_tz < reference_dt
    elif dt.tzinfo is None and reference_dt.tzinfo is not None:
        # Reference has timezone but dt doesn't, convert reference to naive
        reference_naive = reference_dt.replace(tzinfo=None)
        return dt < reference_naive
    elif dt.tzinfo is not None and reference_dt.tzinfo is None:
        # dt has timezone but reference doesn't, convert dt to naive
        dt_naive = dt.replace(tzinfo=None)
        return dt_naive < reference_dt
    else:
        # Both are naive
        return dt < reference_dt


def add_time_interval(
    dt: datetime,
    years: int = 0,
    months: int = 0,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
    seconds: int = 0
) -> datetime:
    """
    Add a time interval to a datetime.

    This function handles adding years and months correctly, accounting for
    varying month lengths and leap years.

    Args:
        dt: The datetime to modify
        years: Years to add
        months: Months to add
        days: Days to add
        hours: Hours to add
        minutes: Minutes to add
        seconds: Seconds to add

    Returns:
        New datetime with interval added

    Example:
        >>> dt = datetime(2023, 1, 15)
        >>> add_time_interval(dt, months=1, days=5)
        datetime.datetime(2023, 2, 20, 0, 0)
    """
    result = dt

    # Add years and months (special handling for month lengths)
    if years or months:
        month = result.month - 1 + months
        year = result.year + years + month // 12
        month = month % 12 + 1

        # Check if we need to adjust the day (e.g., Jan 31 -> Feb 28)
        day = result.day

        # Calculate the last day of the target month
        if day > 28:
            last_day = (datetime(year, month + 1, 1) if month < 12
                      else datetime(year + 1, 1, 1)) - timedelta(days=1)
            day = min(day, last_day.day)

        result = result.replace(year=year, month=month, day=day)

    # Add days, hours, minutes, seconds
    if days or hours or minutes or seconds:
        result += timedelta(
            days=days,
            hours=hours,
            minutes=minutes,
            seconds=seconds
        )

    return result


def beginning_of_day(dt: Optional[datetime] = None, use_utc: bool = False) -> datetime:
    """
    Get the beginning of the day (00:00:00) for a given datetime.

    Args:
        dt: Input datetime (defaults to current datetime if None)
        use_utc: Whether to use UTC timezone

    Returns:
        Datetime representing the start of the day (00:00:00)

    Example:
        >>> dt = datetime(2023, 5, 15, 14, 30, 45)
        >>> beginning_of_day(dt)
        datetime.datetime(2023, 5, 15, 0, 0, 0)
    """
    return get_start_of_day(dt, use_utc)


def end_of_day(dt: Optional[datetime] = None, use_utc: bool = False) -> datetime:
    """
    Get the end of the day (23:59:59.999999) for a given datetime.

    Args:
        dt: Input datetime (defaults to current datetime if None)
        use_utc: Whether to use UTC timezone

    Returns:
        Datetime representing the end of the day (23:59:59.999999)

    Example:
        >>> dt = datetime(2023, 5, 15, 14, 30, 45)
        >>> end_of_day(dt)
        datetime.datetime(2023, 5, 15, 23, 59, 59, 999999)
    """
    return get_end_of_day(dt, use_utc)


# Define what's available for import from this module
__all__ = [
    # Core datetime functions
    'utcnow',
    'localnow',
    'now_with_timezone',
    'format_timestamp',
    'format_timestamp_with_format',
    'format_datetime',
    'parse_datetime',
    'parse_iso_datetime',

    # Timezone operations
    'get_timezone',
    'convert_timezone',

    # Formatting and display
    'format_relative_time',
    'format_duration',
    'to_iso_format',

    # Time calculations and comparison
    'calculate_time_difference',
    'is_same_day',
    'is_business_day',
    'is_future_date',
    'is_past_date',

    # Date ranges and manipulation
    'date_range',
    'add_time_delta',
    'add_time_interval',
    'beginning_of_day',
    'end_of_day',
    'get_start_of_day',
    'get_end_of_day',

    # Timestamp conversions
    'to_timestamp',
    'from_timestamp',
    'to_unix_timestamp',
    'from_unix_timestamp',
]
