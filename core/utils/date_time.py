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


def utcnow() -> datetime:
    """
    Get current UTC datetime with timezone information.

    Returns:
        Current UTC datetime with timezone set to UTC
    """
    return datetime.now(timezone.utc)


def localnow() -> datetime:
    """
    Get current local datetime with timezone information.

    Returns:
        Current local datetime with local timezone
    """
    return datetime.now()


def format_datetime(
    dt: datetime,
    format_str: str = "%Y-%m-%d %H:%M:%S",
    use_utc: bool = False
) -> str:
    """
    Format datetime object using the specified format.

    Args:
        dt: Datetime to format
        format_str: Format string
        use_utc: Whether to convert to UTC first

    Returns:
        Formatted datetime string
    """
    if dt is None:
        return ""

    if use_utc and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime(format_str)


def parse_datetime(
    date_string: str,
    format_str: str = "%Y-%m-%d %H:%M:%S",
    assume_utc: bool = False
) -> datetime:
    """
    Parse string into datetime object.

    Args:
        date_string: Date string to parse
        format_str: Format of the string
        assume_utc: Whether to assume UTC timezone if no timezone info

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If the string cannot be parsed
    """
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
        Datetime representing the end of the day (23:59:59)
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
    elif abs_diff.seconds >= 3600:
        hours = abs_diff.seconds // 3600
        unit = f"{hours} hour{'s' if hours > 1 else ''}"
    elif abs_diff.seconds >= 60:
        minutes = abs_diff.seconds // 60
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
        current = add_time_delta(current, days=step_days)

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
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

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
