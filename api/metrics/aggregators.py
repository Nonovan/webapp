"""
Time series aggregation and processing utilities for metrics data.

This module provides functions for processing, resampling, and analyzing
time series metrics data. It supports various aggregation methods, percentile
calculations, and resampling techniques to transform raw metrics data into
formats suitable for visualization and analysis.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
import math
import statistics
from collections import defaultdict

def aggregate_time_series(
    data_points: List[Dict[str, Any]],
    interval: str,
    aggregation_method: str = 'avg'
) -> List[Dict[str, Any]]:
    """
    Aggregate time series data into consistent intervals.

    Args:
        data_points: List of data point dictionaries with 'timestamp' and 'value' keys
        interval: Aggregation interval ('minute', 'hour', 'day')
        aggregation_method: Method to use for aggregation ('avg', 'min', 'max', 'sum')

    Returns:
        List[Dict[str, Any]]: Aggregated time series data points

    Example:
        data = [{'timestamp': '2023-06-15T14:05:23Z', 'value': 23.4}, ...]
        agg_data = aggregate_time_series(data, 'hour', 'avg')
    """
    if not data_points:
        return []

    # Group data points by their interval bucket
    buckets = defaultdict(list)

    # Get interval in seconds
    seconds_per_interval = {
        'minute': 60,
        'hour': 3600,
        'day': 86400
    }.get(interval.lower(), 3600)  # Default to hour if invalid

    # Parse timestamps and group by interval
    for point in data_points:
        # Skip points without required fields
        if 'timestamp' not in point or 'value' not in point:
            continue

        # Parse the timestamp
        try:
            if isinstance(point['timestamp'], str):
                ts = datetime.fromisoformat(point['timestamp'].replace('Z', '+00:00'))
            else:
                ts = point['timestamp']

            # Create a bucket key by truncating to the interval
            if interval == 'minute':
                bucket_key = ts.replace(second=0, microsecond=0)
            elif interval == 'hour':
                bucket_key = ts.replace(minute=0, second=0, microsecond=0)
            else:  # day
                bucket_key = ts.replace(hour=0, minute=0, second=0, microsecond=0)

            # Add the value to the appropriate bucket
            try:
                value = float(point['value'])
                buckets[bucket_key].append(value)
            except (ValueError, TypeError):
                # Skip non-numeric values
                pass

        except (ValueError, TypeError) as e:
            # Skip invalid timestamps
            continue

    # Aggregate values in each bucket
    result = []
    for bucket, values in sorted(buckets.items()):
        if not values:
            continue

        # Apply aggregation method
        if aggregation_method == 'min':
            agg_value = min(values)
        elif aggregation_method == 'max':
            agg_value = max(values)
        elif aggregation_method == 'sum':
            agg_value = sum(values)
        else:  # default to average
            agg_value = sum(values) / len(values)

        result.append({
            'timestamp': bucket.isoformat().replace('+00:00', 'Z'),
            'value': round(agg_value, 3),
            'count': len(values)
        })

    return result

def calculate_percentiles(
    data_points: List[Dict[str, Any]],
    percentiles: List[float] = [50, 75, 90, 95, 99]
) -> Dict[str, float]:
    """
    Calculate percentile values for a time series dataset.

    Args:
        data_points: List of data point dictionaries with 'value' keys
        percentiles: List of percentiles to calculate (0-100)

    Returns:
        Dict[str, float]: Dictionary of percentile values

    Example:
        data = [{'timestamp': '2023-06-15T14:05:23Z', 'value': 23.4}, ...]
        stats = calculate_percentiles(data, [50, 95, 99])
        print(f"p95: {stats['p95']}")
    """
    if not data_points:
        return {f"p{p}": 0 for p in percentiles}

    # Extract numeric values
    values = []
    for point in data_points:
        try:
            value = float(point['value'])
            values.append(value)
        except (KeyError, ValueError, TypeError):
            pass

    if not values:
        return {f"p{p}": 0 for p in percentiles}

    # Sort values for percentile calculation
    values.sort()

    result = {}
    for p in percentiles:
        if p <= 0:
            result[f"p{p}"] = values[0]
        elif p >= 100:
            result[f"p{p}"] = values[-1]
        else:
            # Calculate index for percentile
            k = (len(values) - 1) * (p / 100)
            f = math.floor(k)
            c = math.ceil(k)

            if f == c:
                result[f"p{p}"] = values[int(k)]
            else:
                # Interpolate between the two surrounding values
                d0 = values[int(f)] * (c - k)
                d1 = values[int(c)] * (k - f)
                result[f"p{p}"] = round(d0 + d1, 3)

    return result

def resample_time_series(
    data_points: List[Dict[str, Any]],
    interval: str,
    start_time: datetime,
    end_time: datetime,
    max_points: int = 1000
) -> List[Dict[str, Any]]:
    """
    Resample time series data to a consistent interval and fill gaps.

    Args:
        data_points: List of data point dictionaries with 'timestamp' and 'value' keys
        interval: Resampling interval ('minute', 'hour', 'day')
        start_time: Start of the time range
        end_time: End of the time range
        max_points: Maximum number of data points to return

    Returns:
        List[Dict[str, Any]]: Resampled time series data

    Example:
        resampled = resample_time_series(data, 'hour', start_date, end_date, 100)
    """
    # If there's no data, generate placeholder data for the timespan
    if not data_points:
        # Determine interval in seconds
        if interval == 'minute':
            delta = timedelta(minutes=1)
        elif interval == 'hour':
            delta = timedelta(hours=1)
        else:  # day
            delta = timedelta(days=1)

        # Calculate how many points we need to generate
        total_duration = end_time - start_time
        total_intervals = int(total_duration.total_seconds() / delta.total_seconds())

        # Limit to max_points
        if total_intervals > max_points:
            # Adjust delta to keep total points within limit
            adjusted_factor = total_intervals / max_points
            delta = timedelta(seconds=delta.total_seconds() * adjusted_factor)
            total_intervals = max_points

        # Generate placeholder data
        result = []
        current = start_time
        for _ in range(total_intervals):
            result.append({
                'timestamp': current.isoformat().replace('+00:00', 'Z'),
                'value': None  # No data available
            })
            current += delta

        return result

    # First, aggregate the data using the specified interval
    aggregated = aggregate_time_series(data_points, interval, 'avg')

    # Determine the interval duration
    if interval == 'minute':
        delta = timedelta(minutes=1)
    elif interval == 'hour':
        delta = timedelta(hours=1)
    else:  # day
        delta = timedelta(days=1)

    # Calculate how many intervals we need for the entire span
    total_intervals = int((end_time - start_time).total_seconds() / delta.total_seconds()) + 1

    # If we'd exceed max points, adjust interval
    if total_intervals > max_points:
        # Calculate a new delta that would give us max_points
        step_factor = math.ceil(total_intervals / max_points)
        delta = timedelta(seconds=delta.total_seconds() * step_factor)
        total_intervals = max_points

    # Create a map of timestamps to values for quick lookup
    timestamp_map = {}
    for point in aggregated:
        try:
            ts = datetime.fromisoformat(point['timestamp'].replace('Z', '+00:00'))
            timestamp_map[ts] = point['value']
        except (ValueError, TypeError):
            pass

    # Create the resampled series with regular intervals
    resampled = []
    current = start_time

    # Round start_time to the beginning of the interval
    if interval == 'minute':
        current = current.replace(second=0, microsecond=0)
    elif interval == 'hour':
        current = current.replace(minute=0, second=0, microsecond=0)
    else:  # day
        current = current.replace(hour=0, minute=0, second=0, microsecond=0)

    # Generate points at regular intervals
    while current <= end_time and len(resampled) < max_points:
        # Use the aggregated value if available, otherwise interpolate or use None
        value = timestamp_map.get(current)

        # If no value and we have surrounding data points, we could interpolate
        # (interpolation logic would go here)

        resampled.append({
            'timestamp': current.isoformat().replace('+00:00', 'Z'),
            'value': value
        })

        current += delta

    return resampled
