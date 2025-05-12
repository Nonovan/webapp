"""
Time series aggregation and processing utilities for metrics data.

This module provides functions for processing, resampling, and analyzing
time series metrics data. It supports various aggregation methods, percentile
calculations, and resampling techniques to transform raw metrics data into
formats suitable for visualization and analysis.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Set, Iterator, Generator, TypedDict
import math
import statistics
from collections import defaultdict
import heapq
from functools import lru_cache
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class TimeSeriesConfig:
    """Configuration constants for time series processing"""
    VALID_INTERVALS: Set[str] = frozenset({'minute', 'hour', 'day'})
    VALID_AGGREGATION_METHODS: Set[str] = frozenset({'avg', 'min', 'max', 'sum', 'median', 'count'})
    DEFAULT_MAX_POINTS: int = 1000
    SECONDS_PER_INTERVAL: Dict[str, int] = {
        'minute': 60,
        'hour': 3600,
        'day': 86400
    }
    MAX_INTERPOLATION_POINTS: int = 5  # Maximum number of points to interpolate between values

class DataPoint(TypedDict):
    """Type definition for a data point"""
    timestamp: str
    value: Union[int, float, None]
    count: Optional[int]

@lru_cache(maxsize=128)
def _get_interval_delta(interval: str) -> timedelta:
    """
    Cache interval delta calculations.

    Args:
        interval: The interval type ('minute', 'hour', 'day')

    Returns:
        timedelta: The corresponding timedelta object

    Raises:
        ValueError: If the interval is not valid
    """
    if interval not in TimeSeriesConfig.VALID_INTERVALS:
        raise ValueError(f"Invalid interval: {interval}")
    return {
        'minute': timedelta(minutes=1),
        'hour': timedelta(hours=1),
        'day': timedelta(days=1)
    }[interval]

def validate_time_series_input(data_points: List[Dict[str, Any]],
                             required_keys: Set[str] = {'timestamp', 'value'}) -> bool:
    """
    Validate time series input data.

    Args:
        data_points: List of data points to validate
        required_keys: Set of required keys in each data point

    Returns:
        bool: True if validation passes

    Raises:
        TypeError: If data_points is not a list or points aren't dictionaries
        ValueError: If required keys are missing
    """
    if not isinstance(data_points, list):
        raise TypeError("data_points must be a list")

    if not data_points:
        return True

    for point in data_points:
        if not isinstance(point, dict):
            raise TypeError("Each data point must be a dictionary")
        if not all(key in point for key in required_keys):
            raise ValueError(f"Each data point must contain keys: {required_keys}")
    return True

def aggregate_time_series(data_points: List[Dict[str, Any]],
                         interval: str,
                         aggregation_method: str = 'avg') -> List[Dict[str, Any]]:
    """
    Aggregate time series data by specified interval and method.

    Args:
        data_points: List of data points with 'timestamp' and 'value' keys
        interval: Time interval for aggregation ('minute', 'hour', 'day')
        aggregation_method: Method to use for aggregation
                           ('avg', 'min', 'max', 'sum', 'median', 'count')

    Returns:
        List[Dict[str, Any]]: Aggregated time series data

    Raises:
        ValueError: If aggregation method is invalid
        TypeError: If input data is malformed
    """
    if not data_points:
        return []

    if aggregation_method not in TimeSeriesConfig.VALID_AGGREGATION_METHODS:
        raise ValueError(f"Invalid aggregation method. Must be one of: {TimeSeriesConfig.VALID_AGGREGATION_METHODS}")

    try:
        validate_time_series_input(data_points)

        # Group data points by interval
        interval_groups = defaultdict(list)

        for point in data_points:
            # Parse the timestamp
            try:
                # Handle both ISO format with and without 'Z' or timezone
                ts_str = point['timestamp']
                if ts_str.endswith('Z'):
                    ts_str = ts_str[:-1] + '+00:00'
                elif '+' not in ts_str and '-' not in ts_str[10:]:  # Check if timezone part is missing
                    ts_str = ts_str + '+00:00'

                ts = datetime.fromisoformat(ts_str)

                # Create interval bucket key based on the interval
                if interval == 'minute':
                    bucket_key = ts.replace(second=0, microsecond=0).isoformat()
                elif interval == 'hour':
                    bucket_key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
                elif interval == 'day':
                    bucket_key = ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                else:
                    raise ValueError(f"Invalid interval: {interval}")

                # Add to the appropriate bucket if value is numeric
                value = point.get('value')
                if value is not None and isinstance(value, (int, float)):
                    interval_groups[bucket_key].append(float(value))
            except (ValueError, KeyError) as e:
                logger.warning(f"Invalid data point in aggregate_time_series: {point}, error: {e}")
                continue

        # Calculate aggregated values for each interval
        result = []
        for bucket_key, values in sorted(interval_groups.items()):
            if not values:
                continue

            # Calculate the aggregated value based on the method
            if aggregation_method == 'avg':
                agg_value = sum(values) / len(values) if values else None
            elif aggregation_method == 'min':
                agg_value = min(values) if values else None
            elif aggregation_method == 'max':
                agg_value = max(values) if values else None
            elif aggregation_method == 'sum':
                agg_value = sum(values) if values else None
            elif aggregation_method == 'median':
                agg_value = statistics.median(values) if values else None
            elif aggregation_method == 'count':
                agg_value = len(values)
            else:
                agg_value = None

            # Format the result with count for additional context
            result.append({
                'timestamp': bucket_key.replace('+00:00', 'Z'),
                'value': agg_value,
                'count': len(values)
            })

        return result
    except Exception as e:
        logger.error(f"Error in aggregate_time_series: {str(e)}", exc_info=True)
        raise

def calculate_percentiles(data_points: List[Dict[str, Any]],
                         percentiles: List[float] = [50, 75, 90, 95, 99]) -> Dict[str, float]:
    """
    Calculate percentile values efficiently using numpy for large datasets.

    Args:
        data_points: List of data points with 'value' key
        percentiles: List of percentile values to calculate

    Returns:
        Dict[str, float]: Dictionary mapping percentile names to values
    """
    if not data_points:
        return {f"p{p}": 0 for p in percentiles}

    # Extract valid numeric values
    values = []
    for point in data_points:
        if isinstance(point.get('value'), (int, float)) and point['value'] is not None:
            values.append(float(point['value']))

    if not values:
        return {f"p{p}": 0 for p in percentiles}

    try:
        # Try to use numpy for efficient calculation
        import numpy as np
        values_array = np.array(values)
        results = np.percentile(values_array, percentiles)
        return {f"p{p}": round(float(v), 3) for p, v in zip(percentiles, results)}
    except ImportError:
        # Fall back to standard library implementation
        return _calculate_percentiles_fallback(values, percentiles)

def _calculate_percentiles_fallback(values: List[float], percentiles: List[float]) -> Dict[str, float]:
    """
    Fallback method to calculate percentiles without numpy.

    Args:
        values: List of numeric values
        percentiles: List of percentiles to calculate

    Returns:
        Dict[str, float]: Dictionary mapping percentile names to values
    """
    if not values:
        return {f"p{p}": 0 for p in percentiles}

    sorted_values = sorted(values)

    def get_percentile(values: List[float], percentile: float) -> float:
        """Calculate a specific percentile value."""
        if not values:
            return 0

        n = len(values)
        k = (n - 1) * (percentile / 100)
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return values[int(k)]

        # Linear interpolation between adjacent values
        d = k - f
        return values[int(f)] * (1 - d) + values[int(c)] * d

    return {f"p{p}": round(get_percentile(sorted_values, p), 3) for p in percentiles}

def resample_time_series(
    data_points: List[Dict[str, Any]],
    interval: str,
    start_time: datetime,
    end_time: datetime,
    max_points: int = TimeSeriesConfig.DEFAULT_MAX_POINTS
) -> List[Dict[str, Any]]:
    """
    Resample time series data to a consistent interval and fill gaps.

    Args:
        data_points: List of data point dictionaries with 'timestamp' and 'value' keys
        interval: Resampling interval ('minute', 'hour', 'day')
        start_time: Start of the time range
        end_time: End of the time range
        max_points: Maximum number of data points to return (default: 1000)

    Returns:
        List[Dict[str, Any]]: Resampled time series data

    Raises:
        ValueError: If input parameters are invalid
        TypeError: If input types are incorrect
    """
    # Validate input parameters
    if interval not in TimeSeriesConfig.VALID_INTERVALS:
        raise ValueError(f"Invalid interval: {interval}")
    if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
        raise TypeError("start_time and end_time must be datetime objects")
    if start_time >= end_time:
        raise ValueError("start_time must be earlier than end_time")
    if not isinstance(max_points, int) or max_points <= 0:
        raise ValueError("max_points must be a positive integer")

    # Get interval delta
    delta = _get_interval_delta(interval)

    # If max_points will limit our output, adjust delta to ensure even distribution
    total_points = (end_time - start_time) // delta + 1
    if total_points > max_points:
        # Calculate a new delta that respects max_points
        total_seconds = (end_time - start_time).total_seconds()
        points_per_interval = total_points / max_points
        adjusted_interval_seconds = total_seconds / max_points
        # Round to nearest minute/hour/day as appropriate
        if adjusted_interval_seconds < 3600:  # Less than an hour
            delta = timedelta(minutes=max(1, round(adjusted_interval_seconds / 60)))
        elif adjusted_interval_seconds < 86400:  # Less than a day
            delta = timedelta(hours=max(1, round(adjusted_interval_seconds / 3600)))
        else:  # Days or more
            delta = timedelta(days=max(1, round(adjusted_interval_seconds / 86400)))

    # If there's no data, generate placeholder data
    if not data_points:
        result = []
        current = start_time
        while current <= end_time:
            result.append({
                'timestamp': current.isoformat().replace('+00:00', 'Z'),
                'value': None
            })
            current += delta
        return result

    # Aggregate the data
    try:
        aggregated = aggregate_time_series(data_points, interval, 'avg')
    except Exception as e:
        logger.error(f"Error aggregating time series: {e}", exc_info=True)
        aggregated = []

    # Create timestamp map for quick lookup
    timestamp_map = {}
    for point in aggregated:
        try:
            ts_str = point['timestamp']
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            ts = datetime.fromisoformat(ts_str)
            timestamp_map[ts] = point['value']
        except (ValueError, KeyError) as e:
            logger.warning(f"Invalid timestamp in aggregated data: {point}, error: {e}")

    # Create resampled series
    resampled = []
    current = start_time

    # Store points that need interpolation for batch processing
    interpolation_points = []

    while current <= end_time and len(resampled) < max_points:
        value = timestamp_map.get(current)

        # If value is missing, mark for potential interpolation
        if value is None:
            interpolation_points.append(current)
        else:
            # If we have pending interpolation points and now found a value,
            # go back and interpolate them if we have enough context
            if interpolation_points:
                # Find previous valid value
                prev_time = current - delta * len(interpolation_points)
                prev_value = timestamp_map.get(prev_time)

                # If we have both endpoints, interpolate all points between
                if prev_value is not None and len(interpolation_points) <= TimeSeriesConfig.MAX_INTERPOLATION_POINTS:
                    total_gap = len(interpolation_points) + 1  # +1 for the current point
                    for i, interp_time in enumerate(interpolation_points, 1):
                        # Linear interpolation
                        ratio = i / total_gap
                        interp_value = prev_value + (value - prev_value) * ratio
                        resampled.append({
                            'timestamp': interp_time.isoformat().replace('+00:00', 'Z'),
                            'value': interp_value
                        })
                else:
                    # Can't interpolate, just add placeholder values
                    for interp_time in interpolation_points:
                        resampled.append({
                            'timestamp': interp_time.isoformat().replace('+00:00', 'Z'),
                            'value': None
                        })

                # Clear the interpolation queue
                interpolation_points = []

            # Add current point with known value
            resampled.append({
                'timestamp': current.isoformat().replace('+00:00', 'Z'),
                'value': value
            })

        current += delta

    # Handle any remaining interpolation points at the end
    for interp_time in interpolation_points:
        resampled.append({
            'timestamp': interp_time.isoformat().replace('+00:00', 'Z'),
            'value': None
        })

    return resampled

def process_large_dataset(data_points: Iterator[Dict[str, Any]],
                         chunk_size: int = 1000,
                         metrics: Optional[Set[str]] = None) -> Generator[Dict[str, Any], None, None]:
    """
    Process large datasets in chunks to reduce memory usage.

    Args:
        data_points: Iterator of data points
        chunk_size: Size of chunks to process at once
        metrics: Set of metrics to calculate (default: all)

    Yields:
        Dict[str, Any]: Processed metrics for each chunk
    """
    default_metrics = {"average", "count", "percentiles", "min", "max"}
    metrics = metrics or default_metrics

    buffer = []
    for point in data_points:
        buffer.append(point)
        if len(buffer) >= chunk_size:
            yield from _process_chunk(buffer, metrics)
            buffer.clear()

    if buffer:
        yield from _process_chunk(buffer, metrics)

def _process_chunk(data_points: List[Dict[str, Any]],
                  metrics: Set[str] = {"average", "count", "percentiles"}) -> Generator[Dict[str, Any], None, None]:
    """
    Process a chunk of data points.

    Args:
        data_points: List of data points to process
        metrics: Set of metrics to calculate

    Yields:
        Dict[str, Any]: Calculated metrics for the chunk
    """
    # Extract numeric values
    values = [float(point['value']) for point in data_points
              if isinstance(point.get('value'), (int, float)) and point['value'] is not None]
    count = len(values)

    if count == 0:
        yield {metric: 0 for metric in metrics}
        return

    result = {}

    # Calculate requested metrics
    if "count" in metrics:
        result["count"] = count

    if "average" in metrics:
        result["average"] = sum(values) / count if count > 0 else 0

    if "min" in metrics:
        result["min"] = min(values) if values else None

    if "max" in metrics:
        result["max"] = max(values) if values else None

    if "percentiles" in metrics:
        # Either extract from data_points or use our pre-calculated values
        result["percentiles"] = calculate_percentiles(data_points)

    yield result

# Fix typo in __all__
__all__ = [
    'TimeSeriesConfig',
    'DataPoint',
    'validate_time_series_input',
    'aggregate_time_series',
    'calculate_percentiles',
    'resample_time_series',
    'process_large_dataset'
]
