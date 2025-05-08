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
    VALID_AGGREGATION_METHODS: Set[str] = frozenset({'avg', 'min', 'max', 'sum', 'median'})
    DEFAULT_MAX_POINTS: int = 1000
    SECONDS_PER_INTERVAL: Dict[str, int] = {
        'minute': 60,
        'hour': 3600,
        'day': 86400
    }

class DataPoint(TypedDict):
    """Type definition for a data point"""
    timestamp: str
    value: Union[int, float]
    count: Optional[int]

@lru_cache(maxsize=128)
def _get_interval_delta(interval: str) -> timedelta:
    """Cache interval delta calculations"""
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

    for point in data_points:
        if not isinstance(point, dict):
            raise TypeError("Each data point must be a dictionary")
        if not all(key in point for key in required_keys):
            raise ValueError(f"Each data point must contain keys: {required_keys}")
    return True

def aggregate_time_series(data_points: List[Dict[str, Any]],
                         interval: str,
                         aggregation_method: str = 'avg') -> List[Dict[str, Any]]:
    """Enhanced aggregation with better error handling"""
    valid_methods = {'avg', 'min', 'max', 'sum', 'median', 'count'}
    if aggregation_method not in valid_methods:
        raise ValueError(f"Invalid aggregation method. Must be one of: {valid_methods}")

    try:
        validate_time_series_input(data_points)
        # ... rest of the function
    except Exception as e:
        logger.error("Error in aggregate_time_series: %s", str(e))
        raise

def calculate_percentiles(data_points: List[Dict[str, Any]], percentiles: List[float] = [50, 75, 90, 95, 99]) -> Dict[str, float]:
    """Calculate percentile values efficiently using numpy for large datasets"""
    if not data_points:
        return {f"p{p}": 0 for p in percentiles}

    try:
        import numpy as np
        # Extract numeric values
        values = np.array([float(point['value']) for point in data_points
                          if isinstance(point.get('value'), (int, float))])

        if len(values) == 0:
            return {f"p{p}": 0 for p in percentiles}

        # Use numpy's efficient percentile calculation
        results = np.percentile(values, percentiles)
        return {f"p{p}": round(float(v), 3) for p, v in zip(percentiles, results)}
    except ImportError:
        # Fallback to current implementation if numpy not available
                return _calculate_percentiles_fallback(data_points, percentiles)

def _calculate_percentiles_fallback(data_points: List[Dict[str, Any]], percentiles: List[float]) -> Dict[str, float]:
    """Fallback method to calculate percentiles without numpy"""
    values = sorted(float(point['value']) for point in data_points if isinstance(point.get('value'), (int, float)))
    if not values:
        return {f"p{p}": 0 for p in percentiles}

    def get_percentile(values: List[float], percentile: float) -> float:
        k = (len(values) - 1) * (percentile / 100)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return values[int(k)]
        return values[int(f)] * (c - k) + values[int(c)] * (k - f)

    return {f"p{p}": round(get_percentile(values, p), 3) for p in percentiles}

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
    aggregated = aggregate_time_series(data_points, interval, 'avg')

    # Create timestamp map for quick lookup
    timestamp_map = {
        datetime.fromisoformat(point['timestamp'].replace('Z', '+00:00')): point['value']
        for point in aggregated
    }

    # Create resampled series
    resampled = []
    current = start_time

    while current <= end_time and len(resampled) < max_points:
        value = timestamp_map.get(current)

        # Interpolate if value is missing
        if value is None:
            prev_time = current - delta
            next_time = current + delta
            prev_value = timestamp_map.get(prev_time)
            next_value = timestamp_map.get(next_time)

            if prev_value is not None and next_value is not None:
                # Linear interpolation
                ratio = (current - prev_time).total_seconds() / (next_time - prev_time).total_seconds()
                value = prev_value + (next_value - prev_value) * ratio

        resampled.append({
            'timestamp': current.isoformat().replace('+00:00', 'Z'),
            'value': value
        })
        current += delta

    return resampled

def process_large_dataset(data_points: Iterator[Dict[str, Any]],
                         chunk_size: int = 1000) -> Generator[Dict[str, Any], None, None]:
    """
    Process large datasets in chunks to reduce memory usage.

    Args:
        data_points: Iterator of data points
        chunk_size: Size of chunks to process at once

    Yields:
        Dict[str, Any]: Processed metrics for each chunk
    """
    buffer = []
    for point in data_points:
        buffer.append(point)
        if len(buffer) >= chunk_size:
            yield from _process_chunk(buffer)
            buffer.clear()

    if buffer:
        yield from _process_chunk(buffer)

def _process_chunk(data_points: List[Dict[str, Any]]) -> Generator[Dict[str, Any], None, None]:
    """
    Process a chunk of data points.

    Args:
        data_points: List of data points to process

    Yields:
        Dict[str, Any]: Calculated metrics for the chunk
    """
    # Calculate average
    total = sum(point['value'] for point in data_points)
    count = len(data_points)
    yield {
        'average': total / count if count > 0 else 0,
        'count': count
    }

    # Calculate percentiles
    yield {
        'percentiles': calculate_percentiles(data_points)
    }

__all___ = [
    'TimeSeriesConfig',
    'DataPoint',

    'validate_time_series_input',
    'aggregate_time_series',
    'calculate_percentiles',
    'resample_time_series',
    'process_large_dataset'
]
