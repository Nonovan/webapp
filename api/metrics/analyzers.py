"""
Metrics analyzers for the Cloud Infrastructure Platform.

This module provides functions for analyzing metrics data, detecting anomalies,
calculating statistics, analyzing trends, and forecasting future values.
It supplies the analytical capabilities needed by the metrics API to provide
insights beyond raw data collection.

Each function is designed to work with time series data and implements
algorithms for statistical analysis, pattern detection, and predictive modeling
appropriate for infrastructure and application metrics.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union, Callable
import statistics as stats

from flask import current_app
from extensions import cache, db, metrics as metrics_registry

# Initialize logger
logger = logging.getLogger(__name__)

# Register metric analyzers with prometheus registry
anomaly_detection_count = metrics_registry.counter(
    'metrics_anomaly_detections_total',
    'Total number of anomaly detection operations',
    labels=['metric_type', 'result']
)

forecasting_operation_count = metrics_registry.counter(
    'metrics_forecasts_total',
    'Total number of forecasting operations',
    labels=['metric_type']
)

trend_analysis_count = metrics_registry.counter(
    'metrics_trend_analyses_total',
    'Total number of trend analysis operations',
    labels=['metric_type']
)


def detect_anomalies(metric_name: str, data_points: List[Dict[str, Any]],
                     sensitivity: str = 'medium') -> List[Dict[str, Any]]:
    """
    Detect anomalies in metrics data using statistical methods.

    This function analyzes time series data to identify data points that
    significantly deviate from normal patterns, which may indicate problems
    or unusual conditions that require attention.

    Args:
        metric_name: Name of the metric being analyzed
        data_points: List of data points with timestamp and value
        sensitivity: Detection sensitivity (low, medium, high)

    Returns:
        List[Dict[str, Any]]: List of detected anomalies with details

    Example:
        anomalies = detect_anomalies('cpu_usage', data_points, sensitivity='medium')
    """
    anomalies = []

    # Check if we have enough data points
    if not data_points or len(data_points) < 5:
        # Not enough data for meaningful anomaly detection
        anomaly_detection_count.inc(1, labels={
            'metric_type': metric_name,
            'result': 'insufficient_data'
        })
        return []

    try:
        # Extract values and timestamps
        values = [float(point.get('value', 0)) for point in data_points
                  if point.get('value') is not None]

        if not values:
            anomaly_detection_count.inc(1, labels={
                'metric_type': metric_name,
                'result': 'no_values'
            })
            return []

        # Calculate statistics
        mean_value = stats.mean(values)

        # Handle case where all values are identical
        if all(v == values[0] for v in values):
            stddev = 0
        else:
            try:
                stddev = stats.stdev(values)
            except stats.StatisticsError:
                # Handle case where stddev calculation fails
                stddev = 0

        # Set threshold based on sensitivity
        thresholds = {
            'low': 3.0,       # 3 sigma - fewer alerts (99.7% of normal data within bounds)
            'medium': 2.5,    # 2.5 sigma - balanced (98.8% of normal data within bounds)
            'high': 2.0       # 2 sigma - more alerts (95.4% of normal data within bounds)
        }

        threshold = thresholds.get(sensitivity.lower(), 2.5)

        # Define anomaly if deviating more than threshold * stddev from mean
        # Skip anomaly detection if standard deviation is 0
        if stddev > 0:
            upper_bound = mean_value + (threshold * stddev)
            lower_bound = mean_value - (threshold * stddev)

            for i, point in enumerate(data_points):
                if point.get('value') is None:
                    continue

                value = float(point.get('value', 0))

                if value > upper_bound or value < lower_bound:
                    # This is an anomaly
                    deviation = abs(value - mean_value) / stddev if stddev > 0 else float('inf')
                    confidence = min(0.99, (deviation - threshold) * 0.1 + 0.7)  # Scale to meaningful confidence values

                    anomaly = {
                        'timestamp': point.get('timestamp'),
                        'value': value,
                        'expected_range': {
                            'lower': round(lower_bound, 3),
                            'upper': round(upper_bound, 3)
                        },
                        'deviation_sigma': round(deviation, 2),
                        'confidence': round(confidence, 2),
                        'type': 'spike' if value > upper_bound else 'dip'
                    }

                    anomalies.append(anomaly)

        # Rate limit detection - look for abnormal rates of change
        if len(values) >= 3:
            # Calculate rates of change
            rates = []
            for i in range(1, len(data_points)):
                prev_value = data_points[i-1].get('value')
                curr_value = data_points[i].get('value')

                if prev_value is not None and curr_value is not None:
                    rate = float(curr_value) - float(prev_value)
                    rates.append(rate)

            if rates:
                rate_mean = stats.mean(rates)
                try:
                    rate_stddev = stats.stdev(rates) if len(rates) > 1 else 0
                except stats.StatisticsError:
                    rate_stddev = 0

                if rate_stddev > 0:
                    rate_upper = rate_mean + (threshold * rate_stddev)
                    rate_lower = rate_mean - (threshold * rate_stddev)

                    for i in range(1, len(data_points)):
                        prev_value = data_points[i-1].get('value')
                        curr_value = data_points[i].get('value')
                        curr_ts = data_points[i].get('timestamp')

                        if prev_value is None or curr_value is None:
                            continue

                        rate = float(curr_value) - float(prev_value)

                        # Check if this rate of change is anomalous
                        if rate > rate_upper or rate < rate_lower:
                            # Only add if we don't already have this point as an anomaly
                            existing = any(a['timestamp'] == curr_ts for a in anomalies)

                            if not existing:
                                rate_deviation = abs(rate - rate_mean) / rate_stddev if rate_stddev > 0 else float('inf')
                                rate_confidence = min(0.99, (rate_deviation - threshold) * 0.1 + 0.7)

                                anomaly = {
                                    'timestamp': curr_ts,
                                    'value': float(curr_value),
                                    'previous_value': float(prev_value),
                                    'rate_of_change': round(rate, 3),
                                    'expected_range': {
                                        'lower': round(prev_value + rate_lower, 3),
                                        'upper': round(prev_value + rate_upper, 3)
                                    },
                                    'confidence': round(rate_confidence, 2),
                                    'type': 'rapid_increase' if rate > rate_upper else 'rapid_decrease'
                                }

                                anomalies.append(anomaly)

        # Log the results
        anomaly_detection_count.inc(1, labels={
            'metric_type': metric_name,
            'result': 'success'
        })

        return anomalies

    except Exception as e:
        logger.error(f"Error detecting anomalies for metric {metric_name}: {str(e)}", exc_info=True)
        anomaly_detection_count.inc(1, labels={
            'metric_type': metric_name,
            'result': 'error'
        })
        return []


def analyze_trends(metric_name: str, period: str = '7d') -> List[Dict[str, Any]]:
    """
    Analyze trends in metrics data over specified time period.

    This function identifies patterns and trends in time series data,
    such as whether a metric is increasing, decreasing, or stable over time,
    as well as identifying cyclical patterns.

    Args:
        metric_name: Name of the metric to analyze
        period: Time period for analysis ('24h', '7d', '30d', '90d')

    Returns:
        List[Dict[str, Any]]: Trend analysis data with timestamps and trend indicators

    Example:
        trends = analyze_trends('memory_usage', period='7d')
    """
    # Convert period to timedelta
    period_map = {
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
        '90d': timedelta(days=90)
    }

    time_period = period_map.get(period, timedelta(days=7))
    end_time = datetime.utcnow()
    start_time = end_time - time_period

    try:
        # Check cache first
        cache_key = f"metric_trends:{metric_name}:{period}"
        cached_trends = cache.get(cache_key)
        if cached_trends:
            return cached_trends

        # In a real implementation, you would fetch the metrics data from your storage system
        # For this example, we'll generate some mock trend data
        trend_data = _generate_mock_trend_data(metric_name, start_time, end_time, period)

        # Analyze trend direction
        if len(trend_data) > 1:
            # Simple linear regression to determine overall trend
            n = len(trend_data)
            x_values = list(range(n))
            y_values = [point['value'] for point in trend_data]

            # Calculate slope using least squares method
            x_mean = sum(x_values) / n
            y_mean = sum(y_values) / n

            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
            denominator = sum((x - x_mean) ** 2 for x in x_values)

            slope = numerator / denominator if denominator != 0 else 0

            # Add trend information
            for point in trend_data:
                # We'll add trend direction for each point
                if 'value' not in point or point['value'] is None:
                    continue

                index = trend_data.index(point)

                if index > 0 and index < len(trend_data) - 1:
                    prev_val = trend_data[index - 1].get('value')
                    next_val = trend_data[index + 1].get('value')
                    curr_val = point.get('value')

                    if prev_val is not None and next_val is not None and curr_val is not None:
                        # Local trend direction
                        if prev_val < curr_val < next_val:
                            point['trend'] = 'increasing'
                        elif prev_val > curr_val > next_val:
                            point['trend'] = 'decreasing'
                        else:
                            point['trend'] = 'fluctuating'

            # Add overall trend information
            if slope > 0.01:
                trend_description = 'increasing'
            elif slope < -0.01:
                trend_description = 'decreasing'
            else:
                trend_description = 'stable'

            # Add metadata to the first point
            if trend_data:
                trend_data[0]['trend_metadata'] = {
                    'overall_trend': trend_description,
                    'slope': round(slope, 4),
                    'period': period,
                    'start_value': trend_data[0]['value'] if trend_data else None,
                    'end_value': trend_data[-1]['value'] if trend_data else None,
                    'percent_change': round(((trend_data[-1]['value'] - trend_data[0]['value']) /
                                           trend_data[0]['value']) * 100, 2) if trend_data and trend_data[0]['value'] != 0 else 0
                }

        # Cache the trend data
        cache_ttl = 900  # 15 minutes
        cache.set(cache_key, trend_data, timeout=cache_ttl)

        trend_analysis_count.inc(1, labels={'metric_type': metric_name})
        return trend_data

    except Exception as e:
        logger.error(f"Error analyzing trends for metric {metric_name}: {str(e)}", exc_info=True)
        return []


def calculate_statistics(data_points: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Calculate statistical measurements for a set of metric data points.

    This function computes common statistical measures such as min, max,
    average, median, standard deviation, and percentiles to summarize
    the time series data.

    Args:
        data_points: List of data points with timestamp and value

    Returns:
        Dict[str, float]: Dictionary of calculated statistics

    Example:
        stats = calculate_statistics(data_points)
        print(f"Average: {stats['avg']}, Max: {stats['max']}")
    """
    if not data_points:
        return {
            'min': 0.0,
            'max': 0.0,
            'avg': 0.0,
            'median': 0.0,
            'stddev': 0.0,
            'p90': 0.0,
            'p95': 0.0,
            'p99': 0.0
        }

    try:
        # Extract values, ignoring None values
        values = [float(point['value']) for point in data_points
                  if point.get('value') is not None]

        if not values:
            return {
                'min': 0.0,
                'max': 0.0,
                'avg': 0.0,
                'median': 0.0,
                'stddev': 0.0,
                'p90': 0.0,
                'p95': 0.0,
                'p99': 0.0
            }

        # Sort values for percentile calculations
        sorted_values = sorted(values)

        # Calculate basic statistics
        result = {
            'min': min(values),
            'max': max(values),
            'avg': stats.mean(values),
            'median': stats.median(values),
            'count': len(values)
        }

        # Add standard deviation
        if len(values) > 1:
            try:
                result['stddev'] = stats.stdev(values)
            except stats.StatisticsError:
                result['stddev'] = 0
        else:
            result['stddev'] = 0

        # Add percentiles
        def percentile(p):
            if not sorted_values:
                return 0
            k = (len(sorted_values) - 1) * (p / 100)
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return sorted_values[int(k)]
            return sorted_values[int(f)] * (c - k) + sorted_values[int(c)] * (k - f)

        result['p90'] = percentile(90)
        result['p95'] = percentile(95)
        result['p99'] = percentile(99)

        # Round numerical values for cleaner output
        return {k: round(v, 3) if isinstance(v, float) else v for k, v in result.items()}

    except Exception as e:
        logger.error(f"Error calculating statistics: {str(e)}", exc_info=True)
        return {
            'min': 0.0,
            'max': 0.0,
            'avg': 0.0,
            'median': 0.0,
            'stddev': 0.0,
            'count': 0,
            'error': str(e)
        }


def forecast_metrics(metric_name: str,
                     trend_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Forecast future metric values based on historical data.

    This function uses time series analysis techniques to predict
    future metric values, which can be used for capacity planning
    and proactive issue prevention.

    Args:
        metric_name: Name of the metric to forecast
        trend_data: Historical trend data with timestamps and values

    Returns:
        Dict[str, Any]: Forecast data including predicted values and confidence levels

    Example:
        forecast = forecast_metrics('disk_usage', trend_data)
    """
    if not trend_data or len(trend_data) < 5:
        return {
            'error': 'Insufficient data for forecasting',
            'data_points': len(trend_data) if trend_data else 0,
            'min_required': 5
        }

    try:
        # Extract values
        values = [float(point.get('value', 0)) for point in trend_data
                  if point.get('value') is not None]

        if len(values) < 5:
            return {
                'error': 'Insufficient valid data points for forecasting',
                'valid_points': len(values),
                'min_required': 5
            }

        # Simple linear regression forecast
        x_values = list(range(len(values)))

        # Calculate slope and intercept using least squares method
        n = len(x_values)
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        slope = numerator / denominator if denominator != 0 else 0
        intercept = y_mean - (slope * x_mean)

        # Calculate forecast points - extend 30% into the future
        forecast_length = max(3, int(len(values) * 0.3))
        forecast_values = []

        # Generate timestamps for forecast
        last_timestamp = datetime.fromisoformat(trend_data[-1]['timestamp'].replace('Z', '+00:00'))
        time_diff = (datetime.fromisoformat(trend_data[-1]['timestamp'].replace('Z', '+00:00')) -
                     datetime.fromisoformat(trend_data[-2]['timestamp'].replace('Z', '+00:00')))

        # Calculate standard error for confidence intervals
        predicted_values = [intercept + slope * x for x in x_values]
        residuals = [y - yhat for y, yhat in zip(values, predicted_values)]

        if len(residuals) < 2:
            std_error = 0
        else:
            try:
                std_error = (sum(res ** 2 for res in residuals) / (len(residuals) - 2)) ** 0.5
            except:
                std_error = 0

        # Generate forecast data points
        for i in range(1, forecast_length + 1):
            x = len(values) - 1 + i
            predicted_value = intercept + slope * x

            # Calculate confidence based on distance from known data
            # We decrease confidence as we predict further into the future
            confidence = max(0.5, 0.95 - (i * 0.03))

            # Generate timestamp
            point_timestamp = (last_timestamp + (time_diff * i)).isoformat().replace('+00:00', 'Z')

            forecast_values.append({
                'timestamp': point_timestamp,
                'value': round(predicted_value, 3),
                'confidence': round(confidence, 2)
            })

        # Create prediction text
        last_known_value = values[-1]
        final_predicted_value = forecast_values[-1]['value']

        if final_predicted_value > last_known_value * 1.20:
            prediction_text = f"Expected to increase significantly (by {round((final_predicted_value/last_known_value - 1)*100, 1)}%) in the forecast period"
        elif final_predicted_value > last_known_value * 1.05:
            prediction_text = f"Expected to increase moderately (by {round((final_predicted_value/last_known_value - 1)*100, 1)}%) in the forecast period"
        elif final_predicted_value < last_known_value * 0.80:
            prediction_text = f"Expected to decrease significantly (by {round((1 - final_predicted_value/last_known_value)*100, 1)}%) in the forecast period"
        elif final_predicted_value < last_known_value * 0.95:
            prediction_text = f"Expected to decrease moderately (by {round((1 - final_predicted_value/last_known_value)*100, 1)}%) in the forecast period"
        else:
            prediction_text = "Expected to remain stable in the forecast period"

        # Predict when certain thresholds will be reached
        threshold_predictions = {}

        # Check if this is a capacity/utilization metric
        if any(substring in metric_name.lower() for substring in ['usage', 'utilization', 'capacity', 'percent']):
            # For capacity metrics, predict when 80% and 90% will be reached
            if last_known_value < 80 and slope > 0:
                points_to_80 = (80 - last_known_value) / slope if slope > 0 else float('inf')
                days_to_80 = points_to_80 * time_diff.total_seconds() / 86400
                if days_to_80 < 90:  # Only predict if within 90 days
                    threshold_predictions['80_percent'] = f"{int(days_to_80)} days"

            if last_known_value < 90 and slope > 0:
                points_to_90 = (90 - last_known_value) / slope if slope > 0 else float('inf')
                days_to_90 = points_to_90 * time_diff.total_seconds() / 86400
                if days_to_90 < 90:  # Only predict if within 90 days
                    threshold_predictions['90_percent'] = f"{int(days_to_90)} days"

        # Construct the forecast result
        forecast_result = {
            'data': forecast_values,
            'model': 'linear_regression',
            'slope': round(slope, 5),
            'prediction': prediction_text,
            'confidence_avg': round(sum(point['confidence'] for point in forecast_values) / len(forecast_values), 2)
        }

        if threshold_predictions:
            forecast_result['threshold_predictions'] = threshold_predictions

        forecasting_operation_count.inc(1, labels={'metric_type': metric_name})
        return forecast_result

    except Exception as e:
        logger.error(f"Error forecasting metrics for {metric_name}: {str(e)}", exc_info=True)
        return {
            'error': f"Forecasting error: {str(e)}",
            'data': []
        }


# --- Helper Functions ---

def _generate_mock_trend_data(metric_name: str, start_time: datetime, end_time: datetime, period: str) -> List[Dict[str, Any]]:
    """
    Generate mock trend data for demonstration purposes.

    In a real implementation, this would be replaced with actual data retrieval
    from your metrics storage.

    Args:
        metric_name: Name of the metric
        start_time: Start time for trend data
        end_time: End time for trend data
        period: Period string ('24h', '7d', etc.)

    Returns:
        List of data points with timestamps and values
    """
    # Choose the appropriate interval based on period
    if period == '24h':
        interval = timedelta(hours=1)
        points = 24
    elif period == '7d':
        interval = timedelta(hours=4)
        points = 42
    elif period == '30d':
        interval = timedelta(hours=8)
        points = 90
    elif period == '90d':
        interval = timedelta(days=1)
        points = 90
    else:
        interval = timedelta(hours=4)
        points = 42

    # Seed the random generator with the metric name for consistent results
    import random
    random.seed(hash(metric_name))

    # Base value depends on metric type
    base_value = 0
    if 'cpu' in metric_name:
        base_value = 45
    elif 'memory' in metric_name:
        base_value = 65
    elif 'disk' in metric_name:
        base_value = 55
    elif 'error' in metric_name:
        base_value = 2
    else:
        base_value = 50

    # Define pattern
    # Generate a list of data points with timestamps
    data = []
    timestamp = start_time

    # Add a small trend based on the metric name
    trend = 0
    if 'cpu' in metric_name:
        trend = 0.1  # Slightly increasing
    elif 'memory' in metric_name:
        trend = 0.2  # More rapidly increasing
    elif 'disk' in metric_name:
        trend = 0.15  # Steadily increasing
    elif 'error' in metric_name:
        trend = -0.05  # Slightly decreasing

    for i in range(points):
        # Add some random variation
        variation = random.uniform(-5, 5)

        # Add trend component
        trend_component = i * trend

        # Calculate value
        value = base_value + variation + trend_component

        # Ensure value is reasonable for percentage metrics
        if 'percent' in metric_name or 'usage' in metric_name:
            value = max(0, min(100, value))

        # Format timestamp
        ts_string = timestamp.isoformat().replace('+00:00', 'Z')

        # Add to data
        data.append({
            'timestamp': ts_string,
            'value': round(value, 2)
        })

        # Increment timestamp
        timestamp += interval

        # Don't go beyond end time
        if timestamp > end_time:
            break

    return data

__all__ = [
    'detect_anomalies',
    'analyze_trends',
    'calculate_statistics',
    'forecast_metrics',
    'anomaly_detection_count',
    'forecasting_operation_count',
    'trend_analysis_count'
]
