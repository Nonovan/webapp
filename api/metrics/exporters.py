"""
Metrics export functionality for the Cloud Infrastructure Platform.

This module provides functions for exporting metrics in various formats including
Prometheus, CSV, and JSON. Each exporter implements proper formatting, data
validation, and security controls to ensure safe and efficient data exports.

The exporters handle complex nested metrics data structures and provide consistent
output across different formats. They support filtering, customizing outputs, and
handling large datasets efficiently.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Union, Optional, Tuple
import csv
import json
from io import StringIO

from flask import current_app, has_app_context

# Initialize logger
logger = logging.getLogger(__name__)


def export_metrics_prometheus(metrics_data: Dict[str, Any],
                             prefix: str = None) -> str:
    """
    Export metrics in Prometheus exposition format.

    This function converts the standard metrics data structure to Prometheus text format,
    including metric types, help text, and proper labeling according to Prometheus best practices.

    Args:
        metrics_data: Dictionary containing metrics data to export
        prefix: Optional prefix for metric names (default: uses app config or 'app_')

    Returns:
        str: Metrics formatted in Prometheus exposition format

    Example:
        prometheus_data = export_metrics_prometheus(metrics_data, prefix='myapp_')
    """
    output = []
    timestamp_ms = int(datetime.utcnow().timestamp() * 1000)

    # Get prefix from config if not specified
    if prefix is None and has_app_context():
        prefix = current_app.config.get('METRICS_PROMETHEUS_PREFIX', 'app_')
    elif prefix is None:
        prefix = 'app_'

    # Track processed metrics to avoid duplicates
    processed_metrics = set()

    # Helper for flattening nested metrics
    def process_metrics(data: Dict[str, Any], path: str = "") -> None:
        for key, value in data.items():
            # Skip special metadata fields
            if key in ('timestamp', '_metadata'):
                continue

            metric_name = f"{path}_{key}" if path else key
            metric_name = prefix + metric_name.lower().replace('.', '_').replace('-', '_')

            # Skip if already processed (avoid duplicates)
            if metric_name in processed_metrics:
                continue

            if isinstance(value, dict):
                # Recurse into nested dictionary
                process_metrics(value, metric_name)
            elif isinstance(value, (int, float)):
                # Process numeric value as a metric
                processed_metrics.add(metric_name)

                # Determine metric type based on name
                metric_type = "gauge"
                if "counter" in metric_name or metric_name.endswith("_total"):
                    metric_type = "counter"
                elif "histogram" in metric_name:
                    metric_type = "histogram"

                # Add help text
                help_text = format_help_text(key)
                output.append(f"# HELP {metric_name} {help_text}")
                output.append(f"# TYPE {metric_name} {metric_type}")

                # Add metric with labels if available
                if isinstance(data.get('_labels'), dict) and data['_labels'].get(key):
                    labels = []
                    for label_key, label_val in data['_labels'][key].items():
                        if isinstance(label_val, (str, int, float, bool)):
                            # Escape quotes in label values
                            label_val_str = str(label_val).replace('"', '\\"')
                            labels.append(f'{label_key}="{label_val_str}"')

                    if labels:
                        output.append(f"{metric_name}{{{','.join(labels)}}} {value} {timestamp_ms}")
                        continue

                # No labels, just add the metric
                output.append(f"{metric_name} {value} {timestamp_ms}")

    # Process top-level categories
    for category, category_data in metrics_data.items():
        if isinstance(category_data, dict):
            process_metrics(category_data, category)

    return "\n".join(output)


def export_metrics_csv(metrics_data: Dict[str, Any]) -> str:
    """
    Export metrics in CSV format.

    This function flattens the nested metrics structure and converts it to a CSV format,
    with proper escaping and formatting of values.

    Args:
        metrics_data: Dictionary containing metrics data to export

    Returns:
        str: CSV-formatted metrics data

    Example:
        csv_data = export_metrics_csv(metrics_data)
    """
    output = StringIO()
    csv_writer = csv.writer(output)

    # Write header row
    csv_writer.writerow(['Category', 'Metric', 'Value', 'Unit'])

    # Get timestamp as ISO8601 for metadata
    timestamp = metrics_data.get('timestamp', datetime.utcnow().isoformat())
    csv_writer.writerow(['Metadata', 'timestamp', timestamp, ''])

    # Helper function to detect units
    def detect_unit(name: str, value: Union[int, float, str]) -> str:
        """Detect appropriate unit based on metric name."""
        if any(substr in name.lower() for substr in ['percent', 'usage', 'utilization']):
            return '%'
        elif any(substr in name.lower() for substr in ['time', 'latency', 'duration']):
            return 'ms' if value < 1000 else 's'
        elif any(substr in name.lower() for substr in ['bytes', 'size']):
            return 'bytes'
        elif any(substr in name.lower() for substr in ['count', 'total', 'num']):
            return 'count'
        return ''

    # Track processed metrics to avoid duplicates
    processed_metrics = set()

    # Process metrics and write to CSV
    def process_metrics(data: Dict[str, Any], category: str, prefix: str = "") -> None:
        for key, value in data.items():
            # Skip special metadata fields and already processed metrics
            if key == '_metadata':
                continue

            metric_name = f"{prefix}.{key}" if prefix else key
            full_key = f"{category}.{metric_name}"

            if full_key in processed_metrics:
                continue

            if isinstance(value, dict):
                # Recurse into nested dictionary
                process_metrics(value, category, metric_name)
            elif isinstance(value, (int, float, str, bool)):
                # Process value as a metric
                processed_metrics.add(full_key)

                # Format value
                formatted_value = value

                # Determine unit
                unit = detect_unit(key, value)

                # Write row
                csv_writer.writerow([category, metric_name, formatted_value, unit])

    # Process top-level categories
    for category, category_data in metrics_data.items():
        # Skip timestamp at the top level
        if category == 'timestamp':
            continue

        if isinstance(category_data, dict):
            process_metrics(category_data, category)
        elif isinstance(category_data, (int, float, str, bool)):
            # Handle flat metrics at the top level
            csv_writer.writerow([category, category, category_data, detect_unit(category, category_data)])

    return output.getvalue()


def export_metrics_json(metrics_data: Dict[str, Any],
                       include_metadata: bool = True) -> str:
    """
    Export metrics in formatted JSON.

    This function structures metrics data as properly formatted JSON with optional
    metadata enrichment.

    Args:
        metrics_data: Dictionary containing metrics data to export
        include_metadata: Whether to include metadata like export timestamp

    Returns:
        str: JSON-formatted metrics data

    Example:
        json_data = export_metrics_json(metrics_data, include_metadata=True)
    """
    # Create a copy to avoid modifying the original
    output_data = metrics_data.copy()

    # Add metadata if requested
    if include_metadata:
        # Add export timestamp if not present
        if 'timestamp' not in output_data:
            output_data['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # Add metadata section with export details
        output_data['_metadata'] = {
            'exported_at': datetime.utcnow().isoformat() + 'Z',
            'format': 'json',
            'version': current_app.config.get('VERSION', '1.0.0') if has_app_context() else '1.0.0'
        }

    # Handle custom JSON serialization issues
    class MetricsEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime):
                return obj.isoformat() + 'Z'
            return super().default(obj)

    # Convert to formatted JSON
    return json.dumps(output_data, indent=2, cls=MetricsEncoder)


# --- Helper functions ---

def format_help_text(metric_name: str) -> str:
    """
    Format help text for Prometheus metrics based on the metric name.

    Args:
        metric_name: Name of the metric

    Returns:
        str: Formatted help text
    """
    # Convert snake_case to spaces and capitalize
    parts = metric_name.split('_')
    text = ' '.join(parts).capitalize()

    # Add context based on metric type
    if 'count' in metric_name or metric_name.endswith('s'):
        return f"Number of {text}"
    elif any(substring in metric_name for substring in ['time', 'duration', 'latency']):
        return f"{text} in seconds"
    elif any(substring in metric_name for substring in ['rate', 'percent', 'usage']):
        return f"{text} ratio"
    elif any(substring in metric_name for substring in ['size', 'bytes']):
        return f"{text} in bytes"

    return text


def flatten_metrics(metrics_data: Dict[str, Any], delimiter: str = '.') -> Dict[str, Any]:
    """
    Flatten a nested metrics dictionary into a single-level dictionary.

    Args:
        metrics_data: Dictionary containing metrics data to flatten
        delimiter: Character to use when joining keys

    Returns:
        Dict[str, Any]: Flattened metrics dictionary
    """
    result = {}

    def _flatten(data: Dict[str, Any], prefix: str = '') -> None:
        for key, value in data.items():
            new_key = f"{prefix}{delimiter}{key}" if prefix else key

            if isinstance(value, dict):
                _flatten(value, new_key)
            else:
                result[new_key] = value

    _flatten(metrics_data)
    return result


def sanitize_metric_name(name: str) -> str:
    """
    Sanitize metric names for Prometheus compatibility.

    Args:
        name: Raw metric name

    Returns:
        str: Sanitized metric name
    """
    # Replace invalid characters with underscores
    sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)

    # Ensure name starts with a letter or underscore
    if sanitized and not (sanitized[0].isalpha() or sanitized[0] == '_'):
        sanitized = f"_{sanitized}"

    return sanitized.lower()


def filter_sensitive_metrics(metrics_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter out sensitive metrics based on configuration.

    Args:
        metrics_data: Dictionary containing metrics data to filter

    Returns:
        Dict[str, Any]: Filtered metrics dictionary
    """
    if not has_app_context():
        return metrics_data

    sensitive_fields = current_app.config.get('METRICS_SENSITIVE_FIELDS', [])
    if not sensitive_fields:
        return metrics_data

    # Create a copy to avoid modifying the original
    result = {}

    def _filter(data, output):
        for key, value in data.items():
            if any(pattern in key.lower() for pattern in sensitive_fields):
                # Skip sensitive fields
                continue

            if isinstance(value, dict):
                output[key] = {}
                _filter(value, output[key])
            else:
                output[key] = value

    _filter(metrics_data, result)
    return result
