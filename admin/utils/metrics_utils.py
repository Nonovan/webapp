"""
Metrics Collection Utilities for Administrative Tools.

This module provides functions and decorators to collect performance and
usage metrics specifically for administrative scripts and CLI tools.
It helps in monitoring the resource consumption and execution time of
administrative operations, integrating with the platform's core monitoring
systems where possible.
"""

import time
import functools
import logging
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Callable, TypeVar, cast, List, Optional, Union

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from flask import current_app, has_app_context
    from extensions import metrics as core_metrics
    from core.loggings import get_logger
    CORE_METRICS_AVAILABLE = True
    logger = get_logger(__name__)
except ImportError:
    CORE_METRICS_AVAILABLE = False
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core metrics/logging not available, using basic functionality.")

# Try to import core metrics functionality if available
try:
    from core.metrics import track_metrics as core_track_metrics
    CORE_METRICS_TRACK_AVAILABLE = True
except ImportError:
    CORE_METRICS_TRACK_AVAILABLE = False

# Type variable for decorator wrapping
F = TypeVar('F', bound=Callable[..., Any])

def get_process_metrics() -> Dict[str, Any]:
    """
    Collects process-specific metrics including CPU and memory usage.

    Returns:
        Dict containing process metrics or empty dict if collection fails
    """
    if not PSUTIL_AVAILABLE:
        return {}

    try:
        process = psutil.Process(os.getpid())
        with process.oneshot():
            return {
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_mb': process.memory_info().rss / (1024 * 1024),
                'open_files': len(process.open_files()),
                'threads': process.num_threads(),
                'status': process.status()
            }
    except Exception as e:
        logger.error("Failed to collect process metrics: %s", e)
        return {}


def get_system_metrics() -> Dict[str, Any]:
    """
    Collects system-wide metrics relevant to admin operations.

    Returns:
        Dict containing system metrics or empty dict if collection fails
    """
    if not PSUTIL_AVAILABLE:
        return {}

    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            'system_cpu_percent': psutil.cpu_percent(interval=0.1),
            'system_memory_percent': memory.percent,
            'system_disk_percent': disk.percent,
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
        }
    except Exception as e:
        logger.error("Failed to collect system metrics: %s", e)
        return {}


def collect_admin_metrics() -> Dict[str, Any]:
    """
    Collects all metrics relevant to administrative operations.

    Returns:
        Dict containing combined metrics from various sources
    """
    metrics = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'process': get_process_metrics(),
        'system': get_system_metrics()
    }

    # Add core platform metrics if available
    if CORE_METRICS_AVAILABLE and has_app_context():
        try:
            # Get relevant metrics from core system
            if hasattr(core_metrics, 'get_all_metrics'):
                core_data = core_metrics.get_all_metrics()
                metrics['platform'] = {
                    'database': core_data.get('database', {}),
                    'security': core_data.get('security', {}),
                    'application': core_data.get('application', {})
                }
        except Exception as e:
            logger.warning("Failed to collect core metrics: %s", e)

    return metrics


def track_operation(name: str, category: str = "admin") -> Callable[[F], F]:
    """
    Decorator to track execution time and resource usage of admin operations.

    Args:
        name: Name of the operation to track
        category: Category for grouping related operations

    Example:
        @track_operation("user_creation", "user_management")
        def create_user(username: str) -> None:
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.monotonic()
            start_metrics = get_process_metrics()

            try:
                result = func(*args, **kwargs)
                status = "success"
                return result
            except Exception as e:
                status = "error"
                logger.error("Operation '%s' failed: %s", name, str(e))
                raise
            finally:
                duration = time.monotonic() - start_time
                end_metrics = get_process_metrics()

                # Log operation metrics
                log_data = {
                    "operation": name,
                    "category": category,
                    "duration_ms": round(duration * 1000, 2),
                    "status": status,
                    "resource_delta": {
                        "cpu": end_metrics.get('cpu_percent', 0) - start_metrics.get('cpu_percent', 0),
                        "memory_mb": end_metrics.get('memory_mb', 0) - start_metrics.get('memory_mb', 0)
                    }
                }
                logger.info("Admin operation metrics: %s", log_data)

                # Record metrics in core system if available
                if CORE_METRICS_AVAILABLE and has_app_context():
                    try:
                        # Record operation duration
                        if hasattr(core_metrics, 'histogram'):
                            core_metrics.histogram(
                                'admin_operation_duration_seconds',
                                'Duration of administrative operations',
                                labels={
                                    'operation': name,
                                    'category': category,
                                    'status': status
                                }
                            ).observe(duration)

                        # Record resource usage
                        if hasattr(core_metrics, 'gauge'):
                            core_metrics.gauge(
                                'admin_operation_memory_mb',
                                'Memory usage of administrative operations in MB',
                                labels={
                                    'operation': name,
                                    'category': category
                                }
                            ).set(end_metrics.get('memory_mb', 0))

                        # Record operation count
                        if hasattr(core_metrics, 'counter'):
                            core_metrics.counter(
                                'admin_operations_total',
                                'Count of administrative operations',
                                labels={
                                    'operation': name,
                                    'category': category,
                                    'status': status
                                }
                            ).inc()
                    except Exception as e:
                        logger.warning("Failed to record metrics: %s", e)

                # Use the core track metrics if available
                if CORE_METRICS_TRACK_AVAILABLE and not has_app_context():
                    try:
                        core_track_metrics(f"admin_{category}")(lambda: None)()
                    except Exception as e:
                        logger.debug("Core metrics tracking failed: %s", e)

        return cast(F, wrapper)
    return decorator


def record_metric(name: str, value: Union[int, float, bool],
                 category: str = "admin",
                 labels: Optional[Dict[str, str]] = None) -> bool:
    """
    Record a custom metric value.

    Args:
        name: Name of the metric to record
        value: Value to record (numeric or boolean)
        category: Category for grouping related metrics
        labels: Additional labels/dimensions for the metric

    Returns:
        bool: True if recording was successful, False otherwise

    Example:
        record_metric("database_size_mb", 1024.5, "database", {"instance": "primary"})
    """
    if labels is None:
        labels = {}

    metric_name = f"{category}_{name}"

    # Attempt to record through core metrics system if available
    if CORE_METRICS_AVAILABLE and has_app_context():
        try:
            # Determine the appropriate metric type based on value
            if isinstance(value, bool):
                # Use gauge for boolean metrics
                core_metrics.gauge(
                    metric_name,
                    f"{name} metric for {category}",
                    labels=labels
                ).set(1 if value else 0)
            elif isinstance(value, (int, float)):
                # Use gauge for numeric metrics
                core_metrics.gauge(
                    metric_name,
                    f"{name} metric for {category}",
                    labels=labels
                ).set(value)

            logger.debug("Recorded metric %s = %s with labels %s",
                        metric_name, value, labels)
            return True
        except Exception as e:
            logger.warning("Failed to record metric %s: %s", metric_name, e)

    # Fallback to logging the metric
    try:
        log_data = {
            "metric": metric_name,
            "value": value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if labels:
            log_data["labels"] = labels

        logger.info("METRIC: %s", json.dumps(log_data))
        return True
    except Exception as e:
        logger.error("Failed to log metric %s: %s", metric_name, e)
        return False


def get_metrics(categories: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Get current metrics for specified categories.

    Args:
        categories: List of categories to retrieve (None for all)

    Returns:
        Dict containing the requested metrics

    Example:
        metrics = get_metrics(["system", "process"])
    """
    all_metrics = collect_admin_metrics()

    # If no categories specified, return all metrics
    if categories is None:
        return all_metrics

    # Filter metrics by requested categories
    filtered_metrics = {
        'timestamp': all_metrics.get('timestamp', datetime.now(timezone.utc).isoformat())
    }

    for category in categories:
        if category in all_metrics:
            filtered_metrics[category] = all_metrics[category]

    return filtered_metrics


def export_metrics(format_type: str = 'json',
                  output_path: Optional[str] = None,
                  categories: Optional[List[str]] = None) -> Union[str, bool]:
    """
    Export metrics in the specified format.

    Args:
        format_type: Output format ('json', 'prometheus', or 'csv')
        output_path: Path to write output file (None returns as string)
        categories: List of categories to include (None for all)

    Returns:
        str: Formatted metrics if output_path is None
        bool: True if export to file was successful

    Example:
        # Get metrics as JSON string
        json_metrics = export_metrics('json')

        # Export to file
        export_metrics('prometheus', '/var/metrics/admin.prom')
    """
    metrics_data = get_metrics(categories)

    # Format the metrics
    if format_type.lower() == 'json':
        output = json.dumps(metrics_data, indent=2, default=str)
    elif format_type.lower() == 'prometheus':
        output = _format_prometheus(metrics_data)
    elif format_type.lower() == 'csv':
        output = _format_csv(metrics_data)
    else:
        logger.error("Unsupported format type: %s", format_type)
        return False

    # If no output path, return formatted string
    if output_path is None:
        return output

    # Write to file
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(output)
        logger.info("Metrics exported to %s in %s format", output_path, format_type)
        return True
    except Exception as e:
        logger.error("Failed to export metrics to %s: %s", output_path, e)
        return False


# --- Helper functions ---

def _format_prometheus(metrics_data: Dict[str, Any]) -> str:
    """Format metrics in Prometheus exposition format."""
    lines = []
    timestamp_ms = int(time.time() * 1000)

    # Process function for nested dictionaries
    def process_metrics(prefix: str, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            metric_name = f"{prefix}_{key}" if prefix else key

            # If value is a dictionary, recurse
            if isinstance(value, dict):
                process_metrics(metric_name, value)
            # Otherwise if it's a numeric value, add as a metric
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                # Clean metric name for Prometheus (lowercase, no special chars)
                clean_name = metric_name.lower().replace(" ", "_").replace("-", "_")
                # Add help and type lines
                lines.append(f"# HELP admin_{clean_name} {metric_name} metric")
                lines.append(f"# TYPE admin_{clean_name} gauge")
                # Add the metric line
                lines.append(f"admin_{clean_name} {value} {timestamp_ms}")

    # Start processing from root
    for category, data in metrics_data.items():
        if isinstance(data, dict):
            process_metrics(category, data)

    return "\n".join(lines)


def _format_csv(metrics_data: Dict[str, Any]) -> str:
    """Format metrics in CSV format."""
    lines = ["Category,Metric,Value,Timestamp"]
    timestamp = metrics_data.get('timestamp', datetime.now(timezone.utc).isoformat())

    # Process function for nested dictionaries
    def process_metrics(category: str, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            # If value is a dictionary, recurse with updated category
            if isinstance(value, dict):
                process_metrics(f"{category}.{key}", value)
            # Otherwise if it's a value we can represent, add as a row
            elif isinstance(value, (int, float, str, bool)):
                # Format value based on type
                if isinstance(value, bool):
                    csv_value = str(value).lower()
                elif isinstance(value, (int, float)):
                    csv_value = str(value)
                else:  # String values need to be quoted if they contain commas
                    if "," in value:
                        csv_value = f'"{value}"'
                    else:
                        csv_value = value

                lines.append(f"{category},{key},{csv_value},{timestamp}")

    # Start processing from root
    for category, data in metrics_data.items():
        if isinstance(data, dict):
            process_metrics(category, data)

    return "\n".join(lines)


# Example Usage
if __name__ == "__main__":
    @track_operation("test_operation")
    def test_function(sleep_time: float = 0.1) -> None:
        """Test function for demonstrating metrics collection."""
        time.sleep(sleep_time)

    # Test metrics collection
    logger.info("Collecting admin metrics...")
    metrics = collect_admin_metrics()
    logger.info("Process metrics: %s", metrics.get('process', {}))
    logger.info("System metrics: %s", metrics.get('system', {}))

    # Test operation tracking
    logger.info("Testing operation tracking...")
    test_function(0.2)

    # Test record metric
    logger.info("Testing record_metric...")
    record_metric("test_value", 42.5, "test", {"source": "metrics_utils"})

    # Test metric export
    logger.info("Testing export_metrics...")
    json_metrics = export_metrics('json')
    if json_metrics and isinstance(json_metrics, str):
        logger.info("JSON export successful (%d bytes)", len(json_metrics))

    logger.info("Metrics utils self-test complete")
