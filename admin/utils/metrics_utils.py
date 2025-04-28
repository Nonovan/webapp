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
from typing import Dict, Any, Callable, TypeVar, cast

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
        'timestamp': time.time(),
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
                        if hasattr(core_metrics, 'admin_operation_duration'):
                            core_metrics.admin_operation_duration.labels(
                                operation=name,
                                category=category,
                                status=status
                            ).observe(duration)

                        # Record resource usage
                        if hasattr(core_metrics, 'admin_operation_resources'):
                            core_metrics.admin_operation_resources.labels(
                                operation=name,
                                resource="memory"
                            ).set(end_metrics.get('memory_mb', 0))
                    except Exception as e:
                        logger.warning("Failed to record metrics: %s", e)

        return cast(F, wrapper)
    return decorator

# Example Usage
if __name__ == "__main__":
    @track_operation("test_operation")
    def test_function(sleep_time: float = 0.1) -> None:
        """Test function for demonstrating metrics collection."""
        time.sleep(sleep_time)

    logger.info("Collecting admin metrics...")
    metrics = collect_admin_metrics()
    logger.info("Process metrics: %s", metrics.get('process', {}))
    logger.info("System metrics: %s", metrics.get('system', {}))

    logger.info("Testing operation tracking...")
    test_function(0.2)
