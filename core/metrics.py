"""
Metrics management module for the application.

This module provides functionality for recording, tracking, and collecting various metrics
related to HTTP requests, system resources, database performance, and application functions.
It integrates with Prometheus for storing and exposing metrics data.
"""

from datetime import datetime
from functools import wraps
from typing import Callable, Any, TypeVar, cast, Dict
import psutil
from flask import request, current_app
from extensions import metrics, db

# Type alias for callable functions
F = TypeVar('F', bound=Callable[..., Any])


def record_request_metrics() -> None:
    """
    Record HTTP request metrics directly to Prometheus.

    Increments the http_requests_total counter with labels for the
    current request method and endpoint name.
    """
    metrics.info('http_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint
    })


def record_endpoint_metrics() -> None:
    """
    Record endpoint-specific metrics directly to Prometheus.

    Increments the http_requests_by_endpoint_total counter with labels
    for the current request method, path, and endpoint name.
    """
    metrics.info('http_requests_by_endpoint_total', 1, labels={
        'method': request.method,
        'path': request.path,
        'endpoint': request.endpoint
    })


def record_error_metrics(error: Exception) -> None:
    """
    Record error metrics directly to Prometheus.

    Increments the http_errors_total counter with labels for the current
    request method and the error's status code.

    Args:
        error (Exception): The exception that occurred. Expected to have a 'code'
                          attribute. If 'code' is missing, defaults to 500.
    """
    metrics.info('http_errors_total', 1, labels={
        'method': request.method,
        'status': getattr(error, 'code', 500)
    })


def track_metrics(name: str) -> Callable[[F], F]:
    """
    Decorator for tracking function execution metrics.

    This decorator wraps a function to measure its execution time and record
    success/error events to Prometheus with the specified metric prefix.

    Args:
        name (str): Base name for the metrics (will be used as prefix)

    Returns:
        Callable: A decorator function that tracks metrics for the decorated function

    Example:
        @track_metrics('user_service')
        def create_user(user_data):
            # Function implementation
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            start = datetime.utcnow()

            try:
                result = func(*args, **kwargs)
                metrics.info(f'{name}_success', 1, labels={
                    'method': func.__name__
                })
                return result

            except Exception as e:
                metrics.info(f'{name}_error', 1, labels={
                    'method': func.__name__,
                    'error': type(e).__name__
                })
                raise

            finally:
                duration = (datetime.utcnow() - start).total_seconds()
                metrics.info(f'{name}_duration_seconds', duration,
                    labels={'method': func.__name__})

        return cast(F, wrapped)
    return decorator


class SystemMetrics:
    """
    Utility class for collecting system-level metrics.

    Provides methods to gather metrics about CPU, memory, disk usage,
    and network I/O from the host system.
    """

    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """
        Collect current system resource metrics.

        Returns:
            Dict[str, Any]: Dictionary containing various system metrics including:
                - CPU usage percentage
                - Memory usage percentage
                - Disk usage percentage for root partition
                - Network I/O stats (bytes sent/received)
                - Current timestamp
        """
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            },
            'timestamp': datetime.utcnow().isoformat()
        }


class DatabaseMetrics:
    """
    Utility class for collecting database-related metrics.

    Provides methods to gather metrics about database connections,
    query performance, and table sizes.
    """

    @staticmethod
    def get_db_metrics() -> Dict[str, Any]:
        """Collect current database performance metrics."""
        try:
            # Get active connections
            active_connections = db.engine.pool.status()['checkedout']
            
            # Get query statistics from pg_stat_database
            query_stats = db.session.execute("""
                SELECT 
                    total_exec_time,
                    calls,
                    rows,
                    shared_blks_hit,
                    shared_blks_read,
                    temp_files,
                    temp_bytes
                FROM pg_stat_statements 
                WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            """).fetchone()

            # Get slow query count
            slow_queries = db.session.execute("""
                SELECT COUNT(*) 
                FROM pg_stat_statements 
                WHERE mean_exec_time > 1000 
                AND dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            """).scalar()

            # Get error count
            error_count = db.session.execute("""
                SELECT sum(xact_rollback) 
                FROM pg_stat_database 
                WHERE datname = current_database()
            """).scalar()

            # Get table sizes
            table_sizes = db.session.execute("""
                SELECT relname, pg_size_pretty(pg_total_relation_size(relname::regclass)) 
                FROM pg_stat_user_tables
            """).fetchall()

            return {
                'active_connections': active_connections,
                'total_queries': query_stats.calls if query_stats else 0,
                'slow_queries': slow_queries or 0,
                'query_errors': error_count or 0,
                'total_exec_time': query_stats.total_exec_time if query_stats else 0,
                'rows_processed': query_stats.rows if query_stats else 0,
                'cache_hit_ratio': (
                    query_stats.shared_blks_hit / 
                    (query_stats.shared_blks_hit + query_stats.shared_blks_read)
                    if query_stats and (query_stats.shared_blks_hit + query_stats.shared_blks_read) > 0 
                    else 0
                ),
                'table_sizes': dict(table_sizes)
            }
        except Exception as e:
            current_app.logger.error(f"Database metrics collection failed: {e}")
            return {
                'error': str(e),
                'active_connections': -1,
                'total_queries': -1,
                'slow_queries': -1,
                'query_errors': -1,
                'table_sizes': {}
            }
        finally:
            db.session.close()
