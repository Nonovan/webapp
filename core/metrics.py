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

            except db.exc.SQLAlchemyError as e:
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
        """
        Collect current database performance metrics.

        Returns:
            Dict[str, Any]: Dictionary containing various database metrics including:
                - Number of active connections
                - Query statistics (total queries, slow queries, execution time)
                - Cache hit ratio
                - Table sizes from PostgreSQL statistics

        Raises:
            No exceptions are raised; errors are caught and reported in the result.
        """
        results = {
            'active_connections': 0,
            'total_queries': 0,
            'slow_queries': 0,
            'query_errors': 0,
            'total_exec_time': 0,
            'rows_processed': 0,
            'cache_hit_ratio': 0,
            'table_sizes': {}
        }

        try:
            # Get active connections
            results['active_connections'] = DatabaseMetrics._get_active_connections()

            # Get query statistics
            query_stats = DatabaseMetrics._get_query_statistics()
            if query_stats:
                results['total_queries'] = getattr(query_stats, 'calls', 0) or 0
                results['total_exec_time'] = getattr(query_stats, 'total_exec_time', 0) or 0
                results['rows_processed'] = getattr(query_stats, 'rows', 0) or 0

                # Calculate cache hit ratio
                results['cache_hit_ratio'] = DatabaseMetrics._calculate_cache_hit_ratio(query_stats)

            # Get slow query count
            results['slow_queries'] = DatabaseMetrics._get_slow_queries()

            # Get error count
            results['query_errors'] = DatabaseMetrics._get_error_count()

            # Get table sizes
            results['table_sizes'] = DatabaseMetrics._get_table_sizes()

            return results

        except db.exc.SQLAlchemyError as e:
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

    @staticmethod
    def _get_active_connections() -> int:
        """Get the number of active database connections."""
        try:
            if hasattr(db.engine, 'pool') and hasattr(db.engine.pool, 'status'):
                pool_status = db.engine.pool.status()
                if pool_status and isinstance(pool_status, dict):
                    return pool_status.get('checkedout', 0)
        except AttributeError:
            current_app.logger.warning("Could not fetch active connections due to missing attributes")
        return 0

    @staticmethod
    def _get_query_statistics():
        """Get query statistics from pg_stat_statements."""
        try:
            return db.session.execute("""
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
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch query stats due to database error: {e}")
            return None

    @staticmethod
    def _get_slow_queries() -> int:
        """Get count of slow queries (execution time > 1000ms)."""
        try:
            return db.session.execute("""
                SELECT COUNT(*)
                FROM pg_stat_statements
                WHERE mean_exec_time > 1000
                AND dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            """).scalar() or 0
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch slow queries count due to database error: {e}")
            return 0

    @staticmethod
    def _get_error_count() -> int:
        """Get transaction rollback count as a proxy for errors."""
        try:
            return db.session.execute("""
                SELECT sum(xact_rollback)
                FROM pg_stat_database
                WHERE datname = current_database()
            """).scalar() or 0
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch error count due to database error: {e}")
            return 0

    @staticmethod
    def _get_table_sizes() -> Dict[str, str]:
        """Get table sizes for all user tables."""
        try:
            table_sizes_result = db.session.execute("""
                SELECT relname, pg_size_pretty(pg_total_relation_size(relname::regclass))
                FROM pg_stat_user_tables
            """).fetchall()
            return dict(table_sizes_result) if table_sizes_result else {}
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch table sizes due to database error: {e}")
            return {}

    @staticmethod
    def _calculate_cache_hit_ratio(query_stats) -> float:
        """Calculate the cache hit ratio from query statistics."""
        try:
            shared_blks_hit = getattr(query_stats, 'shared_blks_hit', 0) or 0
            shared_blks_read = getattr(query_stats, 'shared_blks_read', 0) or 0
            total_blocks = shared_blks_hit + shared_blks_read
            if total_blocks > 0:
                return shared_blks_hit / total_blocks
        except (AttributeError, TypeError, ZeroDivisionError):
            pass
        return 0
