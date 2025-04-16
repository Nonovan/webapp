"""
Application metrics collection and monitoring system.

This module provides a comprehensive metrics collection framework for monitoring
application performance, resource usage, and error conditions. It integrates with
Prometheus for metrics storage and visualization.

Key features:
- HTTP request and endpoint-specific metrics collection
- Function execution timing and error tracking via decorators
- System resource monitoring (CPU, memory, disk, network)
- Database performance metrics collection
- Integration with Flask and SQLAlchemy for application-level metrics

These metrics enable real-time monitoring, alerting, and performance optimization
based on actual usage patterns and system behavior.
"""
from datetime import datetime, timedelta
import os
from functools import wraps
from typing import Callable, Any, TypeVar, cast, Dict
import psutil
from flask import request, current_app
from sqlalchemy import text
from extensions import metrics, db, cache

# Type alias for callable functions
F = TypeVar('F', bound=Callable[..., Any])


def record_request_metrics() -> None:
    """
    Record HTTP request metrics directly to Prometheus.

    Increments the http_requests_total counter with labels for the
    current request method and endpoint name.

    Returns:
        None: This function records metrics as a side effect

    Example:
        @app.before_request
        def before_request():
            record_request_metrics()
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

    Returns:
        None: This function records metrics as a side effect

    Example:
        @app.before_request
        def before_request():
            record_endpoint_metrics()
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

    Returns:
        None: This function records metrics as a side effect

    Example:
        @app.errorhandler(404)
        def page_not_found(error):
            record_error_metrics(error)
            return "Page not found", 404
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

            except (psutil.Error, AttributeError, ValueError) as e:
                error_type = type(e).__name__
                metrics.info(f'{name}_error', 1, labels={
                    'method': func.__name__,
                    'error': error_type
                })
                
                # Log additional details for certain error types
                if isinstance(e, db.exc.SQLAlchemyError):
                    current_app.logger.error(f"Database error in {func.__name__}: {str(e)}")
                else:
                    current_app.logger.error(f"Error in {func.__name__}: {str(e)}")
                    
                raise

            finally:
                duration = (datetime.utcnow() - start).total_seconds()
                metrics.info(f'{name}_duration_seconds', duration,
                    labels={'method': func.__name__})

        return cast(F, wrapped)
    return decorator


def measure_latency(func: F) -> F:
    """
    Decorator to measure function execution latency.

    This decorator wraps a route function to measure its execution time and record
    it to Prometheus, providing visibility into endpoint performance.

    Args:
        func (Callable): The function to measure

    Returns:
        Callable: The wrapped function with latency measurement

    Example:
        @app.route('/api/users')
        @measure_latency
        def get_users():
            # Route implementation
    """
    @wraps(func)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        start_time = datetime.utcnow()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = (datetime.utcnow() - start_time).total_seconds()
            # Use endpoint or path, with fallbacks
            endpoint = request.endpoint or 'unknown'
            path = request.path or '/unknown'
            
            # Record latency with appropriate labels
            metrics.info('request_latency_seconds', duration, labels={
                'endpoint': endpoint,
                'path': path,
                'method': request.method
            })
            
            # Also record to appropriate histogram if available
            if hasattr(metrics, 'histogram') and callable(getattr(metrics, 'histogram')):
                try:
                    metrics.histogram('request_latency_histogram_seconds', duration, labels={
                        'endpoint': endpoint 
                    })
                except AttributeError:
                    # Ignore errors related to missing attributes in histograms
                    pass
            
    return cast(F, wrapped)


class SystemMetrics:
    """
    Utility class for collecting system-level metrics.

    Provides methods to gather metrics about CPU, memory, disk usage,
    and network I/O from the host system.
    """

    @staticmethod
    @cache.memoize(timeout=60)
    def get_system_metrics() -> Dict[str, Any]:
        """
        Collect comprehensive system metrics.
        
        This function gathers various system-level metrics including CPU usage, memory
        utilization, disk space, and network I/O. It uses the psutil library to gather
        these metrics in a cross-platform compatible way.
        
        Returns:
            Dict[str, Any]: Dictionary containing various system metrics including:
                - cpu_usage: CPU usage percentage
                - memory_usage: Memory usage percentage
                - disk_usage: Disk usage percentage for root partition
                - network: Dict with bytes_sent and bytes_recv
                - load_avg: System load averages tuple
                - boot_time: System boot time as ISO string
                - timestamp: Current UTC timestamp as ISO string
                
        Example:
            metrics = SystemMetrics.get_system_metrics()
            print(f"CPU usage: {metrics['cpu_usage']}%")
        """
        try:
            # Get basic system metrics
            system_metrics = {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Add optional metrics with error handling
            try:
                metrics['load_avg'] = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            except (AttributeError, OSError):
                metrics['load_avg'] = (0, 0, 0)
                
            try:
                metrics['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            except (psutil.Error, OSError, OverflowError):
                metrics['boot_time'] = None
                
            return system_metrics
            
        except (psutil.Error, OSError, ValueError) as e:
            current_app.logger.error(f"Error collecting system metrics: {e}")
            # Return minimal metrics to avoid breaking dependent systems
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'network': {'bytes_sent': 0, 'bytes_recv': 0},
                'load_avg': (0, 0, 0),
                'boot_time': None,
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }

    @staticmethod
    @cache.memoize(timeout=30)
    def get_process_metrics() -> Dict[str, Any]:
        """
        Collect metrics for the current process.
        
        Gathers metrics related to the current Python process including
        memory usage, CPU utilization, threads, and open file handles.
        This provides insight into the application's resource consumption.
        
        Returns:
            Dict[str, Any]: Dictionary containing process metrics:
                - memory_used_mb: Memory usage in MB
                - cpu_percent: CPU utilization percentage
                - threads: Thread count
                - open_files: Open file handle count
                - connections: Network connection count
                - timestamp: Current UTC timestamp as ISO string
                
        Example:
            metrics = SystemMetrics.get_process_metrics()
            print(f"Memory usage: {metrics['memory_used_mb']} MB")
        """
        try:
            process = psutil.Process()
            
            # Basic metrics that should always be available
            process_metrics = {
                'memory_used_mb': process.memory_info().rss / (1024 * 1024),
                'cpu_percent': process.cpu_percent(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Optional metrics that might fail on some platforms
            try:
                process_metrics['threads'] = len(process.threads())
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                process_metrics['threads'] = 0
            
            try:
                process_metrics['open_files'] = len(process.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                process_metrics['open_files'] = 0
                
            try:
                process_metrics['connections'] = len(process.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                process_metrics['connections'] = 0
                
            return process_metrics
            
        except (psutil.Error, OSError, ValueError) as e:
            current_app.logger.error(f"Error collecting process metrics: {e}")
            # Return minimal metrics to avoid breaking dependent systems
            return {
                'memory_used_mb': 0,
                'cpu_percent': 0,
                'threads': 0,
                'open_files': 0,
                'connections': 0,
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
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

        Queries the database for performance statistics including connection counts,
        query execution times, and cache effectiveness to monitor database health
        and performance.

        Returns:
            Dict[str, Any]: Dictionary containing various database metrics including:
                - Number of active connections
                - Query statistics (total queries, slow queries, execution time)
                - Cache hit ratio
                - Table sizes from PostgreSQL statistics

        Raises:
            No exceptions are raised; errors are caught and reported in the result.

        Example:
            metrics = DatabaseMetrics.get_db_metrics()
            print(f"Active connections: {metrics['active_connections']}")
        """
        results = {
            'active_connections': 0,
            'total_queries': 0,
            'slow_queries': 0,
            'query_errors': 0,
            'total_exec_time': 0,
            'rows_processed': 0,
            'cache_hit_ratio': 0,
            'table_sizes': {},
            'timestamp': datetime.utcnow().isoformat()
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
                'table_sizes': {},
                'timestamp': datetime.utcnow().isoformat()
            }
        finally:
            db.session.close()

    @staticmethod
    def _get_active_connections() -> int:
        """
        Get count of active database connections.

        Queries pg_stat_activity to count active connections to the database.

        Returns:
            int: Number of active connections
        """
        try:
            return db.session.execute(text("""
                SELECT count(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
            """)).scalar() or 0
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch connection count due to database error: {e}")
            return -1

    @staticmethod
    def _get_query_statistics():
        """
        Get query statistics from pg_stat_statements.

        Retrieves query execution statistics from the PostgreSQL
        pg_stat_statements extension if available.

        Returns:
            Row: Database row with query statistics or None if unavailable
        """
        try:
            return db.session.execute(text("""
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
            """)).fetchone()
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch query stats due to database error: {e}")
            return None

    @staticmethod
    def _get_slow_queries() -> int:
        """
        Get count of slow queries from pg_stat_statements.

        Identifies queries that took longer than a threshold time to execute,
        which can indicate performance issues.

        Returns:
            int: Number of slow queries (>100ms)
        """
        try:
            return db.session.execute(text("""
                SELECT count(*)
                FROM pg_stat_statements
                WHERE mean_exec_time > 100
                AND dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
            """)).scalar() or 0
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch slow query count due to database error: {e}")
            return 0

    @staticmethod
    def _get_error_count() -> int:
        """
        Get transaction rollback count as a proxy for errors.

        Retrieves the count of transaction rollbacks, which generally
        indicate query errors or application exceptions.

        Returns:
            int: Number of transaction rollbacks
        """
        try:
            return db.session.execute(text("""
                SELECT sum(xact_rollback)
                FROM pg_stat_database
                WHERE datname = current_database()
            """)).scalar() or 0
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch error count due to database error: {e}")
            return 0

    @staticmethod
    def _get_table_sizes() -> Dict[str, str]:
        """
        Get sizes of largest tables in the database.

        Retrieves the sizes of the largest tables in the database to identify
        potential space issues or unexpected growth.

        Returns:
            Dict[str, str]: Dictionary mapping table names to their pretty-printed sizes
        """
        try:
            table_sizes = {}
            result = db.session.execute(text("""
                SELECT
                    table_name,
                    pg_size_pretty(pg_total_relation_size(quote_ident(table_name)))
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY pg_total_relation_size(quote_ident(table_name)) DESC
                LIMIT 10
            """)).fetchall()
            
            for table_name, size in result:
                table_sizes[table_name] = size
                
            return table_sizes
        except db.exc.SQLAlchemyError as e:
            current_app.logger.warning(f"Could not fetch table sizes due to database error: {e}")
            return {}

    @staticmethod
    def _calculate_cache_hit_ratio(query_stats) -> float:
        """
        Calculate cache hit ratio from query statistics.

        Determines what percentage of data blocks were found in the buffer cache
        rather than requiring disk reads.

        Args:
            query_stats: Row object with shared_blks_hit and shared_blks_read attributes

        Returns:
            float: Cache hit ratio as a percentage (0-100)
        """
        if hasattr(query_stats, 'shared_blks_hit') and hasattr(query_stats, 'shared_blks_read'):
            hits = getattr(query_stats, 'shared_blks_hit', 0) or 0
            reads = getattr(query_stats, 'shared_blks_read', 0) or 0
            
            if hits + reads > 0:
                return (hits / (hits + reads)) * 100
                
        return 0.0


class ApplicationMetrics:
    """
    Utility class for collecting application-specific metrics.
    
    Provides methods to gather metrics about application usage, performance,
    and business-specific indicators.
    """
    
    @staticmethod
    @cache.memoize(timeout=60)
    def get_app_metrics() -> Dict[str, Any]:
        """
        Collect application-specific metrics.
        
        Gathers metrics related to application usage and business operations
        such as user counts, active sessions, and feature usage.
        
        Returns:
            Dict[str, Any]: Dictionary containing application metrics:
                - total_users: Total user count
                - active_users: Users active in last 5 minutes
                - uptime: Application uptime
                - version: Application version
                
        Example:
            metrics = ApplicationMetrics.get_app_metrics()
            print(f"Active users: {metrics['active_users']}")
        """
        try:
            # Import here to avoid circular imports
            from models.user import User
            
            # Get application uptime
            uptime = datetime.utcnow() - current_app.uptime if hasattr(current_app, 'uptime') else timedelta(seconds=0)
            
            return {
                'total_users': User.query.count(),
                'active_users': User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(minutes=5))
                ).count(),
                'uptime': str(uptime),
                'version': current_app.config.get('VERSION', '1.0.0'),
                'timestamp': datetime.utcnow().isoformat()
            }
        except (db.exc.SQLAlchemyError, AttributeError, ValueError) as e:
            current_app.logger.error(f"Failed to collect application metrics: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }


class SecurityMetrics:
    """
    Utility class for collecting security-related metrics.
    
    Provides methods to gather metrics about security events, authentication
    attempts, and potential security anomalies.
    """
    
    @staticmethod
    @cache.memoize(timeout=120)
    def get_security_metrics() -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        from core.security_utils import get_security_metrics
        return get_security_metrics()


@cache.memoize(timeout=60)
def get_all_metrics() -> Dict[str, Any]:
    """
    Collect all metrics in a single comprehensive report.
    
    Aggregates system, database, application, and security metrics into
    a single dictionary for dashboard display or health monitoring.
    
    Returns:
        Dict[str, Any]: Dictionary containing all metrics organized by category
        
    Example:
        all_metrics = get_all_metrics()
        print(f"CPU usage: {all_metrics['system']['cpu_usage']}%")
        print(f"Active users: {all_metrics['application']['active_users']}")
    """
    from core.security_utils import get_security_metrics

    try:
        return {
            'system': SystemMetrics.get_system_metrics(),
            'process': SystemMetrics.get_process_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'security': get_security_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    except (psutil.Error, db.exc.SQLAlchemyError, AttributeError, ValueError) as e:
        current_app.logger.error(f"Failed to collect all metrics: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }