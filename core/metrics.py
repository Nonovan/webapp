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
- File integrity monitoring metrics
- Security event tracking

These metrics enable real-time monitoring, alerting, and performance optimization
based on actual usage patterns and system behavior.
"""
from datetime import datetime, timedelta
import os
from functools import wraps
import time
from typing import Callable, Any, TypeVar, cast, Dict, List, Optional, Union
import psutil
from flask import request, current_app, has_app_context, g
from sqlalchemy import text
from extensions import metrics, db, cache
from models.security import LoginAttempt
import logging

logger = logging.getLogger(__name__)

# Type alias for callable functions
F = TypeVar('F', bound=Callable[..., Any])

# Store component status information
_component_registry: Dict[str, Dict[str, Any]] = {}


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
            start = time.monotonic()  # Use monotonic for accurate timing

            try:
                result = func(*args, **kwargs)
                metrics.info(f'{name}_success', 1, labels={
                    'method': func.__name__
                })
                return result

            except Exception as e:
                error_type = type(e).__name__
                metrics.info(f'{name}_error', 1, labels={
                    'method': func.__name__,
                    'error': error_type
                })

                # Log additional details for certain error types
                if has_app_context() and hasattr(current_app, 'logger'):
                    if isinstance(e, db.exc.SQLAlchemyError):
                        current_app.logger.error(f"Database error in {func.__name__}: {str(e)}")
                    else:
                        current_app.logger.error(f"Error in {func.__name__}: {str(e)}")

                raise

            finally:
                duration = time.monotonic() - start
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
        start_time = time.monotonic()  # Use monotonic for accurate timing

        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.monotonic() - start_time
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


def register_component_status(
    component_name: str,
    is_available: bool,
    version: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Register a component's status with the metrics system.

    This function allows components to report their availability status and version
    information to the central metrics system for monitoring and alerting purposes.

    Args:
        component_name: The name of the component being registered
        is_available: Whether the component is available/functioning
        version: Optional version string of the component
        details: Optional dictionary with additional details about the component
    """
    global _component_registry

    try:
        _component_registry[component_name] = {
            "available": bool(is_available),
            "version": version,
            "last_updated": datetime.utcnow().isoformat(),
            "details": details or {}
        }

        logger.debug(f"Component status registered: {component_name}, available={is_available}, version={version}")

        # Update component availability metric for real-time monitoring
        try:
            from extensions import metrics
            metrics.gauge(f"component.{component_name}.available", 1 if is_available else 0)
            if version:
                metrics.label(f"component.{component_name}.version", version)
        except (ImportError, AttributeError):
            # Metrics extension might not be available, which is acceptable
            pass

    except Exception as e:
        logger.warning(f"Failed to register component status for {component_name}: {str(e)}")

def get_component_status(component_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve component status information.

    Args:
        component_name: Optional specific component to get status for.
                        If None, returns status for all components.

    Returns:
        Dictionary with component status information
    """
    if component_name is not None:
        return _component_registry.get(component_name, {"available": False, "error": "Component not registered"})
    return _component_registry

def get_all_component_statuses() -> Dict[str, Dict[str, Any]]:
    """
    Get status information for all registered components.

    Returns:
        Dictionary mapping component names to their status information
    """
    return _component_registry.copy()

def check_critical_components() -> Dict[str, Any]:
    """
    Check the status of all critical platform components.

    Returns:
        Dictionary with critical component status summary and details
    """
    critical_components = [
        "core_security",
        "database",
        "cache",
        "authentication",
        "file_integrity",
        "security_monitoring_utils"
    ]

    results = {
        "all_available": True,
        "components": {}
    }

    for component in critical_components:
        status = get_component_status(component)
        results["components"][component] = status
        if component in _component_registry and not status.get("available", False):
            results["all_available"] = False

    return results


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
                system_metrics['load_avg'] = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            except (AttributeError, OSError):
                system_metrics['load_avg'] = (0, 0, 0)

            try:
                system_metrics['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            except (psutil.Error, OSError, OverflowError):
                system_metrics['boot_time'] = None

            # Add disk space info in GB
            try:
                disk = psutil.disk_usage('/')
                system_metrics['disk_total_gb'] = round(disk.total / (1024**3), 2)
                system_metrics['disk_free_gb'] = round(disk.free / (1024**3), 2)
            except (psutil.Error, OSError):
                system_metrics['disk_total_gb'] = 0
                system_metrics['disk_free_gb'] = 0

            return system_metrics

        except (psutil.Error, OSError, ValueError) as e:
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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

            # Add database size information if available
            try:
                db_size = db.session.execute(text("""
                    SELECT pg_size_pretty(pg_database_size(current_database())) as size,
                           pg_database_size(current_database()) as bytes
                """)).fetchone()
                if db_size:
                    results['database_size_pretty'] = getattr(db_size, 'size', 'Unknown')
                    results['database_size_bytes'] = getattr(db_size, 'bytes', 0)
            except Exception:
                # Non-critical metric, continue if it fails
                pass

            return results

        except db.exc.SQLAlchemyError as e:
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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
            if has_app_context() and hasattr(current_app, 'logger'):
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
        except Exception as e:
            if has_app_context() and hasattr(current_app, 'logger'):
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
        """
        Get comprehensive security metrics.

        Collects security-related metrics such as authentication attempts,
        failed logins, security events, and file integrity status.

        Returns:
            Dict[str, Any]: Dictionary containing security metrics
        """
        try:
            # Try importing using the new security module path first
            try:
                from core.security.cs_metrics import get_security_metrics
                return get_security_metrics()
            except ImportError:
                # Fall back to legacy import
                from core.security_utils import get_security_metrics
                return get_security_metrics()
        except ImportError:
            # If neither exists, return basic metrics from models
            return SecurityMetrics._get_basic_security_metrics()

    @staticmethod
    def _get_basic_security_metrics() -> Dict[str, Any]:
        """
        Get basic security metrics from models.

        This is a fallback when the security modules are not available.

        Returns:
            Dict[str, Any]: Dictionary containing basic security metrics
        """
        metrics_data = {
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            # Get login attempt metrics
            cutoff = datetime.utcnow() - timedelta(hours=24)

            metrics_data.update({
                'login_attempts_24h': LoginAttempt.query.filter(
                    LoginAttempt.timestamp > cutoff
                ).count(),
                'failed_logins_24h': LoginAttempt.query.filter(
                    LoginAttempt.timestamp > cutoff,
                    LoginAttempt.success == False
                ).count()
            })
        except Exception:
            pass

        try:
            # Get audit log metrics
            from models.security.audit_log import AuditLog
            cutoff = datetime.utcnow() - timedelta(hours=24)

            metrics_data.update({
                'audit_logs_24h': AuditLog.query.filter(
                    AuditLog.timestamp > cutoff
                ).count(),
                'security_events_24h': AuditLog.query.filter(
                    AuditLog.timestamp > cutoff,
                    AuditLog.category == 'security'
                ).count(),
                'critical_events_24h': AuditLog.query.filter(
                    AuditLog.timestamp > cutoff,
                    AuditLog.level == 'critical'
                ).count()
            })
        except Exception:
            pass

        return metrics_data


class FileIntegrityMetrics:
    """
    Utility class for collecting file integrity monitoring metrics.

    Provides methods to gather metrics about file integrity status,
    changes detected, and verification results.
    """

    @staticmethod
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_file_integrity_metrics() -> Dict[str, Any]:
        """
        Get file integrity monitoring metrics.

        Collects metrics about the file integrity monitoring system including
        the last check time, number of monitored files, and detected violations.

        Returns:
            Dict[str, Any]: Dictionary containing file integrity metrics
        """
        metrics_data = {
            'monitoring_enabled': has_app_context() and current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', False),
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            # Try using the enhanced file integrity module
            from core.security.cs_file_integrity import get_last_integrity_status

            # Get cached status from the security module
            status = get_last_integrity_status()
            if status:
                metrics_data.update({
                    'last_check': status.get('timestamp'),
                    'monitored_files': status.get('monitored_files_count', 0),
                    'violations': status.get('violations', 0),
                    'critical_violations': status.get('critical_violations', 0),
                    'high_violations': status.get('high_violations', 0),
                    'medium_violations': status.get('medium_violations', 0),
                    'baseline_updated': status.get('baseline_updated'),
                    'status': 'critical' if status.get('critical_violations', 0) > 0 else
                              'warning' if status.get('violations', 0) > 0 else 'healthy'
                })
        except ImportError:
            # Fall back to getting metrics from AuditLog
            try:
                from models.security.audit_log import AuditLog

                # Get file integrity events in the last 24 hours
                cutoff = datetime.utcnow() - timedelta(hours=24)
                integrity_events = AuditLog.query.filter(
                    AuditLog.timestamp > cutoff,
                    AuditLog.event_type == 'file_integrity'
                ).all()

                # Count events by severity
                critical_events = 0
                high_events = 0
                medium_events = 0

                for event in integrity_events:
                    if event.level == 'critical':
                        critical_events += 1
                    elif event.level == 'error':
                        high_events += 1
                    elif event.level == 'warning':
                        medium_events += 1

                metrics_data.update({
                    'violations': len(integrity_events),
                    'critical_violations': critical_events,
                    'high_violations': high_events,
                    'medium_violations': medium_events,
                    'status': 'critical' if critical_events > 0 else
                              'warning' if len(integrity_events) > 0 else 'healthy'
                })

                # Get last check time from the most recent event
                if integrity_events:
                    metrics_data['last_check'] = max(event.timestamp for event in integrity_events)
            except Exception as e:
                if has_app_context() and hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Failed to get file integrity metrics from audit logs: {e}")

        return metrics_data


class FileSystemMetrics:
    """
    Utility class for collecting file system metrics.

    Provides methods to gather metrics about file system usage,
    read/write performance, and storage health across the system.
    """

    @staticmethod
    @cache.memoize(timeout=120)
    def get_filesystem_metrics() -> Dict[str, Any]:
        """
        Collect comprehensive file system metrics.

        Gathers metrics related to disk partitions, I/O performance, file system
        usage, and storage health indicators. These metrics help identify storage
        bottlenecks and capacity issues.

        Returns:
            Dict[str, Any]: Dictionary containing filesystem metrics including:
                - partitions: Details about each mounted filesystem
                - io_counters: Read/write statistics
                - disk_io_time: Disk I/O time in milliseconds
                - timestamp: Current UTC timestamp as ISO string

        Example:
            metrics = FileSystemMetrics.get_filesystem_metrics()
            for partition in metrics['partitions']:
                print(f"{partition['mountpoint']}: {partition['usage_percent']}% full")
        """
        try:
            # Initialize the metrics structure
            fs_metrics = {
                'partitions': [],
                'io_counters': {},
                'timestamp': datetime.utcnow().isoformat()
            }

            # Get all available disk partitions
            try:
                partitions = psutil.disk_partitions(all=False)
                for partition in partitions:
                    # Skip optical and network drives on Windows
                    if partition.fstype == '' or partition.mountpoint == '':
                        continue

                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        partition_data = {
                            'device': partition.device,
                            'mountpoint': partition.mountpoint,
                            'fstype': partition.fstype,
                            'opts': partition.opts,
                            'total_gb': round(usage.total / (1024**3), 2),
                            'used_gb': round(usage.used / (1024**3), 2),
                            'free_gb': round(usage.free / (1024**3), 2),
                            'usage_percent': usage.percent
                        }

                        # Add warning level based on usage percentage
                        if usage.percent >= 90:
                            partition_data['status'] = 'critical'
                        elif usage.percent >= 80:
                            partition_data['status'] = 'warning'
                        elif usage.percent >= 70:
                            partition_data['status'] = 'degraded'
                        else:
                            partition_data['status'] = 'healthy'

                        fs_metrics['partitions'].append(partition_data)
                    except (PermissionError, OSError) as e:
                        # Skip partitions we can't access
                        if has_app_context() and hasattr(current_app, 'logger'):
                            current_app.logger.debug(f"Skipping inaccessible partition {partition.mountpoint}: {str(e)}")
                        continue
            except Exception as e:
                if has_app_context() and hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Error collecting partition metrics: {str(e)}")

            # Get disk I/O stats
            try:
                # Get disk I/O counters for all disks
                io_counters = psutil.disk_io_counters(perdisk=True)
                io_summary = psutil.disk_io_counters(perdisk=False)

                fs_metrics['io_counters'] = {
                    'read_count': io_summary.read_count if io_summary else 0,
                    'write_count': io_summary.write_count if io_summary else 0,
                    'read_bytes': io_summary.read_bytes if io_summary else 0,
                    'write_bytes': io_summary.write_bytes if io_summary else 0,
                    'read_time': io_summary.read_time if io_summary else 0,
                    'write_time': io_summary.write_time if io_summary else 0
                }

                # Add detailed per-disk counters
                fs_metrics['per_disk_io'] = {}
                for disk_name, counters in io_counters.items():
                    fs_metrics['per_disk_io'][disk_name] = {
                        'read_count': counters.read_count,
                        'write_count': counters.write_count,
                        'read_bytes': counters.read_bytes,
                        'write_bytes': counters.write_bytes,
                        'read_time': counters.read_time,
                        'write_time': counters.write_time
                    }

                    # Calculate average read/write speeds
                    if counters.read_count > 0:
                        fs_metrics['per_disk_io'][disk_name]['avg_read_speed_kb'] = round(
                            counters.read_bytes / counters.read_count / 1024, 2)
                    if counters.write_count > 0:
                        fs_metrics['per_disk_io'][disk_name]['avg_write_speed_kb'] = round(
                            counters.write_bytes / counters.write_count / 1024, 2)

            except (AttributeError, OSError) as e:
                if has_app_context() and hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Error collecting disk I/O metrics: {str(e)}")

            # Add inodes usage if on Unix-like systems
            if hasattr(os, 'statvfs'):
                try:
                    fs_metrics['inodes'] = []
                    for partition in fs_metrics['partitions']:
                        mountpoint = partition['mountpoint']
                        try:
                            stats = os.statvfs(mountpoint)
                            total_inodes = stats.f_files
                            free_inodes = stats.f_ffree
                            used_inodes = total_inodes - free_inodes
                            inode_usage = 0 if total_inodes == 0 else (used_inodes / total_inodes) * 100

                            fs_metrics['inodes'].append({
                                'mountpoint': mountpoint,
                                'total_inodes': total_inodes,
                                'used_inodes': used_inodes,
                                'free_inodes': free_inodes,
                                'inode_usage_percent': round(inode_usage, 2)
                            })
                        except (PermissionError, OSError):
                            # Skip partitions we can't check
                            continue
                except Exception as e:
                    if has_app_context() and hasattr(current_app, 'logger'):
                        current_app.logger.warning(f"Error collecting inode metrics: {str(e)}")

            # Calculate overall health status
            health_statuses = [p.get('status', 'healthy') for p in fs_metrics['partitions']]
            if 'critical' in health_statuses:
                fs_metrics['overall_status'] = 'critical'
            elif 'warning' in health_statuses:
                fs_metrics['overall_status'] = 'warning'
            elif 'degraded' in health_statuses:
                fs_metrics['overall_status'] = 'degraded'
            else:
                fs_metrics['overall_status'] = 'healthy'

            return fs_metrics

        except Exception as e:
            if has_app_context() and hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error collecting filesystem metrics: {e}")
            return {
                'error': str(e),
                'partitions': [],
                'io_counters': {},
                'timestamp': datetime.utcnow().isoformat(),
                'overall_status': 'unknown'
            }

    @staticmethod
    @cache.memoize(timeout=600)  # Cache for 10 minutes
    def get_storage_trend_metrics(days: int = 7) -> Dict[str, Any]:
        """
        Get storage usage trend metrics.

        Retrieves historical storage usage data to track growth rates and
        identify potential capacity issues before they become critical.

        Args:
            days (int): Number of days of history to include

        Returns:
            Dict[str, Any]: Dictionary with storage trend information
        """
        try:
            metrics_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'period_days': days,
                'trend_available': False
            }

            # Try to get historical storage data from the database
            try:
                from models.security.system_config import SystemConfig
                cutoff = datetime.utcnow() - timedelta(days=days)

                # Get historical disk usage entries
                disk_entries = SystemConfig.query.filter(
                    SystemConfig.key == 'disk_usage_percent',
                    SystemConfig.updated_at >= cutoff
                ).order_by(SystemConfig.updated_at.asc()).all()

                if disk_entries:
                    # Calculate storage growth trend
                    values = []
                    timestamps = []

                    for entry in disk_entries:
                        try:
                            value = float(entry.value)
                            values.append(value)
                            timestamps.append(entry.updated_at.isoformat())
                        except (ValueError, TypeError):
                            continue

                    if len(values) >= 2:
                        metrics_data['trend_available'] = True
                        metrics_data['values'] = values
                        metrics_data['timestamps'] = timestamps

                        # Calculate simple growth metrics
                        first_value = values[0]
                        last_value = values[-1]
                        change = last_value - first_value

                        metrics_data['first_value'] = first_value
                        metrics_data['current_value'] = last_value
                        metrics_data['absolute_change'] = round(change, 2)
                        metrics_data['percent_change'] = round((change / first_value * 100) if first_value > 0 else 0, 2)

                        # Calculate daily growth rate
                        if len(values) > 2 and len(timestamps) > 2:
                            first_date = datetime.fromisoformat(timestamps[0])
                            last_date = datetime.fromisoformat(timestamps[-1])
                            days_diff = (last_date - first_date).total_seconds() / 86400
                            if days_diff > 0:
                                metrics_data['daily_growth_rate'] = round(change / days_diff, 3)

                                # Estimate days until full (90% is considered "full")
                                if change > 0:  # Only if disk usage is increasing
                                    days_until_full = (90 - last_value) / (change / days_diff)
                                    metrics_data['days_until_critical'] = round(days_until_full, 1)

                                    if days_until_full <= 7:
                                        metrics_data['trend_status'] = 'critical'
                                    elif days_until_full <= 30:
                                        metrics_data['trend_status'] = 'warning'
                                    else:
                                        metrics_data['trend_status'] = 'healthy'
                                else:
                                    metrics_data['trend_status'] = 'healthy'
            except (ImportError, AttributeError, Exception) as e:
                if has_app_context() and hasattr(current_app, 'logger'):
                    current_app.logger.debug(f"Could not calculate storage trends: {str(e)}")
                # We'll return the metrics without the trend data

            return metrics_data

        except Exception as e:
            if has_app_context() and hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error collecting storage trend metrics: {e}")
            return {
                'error': str(e),
                'trend_available': False,
                'timestamp': datetime.utcnow().isoformat()
            }


@cache.memoize(timeout=60)
def get_all_metrics() -> Dict[str, Any]:
    """
    Collect all metrics in a single comprehensive report.

    Aggregates system, database, application, security, file integrity metrics,
    and filesystem metrics into a single dictionary for dashboard display or health monitoring.

    Returns:
        Dict[str, Any]: Dictionary containing all metrics organized by category

    Example:
        all_metrics = get_all_metrics()
        print(f"CPU usage: {all_metrics['system']['cpu_usage']}%")
        print(f"Active users: {all_metrics['application']['active_users']}")
        print(f"Disk usage: {all_metrics['filesystem']['overall_status']}")
    """
    try:
        metrics_data = {
            'system': SystemMetrics.get_system_metrics(),
            'process': SystemMetrics.get_process_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'security': SecurityMetrics.get_security_metrics(),
            'file_integrity': FileIntegrityMetrics.get_file_integrity_metrics(),
            'filesystem': FileSystemMetrics.get_filesystem_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }

        # Add health status summary
        metrics_data['health_status'] = _calculate_health_status(metrics_data)

        return metrics_data
    except Exception as e:
        if has_app_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Failed to collect all metrics: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


def _calculate_health_status(metrics: Dict[str, Any]) -> str:
    """
    Calculate overall health status based on collected metrics.

    Determines the overall health status of the application based on
    thresholds for various metrics. Used for high-level reporting.

    Args:
        metrics: Dictionary containing all collected metrics

    Returns:
        str: Health status ("healthy", "degraded", "warning", or "critical")
    """
    # Start with healthy status
    status = "healthy"

    # Check system metrics
    system = metrics.get('system', {})
    if system.get('cpu_usage', 0) > 90 or system.get('memory_usage', 0) > 90:
        status = "critical"
    elif system.get('cpu_usage', 0) > 80 or system.get('memory_usage', 0) > 80:
        status = max(status, "warning")

    # Check disk usage
    if system.get('disk_usage', 0) > 90:
        status = "critical"
    elif system.get('disk_usage', 0) > 80:
        status = max(status, "warning")

    # Check filesystem metrics
    filesystem = metrics.get('filesystem', {})
    if filesystem.get('overall_status') == 'critical':
        status = "critical"
    elif filesystem.get('overall_status') == 'warning':
        status = max(status, "warning")
    elif filesystem.get('overall_status') == 'degraded':
        status = max(status, "degraded")

    # Check database health
    db_metrics = metrics.get('database', {})
    if db_metrics.get('active_connections', 0) < 0:  # Error in database connection
        status = "critical"
    elif db_metrics.get('slow_queries', 0) > 100:
        status = max(status, "warning")

    # Check file integrity status
    file_integrity = metrics.get('file_integrity', {})
    if file_integrity.get('status') == 'critical':
        status = "critical"
    elif file_integrity.get('status') == 'warning':
        status = max(status, "warning")

    # Check security status (if critical events exist)
    security = metrics.get('security', {})
    if security.get('critical_events_24h', 0) > 0:
        status = max(status, "warning")

    # Add degraded state as an intermediate between warning and healthy
    if status == "healthy" and (
        system.get('cpu_usage', 0) > 70 or
        system.get('memory_usage', 0) > 70 or
        system.get('disk_usage', 0) > 70
    ):
        status = "degraded"

    return status


def record_file_integrity_metrics(status: bool, changes: List[Dict[str, Any]]) -> None:
    """
    Record file integrity check results to metrics system.

    Updates Prometheus metrics with file integrity check results to track
    the health and status of the file integrity monitoring system.

    Args:
        status (bool): True if integrity check passed, False if violations found
        changes (List[Dict]): List of detected changes if any

    Returns:
        None: This function records metrics as a side effect
    """
    # Record successful/failed check
    metrics.info('file_integrity_check_total', 1, labels={
        'result': 'success' if status else 'failure'
    })

    # Update gauge for last successful check timestamp
    if status:
        metrics.gauge('security.last_integrity_check', int(time.time()))

    # Record number of changes detected
    if not status and changes:
        metrics.gauge('security.modified_critical_files', len(changes))

        # Count changes by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for change in changes:
            severity = change.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Record metrics for each severity level
        for severity, count in severity_counts.items():
            if count > 0:
                metrics.gauge(f'security.{severity}_severity_changes', count)

        # Count by modification type
        status_counts = {}
        for change in changes:
            change_status = change.get('status', 'unknown')
            status_counts[change_status] = status_counts.get(change_status, 0) + 1

        # Record metrics for each modification type
        for status_key, count in status_counts.items():
            if count > 0:
                metrics.gauge(f'security.modifications.{status_key}', count)
