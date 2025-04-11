"""
Metrics collection module for myproject.

This module provides classes and functions for collecting various system and
application metrics. It gathers data about CPU usage, memory utilization, disk
space, database performance, and application-specific metrics to provide a
comprehensive overview of system health and performance.

The metrics are designed to be:
- Cached appropriately to minimize collection overhead
- Structured consistently for easy consumption
- Error-tolerant to prevent cascading failures
- Extensible for custom application metrics

These metrics enable monitoring, alerting, capacity planning, and performance
optimization of the application in production environments.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Any
import psutil
from flask import current_app
from sqlalchemy import text
from extensions import metrics, db, cache
from models.user import User

class SystemMetrics:
    """
    System-level metrics collection class.

    This class provides methods to collect operating system metrics including
    CPU usage, memory utilization, disk space, and network I/O statistics.
    The collected data provides visibility into the overall health and
    resource utilization of the host system.
    """

    class MetricsError(Exception):
        """
        System metrics specific errors.

        This exception class is used for errors that occur during system
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'SYSTEM_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    def get_system_metrics() -> Dict[str, Any]:
        """
        Collect system-level metrics with caching.

        This method gathers core system metrics including CPU, memory, and disk usage.
        It caches results for 30 seconds to reduce collection overhead for frequent calls.

        Returns:
            Dict[str, Any]: Dictionary containing system metrics:
                - cpu_usage: CPU utilization percentage
                - memory_usage: Memory utilization percentage
                - disk_usage: Disk space utilization percentage
                - boot_time: System boot time
                - load_avg: System load averages
                - network: Network I/O statistics

        Raises:
            SystemMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = SystemMetrics.get_system_metrics()
            print(f"CPU usage: {metrics['cpu_usage']}%")
        """
        try:
            return {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'load_avg': os.getloadavg(),
                'network': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv
                }
            }
        except (psutil.Error, AttributeError, KeyError, TypeError) as e:
            raise SystemMetrics.MetricsError(f"System metrics error: {e}") from e

    @staticmethod
    @cache.memoize(timeout=30)
    def get_process_metrics() -> Dict[str, Any]:
        """
        Collect process-specific metrics with caching.

        This method gathers metrics specific to the current application process,
        including memory usage, CPU utilization, and open file handles.

        Returns:
            Dict[str, Any]: Dictionary containing process metrics:
                - memory_used: Process memory usage in MB
                - cpu_percent: Process CPU utilization percentage
                - threads: Number of threads in the process
                - open_files: Count of open file handles
                - connections: Count of open network connections

        Raises:
            SystemMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = SystemMetrics.get_process_metrics()
            print(f"Process memory: {metrics['memory_used']} MB")
        """
        try:
            process = psutil.Process(os.getpid())
            return {
                'memory_used': process.memory_info().rss / 1024 / 1024,  # MB
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files()),
                'connections': len(process.connections())
            }
        except (psutil.Error, AttributeError) as e:
            raise SystemMetrics.MetricsError(f"Process metrics error: {e}") from e

class DatabaseMetrics:
    """
    Database performance metrics collection class.

    This class provides methods to collect database performance metrics
    including connection count, database size, query performance, and
    pool status. These metrics help monitor database health and identify
    potential performance issues.
    """

    class MetricsError(Exception):
        """
        Database metrics specific errors.

        This exception class is used for errors that occur during database
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'DATABASE_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    def get_db_metrics() -> Dict[str, Any]:
        """
        Collect database performance metrics with caching.

        This method gathers database metrics including the database size,
        connection counts, and pool status to monitor database health and
        resource utilization.

        Returns:
            Dict[str, Any]: Dictionary containing database metrics:
                - database_size: Size of the database
                - active_connections: Number of active database connections
                - deadlocks: Count of deadlocks detected
                - pool_size: Size of the connection pool
                - in_use: Number of connections currently in use

        Raises:
            DatabaseMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = DatabaseMetrics.get_db_metrics()
            print(f"Active connections: {metrics['active_connections']}")
        """
        try:
            with db.engine.connect() as conn:
                # Get database metrics
                db_size = conn.execute(text(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                )).scalar()

                active_connections = conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity"
                )).scalar()

                deadlocks = conn.execute(text(
                    "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
                )).scalar()

                # Access pool status through correct attributes
                connection_pool = db.engine.pool
                pool_status = {}

                if hasattr(connection_pool, 'status') and callable(connection_pool.status):
                    pool_status = connection_pool.status()

                # Safely access pool status with proper error handling
                return {
                    'database_size': db_size,
                    'active_connections': active_connections,
                    'deadlocks': deadlocks,
                    'pool_size': pool_status['size'] if isinstance(pool_status, dict) and 'size' in pool_status else 0,
                    'in_use': pool_status['checkedin'] if isinstance(pool_status, dict) and 'checkedin' in pool_status else 0
                }
        except Exception as e:
            raise DatabaseMetrics.MetricsError(f"Database metrics error: {e}") from e

class ApplicationMetrics:
    """
    Application-specific metrics collection class.

    This class provides methods to collect application-specific metrics such as
    user counts, request rates, and uptime. These metrics help monitor application
    health, usage patterns, and overall performance.
    """

    class MetricsError(Exception):
        """
        Application metrics specific errors.

        This exception class is used for errors that occur during application
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'APPLICATION_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=60)
    def get_app_metrics() -> Dict[str, Any]:
        """
        Collect application-specific metrics with caching.

        This method gathers metrics specific to the application, including
        user counts, request totals, and uptime information to provide
        insight into application usage and health.

        Returns:
            Dict[str, Any]: Dictionary containing application metrics:
                - total_users: Total number of registered users
                - active_users: Number of recently active users
                - uptime: Application uptime duration
                - version: Application version string
                - requests_total: Total number of HTTP requests processed
                - errors_total: Total number of errors encountered

        Raises:
            ApplicationMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = ApplicationMetrics.get_app_metrics()
            print(f"Total users: {metrics['total_users']}")
        """
        try:
            # Access metrics directly or use appropriate method instead of get_metric
            # PrometheusMetrics doesn't have get_metric method
            metric_request_data = 0
            metric_error_data = 0

            # Try to access metrics if they exist in the metrics registry
            if hasattr(metrics, 'registry'):
                for metric in metrics.registry.collect():
                    if metric.name == 'requests_total':
                        for sample in metric.samples:
                            metric_request_data += sample.value
                    if metric.name == 'errors_total':
                        for sample in metric.samples:
                            metric_error_data += sample.value

            return {
                'total_users': User.query.count(),
                'active_users': User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(minutes=5))
                ).count(),
                'uptime': str(datetime.utcnow() - current_app.uptime),
                'version': current_app.config.get('VERSION', '1.0.0'),
                'requests_total': metric_request_data,
                'errors_total': metric_error_data
            }
        except Exception as e:
            raise ApplicationMetrics.MetricsError(f"Application metrics error: {e}") from e

class EnvironmentalData:
    """
    Environmental data collection class.

    This class provides methods to collect environmental metrics such as
    temperature, humidity, and network interface information. These metrics
    are particularly relevant for IoT and industrial control system (ICS)
    applications.
    """

    class MetricsError(Exception):
        """
        Environmental metrics specific errors.

        This exception class is used for errors that occur during environmental
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'ENVIRONMENTAL_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    def get_env_metrics() -> Dict[str, Any]:
        """
        Collect environmental metrics with caching.

        This method gathers environmental data including battery status
        and network interface information, which is useful for monitoring
        the physical environment of the system.

        Returns:
            Dict[str, Any]: Dictionary containing environmental metrics:
                - battery: Battery status information
                - network_interfaces: Network interface details

        Raises:
            EnvironmentalData.MetricsError: If metrics collection fails

        Example:
            metrics = EnvironmentalData.get_env_metrics()
            print(f"Battery: {metrics['battery']}")
        """
        try:
            return {
                'battery': psutil.sensors_battery()._asdict() if psutil.sensors_battery() else {},
                'network_interfaces': {
                    name: [addr.__dict__ for addr in addrs]
                    for name, addrs in psutil.net_if_addrs().items()
                }
            }
        except Exception as e:
            raise EnvironmentalData.MetricsError(f"Environmental metrics error: {e}") from e

    timestamp = db.Column(db.DateTime, nullable=False)  # Add the timestamp attribute


@cache.memoize(timeout=60)
def get_all_metrics() -> Dict[str, Any]:
    """
    Collect all system, database and application metrics.

    This function aggregates metrics from all available sources into a single
    comprehensive metrics report. It caches the result to reduce collection
    overhead for frequent calls.

    Returns:
        Dict[str, Any]: Dictionary containing all metrics:
            - system: System metrics
            - process: Process metrics
            - database: Database metrics
            - application: Application metrics
            - environment: Environmental metrics
            - timestamp: Collection timestamp

    Example:
        all_metrics = get_all_metrics()
        print(f"CPU usage: {all_metrics['system']['cpu_usage']}%")
        print(f"Active users: {all_metrics['application']['active_users']}")
    """
    try:
        metrics_data = {
            'system': SystemMetrics.get_system_metrics(),
            'process': SystemMetrics.get_process_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'environment': EnvironmentalData.get_env_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
        metrics.info('metrics_collection_success', 1)
        return metrics_data

    except (SystemMetrics.MetricsError, DatabaseMetrics.MetricsError,
            EnvironmentalData.MetricsError, ApplicationMetrics.MetricsError) as e:
        current_app.logger.error(f"Metrics collection error: {e}")
        metrics.info('metrics_collection_error', 1, labels={'type': e.error_code})
        return {
            'error': str(e),
            'code': e.error_code,
            'timestamp': datetime.utcnow().isoformat()
        }

    except (psutil.Error, AttributeError, KeyError, TypeError, RuntimeError) as e:
        current_app.logger.error(f"Unexpected metrics error: {e}")
        metrics.info('metrics_collection_error', 1, labels={'type': 'unknown'})
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
