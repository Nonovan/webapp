"""
Metrics collection module for Cloud Infrastructure Platform.

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
from typing import Dict, Any, List, Optional, Union, Tuple
import psutil
from flask import current_app, has_app_context
from sqlalchemy import text, func, desc
from extensions import metrics, db, cache
from models.auth import User


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
                - slow_queries: Number of slow queries detected
                - table_sizes: Size of largest tables in the database

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

                # Get slow queries count
                slow_queries = conn.execute(text("""
                    SELECT COUNT(*) FROM pg_stat_activity
                    WHERE state = 'active'
                    AND (now() - query_start) > '5 seconds'::interval
                """)).scalar() or 0

                # Get table sizes
                table_sizes = {}
                table_size_records = conn.execute(text("""
                    SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) as size
                    FROM pg_catalog.pg_statio_user_tables
                    ORDER BY pg_total_relation_size(relid) DESC
                    LIMIT 5
                """)).fetchall()

                for record in table_size_records:
                    table_sizes[record[0]] = record[1]

                # Access pool status through correct attributes
                connection_pool = db.engine.pool
                pool_status = {}

                if hasattr(connection_pool, 'status') and callable(connection_pool.status):
                    pool_status = connection_pool.status()
                elif hasattr(connection_pool, 'size') and hasattr(connection_pool, 'checkedin'):
                    pool_status = {
                        'size': connection_pool.size(),
                        'checkedin': connection_pool.checkedin()
                    }

                # Safely access pool status with proper error handling
                return {
                    'database_size': db_size,
                    'active_connections': active_connections,
                    'deadlocks': deadlocks,
                    'slow_queries': slow_queries,
                    'table_sizes': table_sizes,
                    'pool_size': pool_status.get('size', 0) if isinstance(pool_status, dict) else 0,
                    'in_use': pool_status.get('checkedin', 0) if isinstance(pool_status, dict) else 0
                }
        except Exception as e:
            raise DatabaseMetrics.MetricsError(f"Database metrics error: {e}") from e

    @staticmethod
    def get_query_performance_metrics() -> Dict[str, Any]:
        """
        Collect query performance metrics.

        This method gathers statistics about query execution times, including
        average query time and slow query identification.

        Returns:
            Dict[str, Any]: Dictionary containing query performance metrics

        Raises:
            DatabaseMetrics.MetricsError: If metrics collection fails
        """
        try:
            with db.engine.connect() as conn:
                # Get top 5 slowest queries
                slow_queries = conn.execute(text("""
                    SELECT query, calls, total_time, mean_time
                    FROM pg_stat_statements
                    ORDER BY mean_time DESC
                    LIMIT 5
                """)).fetchall()

                result = []
                for query in slow_queries:
                    # Sanitize query text to avoid overly long entries
                    query_text = str(query[0])
                    if len(query_text) > 200:
                        query_text = query_text[:197] + "..."

                    result.append({
                        'query': query_text,
                        'calls': query[1],
                        'total_time': round(float(query[2]), 2),
                        'mean_time': round(float(query[3]), 2)
                    })

                return {
                    'slow_queries': result,
                    'collected_at': datetime.utcnow().isoformat()
                }

        except Exception as e:
            raise DatabaseMetrics.MetricsError(f"Query performance metrics error: {e}") from e


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
                - api_requests: API-specific request metrics
                - cache_hit_rate: Cache performance metrics

        Raises:
            ApplicationMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = ApplicationMetrics.get_app_metrics()
            print(f"Total users: {metrics['total_users']}")
        """
        try:
            # Access metrics directly or use appropriate method instead of get_metric
            metric_request_data = 0
            metric_error_data = 0
            api_requests = 0

            # Collect user metrics
            try:
                total_users = User.query.count()
                active_users = User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(minutes=5))
                ).count()
                active_last_hour = User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(hours=1))
                ).count()
                active_last_day = User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(days=1))
                ).count()
            except Exception:
                total_users = 0
                active_users = 0
                active_last_hour = 0
                active_last_day = 0

            # Try to access metrics if they exist in the metrics registry
            if hasattr(metrics, 'registry'):
                for metric in metrics.registry.collect():
                    if metric.name == 'http_requests_total' or metric.name.endswith('requests_total'):
                        for sample in metric.samples:
                            metric_request_data += sample.value
                    if metric.name == 'http_errors_total' or metric.name.endswith('errors_total'):
                        for sample in metric.samples:
                            metric_error_data += sample.value
                    if metric.name == 'api_requests_total' or metric.name.endswith('api_requests_total'):
                        for sample in metric.samples:
                            api_requests += sample.value

            # Get cache hit rate
            cache_hit_rate = ApplicationMetrics._get_cache_hit_rate()

            # Collect application data
            app_data = {
                'total_users': total_users,
                'active_users': active_users,
                'active_last_hour': active_last_hour,
                'active_last_day': active_last_day,
                'uptime': str(datetime.utcnow() - current_app.uptime) if hasattr(current_app, 'uptime') else 'unknown',
                'version': current_app.config.get('VERSION', '1.0.0'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'requests_total': int(metric_request_data),
                'errors_total': int(metric_error_data),
                'api_requests': int(api_requests),
                'cache_hit_rate': cache_hit_rate
            }

            # Add HTTP status code breakdown if available
            status_codes = ApplicationMetrics._get_status_code_breakdown()
            if status_codes:
                app_data['status_codes'] = status_codes

            return app_data

        except Exception as e:
            raise ApplicationMetrics.MetricsError(f"Application metrics error: {e}") from e

    @staticmethod
    def _get_cache_hit_rate() -> float:
        """Get the cache hit rate if available."""
        try:
            if hasattr(cache, 'stats') and callable(cache.stats):
                stats = cache.stats()
                if isinstance(stats, dict):
                    hits = stats.get('hits', 0)
                    misses = stats.get('misses', 0)
                    total = hits + misses
                    if total > 0:
                        return round((hits / total) * 100, 2)
            return 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _get_status_code_breakdown() -> Dict[str, int]:
        """Get a breakdown of HTTP status codes from the metrics registry."""
        status_codes = {}
        try:
            if hasattr(metrics, 'registry'):
                for metric in metrics.registry.collect():
                    if metric.name == 'http_requests_by_status_total' or 'status' in metric.name:
                        for sample in metric.samples:
                            labels = sample.labels if hasattr(sample, 'labels') else {}
                            status = labels.get('status', 'unknown')
                            if status not in status_codes:
                                status_codes[status] = 0
                            status_codes[status] += sample.value
            return status_codes
        except Exception:
            return {}


class SecurityMetrics:
    """
    Security metrics collection class.

    This class provides methods to collect security-related metrics such as
    failed login attempts, suspicious activities, and security events. These
    metrics help monitor system security and detect potential threats.
    """

    class MetricsError(Exception):
        """
        Security metrics specific errors.

        This exception class is used for errors that occur during security
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'SECURITY_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=60)
    def get_security_metrics(hours: int = 24) -> Dict[str, Any]:
        """
        Collect security metrics with caching.

        This method gathers security metrics including failed login attempts,
        account lockouts, and suspicious activities to provide insight into
        potential security threats.

        Args:
            hours: Time window for metrics in hours (default: 24)

        Returns:
            Dict[str, Any]: Dictionary containing security metrics:
                - failed_logins_24h: Failed login attempts in the last 24 hours
                - account_lockouts_24h: Account lockouts in the last 24 hours
                - security_events_24h: Security events in the last 24 hours
                - suspicious_ips: List of suspicious IP addresses

        Raises:
            SecurityMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = SecurityMetrics.get_security_metrics()
            print(f"Failed logins: {metrics['failed_logins_24h']}")
        """
        try:
            # Import here to avoid circular imports
            from models.security.audit_log import AuditLog
            from core.security.cs_monitoring import (
                get_failed_login_count,
                get_account_lockout_count,
                get_suspicious_ips
            )

            cutoff = datetime.utcnow() - timedelta(hours=hours)

            # Get counts from security monitoring functions
            try:
                failed_logins = get_failed_login_count(hours)
                account_lockouts = get_account_lockout_count(hours)
                suspicious_ips = get_suspicious_ips(hours)
            except (ImportError, AttributeError):
                # Fall back to direct counts if functions not available
                failed_logins = 0
                account_lockouts = 0
                suspicious_ips = []

                # Try to count from audit log directly
                try:
                    failed_logins = AuditLog.query.filter(
                        AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                        AuditLog.created_at >= cutoff
                    ).count()

                    account_lockouts = AuditLog.query.filter(
                        AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
                        AuditLog.created_at >= cutoff
                    ).count()
                except (AttributeError, NameError):
                    pass

            # Get security events count
            security_events = 0
            try:
                security_events = AuditLog.query.filter(
                    AuditLog.category == AuditLog.EVENT_CATEGORY_SECURITY,
                    AuditLog.created_at >= cutoff
                ).count()
            except (AttributeError, NameError):
                pass

            # Check file integrity status
            file_integrity = True
            config_integrity = True
            try:
                from core.security.cs_file_integrity import (
                    check_critical_file_integrity,
                    check_config_integrity
                )
                file_integrity = check_critical_file_integrity()
                config_integrity = check_config_integrity()
            except (ImportError, AttributeError):
                pass

            # Get incidents data
            incidents_count = 0
            incidents_active = 0
            try:
                from models.security.security_incident import SecurityIncident
                incidents_count = SecurityIncident.query.filter(
                    SecurityIncident.created_at >= cutoff
                ).count()
                incidents_active = SecurityIncident.query.filter(
                    SecurityIncident.status != SecurityIncident.STATUS_RESOLVED,
                    SecurityIncident.status != SecurityIncident.STATUS_CLOSED
                ).count()
            except (ImportError, AttributeError, NameError):
                pass

            return {
                'failed_logins_24h': failed_logins,
                'account_lockouts_24h': account_lockouts,
                'security_events_24h': security_events,
                'suspicious_ips': suspicious_ips,
                'file_integrity': file_integrity,
                'config_integrity': config_integrity,
                'incidents_count': incidents_count,
                'incidents_active': incidents_active,
                'time_window_hours': hours
            }

        except Exception as e:
            raise SecurityMetrics.MetricsError(f"Security metrics error: {e}") from e


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
                - sensors: Temperature sensor data if available

        Raises:
            EnvironmentalData.MetricsError: If metrics collection fails

        Example:
            metrics = EnvironmentalData.get_env_metrics()
            print(f"Battery: {metrics['battery']}")
        """
        try:
            result = {
                'battery': {},
                'network_interfaces': {},
                'sensors': {}
            }

            # Get battery information
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    result['battery'] = {
                        'percent': battery.percent,
                        'power_plugged': battery.power_plugged,
                        'secsleft': battery.secsleft if battery.secsleft != -1 else None
                    }

            # Get network interface information
            if hasattr(psutil, 'net_if_addrs'):
                net_if_addrs = psutil.net_if_addrs()
                interfaces = {}

                for name, addrs in net_if_addrs.items():
                    addr_info = []
                    for addr in addrs:
                        addr_dict = {}
                        for attr in ['family', 'address', 'netmask', 'broadcast', 'ptp']:
                            if hasattr(addr, attr):
                                addr_dict[attr] = getattr(addr, attr)
                        addr_info.append(addr_dict)

                    interfaces[name] = addr_info

                result['network_interfaces'] = interfaces

            # Get temperature sensors data
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    temp_data = {}
                    for chip, sensors in temps.items():
                        temp_data[chip] = [sensor._asdict() for sensor in sensors]
                    result['sensors']['temperatures'] = temp_data

            # Get fan sensors data
            if hasattr(psutil, 'sensors_fans'):
                fans = psutil.sensors_fans()
                if fans:
                    fan_data = {}
                    for chip, sensors in fans.items():
                        fan_data[chip] = [sensor._asdict() for sensor in sensors]
                    result['sensors']['fans'] = fan_data

            return result

        except Exception as e:
            raise EnvironmentalData.MetricsError(f"Environmental metrics error: {e}") from e


class CloudMetrics:
    """
    Cloud resources metrics collection class.

    This class provides methods to collect metrics about cloud resources
    from various cloud providers. These metrics help monitor cloud infrastructure
    costs, utilization, and performance.
    """

    class MetricsError(Exception):
        """
        Cloud metrics specific errors.

        This exception class is used for errors that occur during cloud
        metrics collection, providing structured error reporting.

        Attributes:
            message (str): Error message describing the issue
            error_code (str): Identifier for the type of error
        """
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'CLOUD_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=300)  # 5-minute cache since cloud metrics change less frequently
    def get_cloud_metrics() -> Dict[str, Any]:
        """
        Collect cloud resources metrics with caching.

        This method gathers metrics about cloud resources across different providers
        to provide insight into infrastructure costs and resource utilization.

        Returns:
            Dict[str, Any]: Dictionary containing cloud metrics:
                - resources_by_provider: Count of resources by provider
                - resources_by_type: Count of resources by type
                - cost_summary: Cost metrics by provider
                - alerts: Resource alerts or warnings

        Raises:
            CloudMetrics.MetricsError: If metrics collection fails

        Example:
            metrics = CloudMetrics.get_cloud_metrics()
            print(f"AWS resources: {metrics['resources_by_provider']['aws']}")
        """
        try:
            # Import here to avoid circular imports
            try:
                from models.cloud.cloud_resource import CloudResource
                from models.cloud.cloud_provider import CloudProvider
            except ImportError:
                return {
                    'resources_by_provider': {},
                    'resources_by_type': {},
                    'cost_summary': {},
                    'alerts': []
                }

            # Get counts by provider
            resources_by_provider = {}
            providers = CloudProvider.query.all()

            for provider in providers:
                count = CloudResource.query.filter(
                    CloudResource.provider_id == provider.id,
                    CloudResource.is_active == True
                ).count()
                resources_by_provider[provider.name.lower()] = count

            # Get counts by type
            resources_by_type = {}
            resource_types = db.session.query(
                CloudResource.resource_type,
                func.count(CloudResource.id)
            ).group_by(
                CloudResource.resource_type
            ).all()

            for resource_type, count in resource_types:
                resources_by_type[resource_type] = count

            # Get cost summary
            cost_summary = {}
            providers = CloudProvider.query.all()

            for provider in providers:
                # Calculate current month costs
                current_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

                cost_sum = db.session.query(
                    func.sum(CloudResource.estimated_cost_monthly)
                ).filter(
                    CloudResource.provider_id == provider.id,
                    CloudResource.is_active == True
                ).scalar() or 0

                cost_summary[provider.name.lower()] = {
                    'estimated_monthly': float(cost_sum),
                    'currency': provider.cost_currency or 'USD'
                }

            # Get resource alerts
            alerts = []
            problematic_resources = CloudResource.query.filter(
                (CloudResource.health_status != 'healthy') &
                (CloudResource.is_active == True)
            ).order_by(CloudResource.updated_at.desc()).limit(5).all()

            for resource in problematic_resources:
                alerts.append({
                    'resource_id': resource.id,
                    'resource_name': resource.name,
                    'resource_type': resource.resource_type,
                    'provider': CloudProvider.query.get(resource.provider_id).name,
                    'status': resource.health_status,
                    'message': resource.status_message
                })

            return {
                'resources_by_provider': resources_by_provider,
                'resources_by_type': resources_by_type,
                'cost_summary': cost_summary,
                'alerts': alerts
            }

        except Exception as e:
            raise CloudMetrics.MetricsError(f"Cloud metrics error: {e}") from e


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
            - security: Security metrics
            - cloud: Cloud resource metrics
            - environment: Environmental metrics
            - timestamp: Collection timestamp
            - health: Overall system health status

    Example:
        all_metrics = get_all_metrics()
        print(f"CPU usage: {all_metrics['system']['cpu_usage']}%")
        print(f"Active users: {all_metrics['application']['active_users']}")
        print(f"System health: {all_metrics['health']}")
    """
    try:
        # Collect metrics from each category
        system_metrics = SystemMetrics.get_system_metrics()
        process_metrics = SystemMetrics.get_process_metrics()
        db_metrics = DatabaseMetrics.get_db_metrics()
        app_metrics = ApplicationMetrics.get_app_metrics()

        # Try to get security metrics, but don't fail if not available
        security_metrics = {}
        try:
            security_metrics = SecurityMetrics.get_security_metrics()
        except Exception as security_error:
            if has_app_context() and hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Security metrics collection failed: {security_error}")
            security_metrics = {'error': str(security_error)}

        # Try to get cloud metrics, but don't fail if not available
        cloud_metrics = {}
        try:
            cloud_metrics = CloudMetrics.get_cloud_metrics()
        except Exception as cloud_error:
            if has_app_context() and hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Cloud metrics collection failed: {cloud_error}")
            cloud_metrics = {'error': str(cloud_error)}

        # Try to get environmental metrics, but don't fail if not available
        env_metrics = {}
        try:
            env_metrics = EnvironmentalData.get_env_metrics()
        except Exception as env_error:
            if has_app_context() and hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Environmental metrics collection failed: {env_error}")
            env_metrics = {'error': str(env_error)}

        # Compile all metrics into one dictionary
        metrics_data = {
            'system': system_metrics,
            'process': process_metrics,
            'database': db_metrics,
            'application': app_metrics,
            'security': security_metrics,
            'cloud': cloud_metrics,
            'environment': env_metrics,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Calculate overall health status
        metrics_data['health'] = _calculate_health_status(metrics_data)

        # Record successful metrics collection
        if has_app_context():
            metrics.info('metrics_collection_success', 1)

        return metrics_data

    except (SystemMetrics.MetricsError, DatabaseMetrics.MetricsError,
            EnvironmentalData.MetricsError, ApplicationMetrics.MetricsError,
            SecurityMetrics.MetricsError, CloudMetrics.MetricsError) as e:
        if has_app_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Metrics collection error: {e}")
        if has_app_context():
            metrics.info('metrics_collection_error', 1, labels={'type': e.error_code})
        return {
            'error': str(e),
            'code': e.error_code,
            'timestamp': datetime.utcnow().isoformat(),
            'health': 'critical'
        }

    except (psutil.Error, AttributeError, KeyError, TypeError, RuntimeError) as e:
        if has_app_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Unexpected metrics error: {e}")
        if has_app_context():
            metrics.info('metrics_collection_error', 1, labels={'type': 'unknown'})
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat(),
            'health': 'critical'
        }


def _calculate_health_status(metrics: Dict[str, Any]) -> str:
    """
    Calculate overall health status based on collected metrics.

    This function analyzes various metrics to determine if the system is:
    - healthy: All systems functioning normally
    - degraded: Performance issues but still functioning
    - warning: Potential issues that require attention
    - critical: Serious issues requiring immediate action

    Args:
        metrics: Dictionary containing collected metrics

    Returns:
        str: Health status ('healthy', 'degraded', 'warning', or 'critical')
    """
    status = "healthy"

    # Check for errors that would immediately make status critical
    if 'error' in metrics:
        return 'critical'

    # Check system resources
    system = metrics.get('system', {})
    if system.get('cpu_usage', 0) > 90 or system.get('memory_usage', 0) > 90 or system.get('disk_usage', 0) > 90:
        status = "critical"
    elif system.get('cpu_usage', 0) > 80 or system.get('memory_usage', 0) > 80 or system.get('disk_usage', 0) > 80:
        status = max(status, "warning")

    # Check database health
    db_metrics = metrics.get('database', {})
    if db_metrics.get('active_connections', 0) < 0:  # Error in database connection
        status = "critical"
    elif db_metrics.get('slow_queries', 0) > 100:
        status = max(status, "warning")

    # Check security status
    security = metrics.get('security', {})
    if security.get('failed_logins_24h', 0) > 100:
        status = max(status, "warning")
    if security.get('account_lockouts_24h', 0) > 10:
        status = max(status, "warning")
    if not security.get('file_integrity', True) or not security.get('config_integrity', True):
        status = "critical"
    if security.get('incidents_active', 0) > 5:
        status = max(status, "warning")

    # Add degraded state as an intermediate between warning and healthy
    if status == "healthy" and (
        system.get('cpu_usage', 0) > 70 or
        system.get('memory_usage', 0) > 70 or
        system.get('disk_usage', 0) > 70 or
        db_metrics.get('slow_queries', 0) > 50
    ):
        status = "degraded"

    return status
