"""
Metrics collectors for the Cloud Infrastructure Platform.

This module provides functions to collect metrics from various sources including
system resources, database performance, application metrics, security status,
and cloud resources. These collectors abstract the complexity of gathering metrics
from different sources and present them in a consistent format.

Each collector follows best practices for error handling, caching, and performance
optimization to ensure minimal impact on the monitored systems while providing
accurate and timely metrics.
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple

from flask import current_app, g, has_app_context
import psutil

from extensions import db, metrics, cache
from core.metrics import (
    SystemMetrics,
    DatabaseMetrics,
    ApplicationMetrics,
    SecurityMetrics
)
from core.security.cs_metrics import get_security_metrics

# Initialize logger
logger = logging.getLogger(__name__)

def collect_system_metrics(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect system-level metrics about CPU, memory, disk, and network.

    This function gathers metrics about the host system's resource utilization
    including CPU load, memory usage, disk space, and network I/O statistics.

    Args:
        detailed: Whether to include additional detailed metrics

    Returns:
        Dict[str, Any]: Dictionary containing system metrics
            - cpu_usage: CPU utilization percentage
            - memory_usage: Memory utilization percentage
            - disk_usage: Disk space utilization percentage
            - load_average: System load averages (1, 5, 15 min)
            - network_io: Network bytes sent/received
            - uptime: System uptime
            - processes: Process count (if detailed=True)
            - io_wait: I/O wait percentage (if detailed=True)
            - swap_usage: Swap memory usage (if detailed=True)
            - network_connections: Active connection count (if detailed=True)

    Example:
        basic_metrics = collect_system_metrics()
        print(f"CPU Usage: {basic_metrics['cpu_usage']}%")

        detailed_metrics = collect_system_metrics(detailed=True)
        print(f"Network Connections: {detailed_metrics['network_connections']}")
    """
    try:
        # First try to get metrics from the core SystemMetrics class
        system_metrics = SystemMetrics.get_system_metrics()

        # If we need more detailed metrics, supplement with additional data
        if detailed:
            try:
                # Add process count
                system_metrics['processes'] = len(psutil.pids())

                # Add CPU times breakdown
                cpu_times = psutil.cpu_times_percent(interval=0.1)
                system_metrics['cpu_user'] = cpu_times.user
                system_metrics['cpu_system'] = cpu_times.system
                system_metrics['cpu_idle'] = cpu_times.idle
                if hasattr(cpu_times, 'iowait'):
                    system_metrics['io_wait'] = cpu_times.iowait

                # Add swap information
                swap = psutil.swap_memory()
                system_metrics['swap_total'] = swap.total
                system_metrics['swap_used'] = swap.used
                system_metrics['swap_percent'] = swap.percent

                # Add network connections count
                system_metrics['network_connections'] = len(psutil.net_connections())

                # Add disk I/O statistics if available
                try:
                    disk_io = psutil.disk_io_counters()
                    system_metrics['disk_read_bytes'] = disk_io.read_bytes
                    system_metrics['disk_write_bytes'] = disk_io.write_bytes
                except (AttributeError, OSError):
                    pass

                # Add detailed network interface information
                interfaces = {}
                for iface, stats in psutil.net_if_stats().items():
                    interfaces[iface] = {
                        'isup': stats.isup,
                        'speed': stats.speed,
                        'mtu': stats.mtu
                    }
                system_metrics['network_interfaces'] = interfaces

            except (psutil.Error, OSError, Exception) as e:
                logger.warning(f"Could not collect some detailed system metrics: {e}")

        return system_metrics

    except Exception as e:
        logger.error(f"Error collecting system metrics: {e}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

def collect_database_metrics(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect metrics about database performance and health.

    This function gathers metrics about database connections, query performance,
    table sizes, and other database-specific information.

    Args:
        detailed: Whether to include additional detailed metrics

    Returns:
        Dict[str, Any]: Dictionary containing database metrics
            - active_connections: Current active connections
            - total_queries: Total query count
            - slow_queries: Count of slow-running queries
            - database_size: Size of the database
            - query_time_avg: Average query time in milliseconds
            - table_sizes: Sizes of largest tables (if detailed=True)
            - deadlocks: Count of deadlocks (if detailed=True)
            - cache_hit_ratio: Database cache effectiveness (if detailed=True)

    Example:
        db_metrics = collect_database_metrics()
        print(f"Active connections: {db_metrics['active_connections']}")
    """
    try:
        # First try to get metrics from the core DatabaseMetrics class
        db_metrics = DatabaseMetrics.get_db_metrics()

        # If we need more detailed metrics, supplement with additional data
        if detailed and has_app_context():
            try:
                # Get database type
                db_type = str(db.engine.url).split('://')[0] if '://' in str(db.engine.url) else 'unknown'
                db_metrics['database_type'] = db_type

                # If PostgreSQL, get additional metrics
                if 'postgresql' in db_type.lower():
                    with db.engine.connect() as conn:
                        # Get replication lag if this is a replica
                        try:
                            rep_result = conn.execute(db.text(
                                "SELECT pg_last_wal_receive_lsn() IS NOT NULL AS is_replica"
                            )).scalar()

                            if rep_result:
                                lag = conn.execute(db.text(
                                    "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))"
                                )).scalar()
                                db_metrics['replication_lag_seconds'] = lag
                        except Exception:
                            # Not a replica or can't determine
                            pass

                        # Get statistics about specific types of queries
                        try:
                            query_stats = conn.execute(db.text("""
                                SELECT
                                    COALESCE(sum(calls), 0) as calls,
                                    COALESCE(round(sum(total_exec_time)::numeric, 2), 0) as total_time,
                                    COALESCE(round(avg(mean_exec_time)::numeric, 2), 0) as avg_time
                                FROM pg_stat_statements
                                WHERE calls > 10
                            """)).fetchone()

                            if query_stats:
                                db_metrics['monitored_queries'] = {
                                    'count': query_stats[0],
                                    'total_execution_time': query_stats[1],
                                    'avg_execution_time': query_stats[2]
                                }
                        except Exception:
                            # pg_stat_statements may not be enabled
                            pass

                # Get transaction metrics
                if hasattr(db.engine, 'pool'):
                    checkout_count = getattr(db.engine.pool, 'checkedout', lambda: 0)()
                    if callable(checkout_count):
                        checkout_count = checkout_count()
                    db_metrics['pool_checkouts'] = checkout_count

            except Exception as detail_err:
                logger.warning(f"Could not collect detailed database metrics: {detail_err}")

        return db_metrics

    except Exception as e:
        logger.error(f"Error collecting database metrics: {e}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

def collect_application_metrics(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect metrics about application performance and usage.

    This function gathers metrics about request rates, response times,
    user counts, cache performance, and other application-level measurements.

    Args:
        detailed: Whether to include additional detailed metrics

    Returns:
        Dict[str, Any]: Dictionary containing application metrics
            - request_rate: Requests per second
            - response_time_avg: Average response time in milliseconds
            - error_rate: Error percentage
            - active_users: Currently active users
            - cache_hit_rate: Cache effectiveness percentage
            - uptime: Application uptime
            - version: Application version
            - endpoint_metrics: Per-endpoint statistics (if detailed=True)
            - request_methods: Breakdown by HTTP method (if detailed=True)
            - status_codes: HTTP status code distribution (if detailed=True)

    Example:
        app_metrics = collect_application_metrics()
        print(f"Request rate: {app_metrics['request_rate']}/sec")
    """
    try:
        # First try to get metrics from the core ApplicationMetrics class
        app_metrics = ApplicationMetrics.get_app_metrics()

        # If we need more detailed metrics, supplement with additional data
        if detailed and has_app_context():
            try:
                # Get detailed HTTP method distribution
                http_methods = {}
                for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    method_key = f'http_requests_method_{method.lower()}'
                    http_methods[method] = app_metrics.get(method_key, 0)
                app_metrics['request_methods'] = http_methods

                # Get detailed endpoint performance data
                all_metrics = list(metrics.registry.collect())
                endpoint_metrics = {}

                for metric in all_metrics:
                    if metric.name == 'app_http_request_latency_seconds':
                        for sample in metric.samples:
                            if 'endpoint' in sample.labels:
                                endpoint = sample.labels['endpoint']
                                if endpoint not in endpoint_metrics:
                                    endpoint_metrics[endpoint] = {
                                        'count': 0,
                                        'latency_avg': 0,
                                        'errors': 0
                                    }
                                # Process sample data based on the specific metric type
                                if 'quantile' in sample.labels:
                                    if sample.labels['quantile'] == '0.5':
                                        endpoint_metrics[endpoint]['latency_median'] = sample.value
                                    elif sample.labels['quantile'] == '0.95':
                                        endpoint_metrics[endpoint]['latency_p95'] = sample.value
                                elif sample.name.endswith('_count'):
                                    endpoint_metrics[endpoint]['count'] += int(sample.value)
                                elif sample.name.endswith('_sum'):
                                    if endpoint_metrics[endpoint]['count'] > 0:
                                        endpoint_metrics[endpoint]['latency_avg'] = sample.value / endpoint_metrics[endpoint]['count']

                # Add top 10 endpoints by request count
                top_endpoints = sorted(
                    endpoint_metrics.items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )[:10]
                app_metrics['top_endpoints'] = dict(top_endpoints)

                # Add request breakdown by status code
                status_counts = {}
                for metric in all_metrics:
                    if metric.name == 'app_http_requests_total':
                        for sample in metric.samples:
                            if 'http_status' in sample.labels:
                                status = sample.labels['http_status']
                                if status not in status_counts:
                                    status_counts[status] = 0
                                status_counts[status] += int(sample.value)
                app_metrics['status_codes'] = status_counts

                # Calculate total request count and success rate
                total_requests = sum(status_counts.values())
                if total_requests > 0:
                    success_requests = sum(status_counts.get(str(s), 0) for s in range(200, 300))
                    app_metrics['success_rate'] = (success_requests / total_requests) * 100

            except Exception as detail_err:
                logger.warning(f"Could not collect detailed application metrics: {detail_err}")

        return app_metrics

    except Exception as e:
        logger.error(f"Error collecting application metrics: {e}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

def collect_security_metrics(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect metrics about system security and potential threats.

    This function gathers metrics about authentication attempts, suspicious activities,
    file integrity status, and other security-related measurements.

    Args:
        detailed: Whether to include additional detailed metrics

    Returns:
        Dict[str, Any]: Dictionary containing security metrics
            - failed_logins_24h: Failed login attempts in the last 24 hours
            - security_score: Overall security score (0-100)
            - incidents_active: Number of active security incidents
            - suspicious_ips: Count of suspicious IP addresses
            - file_integrity: File integrity status (True/False)
            - security_events_24h: Security events in the last 24 hours
            - ip_locations: Geographical distribution (if detailed=True)
            - attack_vectors: Attack method distribution (if detailed=True)

    Example:
        security_metrics = collect_security_metrics()
        print(f"Failed logins (24h): {security_metrics['failed_logins_24h']}")
    """
    try:
        # First try to get metrics from the core SecurityMetrics class
        try:
            # For basic metrics, try the core module first
            security_metrics = SecurityMetrics.get_security_metrics()
        except (ImportError, AttributeError):
            # Fall back to the cs_metrics module if the core module is unavailable
            security_metrics = get_security_metrics()

        # Remove sensitive data that shouldn't be exposed via API
        # We'll only include specific metrics that are safe to expose
        safe_metrics = {
            'failed_logins_24h': security_metrics.get('failed_logins_24h', 0),
            'account_lockouts_24h': security_metrics.get('account_lockouts_24h', 0),
            'suspicious_ips_count': len(security_metrics.get('suspicious_ips', [])),
            'config_integrity': security_metrics.get('config_integrity', True),
            'file_integrity': security_metrics.get('file_integrity', True),
            'security_events_24h': sum(security_metrics.get('security_events', {}).values()),
            'incidents_active': security_metrics.get('incidents_active', 0),
            'security_score': security_metrics.get('risk_score', 0),
            'last_checked': security_metrics.get('last_checked', datetime.utcnow().isoformat())
        }

        # If we need more detailed metrics, supplement with additional data
        if detailed and has_app_context():
            try:
                # Add event type breakdown
                event_types = security_metrics.get('security_events', {})
                if event_types:
                    # Only include non-empty categories
                    safe_metrics['event_types'] = {k: v for k, v in event_types.items() if v > 0}

                # Add security recommendations (without sensitive internal details)
                recommendations = security_metrics.get('security_recommendations', [])
                if recommendations:
                    safe_recommendations = []
                    for rec in recommendations:
                        if isinstance(rec, dict):
                            safe_recommendations.append({
                                'priority': rec.get('priority', 'medium'),
                                'title': rec.get('title', 'Unnamed recommendation')
                                # Note: we intentionally exclude 'description' as it might contain
                                # sensitive details about the system security configuration
                            })
                    safe_metrics['recommendations_count'] = len(safe_recommendations)
                    safe_metrics['recommendations'] = safe_recommendations

                # Add high-level integrity changes data
                integrity_changes = security_metrics.get('integrity_changes', [])
                if integrity_changes:
                    safe_metrics['integrity_changes_count'] = len(integrity_changes)

                # Risk trend
                if 'risk_trend' in security_metrics:
                    safe_metrics['risk_trend'] = security_metrics['risk_trend']

            except Exception as detail_err:
                logger.warning(f"Could not collect detailed security metrics: {detail_err}")

        return safe_metrics

    except Exception as e:
        logger.error(f"Error collecting security metrics: {e}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

def collect_cloud_metrics(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect metrics about cloud resources and services.

    This function gathers metrics about cloud resource utilization, costs,
    service health, and other cloud-specific measurements across providers.

    Args:
        detailed: Whether to include additional detailed metrics

    Returns:
        Dict[str, Any]: Dictionary containing cloud metrics
            - resource_count: Total number of cloud resources
            - resource_types: Count by resource type
            - regions: Distribution by region
            - estimated_cost: Estimated daily cost
            - services: Service health status
            - provider_metrics: Per-provider breakdown (if detailed=True)
            - resource_details: Detailed resource metrics (if detailed=True)

    Example:
        cloud_metrics = collect_cloud_metrics()
        print(f"Total resources: {cloud_metrics['resource_count']}")
    """
    try:
        # Initialize with empty data structure
        cloud_metrics = {
            'resource_count': 0,
            'resource_types': {},
            'regions': {},
            'providers': {
                'aws': {'count': 0, 'healthy': True},
                'azure': {'count': 0, 'healthy': True},
                'gcp': {'count': 0, 'healthy': True}
            },
            'estimated_cost': 0.0,
            'timestamp': datetime.utcnow().isoformat()
        }

        # First check for cloud metrics from the database
        try:
            if has_app_context():
                # Try to import cloud-specific models
                from models.cloud.cloud_resource import CloudResource
                from models.cloud.cloud_metric import CloudMetric

                # Query for resource counts by type
                resources_by_type = db.session.query(
                    CloudResource.resource_type,
                    db.func.count(CloudResource.id)
                ).group_by(CloudResource.resource_type).all()

                cloud_metrics['resource_types'] = {r[0]: r[1] for r in resources_by_type}
                cloud_metrics['resource_count'] = sum(cloud_metrics['resource_types'].values())

                # Query for resources by region
                resources_by_region = db.session.query(
                    CloudResource.region,
                    db.func.count(CloudResource.id)
                ).group_by(CloudResource.region).all()

                cloud_metrics['regions'] = {r[0]: r[1] for r in resources_by_region}

                # Query for resources by provider
                resources_by_provider = db.session.query(
                    CloudResource.provider,
                    db.func.count(CloudResource.id)
                ).group_by(CloudResource.provider).all()

                for provider, count in resources_by_provider:
                    if provider in cloud_metrics['providers']:
                        cloud_metrics['providers'][provider]['count'] = count

                # Get estimated cost
                try:
                    cost_metrics = db.session.query(
                        CloudMetric.resource_id,
                        CloudResource.provider,
                        CloudMetric.value
                    ).join(
                        CloudResource, CloudResource.id == CloudMetric.resource_id
                    ).filter(
                        CloudMetric.metric_name == 'cost',
                        CloudMetric.collected_at > (datetime.utcnow() - timedelta(days=1))
                    ).all()

                    total_cost = sum(m[2] for m in cost_metrics)
                    cloud_metrics['estimated_cost'] = round(total_cost, 2)

                    # Break down costs by provider
                    provider_costs = {}
                    for _, provider, cost in cost_metrics:
                        provider_costs[provider] = provider_costs.get(provider, 0) + cost

                    # Add costs to provider data
                    for provider, cost in provider_costs.items():
                        if provider in cloud_metrics['providers']:
                            cloud_metrics['providers'][provider]['cost'] = round(cost, 2)

                except Exception as cost_error:
                    logger.warning(f"Could not collect cost metrics: {cost_error}")

                # If detailed view is requested, add more information
                if detailed:
                    try:
                        # Get top resources by cost
                        top_resources = db.session.query(
                            CloudResource.id,
                            CloudResource.name,
                            CloudResource.resource_type,
                            CloudResource.provider,
                            CloudResource.region,
                            CloudMetric.value
                        ).join(
                            CloudMetric, CloudResource.id == CloudMetric.resource_id
                        ).filter(
                            CloudMetric.metric_name == 'cost'
                        ).order_by(
                            CloudMetric.value.desc()
                        ).limit(10).all()

                        cloud_metrics['top_resources_by_cost'] = [{
                            'id': r[0],
                            'name': r[1],
                            'type': r[2],
                            'provider': r[3],
                            'region': r[4],
                            'cost': round(r[5], 2)
                        } for r in top_resources]

                        # Get resource metrics over time
                        # This could be expanded to include time-series data
                        # for resources, but we'll keep it simple for now

                    except Exception as detail_error:
                        logger.warning(f"Could not collect detailed cloud metrics: {detail_error}")

        except (ImportError, AttributeError) as model_error:
            logger.warning(f"Cloud models not available: {model_error}")

        except Exception as db_error:
            logger.warning(f"Database error while collecting cloud metrics: {db_error}")

        # If no data was collected from the database, use some placeholder data
        # This is just for demonstration purposes when no cloud resources are present
        if cloud_metrics['resource_count'] == 0:
            cloud_metrics['status'] = 'no_resources_found'
        else:
            cloud_metrics['status'] = 'active'

        return cloud_metrics

    except Exception as e:
        logger.error(f"Error collecting cloud metrics: {e}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

__all__ = [
    'collect_system_metrics',
    'collect_database_metrics',
    'collect_application_metrics',
    'collect_security_metrics',
    'collect_cloud_metrics'
]
