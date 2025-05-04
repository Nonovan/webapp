"""
Monitoring commands for the myproject CLI.

This module provides command-line utilities for system monitoring, metrics collection,
log viewing, and health diagnostics. These commands help administrators observe the
application's operational health, collect performance data, and troubleshoot issues.

The monitoring commands support both interactive use for immediate diagnostics and
scriptable operation for automated monitoring and alerting workflows.
"""

import logging
import errno
import time
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Set
import os
import json
import sys
import psutil
import click
import requests
from flask.cli import AppGroup
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
from core.utils.logging_utils import get_logger
from extensions import db, metrics, cache
from cli.common import (
    format_output, handle_error, confirm_action, require_permission,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_RESOURCE_ERROR
)

# Ensure logger is initialized
logger = get_logger(current_app)
if logger is None:
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

# Create command group
monitor_cli = AppGroup('monitor')

# Constants for thresholds and monitoring
DEFAULT_THRESHOLD = 80  # Percentage threshold for resource warnings
DEFAULT_RETRY_ATTEMPTS = 3  # Default number of retries for operations
DEFAULT_TIMEOUT = 5  # Default timeout in seconds
CRITICAL_SERVICES = ['database', 'web', 'cache', 'api']  # Critical services to monitor

def collect_system_metrics() -> Dict[str, str]:
    """
    Collect system-level metrics.

    Gathers key metrics about the host system including CPU usage,
    memory utilization, and disk usage. These metrics provide a snapshot
    of system resource utilization.

    Returns:
        Dict[str, str]: Dictionary of metrics with formatted values

    Example:
        {'CPU Usage': '45%', 'Memory Usage': '68%', 'Disk Usage': '72%'}
    """
    return {
        'CPU Usage': f"{psutil.cpu_percent()}%",
        'Memory Usage': f"{psutil.virtual_memory().percent}%",
        'Disk Usage': f"{psutil.disk_usage('/').percent}%"
    }

def collect_db_metrics() -> Dict[str, Any]:
    """
    Collect database metrics.

    Gathers key metrics about the database including active connections,
    total tables, and connection pool size. These metrics help monitor
    database health and resource utilization.

    Returns:
        Dict[str, Any]: A dictionary containing database metrics including
        active connections, total tables, and connection pool size.

    Example:
        {'Active Connections': 5, 'Total Tables': 12, 'Pool Size': 10}
    """
    try:
        # Handle pool status safely by checking for the existence of attributes
        pool_status = {}
        if hasattr(db.engine, 'pool') and db.engine.pool is not None:
            if hasattr(db.engine.pool, 'status') and callable(db.engine.pool.status):
                pool_status = db.engine.pool.status()
                # Check if pool_status is a dictionary
                if not isinstance(pool_status, dict):
                    pool_status = {}

        # Extract metrics with proper error handling
        active_connections = pool_status.get('checkedout', 0) if isinstance(pool_status, dict) else 0
        pool_size = pool_status.get('size', 0) if isinstance(pool_status, dict) else 0

        # Get additional metrics
        try:
            # Get database size if PostgreSQL
            if 'postgres' in str(db.engine.url).lower():
                db_size = db.session.execute(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                ).scalar()
            else:
                db_size = "Unknown"

            # Get query stats
            query_stats = db.session.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"
            ).scalar() if 'postgres' in str(db.engine.url).lower() else 0
        except Exception:
            db_size = "Unknown"
            query_stats = 0

        return {
            'Active Connections': active_connections,
            'Total Tables': len(db.metadata.tables),
            'Pool Size': pool_size,
            'Database Size': db_size,
            'Active Queries': query_stats
        }
    except Exception as e:
        logger.error("Error collecting database metrics: %s", str(e))

        # Still try to collect table count if possible
        total_tables = 0
        try:
            total_tables = len(db.metadata.tables)
        except Exception:
            pass

        return {
            'Active Connections': 'Error',
            'Total Tables': total_tables,
            'Pool Size': 'Error',
            'Database Size': 'Error',
            'Active Queries': 'Error'
        }

def collect_perf_metrics(app_metrics: Dict[str, Any]) -> Dict[str, str]:
    """
    Collect performance metrics.

    Formats application performance metrics for display, including response time,
    error rate, and cache hit rate. These metrics help identify performance
    bottlenecks and service degradation.

    Args:
        app_metrics: Dictionary containing raw application metrics

    Returns:
        Dict[str, str]: Formatted performance metrics with units

    Example:
        {'Response Time': '45ms', 'Error Rate': '0.5%', 'Cache Hit Rate': '95%'}
    """
    return {
        'Response Time': f"{app_metrics.get('response_time_avg', 0)}ms",
        'Error Rate': f"{app_metrics.get('error_rate', 0)}%",
        'Cache Hit Rate': f"{app_metrics.get('cache_hit_rate', 0)}%",
        'Request Rate': f"{app_metrics.get('request_rate', 0)}/sec"
    }

def collect_security_metrics() -> Dict[str, Any]:
    """
    Collect security-related metrics.

    Gathers metrics related to system security including failed login attempts,
    suspicious activities, and file integrity status. These metrics help identify
    potential security issues.

    Returns:
        Dict[str, Any]: Dictionary of security metrics

    Example:
        {'Failed Logins': 5, 'Suspicious IPs': 2, 'File Integrity': 'OK'}
    """
    try:
        # Import security functions only when needed to avoid circular imports
        from core.security.cs_monitoring import (
            get_failed_login_count,
            get_suspicious_ips,
            get_security_event_distribution
        )
        from core.security.cs_file_integrity import (
            check_critical_file_integrity,
            check_config_integrity
        )

        # Get last 24 hours of data
        hours = 24

        # Collect metrics
        failed_logins = get_failed_login_count(hours)
        suspicious_ips = len(get_suspicious_ips(hours))
        security_events = get_security_event_distribution(hours)
        file_integrity = "OK" if check_critical_file_integrity() else "COMPROMISED"
        config_integrity = "OK" if check_config_integrity() else "MODIFIED"

        # Count security event types
        high_severity_events = sum(count for event_type, count in security_events.items()
                                  if 'attack' in event_type or 'breach' in event_type)

        return {
            'Failed Logins (24h)': failed_logins,
            'Suspicious IPs': suspicious_ips,
            'High Severity Events': high_severity_events,
            'File Integrity': file_integrity,
            'Config Integrity': config_integrity
        }
    except (ImportError, AttributeError) as e:
        logger.warning("Security metrics collection limited: %s", str(e))
        return {
            'Failed Logins (24h)': 'N/A',
            'Suspicious IPs': 'N/A',
            'High Severity Events': 'N/A',
            'File Integrity': 'N/A',
            'Config Integrity': 'N/A'
        }

@monitor_cli.command('status')
@click.option('--detailed/--simple', default=False, help='Show detailed metrics')
@click.option('--security/--no-security', default=False, help='Include security metrics')
@click.option('--format', type=click.Choice(['text', 'json', 'csv']), default='text',
              help='Output format')
def system_status(detailed: bool, security: bool, format: str) -> None:
    """
    Show system status and metrics.

    Collects and displays various system metrics including system resources,
    database status, and application performance indicators. This command
    provides a quick overview of system health.

    In detailed mode, additional application metrics are displayed, including
    internal counters and gauges that can help with deeper analysis.

    Args:
        detailed: Whether to show detailed application metrics
        security: Whether to include security metrics
        format: Output format (text, json, csv)

    Examples:
        # Show basic system status
        $ flask monitor status

        # Show detailed metrics with security information
        $ flask monitor status --detailed --security

        # Export status as JSON
        $ flask monitor status --format json
    """
    try:
        # Collect all metrics
        metrics_data = _collect_all_metrics()

        # Add security metrics if requested
        if security:
            metrics_data['security'] = collect_security_metrics()

        # Determine display format
        if format != 'text':
            # Use the format_output utility for consistent output formatting
            output = format_output(metrics_data, format)
            click.echo(output)
            return

        # Text output format
        click.echo('\nSystem Status:')

        # Display metrics by category
        categories = ['system', 'database', 'performance']
        if security:
            categories.append('security')

        for category in categories:
            if category in metrics_data:
                click.echo(f"\n{category.capitalize()}:")
                for key, value in metrics_data[category].items():
                    click.echo(f"  {key}: {value}")

        if detailed:
            click.echo("\nDetailed Application Metrics:")
            for key, value in metrics_data['application'].items():
                click.echo(f"  {key}: {value}")

    except Exception as e:
        handle_error(e, "Status check failed")
        sys.exit(EXIT_RESOURCE_ERROR)

def _collect_all_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Helper function to collect all metrics with progress bar.

    Gathers metrics from various sources including system resources,
    database status, and application performance counters. Uses a progress
    bar to indicate collection status.

    Returns:
        Dict containing categorized metrics

    Example:
        {
            'system': {'CPU Usage': '45%', ...},
            'database': {'Active Connections': 5, ...},
            'application': {'requests_total': 1240, ...},
            'performance': {'Response Time': '45ms', ...}
        }
    """
    metrics_data: Dict[str, Dict[str, Any]] = {
        'system': {},
        'database': {},
        'application': {},
        'performance': {}
    }

    with click.progressbar(length=4, label='Collecting metrics') as bar_line:
        # System metrics
        metrics_data['system'] = collect_system_metrics()
        bar_line.update(1)

        # Database metrics
        metrics_data['database'] = collect_db_metrics()
        bar_line.update(1)

        # Application metrics - base metrics with correct types
        app_metrics: Dict[str, Any] = {
            'response_time_avg': 0,
            'error_rate': 0,
            'cache_hit_rate': 0,
            'request_rate': 0
        }

        # Extract metrics from Prometheus if possible
        try:
            _collect_prometheus_metrics(app_metrics)
        except Exception as metric_error:
            logger.warning("Could not collect application metrics: %s", str(metric_error))

        metrics_data['application'] = app_metrics
        bar_line.update(1)

        # Performance metrics
        metrics_data['performance'] = collect_perf_metrics(app_metrics)
        bar_line.update(1)

    return metrics_data

def _collect_prometheus_metrics(app_metrics: Dict[str, Any]) -> None:
    """
    Safely collect metrics from Prometheus registry.

    Extracts metrics from the Prometheus registry if available and adds them
    to the application metrics dictionary. Handles missing registry gracefully.

    Args:
        app_metrics: Dictionary to store collected metrics

    Raises:
        AttributeError: If metrics registry is not accessible
    """
    if not hasattr(metrics, 'registry') or not metrics.registry:
        return

    for metric in metrics.registry.collect():
        for sample in metric.samples:
            metric_name = str(sample.name)
            metric_value = sample.value

            # Handle metric storage in a type-safe way
            if metric_name not in app_metrics:
                # New metrics can be added directly
                app_metrics[metric_name] = metric_value
            else:
                # For existing metrics, we need to be type-safe
                _update_metric_safely(app_metrics, metric_name, metric_value)

def _update_metric_safely(metrics_dict: Dict[str, Any], key: str, value: Any) -> None:
    """
    Update a metric while preserving its type.

    Ensures metrics are stored with the appropriate type to prevent errors when
    displaying or processing metrics data. Handles type conversion gracefully.

    Args:
        metrics_dict: Dictionary containing metrics
        key: Metric name
        value: New value to store

    Example:
        # If metrics_dict['requests'] is an integer:
        _update_metric_safely(metrics_dict, 'requests', 42.0)
        # metrics_dict['requests'] will be updated to 42 (int)
    """
    existing_value = metrics_dict[key]

    if isinstance(existing_value, int):
        try:
            metrics_dict[key] = int(value)
        except (ValueError, TypeError):
            # Store as alternative key if can't convert
            metrics_dict[f"{key}_alt"] = value
    elif isinstance(existing_value, float):
        try:
            metrics_dict[key] = float(value)
        except (ValueError, TypeError):
            # Store as alternative key if can't convert
            metrics_dict[f"{key}_alt"] = value
    else:
        # For other types, just convert to string
        metrics_dict[f"{key}_alt"] = str(value)

@monitor_cli.command('logs')
@click.option('--lines', default=100, help='Number of lines to show')
@click.option('--level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO')
@click.option('--filter', help='Text to filter logs by')
@click.option('--watch', is_flag=True, help='Watch logs in real-time')
@click.option('--security', is_flag=True, help='Show security logs instead of application logs')
def view_logs(lines: int, level: str, filter: Optional[str], watch: bool, security: bool) -> None:
    """
    View application logs with filtering.

    Displays the most recent log entries from the application log file,
    filtered by the specified log level and optional text filter. This command
    is useful for quickly checking recent application activity and troubleshooting issues.

    Args:
        lines: Number of log lines to display
        level: Minimum log level to display (DEBUG, INFO, WARNING, ERROR)
        filter: Optional text to further filter logs
        watch: Watch logs in real-time (like tail -f)
        security: Show security logs instead of application logs

    Examples:
        # Show last 100 INFO or higher level logs
        $ flask monitor logs

        # Show last 500 ERROR logs
        $ flask monitor logs --lines=500 --level=ERROR

        # Show security-related logs
        $ flask monitor logs --security --level=WARNING

        # Watch logs in real-time
        $ flask monitor logs --watch
    """
    try:
        # Select the right log file
        log_file = 'logs/security.log' if security else 'logs/app.log'

        # Fall back to default log file if the selected one doesn't exist
        if not os.path.exists(log_file):
            alt_log_file = 'logs/app.log' if security else 'logs/security.log'
            if os.path.exists(alt_log_file):
                log_file = alt_log_file
                click.echo(f"Selected log file not found, using {log_file} instead")
            else:
                raise click.ClickException("Log file not found")

        # Handle watch mode differently
        if watch:
            # Implement a tail -f like functionality
            click.echo(f'\nWatching {log_file} for new {level} logs:')

            # Get the file size before we start
            initial_size = os.path.getsize(log_file)

            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    # Go to the end of the file
                    f.seek(0, 2)

                    # Show the last few lines first
                    last_lines = []
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f2:
                            all_lines = f2.readlines()
                            for line in all_lines[-10:]:  # Show last 10 lines initially
                                if level in line and (not filter or filter in line):
                                    last_lines.append(line.strip())

                        for line in last_lines:
                            click.echo(line)
                    except Exception:
                        pass

                    click.echo("\nWaiting for new logs... (Press Ctrl+C to exit)")

                    # Loop forever until user interrupts
                    while True:
                        line = f.readline()
                        if line:
                            if level in line and (not filter or filter in line):
                                click.echo(line.strip())
                        else:
                            # File hasn't been updated, wait a bit
                            time.sleep(0.1)

                            # Check if the file has been rotated
                            try:
                                current_size = os.path.getsize(log_file)
                                if current_size < initial_size:
                                    # File has been rotated, reopen it
                                    f.close()
                                    f = open(log_file, 'r', encoding='utf-8')
                                    initial_size = current_size
                            except FileNotFoundError:
                                # File has been deleted, exit gracefully
                                click.echo("Log file no longer exists, exiting watch mode.")
                                return
            except KeyboardInterrupt:
                click.echo("\nStopped watching logs")
                return
        else:
            # Normal mode - read and display logs
            click.echo(f'\nShowing last {lines} lines of {level} logs:')

            with open(log_file, 'r', encoding='utf-8') as f:
                logs = f.readlines()
                filtered_logs = [log for log in logs if level in log and (not filter or filter in log)]
                displayed = 0

                for log in filtered_logs[-lines:]:
                    click.echo(log.strip())
                    displayed += 1

                if displayed == 0:
                    click.echo(f"No logs found matching the criteria (level: {level}, filter: {filter})")
                else:
                    click.echo(f"\nDisplayed {displayed} log entries")

    except Exception as e:
        handle_error(e, "Log viewing failed")
        sys.exit(EXIT_ERROR)

@monitor_cli.command('metrics')
@click.option('--export', help='Export metrics to file')
@click.option('--format', type=click.Choice(['json', 'csv', 'prometheus']), default='json',
              help='Output format')
@click.option('--security', is_flag=True, help='Include security metrics')
def export_metrics(export: Optional[str] = None, format: str = 'json', security: bool = False) -> None:
    """
    Export system metrics to various formats.

    Collects comprehensive system metrics including CPU, memory, disk usage,
    network stats, and application/database information, and exports them to
    the specified format. Data can be displayed to the console or saved to a file.

    This command is useful for creating snapshots of system performance for
    analysis, historical comparison, or integration with monitoring systems.

    Args:
        export: Filename to export metrics to (if omitted, prints to console)
        format: Output format (json, csv, prometheus)
        security: Whether to include security metrics

    Examples:
        # Display metrics on console in JSON format
        $ flask monitor metrics

        # Export metrics to file
        $ flask monitor metrics --export=metrics_2023-10-15.json

        # Export metrics in Prometheus format
        $ flask monitor metrics --format=prometheus --export=node_metrics.prom

        # Include security metrics
        $ flask monitor metrics --security
    """
    try:
        # Collect all metrics in separate functions to reduce complexity
        app_metrics = _collect_application_metrics()
        db_metrics = _collect_database_metrics()
        sys_metrics = _collect_system_metrics()

        # Collect security metrics if requested
        security_metrics = {}
        if security:
            security_metrics = collect_security_metrics()

        # Get platform/environment information
        env_info = {
            'hostname': platform.node(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'python_version': platform.python_version(),
            'environment': current_app.config.get('ENVIRONMENT', 'production') if current_app else None
        }

        # Remove None values from environment info
        env_info = {k: v for k, v in env_info.items() if v is not None}

        # Assemble final data structure
        data = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': env_info,
            'system': sys_metrics,
            'application': app_metrics,
            'database': db_metrics
        }

        # Add security metrics if collected
        if security and security_metrics:
            data['security'] = security_metrics

        # Format output according to specified format
        if format == 'json':
            output = json.dumps(data, indent=2)
        elif format == 'csv':
            # Create CSV output - flatten the nested structure
            import csv
            from io import StringIO

            output_buffer = StringIO()
            csv_writer = csv.writer(output_buffer)

            # Write header row
            csv_writer.writerow(['Category', 'Metric', 'Value'])

            # Write metrics rows
            for category, metrics_dict in data.items():
                if category == 'timestamp':
                    csv_writer.writerow(['General', 'timestamp', data['timestamp']])
                    continue

                if isinstance(metrics_dict, dict):
                    for metric_name, metric_value in metrics_dict.items():
                        if isinstance(metric_value, dict):
                            for sub_name, sub_value in metric_value.items():
                                csv_writer.writerow([category, f"{metric_name}.{sub_name}", sub_value])
                        else:
                            csv_writer.writerow([category, metric_name, metric_value])

            output = output_buffer.getvalue()
        else:  # prometheus
            # Create Prometheus format output
            lines = []
            prefix = "myproject"

            # Add system metrics
            for key, value in sys_metrics.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, (int, float)):
                            lines.append(f"{prefix}_system_{key}_{sub_key} {sub_value}")
                elif isinstance(value, (int, float)):
                    lines.append(f"{prefix}_system_{key} {value}")

            # Add application metrics
            for key, value in app_metrics.items():
                if isinstance(value, (int, float)):
                    lines.append(f"{prefix}_{key} {value}")

            # Add database metrics
            for key, value in db_metrics.items():
                if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
                    try:
                        numeric_value = float(value)
                        lines.append(f"{prefix}_db_{key.lower().replace(' ', '_')} {numeric_value}")
                    except (ValueError, TypeError):
                        pass

            # Add timestamp
            lines.append(f"{prefix}_metrics_timestamp {int(datetime.utcnow().timestamp())}")

            output = "\n".join(lines)

        # Save to file or output to console
        if export:
            # Ensure directory exists
            os.makedirs(os.path.dirname(export) if os.path.dirname(export) else 'metrics', exist_ok=True)

            # Write to file
            with open(export, 'w', encoding='utf-8') as f:
                f.write(output)
            click.echo(f"Metrics exported to {export}")
        else:
            # Print to console
            click.echo(output)

    except Exception as e:
        handle_error(e, "Metrics export failed")
        sys.exit(EXIT_ERROR)

def _collect_application_metrics() -> Dict[str, Any]:
    """
    Collect application metrics from Prometheus registry.

    Gathers application-specific metrics including request counts, response times,
    error rates, and custom business metrics from the Prometheus registry.

    Returns:
        Dict[str, Any]: Dictionary of application metrics

    Example:
        {
            'http_requests_total': 1240,
            'http_request_duration_seconds_avg': 0.056,
            'error_count': 23
        }
    """
    app_metrics = {}
    try:
        # Collect metrics from Prometheus registry
        if hasattr(metrics, 'registry') and metrics.registry:
            for metric in metrics.registry.collect():
                for sample in metric.samples:
                    app_metrics[sample.name] = sample.value

        # Calculate derived metrics if possible
        http_requests = app_metrics.get('http_requests_total', 0)
        http_errors = app_metrics.get('http_errors_total', 0)

        # Calculate error rate if we have both values
        if http_requests > 0:
            app_metrics['error_rate'] = (http_errors / http_requests) * 100

        # Get cache hit rate if available
        if 'cache_hits_total' in app_metrics and 'cache_misses_total' in app_metrics:
            cache_hits = app_metrics.get('cache_hits_total', 0)
            cache_misses = app_metrics.get('cache_misses_total', 0)
            total_cache_ops = cache_hits + cache_misses

            if total_cache_ops > 0:
                app_metrics['cache_hit_rate'] = (cache_hits / total_cache_ops) * 100

        # Get application version and uptime if available
        app_metrics['version'] = current_app.config.get('VERSION', '0.0.0') if current_app else None

        # If we have Flask app context, get the uptime
        if hasattr(current_app, 'uptime'):
            app_uptime = datetime.utcnow() - current_app.uptime
            app_metrics['uptime_seconds'] = app_uptime.total_seconds()

    except Exception as app_error:
        logger.warning("Error collecting application metrics: %s", str(app_error))
        app_metrics = {"error": str(app_error)}

    return app_metrics

def _collect_database_metrics() -> Dict[str, Any]:
    """
    Collect database metrics safely.

    Gathers database performance metrics including connection pool status,
    table counts, and database size. Handles missing attributes gracefully.

    Returns:
        Dict[str, Any]: Dictionary of database metrics

    Example:
        {
            'connections': 5,
            'tables': 12,
            'pool_size': 10
        }
    """
    db_metrics = {}
    try:
        pool_status = {}
        if hasattr(db.engine, 'pool') and db.engine.pool is not None:
            if hasattr(db.engine.pool, 'status') and callable(db.engine.pool.status):
                pool_status = db.engine.pool.status()
                if not isinstance(pool_status, dict):
                    pool_status = {}

        db_metrics = {
            'connections': pool_status.get('checkedout', 0),
            'tables': len(db.metadata.tables)
        }

        # Collect database type and version if possible
        if hasattr(db, 'engine') and hasattr(db.engine, 'url'):
            db_metrics['type'] = str(db.engine.url).split('://')[0] if '://' in str(db.engine.url) else 'unknown'

            # Get database version if PostgreSQL
            if db_metrics['type'] == 'postgresql':
                try:
                    db_version = db.session.execute("SELECT version()").scalar()
                    db_metrics['version'] = db_version.split(' on ')[0] if ' on ' in db_version else db_version
                except Exception:
                    pass

        # Get connection pool info
        if pool_status:
            for key in ['size', 'overflow', 'timeout']:
                if key in pool_status:
                    db_metrics[f"pool_{key}"] = pool_status[key]

    except Exception as db_error:
        logger.warning("Error collecting database metrics: %s", str(db_error))
        db_metrics = {"error": str(db_error)}

    return db_metrics

def _collect_system_metrics() -> Dict[str, Any]:
    """
    Collect system metrics with error handling.

    Gathers system-level metrics including CPU usage, memory utilization,
    disk usage, and network I/O statistics. Handles exceptions gracefully.

    Returns:
        Dict[str, Any]: Dictionary of system metrics

    Example:
        {
            'cpu': 45.2,
            'memory': {'total': 16384, 'used': 8192, 'free': 8192},
            'disk': {'total': 512000, 'used': 256000, 'free': 256000},
            'network': {'bytes_sent': 123456, 'bytes_recv': 654321}
        }
    """
    sys_metrics = {}
    try:
        # Core system metrics
        sys_metrics = {
            'cpu': psutil.cpu_percent(),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disk': dict(psutil.disk_usage('/')._asdict()),
            'network': dict(psutil.net_io_counters()._asdict())
        }

        # Add CPU load averages on Unix-like systems
        if hasattr(os, 'getloadavg'):
            sys_metrics['load'] = list(os.getloadavg())

        # Get CPU count for context
        sys_metrics['cpu_count'] = psutil.cpu_count(logical=False)
        sys_metrics['cpu_count_logical'] = psutil.cpu_count(logical=True)

        # Get boot time
        sys_metrics['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).isoformat()

        # Get disk I/O statistics
        if hasattr(psutil, 'disk_io_counters'):
            sys_metrics['disk_io'] = dict(psutil.disk_io_counters()._asdict())

        # System uptime
        sys_metrics['uptime_seconds'] = (datetime.now() -
                                      datetime.fromtimestamp(psutil.boot_time())).total_seconds()

    except Exception as sys_error:
        logger.warning("Error collecting system metrics: %s", str(sys_error))
        sys_metrics = {"error": str(sys_error)}

    return sys_metrics

@monitor_cli.command('health')
@click.option('--threshold', default=90, help='Warning threshold percentage')
@click.option('--export', help='Export results to file')
@click.option('--format', type=click.Choice(['json', 'text', 'csv']), default='text',
              help='Output format')
@click.option('--alert', is_flag=True, help='Generate alert for failures')
def health_check(threshold: int, export: Optional[str] = None, format: str = 'text',
                alert: bool = False) -> None:
    """
    Perform system health check with comprehensive diagnostics.

    Runs a series of checks on system resources, database connectivity,
    cache availability, and external API health. Reports results and
    optionally exports the data to a file.

    This command is designed for both interactive diagnostics and
    automated monitoring in scripts or CI/CD pipelines.

    Args:
        threshold: Warning threshold percentage for resource usage
        export: Filename to export results to (optional)
        format: Output format (json, text, csv)
        alert: Generate alert for failed checks

    Examples:
        # Run health check with default thresholds
        $ flask monitor health

        # Run health check with custom threshold
        $ flask monitor health --threshold=80

        # Export health check results to file
        $ flask monitor health --export=health_2023-10-15.json --format=json

        # Generate alerts for failed checks
        $ flask monitor health --alert
    """
    try:
        # Define health checks with proper error handling
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < threshold,
            'Memory': lambda: psutil.virtual_memory().percent < threshold,
            'CPU': lambda: psutil.cpu_percent() < threshold,
            'Redis': lambda: _check_redis_connection(),
            'API Health': lambda: _check_api_health(),
            'File System': lambda: _check_filesystem_access(),
            'Process Count': lambda: _check_process_count(),
            'Network Connectivity': lambda: _check_network_connectivity()
        }

        results = {}
        failures = []
        details = {}

        with click.progressbar(length=len(checks), label='Running health checks') as bar_line:
            for name, check in checks.items():
                try:
                    # Get result and additional details if available
                    check_result = check()

                    # Handle tuple return (result, details)
                    if isinstance(check_result, tuple) and len(check_result) == 2:
                        results[name] = check_result[0]
                        details[name] = check_result[1]
                    else:
                        results[name] = bool(check_result)

                    if not results[name]:
                        failures.append(name)
                    bar_line.update(1)
                except (psutil.Error, SQLAlchemyError, requests.RequestException) as e:
                    results[name] = False
                    failures.append(name)
                    details[name] = str(e)
                    logger.error("Health check '%s' failed: %s", name, e)

        # Create health status dictionary for output
        health_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'results': results,
            'failures': failures,
            'threshold': threshold,
            'overall_status': 'healthy' if not failures else 'unhealthy',
            'details': details
        }

        # Generate alert if requested and there are failures
        if alert and failures:
            _generate_health_alert(failures, details)

        # Format and display output based on format option
        if format == 'json':
            if export:
                os.makedirs(os.path.dirname(export) if os.path.dirname(export) else 'metrics', exist_ok=True)
                with open(export, 'w', encoding='utf-8') as f:
                    json.dump(health_data, f, indent=2)
                click.echo(f"\nResults exported to {export}")
            else:
                click.echo(json.dumps(health_data, indent=2))
        elif format == 'csv':
            # Create CSV output
            import csv
            from io import StringIO

            output_buffer = StringIO()
            csv_writer = csv.writer(output_buffer)

            # Write header and data
            csv_writer.writerow(['Check', 'Status', 'Details'])
            for name in sorted(results.keys()):
                status = 'Pass' if results[name] else 'Fail'
                detail = details.get(name, '')
                csv_writer.writerow([name, status, detail])

            csv_output = output_buffer.getvalue()

            if export:
                os.makedirs(os.path.dirname(export) if os.path.dirname(export) else 'metrics', exist_ok=True)
                with open(export, 'w', encoding='utf-8') as f:
                    f.write(csv_output)
                click.echo(f"\nResults exported to {export}")
            else:
                click.echo(csv_output)
        else:  # text format
            # Display results
            click.echo("\nHealth Check Results:")
            for name in sorted(results.keys()):
                status_symbol = '✅' if results[name] else '❌'
                status_text = click.style('PASS', fg='green') if results[name] else click.style('FAIL', fg='red')
                click.echo(f"  {status_symbol} {name}: {status_text}")

                # Show details for failures
                if not results[name] and name in details:
                    click.echo(f"      Details: {details[name]}")

            # Show summary
            click.echo(f"\nSummary: {len(results) - len(failures)}/{len(results)} checks passed")

            if export:
                # For text format with export, use JSON for the file
                os.makedirs(os.path.dirname(export) if os.path.dirname(export) else 'metrics', exist_ok=True)
                with open(export, 'w', encoding='utf-8') as f:
                    json.dump(health_data, f, indent=2)
                click.echo(f"\nResults exported to {export}")

        # Exit with error if any checks failed
        if failures:
            sys.exit(EXIT_RESOURCE_ERROR)

    except Exception as e:
        handle_error(e, "Health check failed")
        sys.exit(EXIT_ERROR)


def _check_redis_connection() -> bool:
    """
    Helper to safely check Redis connection.

    Attempts to verify Redis connectivity by setting and retrieving a test value.
    This validates both connection status and read/write functionality.

    Returns:
        bool: True if Redis connection is working, False otherwise

    Example:
        if _check_redis_connection():
            # Redis is available
            cache.set('key', 'value')
    """
    try:
        # First try to set a test value
        if cache.set('health_check_test', True):
            # Then verify we can retrieve it
            test_value = cache.get('health_check_test')
            # Clean up after ourselves
            cache.delete('health_check_test')
            # Explicitly return a boolean value
            return test_value is True
        return False
    except Exception as e:
        logger.error("Redis connection check failed: %s", e)
        return False


def _check_api_health() -> bool:
    """
    Helper to safely check API health.

    Verifies the health of external API dependencies by making a request
    to their health endpoint. This ensures the application can communicate
    with external services.

    Returns:
        bool: True if API is healthy, False otherwise

    Example:
        if _check_api_health():
            # External API is available
            response = requests.get(f"{API_URL}/data")
    """
    try:
        if not current_app or not current_app.config.get('API_URL'):
            return True

        response = requests.get(
            f"{current_app.config['API_URL']}/health",
            timeout=DEFAULT_TIMEOUT
        )
        return response.ok
    except Exception as e:
        logger.error("API health check failed: %s", e)
        return False


def _check_filesystem_access() -> Tuple[bool, Dict[str, Any]]:
    """
    Check filesystem access and permissions.

    Verifies that the application can read and write to necessary
    directories for proper operation.

    Returns:
        Tuple containing:
        - bool: True if filesystem checks pass, False otherwise
        - Dict: Details about the filesystem check
    """
    details = {}
    try:
        # Check temp directory
        temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp') if current_app else '/tmp'
        test_file = os.path.join(temp_dir, f"health_check_{int(time.time())}.txt")

        # Try to write a test file
        with open(test_file, "w") as f:
            f.write("health check test")

        # Read it back
        with open(test_file, "r") as f:
            content = f.read()

        # Verify content
        if content != "health check test":
            details['read_test'] = "Failed: Content mismatch"
            return False, details

        # Clean up
        os.remove(test_file)

        # Check application directories
        app_dirs = ['logs', 'uploads', 'instance']
        for directory in app_dirs:
            if os.path.exists(directory):
                if not os.access(directory, os.R_OK | os.W_OK):
                    details[f'dir_{directory}'] = "Failed: Permission denied"
                    return False, details
            else:
                details[f'dir_{directory}'] = "Warning: Directory not found"

        details['status'] = "All filesystem checks passed"
        return True, details

    except Exception as e:
        details['error'] = str(e)
        logger.error("Filesystem check failed: %s", e)
        return False, details


def _check_process_count() -> Tuple[bool, Dict[str, Any]]:
    """
    Check system process count and resource usage.

    Verifies that the system is not overloaded with too many processes
    and that critical system processes are running.

    Returns:
        Tuple containing:
        - bool: True if process checks pass, False otherwise
        - Dict: Details about process counts and status
    """
    details = {}
    try:
        # Get process count
        process_count = len(psutil.pids())
        details['process_count'] = process_count

        # Check if we're close to system limits
        # A typical system can handle thousands of processes, but performance
        # may degrade with too many. This is a very conservative threshold.
        max_recommended = 500

        if process_count > max_recommended:
            details['status'] = f"Warning: High process count ({process_count})"
            return True, details  # Not failing but including a warning

        # Check for critical system processes (simplified)
        critical_patterns = ['systemd', 'init', 'sshd', 'nginx', 'apache2', 'httpd', 'postgres', 'mysql', 'redis']
        found_processes = set()

        for proc in psutil.process_iter(['name']):
            try:
                for pattern in critical_patterns:
                    if pattern in proc.info['name']:
                        found_processes.add(pattern)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        details['critical_services'] = list(found_processes)

        # Not failing the check based on critical processes
        # as the requirements will vary by environment
        details['status'] = "Process check passed"
        return True, details

    except Exception as e:
        details['error'] = str(e)
        logger.error("Process count check failed: %s", e)
        return True, details  # Not failing the health check for this


def _check_network_connectivity() -> Tuple[bool, Dict[str, Any]]:
    """
    Check network connectivity to critical services.

    Verifies that the system can connect to important external
    services like DNS servers, API endpoints, etc.

    Returns:
        Tuple containing:
        - bool: True if network connectivity is good, False otherwise
        - Dict: Details about the connectivity check
    """
    details = {'services': {}}
    all_checks_passed = True

    # Define services to check
    services = [
        ('dns', 'www.google.com', 443),  # DNS resolution test
        ('cloud_api', 'api.github.com', 443)  # Example external API
    ]

    # Add configurable API endpoint if available
    if current_app and current_app.config.get('API_URL'):
        try:
            from urllib.parse import urlparse
            api_url = current_app.config['API_URL']
            parsed = urlparse(api_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if hostname:
                services.append(('app_api', hostname, port))
        except Exception:
            pass

    # Check each service
    for service_name, host, port in services:
        service_status = _check_tcp_connection(host, port)
        details['services'][service_name] = {
            'host': host,
            'port': port,
            'status': 'up' if service_status else 'down'
        }
        if not service_status:
            all_checks_passed = False

    # Check for general internet connectivity
    try:
        # Simple ping-like check
        response = requests.get('https://www.google.com', timeout=DEFAULT_TIMEOUT)
        internet_up = response.status_code == 200
    except Exception:
        internet_up = False

    details['internet_connectivity'] = 'up' if internet_up else 'down'

    # Fail the check only if critical services are down
    if not internet_up or not details['services'].get('dns', {}).get('status') == 'up':
        all_checks_passed = False

    return all_checks_passed, details


def _check_tcp_connection(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """
    Check if a TCP connection can be established to the specified host and port.

    Args:
        host: The hostname or IP address to connect to
        port: The port to connect to
        timeout: Connection timeout in seconds

    Returns:
        bool: True if connection successful, False otherwise
    """
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
        return True
    except (socket.timeout, socket.error):
        return False


def _generate_health_alert(failures: List[str], details: Dict[str, Any]) -> None:
    """
    Generate alert for failed health checks.

    Logs alerts for failed health checks and optionally sends
    notifications depending on configuration.

    Args:
        failures: List of failed check names
        details: Dictionary with detailed failure information
    """
    try:
        # Log alert
        failure_str = ', '.join(failures)
        logger.error(f"ALERT: Health check failed: {failure_str}")

        # If notification system is available
        if current_app and hasattr(current_app, 'notify_admins'):
            message = f"Health check failure detected: {failure_str}\n\nDetails:\n"
            for failure in failures:
                message += f"- {failure}: {details.get(failure, 'No details')}\n"

            # Send notification
            current_app.notify_admins("System Health Alert", message)

        # Write to alert file if configured
        alert_dir = current_app.config.get('ALERT_DIR', 'logs/alerts') if current_app else 'logs/alerts'
        if alert_dir:
            os.makedirs(alert_dir, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            alert_file = os.path.join(alert_dir, f"health_alert_{timestamp}.json")

            with open(alert_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.utcnow().isoformat(),
                    'failures': failures,
                    'details': details
                }, f, indent=2)

    except Exception as e:
        logger.error(f"Failed to generate health alert: {e}")


@monitor_cli.command('resource-usage')
@click.option('--duration', default=60, help='Duration to monitor in seconds')
@click.option('--interval', default=5, help='Sampling interval in seconds')
@click.option('--cpu-threshold', default=DEFAULT_THRESHOLD, help='CPU usage threshold percentage')
@click.option('--memory-threshold', default=DEFAULT_THRESHOLD, help='Memory usage threshold percentage')
@click.option('--disk-threshold', default=DEFAULT_THRESHOLD, help='Disk usage threshold percentage')
@click.option('--export', help='Export results to file')
@click.option('--notify/--no-notify', default=False, help='Notify on threshold violations')
@click.option('--watch/--no-watch', default=False, help='Display live updates')
def monitor_resources(duration: int, interval: int, cpu_threshold: int, memory_threshold: int,
                    disk_threshold: int, export: Optional[str] = None, notify: bool = False,
                    watch: bool = False) -> None:
    """
    Monitor system resource usage over time.

    Collects and displays system resource metrics (CPU, memory, disk) at specified
    intervals for a specified duration. Can notify when thresholds are exceeded
    and export the collected data to a file.

    This command is useful for performance analysis, capacity planning,
    and identifying resource bottlenecks.

    Args:
        duration: Duration to monitor in seconds
        interval: Sampling interval in seconds
        cpu_threshold: CPU usage threshold percentage
        memory_threshold: Memory usage threshold percentage
        disk_threshold: Disk usage threshold percentage
        export: Export results to file
        notify: Send notifications on threshold violations
        watch: Display live updates in watch mode

    Examples:
        # Monitor resources for 5 minutes with 10-second intervals
        $ flask monitor resource-usage --duration 300 --interval 10

        # Monitor with custom thresholds and export results
        $ flask monitor resource-usage --cpu-threshold 70 --export resource_log.json

        # Monitor in watch mode with live updates
        $ flask monitor resource-usage --watch
    """
    try:
        # Validate input parameters
        if interval <= 0 or duration <= 0:
            raise click.BadParameter("Interval and duration must be positive")
        if interval > duration:
            raise click.BadParameter("Interval must be less than or equal to duration")

        # Initialize data structures for collection
        timestamps = []
        cpu_data = []
        memory_data = []
        disk_data = []
        violations = []

        # If in watch mode, calculate how many steps we need
        steps = duration // interval

        # Function to check threshold violations
        def check_violations(cpu: float, memory: float, disk: float, timestamp: str) -> None:
            if cpu >= cpu_threshold:
                violations.append({
                    'type': 'CPU',
                    'value': cpu,
                    'threshold': cpu_threshold,
                    'timestamp': timestamp
                })
                if notify:
                    logger.warning(f"CPU usage threshold exceeded: {cpu}% >= {cpu_threshold}%")

            if memory >= memory_threshold:
                violations.append({
                    'type': 'Memory',
                    'value': memory,
                    'threshold': memory_threshold,
                    'timestamp': timestamp
                })
                if notify:
                    logger.warning(f"Memory usage threshold exceeded: {memory}% >= {memory_threshold}%")

            if disk >= disk_threshold:
                violations.append({
                    'type': 'Disk',
                    'value': disk,
                    'threshold': disk_threshold,
                    'timestamp': timestamp
                })
                if notify:
                    logger.warning(f"Disk usage threshold exceeded: {disk}% >= {disk_threshold}%")

        # If in watch mode, set up display
        if watch:
            click.echo("\nMonitoring system resources (Press Ctrl+C to exit):\n")
            click.echo(f"{'Timestamp':^20} | {'CPU Usage':^10} | {'Memory Usage':^12} | {'Disk Usage':^10}")
            click.echo("-" * 60)
        else:
            click.echo(f"\nMonitoring system resources for {duration} seconds with {interval}-second intervals...")

        # Start monitoring
        start_time = time.time()
        end_time = start_time + duration

        try:
            # Main monitoring loop
            while time.time() < end_time:
                # Get current timestamp
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                timestamps.append(current_time)

                # Collect metrics
                cpu_percent = psutil.cpu_percent(interval=0)  # Non-blocking
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent

                # Store data
                cpu_data.append(cpu_percent)
                memory_data.append(memory_percent)
                disk_data.append(disk_percent)

                # Check for threshold violations
                check_violations(cpu_percent, memory_percent, disk_percent, current_time)

                # Display in watch mode
                if watch:
                    # Apply color formatting based on thresholds
                    cpu_color = 'red' if cpu_percent >= cpu_threshold else (
                        'yellow' if cpu_percent >= cpu_threshold * 0.8 else None)
                    mem_color = 'red' if memory_percent >= memory_threshold else (
                        'yellow' if memory_percent >= memory_threshold * 0.8 else None)
                    disk_color = 'red' if disk_percent >= disk_threshold else (
                        'yellow' if disk_percent >= disk_threshold * 0.8 else None)

                    cpu_value = click.style(f"{cpu_percent:>6.1f}%", fg=cpu_color)
                    mem_value = click.style(f"{memory_percent:>6.1f}%", fg=mem_color)
                    disk_value = click.style(f"{disk_percent:>6.1f}%", fg=disk_color)

                    click.echo(f"{current_time} | {cpu_value:^10} | {mem_value:^12} | {disk_value:^10}")

                # Sleep until next interval
                time.sleep(interval)

        except KeyboardInterrupt:
            if watch:
                click.echo("\nMonitoring stopped by user")

        # Calculate statistics
        from typing import Callable

        def safe_stat(data_list: List[float], func: Callable[[List[float]], float]) -> float:
            try:
                if data_list:
                    return func(data_list)
                return 0.0
            except:
                return 0.0

        # Prepare results
        results = {
            'start_time': timestamps[0] if timestamps else None,
            'end_time': timestamps[-1] if timestamps else None,
            'duration': duration,
            'interval': interval,
            'samples': len(timestamps),
            'thresholds': {
                'cpu': cpu_threshold,
                'memory': memory_threshold,
                'disk': disk_threshold
            },
            'cpu': {
                'min': safe_stat(cpu_data, min),
                'max': safe_stat(cpu_data, max),
                'avg': sum(cpu_data) / len(cpu_data) if cpu_data else 0,
                'samples': cpu_data
            },
            'memory': {
                'min': safe_stat(memory_data, min),
                'max': safe_stat(memory_data, max),
                'avg': sum(memory_data) / len(memory_data) if memory_data else 0,
                'samples': memory_data
            },
            'disk': {
                'min': safe_stat(disk_data, min),
                'max': safe_stat(disk_data, max),
                'avg': sum(disk_data) / len(disk_data) if disk_data else 0,
                'samples': disk_data
            },
            'timestamps': timestamps,
            'violations': violations,
            'violation_count': len(violations)
        }

        # Display summary if not in watch mode
        if not watch:
            click.echo("\nResource Monitoring Summary:")
            click.echo(f"  Duration: {duration} seconds")
            click.echo(f"  Interval: {interval} seconds")
            click.echo(f"  Samples: {len(timestamps)}")

            # CPU
            cpu_avg = results['cpu']['avg']
            cpu_max = results['cpu']['max']
            cpu_color = 'red' if cpu_max >= cpu_threshold else (
                'yellow' if cpu_max >= cpu_threshold * 0.8 else 'green')
            click.echo(f"\nCPU Usage:")
            click.echo(f"  Average: {cpu_avg:.1f}%")
            click.echo(f"  Maximum: {click.style(f'{cpu_max:.1f}%', fg=cpu_color)}")
            click.echo(f"  Threshold: {cpu_threshold}%")

            # Memory
            mem_avg = results['memory']['avg']
            mem_max = results['memory']['max']
            mem_color = 'red' if mem_max >= memory_threshold else (
                'yellow' if mem_max >= memory_threshold * 0.8 else 'green')
            click.echo(f"\nMemory Usage:")
            click.echo(f"  Average: {mem_avg:.1f}%")
            click.echo(f"  Maximum: {click.style(f'{mem_max:.1f}%', fg=mem_color)}")
            click.echo(f"  Threshold: {memory_threshold}%")

            # Disk
            disk_avg = results['disk']['avg']
            disk_max = results['disk']['max']
            disk_color = 'red' if disk_max >= disk_threshold else (
                'yellow' if disk_max >= disk_threshold * 0.8 else 'green')
            click.echo(f"\nDisk Usage:")
            click.echo(f"  Average: {disk_avg:.1f}%")
            click.echo(f"  Maximum: {click.style(f'{disk_max:.1f}%', fg=disk_color)}")
            click.echo(f"  Threshold: {disk_threshold}%")

            # Violations
            if violations:
                click.echo(f"\nThreshold Violations: {len(violations)}")
                for v in violations[:5]:  # Show up to 5 violations
                    click.echo(f"  {v['timestamp']}: {v['type']} {v['value']:.1f}% (threshold: {v['threshold']}%)")
                if len(violations) > 5:
                    click.echo(f"  ... and {len(violations) - 5} more")
            else:
                click.echo("\nNo threshold violations detected")

        # Export results if requested
        if export:
            os.makedirs(os.path.dirname(export) if os.path.dirname(export) else 'metrics', exist_ok=True)
            with open(export, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            click.echo(f"\nResults exported to {export}")

        # Set exit code based on violations
        if violations:
            if not watch:
                click.echo("\nWarning: Resource thresholds exceeded during monitoring period")
            return EXIT_RESOURCE_ERROR

    except Exception as e:
        handle_error(e, "Resource monitoring failed")
        return EXIT_ERROR


@monitor_cli.command('processes')
@click.option('--sort-by', type=click.Choice(['cpu', 'memory', 'name', 'pid']), default='cpu',
              help='Sort processes by this field')
@click.option('--count', default=10, help='Number of processes to show')
@click.option('--format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
def list_processes(sort_by: str, count: int, format: str) -> None:
    """
    List top system processes by resource usage.

    Shows the most resource-intensive processes running on the system,
    sorted by CPU usage, memory usage, name, or PID. This command helps
    identify processes that may be causing resource constraints.

    Args:
        sort_by: Field to sort processes by (cpu, memory, name, pid)
        count: Number of processes to show
        format: Output format (table, json, csv)

    Examples:
        # Show top 10 processes by CPU usage
        $ flask monitor processes

        # Show top 20 processes by memory usage
        $ flask monitor processes --sort-by memory --count 20

        # Export process list as JSON
        $ flask monitor processes --format json
    """
    try:
        # Get list of processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'status', 'create_time']):
            try:
                # Get process info
                proc_info = proc.info

                # Get additional info
                proc_info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                proc_info['memory_percent'] = proc.memory_percent()
                proc_info['memory_mb'] = proc_info['memory_info'].rss / (1024 * 1024)
                proc_info['running_time'] = datetime.now().timestamp() - proc_info['create_time']
                proc_info['command'] = ' '.join(proc.cmdline())[:50] if hasattr(proc, 'cmdline') else ''

                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Sort processes
        if sort_by == 'cpu':
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        elif sort_by == 'memory':
            processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
        elif sort_by == 'name':
            processes.sort(key=lambda x: x.get('name', '').lower())
        else:  # pid
            processes.sort(key=lambda x: x.get('pid', 0))

        # Limit to specified count
        processes = processes[:count]

        # Prepare data for output
        output_data = []
        for proc in processes:
            # Format running time
            running_seconds = proc.get('running_time', 0)
            hours, remainder = divmod(running_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            runtime = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

            output_data.append({
                'pid': proc.get('pid', 0),
                'name': proc.get('name', 'unknown'),
                'cpu': f"{proc.get('cpu_percent', 0):.1f}%",
                'memory': f"{proc.get('memory_mb', 0):.1f} MB ({proc.get('memory_percent', 0):.1f}%)",
                'user': proc.get('username', 'unknown'),
                'status': proc.get('status', 'unknown'),
                'runtime': runtime,
                'command': proc.get('command', '')
            })

        # Format and display output based on format option
        if format == 'json':
            # JSON output
            click.echo(json.dumps(output_data, indent=2))
        elif format == 'csv':
            # CSV output
            import csv
            from io import StringIO

            output_buffer = StringIO()
            csv_writer = csv.writer(output_buffer)

            # Write header row
            csv_writer.writerow(['PID', 'Name', 'CPU Usage', 'Memory', 'User', 'Status', 'Runtime', 'Command'])

            # Write data rows
            for proc in output_data:
                csv_writer.writerow([
                    proc['pid'],
                    proc['name'],
                    proc['cpu'],
                    proc['memory'],
                    proc['user'],
                    proc['status'],
                    proc['runtime'],
                    proc['command']
                ])

            click.echo(output_buffer.getvalue())
        else:
            # Table output with proper formatting
            click.echo("\nTop System Processes:")
            click.echo(f"{'PID':>8} {'Name':<20} {'CPU':>6} {'Memory':>14} {'User':<12} {'Status':<10} {'Runtime':<10}")
            click.echo("-" * 90)

            for proc in output_data:
                pid = proc['pid']
                name = proc['name'][:18] + '..' if len(proc['name']) > 20 else proc['name']
                cpu = proc['cpu']
                memory = proc['memory']
                user = proc['user'][:10] + '..' if len(proc['user']) > 12 else proc['user']
                status = proc['status']
                runtime = proc['runtime']

                # Colorize high CPU or memory usage
                if float(cpu.strip('%')) > 50:
                    cpu = click.style(cpu, fg='red')
                elif float(cpu.strip('%')) > 20:
                    cpu = click.style(cpu, fg='yellow')

                # Truncate long fields
                click.echo(f"{pid:>8} {name:<20} {cpu:>6} {memory:>14} {user:<12} {status:<10} {runtime:<10}")

            click.echo(f"\nShowing top {len(output_data)} processes sorted by {sort_by}")

    except Exception as e:
        handle_error(e, "Process listing failed")
        sys.exit(EXIT_ERROR)


@monitor_cli.command('connections')
@click.option('--state', type=click.Choice(['all', 'established', 'listen', 'time_wait']), default='all',
                help='Filter connections by state')
@click.option('--protocol', type=click.Choice(['all', 'tcp', 'udp']), default='all',
                help='Filter connections by protocol')
@click.option('--local-only/--all-connections', default=False,
                help='Show only local connections')
@click.option('--count', default=20, help='Number of connections to show')
@click.option('--format', type=click.Choice(['table', 'json', 'csv']), default='table',
                help='Output format')
@require_permission('system:monitor')
def list_connections(state: str, protocol: str, local_only: bool, count: int, format: str) -> None:
    """
    List active network connections.

    Displays active network connections, their status, protocols, and associated
    processes. Supports filtering by connection state and protocol.

    Args:
        state: Filter connections by state
        protocol: Filter connections by protocol
        local_only: Show only local connections
        count: Number of connections to show
        format: Output format (table, json, csv)

    Examples:
        # Show all active connections
        $ flask monitor connections

        # Show only established TCP connections
        $ flask monitor connections --state established --protocol tcp

        # Show only local connections
        $ flask monitor connections --local-only

        # Export connections list as JSON
        $ flask monitor connections --format json
    """
    try:
        # Get all network connections
        all_connections = []
        for conn in psutil.net_connections(kind='all'):
            try:
                # Extract connection information
                connection_info = {
                    'fd': conn.fd if hasattr(conn, 'fd') else '',
                    'family': conn.family.name if hasattr(conn, 'family') else '',
                    'type': conn.type.name if hasattr(conn, 'type') else '',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn, 'laddr') and conn.laddr else '',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else '',
                    'status': conn.status if hasattr(conn, 'status') else '',
                    'pid': conn.pid if hasattr(conn, 'pid') else None
                }

                # Apply filters
                if state != 'all' and connection_info['status'].lower() != state:
                    continue

                if protocol != 'all':
                    if protocol == 'tcp' and connection_info['type'] != 'SOCK_STREAM':
                        continue
                    if protocol == 'udp' and connection_info['type'] != 'SOCK_DGRAM':
                        continue

                if local_only and connection_info['remote_addr']:
                    remote_ip = connection_info['remote_addr'].split(':')[0]
                    if not (remote_ip.startswith('127.') or remote_ip == '::1'):
                        continue

                # Get process name if pid is available
                if connection_info['pid'] is not None:
                    try:
                        process = psutil.Process(connection_info['pid'])
                        connection_info['process_name'] = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        connection_info['process_name'] = 'unknown'
                else:
                    connection_info['process_name'] = 'unknown'

                all_connections.append(connection_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

        # Limit to specified count
        all_connections = all_connections[:count]

        # Format and display output based on format option
        if format == 'json':
            # JSON output
            click.echo(json.dumps(all_connections, indent=2))
        elif format == 'csv':
            # CSV output
            import csv
            from io import StringIO

            output_buffer = StringIO()
            csv_writer = csv.writer(output_buffer)

            # Write header row
            csv_writer.writerow(['Protocol', 'Local Address', 'Remote Address', 'Status', 'PID', 'Process'])

            # Write data rows
            for conn in all_connections:
                csv_writer.writerow([
                    conn['type'],
                    conn['local_addr'],
                    conn['remote_addr'],
                    conn['status'],
                    conn['pid'] or '',
                    conn['process_name']
                ])

            click.echo(output_buffer.getvalue())
        else:
            # Table output
            click.echo("\nActive Network Connections:")
            click.echo(f"{'Protocol':<10} {'Local Address':<20} {'Remote Address':<20} {'Status':<12} {'PID':<8} {'Process':<15}")
            click.echo("-" * 90)

            for conn in all_connections:
                protocol = conn['type'].replace('SOCK_', '')[:8]
                local_addr = conn['local_addr'][:18] + '..' if len(conn['local_addr']) > 20 else conn['local_addr']
                remote_addr = conn['remote_addr'][:18] + '..' if len(conn['remote_addr']) > 20 else conn['remote_addr']
                status = conn['status']
                pid = conn['pid'] or ''
                process = conn['process_name'][:13] + '..' if len(conn['process_name']) > 15 else conn['process_name']

                # Highlight special statuses
                if status.lower() == 'established':
                    status = click.style(status, fg='green')
                elif status.lower() == 'listen':
                    status = click.style(status, fg='blue')
                elif status.lower() == 'time_wait':
                    status = click.style(status, fg='yellow')

                click.echo(f"{protocol:<10} {local_addr:<20} {remote_addr:<20} {status:<12} {pid:<8} {process:<15}")

            click.echo(f"\nShowing {len(all_connections)} connections")

    except Exception as e:
        handle_error(e, "Network connection listing failed")
        sys.exit(EXIT_ERROR)


def _safe_disk_io_stats() -> Dict[str, Any]:
    """
    Safely get disk I/O statistics.

    Collects disk I/O statistics with proper error handling for systems
    where this information might not be available.

    Returns:
        Dict containing disk I/O statistics or empty dict if unavailable
    """
    try:
        if hasattr(psutil, 'disk_io_counters'):
            return dict(psutil.disk_io_counters()._asdict())
        return {}
    except Exception:
        return {}


def _safe_network_io_stats() -> Dict[str, Any]:
    """
    Safely get network I/O statistics.

    Collects network I/O statistics with proper error handling for systems
    where this information might not be available.

    Returns:
        Dict containing network I/O statistics or empty dict if unavailable
    """
    try:
        return dict(psutil.net_io_counters()._asdict())
    except Exception:
        return {}
