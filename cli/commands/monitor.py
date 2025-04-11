import logging
from datetime import datetime
from typing import Dict, Any
import os
import json
import psutil
import click
import requests
from flask.cli import AppGroup
from flask import current_app
from core.loggings import get_logger
from extensions import metrics, db, cache

# Ensure logger is initialized
logger = get_logger(current_app)
if logger is None:
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)
monitor_cli = AppGroup('monitor')

def collect_system_metrics() -> Dict[str, str]:
    """Collect system-level metrics."""
    return {
        'CPU Usage': f"{psutil.cpu_percent()}%",
        'Memory Usage': f"{psutil.virtual_memory().percent}%",
        'Disk Usage': f"{psutil.disk_usage('/').percent}%"
    }

def collect_db_metrics() -> Dict[str, Any]:
    """
    Collect database metrics.

    Returns:
        Dict[str, Any]: A dictionary containing database metrics including
        active connections, total tables, and connection pool size.
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

        return {
            'Active Connections': active_connections,
            'Total Tables': len(db.metadata.tables),
            'Pool Size': pool_size
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
            'Pool Size': 'Error'
        }

def collect_perf_metrics(app_metrics: Dict[str, Any]) -> Dict[str, str]:
    """Collect performance metrics."""
    return {
        'Response Time': f"{app_metrics.get('response_time_avg', 0)}ms",
        'Error Rate': f"{app_metrics.get('error_rate', 0)}%",
        'Cache Hit Rate': f"{app_metrics.get('cache_hit_rate', 0)}%"
    }

@monitor_cli.command('status')
@click.option('--detailed/--simple', default=False, help='Show detailed metrics')
def system_status(detailed: bool) -> None:
    """
    Show system status and metrics.

    Collects and displays various system metrics including system resources,
    database status, and application performance indicators.

    Args:
        detailed (bool): Whether to show detailed application metrics
    """
    try:
        click.echo('\nSystem Status:')

        # Collect all metrics
        metrics_data = _collect_all_metrics()

        # Display metrics
        for category, values in [
            ('System', metrics_data['system']),
            ('Database', metrics_data['database']),
            ('Performance', metrics_data['performance'])
        ]:
            click.echo(f"\n{category}:")
            for key, value in values.items():
                click.echo(f"  {key}: {value}")

        if detailed:
            click.echo("\nDetailed Application Metrics:")
            for key, value in metrics_data['application'].items():
                click.echo(f"  {key}: {value}")

    except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException) as e:
        logger.error("Status check failed: %s", e)
        raise click.ClickException(str(e))


def _collect_all_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Helper function to collect all metrics with progress bar.

    Returns:
        Dict containing categorized metrics
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

    Args:
        app_metrics: Dictionary to store collected metrics
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

    Args:
        metrics_dict: Dictionary containing metrics
        key: Metric name
        value: New value to store
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
def view_logs(lines: int, level: str) -> None:
    """
    View application logs with filtering.

    Args:
        lines (int): Number of log lines to show
        level (str): Log level to filter by (DEBUG, INFO, WARNING, ERROR)

    Raises:
        click.ClickException: If log file not found or other errors occur
    """
    try:
        log_file = 'logs/app.log'
        if not os.path.exists(log_file):
            raise click.ClickException("Log file not found")

        click.echo(f'\nShowing last {lines} lines of {level} logs:')

        with open(log_file, 'r', encoding='utf-8') as f:
            logs = f.readlines()
            filtered_logs = [log for log in logs if level in log]
            for log in filtered_logs[-lines:]:
                click.echo(log.strip())

    except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException) as e:
        logger.error("Log viewing failed: %s", e)
        raise click.ClickException(str(e))

@monitor_cli.command('metrics')
@click.option('--export', help='Export metrics to file')
def export_metrics(export: str | None = None) -> None:
    """
    Export system metrics to JSON.

    Collects and exports comprehensive system metrics including CPU, memory,
    disk usage, network stats, and application/database information.

    Args:
        export (str, optional): Filename to export metrics to. If not provided,
                               metrics will be printed to the console.

    Raises:
        click.ClickException: If metrics collection or export fails
    """
    try:
        # Collect all metrics in separate functions to reduce complexity
        app_metrics = _collect_application_metrics()
        db_metrics = _collect_database_metrics()
        sys_metrics = _collect_system_metrics()

        # Assemble final data structure
        data = {
            'timestamp': datetime.utcnow().isoformat(),
            'system': sys_metrics,
            'application': app_metrics,
            'database': db_metrics
        }

        if export:
            os.makedirs('metrics', exist_ok=True)
            with open(f'metrics/{export}', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            click.echo(f"Metrics exported to metrics/{export}")
        else:
            click.echo(json.dumps(data, indent=2))

    except Exception as e:
        logger.error("Metrics export failed: %s", e)
        raise click.ClickException(str(e))


def _collect_application_metrics() -> Dict[str, Any]:
    """Collect application metrics from Prometheus registry."""
    app_metrics = {}
    try:
        # Collect metrics from Prometheus registry
        if hasattr(metrics, 'registry') and metrics.registry:
            for metric in metrics.registry.collect():
                for sample in metric.samples:
                    app_metrics[sample.name] = sample.value
    except Exception as app_error:
        logger.warning("Error collecting application metrics: %s", str(app_error))
        app_metrics = {"error": str(app_error)}

    return app_metrics


def _collect_database_metrics() -> Dict[str, Any]:
    """Collect database metrics safely."""
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
    except Exception as db_error:
        logger.warning("Error collecting database metrics: %s", str(db_error))
        db_metrics = {"error": str(db_error)}

    return db_metrics


def _collect_system_metrics() -> Dict[str, Any]:
    """Collect system metrics with error handling."""
    sys_metrics = {}
    try:
        sys_metrics = {
            'cpu': psutil.cpu_percent(),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disk': dict(psutil.disk_usage('/')._asdict()),
            'network': dict(psutil.net_io_counters()._asdict())
        }
    except Exception as sys_error:
        logger.warning("Error collecting system metrics: %s", str(sys_error))
        sys_metrics = {"error": str(sys_error)}

    return sys_metrics

@monitor_cli.command('health')
@click.option('--threshold', default=90, help='Warning threshold percentage')
@click.option('--export', help='Export results to file')
def health_check(threshold: int, export: str | None = None) -> None:
    """
    Perform system health check with comprehensive diagnostics.

    Runs a series of checks on system resources, database connectivity,
    cache availability, and external API health. Reports results and
    optionally exports the data to a file.

    Args:
        threshold (int): Warning threshold percentage for resource usage
        export (str, optional): Filename to export results to

    Raises:
        click.ClickException: If any health check fails or if there's an error running checks
    """
    try:
        # Define health checks with proper error handling
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < threshold,
            'Memory': lambda: psutil.virtual_memory().percent < threshold,
            'CPU': lambda: psutil.cpu_percent() < threshold,
            'Redis': lambda: _check_redis_connection(),
            'API Health': lambda: _check_api_health()
        }

        results = {}
        failures = []

        with click.progressbar(length=len(checks), label='Running health checks') as bar_line:
            for name, check in checks.items():
                try:
                    results[name] = check()
                    if not results[name]:
                        failures.append(name)
                    bar_line.update(1)
                except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException) as e:
                    results[name] = False
                    failures.append(name)
                    logger.error("Health check '%s' failed: %s", name, e)

        # Display results
        click.echo("\nHealth Check Results:")
        for name, passed in results.items():
            click.echo(f"  {name}: {'✅' if passed else '❌'}")

        # Export if requested
        if export:
            os.makedirs('metrics', exist_ok=True)
            export_path = f'metrics/{export}' if not export.startswith('/') else export
            data = {
                'timestamp': datetime.utcnow().isoformat(),
                'results': results,
                'failures': failures,
                'threshold': threshold
            }
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            click.echo(f"\nResults exported to {export_path}")

        # Exit with error if any checks failed
        if failures:
            raise click.ClickException(
                f"Failed checks: {', '.join(failures)}"
            )

    except Exception as e:
        logger.error("Health check failed: %s", e)
        raise click.ClickException(str(e))


def _check_redis_connection() -> bool:
    """
    Helper to safely check Redis connection.

    Attempts to verify Redis connectivity by setting and retrieving a test value.

    Returns:
        bool: True if Redis connection is working, False otherwise
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
    """Helper to safely check API health."""
    try:
        if not current_app.config.get('API_URL'):
            return True

        response = requests.get(
            f"{current_app.config['API_URL']}/health",
            timeout=5
        )
        return response.ok
    except Exception as e:
        logger.error("API health check failed: %s", e)
        return False
