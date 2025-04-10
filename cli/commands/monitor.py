from datetime import datetime
from typing import Dict, Any
import os
import json
import psutil
import click
import requests
from flask.cli import AppGroup
from flask import current_app
from core.logging import get_logger
from extensions import metrics, db, cache

# Ensure logger is initialized
logger = get_logger(__name__)
if logger is None:
    import logging
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
    """Collect database metrics."""
    return {
        'Active Connections': db.engine.pool.checkedout(),
        'Total Tables': len(db.metadata.tables),
        'Pool Size': db.engine.pool.size()
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
    """Show system status and metrics."""
    try:
        click.echo('\nSystem Status:')
        
        with click.progressbar(length=4, label='Collecting metrics') as bar_line:
            # System metrics
            sys_metrics = collect_system_metrics()
            bar_line.update(1)

            # Database metrics
            db_metrics = collect_db_metrics()
            bar_line.update(1)

            # Application metrics
            app_metrics = metrics.get_all()
            bar_line.update(1)

            # Performance metrics
            perf_metrics = collect_perf_metrics(app_metrics)
            bar_line.update(1)

        # Display metrics
        for category, values in [
            ('System', sys_metrics),
            ('Database', db_metrics),
            ('Performance', perf_metrics)
        ]:
            click.echo(f"\n{category}:")
            for key, value in values.items():
                click.echo(f"  {key}: {value}")

        if detailed:
            click.echo("\nDetailed Application Metrics:")
            for key, value in app_metrics.items():
                click.echo(f"  {key}: {value}")

    except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException) as e:
        logger.error("Status check failed: %s", e)
        raise click.ClickException(str(e))

@monitor_cli.command('logs')
@click.option('--lines', default=100, help='Number of lines to show')
@click.option('--level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO')
def view_logs(lines: int, level: str) -> None:
    """View application logs with filtering."""
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

    except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException, cache.CacheError) as e:
        logger.error("Log viewing failed: %s", e)
        raise click.ClickException(str(e))

@monitor_cli.command('metrics')
@click.option('--export', help='Export metrics to file')
def export_metrics(export: str) -> None:
    """Export system metrics to file."""
    try:
        data = {
            'timestamp': datetime.utcnow().isoformat(),
            'system': {
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict(),
                'network': psutil.net_io_counters()._asdict()
            },
            'application': metrics.get_all(),
            'database': {
                'connections': db.engine.pool.status().get('checkedout', 0),
                'tables': len(db.metadata.tables)
            }
        }

        if export:
            os.makedirs('metrics', exist_ok=True)
            with open(f'metrics/{export}', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            click.echo(f"Metrics exported to metrics/{export}")
        else:
            click.echo(json.dumps(data, indent=2))

    except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException, cache.CacheError) as e:
        logger.error("Metrics export failed: %s", e)
        raise click.ClickException(str(e))

@monitor_cli.command('health')
@click.option('--threshold', default=90, help='Warning threshold percentage')
@click.option('--export', help='Export results to file')
def health_check(threshold: int, export: str) -> None:
    """Perform system health check."""
    try:
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < threshold,
            'Memory': lambda: psutil.virtual_memory().percent < threshold,
            'CPU': lambda: psutil.cpu_percent() < threshold,
            'Redis': lambda: bool(cache.ping()),
            'API Health': lambda: requests.get(
                f"{current_app.config['API_URL']}/health"
            ).ok if current_app.config.get('API_URL') else True
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
                except (psutil.Error, db.exc.SQLAlchemyError, requests.RequestException, cache.CacheError) as e:
                    results[name] = False
                    failures.append(name)
                    logger.error("Health check '%s' failed: %s", name, e)

        # Display results
        click.echo("\nHealth Check Results:")
        for name, passed in results.items():
            click.echo(f"  {name}: {'✅' if passed else '❌'}")

        # Export if requested
        if export:
            data = {
                'timestamp': datetime.utcnow().isoformat(),
                'results': results,
                'failures': failures,
                'threshold': threshold
            }
            with open(export, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            click.echo(f"\nResults exported to {export}")

        # Exit with error if any checks failed
        if failures:
            raise click.ClickException(
                f"Failed checks: {', '.join(failures)}"
            )

    except Exception as e:
        logger.error("Health check failed: %s", e)
        raise click.ClickException(str(e))
