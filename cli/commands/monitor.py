from datetime import datetime
import os
import psutil
import click
from flask.cli import AppGroup
from core.logging import get_logger
from extensions import metrics, db

logger = get_logger(__name__)
monitor_cli = AppGroup('monitor')

@monitor_cli.command('status')
@click.option('--detailed/--simple', default=False, help='Show detailed metrics')
def system_status(detailed: bool) -> None:
    """Show system status and metrics."""
    try:
        click.echo('\nSystem Status:')
        
        with click.progressbar(length=4, label='Collecting metrics') as bar:
            # System metrics
            sys_metrics = {
                'CPU Usage': f"{psutil.cpu_percent()}%",
                'Memory Usage': f"{psutil.virtual_memory().percent}%",
                'Disk Usage': f"{psutil.disk_usage('/').percent}%"
            }
            bar.update(1)

            # Database metrics
            db_metrics = {
                'Active Connections': len(db.engine.pool._channels),
                'Total Tables': len(db.metadata.tables)
            }
            bar.update(1)

            # Application metrics
            app_metrics = metrics.get_all()
            bar.update(1)

            # Performance metrics
            perf_metrics = {
                'Response Time': f"{app_metrics.get('response_time_avg', 0)}ms",
                'Error Rate': f"{app_metrics.get('error_rate', 0)}%"
            }
            bar.update(1)

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
            click.echo("\nDetailed Metrics:")
            for key, value in app_metrics.items():
                click.echo(f"  {key}: {value}")

    except Exception as e:
        logger.error(f"Status check failed: {e}")
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
        
        with open(log_file, 'r') as f:
            logs = f.readlines()
            filtered_logs = [log for log in logs if level in log]
            for log in filtered_logs[-lines:]:
                click.echo(log.strip())

    except Exception as e:
        logger.error(f"Log viewing failed: {e}")
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
                'connections': len(db.engine.pool._channels),
                'tables': len(db.metadata.tables)
            }
        }

        if export:
            os.makedirs('metrics', exist_ok=True)
            with open(f'metrics/{export}', 'w') as f:
                import json
                json.dump(data, f, indent=2)
            click.echo(f"Metrics exported to metrics/{export}")
        else:
            click.echo(json.dumps(data, indent=2))

    except Exception as e:
        logger.error(f"Metrics export failed: {e}")
        raise click.ClickException(str(e))

@monitor_cli.command('health')
def health_check() -> None:
    """Perform system health check."""
    try:
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < 90,
            'Memory': lambda: psutil.virtual_memory().percent < 90,
            'CPU': lambda: psutil.cpu_percent() < 80
        }

        with click.progressbar(length=len(checks), label='Running health checks') as bar:
            results = {}
            for name, check in checks.items():
                try:
                    results[name] = check()
                    bar.update(1)
                except Exception as e:
                    results[name] = False
                    logger.error(f"Health check '{name}' failed: {e}")

        click.echo("\nHealth Check Results:")
        for name, passed in results.items():
            click.echo(f"  {name}: {'✅' if passed else '❌'}")

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise click.ClickException(str(e))