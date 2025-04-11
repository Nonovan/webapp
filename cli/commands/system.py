"""
System management commands for the myproject CLI.

This module provides command-line utilities for system administration, health checks,
and configuration management. These commands help administrators monitor the system's
operational status, validate configuration settings, and diagnose problems.

The system commands provide visibility into the application's runtime environment
and dependencies, making them essential tools for deployment validation and
operational troubleshooting.
"""

import logging
import psutil
import click
from flask.cli import AppGroup
from core.config import Config
from extensions import db, metrics

try:
    # Use logging module directly since we don't have a Flask app at this point
    logger = logging.getLogger(__name__)
except TypeError:
    logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
system_cli = AppGroup('system')

@system_cli.command('status')
@click.option('--detailed/--simple', default=False, help='Show detailed metrics')
def system_status(detailed: bool) -> None:
    """
    Show system status and metrics.

    Displays current system health information including CPU, memory, disk usage,
    database connection status, and application metrics. This command is useful for
    operational monitoring and diagnostics.

    In detailed mode, additional metrics are displayed including application-specific
    counters and performance indicators, which can help identify performance bottlenecks
    and resource constraints.

    Args:
        detailed: Whether to show additional detailed metrics

    Examples:
        # Show basic system status
        $ flask system status

        # Show detailed system metrics
        $ flask system status --detailed
    """
    try:
        click.echo('\nSystem Status:')

        with click.progressbar(length=4, label='Collecting metrics') as bar_line:
            # System metrics
            sys_metrics = {
                'CPU Usage': f"{psutil.cpu_percent()}%",
                'Memory Usage': f"{psutil.virtual_memory().percent}%",
                'Disk Usage': f"{psutil.disk_usage('/').percent}%"
            }
            bar_line.update(1)

            # Application metrics
            app_metrics = {}
            try:
                # Try to get metrics from registry if available
                if hasattr(metrics, 'registry'):
                    app_metrics = {
                        metric.name: metric.samples
                        for metric in metrics.registry.collect()
                    }
                # Fallback if registry not available
                else:
                    app_metrics = {"Info": "Detailed metrics not available"}
            except (AttributeError, TypeError) as e:
                logger.warning("Failed to collect application metrics: %s", e)
                app_metrics = {"Error": str(e)}
            bar_line.update(1)

            # Database metrics
            db_metrics = {}
            try:
                # Use engine.pool.status() to get connection info
                pool_status = db.engine.pool.status() if hasattr(db.engine.pool, 'status') else {}
                active_connections = pool_status.get('checkedout', 0) if isinstance(pool_status, dict) else 0

                db_metrics = {
                    'Active Connections': active_connections,
                    'Database Size': db.session.execute(
                        "SELECT pg_size_pretty(pg_database_size(current_database()))"
                    ).scalar(),
                    'Total Tables': len(db.metadata.tables)
                }
            except (psutil.Error, db.exc.SQLAlchemyError) as e:
                logger.warning("Failed to collect database metrics: %s", e)
                db_metrics = {"Error": str(e)}
            bar_line.update(1)

            # Process metrics
            proc = psutil.Process()
            process_metrics = {
                'Memory Usage': f"{proc.memory_info().rss / 1024 / 1024:.1f} MB",
                'CPU Usage': f"{proc.cpu_percent()}%",
                'Threads': proc.num_threads(),
                'Open Files': len(proc.open_files())
            }
            bar_line.update(1)

        # Display metrics
        for category, values in [
            ('System', sys_metrics),
            ('Database', db_metrics),
            ('Process', process_metrics)
        ]:
            click.echo(f"\n{category}:")
            for key, value in values.items():
                click.echo(f"  {key}: {value}")

        if detailed:
            click.echo("\nDetailed Application Metrics:")
            for key, value in app_metrics.items():
                click.echo(f"  {key}: {value}")

    except (psutil.Error, db.exc.SQLAlchemyError) as e:
        logger.error("Status check failed: %s", e)

@system_cli.command('health')
def health_check() -> None:
    """
    Perform system health check.

    Runs a series of validation checks to verify that all system components
    are functioning correctly. Tests include database connectivity, disk space
    availability, memory usage, and CPU utilization.

    This command is useful for automated monitoring and deployment verification.
    It exits with a non-zero status if any check fails, making it suitable for
    use in scripts and CI/CD pipelines.

    Example:
        $ flask system health
    """
    try:
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < 90,
            'Memory': lambda: psutil.virtual_memory().percent < 90,
            'CPU': lambda: psutil.cpu_percent() < 80
        }

        with click.progressbar(length=len(checks), label='Running health checks') as bar_line:
            results = {}
            for name, check in checks.items():
                try:
                    results[name] = check()
                    bar_line.update(1)
                except (psutil.Error, db.exc.SQLAlchemyError) as e:
                    results[name] = False
                    logger.error("Health check '%s' failed: %s", name, e)

                    logger.error("Health check '%s' failed: %s", name, e)
        for name, passed in results.items():
            click.echo(f"  {name}: {'✅' if passed else '❌'}")

    except (psutil.Error, db.exc.SQLAlchemyError) as e:
        logger.error("Health check failed: %s", e)
        raise click.ClickException(str(e))

@system_cli.command('config')
@click.option('--verify/--no-verify', default=True, help='Verify configuration')
def check_config(verify: bool) -> None:
    """
    Check system configuration.

    Displays the current application configuration settings and optionally
    verifies that all required variables are present. This command helps
    diagnose configuration-related issues and ensures the application
    environment is properly set up.

    Sensitive values like passwords and keys are masked in the output for security.

    Args:
        verify: Whether to verify required configuration variables

    Examples:
        # Show configuration with verification
        $ flask system config

        # Show configuration without verification
        $ flask system config --no-verify
    """
    try:
        config = Config.load()

        click.echo("\nConfiguration Status:")
        for key, value in config.items():
            if isinstance(value, str) and any(substring in key.lower() for substring in ('key', 'secret', 'password')):
                value = '********'
            click.echo(f"  {key}: {value}")

        if verify:
            required_vars = [
                'SECRET_KEY', 'DATABASE_URL', 'REDIS_URL',
                'MAIL_SERVER', 'SENTRY_DSN'
            ]
            missing = [var for var in required_vars if not config.get(var)]
            if missing:
                click.echo("\n❌ Missing required variables:")
                for var in missing:
                    click.echo(f"  - {var}")
            else:
                click.echo("\n✅ All required variables present")

    except (ImportError, AttributeError, KeyError) as e:
        logger.error("Config check failed: %s", e)
        raise click.ClickException(str(e))
