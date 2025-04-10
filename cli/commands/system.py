from datetime import datetime
import os
import psutil
import click
from flask.cli import AppGroup
from core.logging import get_logger
from extensions import db, metrics

logger = get_logger(__name__)
system_cli = AppGroup('system')

@system_cli.command('status')
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

            # Application metrics
            app_metrics = metrics.get_all()
            bar.update(1)

            # Database metrics
            db_metrics = {
                'Active Connections': len(db.engine.pool._channels),
                'Database Size': db.session.execute(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                ).scalar(),
                'Total Tables': len(db.metadata.tables)
            }
            bar.update(1)

            # Process metrics
            proc = psutil.Process()
            process_metrics = {
                'Memory Usage': f"{proc.memory_info().rss / 1024 / 1024:.1f} MB",
                'CPU Usage': f"{proc.cpu_percent()}%",
                'Threads': proc.num_threads(),
                'Open Files': len(proc.open_files())
            }
            bar.update(1)

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

    except Exception as e:
        logger.error(f"Status check failed: {e}")
        raise click.ClickException(str(e))

@system_cli.command('health')
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

@system_cli.command('config')
@click.option('--verify/--no-verify', default=True, help='Verify configuration')
def check_config(verify: bool) -> None:
    """Check system configuration."""
    try:
        from core.config import Config
        config = Config.load()
        
        click.echo("\nConfiguration Status:")
        for key, value in config.items():
            if isinstance(value, str) and key.lower().contains(('key', 'secret', 'password')):
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

    except Exception as e:
        logger.error(f"Config check failed: {e}")
        raise click.ClickException(str(e))