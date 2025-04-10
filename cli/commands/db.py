from datetime import datetime
import os
import click
from flask.cli import AppGroup
from core.logging import get_logger

logger = get_logger(__name__)
db_cli = AppGroup('db')

@db_cli.command('init')
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
@click.option('--env', default='development', help='Environment to initialize')
def init_db(seed: bool, env: str) -> None:
    """Initialize database tables and optionally seed data."""
    try:
        with click.progressbar(length=3, label='Initializing database') as bar:
            from extensions import db
            db.create_all()
            bar.update(1)

            if seed:
                from core.seeder import seed_database
                seed_database()
            bar.update(1)

            # Verify schema
            db.session.execute('SELECT 1')
            bar.update(1)

        click.echo('Database initialized successfully')
    except Exception as e:
        logger.error(f'Database initialization failed: {e}')
        raise click.ClickException(str(e))

@db_cli.command('backup')
@click.option('--dir', default='./backups', help='Backup directory')
@click.option('--compress/--no-compress', default=True, help='Use compression')
def backup_db(dir: str, compress: bool) -> None:
    """Create database backup."""
    try:
        os.makedirs(dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{dir}/backup_{timestamp}.sql{"" if not compress else ".gz"}'

        with click.progressbar(length=2, label='Creating backup') as bar:
            if compress:
                cmd = f'pg_dump $DATABASE_URL | gzip > {filename}'
            else:
                cmd = f'pg_dump $DATABASE_URL > {filename}'

            result = os.system(cmd)
            bar.update(1)

            if result != 0:
                raise Exception('Backup command failed')

            # Verify backup file
            if not os.path.exists(filename):
                raise Exception('Backup file not created')
            bar.update(1)

        click.echo(f'Database backed up to {filename}')
    except Exception as e:
        logger.error(f'Backup failed: {e}')
        raise click.ClickException(str(e))

@db_cli.command('restore')
@click.argument('backup_file')
@click.option('--force/--no-force', default=False, help='Force restore without confirmation')
def restore_db(backup_file: str, force: bool) -> None:
    """Restore database from backup."""
    if not os.path.exists(backup_file):
        raise click.ClickException(f'Backup file not found: {backup_file}')

    if not force and not click.confirm('This will overwrite the current database. Continue?'):
        return

    try:
        with click.progressbar(length=2, label='Restoring database') as bar:
            if backup_file.endswith('.gz'):
                cmd = f'gunzip -c {backup_file} | psql $DATABASE_URL'
            else:
                cmd = f'psql $DATABASE_URL < {backup_file}'

            result = os.system(cmd)
            bar.update(1)

            if result != 0:
                raise Exception('Restore command failed')

            # Verify restore
            from extensions import db
            db.session.execute('SELECT 1')
            bar.update(1)

        click.echo('Database restored successfully')
    except Exception as e:
        logger.error(f'Restore failed: {e}')
        raise click.ClickException(str(e))
