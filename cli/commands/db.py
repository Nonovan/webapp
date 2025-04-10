from datetime import datetime
import os
import click
from flask.cli import AppGroup
from core.logging import get_logger
from core.seeder import seed_database
from extensions import db

logger = get_logger(__name__) or click.get_current_context().obj.get('logger', None)
db_cli = AppGroup('db')

@db_cli.command('init')
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
@click.option('--env', default='development', help='Environment to initialize')
def init_db(seed: bool) -> None:
    """Initialize database tables and optionally seed data."""
    try:
        with click.progressbar(length=3, label='Initializing database') as bar_line:
            db.create_all()
            bar_line.update(1)

            if seed:
                seed_database()
            bar_line.update(1)

            # Verify schema
            db.session.execute('SELECT 1')
            bar_line.update(1)

        click.echo('Database initialized successfully')
    except Exception as e:
        logger.error(f'Database initialization failed: {e}')
        raise click.ClickException(str(e))

@db_cli.command('backup')
@click.option('--dir', default='./backups', help='Backup directory')
@click.option('--compress/--no-compress', default=True, help='Use compression')
def backup_db(backup_dir: str, compress: bool) -> None:
    """Create database backup."""
    filename = None  # Initialize filename to avoid unbound variable error
    try:
        # Validate backup directory
        backup_dir = os.path.abspath(backup_dir)
        os.makedirs(backup_dir, exist_ok=True)

        # Validate write permissions
        if not os.access(backup_dir, os.W_OK):
            raise PermissionError(f"No write access to {backup_dir}")

        # Create backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(
            backup_dir, 
            f'backup_{timestamp}.sql{"" if not compress else ".gz"}'
        )

        # Check if file already exists
        if os.path.exists(filename):
            raise FileExistsError(f"Backup file already exists: {filename}")

        with click.progressbar(length=3, label='Creating backup') as bar:
            # Validate database connection
            db.session.execute('SELECT 1')
            bar.update(1)

            # Create backup
            if compress:
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean --no-owner --no-privileges $DATABASE_URL | gzip > {filename}'
            else:
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean --no-owner --no-privileges $DATABASE_URL > {filename}'

            result = os.system(cmd)
            if result != 0:
                raise RuntimeError('Backup command failed')
            bar.update(1)

            # Verify backup
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                raise FileNotFoundError('Backup file not created or empty')
            bar.update(1)

        logger.info(f'Database backup created: {filename}')
        click.echo(f'Database backed up to {filename}')

    except Exception as e:
        logger.error(f'Backup failed: {str(e)}')
        # Only attempt cleanup if filename was created
        if 'filename' in locals() and os.path.exists(filename):
            os.remove(filename)
        raise click.ClickException(f'Backup failed: {str(e)}')

@db_cli.command('restore') 
@click.argument('backup_file')
@click.option('--force/--no-force', default=False, help='Force restore without confirmation')
def restore_db(backup_file: str, force: bool) -> None:
    """Restore database from backup."""
    backup_file = os.path.abspath(backup_file)
    
    if not os.path.exists(backup_file):
        raise click.ClickException(f'Backup file not found: {backup_file}')

    if not force and not click.confirm('This will overwrite the current database. Continue?'):
        return

    try:
        with click.progressbar(length=3, label='Restoring database') as bar_line:
            # Validate backup file
            if os.path.getsize(backup_file) == 0:
                raise ValueError('Backup file is empty')
            bar_line.update(1)

            # Restore backup
            if backup_file.endswith('.gz'):
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" gunzip -c {backup_file} | psql $DATABASE_URL'
            else:
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" psql $DATABASE_URL < {backup_file}'

            result = os.system(cmd)
            if result != 0:
                raise RuntimeError('Restore command failed')
            bar_line.update(1)

            # Verify restore
            db.session.execute('SELECT 1')
            bar_line.update(1)

        logger.info('Database restored successfully')
        click.echo('Database restored successfully')

    except Exception as e:
        logger.error(f'Restore failed: {str(e)}')
        raise click.ClickException(f'Restore failed: {str(e)}')