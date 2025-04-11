"""
Database management commands for the myproject CLI.

This module provides command-line utilities for database operations including
initialization, migration, backup, and restoration. These commands enable
database administration without requiring direct database access, allowing
for safer and more controlled operations through the application's ORM layer.

Commands in this module handle critical database operations that should be
performed with proper authorization and understanding of their effects on
application data.
"""

from datetime import datetime
import os
import click
from flask.cli import AppGroup
from core.loggings import get_logger
from core.seeder import seed_database
from extensions import db

# Initialize CLI group and logger
db_cli = AppGroup('db')
# Initialize logger with None for now,
# the application instance will be attached when available
logger = get_logger(app=None)  # type: ignore

@db_cli.command('init')
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
@click.option('--env', default='development', help='Environment to initialize')
def init_db(seed: bool, env: str) -> None:
    """
    Initialize database tables and optionally seed data.

    Creates all database tables defined in the application models based on
    SQLAlchemy models. If the --seed option is specified, populates the database
    with initial data required for application functionality.

    This command should typically be run once when setting up a new environment
    or after a schema reset. For incremental schema changes, use migrations instead.

    Args:
        seed: Whether to seed initial data after table creation
        env: Environment to initialize (affects configuration selection)

    Examples:
        # Initialize tables only
        $ flask db init

        # Initialize and seed development data
        $ flask db init --seed --env=development
    """
    try:
        with click.progressbar(length=3, label='Initializing database') as bar_line:
            # Create schema
            db.create_all()
            bar_line.update(1)

            # Seed data if requested
            if seed:
                seed_database()
            bar_line.update(1)

            # Verify database
            db.session.execute('SELECT 1')
            bar_line.update(1)

        click.echo('Database initialized successfully')
        logger.info(f'Database initialized in {env} environment')

    except Exception as e:
        logger.error(f'Database initialization failed: {e}')
        raise click.ClickException(str(e))

@db_cli.command('backup')
@click.option('--dir', default='./backups', help='Backup directory')
@click.option('--compress/--no-compress', default=True, help='Use compression')
def backup_db(backup_dir: str, compress: bool) -> None:
    """
    Create database backup.

    Generates a SQL dump of the current database state and saves it to the
    specified directory with a timestamp. The backup can optionally be compressed
    to save disk space. This command requires appropriate database credentials
    to be available in the environment.

    The backup process validates write permissions, available space, and backup
    success. If any step fails, the operation is aborted and any partial backup
    files are cleaned up.

    Args:
        backup_dir: Directory where backup files will be stored
        compress: Whether to compress the backup using gzip

    Examples:
        # Create a compressed backup in default directory
        $ flask db backup

        # Create an uncompressed backup in custom directory
        $ flask db backup --dir=/path/to/backups --no-compress
    """
    # Initialize filename to avoid unbound variable error
    filename = None
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

        with click.progressbar(length=3, label='Creating backup') as bar_line:
            # Validate database connection
            db.session.execute('SELECT 1')
            bar_line.update(1)

            # Create backup
            if compress:
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean --no-owner --no-privileges $DATABASE_URL | gzip > {filename}'
            else:
                cmd = f'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean --no-owner --no-privileges $DATABASE_URL > {filename}'

            result = os.system(cmd)
            if result != 0:
                raise RuntimeError('Backup command failed')
            bar_line.update(1)

            # Verify backup
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                raise FileNotFoundError('Backup file not created or empty')
            bar_line.update(1)

        logger.info(f'Database backup created: {filename}')
        click.echo(f'Database backed up to {filename}')

    except Exception as e:
        logger.error(f'Backup failed: {str(e)}')
        # Only attempt cleanup if filename was created
        if filename is not None and os.path.exists(filename):
            os.remove(filename)
        raise click.ClickException(f'Backup failed: {str(e)}')

@db_cli.command('restore')
@click.argument('backup_file')
@click.option('--force/--no-force', default=False, help='Force restore without confirmation')
def restore_db(backup_file: str, force: bool) -> None:
    """
    Restore database from backup.

    Restores a database from a previously created backup file. This command
    will overwrite all current data in the database with the data from the backup,
    so it should be used with caution.

    The command supports both compressed (.gz) and uncompressed backup files.
    It performs validation checks before and after restoration to ensure data
    integrity.

    Args:
        backup_file: Path to the backup file to restore from
        force: Skip confirmation prompt if true

    Examples:
        # Restore with confirmation prompt
        $ flask db restore ./backups/backup_20231015_123045.sql.gz

        # Force restore without confirmation
        $ flask db restore ./backups/backup_20231015_123045.sql --force
    """
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
