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
import sys
import json
import subprocess
import tempfile
from typing import Dict, Any, List, Optional, Tuple
import click
from flask.cli import AppGroup
from flask import current_app
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from core.utils.logging_utils import get_logger
from core.seeder import seed_database, seed_development_data
from extensions import db, metrics
from cli.common import (
    require_permission, handle_error, confirm_action, format_output,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_RESOURCE_ERROR
)

# Initialize CLI group and logger
db_cli = AppGroup('db')
# Initialize logger with None for now,
# the application instance will be attached when available
logger = get_logger(app=None)  # type: ignore

@db_cli.command('init')
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
@click.option('--env', default='development', help='Environment to initialize')
@click.option('--dev-data/--no-dev-data', default=False, help='Include development/sample data')
@click.option('--force/--no-force', default=False, help='Force initialization without confirmation')
@require_permission('db:admin')
def init_db(seed: bool, env: str, dev_data: bool, force: bool) -> None:
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
        dev_data: Whether to include sample development data
        force: Skip confirmation prompts if true

    Examples:
        # Initialize tables only
        $ flask db init

        # Initialize and seed development data
        $ flask db init --seed --env=development

        # Initialize with sample data for testing
        $ flask db init --seed --dev-data --env=development
    """
    # Security check for production
    if env == 'production' and not force:
        if not confirm_action('You are initializing a PRODUCTION database. This will ERASE ALL DATA. Continue?', default=False):
            click.echo('Operation cancelled')
            return

    try:
        with click.progressbar(length=4, label='Initializing database') as bar_line:
            # Create schema
            db.create_all()
            bar_line.update(1)

            # Verify database connection
            db.session.execute('SELECT 1')
            bar_line.update(1)

            # Seed data if requested
            if seed:
                seed_success = seed_database(verbose=True)
                if not seed_success:
                    click.echo('Warning: Some seed data could not be inserted', err=True)
                bar_line.update(1)

                # Add development data if requested
                if dev_data and env != 'production':
                    dev_data_success = seed_development_data(verbose=True)
                    if not dev_data_success:
                        click.echo('Warning: Some development data could not be inserted', err=True)
                bar_line.update(1)
            else:
                # Skip seeding steps
                bar_line.update(2)

        metrics.increment('db.initialization_success')
        click.echo('Database initialized successfully')
        logger.info(f'Database initialized in {env} environment')
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment('db.initialization_failure')
        logger.error(f'Database initialization failed: {e}')
        raise click.ClickException(f'Database initialization failed: {str(e)}')

@db_cli.command('backup')
@click.option('--dir', default='./backups', help='Backup directory')
@click.option('--compress/--no-compress', default=True, help='Use compression')
@click.option('--schema-only/--with-data', default=False, help='Backup schema without data')
@click.option('--include-tables', help='Comma-separated list of tables to include')
@click.option('--exclude-tables', help='Comma-separated list of tables to exclude')
@require_permission('db:backup')
def backup_db(backup_dir: str, compress: bool, schema_only: bool,
              include_tables: Optional[str] = None, exclude_tables: Optional[str] = None) -> None:
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
        schema_only: Backup only the schema, not the data
        include_tables: Comma-separated list of tables to include (exclusive with exclude_tables)
        exclude_tables: Comma-separated list of tables to exclude (exclusive with include_tables)

    Examples:
        # Create a compressed backup in default directory
        $ flask db backup

        # Create an uncompressed backup in custom directory
        $ flask db backup --dir=/path/to/backups --no-compress

        # Create schema-only backup (no data)
        $ flask db backup --schema-only

        # Backup only specific tables
        $ flask db backup --include-tables=users,roles,permissions
    """
    # Input validation
    if include_tables and exclude_tables:
        raise click.ClickException('Cannot use both --include-tables and --exclude-tables simultaneously')

    # Process include/exclude tables
    include_table_list = include_tables.split(',') if include_tables else []
    exclude_table_list = exclude_tables.split(',') if exclude_tables else []

    # Initialize filename to avoid unbound variable error
    filename = None
    try:
        # Validate backup directory
        backup_dir = os.path.abspath(backup_dir)
        os.makedirs(backup_dir, exist_ok=True)

        # Validate write permissions
        if not os.access(backup_dir, os.W_OK):
            raise PermissionError(f"No write access to {backup_dir}")

        # Check available disk space
        free_space = get_free_disk_space(backup_dir)
        estimated_size = estimate_backup_size()
        if free_space < estimated_size * 1.5:  # 50% safety margin
            raise click.ClickException(
                f"Insufficient disk space for backup. "
                f"Available: {format_bytes(free_space)}, "
                f"Required: {format_bytes(estimated_size * 1.5)}"
            )

        # Create backup filename with appropriate prefix for schema-only
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_type = 'schema' if schema_only else 'backup'
        filename = os.path.join(
            backup_dir,
            f'{backup_type}_{timestamp}.sql{"" if not compress else ".gz"}'
        )

        # Check if file already exists
        if os.path.exists(filename):
            raise FileExistsError(f"Backup file already exists: {filename}")

        with click.progressbar(length=3, label='Creating backup') as bar_line:
            # Validate database connection
            db.session.execute('SELECT 1')
            bar_line.update(1)

            # Build pg_dump command with options
            pg_dump_args = ['pg_dump', '--clean', '--no-owner', '--no-privileges']

            if schema_only:
                pg_dump_args.append('--schema-only')

            # Handle include/exclude tables
            for table in include_table_list:
                pg_dump_args.extend(['--table', table.strip()])
            for table in exclude_table_list:
                pg_dump_args.extend(['--exclude-table', table.strip()])

            # Execute the appropriate command based on compression
            if compress:
                # Create a compressed backup
                with open(filename, 'wb') as f:
                    pg_dump = subprocess.Popen(
                        pg_dump_args + ['$DATABASE_URL'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True,
                        env=os.environ.copy()
                    )
                    gzip_process = subprocess.Popen(
                        ['gzip'],
                        stdin=pg_dump.stdout,
                        stdout=f,
                        stderr=subprocess.PIPE
                    )
                    pg_dump.stdout.close()  # Allow pg_dump to receive SIGPIPE
                    gzip_process.communicate()
                    result = pg_dump.wait()
            else:
                # Create an uncompressed backup
                with open(filename, 'wb') as f:
                    result = subprocess.call(
                        pg_dump_args + ['$DATABASE_URL'],
                        stdout=f,
                        stderr=subprocess.PIPE,
                        shell=True,
                        env=os.environ.copy()
                    )

            if result != 0:
                raise RuntimeError('Backup command failed')
            bar_line.update(1)

            # Verify backup
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                raise FileNotFoundError('Backup file not created or empty')
            bar_line.update(1)

        # Log success
        backup_type = 'Schema-only' if schema_only else 'Full'
        metrics.increment('db.backup_success')
        logger.info(f'{backup_type} database backup created: {filename}')
        click.echo(f'{backup_type} database backed up to {filename}')
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment('db.backup_failure')
        logger.error(f'Backup failed: {str(e)}')
        # Only attempt cleanup if filename was created
        if filename is not None and os.path.exists(filename):
            os.remove(filename)
        raise click.ClickException(f'Backup failed: {str(e)}')

@db_cli.command('restore')
@click.argument('backup_file')
@click.option('--force/--no-force', default=False, help='Force restore without confirmation')
@click.option('--verify/--no-verify', default=True, help='Verify database integrity after restore')
@require_permission('db:admin')
def restore_db(backup_file: str, force: bool, verify: bool) -> None:
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
        verify: Perform integrity checks after restore

    Examples:
        # Restore with confirmation prompt
        $ flask db restore ./backups/backup_20231015_123045.sql.gz

        # Force restore without confirmation
        $ flask db restore ./backups/backup_20231015_123045.sql --force

        # Restore without verification
        $ flask db restore ./backups/backup_20231015_123045.sql.gz --no-verify
    """
    backup_file = os.path.abspath(backup_file)

    if not os.path.exists(backup_file):
        raise click.ClickException(f'Backup file not found: {backup_file}')

    # Security check for production
    if not force:
        # Check if we're in production environment
        is_prod = False
        try:
            is_prod = current_app.config.get('ENV', '').lower() == 'production'
        except (RuntimeError, AttributeError):
            # App context not available, use environment variable as fallback
            is_prod = os.environ.get('FLASK_ENV', '').lower() == 'production'

        warning = "This will OVERWRITE ALL DATA in the database with the contents of the backup."
        if is_prod:
            warning = f"WARNING: PRODUCTION ENVIRONMENT! {warning}"

        if not confirm_action(f"{warning} Continue?", default=False):
            click.echo('Operation cancelled')
            return

    try:
        with click.progressbar(length=4, label='Restoring database') as bar_line:
            # Validate backup file
            if os.path.getsize(backup_file) == 0:
                raise ValueError('Backup file is empty')
            bar_line.update(1)

            # Restore backup
            if backup_file.endswith('.gz'):
                # For gzip compressed backups
                with subprocess.Popen(
                    ['gunzip', '-c', backup_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ) as gunzip_process:
                    with subprocess.Popen(
                        ['psql', '$DATABASE_URL'],
                        stdin=gunzip_process.stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True,
                        env=os.environ.copy()
                    ) as psql_process:
                        gunzip_process.stdout.close()  # Allow gunzip to receive SIGPIPE
                        stdout, stderr = psql_process.communicate()
                        if psql_process.returncode != 0:
                            error_message = stderr.decode('utf-8', errors='replace')
                            raise RuntimeError(f'Restore command failed: {error_message}')
            else:
                # For uncompressed backups
                with open(backup_file, 'r') as f:
                    with subprocess.Popen(
                        ['psql', '$DATABASE_URL'],
                        stdin=f,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True,
                        env=os.environ.copy()
                    ) as psql_process:
                        stdout, stderr = psql_process.communicate()
                        if psql_process.returncode != 0:
                            error_message = stderr.decode('utf-8', errors='replace')
                            raise RuntimeError(f'Restore command failed: {error_message}')
            bar_line.update(1)

            # Verify restore by checking connection
            db.session.execute('SELECT 1')
            bar_line.update(1)

            # Perform additional integrity checks if requested
            if verify:
                integrity_issues = verify_database_integrity()
                if integrity_issues:
                    click.echo('\nWarning: Database integrity issues detected:')
                    for issue in integrity_issues:
                        click.echo(f" - {issue}")
                        logger.warning(f"Database integrity issue: {issue}")
            bar_line.update(1)

        metrics.increment('db.restore_success')
        logger.info('Database restored successfully')
        click.echo('Database restored successfully')
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment('db.restore_failure')
        logger.error(f'Restore failed: {str(e)}')
        raise click.ClickException(f'Restore failed: {str(e)}')

@db_cli.command('verify')
@click.option('--verbose/--quiet', default=False, help='Show detailed results')
@click.option('--fix/--no-fix', default=False, help='Attempt to fix integrity issues')
@require_permission('db:read')
def verify_db(verbose: bool, fix: bool) -> None:
    """
    Verify database integrity.

    Performs a series of checks to verify the integrity of the database,
    including schema validation, foreign key checks, and index verification.
    This command is useful for diagnosing database issues.

    Args:
        verbose: Show detailed information about each check
        fix: Attempt to automatically fix integrity issues

    Examples:
        # Run basic verification
        $ flask db verify

        # Run detailed verification
        $ flask db verify --verbose

        # Run verification and attempt repairs
        $ flask db verify --fix
    """
    try:
        click.echo('Verifying database integrity...')

        issues = verify_database_integrity()

        if not issues:
            click.echo('✅ Database integrity check passed. No issues found.')
            metrics.increment('db.verification_success')
            return EXIT_SUCCESS

        click.echo('❌ Database integrity check failed. Issues found:')
        for issue in issues:
            click.echo(f" - {issue}")

        metrics.increment('db.verification_failure')

        if fix:
            click.echo('\nAttempting to fix issues...')
            fixed = fix_database_integrity_issues(issues, verbose)

            if fixed:
                click.echo('✅ Issues fixed successfully.')
                return EXIT_SUCCESS
            else:
                click.echo('❌ Some issues could not be fixed automatically.')
                return EXIT_ERROR

        return EXIT_ERROR

    except Exception as e:
        metrics.increment('db.verification_error')
        logger.error(f'Database verification failed: {str(e)}')
        raise click.ClickException(f'Database verification failed: {str(e)}')

@db_cli.command('optimize')
@click.option('--analyze/--no-analyze', default=True, help='Run ANALYZE to update statistics')
@click.option('--vacuum/--no-vacuum', default=True, help='Run VACUUM to reclaim space')
@click.option('--full/--no-full', default=False, help='Run VACUUM FULL (locks tables)')
@click.option('--reindex/--no-reindex', default=False, help='Rebuild indexes')
@require_permission('db:admin')
def optimize_db(analyze: bool, vacuum: bool, full: bool, reindex: bool) -> None:
    """
    Optimize database performance.

    Runs PostgreSQL optimization commands like VACUUM, ANALYZE, and REINDEX
    to improve database performance. These operations can help reclaim disk space,
    update statistics for the query planner, and reduce index fragmentation.

    Warning: Some operations like VACUUM FULL and REINDEX lock tables and
    can impact application availability.

    Args:
        analyze: Update table statistics for the query planner
        vacuum: Reclaim storage and update visibility map
        full: Perform full vacuum (locks tables, rewrites entire table)
        reindex: Rebuild indexes to remove bloat

    Examples:
        # Run basic optimization (VACUUM and ANALYZE)
        $ flask db optimize

        # Run full vacuum (locks tables)
        $ flask db optimize --full

        # Run only statistics update
        $ flask db optimize --no-vacuum --analyze
    """
    if full and not vacuum:
        raise click.ClickException("Cannot specify --full without --vacuum")

    if full and not confirm_action(
        "VACUUM FULL will lock tables and could cause downtime. Continue?",
        default=False
    ):
        click.echo("Operation cancelled")
        return

    if reindex and not confirm_action(
        "REINDEX will lock tables and could cause downtime. Continue?",
        default=False
    ):
        click.echo("Operation cancelled")
        return

    try:
        # Track operations performed
        operations = []

        # Perform requested operations
        with click.progressbar(
            length=sum([analyze, vacuum, reindex]),
            label='Optimizing database'
        ) as bar_line:
            # Run ANALYZE if requested
            if analyze:
                click.echo('\nUpdating statistics...')
                db.session.execute('ANALYZE')
                operations.append('ANALYZE')
                bar_line.update(1)

            # Run VACUUM if requested
            if vacuum:
                if full:
                    click.echo('\nPerforming full vacuum (this may take a while)...')
                    db.session.execute('VACUUM FULL')
                    operations.append('VACUUM FULL')
                else:
                    click.echo('\nPerforming regular vacuum...')
                    db.session.execute('VACUUM')
                    operations.append('VACUUM')
                bar_line.update(1)

            # Run REINDEX if requested
            if reindex:
                click.echo('\nRebuilding indexes...')

                # Get database name
                result = db.session.execute("SELECT current_database()").scalar()
                db_name = result if result else 'database'

                db.session.execute(f'REINDEX DATABASE {db_name}')
                operations.append('REINDEX')
                bar_line.update(1)

        metrics.increment('db.optimization_success')
        logger.info(f"Database optimized successfully: {', '.join(operations)}")
        click.echo(f"\nDatabase optimized successfully. Operations performed: {', '.join(operations)}")
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment('db.optimization_failure')
        logger.error(f'Database optimization failed: {str(e)}')
        raise click.ClickException(f'Database optimization failed: {str(e)}')

@db_cli.command('list-backups')
@click.option('--dir', default='./backups', help='Backup directory')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
@click.option('--show-size/--no-show-size', default=True, help='Include file size information')
def list_backups(backup_dir: str, output_format: str, show_size: bool) -> None:
    """
    List available database backups.

    Displays a list of database backups in the specified directory,
    along with metadata such as timestamp, size, and type.

    Args:
        backup_dir: Directory containing backup files
        output_format: Format for the output (table, json, csv)
        show_size: Include file size information in the output

    Examples:
        # List backups in the default directory
        $ flask db list-backups

        # List backups in a specific directory with JSON output
        $ flask db list-backups --dir=/path/to/backups --format=json
    """
    try:
        backup_dir = os.path.abspath(backup_dir)

        if not os.path.exists(backup_dir):
            click.echo(f"Backup directory does not exist: {backup_dir}")
            return EXIT_RESOURCE_ERROR

        # Find backup files
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith('.sql') or filename.endswith('.sql.gz'):
                # Parse filename to extract information
                full_path = os.path.join(backup_dir, filename)
                backup_info = {
                    'filename': filename,
                    'path': full_path,
                    'timestamp': get_backup_timestamp(filename),
                    'compressed': filename.endswith('.gz'),
                    'schema_only': filename.startswith('schema_'),
                }

                # Add file size if requested
                if show_size:
                    size_bytes = os.path.getsize(full_path)
                    backup_info['size_bytes'] = size_bytes
                    backup_info['size'] = format_bytes(size_bytes)

                backups.append(backup_info)

        # Sort by timestamp (newest first)
        backups.sort(key=lambda x: x['timestamp'], reverse=True)

        # Format output
        if output_format == 'json':
            click.echo(format_output(backups, 'json'))
        elif output_format == 'csv':
            click.echo(format_output(backups, 'csv'))
        else:
            # Table output
            if not backups:
                click.echo("No backups found.")
                return EXIT_SUCCESS

            click.echo(f"Found {len(backups)} backups in {backup_dir}:")
            click.echo("\nTimestamp           Type        " + ("Size       " if show_size else "") + "Filename")
            click.echo("-" * (48 + (12 if show_size else 0)))

            for backup in backups:
                timestamp_str = backup['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                backup_type = "Schema-only" if backup['schema_only'] else "Full backup"

                line = f"{timestamp_str}  {backup_type:<10} "
                if show_size:
                    line += f"{backup['size']:<10} "
                line += f"{backup['filename']}"

                click.echo(line)

        return EXIT_SUCCESS

    except Exception as e:
        logger.error(f'Failed to list backups: {str(e)}')
        raise click.ClickException(f'Failed to list backups: {str(e)}')

@db_cli.command('stats')
@click.option('--detailed/--simple', default=False, help='Show detailed statistics')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
@require_permission('db:read')
def database_stats(detailed: bool, output_format: str) -> None:
    """
    Show database statistics.

    Displays statistics about the database, including table sizes, row counts,
    index usage, and query performance metrics. This information is useful for
    performance monitoring and optimization.

    Args:
        detailed: Show detailed statistics
        output_format: Format for the output (table, json, csv)

    Examples:
        # Show basic statistics
        $ flask db stats

        # Show detailed statistics in JSON format
        $ flask db stats --detailed --format=json
    """
    try:
        # Collect database statistics
        stats = collect_database_stats(detailed)

        # Format output
        if output_format == 'json':
            click.echo(format_output(stats, 'json'))
        elif output_format == 'csv':
            # Flatten the nested structure for CSV output
            flattened_stats = []
            for category, items in stats.items():
                if isinstance(items, dict):
                    for key, value in items.items():
                        flattened_stats.append({
                            'category': category,
                            'metric': key,
                            'value': value
                        })
                else:
                    flattened_stats.append({
                        'category': 'general',
                        'metric': category,
                        'value': items
                    })
            click.echo(format_output(flattened_stats, 'csv'))
        else:
            # Table output
            click.echo("\nDatabase Statistics:")

            # General statistics
            click.echo("\nGeneral:")
            click.echo(f"  Database Size: {stats['database_size']}")
            click.echo(f"  Total Tables: {stats['table_count']}")
            click.echo(f"  Total Indexes: {stats['index_count']}")
            click.echo(f"  Total Rows: {stats['total_rows']:,}")
            click.echo(f"  Active Connections: {stats['active_connections']}")

            # Table statistics
            if 'tables' in stats:
                click.echo("\nLargest Tables:")
                click.echo("  Table Name                  Rows     Size      Indexes   Last Vacuum")
                click.echo("  -------------------------- -------- --------- --------- --------------")

                for table in stats['tables'][:10]:  # Show top 10
                    name = table['table_name'][:26]
                    rows = f"{table['row_count']:,}"
                    size = table['size']
                    indexes = str(table['index_count'])
                    vacuum = table.get('last_vacuum', 'Never')

                    click.echo(f"  {name:<26} {rows:>8} {size:>9} {indexes:>9} {vacuum}")

            # Index statistics
            if detailed and 'indexes' in stats:
                click.echo("\nMost Used Indexes:")
                click.echo("  Index Name                  Table         Scans      Size")
                click.echo("  --------------------------- ------------- ---------- ---------")

                for index in stats['indexes'][:10]:  # Show top 10
                    name = index['index_name'][:27]
                    table = index['table_name'][:13]
                    scans = f"{index['scans']:,}"
                    size = index['size']

                    click.echo(f"  {name:<27} {table:<13} {scans:>10} {size:>9}")

                click.echo("\nUnused Indexes:")
                unused_indexes = [idx for idx in stats['indexes'] if idx['scans'] == 0]
                for index in unused_indexes[:5]:  # Show just a few
                    click.echo(f"  {index['index_name']} on {index['table_name']} ({index['size']})")

                if len(unused_indexes) > 5:
                    click.echo(f"  ... and {len(unused_indexes) - 5} more")

            # Query statistics
            if 'queries' in stats:
                click.echo("\nSlow Queries:")
                slow_queries = stats['queries']['slow_queries']
                if isinstance(slow_queries, list):
                    for query in slow_queries[:3]:  # Show top 3
                        click.echo(f"  {query['query_text'][:80]}...")
                        click.echo(f"    Calls: {query['calls']}, Avg Time: {query['avg_time']} ms")
                else:
                    click.echo(f"  Slow query count: {slow_queries}")

        return EXIT_SUCCESS

    except Exception as e:
        logger.error(f'Failed to collect database statistics: {str(e)}')
        raise click.ClickException(f'Failed to collect database statistics: {str(e)}')

@db_cli.command('connections')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
@click.option('--kill', type=int, help='Kill a specific connection by PID')
@require_permission('db:admin')
def database_connections(output_format: str, kill: Optional[int] = None) -> None:
    """
    Show active database connections.

    Displays information about active connections to the database, including
    client information, query state, and duration. Can also be used to terminate
    specific connections if needed.

    Args:
        output_format: Format for the output (table, json, csv)
        kill: PID of connection to terminate (if provided)

    Examples:
        # Show all connections
        $ flask db connections

        # Show connections in JSON format
        $ flask db connections --format=json

        # Kill a specific connection
        $ flask db connections --kill=12345
    """
    try:
        # Kill a specific connection if requested
        if kill is not None:
            db.session.execute(f"SELECT pg_terminate_backend({kill})")
            click.echo(f"Connection with PID {kill} terminated")
            return EXIT_SUCCESS

        # Get active connections
        query = """
        SELECT pid, usename, application_name, client_addr, backend_start,
               xact_start, query_start, state, query
        FROM pg_stat_activity
        WHERE pid <> pg_backend_pid()
        ORDER BY query_start DESC NULLS LAST
        """

        result = db.session.execute(query).fetchall()

        # Convert to list of dictionaries
        connections = []
        for row in result:
            # Calculate duration if query_start is not None
            duration = None
            if row.query_start is not None:
                duration = (datetime.now() - row.query_start).total_seconds()

            conn = {
                'pid': row.pid,
                'user': row.usename,
                'app': row.application_name,
                'client_addr': str(row.client_addr) if row.client_addr else None,
                'backend_start': row.backend_start.isoformat() if row.backend_start else None,
                'xact_start': row.xact_start.isoformat() if row.xact_start else None,
                'query_start': row.query_start.isoformat() if row.query_start else None,
                'state': row.state,
                'duration_seconds': duration,
                'query': row.query
            }
            connections.append(conn)

        # Format output
        if output_format == 'json':
            click.echo(format_output(connections, 'json'))
        elif output_format == 'csv':
            click.echo(format_output(connections, 'csv'))
        else:
            # Table output
            if not connections:
                click.echo("No active connections.")
                return EXIT_SUCCESS

            click.echo(f"\nActive Database Connections: {len(connections)}")
            click.echo("\nPID     User     State      Duration  Query")
            click.echo("-" * 80)

            for conn in connections:
                pid = f"{conn['pid']:<7}"
                user = f"{conn['user'][:8]:<8}"
                state = f"{conn['state'][:10]:<10}"

                duration = "N/A"
                if conn['duration_seconds'] is not None:
                    seconds = int(conn['duration_seconds'])
                    if seconds < 60:
                        duration = f"{seconds}s"
                    else:
                        minutes = seconds // 60
                        sec = seconds % 60
                        duration = f"{minutes}m {sec}s"
                duration = f"{duration:<8}"

                query = conn['query'] or "N/A"
                if len(query) > 50:
                    query = query[:47] + "..."

                click.echo(f"{pid} {user} {state} {duration} {query}")

            click.echo("\nTo terminate a connection, use: flask db connections --kill=<PID>")

        return EXIT_SUCCESS

    except Exception as e:
        logger.error(f'Failed to retrieve database connections: {str(e)}')
        raise click.ClickException(f'Failed to retrieve database connections: {str(e)}')

# Helper functions

def get_backup_timestamp(filename: str) -> datetime:
    """Extract timestamp from backup filename."""
    try:
        # Format is: backup_YYYYMMDD_HHMMSS.sql[.gz] or schema_YYYYMMDD_HHMMSS.sql[.gz]
        parts = filename.split('_')
        if len(parts) >= 3:
            date_part = parts[1]
            time_part = parts[2].split('.')[0]  # Remove file extension

            if len(date_part) == 8 and len(time_part) == 6:
                timestamp_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]} "
                timestamp_str += f"{time_part[:2]}:{time_part[2:4]}:{time_part[4:6]}"
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except (ValueError, IndexError):
        pass

    # Fallback: use file modification time
    full_path = os.path.join('./backups', filename)
    if os.path.exists(full_path):
        return datetime.fromtimestamp(os.path.getmtime(full_path))

    return datetime.now()

def format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if bytes_value < 1024:
        return f"{bytes_value} B"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value / 1024:.1f} KB"
    elif bytes_value < 1024 * 1024 * 1024:
        return f"{bytes_value / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"

def get_free_disk_space(path: str) -> int:
    """Get free disk space for the given path."""
    import shutil
    return shutil.disk_usage(path).free

def estimate_backup_size() -> int:
    """Estimate the size of the database backup."""
    try:
        result = db.session.execute(text("""
            SELECT pg_database_size(current_database()) as size
        """)).scalar()
        return int(result) if result else 50 * 1024 * 1024  # Default to 50MB if unknown
    except Exception:
        # Default estimate: 50MB
        return 50 * 1024 * 1024

def verify_database_integrity() -> List[str]:
    """
    Verify database integrity and return list of issues.

    Returns:
        List of issue descriptions, empty if no issues found
    """
    issues = []

    try:
        # Check for orphaned records (broken foreign keys)
        # This will only work if foreign key constraints are defined
        # Otherwise, we need to check manually based on model relationships

        # Get all tables with foreign keys
        tables = db.metadata.tables

        # Check each table for potential issues
        for table_name, table in tables.items():
            # Skip SQLAlchemy-internal tables
            if table_name.startswith('_'):
                continue

            try:
                # Check if table exists in database
                result = db.session.execute(text(
                    f"SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    f"WHERE table_name = '{table_name}')"
                )).scalar()

                if not result:
                    issues.append(f"Table '{table_name}' defined in models but missing in database")
                    continue

                # Check if all columns exist
                for column in table.columns:
                    result = db.session.execute(text(
                        f"SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                        f"WHERE table_name = '{table_name}' AND column_name = '{column.name}')"
                    )).scalar()

                    if not result:
                        issues.append(f"Column '{column.name}' missing from table '{table_name}'")

            except Exception as e:
                issues.append(f"Error checking table '{table_name}': {str(e)}")

        # Check for database corruption
        try:
            db.session.execute("ANALYZE")
        except SQLAlchemyError as e:
            issues.append(f"Database statistical analysis failed: {str(e)}")

        # Check for broken sequences
        try:
            result = db.session.execute(text("""
                SELECT sequencename, max_value, last_value
                FROM pg_sequences
                WHERE last_value >= max_value * 0.9
            """)).fetchall()

            for row in result:
                issues.append(f"Sequence {row.sequencename} is at {row.last_value}/{row.max_value} "
                             f"({(row.last_value / row.max_value * 100):.1f}% used)")
        except Exception:
            # Not all databases support this query
            pass

    except Exception as e:
        issues.append(f"General integrity check error: {str(e)}")

    return issues

def fix_database_integrity_issues(issues: List[str], verbose: bool) -> bool:
    """
    Attempt to fix database integrity issues.

    Args:
        issues: List of identified issues
        verbose: Whether to display detailed progress

    Returns:
        True if all issues were fixed, False otherwise
    """
    # Track successful fixes
    fixed_count = 0
    total_issues = len(issues)

    for issue in issues:
        try:
            if "missing from table" in issue:
                # Column missing issue
                # Would need schema migration, cannot fix automatically
                if verbose:
                    click.echo(f"Cannot automatically fix: {issue}")
                continue

            if "missing in database" in issue:
                # Table missing issue
                table_name = issue.split("'")[1]
                if verbose:
                    click.echo(f"Creating missing table: {table_name}")

                # This is dangerous and rarely works correctly
                # as it doesn't consider foreign keys and relationships
                db.create_all([db.metadata.tables[table_name]])
                fixed_count += 1
                continue

            if "Sequence" in issue and "used" in issue:
                # Sequence near max value
                sequence_name = issue.split(" ")[1]
                if verbose:
                    click.echo(f"Restarting sequence: {sequence_name}")

                # Alter sequence to continue from a lower value
                db.session.execute(text(f"ALTER SEQUENCE {sequence_name} RESTART WITH 1"))
                fixed_count += 1
                continue

        except Exception as e:
            if verbose:
                click.echo(f"Error fixing issue: {issue} - {str(e)}")

    # Return True if all issues fixed
    return fixed_count == total_issues

def collect_database_stats(detailed: bool = False) -> Dict[str, Any]:
    """
    Collect database statistics.

    Args:
        detailed: Whether to include detailed statistics

    Returns:
        Dictionary of database statistics
    """
    stats = {}

    try:
        # Basic database information
        db_size_result = db.session.execute(text("""
            SELECT pg_size_pretty(pg_database_size(current_database())) as size,
                   pg_database_size(current_database()) as bytes
        """)).fetchone()

        stats['database_size'] = db_size_result.size if db_size_result else 'Unknown'
        stats['database_size_bytes'] = db_size_result.bytes if db_size_result else 0

        # Count tables
        table_count_result = db.session.execute(text("""
            SELECT count(*) as count FROM information_schema.tables
            WHERE table_schema = 'public'
        """)).scalar()
        stats['table_count'] = table_count_result or 0

        # Count indexes
        index_count_result = db.session.execute(text("""
            SELECT count(*) as count FROM pg_indexes
            WHERE schemaname = 'public'
        """)).scalar()
        stats['index_count'] = index_count_result or 0

        # Count total rows
        total_rows_result = db.session.execute(text("""
            SELECT sum(n_live_tup) as count FROM pg_stat_user_tables
        """)).scalar()
        stats['total_rows'] = total_rows_result or 0

        # Active connections
        connections_result = db.session.execute(text("""
            SELECT count(*) as count FROM pg_stat_activity
            WHERE datname = current_database()
        """)).scalar()
        stats['active_connections'] = connections_result or 0

        # Table statistics (largest tables)
        if detailed:
            tables_result = db.session.execute(text("""
                SELECT
                    relname as table_name,
                    n_live_tup as row_count,
                    pg_size_pretty(pg_total_relation_size(C.oid)) as size,
                    pg_size_pretty(pg_indexes_size(C.oid)) as index_size,
                    pg_total_relation_size(C.oid) as total_bytes,
                    (SELECT count(*) FROM pg_index I WHERE I.indrelid = C.oid) as index_count,
                    last_vacuum,
                    last_analyze
                FROM pg_class C
                LEFT JOIN pg_stat_user_tables T on C.relname = T.relname
                WHERE C.relkind = 'r'
                  AND C.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
                ORDER BY pg_total_relation_size(C.oid) DESC
                LIMIT 20
            """)).fetchall()

            tables = []
            for row in tables_result:
                table_info = {
                    'table_name': row.table_name,
                    'row_count': row.row_count,
                    'size': row.size,
                    'index_size': row.index_size,
                    'total_bytes': row.total_bytes,
                    'index_count': row.index_count
                }

                if row.last_vacuum:
                    table_info['last_vacuum'] = row.last_vacuum.strftime('%Y-%m-%d')

                if row.last_analyze:
                    table_info['last_analyze'] = row.last_analyze.strftime('%Y-%m-%d')

                tables.append(table_info)

            stats['tables'] = tables

            # Index statistics
            indexes_result = db.session.execute(text("""
                SELECT
                    indexrelname as index_name,
                    relname as table_name,
                    idx_scan as scans,
                    pg_size_pretty(pg_relation_size(indexrelid)) as size,
                    pg_relation_size(indexrelid) as size_bytes
                FROM pg_stat_user_indexes
                ORDER BY idx_scan DESC
                LIMIT 50
            """)).fetchall()

            indexes = []
            for row in indexes_result:
                index_info = {
                    'index_name': row.index_name,
                    'table_name': row.table_name,
                    'scans': row.scans,
                    'size': row.size,
                    'size_bytes': row.size_bytes
                }
                indexes.append(index_info)

            stats['indexes'] = indexes

            # Query statistics
            try:
                # This requires pg_stat_statements extension
                query_stats = db.session.execute(text("""
                    SELECT
                        query,
                        calls,
                        total_time / calls as avg_time,
                        rows / calls as avg_rows
                    FROM pg_stat_statements
                    WHERE calls > 10
                    ORDER BY total_time / calls DESC
                    LIMIT 10
                """)).fetchall()

                slow_queries = []
                for row in query_stats:
                    query_info = {
                        'query_text': row.query,
                        'calls': row.calls,
                        'avg_time': round(row.avg_time, 2),
                        'avg_rows': round(row.avg_rows, 2)
                    }
                    slow_queries.append(query_info)

                stats['queries'] = {
                    'slow_queries': slow_queries
                }
            except Exception:
                # Extension may not be enabled
                stats['queries'] = {
                    'slow_queries': "pg_stat_statements extension not available"
                }

        return stats

    except Exception as e:
        return {
            'error': str(e),
            'database_size': 'Error',
            'table_count': 'Error',
            'index_count': 'Error',
            'total_rows': 'Error',
            'active_connections': 'Error'
        }
