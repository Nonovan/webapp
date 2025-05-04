"""
Maintenance commands for the Cloud Infrastructure Platform CLI.

This module provides commands for system maintenance operations including backup management,
log rotation, cache management, and task scheduling.
"""

import os
import shutil
import logging
import datetime
import psutil
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

import click
from flask import current_app
from flask.cli import AppGroup

from cli.common import (
    require_permission,
    handle_error,
    confirm_action,
    secure_resource_cleanup,
    create_secure_tempdir,
    get_safe_config_dir,
    EXIT_SUCCESS,
    EXIT_ERROR
)
from core.security import (
    audit_log,
    is_safe_file_operation,
    sanitize_path
)
from extensions import cache, db

# Initialize logger
logger = logging.getLogger(__name__)

maintenance_cli = AppGroup('maintenance', help='System maintenance commands')

@maintenance_cli.command('cache-clear')
@click.option('--type', type=click.Choice(['all', 'application', 'template']), default='all',
              help='Type of cache to clear')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompt')
@require_permission('system:admin')
def clear_cache(type: str, force: bool) -> int:
    """
    Clear application caches.

    Clears various system caches to resolve cache-related issues or apply changes.
    """
    try:
        if not force:
            if not confirm_action("This will clear application caches, which might temporarily impact performance. Continue?"):
                click.echo("Cache clear operation cancelled.")
                return EXIT_SUCCESS

        click.echo(f"Clearing {type} cache(s)...")

        # Track which caches were cleared for logging
        cleared_caches = []

        # Application cache (Redis or other backend)
        if type in ['all', 'application']:
            cache.clear()
            cleared_caches.append('application')
            click.echo("✓ Application cache cleared")

        # Template cache (filesystem-based)
        if type in ['all', 'template']:
            template_cache_dir = current_app.config.get('TEMPLATE_CACHE_DIR',
                                                      os.path.join(current_app.instance_path, 'template_cache'))

            # Validate path safety before operation
            if is_safe_file_operation('delete', template_cache_dir):
                if os.path.exists(template_cache_dir):
                    # Only remove contents, not the directory itself
                    for item in os.listdir(template_cache_dir):
                        item_path = os.path.join(template_cache_dir, item)
                        if os.path.isfile(item_path):
                            os.unlink(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)

                    cleared_caches.append('template')
                    click.echo("✓ Template cache cleared")
                else:
                    click.echo("Template cache directory doesn't exist, nothing to clear")
            else:
                logger.error(f"Security validation failed for template cache path: {template_cache_dir}")
                click.echo("✗ Template cache could not be cleared due to security validation failure")

        # Log the action
        audit_log(
            category='maintenance',
            event_type='cache_cleared',
            details={'cache_types': cleared_caches},
            severity='info'
        )

        click.echo("Cache clearing operation completed successfully.")
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to clear cache")
        audit_log(
            category='maintenance',
            event_type='cache_clear_failed',
            details={'error': str(e)},
            severity='error'
        )
        return EXIT_ERROR

@maintenance_cli.command('logs-rotate')
@click.option('--all/--application-only', default=False, help='Rotate all logs or just application logs')
@click.option('--compress/--no-compress', default=True, help='Compress rotated logs')
@click.option('--max-age', type=int, default=90, help='Maximum age in days for log retention')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompt')
@require_permission('system:admin')
def rotate_logs(all: bool, compress: bool, max_age: int, force: bool) -> int:
    """
    Rotate application logs.

    Forces log rotation to start new log files and archive old ones.
    """
    try:
        if not force:
            if not confirm_action("This will rotate and archive log files. Continue?"):
                click.echo("Log rotation operation cancelled.")
                return EXIT_SUCCESS

        # Get log directories from config
        app_log_dir = current_app.config.get('LOG_DIR', 'logs')
        archive_dir = os.path.join(app_log_dir, 'archive')

        # Create archive directory if it doesn't exist
        os.makedirs(archive_dir, exist_ok=True)

        # Define log rotation function
        def rotate_logs_in_dir(log_dir: str) -> int:
            """Rotate logs in the specified directory."""
            if not os.path.isdir(log_dir):
                logger.warning(f"Log directory not found: {log_dir}")
                return 0

            # Track stats
            rotated_count = 0
            compressed_count = 0
            archived_count = 0
            deleted_count = 0

            # Handle logs
            for filename in os.listdir(log_dir):
                filepath = os.path.join(log_dir, filename)

                # Skip directories and already rotated/compressed files
                if os.path.isdir(filepath) or not filename.endswith('.log'):
                    continue

                # Validate safety before operation
                if not is_safe_file_operation('write', filepath):
                    logger.warning(f"Skipping potentially unsafe log file: {filepath}")
                    continue

                # Get file modification time and age
                file_time = os.path.getmtime(filepath)
                file_age = (datetime.datetime.now() -
                           datetime.datetime.fromtimestamp(file_time)).days

                # Current date for rotation suffix
                date_suffix = datetime.datetime.now().strftime('%Y%m%d')

                # Rotate current logs
                rotated_name = f"{filename}.{date_suffix}"
                rotated_path = os.path.join(log_dir, rotated_name)

                # Rename current log to rotated name
                try:
                    shutil.copy2(filepath, rotated_path)
                    # Truncate original file rather than removing it
                    with open(filepath, 'w') as f:
                        pass
                    rotated_count += 1
                except Exception as e:
                    logger.error(f"Failed to rotate log {filepath}: {e}")
                    continue

                # Compress logs older than 7 days or freshly rotated logs
                if compress:
                    if file_age >= 7 or filepath != rotated_path:
                        try:
                            if not rotated_path.endswith('.gz'):
                                import gzip
                                with open(rotated_path, 'rb') as f_in:
                                    with gzip.open(f"{rotated_path}.gz", 'wb') as f_out:
                                        shutil.copyfileobj(f_in, f_out)
                                os.unlink(rotated_path)
                                compressed_count += 1
                        except Exception as e:
                            logger.error(f"Failed to compress log {rotated_path}: {e}")

                # Archive compressed logs older than 14 days
                compressed_path = f"{rotated_path}.gz"
                if os.path.exists(compressed_path) and file_age >= 14:
                    try:
                        archive_filename = os.path.basename(compressed_path)
                        archive_path = os.path.join(archive_dir, archive_filename)
                        shutil.move(compressed_path, archive_path)
                        archived_count += 1
                    except Exception as e:
                        logger.error(f"Failed to archive log {compressed_path}: {e}")

                # Delete archived logs older than max_age days
                for archive_file in os.listdir(archive_dir):
                    archive_path = os.path.join(archive_dir, archive_file)
                    if not os.path.isfile(archive_path):
                        continue

                    file_time = os.path.getmtime(archive_path)
                    file_age = (datetime.datetime.now() -
                               datetime.datetime.fromtimestamp(file_time)).days

                    if file_age > max_age:
                        try:
                            os.unlink(archive_path)
                            deleted_count += 1
                        except Exception as e:
                            logger.error(f"Failed to delete old log {archive_path}: {e}")

            return {
                'rotated': rotated_count,
                'compressed': compressed_count,
                'archived': archived_count,
                'deleted': deleted_count
            }

        # Rotate application logs
        click.echo(f"Rotating application logs in {app_log_dir}...")
        app_stats = rotate_logs_in_dir(app_log_dir)

        # Rotate other logs if requested
        system_stats = {}
        if all:
            system_log_dirs = ['/var/log/cloud-platform']
            for log_dir in system_log_dirs:
                if os.path.isdir(log_dir) and os.access(log_dir, os.W_OK):
                    click.echo(f"Rotating system logs in {log_dir}...")
                    dir_stats = rotate_logs_in_dir(log_dir)
                    for key, value in dir_stats.items():
                        system_stats[key] = system_stats.get(key, 0) + value
                else:
                    logger.warning(f"System log directory not accessible: {log_dir}")

        # Print summary
        click.echo("\nLog rotation summary:")
        click.echo(f"  Application logs: {app_stats.get('rotated', 0)} rotated, " +
                  f"{app_stats.get('compressed', 0)} compressed, " +
                  f"{app_stats.get('archived', 0)} archived, " +
                  f"{app_stats.get('deleted', 0)} deleted")

        if all and system_stats:
            click.echo(f"  System logs: {system_stats.get('rotated', 0)} rotated, " +
                      f"{system_stats.get('compressed', 0)} compressed, " +
                      f"{system_stats.get('archived', 0)} archived, " +
                      f"{system_stats.get('deleted', 0)} deleted")

        # Log the action
        audit_log(
            category='maintenance',
            event_type='logs_rotated',
            details={
                'app_logs': app_stats,
                'system_logs': system_stats if all else {},
                'compress': compress,
                'max_age': max_age
            },
            severity='info'
        )

        click.echo("Log rotation completed successfully.")
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to rotate logs")
        audit_log(
            category='maintenance',
            event_type='logs_rotate_failed',
            details={'error': str(e)},
            severity='error'
        )
        return EXIT_ERROR

@maintenance_cli.command('cleanup')
@click.option('--older-than', type=int, default=30, help='Clean files older than days')
@click.option('--type', type=click.Choice(['all', 'logs', 'temp', 'uploads']), default='all',
              help='Type of files to clean up')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompt')
@click.option('--dry-run/--no-dry-run', default=False, help='Show what would be deleted without deleting')
@require_permission('system:admin')
def cleanup_files(older_than: int, type: str, force: bool, dry_run: bool) -> int:
    """
    Clean up old files.

    Removes old logs, temporary files, and other artifacts based on age.
    """
    try:
        # Define safe directories for cleanup
        base_dir = current_app.instance_path
        log_dir = current_app.config.get('LOG_DIR', os.path.join(base_dir, 'logs'))
        temp_dir = current_app.config.get('TEMP_DIR', os.path.join(base_dir, 'temp'))
        upload_dir = current_app.config.get('UPLOAD_DIR', os.path.join(base_dir, 'uploads'))

        # Build list of directories to clean based on type
        dirs_to_clean = []
        if type in ['all', 'logs']:
            dirs_to_clean.append(log_dir)
        if type in ['all', 'temp']:
            dirs_to_clean.append(temp_dir)
        if type in ['all', 'uploads']:
            dirs_to_clean.append(upload_dir)

        # Calculate cutoff date
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=older_than)
        cutoff_timestamp = cutoff_date.timestamp()

        if not force and not dry_run:
            message = f"This will delete files older than {older_than} days"
            if type != 'all':
                message += f" in {type} directories"
            message += ". Continue?"

            if not confirm_action(message, default=False):
                click.echo("Cleanup operation cancelled.")
                return EXIT_SUCCESS

        # Collect files for deletion
        files_to_delete = []
        skipped_files = []

        for directory in dirs_to_clean:
            # Skip directories that don't exist
            if not os.path.isdir(directory):
                logger.warning(f"Directory not found, skipping: {directory}")
                continue

            # Find old files in the directory
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)

                    # Skip if path validation fails
                    if not is_safe_file_operation('delete', file_path):
                        skipped_files.append(file_path)
                        continue

                    try:
                        # Check file age
                        mtime = os.path.getmtime(file_path)
                        if mtime < cutoff_timestamp:
                            files_to_delete.append(file_path)
                    except Exception as e:
                        logger.warning(f"Error checking file {file_path}: {e}")
                        skipped_files.append(file_path)

        # Report on files that would be deleted
        click.echo(f"\nFound {len(files_to_delete)} files older than {older_than} days to clean up.")
        if skipped_files:
            click.echo(f"Skipping {len(skipped_files)} files due to security checks or errors.")

        if dry_run:
            click.echo("\nDRY RUN - No files will be deleted.")
            click.echo("\nSample of files that would be deleted:")
            for file_path in files_to_delete[:10]:  # Show only first 10
                file_age = (datetime.datetime.now().timestamp() - os.path.getmtime(file_path)) / 86400  # days
                click.echo(f"  {file_path} (age: {file_age:.1f} days)")

            if len(files_to_delete) > 10:
                click.echo(f"  ... and {len(files_to_delete) - 10} more files")

            # Log the dry run
            audit_log(
                category='maintenance',
                event_type='cleanup_dry_run',
                details={
                    'file_count': len(files_to_delete),
                    'skipped_count': len(skipped_files),
                    'older_than': older_than,
                    'type': type
                },
                severity='info'
            )

            return EXIT_SUCCESS

        # Perform deletion
        deleted_count = 0
        failed_count = 0

        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to delete file {file_path}: {e}")
                failed_count += 1

        # Clean up empty directories
        empty_dirs_removed = 0
        for directory in dirs_to_clean:
            if not os.path.isdir(directory):
                continue

            for root, dirs, files in os.walk(directory, topdown=False):
                # Skip the top-level directories themselves
                if root in dirs_to_clean:
                    continue

                # Try to remove empty directories
                if not files and not dirs:
                    try:
                        os.rmdir(root)
                        empty_dirs_removed += 1
                    except Exception as e:
                        logger.warning(f"Failed to remove empty directory {root}: {e}")

        # Report results
        click.echo(f"\nDeleted {deleted_count} files.")
        if failed_count:
            click.echo(f"Failed to delete {failed_count} files.")
        if empty_dirs_removed:
            click.echo(f"Removed {empty_dirs_removed} empty directories.")

        # Log the action
        audit_log(
            category='maintenance',
            event_type='files_cleaned',
            details={
                'deleted_count': deleted_count,
                'failed_count': failed_count,
                'empty_dirs_removed': empty_dirs_removed,
                'skipped_count': len(skipped_files),
                'older_than': older_than,
                'type': type
            },
            severity='info'
        )

        click.echo("Cleanup operation completed successfully.")
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to clean up files")
        audit_log(
            category='maintenance',
            event_type='cleanup_failed',
            details={'error': str(e)},
            severity='error'
        )
        return EXIT_ERROR

@maintenance_cli.command('scheduled-tasks')
@click.option('--run-now', is_flag=True, help='Run scheduled maintenance tasks immediately')
@click.option('--task', type=str, help='Run a specific task by name')
@click.option('--list', 'list_tasks', is_flag=True, help='List available scheduled tasks')
@require_permission('system:admin')
def scheduled_tasks(run_now: bool, task: Optional[str], list_tasks: bool) -> int:
    """
    Manage scheduled maintenance tasks.

    Lists, runs, or schedules maintenance tasks for the application.
    """
    try:
        # Define available scheduled tasks
        tasks = {
            'optimize_db': {
                'description': 'Run database optimization routines',
                'function': lambda: db_optimization_task()
            },
            'clean_sessions': {
                'description': 'Clean expired user sessions',
                'function': lambda: clean_expired_sessions_task()
            },
            'update_metrics': {
                'description': 'Update system metrics and statistics',
                'function': lambda: update_metrics_task()
            },
            'check_disk_space': {
                'description': 'Check disk space usage and send alerts if needed',
                'function': lambda: check_disk_space_task()
            }
        }

        # List tasks if requested
        if list_tasks:
            click.echo("Available scheduled tasks:")
            for task_name, task_info in tasks.items():
                click.echo(f"- {task_name}: {task_info['description']}")
            return EXIT_SUCCESS

        # Run a specific task if requested
        if task:
            if task not in tasks:
                click.echo(f"Error: Unknown task '{task}'")
                click.echo("Use --list to see available tasks")
                return EXIT_ERROR

            click.echo(f"Running task: {task}")
            result = tasks[task]['function']()
            audit_log(
                category='maintenance',
                event_type='scheduled_task_run',
                details={
                    'task': task,
                    'result': result
                },
                severity='info'
            )
            click.echo(f"Task completed with result: {result}")
            return EXIT_SUCCESS

        # Run all tasks if run-now flag is set
        if run_now:
            click.echo("Running all scheduled maintenance tasks:")
            results = {}

            for task_name, task_info in tasks.items():
                click.echo(f"- Running {task_name}...")
                try:
                    result = task_info['function']()
                    results[task_name] = {'status': 'success', 'result': result}
                    click.echo(f"  ✓ Completed")
                except Exception as e:
                    logger.error(f"Task {task_name} failed: {e}")
                    results[task_name] = {'status': 'error', 'error': str(e)}
                    click.echo(f"  ✗ Failed: {e}")

            # Log the run
            audit_log(
                category='maintenance',
                event_type='scheduled_tasks_all_run',
                details={'results': results},
                severity='info'
            )

            click.echo("\nAll tasks completed.")
            return EXIT_SUCCESS

        # If no action specified, show help
        click.echo("Please specify an action: --list, --run-now, or --task <task_name>")
        return EXIT_ERROR

    except Exception as e:
        handle_error(e, "Failed to manage scheduled tasks")
        audit_log(
            category='maintenance',
            event_type='scheduled_tasks_failed',
            details={'error': str(e)},
            severity='error'
        )
        return EXIT_ERROR

# Helper functions for scheduled tasks
def db_optimization_task() -> Dict[str, Any]:
    """Run database optimization routines."""
    start_time = datetime.datetime.now()

    # These queries are PostgreSQL-specific; adapt for other DB engines as needed
    queries = [
        # Update table statistics
        "ANALYZE",

        # Clean up waiting connections over 1 hour
        """
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE state = 'idle'
        AND state_change < NOW() - INTERVAL '1 hour'
        """,

        # Find indexes that haven't been used
        """
        SELECT schemaname, relname, indexrelname, idx_scan
        FROM pg_stat_user_indexes
        WHERE idx_scan = 0 AND schemaname NOT LIKE 'pg_%'
        """
    ]

    results = {}

    try:
        for i, query in enumerate(queries):
            if i == 0:  # ANALYZE
                db.session.execute(query)
                results['analyze'] = 'success'
            elif i == 1:  # Terminate connections
                result = db.session.execute(query)
                results['connections_terminated'] = result.rowcount
            elif i == 2:  # Unused indexes
                result = db.session.execute(query)
                unused_indexes = [dict(row) for row in result]
                results['unused_indexes'] = unused_indexes

        # Commit any changes
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database optimization failed: {e}")
        results['error'] = str(e)

    # Calculate execution time
    end_time = datetime.datetime.now()
    execution_time = (end_time - start_time).total_seconds()
    results['execution_time'] = execution_time

    return results

def clean_expired_sessions_task() -> Dict[str, Any]:
    """Clean expired user sessions."""
    # This depends on your session storage implementation
    # Example for database-backed sessions
    from models.auth.user_session import UserSession

    try:
        # Get expired sessions
        expired_query = UserSession.query.filter(UserSession.expiry < datetime.datetime.now())
        expired_count = expired_query.count()

        # Delete expired sessions
        expired_query.delete()
        db.session.commit()

        return {
            'expired_sessions_removed': expired_count,
            'status': 'success'
        }
    except Exception as e:
        db.session.rollback()
        logger.error(f"Session cleanup failed: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }

def update_metrics_task() -> Dict[str, Any]:
    """Update system metrics and statistics."""
    try:
        # This would connect to your metrics system
        metrics_updated = 0

        # Example: disk usage
        disk_usage = psutil.disk_usage('/')

        # Example: storing metrics in database
        from models.security.system_config import SystemConfig

        # Store disk usage metric
        disk_config = SystemConfig.query.filter_by(key='disk_usage_percent').first()
        if not disk_config:
            disk_config = SystemConfig(
                key='disk_usage_percent',
                value=str(disk_usage.percent),
                description='Current disk usage percentage'
            )
            db.session.add(disk_config)
        else:
            disk_config.value = str(disk_usage.percent)

        metrics_updated += 1

        # Store memory usage metric
        mem = psutil.virtual_memory()
        memory_config = SystemConfig.query.filter_by(key='memory_usage_percent').first()
        if not memory_config:
            memory_config = SystemConfig(
                key='memory_usage_percent',
                value=str(mem.percent),
                description='Current memory usage percentage'
            )
            db.session.add(memory_config)
        else:
            memory_config.value = str(mem.percent)

        metrics_updated += 1

        # Commit changes
        db.session.commit()

        return {
            'metrics_updated': metrics_updated,
            'status': 'success',
            'disk_usage': disk_usage.percent,
            'memory_usage': mem.percent
        }
    except Exception as e:
        db.session.rollback()
        logger.error(f"Metrics update failed: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }

def check_disk_space_task() -> Dict[str, Any]:
    """Check disk space usage and alert if needed."""
    try:
        # Get disk usage
        disk_usage = psutil.disk_usage('/')
        disk_percent = disk_usage.percent

        # Check against thresholds
        warning_threshold = 80
        critical_threshold = 90
        result = {
            'disk_usage': disk_percent,
            'status': 'normal',
            'alert_sent': False
        }

        if disk_percent >= critical_threshold:
            # Critical alert
            result['status'] = 'critical'

            # Send alert (using audit log for now)
            audit_log(
                category='system',
                event_type='disk_usage_critical',
                details={'usage_percent': disk_percent},
                severity='critical'
            )
            result['alert_sent'] = True

        elif disk_percent >= warning_threshold:
            # Warning alert
            result['status'] = 'warning'

            # Send alert (using audit log for now)
            audit_log(
                category='system',
                event_type='disk_usage_warning',
                details={'usage_percent': disk_percent},
                severity='warning'
            )
            result['alert_sent'] = True

        return result

    except Exception as e:
        logger.error(f"Disk space check failed: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }
