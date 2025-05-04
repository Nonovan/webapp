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
import os
import json
import socket
import platform
import psutil
import click
import sys
import yaml
from datetime import datetime, timedelta
from flask.cli import AppGroup
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
from typing import Dict, Any, List, Tuple, Optional, Set

from core.config import Config
from core.security import check_file_integrity, check_critical_file_integrity
from extensions import db, metrics, cache
from cli.common import (
    format_output, handle_error, confirm_action,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_RESOURCE_ERROR
)

try:
    # Use logging module directly since we don't have a Flask app at this point
    logger = logging.getLogger(__name__)
except TypeError:
    logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
system_cli = AppGroup('system')

# Constants for resource thresholds
DEFAULT_DISK_WARNING = 80  # Percentage threshold for disk space warning
DEFAULT_MEMORY_WARNING = 85  # Percentage threshold for memory warning
DEFAULT_CPU_WARNING = 75  # Percentage threshold for CPU warning


@system_cli.command('status')
@click.option('--detailed/--simple', default=False, help='Show detailed metrics')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
def system_status(detailed: bool, output_format: str) -> None:
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
        output_format: Format for the output (table, json, csv)

    Examples:
        # Show basic system status
        $ flask system status

        # Show detailed system metrics
        $ flask system status --detailed

        # Export status information as JSON
        $ flask system status --format json
    """
    try:
        if output_format == 'table':
            click.echo('\nSystem Status:')

        # Data collection
        metrics_data = {}

        with click.progressbar(length=4, label='Collecting metrics') as bar_line:
            # System metrics
            sys_metrics = {
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'cpu_usage': psutil.cpu_percent(interval=1),  # 1 second sample
                'memory_total': f"{psutil.virtual_memory().total / (1024 * 1024 * 1024):.2f} GB",
                'memory_usage': psutil.virtual_memory().percent,
                'disk_total': f"{psutil.disk_usage('/').total / (1024 * 1024 * 1024):.2f} GB",
                'disk_usage': psutil.disk_usage('/').percent,
                'uptime': str(timedelta(seconds=int(datetime.now().timestamp() - psutil.boot_time())))
            }
            bar_line.update(1)
            metrics_data['system'] = sys_metrics

            # Application metrics
            app_metrics = {}
            try:
                # Try to get metrics from registry if available
                if hasattr(metrics, 'registry'):
                    for metric in metrics.registry.collect():
                        metric_samples = []
                        for sample in metric.samples:
                            sample_data = {
                                'value': sample.value,
                                'timestamp': sample.timestamp
                            }
                            if sample.labels:
                                sample_data['labels'] = dict(sample.labels)
                            metric_samples.append(sample_data)
                        app_metrics[metric.name] = metric_samples

                # Fallback if registry not available
                if not app_metrics:
                    app_metrics["info"] = "Detailed metrics not available"
            except (AttributeError, TypeError) as e:
                logger.warning("Failed to collect application metrics: %s", e)
                app_metrics["error"] = str(e)
            bar_line.update(1)
            metrics_data['application'] = app_metrics

            # Database metrics
            db_metrics = {}
            try:
                # Use engine.pool.status() to get connection info
                pool_status = db.engine.pool.status() if hasattr(db.engine.pool, 'status') else {}
                active_connections = pool_status.get('checkedout', 0) if isinstance(pool_status, dict) else 0

                # Query database for basic statistics
                db_metrics = {
                    'active_connections': active_connections,
                    'idle_connections': pool_status.get('idle', 0) if isinstance(pool_status, dict) else 0,
                    'total_connections': pool_status.get('size', 0) if isinstance(pool_status, dict) else 0
                }

                try:
                    # Try to get database size (PostgreSQL specific)
                    db_size_result = db.session.execute(
                        "SELECT pg_size_pretty(pg_database_size(current_database()))"
                    ).scalar()
                    db_metrics['database_size'] = db_size_result
                except:
                    # Fallback for other database engines
                    pass

                db_metrics['table_count'] = len(db.metadata.tables)

                # Try to get table statistics if possible
                try:
                    tables_info = []
                    for table_name in db.metadata.tables.keys():
                        row_count_query = f"SELECT COUNT(*) FROM {table_name}"
                        try:
                            row_count = db.session.execute(row_count_query).scalar()
                            tables_info.append({
                                'name': table_name,
                                'rows': row_count
                            })
                        except:
                            # Skip tables that can't be queried
                            continue

                    if tables_info and detailed:
                        db_metrics['tables'] = tables_info
                except:
                    # Skip table statistics on error
                    pass

            except (psutil.Error, SQLAlchemyError, AttributeError) as e:
                logger.warning("Failed to collect database metrics: %s", e)
                db_metrics = {"error": str(e)}
            bar_line.update(1)
            metrics_data['database'] = db_metrics

            # Process metrics
            proc = psutil.Process()
            process_metrics = {
                'pid': proc.pid,
                'username': proc.username(),
                'memory_mb': proc.memory_info().rss / (1024 * 1024),
                'memory_percent': proc.memory_percent(),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'threads': proc.num_threads(),
                'open_files': len(proc.open_files()),
                'connections': len(proc.connections()),
                'start_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'running_time': str(timedelta(seconds=int(datetime.now().timestamp() - proc.create_time())))
            }

            # Add child processes if detailed
            if detailed:
                try:
                    children = proc.children(recursive=True)
                    process_metrics['child_processes'] = len(children)

                    if children:
                        child_details = []
                        for child in children:
                            try:
                                child_details.append({
                                    'pid': child.pid,
                                    'cpu_percent': child.cpu_percent(interval=0.1),
                                    'memory_mb': child.memory_info().rss / (1024 * 1024),
                                })
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        process_metrics['child_details'] = child_details
                except:
                    pass

            bar_line.update(1)
            metrics_data['process'] = process_metrics

            # Cache metrics if using Redis or similar
            cache_metrics = {}
            if cache and hasattr(cache, 'get_stats'):
                try:
                    cache_stats = cache.get_stats()
                    if cache_stats:
                        cache_metrics = dict(cache_stats)
                except:
                    pass

            if cache_metrics:
                metrics_data['cache'] = cache_metrics

        # Format and display the information according to output_format
        if output_format == 'json':
            click.echo(format_output(metrics_data, 'json'))
        elif output_format == 'csv':
            # Flatten the structure into rows for CSV
            flattened_data = []

            for category, metrics in metrics_data.items():
                for key, value in metrics.items():
                    if key != 'tables' and not isinstance(value, (dict, list)):
                        flattened_data.append({
                            'category': category,
                            'metric': key,
                            'value': value
                        })

            click.echo(format_output(flattened_data, 'csv'))
        else:  # Default to table format
            # Display metrics
            for category, values in [
                ('System', metrics_data['system']),
                ('Process', metrics_data['process']),
                ('Database', metrics_data['database'])
            ]:
                click.echo(f"\n{category}:")
                for key, value in values.items():
                    # Skip detailed info in simple mode
                    if not detailed and key in ('tables', 'child_details'):
                        continue

                    # Format value display for certain metrics
                    if key == 'cpu_usage' or key == 'cpu_percent' or key == 'memory_usage' or key == 'memory_percent' or key == 'disk_usage':
                        # Add color coding for values near thresholds
                        if isinstance(value, (int, float)):
                            value_str = f"{value}%"
                            if value >= 90:
                                value_str = click.style(value_str, fg='red', bold=True)
                            elif value >= 75:
                                value_str = click.style(value_str, fg='yellow')
                        else:
                            value_str = str(value)
                        click.echo(f"  {key.replace('_', ' ').title()}: {value_str}")
                    elif key in ('tables', 'child_details'):
                        # Skip these in the main output - they'll be shown separately if needed
                        continue
                    else:
                        click.echo(f"  {key.replace('_', ' ').title()}: {value}")

            # Show database tables if available and detailed mode
            if detailed and 'tables' in metrics_data.get('database', {}):
                click.echo("\nDatabase Tables:")
                for table in metrics_data['database']['tables']:
                    click.echo(f"  {table['name']}: {table['rows']:,} rows")

            # Show child processes if available and detailed mode
            if detailed and 'child_details' in metrics_data.get('process', {}):
                click.echo("\nChild Processes:")
                for child in metrics_data['process']['child_details']:
                    click.echo(f"  PID {child['pid']}: {child['cpu_percent']}% CPU, {child['memory_mb']:.1f} MB")

            if detailed:
                click.echo("\nApplication Metrics:")
                if isinstance(metrics_data.get('application', {}), dict):
                    for name, samples in metrics_data['application'].items():
                        if name in ('info', 'error'):
                            click.echo(f"  {samples}")
                        elif isinstance(samples, list) and len(samples) > 0:
                            click.echo(f"  {name}:")
                            for i, sample in enumerate(samples[:3]):  # Limit to first 3 samples
                                if isinstance(sample, dict):
                                    if 'labels' in sample:
                                        label_str = ', '.join(f"{k}={v}" for k, v in sample['labels'].items())
                                        click.echo(f"    {label_str}: {sample['value']}")
                                    else:
                                        click.echo(f"    {sample['value']}")
                            if len(samples) > 3:
                                click.echo(f"    ... and {len(samples) - 3} more samples")

        return EXIT_SUCCESS

    except (psutil.Error, SQLAlchemyError) as e:
        handle_error(e, "Status check failed")
        return EXIT_ERROR


@system_cli.command('health')
@click.option('--detailed/--simple', default=False, help='Show detailed health information')
@click.option('--check-files/--no-check-files', default=True, help='Check file integrity')
@click.option('--exit-code/--no-exit-code', default=True,
              help='Return non-zero exit code if any check fails')
def health_check(detailed: bool, check_files: bool, exit_code: bool) -> int:
    """
    Perform system health check.

    Runs a series of validation checks to verify that all system components
    are functioning correctly. Tests include database connectivity, disk space
    availability, memory usage, and CPU utilization.

    This command is useful for automated monitoring and deployment verification.
    It exits with a non-zero status if any check fails, making it suitable for
    use in scripts and CI/CD pipelines.

    Args:
        detailed: Whether to show detailed health information
        check_files: Whether to include file integrity checks
        exit_code: Whether to return non-zero exit code if checks fail

    Examples:
        # Run basic health check
        $ flask system health

        # Run detailed health check
        $ flask system health --detailed

        # Run health check without file checks
        $ flask system health --no-check-files
    """
    try:
        all_passed = True
        checks = {
            'Database': lambda: bool(db.session.execute('SELECT 1').scalar()),
            'Disk Space': lambda: psutil.disk_usage('/').percent < DEFAULT_DISK_WARNING,
            'Memory': lambda: psutil.virtual_memory().percent < DEFAULT_MEMORY_WARNING,
            'CPU': lambda: psutil.cpu_percent(interval=1) < DEFAULT_CPU_WARNING
        }

        # Add file integrity check if requested
        if check_files:
            checks['File Integrity'] = lambda: check_critical_file_integrity()

        # Try Redis connection if configured
        if hasattr(cache, 'ping'):
            checks['Cache'] = lambda: bool(cache.ping())

        with click.progressbar(length=len(checks), label='Running health checks') as bar_line:
            results = {}
            details = {}

            for name, check in checks.items():
                try:
                    passed = check()
                    results[name] = passed
                    if not passed:
                        all_passed = False

                    # Collect detailed information where possible
                    if detailed:
                        if name == 'Disk Space':
                            disk_info = psutil.disk_usage('/')
                            details[name] = {
                                'total': f"{disk_info.total / (1024**3):.2f} GB",
                                'used': f"{disk_info.used / (1024**3):.2f} GB",
                                'free': f"{disk_info.free / (1024**3):.2f} GB",
                                'percent': f"{disk_info.percent}%"
                            }
                        elif name == 'Memory':
                            mem_info = psutil.virtual_memory()
                            details[name] = {
                                'total': f"{mem_info.total / (1024**3):.2f} GB",
                                'used': f"{mem_info.used / (1024**3):.2f} GB",
                                'available': f"{mem_info.available / (1024**3):.2f} GB",
                                'percent': f"{mem_info.percent}%"
                            }
                        elif name == 'CPU':
                            cpu_info = psutil.cpu_times_percent()
                            details[name] = {
                                'user': f"{cpu_info.user}%",
                                'system': f"{cpu_info.system}%",
                                'idle': f"{cpu_info.idle}%",
                                'cores': psutil.cpu_count()
                            }
                        elif name == 'Database' and passed:
                            try:
                                version = db.session.execute("SELECT version()").scalar()
                                details[name] = {
                                    'version': str(version),
                                    'tables': len(db.metadata.tables)
                                }
                            except:
                                details[name] = {'status': 'Connected, but unable to get version'}
                        elif name == 'File Integrity' and not passed:
                            # Note: Detailed file integrity info would be available
                            # from the actual check_critical_file_integrity function
                            details[name] = {
                                'status': 'Failed - run dedicated integrity check for details'
                            }

                    bar_line.update(1)
                except (psutil.Error, SQLAlchemyError, Exception) as e:
                    results[name] = False
                    all_passed = False
                    details[name] = {'error': str(e)}
                    logger.error("Health check '%s' failed: %s", name, e)

        # Display results
        click.echo("\nHealth Check Results:")

        for name, passed in results.items():
            status = '✅' if passed else '❌'
            click.echo(f"  {name}: {status}")

        # Show detailed information if requested
        if detailed:
            click.echo("\nDetailed Information:")
            for name, info in details.items():
                click.echo(f"  {name}:")
                if isinstance(info, dict):
                    for key, value in info.items():
                        click.echo(f"    {key}: {value}")
                else:
                    click.echo(f"    {info}")

        click.echo(f"\nOverall Status: {'✅ Healthy' if all_passed else '❌ Issues Detected'}")

        # Return appropriate exit code
        if not all_passed and exit_code:
            return EXIT_ERROR

        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Health check failed")
        return EXIT_ERROR


@system_cli.command('config')
@click.option('--verify/--no-verify', default=True, help='Verify configuration')
@click.option('--env', default=None, help='Specific environment to check')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.option('--mask-secrets/--show-secrets', default=True,
              help='Mask sensitive values like passwords and keys')
def check_config(verify: bool, env: Optional[str], output_format: str, mask_secrets: bool) -> int:
    """
    Check system configuration.

    Displays the current application configuration settings and optionally
    verifies that all required variables are present. This command helps
    diagnose configuration-related issues and ensures the application
    environment is properly set up.

    Sensitive values like passwords and keys are masked in the output for security.

    Args:
        verify: Whether to verify required configuration variables
        env: Specific environment to check (current env if not specified)
        output_format: Format for the output (table, json, yaml)
        mask_secrets: Whether to mask sensitive values like passwords

    Examples:
        # Show configuration with verification
        $ flask system config

        # Show production configuration in JSON format
        $ flask system config --env production --format json

        # Show full configuration without masking secrets (be careful!)
        $ flask system config --mask-secrets
    """
    try:
        config = Config.load(env)

        # List of fields that might contain sensitive information
        sensitive_fields = {'key', 'secret', 'password', 'token', 'credential', 'auth'}

        # Create a copy for display, masking sensitive values if needed
        display_config = {}

        for key, value in config.items():
            # Mask sensitive values if requested
            if (mask_secrets and isinstance(value, str) and
                any(substring in key.lower() for substring in sensitive_fields)):
                display_config[key] = '********'
            else:
                display_config[key] = value

        # Output the configuration in the requested format
        if output_format == 'json':
            click.echo(json.dumps(display_config, indent=2, sort_keys=True))
        elif output_format == 'yaml':
            try:
                click.echo(yaml.dump(display_config, default_flow_style=False))
            except ImportError:
                click.echo("PyYAML is not installed. Falling back to JSON format.")
                click.echo(json.dumps(display_config, indent=2, sort_keys=True))
        else:  # Default to table format
            click.echo("\nConfiguration Status:")

            # Group configuration by categories based on key prefixes
            categories = {}
            uncategorized = {}

            # Define common prefixes to group
            prefix_categories = {
                'DATABASE': 'Database',
                'DB_': 'Database',
                'SQLALCHEMY': 'Database',
                'MAIL_': 'Email',
                'SMTP_': 'Email',
                'EMAIL_': 'Email',
                'REDIS_': 'Cache',
                'CACHE_': 'Cache',
                'SESSION_': 'Session',
                'SECURITY_': 'Security',
                'CSRF_': 'Security',
                'JWT_': 'Auth',
                'AUTH_': 'Auth',
                'OAUTH_': 'Auth',
                'DEBUG': 'Debug',
                'LOG_': 'Logging',
                'SENTRY_': 'Monitoring',
            }

            # Process each config item
            for key, value in display_config.items():
                # Determine category
                category = None
                for prefix, cat in prefix_categories.items():
                    if key.startswith(prefix) or key.upper().startswith(prefix):
                        category = cat
                        break

                if category:
                    if category not in categories:
                        categories[category] = {}
                    categories[category][key] = value
                else:
                    uncategorized[key] = value

            # Output by category
            for category_name, items in sorted(categories.items()):
                click.echo(f"\n{category_name} Configuration:")
                for key, value in sorted(items.items()):
                    click.echo(f"  {key}: {value}")

            # Output uncategorized items
            if uncategorized:
                click.echo("\nOther Configuration:")
                for key, value in sorted(uncategorized.items()):
                    click.echo(f"  {key}: {value}")

        # Verify required variables if requested
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

        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Configuration check failed")
        return EXIT_ERROR


@system_cli.command('check-integrity')
@click.option('--verbose/--quiet', default=False, help='Show detailed results')
@click.option('--update-baseline/--no-update-baseline', default=False,
              help='Update the baseline with current file hashes')
@click.option('--fast/--thorough', default=True, help='Only check critical files (fast) or all files (thorough)')
def check_integrity(verbose: bool, update_baseline: bool, fast: bool) -> int:
    """
    Check file integrity.

    Verifies the integrity of application files to detect unauthorized modifications.
    This command compares file checksums against a stored baseline to identify
    potential security issues or corruption.

    In fast mode, only critical system files are checked. In thorough mode,
    all application files are verified.

    Args:
        verbose: Whether to show detailed information about each file
        update_baseline: Whether to update the baseline with current file hashes
        fast: Check only critical files (fast) or all files (thorough)

    Examples:
        # Quick integrity check of critical files
        $ flask system check-integrity

        # Full integrity check with detailed output
        $ flask system check-integrity --thorough --verbose

        # Update the integrity baseline
        $ flask system check-integrity --update-baseline
    """
    try:
        if update_baseline:
            confirmation = "Are you sure you want to update the file integrity baseline?"
            if not confirm_action(confirmation, default=False):
                click.echo("Baseline update cancelled.")
                return EXIT_SUCCESS

            click.echo("Updating file integrity baseline...")
            try:
                # Call function to update baseline
                # This is project-specific and would need to be implemented
                from core.security import create_file_hash_baseline
                result = create_file_hash_baseline()

                if result:
                    click.echo("✅ File integrity baseline updated successfully.")
                    return EXIT_SUCCESS
                else:
                    click.echo("❌ Failed to update file integrity baseline.")
                    return EXIT_ERROR

            except Exception as e:
                handle_error(e, "Failed to update integrity baseline")
                return EXIT_ERROR

        click.echo("Checking file integrity...")
        with click.progressbar(length=1, label='Verifying files') as bar:
            # Use the fast or thorough check depending on the option
            if fast:
                result = check_critical_file_integrity()
                modified_files = []  # This would be populated from the result
            else:
                # This function would scan all files, not just critical ones
                result = check_file_integrity()
                modified_files = []  # This would be populated from the result

            bar.update(1)

        # Check the result
        if result:
            click.echo("✅ File integrity check passed. No unauthorized modifications detected.")

            # If verbose and we have detailed information, show it
            if verbose and hasattr(result, 'details'):
                click.echo("\nVerified files:")
                for file_path, status in result.details.items():
                    click.echo(f"  ✓ {file_path}")

            return EXIT_SUCCESS
        else:
            click.echo("❌ File integrity check failed. Modifications detected.")

            # Show modified files if available
            if modified_files:
                click.echo("\nModified files:")
                for file_path in modified_files:
                    click.echo(f"  ! {file_path}")

            return EXIT_ERROR

    except Exception as e:
        handle_error(e, "File integrity check failed")
        return EXIT_ERROR


@system_cli.command('services')
@click.option('--status/--no-status', default=True, help='Check service status')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table',
              help='Output format')
def check_services(status: bool, output_format: str) -> int:
    """
    Check status of system services.

    Tests connectivity to essential services that the application depends on,
    such as the database, cache server, message queue, etc. This command helps
    identify service-level issues that might affect application functionality.

    Args:
        status: Whether to check current service status
        output_format: Format for the output (table, json)

    Examples:
        # Check all services with tabular output
        $ flask system services

        # Get service status in JSON format
        $ flask system services --format json
    """
    try:
        services = {
            'Database': {
                'name': 'PostgreSQL',
                'status': 'Unknown',
                'details': {},
                'check': lambda: bool(db.session.execute('SELECT 1').scalar())
            },
            'Cache': {
                'name': 'Redis',
                'status': 'Unknown',
                'details': {},
                'check': lambda: False  # Placeholder, would use cache.ping() if available
            },
            'File Storage': {
                'name': 'Local Filesystem',
                'status': 'Unknown',
                'details': {},
                'check': lambda: os.access(os.path.join(os.getcwd(), 'uploads'), os.W_OK)
            }
        }

        # Add Redis check if available
        if hasattr(cache, 'ping'):
            services['Cache']['check'] = lambda: cache.ping()

        # Check each service
        with click.progressbar(length=len(services), label='Checking services') as bar_line:
            for service_name, service_info in services.items():
                try:
                    if status:
                        service_info['status'] = 'Up' if service_info['check']() else 'Down'
                    else:
                        service_info['status'] = 'Not Checked'

                    # Add more details for specific services
                    if service_name == 'Database' and service_info['status'] == 'Up':
                        try:
                            version = db.session.execute("SELECT version()").scalar()
                            service_info['details']['version'] = str(version)

                            # Check connection pool status
                            pool_status = db.engine.pool.status() if hasattr(db.engine.pool, 'status') else {}
                            if pool_status:
                                service_info['details']['connections'] = {
                                    'active': pool_status.get('checkedout', 0),
                                    'idle': pool_status.get('idle', 0),
                                    'total': pool_status.get('size', 0)
                                }
                        except:
                            pass

                except Exception as e:
                    service_info['status'] = 'Error'
                    service_info['details']['error'] = str(e)

                bar_line.update(1)

        # Remove the check functions before output
        for service_info in services.values():
            if 'check' in service_info:
                del service_info['check']

        # Format output
        if output_format == 'json':
            click.echo(format_output(services, 'json'))
        else:
            click.echo("\nSystem Services Status:")
            for service_name, service_info in services.items():
                status_str = service_info['status']
                if status_str == 'Up':
                    status_formatted = click.style('✅ Up', fg='green')
                elif status_str == 'Down':
                    status_formatted = click.style('❌ Down', fg='red')
                elif status_str == 'Error':
                    status_formatted = click.style('⚠️ Error', fg='yellow')
                else:
                    status_formatted = status_str

                click.echo(f"  {service_name} ({service_info['name']}): {status_formatted}")

                # Show details if any
                if service_info['details']:
                    for key, value in service_info['details'].items():
                        if key == 'error':
                            click.echo(f"    - Error: {click.style(value, fg='red')}")
                        elif isinstance(value, dict):
                            click.echo(f"    - {key.title()}:")
                            for k, v in value.items():
                                click.echo(f"      - {k.title()}: {v}")
                        else:
                            click.echo(f"    - {key.title()}: {value}")

        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Service check failed")
        return EXIT_ERROR


@system_cli.command('diagnostics')
@click.option('--output', help='Output file for diagnostic information', default=None)
@click.option('--full/--basic', help='Include full diagnostic information', default=False)
def diagnostics(output: Optional[str], full: bool) -> int:
    """
    Generate system diagnostic report.

    Collects comprehensive information about the system environment, application
    configuration, and runtime statistics. This command is useful for troubleshooting
    and support purposes.

    The diagnostic report includes system information, Python environment details,
    configuration settings, and resource usage statistics.

    Args:
        output: File to write diagnostics report to (prints to stdout if not specified)
        full: Whether to include full diagnostic information

    Examples:
        # Generate basic diagnostic report
        $ flask system diagnostics

        # Generate full diagnostic report to file
        $ flask system diagnostics --full --output=diagnostics.txt
    """
    try:
        diag_data = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'hostname': socket.gethostname(),
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': f"{psutil.virtual_memory().total / (1024 * 1024 * 1024):.2f} GB"
            },
            'application': {
                'version': getattr(current_app, 'version', 'Unknown'),
                'environment': os.environ.get('FLASK_ENV', 'Unknown')
            },
            'resources': {
                'cpu_usage': f"{psutil.cpu_percent()}%",
                'memory_usage': f"{psutil.virtual_memory().percent}%",
                'disk_usage': f"{psutil.disk_usage('/').percent}%"
            }
        }

        # Add more detailed information if requested
        if full:
            # Python package information
            try:
                import pkg_resources
                diag_data['packages'] = [
                    {'name': pkg.key, 'version': pkg.version}
                    for pkg in pkg_resources.working_set
                ]
            except ImportError:
                diag_data['packages'] = "Package information not available"

            # Environment variables (excluding sensitive ones)
            env_vars = {}
            sensitive_prefixes = ['SECRET', 'KEY', 'PASS', 'TOKEN', 'AUTH', 'CREDENTIAL']

            for key, value in os.environ.items():
                if any(sensitive in key.upper() for sensitive in sensitive_prefixes):
                    env_vars[key] = '********'
                else:
                    env_vars[key] = value

            diag_data['environment_variables'] = env_vars

            # Process information
            proc = psutil.Process()
            diag_data['process'] = {
                'pid': proc.pid,
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'memory_info': {
                    'rss': f"{proc.memory_info().rss / (1024 * 1024):.2f} MB",
                    'vms': f"{proc.memory_info().vms / (1024 * 1024):.2f} MB"
                },
                'cpu_times': dict(proc.cpu_times()._asdict()),
                'num_threads': proc.num_threads(),
                'num_fds': proc.num_fds() if hasattr(proc, 'num_fds') else 'Unknown',
                'connections': len(proc.connections())
            }

            # Disk information
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': f"{usage.total / (1024**3):.2f} GB",
                        'used': f"{usage.used / (1024**3):.2f} GB",
                        'free': f"{usage.free / (1024**3):.2f} GB",
                        'percent': f"{usage.percent}%"
                    })
                except PermissionError:
                    continue

            diag_data['disk_info'] = disk_info

        # Format the output
        formatted_output = json.dumps(diag_data, indent=2)

        # Write to file or print to console
        if output:
            with open(output, 'w') as f:
                f.write(formatted_output)
            click.echo(f"Diagnostic information written to {output}")
        else:
            click.echo(formatted_output)

        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to generate diagnostics")
        return EXIT_ERROR


# Register all commands
if __name__ == '__main__':
    system_cli()
