"""
Main application entry point for the myproject Flask application.

This module handles the application initialization, configuration loading,
and environment validation. It serves as the WSGI entry point and provides
CLI commands for administrative tasks.

The application uses a factory pattern for initialization to allow for
proper extension setup and blueprint registration. Security checks are
performed before initialization to ensure proper configuration.

Key responsibilities:
- Environment validation for security-critical variables
- Application logging setup
- Blueprint registration for routing
- API route registration and versioning
- Security monitoring and controls
- Command-line interface tools
"""

import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union, List, Callable

from flask import Flask, session, flash, redirect, url_for, request, Response, g, jsonify, current_app
import click
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException

from extensions import db, metrics
from models.security import AuditLog
from core.security.cs_audit import log_security_event
from core.factory import create_app
from core.seeder import seed_database, seed_development_data
from core.security import (
    check_critical_file_integrity,
    log_security_event,
    detect_suspicious_activity,
    require_permission
)
from api import register_api_routes

# Security constants
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
    'JWT_SECRET_KEY',
    'CSRF_SECRET_KEY',
    'SESSION_KEY'
]

# Session configuration
SESSION_TIMEOUT_MINUTES = 30
SESSION_INACTIVE_MESSAGE = 'Your session has expired. Please log in again.'
SESSION_SECURITY_MESSAGE = 'Your session has been terminated due to a security concern.'

# Exit status codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1

def validate_environment() -> None:
    """
    Validate required environment variables are set.

    This function ensures that critical security-related environment variables
    are properly set before the application starts, preventing insecure
    configurations from being deployed.

    Raises:
        RuntimeError: If any required variables are missing
    """
    missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing security variables: {', '.join(missing)}")

    # Check for secure secret keys in production
    if os.getenv('ENVIRONMENT', '').lower() == 'production':
        for key_var in ['SECRET_KEY', 'JWT_SECRET_KEY', 'CSRF_SECRET_KEY']:
            key_value = os.getenv(key_var, '')
            if key_value in ['dev', 'development', 'secret', 'changeme'] or len(key_value) < 16:
                raise RuntimeError(f"Insecure {key_var} detected in production environment")

def setup_logging(flask_app: Flask) -> None:
    """
    Configure application logging with formatting and handlers.

    Args:
        flask_app: Flask application instance
    """
    formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    flask_app.logger.handlers = [handler]
    flask_app.logger.setLevel(flask_app.config['LOG_LEVEL'])

    # Add file handler for persistent logs in production environments
    if flask_app.config.get('ENVIRONMENT', 'development') in ['production', 'staging']:
        try:
            log_dir = flask_app.config.get('LOG_DIR', 'logs')
            os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(os.path.join(log_dir, 'application.log'))
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO)
            flask_app.logger.addHandler(file_handler)

            # Separate log file for security events with higher retention
            security_log_handler = logging.FileHandler(os.path.join(log_dir, 'security.log'))
            security_log_handler.setFormatter(formatter)
            security_logger = logging.getLogger('security')
            security_logger.addHandler(security_log_handler)
            security_logger.propagate = False  # Prevent duplicate logging

            flask_app.logger.info("File logging initialized")
        except OSError as e:
            flask_app.logger.warning(f"Could not initialize file logging: {e}")

def validate_user_session() -> Optional[Response]:
    """
    Validate user session on each request.

    Checks session age, user agent consistency, and IP address changes.
    This function implements security controls to detect session hijacking
    and enforce session timeouts.

    Returns:
        Response or None: Redirect to login if session is invalid, None otherwise
    """
    # Skip validation for static resources and health checks
    if request.path.startswith(('/static/', '/health')):
        return None

    # Skip validation for API endpoints - they use token auth
    if request.path.startswith('/api/'):
        return None

    if 'user_id' not in session:
        return None

    # Check for session age
    if 'last_active' in session:
        try:
            last_active = datetime.fromisoformat(session['last_active'])
            if datetime.utcnow() - last_active > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                return _handle_session_expiration('session_timeout',
                                                f"Session timed out for user {session['user_id']}",
                                                'info',
                                                SESSION_INACTIVE_MESSAGE,
                                                'warning')
        except (ValueError, TypeError):
            # Handle invalid timestamp format
            return _handle_session_expiration('session_error',
                                            "Invalid session timestamp",
                                            'warning',
                                            SESSION_SECURITY_MESSAGE,
                                            'danger')

    # Check for IP address change
    if 'ip_address' in session and session['ip_address'] != request.remote_addr:
        return _handle_ip_change()

    # Check for user agent consistency
    if current_app.config.get('STRICT_SESSION_SECURITY', False):
        current_user_agent = request.headers.get('User-Agent', '')
        session_user_agent = session.get('user_agent', '')

        if session_user_agent and session_user_agent != current_user_agent:
            return _handle_session_expiration(
                'user_agent_changed',
                f"User agent changed during session: {session_user_agent} -> {current_user_agent}",
                'warning',
                SESSION_SECURITY_MESSAGE,
                'danger'
            )

    # Update last active time and IP
    session['last_active'] = datetime.utcnow().isoformat()
    session['ip_address'] = request.remote_addr
    if 'user_agent' not in session:
        session['user_agent'] = request.headers.get('User-Agent', '')

    return None

def _handle_session_expiration(event_type: str, description: str, severity: str,
                              message: str, flash_category: str) -> Response:
    """
    Handle session expiration or termination.

    Args:
        event_type: Type of event for security monitoring
        description: Detailed description of the event
        severity: Severity level (info, warning, error)
        message: User-facing message
        flash_category: Flash message category

    Returns:
        Response: Redirect to login page
    """
    user_id = session.get('user_id')
    username = session.get('username', 'unknown')

    log_security_event(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        ip_address=request.remote_addr,
    )

    # Track session expiration metrics
    if hasattr(metrics, 'counter'):
        try:
            metrics.counter('session.expiration_total',
                labels={
                    'reason': event_type,
                    'severity': severity
                }).inc()
        except Exception:
            pass

    # Log the session termination for audit
    try:
        log_security_event(
            event_type="session_terminated",
            description=f"Session terminated for {username}",
            severity=severity,
            user_id=user_id,
            ip_address=request.remote_addr,
            details={
                "reason": event_type,
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get('User-Agent', 'unknown')
            },
            object_type="session",
            object_id=username
        )
    except Exception as e:
        current_app.logger.error(f"Failed to log audit event: {e}")

    session.clear()
    flash(message, flash_category)
    return redirect(url_for('auth.login'))

def _handle_ip_change() -> Optional[Response]:
    """
    Handle IP address change in user session.

    This function detects and responds to IP address changes during an active session,
    which could indicate session hijacking or user network changes.

    Returns:
        Optional[Response]: Redirect response if session is terminated, None otherwise
    """
    old_ip = session['ip_address']
    new_ip = request.remote_addr

    # Log the IP change
    log_security_event(
        event_type='session_ip_change',
        description=f"IP address changed during session: {old_ip} -> {new_ip}",
        severity='warning',
        user_id=session.get('user_id'),
        ip_address=new_ip,
    )

    # Record security audit event
    log_security_event(
        event_type=AuditLog.EVENT_SESSION_ANOMALY,
        description=f"IP address changed: {old_ip} -> {new_ip}",
        user_id=session.get('user_id'),
        ip_address=new_ip,
        severity='warning'
    )

    # Track IP change metrics
    if hasattr(metrics, 'counter'):
        try:
            metrics.counter('session.ip_changes_total').inc()
        except Exception:
            pass

    # Check if IP change is suspicious
    if detect_suspicious_activity(
        'session_ip_change',
        {'old_ip': old_ip, 'new_ip': new_ip, 'user_id': session.get('user_id', 0)}
    ):
        # For critical systems or suspicious changes, invalidate the session
        return _handle_session_expiration(
            'session_terminated',
            f"Session terminated due to suspicious IP change: {old_ip} -> {new_ip}",
            'warning',
            SESSION_SECURITY_MESSAGE,
            'danger'
        )

    # For normal non-suspicious changes or non-strict mode
    if request.app.config.get('STRICT_SESSION_SECURITY', False):
        return _handle_session_expiration(
            'session_terminated',
            f"Session terminated due to IP change: {old_ip} -> {new_ip}",
            'warning',
            SESSION_SECURITY_MESSAGE,
            'danger'
        )

    return None

def register_cli_commands(app: Flask) -> None:
    """
    Register command line interface commands with the application.

    This function adds CLI commands for database management, security checks,
    and system administration tasks.

    Args:
        app: Flask application instance
    """
    @app.cli.command()
    def init_db() -> None:
        """Initialize database tables and indexes."""
        try:
            db.create_all()
            click.echo('Database initialized successfully')
        except SQLAlchemyError as e:
            app.logger.error("Database initialization failed", exc_info=e)
            click.echo(f'Database initialization failed: {e}', err=True)
            sys.exit(1)

    @app.cli.command()
    @click.option('--dev-data/--no-dev-data', default=False,
                help='Seed development data for testing')
    @click.option('--force/--no-force', default=False,
                help='Force seeding even if data exists')
    def seed_db(dev_data: bool, force: bool) -> None:
        """Seed the database with initial data."""
        try:
            success = seed_database(force=force)
            if success:
                click.echo('Database seeded successfully')
            else:
                click.echo('Database already seeded or seeding failed')

            if dev_data and app.config.get('ENVIRONMENT') == 'development':
                dev_success = seed_development_data(force=force)
                if dev_success:
                    click.echo('Development data seeded successfully')
                else:
                    click.echo('Development data seeding skipped or failed')

            # Track seeding operation in metrics
            if hasattr(metrics, 'counter'):
                metrics.counter('db.seed_operations_total', labels={
                    'dev_data': str(dev_data).lower(),
                    'success': str(success).lower()
                }).inc()

        except (RuntimeError, ValueError, KeyError) as e:
            app.logger.error("Database seeding failed", exc_info=e)
            click.echo(f'Database seeding failed: {e}', err=True)
            sys.exit(1)

    @app.cli.command()
    @click.option('--update-baseline/--no-update-baseline', default=False,
                help='Update baseline hashes if differences found')
    def verify_integrity(update_baseline: bool) -> None:
        """
        Verify the integrity of critical application files.

        This checks for unauthorized changes to security-critical files.
        """
        try:
            integrity_result, changes = check_critical_file_integrity(app, full_output=True)

            if not integrity_result:
                click.echo('WARNING: Critical file integrity check failed')

                for idx, change in enumerate(changes, 1):
                    click.echo(f"{idx}. {change.get('path')} - {change.get('status')} (Severity: {change.get('severity', 'unknown')})")

                if update_baseline and app.config.get('ENVIRONMENT') != 'production':
                    # Only allow baseline updates in non-production environments
                    click.echo('\nUpdating integrity baseline with current file state...')

                    # Import and use baseline update function
                    from core.security.cs_file_integrity import update_file_integrity_baseline
                    baseline_path = app.config.get('FILE_BASELINE_PATH')
                    update_file_integrity_baseline(app, baseline_path, changes)

                    click.echo('Baseline updated successfully.')
                else:
                    sys.exit(1)
            else:
                click.echo('All critical files verified. Integrity check passed.')
        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            app.logger.error("File integrity check failed", exc_info=e)
            click.echo(f'File integrity check failed: {e}', err=True)
            sys.exit(1)

    @app.cli.group('baseline')
    def baseline_cli():
        """File integrity baseline management commands."""
        pass

    @baseline_cli.command('update')
    @click.option('--path', help='Path to the baseline file to update (uses configured path if not specified)')
    @click.option('--force/--no-force', default=False,
                help='Update baseline even for critical files')
    @click.option('--include', '-i', multiple=True,
                help='Patterns to include (e.g., "*.py", "config/*.yaml")')
    @click.option('--exclude', '-e', multiple=True,
                help='Patterns to exclude (e.g., "*.pyc", "tmp/*")')
    @click.option('--backup/--no-backup', default=True,
                help='Create backup of existing baseline')
    @click.option('--reason', help='Reason for updating the baseline (for audit logs)')
    def update_baseline(path: Optional[str], force: bool, include: tuple,
                       exclude: tuple, backup: bool, reason: Optional[str]) -> None:
        """
        Update file integrity baseline with current file states.

        This command creates or updates the file integrity baseline with the current
        state of files in the application, optionally filtering by include/exclude patterns.
        By default, a backup of the existing baseline is created for safety.
        """
        try:
            from core.seeder import update_integrity_baseline

            click.echo(f"Updating file integrity baseline{' (FORCE mode)' if force else ''}...")

            # Convert tuples to lists
            include_patterns = list(include) if include else None
            exclude_patterns = list(exclude) if exclude else None

            # Call implementation from core module
            result = update_integrity_baseline(
                baseline_path=path,
                force=force,
                include_pattern=include_patterns,
                exclude_pattern=exclude_patterns,
                backup=backup,
                verbose=True
            )

            if result.get('success', False):
                stats = result.get('stats', {})
                click.echo(click.style("✓ Baseline updated successfully", fg='green'))
                click.echo(f"  - Files added:     {stats.get('added', 0)}")
                click.echo(f"  - Files updated:   {stats.get('updated', 0)}")
                click.echo(f"  - Files unchanged: {stats.get('unchanged', 0)}")
                click.echo(f"  - Files skipped:   {stats.get('skipped', 0)}")
                click.echo(f"  - Errors:          {stats.get('error', 0)}")
                click.echo(f"  - Total files:     {result.get('total_files', 0)}")
                click.echo(f"  - Baseline path:   {result.get('baseline_path')}")

                # Log to audit trail
                try:
                    log_security_event(
                        event_type="baseline_manual_update",
                        description=f"Manual baseline update via CLI",
                        severity="info",
                        details={
                            'added': stats.get('added', 0),
                            'updated': stats.get('updated', 0),
                            'unchanged': stats.get('unchanged', 0),
                            'skipped': stats.get('skipped', 0),
                            'reason': reason or 'CLI manual update',
                            'include_patterns': include_patterns,
                            'exclude_patterns': exclude_patterns,
                            'force_mode': force
                        }
                    )
                except Exception as e:
                    click.echo(f"Warning: Failed to log audit event: {e}", err=True)
            else:
                click.echo(click.style(f"✗ Baseline update failed: {result.get('error', 'Unknown error')}", fg='red'))
                sys.exit(1)

        except ImportError as e:
            click.echo(f"Error: Required module not available - {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @baseline_cli.command('verify')
    @click.option('--path', help='Path to the baseline file to verify against')
    @click.option('--report-only/--update', default=True,
                help='Only report issues, do not update baseline')
    @click.option('--verbose', '-v', count=True,
                help='Verbose output (use multiple times for more detail)')
    @click.option('--exit-code/--no-exit-code', default=True,
                help='Return non-zero exit code if integrity violations found')
    def verify_baseline(path: Optional[str], report_only: bool, verbose: int, exit_code: bool) -> None:
        """
        Verify file integrity against baseline.

        Compares current file states with the stored baseline to detect unauthorized
        modifications, permission changes, or missing files. Results are organized
        by severity to highlight the most critical issues.
        """
        try:
            from core import verify_baseline_integrity

            # Get result with detailed info
            result = verify_baseline_integrity(
                app,
                baseline_path=path,
                verbose=verbose > 0
            )

            if not result.get('success', False):
                click.echo(click.style(f"✗ Verification failed: {result.get('error', 'Unknown error')}", fg='red'))
                return EXIT_ERROR

            changes = result.get('changes', [])
            if not changes:
                click.echo(click.style("✓ All files passed integrity check", fg='green'))
                click.echo(f"  - Files checked: {result.get('files_checked', 0)}")
                return EXIT_SUCCESS
            else:
                click.echo(click.style(f"✗ {len(changes)} integrity violations found!", fg='yellow'))

                # Group changes by severity
                by_severity = {}
                for change in changes:
                    severity = change.get('severity', 'unknown')
                    by_severity.setdefault(severity, []).append(change)

                # Display counts by severity
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in by_severity:
                        color = 'red' if severity == 'critical' else 'yellow'
                        click.echo(click.style(
                            f"  - {severity.upper()}: {len(by_severity[severity])} issues",
                            fg=color
                        ))

                # Display critical and high severity issues
                for severity in ['critical', 'high']:
                    if severity in by_severity:
                        click.echo(f"\n{severity.upper()} SEVERITY ISSUES:")
                        for change in by_severity[severity]:
                            status = change.get('status', 'unknown')
                            path = change.get('path', 'unknown')
                            click.echo(click.style(f"  • {status}: {path}", fg='red'))

                # Suggest automatic update if not in report-only mode and automatic updates allowed
                if not report_only and app.config.get('ENVIRONMENT', '') != 'production':
                    if click.confirm("Would you like to update the baseline with these changes?", default=False):
                        from core.security.cs_file_integrity import update_file_integrity_baseline

                        # Update baseline excluding critical changes
                        non_critical = [c for c in changes if c.get('severity', '') != 'critical']

                        if non_critical:
                            baseline_path = path or app.config.get('FILE_BASELINE_PATH')
                            success = update_file_integrity_baseline(app, baseline_path, non_critical)
                            if success:
                                click.echo(click.style(
                                    f"✓ Baseline updated with {len(non_critical)} non-critical changes",
                                    fg='green'
                                ))
                            else:
                                click.echo(click.style("✗ Baseline update failed", fg='red'))
                        else:
                            click.echo("No non-critical changes to apply.")

                # Return appropriate exit code based on configuration
                if exit_code:
                    sys.exit(1)
                return 1

        except ImportError as e:
            click.echo(f"Error: Required module not available - {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @baseline_cli.command('analyze')
    @click.option('--path', help='Path to directory to analyze')
    @click.option('--pattern', '-p', multiple=True, help='File patterns to include')
    @click.option('--limit', type=int, default=100, help='Limit number of files to analyze')
    def analyze_baseline(path: Optional[str], pattern: tuple, limit: int) -> None:
        """
        Analyze files for potential integrity risks.

        Scans files in the specified directory (or application root if not provided)
        to identify potential integrity risks such as:
        - Files with suspicious permissions
        - Recently modified files
        - Unexpected executable files
        - Files with suspicious patterns

        This is useful for proactive security monitoring and forensic analysis.
        """
        try:
            from core.security.cs_file_integrity import analyze_files_for_integrity_risks

            patterns = list(pattern) if pattern else None

            click.echo("Analyzing files for integrity risks...")

            result = analyze_files_for_integrity_risks(
                app,
                directory=path,
                patterns=patterns,
                limit=limit
            )

            if not result.get('success', False):
                click.echo(click.style(f"✗ Analysis failed: {result.get('error', 'Unknown error')}", fg='red'))
                sys.exit(1)

            findings = result.get('findings', {})

            # Display results by category
            click.echo("\nAnalysis Results:")

            if findings.get('suspicious_permissions', []):
                files = findings.get('suspicious_permissions', [])
                click.echo(click.style(f"\nFiles with suspicious permissions: {len(files)}", fg='yellow'))
                for file_info in files[:10]:
                    filename = file_info.get('path', 'unknown')
                    permission = file_info.get('permission', 'unknown')
                    click.echo(f"  • {filename} - {permission}")
                if len(files) > 10:
                    click.echo(f"  ... and {len(files) - 10} more files")

            if findings.get('recently_modified', []):
                files = findings.get('recently_modified', [])
                click.echo(click.style(f"\nRecently modified files: {len(files)}", fg='blue'))
                for file_info in files[:10]:
                    filename = file_info.get('path', 'unknown')
                    modified = file_info.get('modified_time', 'unknown')
                    click.echo(f"  • {filename} - {modified}")
                if len(files) > 10:
                    click.echo(f"  ... and {len(files) - 10} more files")

            if findings.get('unexpected_executables', []):
                files = findings.get('unexpected_executables', [])
                click.echo(click.style(f"\nUnexpected executable files: {len(files)}", fg='yellow'))
                for file_path in files[:10]:
                    click.echo(f"  • {file_path}")
                if len(files) > 10:
                    click.echo(f"  ... and {len(files) - 10} more files")

            if findings.get('suspicious_content', []):
                files = findings.get('suspicious_content', [])
                click.echo(click.style(f"\nFiles with suspicious content: {len(files)}", fg='red'))
                for file_info in files:
                    filename = file_info.get('path', 'unknown')
                    reason = file_info.get('reason', 'unknown')
                    click.echo(f"  • {filename} - {reason}")

            total_issues = sum(len(findings.get(category, []))
                              for category in ['suspicious_permissions', 'recently_modified',
                                             'unexpected_executables', 'suspicious_content'])

            if total_issues == 0:
                click.echo(click.style("\nNo integrity risks detected.", fg='green'))
            else:
                click.echo(click.style(f"\nTotal potential integrity risks found: {total_issues}", fg='yellow'))

                # Provide recommendations
                click.echo("\nRecommendations:")
                if findings.get('suspicious_permissions', []):
                    click.echo("  • Review and fix file permissions for suspicious files")
                    click.echo("    Run: chmod 640 [file] to set secure permissions")
                if findings.get('recently_modified', []):
                    click.echo("  • Verify that recent file changes were authorized")
                    click.echo("    Run: flask baseline verify to check against baseline")
                if findings.get('unexpected_executables', []):
                    click.echo("  • Investigate unexpected executable files")
                if findings.get('suspicious_content', []):
                    click.echo("  • Examine files with suspicious content immediately")
                    click.echo("    Consider: isolating these files for further analysis")

        except ImportError as e:
            click.echo(f"Error: Required module not available - {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @baseline_cli.command('backup')
    @click.option('--path', help='Path to the baseline file to backup')
    @click.option('--output', help='Output directory for backups')
    @click.option('--comment', help='Comment to include with backup')
    def backup_baseline(path: Optional[str], output: Optional[str], comment: Optional[str]) -> None:
        """
        Create a backup of the current file integrity baseline.

        This command creates a timestamped backup of the current baseline file,
        which is useful before making significant system changes.
        """
        try:
            from core.security.cs_file_integrity import backup_baseline_file

            result = backup_baseline_file(
                app,
                baseline_path=path,
                backup_dir=output,
                comment=comment
            )

            if result.get('success', False):
                backup_path = result.get('backup_path', 'unknown')
                click.echo(click.style("✓ Baseline backup created successfully", fg='green'))
                click.echo(f"  - Backup saved to: {backup_path}")
                if comment:
                    click.echo(f"  - Comment: {comment}")
            else:
                click.echo(click.style(f"✗ Backup failed: {result.get('error', 'Unknown error')}", fg='red'))
                sys.exit(1)

        except ImportError as e:
            click.echo(f"Error: Required module not available - {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @baseline_cli.command('compare')
    @click.argument('baseline1')
    @click.argument('baseline2')
    @click.option('--format', type=click.Choice(['text', 'json']), default='text',
                 help='Output format')
    @click.option('--output', help='Output file (stdout if not specified)')
    def compare_baselines(baseline1: str, baseline2: str, format: str, output: Optional[str]) -> None:
        """
        Compare two baseline files to identify differences.

        This command is useful for reviewing changes between baseline versions
        or comparing baselines between environments.

        Examples:
            flask baseline compare baseline.json baseline.backup.json
            flask baseline compare prod_baseline.json staging_baseline.json --format json --output diff.json
        """
        try:
            from core.security.cs_file_integrity import compare_baseline_files
            import json
            import sys

            result = compare_baseline_files(
                baseline1_path=baseline1,
                baseline2_path=baseline2
            )

            if not result.get('success', False):
                click.echo(click.style(f"✗ Comparison failed: {result.get('error', 'Unknown error')}", fg='red'))
                sys.exit(1)

            differences = result.get('differences', {})
            added = differences.get('added', [])
            removed = differences.get('removed', [])
            changed = differences.get('changed', [])

            # Prepare output
            if format == 'json':
                output_content = json.dumps({
                    'summary': {
                        'added': len(added),
                        'removed': len(removed),
                        'changed': len(changed),
                        'total_differences': len(added) + len(removed) + len(changed)
                    },
                    'differences': differences,
                    'baseline1': baseline1,
                    'baseline2': baseline2,
                    'timestamp': datetime.now().isoformat()
                }, indent=2)
            else:
                # Text format
                output_content = f"Baseline Comparison\n"
                output_content += f"==================\n"
                output_content += f"Baseline 1: {baseline1}\n"
                output_content += f"Baseline 2: {baseline2}\n"
                output_content += f"Time: {datetime.now()}\n\n"
                output_content += f"Summary:\n"
                output_content += f"  - Added:   {len(added)} files\n"
                output_content += f"  - Removed: {len(removed)} files\n"
                output_content += f"  - Changed: {len(changed)} files\n"
                output_content += f"  - Total differences: {len(added) + len(removed) + len(changed)} files\n\n"

                if added:
                    output_content += f"Added Files:\n"
                    for file_path in sorted(added):
                        output_content += f"  + {file_path}\n"
                    output_content += "\n"

                if removed:
                    output_content += f"Removed Files:\n"
                    for file_path in sorted(removed):
                        output_content += f"  - {file_path}\n"
                    output_content += "\n"

                if changed:
                    output_content += f"Changed Files:\n"
                    for file_path in sorted(changed):
                        output_content += f"  * {file_path}\n"
                    output_content += "\n"

            # Write output
            if output:
                with open(output, 'w') as f:
                    f.write(output_content)
                click.echo(f"Comparison written to {output}")
            else:
                click.echo(output_content)

            # Return non-zero exit code if differences found
            if added or removed or changed:
                sys.exit(1)

        except ImportError as e:
            click.echo(f"Error: Required module not available - {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @app.cli.command()
    @click.option('--fix/--no-fix', default=False,
                help='Attempt to automatically fix detected issues')
    @click.option('--detailed/--summary', default=False,
                help='Show detailed scan results')
    def security_scan(fix: bool, detailed: bool) -> None:
        """Run a comprehensive security scan."""
        try:
            from blueprints.monitoring.routes import (
                detect_login_anomalies,
                detect_database_anomalies,
                detect_session_anomalies,
                detect_file_access_anomalies,
                detect_api_anomalies,
                detect_configuration_issues
            )

            click.echo("Starting security scan...")

            # Record scan start time
            start_time = time.time()

            with app.app_context():
                # Run various security detection functions
                scan_results = _run_security_scans(
                    detect_login_anomalies,
                    detect_database_anomalies,
                    detect_session_anomalies,
                    detect_file_access_anomalies,
                    detect_api_anomalies,
                    detect_configuration_issues
                )

                # Check for issues in each category
                issues, issue_details = _analyze_security_scan_results(scan_results, detailed)

                # Calculate scan duration
                duration = time.time() - start_time

                # Show scan summary
                click.echo(f"Security scan completed in {duration:.2f} seconds.")

                if issues:
                    click.echo(f"\nIssues found: {len(issues)}")
                    for i, issue in enumerate(issues, 1):
                        click.echo(f"  {i}. {issue}")

                    if detailed and issue_details:
                        click.echo("\nDetailed findings:")
                        for category, details in issue_details.items():
                            click.echo(f"\n{category.upper()}:")
                            for detail in details:
                                click.echo(f"  - {detail}")

                    # Attempt automated fixes if requested
                    if fix:
                        click.echo("\nAttempting to fix issues...")
                        fixed_count = _apply_security_fixes(scan_results, app)
                        click.echo(f"Successfully applied {fixed_count} fixes.")

                    sys.exit(1)
                else:
                    click.echo("No security issues found.")

                # Log scan completion to audit log
                try:
                    log_security_event(
                        event_type="security_scan",
                        description="Security scan completed",
                        severity="info",
                        user_id=0,  # System user
                        details={
                            "duration_seconds": duration,
                            "issues_found": len(issues) if issues else 0,
                            "scan_mode": "detailed" if detailed else "summary",
                            "auto_fix": fix
                        },
                        object_type="security",
                        object_id="application"
                    )
                except Exception as e:
                    app.logger.error(f"Failed to log security scan completion: {e}")

        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            app.logger.error("Security scan failed", exc_info=e)
            click.echo(f"Security scan failed: {e}", err=True)
            sys.exit(1)

    @app.cli.command()
    @click.option('--port', default=5000, help='Port to listen on')
    @click.option('--host', default='127.0.0.1', help='Host to bind to')
    @click.option('--debug/--no-debug', default=None, help='Enable debug mode')
    def run_server(port: int, host: str, debug: Optional[bool] = None) -> None:
        """Run the development server with security checks."""
        # Check if we're in production but using the dev server
        if app.config.get('ENVIRONMENT') == 'production' and not debug:
            click.echo("WARNING: Running development server in production environment!", err=True)
            click.echo("This is NOT recommended for production use.", err=True)
            if not click.confirm("Continue anyway?", default=False):
                click.echo("Aborted.")
                return

        # Run integrity check before starting server
        try:
            integrity_result, _ = check_critical_file_integrity(app)
            if not integrity_result:
                click.echo("WARNING: File integrity check failed. Server may be compromised.", err=True)
                if not click.confirm("Continue anyway?", default=False):
                    click.echo("Aborted.")
                    return
        except Exception as e:
            click.echo(f"WARNING: Could not verify file integrity: {e}", err=True)

        # Determine debug mode
        debug_mode = debug if debug is not None else app.config.get('DEBUG', False)

        # Run the server
        click.echo(f"Starting server on {host}:{port} (debug: {debug_mode})")
        app.run(host=host, port=port, debug=debug_mode)

    @app.cli.command('check-api')
    @click.argument('endpoint', required=False)
    def check_api(endpoint: Optional[str] = None):
        """Check API endpoints and their status."""
        from werkzeug.routing import Rule

        api_routes = []
        other_routes = []

        # Group routes
        for rule in app.url_map.iter_rules():
            if str(rule).startswith('/api/'):
                api_routes.append(rule)
            else:
                other_routes.append(rule)

        if endpoint:
            # Filter to specific endpoint if provided
            api_routes = [r for r in api_routes if endpoint.lower() in str(r).lower()]
            if not api_routes:
                click.echo(f"No API endpoints matching '{endpoint}' found.")
                return

        # Display API routes
        click.echo(f"Found {len(api_routes)} API endpoints:")
        click.echo("\nAPI ENDPOINTS:")
        click.echo("=" * 80)
        click.echo(f"{'Endpoint':<50} {'Methods':<20} {'Authentication'}")
        click.echo("-" * 80)

        for rule in sorted(api_routes, key=lambda x: str(x)):
            # Determine if the endpoint requires authentication
            auth_required = "Required"
            if any(m in ['OPTIONS', 'HEAD'] for m in rule.methods):
                auth_required = "Optional"
            if str(rule).startswith('/api/health') or str(rule).startswith('/api/metrics'):
                auth_required = "Optional"

            methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
            click.echo(f"{str(rule):<50} {methods:<20} {auth_required}")

        click.echo("\n")

def _run_security_scans(*detection_functions) -> Dict[str, Any]:
    """
    Run multiple security detection functions and collect results.

    Args:
        *detection_functions: Variable number of security detection functions

    Returns:
        Dict[str, Any]: Results from each detection function
    """
    results = {}
    for func in detection_functions:
        try:
            results[func.__name__] = func()
        except Exception as e:
            current_app.logger.error(f"Error in {func.__name__}: {e}", exc_info=True)
            results[func.__name__] = {"error": str(e), "status": "failed"}
    return results

def _analyze_security_scan_results(scan_results: Dict[str, Dict[str, Any]],
                                  detailed: bool = False) -> tuple[List[str], Dict[str, List[str]]]:
    """
    Analyze security scan results and return list of issues.

    Args:
        scan_results: Dictionary of scan results from different detection functions
        detailed: Whether to include detailed findings

    Returns:
        tuple[List[str], Dict[str, List[str]]]: Summary issues and detailed findings
    """
    issues = []
    issue_details = {} if detailed else {}

    # Check login anomalies
    login_anomalies = scan_results.get('detect_login_anomalies', {})
    if login_anomalies.get('suspicious_ips'):
        issues.append(f"Found {len(login_anomalies['suspicious_ips'])} suspicious IPs")
        if detailed:
            issue_details['login_anomalies'] = [
                f"Suspicious IP: {ip} ({details.get('count', 0)} attempts)"
                for ip, details in login_anomalies['suspicious_ips'].items()
            ]

    if login_anomalies.get('brute_force_attempts'):
        issues.append(f"Found {len(login_anomalies['brute_force_attempts'])} potential brute force attacks")
        if detailed and 'brute_force_attempts' in login_anomalies:
            issue_details.setdefault('login_anomalies', []).extend([
                f"Brute force on user: {username} from {ip}"
                for username, ip in login_anomalies['brute_force_attempts']
            ])

    # Check database anomalies
    db_anomalies = scan_results.get('detect_database_anomalies', {})
    if db_anomalies.get('sensitive_tables'):
        issues.append(f"Found {len(db_anomalies['sensitive_tables'])} sensitive table access events")
        if detailed:
            issue_details['database_anomalies'] = [
                f"Sensitive table access: {table} by {user}"
                for table, user in db_anomalies['sensitive_tables']
            ]

    if db_anomalies.get('injection_attempts'):
        issues.append(f"Found {len(db_anomalies['injection_attempts'])} potential SQL injection attempts")
        if detailed:
            issue_details.setdefault('database_anomalies', []).extend([
                f"Injection attempt: {details}"
                for details in db_anomalies['injection_attempts']
            ])

    # Check session anomalies
    session_anomalies = scan_results.get('detect_session_anomalies', {})
    if session_anomalies.get('ip_changes'):
        issues.append(f"Found {len(session_anomalies['ip_changes'])} session IP changes")
        if detailed:
            issue_details['session_anomalies'] = [
                f"Session IP change: User {user_id} from {old_ip} to {new_ip}"
                for user_id, old_ip, new_ip in session_anomalies['ip_changes']
            ]

    # Check file access anomalies
    file_access_anomalies = scan_results.get('detect_file_access_anomalies', {})
    if file_access_anomalies.get('sensitive_files'):
        issues.append(f"Found {len(file_access_anomalies['sensitive_files'])} sensitive file access events")
        if detailed:
            issue_details['file_access_anomalies'] = [
                f"Sensitive file access: {filepath} by {user}"
                for filepath, user in file_access_anomalies['sensitive_files']
            ]

    # Check API anomalies
    api_anomalies = scan_results.get('detect_api_anomalies', {})
    if api_anomalies.get('error_rates'):
        high_error_endpoints = api_anomalies.get('error_rates', [])
        if high_error_endpoints:
            issues.append(f"Found {len(high_error_endpoints)} API endpoints with high error rates")
            if detailed:
                issue_details['api_anomalies'] = [
                    f"API error rate: {endpoint} ({error_rate}%)"
                    for endpoint, error_rate in high_error_endpoints
                ]

    # Check configuration issues
    config_issues = scan_results.get('detect_configuration_issues', {})
    if config_issues.get('insecure_settings'):
        insecure_settings = config_issues.get('insecure_settings', [])
        if insecure_settings:
            issues.append(f"Found {len(insecure_settings)} insecure configuration settings")
            if detailed:
                issue_details['configuration_issues'] = [
                    f"Insecure setting: {setting}"
                    for setting in insecure_settings
                ]

    return issues, issue_details

def _apply_security_fixes(scan_results: Dict[str, Dict[str, Any]], app: Flask) -> int:
    """
    Apply automatic fixes for detected security issues.

    Args:
        scan_results: Dictionary of scan results
        app: Flask application instance

    Returns:
        int: Number of successfully applied fixes
    """
    fixes_applied = 0

    # Block suspicious IPs
    login_anomalies = scan_results.get('detect_login_anomalies', {})
    suspicious_ips = login_anomalies.get('suspicious_ips', {})

    if suspicious_ips:
        try:
            from core.security.cs_firewall import block_suspicious_ips
            blocked = block_suspicious_ips([ip for ip in suspicious_ips.keys()])
            fixes_applied += blocked
            app.logger.info(f"Blocked {blocked} suspicious IPs")
        except ImportError:
            app.logger.warning("Could not import IP blocking module")

    # Lock accounts with brute force attempts
    brute_force_attempts = login_anomalies.get('brute_force_attempts', [])
    if brute_force_attempts:
        try:
            from models.auth.user import User
            usernames = set(username for username, _ in brute_force_attempts)

            # Lock the accounts
            for username in usernames:
                user = User.query.filter_by(username=username).first()
                if user:
                    user.lock_account("Automatic lock due to security scan detection")
                    app.logger.warning(f"Locked account {username} due to brute force attempts")
                    fixes_applied += 1
        except ImportError:
            app.logger.warning("Could not import User model for locking accounts")

    # Fix insecure configuration settings where possible
    config_issues = scan_results.get('detect_configuration_issues', {})
    insecure_settings = config_issues.get('insecure_settings', [])

    if insecure_settings and app.config.get('ENVIRONMENT') != 'production':
        # Only auto-fix in non-production environments
        fixes_applied += _fix_insecure_settings(app, insecure_settings)

    return fixes_applied

def _fix_insecure_settings(app: Flask, issues: List[str]) -> int:
    """
    Fix insecure settings that can be automatically remedied.

    Args:
        app: Flask application instance
        issues: List of insecure settings

    Returns:
        int: Number of fixed settings
    """
    fixes = 0

    # Map of insecure settings to their recommended secure values
    secure_values = {
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'REMEMBER_COOKIE_SECURE': True,
        'REMEMBER_COOKIE_HTTPONLY': True,
        'SECURITY_HEADERS_ENABLED': True,
        'WTF_CSRF_ENABLED': True,
    }

    for issue in issues:
        # Extract the setting name from the issue description
        for setting in secure_values.keys():
            if setting in issue:
                app.config[setting] = secure_values[setting]
                app.logger.info(f"Fixed insecure setting: {setting}")
                fixes += 1
                break

    return fixes

def setup_request_context(app: Flask) -> None:
    """
    Set up request context processing.

    This function configures request preprocessing and postprocessing for
    tracking, security, and monitoring purposes.

    Args:
        app: Flask application instance
    """
    @app.before_request
    def init_request_context():
        """Initialize request context data."""
        # Set request start time for performance tracking
        g.start_time = time.time()

        # Generate request ID for tracking
        g.request_id = request.headers.get('X-Request-ID',
                                          f"req-{os.urandom(8).hex()}")

        # Set the request ID in the logger's context
        logging.LoggerAdapter(app.logger, {'request_id': g.request_id})

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        # Only add security headers if enabled in config
        if app.config.get('SECURITY_HEADERS_ENABLED', True):
            # Set strict Content Security Policy for non-API routes
            if not request.path.startswith('/api/'):
                response.headers['Content-Security-Policy'] = app.config.get(
                    'CONTENT_SECURITY_POLICY',
                    "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'"
                ).format(nonce=getattr(g, 'csp_nonce', ''))

            # Set basic security headers for all responses
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'

            # Add Strict-Transport-Security header for HTTPS
            if app.config.get('ENVIRONMENT') in ('production', 'staging'):
                response.headers['Strict-Transport-Security'] = app.config.get(
                    'SECURITY_HSTS_MAX_AGE', 'max-age=31536000; includeSubDomains; preload'
                )

        # Add request ID header for tracking
        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
        return response

    @app.teardown_request
    def teardown_request_context(exception=None):
        """
        Clean up resources and log request completion.

        Args:
            exception: Exception that occurred during request handling, if any
        """
        if hasattr(g, 'start_time'):
            # Calculate request duration
            duration = time.time() - g.start_time

            # Log slow requests
            if duration > app.config.get('SLOW_REQUEST_THRESHOLD', 1.0):
                app.logger.warning(
                    f"Slow request: {request.method} {request.path} ({duration:.3f}s)",
                    extra={
                        'duration': duration,
                        'method': request.method,
                        'path': request.path,
                        'endpoint': request.endpoint
                    }
                )

            # Track request latency metrics
            if hasattr(metrics, 'histogram'):
                try:
                    metrics.histogram('http_request_duration_seconds').observe(
                        duration,
                        labels={
                            'method': request.method,
                            'endpoint': str(request.endpoint),
                            'status': getattr(g, 'response_status', 200)
                        }
                    )
                except Exception:
                    pass

# Initialize application
try:
    # Validate critical environment variables
    validate_environment()

    # Create the Flask application
    app = create_app()

    # Set up request context handling
    setup_request_context(app)

    # Register request handlers for session validation
    @app.before_request
    def validate_session():
        return validate_user_session()

    # Register routing for API endpoints
    register_api_routes(app)

    # Register CLI commands
    register_cli_commands(app)

    # Log successful initialization
    app.logger.info(f"Application initialized successfully (version: {app.config.get('VERSION', '1.0.0')})")

except SQLAlchemyError as e:
    logging.critical("Application initialization failed: %s", e)
    raise
except Exception as e:
    logging.critical("Application initialization failed: %s", e)
    raise

if __name__ == '__main__':
    app.run()
