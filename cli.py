"""
Command-line interface module for the Cloud Infrastructure Platform.

This module serves as the primary entry point for all CLI commands, providing a unified
interface for managing various aspects of the platform. It leverages Flask's CLI integration
with Click and delegates to specialized command modules in the cli package.

Key Features:
- Server management with customizable host and port settings
- Database initialization, migration, and maintenance
- Configuration management across different environments
- Security operations including file integrity monitoring
- User and permission administration
- Deployment automation for multiple cloud providers
- System health checks and monitoring capabilities

The CLI interface is accessible through the 'flask' command when the application
is installed, or directly through this module when executed as a script.
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

import click
from flask.cli import FlaskGroup, ScriptInfo

# Add project root to path to ensure imports work correctly
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app
from cli import register_cli_commands
from core.utils.logging_utils import setup_cli_logging

# Set up CLI-specific logging
setup_cli_logging()
logger = logging.getLogger(__name__)

# Exit status codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2
EXIT_PERMISSION_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_RESOURCE_ERROR = 5


def create_cli_app(info: ScriptInfo):
    """
    Create the Flask application with CLI-specific configuration.

    Args:
        info: Flask script info object

    Returns:
        Configured Flask application instance
    """
    # Get environment from CLI args or environment variable
    env = os.environ.get('FLASK_ENV', 'development')

    # Create app with CLI-optimized settings
    app = create_app(env)

    # Register CLI command groups
    register_cli_commands(app)

    return app


# Create CLI with application factory
cli = FlaskGroup(create_app=create_cli_app)


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug/--no-debug', default=False, help='Enable debug mode')
def run(host: str, port: int, debug: bool) -> int:
    """
    Run the application server.

    Starts the Flask development server with the specified host, port, and debug settings.
    This command is intended for development and testing purposes and should not be
    used for production deployments.

    Args:
        host: The hostname or IP address to bind the server to
        port: The port number to listen on
        debug: Whether to run the server in debug mode

    Example:
        $ flask run --host=0.0.0.0 --port=8000 --debug
    """
    try:
        app = create_app()

        # Log startup information
        logger.info(f"Starting development server at {host}:{port}")
        if debug:
            logger.info("Debug mode enabled")

        # Run the application
        app.run(host=host, port=port, debug=debug)
        return EXIT_SUCCESS

    except Exception as e:
        logger.error(f"Server startup failed: {e}", exc_info=debug)
        click.echo(f"Error: {e}", err=True)
        return EXIT_ERROR


@cli.command()
@click.option('--check-files/--no-check-files', default=True,
              help='Check file integrity during health check')
@click.option('--check-config/--no-check-config', default=True,
              help='Validate configuration settings')
@click.option('--verbose/--quiet', default=False, help='Show detailed status')
def check(check_files: bool, check_config: bool, verbose: bool) -> int:
    """
    Check application health.

    Performs a comprehensive health check of the application, verifying:
    - Database connectivity
    - Required environment variables
    - Configuration settings
    - File integrity (if enabled)
    - Service dependencies

    This command is useful for validating deployments and troubleshooting
    configuration issues.

    Example:
        $ flask check --verbose
    """
    try:
        app = create_app()

        with app.app_context():
            from cli.app.commands.system import system_health

            # Delegate to the dedicated health check command
            result = system_health(
                detailed=verbose,
                check_files=check_files,
                exit_code=True
            )
            return result

    except (ImportError, RuntimeError) as e:
        # Fall back to basic health check if command module not available
        logger.error(f"Failed to load health check module: {e}", exc_info=verbose)
        click.echo("Falling back to basic health check...")

        try:
            app = create_app()
            with app.app_context():
                from extensions import db

                # Basic database check
                db.session.execute('SELECT 1')
                click.echo('Database: OK')

                # Basic environment check
                required_vars = ['SECRET_KEY', 'DATABASE_URL']
                missing = [var for var in required_vars if not os.getenv(var)]
                if missing:
                    click.echo(f"Missing environment variables: {', '.join(missing)}", err=True)
                    return EXIT_VALIDATION_ERROR
                click.echo('Environment: OK')

                # Report success
                click.echo('Basic health check passed.')
                return EXIT_SUCCESS

        except Exception as e:
            click.echo(f'Health check failed: {e}', err=True)
            return EXIT_ERROR


# File integrity baseline management commands
@cli.group()
def integrity():
    """
    File integrity baseline management commands.

    These commands allow you to create, update, and verify file integrity
    baselines used for security monitoring and compliance.
    """
    pass


@integrity.command('verify')
@click.option('--baseline', help='Path to the baseline file to verify against')
@click.option('--report-only/--update', default=True,
              help='Only report issues, do not update baseline')
@click.option('--verbose', '-v', count=True,
              help='Verbose output (use multiple times for more detail)')
@click.option('--exit-code/--no-exit-code', default=True,
              help='Return non-zero exit code if integrity violations found')
def verify_integrity(baseline: Optional[str], report_only: bool, verbose: int, exit_code: bool) -> int:
    """
    Verify file integrity against baseline.

    Compares current file states with the stored baseline to detect unauthorized
    modifications, permission changes, or missing files. Results are organized
    by severity to highlight the most critical issues.

    Examples:
        # Basic verification
        $ flask integrity verify

        # Verbose output with detailed findings
        $ flask integrity verify -vv

        # Use custom baseline file
        $ flask integrity verify --baseline=/path/to/baseline.json

        # Update baseline with current file state
        $ flask integrity verify --update
    """
    try:
        app = create_app()
        with app.app_context():
            from core.seeder import verify_baseline_integrity

            # Forward to core implementation
            result = verify_baseline_integrity(
                baseline_path=baseline,
                report_only=report_only,
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

                # Display summary and baseline path
                click.echo(f"\nSummary:")
                click.echo(f"  - Files checked: {result.get('files_checked', 0)}")
                click.echo(f"  - Issues found: {len(changes)}")

                # Suggest action if in report-only mode
                if report_only:
                    click.echo("\nTo update the baseline with these changes, run:")
                    click.echo(click.style("  flask integrity update-baseline --force", fg='blue'))

                # Return appropriate exit code
                return EXIT_VALIDATION_ERROR if exit_code else EXIT_SUCCESS

    except Exception as e:
        logger.exception("Integrity verification failed")
        click.echo(click.style(f"✗ Integrity verification failed: {str(e)}", fg='red'))
        return EXIT_ERROR


@integrity.command('update-baseline')
@click.option('--path', help='Path to the baseline file to update')
@click.option('--force/--no-force', default=False,
              help='Update baseline even for critical files')
@click.option('--include', '-i', multiple=True,
              help='Patterns to include (e.g., "*.py", "config/*.yaml")')
@click.option('--exclude', '-e', multiple=True,
              help='Patterns to exclude (e.g., "*.pyc", "tmp/*")')
@click.option('--backup/--no-backup', default=True,
              help='Create backup of existing baseline')
@click.option('--verbose', '-v', count=True,
              help='Verbose output (use multiple times for more detail)')
def update_baseline(path: Optional[str], force: bool, include: tuple,
                    exclude: tuple, backup: bool, verbose: int) -> int:
    """
    Update file integrity baseline with current file states.

    Creates or updates a file integrity baseline with the current state of
    files in the application, optionally filtering by include/exclude patterns.
    A backup of the existing baseline can be automatically created.

    Examples:
        # Update baseline with default settings
        $ flask integrity update-baseline

        # Force update including critical files
        $ flask integrity update-baseline --force

        # Update only Python files
        $ flask integrity update-baseline --include "*.py"

        # Exclude temporary files
        $ flask integrity update-baseline --exclude "*.temp" --exclude "tmp/*"

        # Skip backup creation
        $ flask integrity update-baseline --no-backup
    """
    try:
        app = create_app()
        with app.app_context():
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
                verbose=verbose > 0
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
                return EXIT_SUCCESS
            else:
                click.echo(click.style(f"✗ Baseline update failed: {result.get('error', 'Unknown error')}", fg='red'))
                return EXIT_ERROR

    except Exception as e:
        logger.exception("Baseline update failed")
        click.echo(click.style(f"✗ Baseline update failed: {str(e)}", fg='red'))
        return EXIT_ERROR


@integrity.command('list')
@click.option('--path', help='Path to the baseline file to list')
@click.option('--filter', '-f', help='Filter files containing this string')
@click.option('--format', type=click.Choice(['text', 'json']), default='text',
              help='Output format (text or json)')
@click.option('--sort', type=click.Choice(['path', 'hash']), default='path',
              help='Sort by path or hash')
def list_baseline(path: Optional[str], filter: Optional[str],
                  format: str, sort: str) -> int:
    """
    List the contents of the integrity baseline file.

    Displays the files and hashes stored in the integrity baseline,
    with options for filtering, formatting, and sorting the output.

    Examples:
        # List all baseline entries
        $ flask integrity list

        # List only files in the core directory
        $ flask integrity list --filter core/

        # Output as JSON
        $ flask integrity list --format json

        # Sort by hash value
        $ flask integrity list --sort hash
    """
    try:
        app = create_app()
        with app.app_context():
            import json

            # Get baseline path from config if not provided
            if not path:
                path = app.config.get('FILE_BASELINE_PATH')
                if not path:
                    click.echo("Error: No baseline path configured", err=True)
                    return EXIT_ERROR

            # Check if baseline exists
            if not os.path.exists(path):
                click.echo(f"Error: Baseline file not found: {path}", err=True)
                return EXIT_ERROR

            try:
                # Load baseline
                with open(path, 'r') as f:
                    baseline = json.load(f)

                # Count entries
                total_entries = len(baseline)

                # Filter if requested
                if filter:
                    baseline = {path: hash for path, hash in baseline.items() if filter in path}

                # Sort entries
                if sort == 'path':
                    sorted_entries = sorted(baseline.items())
                else:  # sort by hash
                    sorted_entries = sorted(baseline.items(), key=lambda x: x[1])

                # Output in requested format
                if format == 'json':
                    filtered_baseline = dict(sorted_entries)
                    click.echo(json.dumps(filtered_baseline, indent=2))
                else:
                    click.echo(f"Baseline file: {path}")
                    click.echo(f"Total entries: {total_entries}")
                    if filter:
                        click.echo(f"Filtered entries: {len(sorted_entries)} (filter: '{filter}')")

                    for path, hash in sorted_entries:
                        click.echo(f"{path}: {hash}")

                return EXIT_SUCCESS
            except json.JSONDecodeError:
                click.echo(f"Error: Invalid baseline file format: {path}", err=True)
                return EXIT_ERROR
            except Exception as e:
                click.echo(f"Error reading baseline file: {str(e)}", err=True)
                return EXIT_ERROR

    except Exception as e:
        logger.exception("Failed to list baseline")
        click.echo(f"Error listing baseline: {str(e)}", err=True)
        return EXIT_ERROR


@integrity.command('check-file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--baseline', help='Path to the baseline file (uses configured path if not provided)')
@click.option('--algorithm', type=click.Choice(['sha256', 'sha384', 'sha512', 'md5', 'sha1']),
              default='sha256', help='Hash algorithm to use')
def check_file_integrity(file_path: str, baseline: Optional[str], algorithm: str) -> int:
    """
    Check if a specific file's hash matches the baseline.

    Calculates the hash of a specific file and compares it with
    the value stored in the integrity baseline to verify its integrity.

    Args:
        file_path: Path to the file to check

    Examples:
        # Check a specific file
        $ flask integrity check-file app.py

        # Check with custom baseline and algorithm
        $ flask integrity check-file config.py --baseline=/path/to/baseline.json --algorithm=sha512
    """
    try:
        app = create_app()
        with app.app_context():
            import json
            import os

            # Get baseline path from config if not provided
            if not baseline:
                baseline = app.config.get('FILE_BASELINE_PATH')
                if not baseline:
                    click.echo("Error: No baseline path configured", err=True)
                    return EXIT_ERROR

            # Check if baseline exists
            if not os.path.exists(baseline):
                click.echo(f"Error: Baseline file not found: {baseline}", err=True)
                return EXIT_ERROR

            try:
                # Load baseline
                with open(baseline, 'r') as f:
                    baseline_data = json.load(f)

                # Get absolute path and then relative path for consistency
                abs_path = os.path.abspath(file_path)
                rel_path = os.path.relpath(abs_path, os.path.dirname(app.root_path))

                # Calculate current hash
                from core.security.cs_crypto import compute_hash
                current_hash = compute_hash(file_path=file_path, algorithm=algorithm)

                # Check if file exists in baseline
                if rel_path in baseline_data:
                    baseline_hash = baseline_data[rel_path]
                    if baseline_hash == current_hash:
                        click.echo(click.style("✓ File integrity verified", fg='green'))
                        click.echo(f"  - Path: {rel_path}")
                        click.echo(f"  - Hash: {current_hash}")
                        return EXIT_SUCCESS
                    else:
                        click.echo(click.style("✗ File hash mismatch!", fg='red'))
                        click.echo(f"  - Path: {rel_path}")
                        click.echo(f"  - Current hash: {current_hash}")
                        click.echo(f"  - Baseline hash: {baseline_hash}")
                        return EXIT_VALIDATION_ERROR
                else:
                    click.echo(click.style("! File not in baseline", fg='yellow'))
                    click.echo(f"  - Path: {rel_path}")
                    click.echo(f"  - Current hash: {current_hash}")

                    # Show command to add file to baseline
                    click.echo("\nTo add this file to the baseline, run:")
                    click.echo(click.style(f"  flask integrity update-baseline --include '{os.path.basename(file_path)}'", fg='blue'))
                    return EXIT_VALIDATION_ERROR

            except json.JSONDecodeError:
                click.echo(f"Error: Invalid baseline file format: {baseline}", err=True)
                return EXIT_ERROR
            except Exception as e:
                click.echo(f"Error checking file: {str(e)}", err=True)
                return EXIT_ERROR

    except Exception as e:
        logger.exception(f"Failed to check file integrity: {e}")
        click.echo(f"Error checking file integrity: {str(e)}", err=True)
        return EXIT_ERROR


@integrity.command('analyze')
@click.option('--path', help='Path to directory to analyze')
@click.option('--pattern', '-p', multiple=True, help='File patterns to include')
@click.option('--limit', type=int, default=100, help='Limit number of files to analyze')
def analyze_files(path: Optional[str], pattern: tuple, limit: int) -> int:
    """
    Analyze files for potential integrity risks.

    Scans files in the specified directory (or application root if not provided)
    to identify potential integrity risks such as:
    - Files with suspicious permissions
    - Recently modified files
    - Unexpected executable files
    - Files with suspicious hash values

    Examples:
        # Analyze files in the application directory
        $ flask integrity analyze

        # Analyze specific patterns in a custom directory
        $ flask integrity analyze --path /etc/myapp --pattern "*.conf" --pattern "*.yaml"

        # Analyze more files
        $ flask integrity analyze --limit 500
    """
    try:
        app = create_app()
        with app.app_context():
            import os
            import fnmatch
            import hashlib
            from datetime import datetime

            if not path:
                path = os.path.dirname(app.root_path)

            patterns = list(pattern) if pattern else ['*.py', '*.sh', '*.ini', '*.conf', '*.yaml', '*.yml']

            click.echo(f"Analyzing files in {path} matching {', '.join(patterns)}")

            # Find all matching files
            matches = []
            for root, _, filenames in os.walk(path):
                for filename in filenames:
                    for pattern_item in patterns:
                        if fnmatch.fnmatch(filename, pattern_item):
                            matches.append(os.path.join(root, filename))
                            break

                    if len(matches) >= limit:
                        break

                if len(matches) >= limit:
                    click.echo(f"Reached analysis limit of {limit} files")
                    break

            # Analyze files
            click.echo(f"Found {len(matches)} files to analyze")

            analysis_results = {
                'suspicious_permissions': [],
                'recently_modified': [],
                'unexpected_hash_values': [],
                'executable_scripts': []
            }

            now = datetime.now()

            for file_path in matches:
                try:
                    # Get file stats
                    stats = os.stat(file_path)

                    # Check permissions
                    if stats.st_mode & 0o022:  # World-writable
                        analysis_results['suspicious_permissions'].append(file_path)

                    # Check modification time
                    mod_time = datetime.fromtimestamp(stats.st_mtime)
                    if (now - mod_time).days < 1:  # Modified in the last 24 hours
                        analysis_results['recently_modified'].append(file_path)

                    # Check if file is executable
                    if os.access(file_path, os.X_OK) and not file_path.endswith(('.py', '.sh')):
                        analysis_results['executable_scripts'].append(file_path)

                    # Check content for suspicious patterns
                    with open(file_path, 'rb') as f:
                        content = f.read(8192)  # Read the first 8KB

                        # Calculate hash
                        file_hash = hashlib.sha256(content).hexdigest()

                        # This list would typically come from a threat intelligence feed
                        # or known-bad hash database
                        known_bad_hashes = app.config.get('KNOWN_BAD_HASHES', [])

                        if file_hash in known_bad_hashes:
                            analysis_results['unexpected_hash_values'].append(file_path)

                except Exception as e:
                    click.echo(f"Error analyzing {file_path}: {str(e)}")

            # Display results
            click.echo("\nAnalysis Results:")

            if analysis_results['suspicious_permissions']:
                click.echo(click.style("\nFiles with suspicious permissions:", fg='yellow'))
                for file_path in analysis_results['suspicious_permissions'][:10]:
                    click.echo(f"  • {os.path.relpath(file_path, path)}")
                if len(analysis_results['suspicious_permissions']) > 10:
                    click.echo(f"  ... and {len(analysis_results['suspicious_permissions']) - 10} more")

            if analysis_results['recently_modified']:
                click.echo(click.style("\nRecently modified files:", fg='blue'))
                for file_path in analysis_results['recently_modified'][:10]:
                    click.echo(f"  • {os.path.relpath(file_path, path)}")
                if len(analysis_results['recently_modified']) > 10:
                    click.echo(f"  ... and {len(analysis_results['recently_modified']) - 10} more")

            if analysis_results['executable_scripts']:
                click.echo(click.style("\nUnexpected executable files:", fg='yellow'))
                for file_path in analysis_results['executable_scripts'][:10]:
                    click.echo(f"  • {os.path.relpath(file_path, path)}")
                if len(analysis_results['executable_scripts']) > 10:
                    click.echo(f"  ... and {len(analysis_results['executable_scripts']) - 10} more")

            if analysis_results['unexpected_hash_values']:
                click.echo(click.style("\nFiles with suspicious hash values:", fg='red'))
                for file_path in analysis_results['unexpected_hash_values']:
                    click.echo(f"  • {os.path.relpath(file_path, path)}")

            # Provide a summary and recommendations
            click.echo("\nSummary:")
            total_issues = sum(len(items) for items in analysis_results.values())
            if total_issues > 0:
                click.echo(click.style(f"  • {total_issues} potential issues found", fg='yellow'))
                click.echo("\nRecommendations:")
                if analysis_results['suspicious_permissions']:
                    click.echo("  • Review and correct file permissions")
                    click.echo("    Run: chmod 640 [file] to set appropriate permissions")
                if analysis_results['recently_modified']:
                    click.echo("  • Verify recent file changes are expected")
                    click.echo("    Run: flask integrity verify")
                if analysis_results['unexpected_hash_values']:
                    click.echo("  • Investigate files with suspicious hashes immediately")
            else:
                click.echo(click.style("  • No potential issues found", fg='green'))

            return EXIT_SUCCESS if total_issues == 0 else EXIT_VALIDATION_ERROR

    except Exception as e:
        logger.exception("File analysis failed")
        click.echo(f"Error analyzing files: {str(e)}", err=True)
        return EXIT_ERROR


@cli.command()
@click.argument('username')
@click.option('--reason', required=True, help='Reason for unlocking (for audit purposes)')
def unlock_account(username: str, reason: str) -> int:
    """
    Unlock a user account that has been locked due to failed login attempts.

    This command removes account lockouts applied through the login attempt limiter,
    resetting the failed login counter and allowing the user to authenticate again.
    It requires a reason for audit logging purposes.

    Args:
        username: Username of the account to unlock
        reason: Justification for the unlock (required for audit)

    Example:
        $ flask unlock_account johndoe --reason="Identity verified via support ticket #12345"
    """
    try:
        app = create_app()
        with app.app_context():
            # Try to use the command from cli.app.commands.user if available
            try:
                from cli.app.commands.user import unlock_account as cmd_unlock
                return cmd_unlock(username=username, reason=reason)
            except ImportError:
                logger.warning("Could not import user commands module, using basic implementation")

            # Fall back to basic implementation
            from models import User
            from extensions import db
            from core.security import log_security_event

            user = User.query.filter_by(username=username).first()

            if not user:
                click.echo(f"User '{username}' not found.")
                return EXIT_ERROR

            # Check if user has is_locked method or locked property
            is_locked = False
            if hasattr(user, 'is_locked') and callable(getattr(user, 'is_locked')):
                is_locked = user.is_locked()
            elif hasattr(user, 'locked'):
                is_locked = user.locked
            elif hasattr(user, 'status') and user.status == 'locked':
                is_locked = True

            if is_locked:
                # Reset lock fields based on which are available
                if hasattr(user, 'locked_until'):
                    user.locked_until = None
                if hasattr(user, 'failed_login_count'):
                    user.failed_login_count = 0
                if hasattr(user, 'locked'):
                    user.locked = False
                if hasattr(user, 'status') and user.status == 'locked':
                    user.status = 'active'

                # Save changes
                db.session.commit()

                # Log the action
                try:
                    log_security_event(
                        event_type='account_unlocked',
                        description=f"Account manually unlocked: {username}",
                        severity='info',
                        details={
                            "username": username,
                            "reason": reason,
                            "action": "manual_unlock"
                        }
                    )
                except Exception as log_error:
                    logger.warning(f"Failed to log security event: {log_error}")

                click.echo(f"Account for '{username}' has been successfully unlocked.")
                return EXIT_SUCCESS
            else:
                click.echo(f"Account for '{username}' is not locked.")
                return EXIT_SUCCESS

    except Exception as e:
        logger.error(f"Error unlocking account: {e}")
        click.echo(f"Error unlocking account: {e}")
        return EXIT_ERROR


@cli.command()
@click.option('--version', is_flag=True, help='Show version information')
@click.option('--info', is_flag=True, help='Show detailed environment information')
def about(version: bool, info: bool) -> int:
    """
    Display information about the application.

    Shows version information and system details useful for troubleshooting
    and support.

    Example:
        $ flask about --info
    """
    try:
        from cli.common import print_version

        # Show simple version if requested
        if version and not info:
            print_version()
            return EXIT_SUCCESS

        app = create_app()
        with app.app_context():
            # Print application banner
            click.echo("\n=== Cloud Infrastructure Platform ===\n")

            # Get package version
            from cli import __version__ as cli_version
            click.echo(f"CLI Version: {cli_version}")

            if info:
                # Print environment info
                click.echo("\nEnvironment Information:")
                click.echo(f"- Python: {sys.version}")
                click.echo(f"- Environment: {os.environ.get('FLASK_ENV', 'development')}")
                click.echo(f"- Runtime: {sys.platform}")

                # Show available command groups
                from cli import get_available_commands
                available = [k for k, v in get_available_commands().items() if v]
                click.echo(f"\nAvailable command groups: {', '.join(available)}")

                # Get file integrity status
                try:
                    from core.security import get_last_integrity_status
                    status = get_last_integrity_status(app)
                    click.echo(f"\nFile Integrity: {status.get('status', 'Unknown')}")
                    click.echo(f"Last Check: {status.get('last_checked', 'Never')}")
                except (ImportError, AttributeError):
                    click.echo("\nFile Integrity: Module not available")

            return EXIT_SUCCESS

    except Exception as e:
        logger.error(f"Error displaying application information: {e}")
        click.echo(f"Error: {e}")
        return EXIT_ERROR


# Compatibility layer for running legacy commands directly in this file
def _legacy_command(command_name: str, *args, **kwargs) -> int:
    """Run a command using the new CLI structure but exposed in the legacy format."""
    try:
        # Register all CLI commands to ensure they're available
        app = create_app()
        register_cli_commands(app)

        # Import the run_command function from cli module
        from cli import run_command

        # Convert args and kwargs to command-line arguments
        cmd_args = list(args)
        for k, v in kwargs.items():
            if isinstance(v, bool):
                if v:
                    cmd_args.append(f"--{k.replace('_', '-')}")
            else:
                cmd_args.append(f"--{k.replace('_', '-')}={v}")

        # Run the command
        return run_command(command_name, cmd_args)

    except ImportError:
        logger.error(f"Command module not available: {command_name}")
        click.echo(f"Command not available: {command_name}. Please install required packages.")
        return EXIT_ERROR

    except Exception as e:
        logger.error(f"Error executing command: {e}")
        click.echo(f"Error: {e}")
        return EXIT_ERROR


# Add compatibility wrapper for init_db to maintain backward compatibility
@cli.command()
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
@click.option('--sample-data/--no-sample-data', default=False,
              help='Include sample data (development/testing only)')
@click.option('--reset/--no-reset', default=False, help='Drop existing tables before initialization')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompts')
def init_db(seed: bool, sample_data: bool, reset: bool, force: bool) -> int:
    """
    Initialize the database.

    Creates all database tables defined in the application models and optionally
    seeds the database with initial data. This command delegates to the new CLI
    structure while maintaining backward compatibility.

    Args:
        seed: Whether to populate the database with initial data
        sample_data: Whether to include sample data for development
        reset: Whether to drop and recreate existing tables
        force: Skip confirmation prompts

    Example:
        $ flask init_db --seed
    """
    # Forward to new command structure
    return _legacy_command(
        'db.init',
        seed=seed,
        sample_data=sample_data,
        reset=reset,
        force=force
    )


# Add compatibility wrapper for backup_db to maintain backward compatibility
@cli.command()
@click.option('--backup-dir', default='./backups', help='Backup directory')
@click.option('--format', 'backup_format', type=click.Choice(['sql', 'custom', 'plain', 'directory']),
              default='custom', help='Backup format')
@click.option('--compress/--no-compress', default=True, help='Enable backup compression')
def backup_db(backup_dir: str, backup_format: str, compress: bool) -> int:
    """
    Backup database.

    Creates a backup of the current database and saves it to the specified
    directory with a timestamp. This command delegates to the new CLI
    structure while maintaining backward compatibility.

    Args:
        backup_dir: Directory where the backup file will be stored
        backup_format: Format of the backup file
        compress: Whether to apply compression to the backup

    Example:
        $ flask backup_db --backup-dir=/var/backups/myproject
    """
    # Forward to new command structure
    return _legacy_command(
        'db.backup',
        output_dir=backup_dir,
        format=backup_format,
        compress=compress
    )


if __name__ == '__main__':
    cli()
