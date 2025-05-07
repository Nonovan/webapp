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
