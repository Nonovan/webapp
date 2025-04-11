"""
Command-Line Interface (CLI) package for the myproject application.

This package provides a comprehensive set of command-line utilities for managing,
administering, and monitoring all aspects of the myproject application. It organizes
commands into logical groups based on functionality, allowing system administrators
and developers to effectively interact with the application from the terminal.

The CLI is built using Flask's CLI integration with Click, providing a rich command-line
experience with proper argument handling, help documentation, error reporting, and
command grouping.

Command groups include:
- Database management (migrations, backup/restore, optimization)
- User administration (creation, permissions, password resets)
- System monitoring (health checks, metrics collection, diagnostics)
- Application maintenance (cache clearing, session management)

The commands can be accessed through the 'flask' command when the application is
properly installed, or through specialized entry points for specific operations.
"""

from flask.cli import FlaskGroup
from app import create_app
from .commands.db import db_cli
from .commands.user import user_cli
from .commands.system import system_cli
from .commands.monitor import monitor_cli

def init_cli() -> FlaskGroup:
    """
    Initialize the CLI application with all command groups.

    This function creates a Flask CLI group and registers all command subgroups,
    establishing the complete command-line interface hierarchy. It integrates
    with the application's factory pattern to ensure commands have access to
    properly configured application instances.

    The function handles any initialization errors to prevent CLI startup failures,
    ensuring administrators always have access to diagnostic commands even when
    the application is in a partially functional state.

    Command groups registered:
    - db_cli: Database management commands
    - user_cli: User administration commands
    - system_cli: System management and diagnostics
    - monitor_cli: Monitoring and metrics collection

    Returns:
        FlaskGroup: A fully configured Flask CLI group with all commands registered

    Raises:
        Exception: If CLI initialization encounters a critical failure
    """
    try:
        flask_group = FlaskGroup(create_app=create_app)

        # Register command groups
        flask_group.add_command(db_cli)
        flask_group.add_command(user_cli)
        flask_group.add_command(system_cli)
        flask_group.add_command(monitor_cli)

        return flask_group

    except Exception as e:
        print(f"CLI initialization failed: {e}")
        raise

cli = init_cli()

__all__ = ['cli']
