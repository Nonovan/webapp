from flask.cli import FlaskGroup
from app import create_app
from .commands.db import db_cli
from .commands.user import user_cli
from .commands.system import system_cli
from .commands.monitor import monitor_cli

def init_cli() -> FlaskGroup:
    """Initialize CLI application with all commands."""
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
