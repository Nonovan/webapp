"""
Unified CLI for Cloud Infrastructure Platform.
This module provides command-line interfaces for both application
management and infrastructure deployment operations.
"""

from flask.cli import FlaskGroup
from .app import user_cli, db_cli, system_cli, security_cli, maintenance_cli, init_cli
from .deploy import deployment_cli, aws_cli, azure_cli, gcp_cli, k8s_cli, docker_cli, deploy_cli
from .common import utils

# Package version
__version__ = '0.1.1'

def register_cli_commands(app):
    """Register all CLI commands with the Flask application."""
    # Application management commands
    app.cli.add_command(user_cli)
    app.cli.add_command(db_cli)
    app.cli.add_command(system_cli)
    app.cli.add_command(security_cli)
    app.cli.add_command(maintenance_cli)
    app.cli.add_command(init_cli)

    # Deployment and infrastructure commands
    app.cli.add_command(deployment_cli)  # Main deployment group
    app.cli.add_command(aws_cli)
    app.cli.add_command(azure_cli)
    app.cli.add_command(gcp_cli)
    app.cli.add_command(k8s_cli)
    app.cli.add_command(docker_cli)
    app.cli.add_command(deploy_cli)  # General deployment commands

# Define what is available for import from this package
__all__ = [
    'register_cli_commands',
    '__version__'
]
