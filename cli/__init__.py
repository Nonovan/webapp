"""
Unified CLI for Cloud Infrastructure Platform.
This module provides command-line interfaces for both application
management and infrastructure deployment operations.
"""

from flask.cli import FlaskGroup
from .app import user_cli, db_cli, system_cli
from .deploy import aws_cli, azure_cli, gcp_cli, k8s_cli
from .common import utils

def register_cli_commands(app):
    """Register all CLI commands with the Flask application."""
    # Application management commands
    app.cli.add_command(user_cli)
    app.cli.add_command(db_cli)
    app.cli.add_command(system_cli)
    
    # Deployment and infrastructure commands
    app.cli.add_command(aws_cli)
    app.cli.add_command(azure_cli)
    app.cli.add_command(gcp_cli)
    app.cli.add_command(k8s_cli)
