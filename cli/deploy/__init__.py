"""
Command-line interface for deployment operations.

This module provides CLI commands for deploying, updating, and managing
infrastructure components across various environments.
"""

from flask.cli import AppGroup
from .aws import aws_cli
from .azure import azure_cli
from .gcp import gcp_cli
from .kubernetes import k8s_cli
from .docker import docker_cli
from .general import deploy_cli

# Create the main deployment CLI group
deployment_cli = AppGroup('deploy', help='Deployment operations')

# Register sub-command groups
deployment_cli.add_command(aws_cli)
deployment_cli.add_command(azure_cli)
deployment_cli.add_command(gcp_cli)
deployment_cli.add_command(k8s_cli)
deployment_cli.add_command(docker_cli)

# Export command groups
__all__ = [
    'deployment_cli',
    'aws_cli',
    'azure_cli',
    'gcp_cli',
    'k8s_cli',
    'docker_cli',
    'deploy_cli'
]
