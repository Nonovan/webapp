"""
General deployment CLI commands.

This module provides cross-platform deployment commands that are agnostic to the
specific cloud provider or deployment target.
"""

import os
import json
import logging
import subprocess
import click
from flask.cli import AppGroup
from core.loggings import get_logger

# Initialize CLI group and logger
deploy_cli = AppGroup('general', help='General deployment commands')
logger = get_logger(app=None)  # type: ignore

@deploy_cli.command('prepare')
@click.option('--env', default='development', help='Target environment')
@click.option('--output-dir', default='deployment/artifacts', help='Output directory for artifacts')
def prepare_deployment(env, output_dir):
    """Prepare application for deployment."""
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        click.echo(f"Preparing deployment for {env} environment")
        
        # Run tests
        click.echo("Running tests...")
        subprocess.run(['pytest', '-xvs'], check=True)
        
        # Run security checks
        click.echo("Running security checks...")
        subprocess.run(['flask', 'security-scan'], check=True)
        
        # Create requirements freeze
        click.echo("Freezing requirements...")
        with open(os.path.join(output_dir, 'requirements-freeze.txt'), 'w') as f:
            subprocess.run(['pip', 'freeze'], stdout=f, check=True)
        
        # Package static assets
        click.echo("Packaging static assets...")
        subprocess.run(['flask', 'assets', 'build'], check=True)
        
        click.echo(f"Deployment preparation completed. Artifacts saved to {output_dir}")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Deployment preparation failed: {e}")
        raise click.ClickException(f"Preparation failed: {e}")
    except Exception as e:
        logger.error(f"Deployment preparation failed: {e}", exc_info=True)
        raise click.ClickException(f"Preparation failed: {str(e)}")

@deploy_cli.command('list')
def list_environments():
    """List available deployment environments."""
    env_dir = 'deployment/environments'
    
    if not os.path.exists(env_dir):
        click.echo("No environment configurations found")
        return
    
    click.echo("Available environments:")
    for file in os.listdir(env_dir):
        if file.endswith('.env'):
            env_name = file.replace('.env', '')
            click.echo(f"  - {env_name}")

@deploy_cli.command('validate')
@click.option('--env', default='development', help='Target environment')
def validate_config(env):
    """Validate deployment configuration."""
    try:
        # Validate AWS CloudFormation template if it exists
        cf_template = 'deployment/aws/cloudformation.yaml'
        if os.path.exists(cf_template):
            click.echo("Validating AWS CloudFormation template...")
            subprocess.run([
                'aws', 'cloudformation', 'validate-template',
                '--template-body', f'file://{cf_template}'
            ], check=True)
            click.echo("AWS CloudFormation template is valid")
        
        # Validate Kubernetes manifests if they exist
        k8s_dir = 'deployment/kubernetes'
        if os.path.exists(k8s_dir):
            click.echo("Validating Kubernetes manifests...")
            for file in os.listdir(k8s_dir):
                if file.endswith('.yaml'):
                    manifest_path = os.path.join(k8s_dir, file)
                    subprocess.run([
                        'kubectl', 'apply', '--dry-run=client', '-f', manifest_path
                    ], check=True)
            click.echo("Kubernetes manifests are valid")
        
        # Validate Docker Compose file if it exists
        compose_file = 'deployment/docker/docker-compose.yml'
        if os.path.exists(compose_file):
            click.echo("Validating Docker Compose file...")
            subprocess.run([
                'docker-compose', '-f', compose_file, 'config'
            ], check=True)
            click.echo("Docker Compose file is valid")
        
        click.echo("Configuration validation completed successfully")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Configuration validation failed: {e}")
        raise click.ClickException(f"Validation failed: {e}")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}", exc_info=True)
        raise click.ClickException(f"Validation failed: {str(e)}")
