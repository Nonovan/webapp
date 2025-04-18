"""
Docker deployment CLI commands.

This module provides commands for building, pushing, and managing container
images for the application.
"""

import os
import subprocess
import time
import logging
import click
from flask.cli import AppGroup
from core.loggings import get_logger

# Initialize CLI group and logger
docker_cli = AppGroup('docker', help='Docker image commands')
logger = get_logger(app=None)  # type: ignore

@docker_cli.command('build')
@click.option('--env', default='development', help='Build environment')
@click.option('--tag', default=None, help='Image tag')
@click.option('--dockerfile', default='deployment/docker/Dockerfile', help='Dockerfile path')
@click.option('--push/--no-push', default=False, help='Push image after building')
@click.option('--registry', default=None, help='Container registry')
def build_image(env, tag, dockerfile, push, registry):
    """Build Docker image for the application."""
    if tag is None:
        tag = f"cloud-platform:{env}"
    
    if registry:
        tag = f"{registry}/{tag}"
    
    click.echo(f"Building Docker image: {tag}")
    
    try:
        # Check if Docker is installed
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            raise click.ClickException("Docker not found. Please install it first.")
        
        # Build image
        click.echo("Building image...")
        build_cmd = [
            'docker', 'build',
            '--tag', tag,
            '--file', dockerfile,
            '--build-arg', f"BUILD_ENV={env}",
            '.'
        ]
        
        subprocess.run(build_cmd, check=True)
        click.echo(f"Image built: {tag}")
        
        # Push image if requested
        if push:
            click.echo(f"Pushing image to registry: {tag}")
            subprocess.run(['docker', 'push', tag], check=True)
            click.echo("Image pushed successfully")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Docker build failed: {e}")
        raise click.ClickException(f"Build failed: {e}")
    except Exception as e:
        logger.error(f"Docker build failed: {e}", exc_info=True)
        raise click.ClickException(f"Build failed: {str(e)}")

@docker_cli.command('compose')
@click.option('--env', default='development', help='Environment')
@click.option('--compose-file', default='deployment/docker/docker-compose.yml', help='Docker Compose file path')
@click.option('--action', type=click.Choice(['up', 'down', 'restart']), default='up', help='Action to perform')
@click.option('--detach/--no-detach', '-d', default=True, help='Run in detached mode')
def docker_compose(env, compose_file, action, detach):
    """Run Docker Compose operations."""
    env_file = f"deployment/environments/{env}.env"
    
    try:
        # Check if Docker Compose is installed
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            raise click.ClickException("Docker Compose not found. Please install it first.")
        
        # Build command based on action
        cmd = ['docker-compose', '-f', compose_file]
        
        # Add environment file if it exists
        if os.path.exists(env_file):
            cmd.extend(['--env-file', env_file])
        
        # Add action and options
        cmd.append(action)
        
        if action == 'up':
            # Only add detach flag for 'up'
            if detach:
                cmd.append('-d')
        
        click.echo(f"Running docker-compose {action} for {env} environment")
        subprocess.run(cmd, check=True)
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Docker Compose operation failed: {e}")
        raise click.ClickException(f"Operation failed: {e}")
    except Exception as e:
        logger.error(f"Docker Compose operation failed: {e}", exc_info=True)
        raise click.ClickException(f"Operation failed: {str(e)}")

@docker_cli.command('prune')
@click.confirmation_option(prompt='This will remove all unused Docker objects. Are you sure?')
def prune_docker():
    """Clean up unused Docker resources."""
    try:
        click.echo("Pruning Docker resources...")
        subprocess.run(['docker', 'system', 'prune', '-f'], check=True)
        click.echo("Docker cleanup completed")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Docker prune failed: {e}")
        raise click.ClickException(f"Cleanup failed: {e}")
    except Exception as e:
        logger.error(f"Docker prune failed: {e}", exc_info=True)
        raise click.ClickException(f"Cleanup failed: {str(e)}")
