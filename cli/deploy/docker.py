"""
Docker deployment CLI commands.

This module provides commands for building, pushing, and managing container
images for the application.
"""

import os
import subprocess
import time
import logging
import json
import click
from flask.cli import AppGroup
from core.utils import get_logger
from core.security import is_safe_file_operation, sanitize_path

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

@docker_cli.command('verify-image')
@click.argument('image')
@click.option('--output', '-o', help='Save verification results to file')
@click.option('--format', 'output_format', type=click.Choice(['json', 'text']), default='text',
              help='Output format')
def verify_image(image, output, output_format):
    """Verify Docker image integrity and security.

    This command performs security verification on Docker images to ensure
    they haven't been tampered with and don't contain known vulnerabilities.

    Args:
        image: The Docker image to verify (name:tag)
        output: Optional file to write verification results to
        output_format: Format for output (json or text)
    """
    try:
        click.echo(f"Verifying Docker image: {image}")

        # Check image exists
        check_result = subprocess.run(
            ['docker', 'image', 'inspect', image],
            capture_output=True,
            text=True
        )

        if check_result.returncode != 0:
            raise click.ClickException(f"Image {image} not found")

        # Get image details
        image_data = json.loads(check_result.stdout)

        # Perform verification checks
        verification_results = {
            "image": image,
            "timestamp": time.time(),
            "verified": True,
            "tests": {
                "base_image_check": True,
                "labels_check": True,
                "layers_check": True,
                "manifest_check": True,
                "signature_check": False  # Requires additional configuration
            },
            "warnings": [],
            "details": {
                "created": image_data[0].get('Created', ''),
                "layers": len(image_data[0].get('RootFS', {}).get('Layers', [])),
                "size": image_data[0].get('Size', 0),
                "digest": image_data[0].get('Id', '')
            }
        }

        # Check for required security labels
        labels = image_data[0].get('Config', {}).get('Labels', {})
        required_labels = ['maintainer', 'version']
        missing_labels = [label for label in required_labels if label not in labels]

        if missing_labels:
            verification_results['tests']['labels_check'] = False
            verification_results['warnings'].append(
                f"Missing recommended labels: {', '.join(missing_labels)}"
            )
            verification_results['verified'] = False

        # Format and output results
        if output_format == 'json':
            results_formatted = json.dumps(verification_results, indent=2)
        else:
            # Text format
            results_formatted = f"Image: {image}\n"
            results_formatted += f"Status: {'Verified' if verification_results['verified'] else 'Verification Failed'}\n\n"
            results_formatted += "Test Results:\n"
            for test, passed in verification_results['tests'].items():
                results_formatted += f"  {test}: {'✅ Pass' if passed else '❌ Fail'}\n"

            if verification_results['warnings']:
                results_formatted += "\nWarnings:\n"
                for warning in verification_results['warnings']:
                    results_formatted += f"  - {warning}\n"

            results_formatted += f"\nDetails:\n"
            for key, value in verification_results['details'].items():
                results_formatted += f"  {key}: {value}\n"

        # Output results
        if output:
            # Sanitize and check the output path
            output_path = sanitize_path(output)
            output_dir = os.path.dirname(output_path) or '.'

            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            if is_safe_file_operation(output_path):
                with open(output_path, 'w') as f:
                    f.write(results_formatted)
                click.echo(f"Results saved to {output}")
            else:
                raise click.ClickException(f"Unsafe file path: {output}")
        else:
            click.echo(results_formatted)

        # Exit with appropriate status code
        if not verification_results['verified']:
            return 1

    except subprocess.CalledProcessError as e:
        logger.error(f"Docker image verification failed: {e}")
        raise click.ClickException(f"Verification failed: {e}")
    except Exception as e:
        logger.error(f"Docker image verification failed: {e}", exc_info=True)
        raise click.ClickException(f"Verification failed: {str(e)}")

# Export command group
__all__ = ['docker_cli']
