"""
General deployment CLI commands.

This module provides cross-platform deployment commands that are agnostic to the
specific cloud provider or deployment target.
"""

import os
import json
import logging
import subprocess
from datetime import datetime
import shutil
import click
from flask.cli import AppGroup
from core.utils import get_logger
from core.security import is_safe_file_operation, sanitize_path

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

@deploy_cli.command('verify-integrity')
@click.option('--env', default='development', help='Target environment')
@click.option('--fail-on-changes/--warn-only', default=True, help='Fail if integrity violations are found')
def verify_integrity(env, fail_on_changes):
    """Verify file integrity of deployment artifacts."""
    try:
        from core.security import check_critical_file_integrity

        click.echo(f"Verifying file integrity for {env} deployment...")
        integrity_result, changes = check_critical_file_integrity()

        if not integrity_result:
            message = f"Found {len(changes)} file integrity issues"
            click.echo(f"⚠️ {message}")

            for change in changes[:5]:  # Show first 5 changes
                click.echo(f"  - {change.get('path', 'unknown')}: {change.get('status', 'modified')}")

            if len(changes) > 5:
                click.echo(f"  ... and {len(changes) - 5} more")

            if fail_on_changes:
                raise click.ClickException("File integrity check failed")
        else:
            click.echo("✅ File integrity verified")

    except ImportError:
        logger.warning("File integrity check not available")
        click.echo("⚠️ File integrity check not available")
    except Exception as e:
        logger.error(f"File integrity verification failed: {e}", exc_info=True)
        raise click.ClickException(f"Integrity verification failed: {str(e)}")

@deploy_cli.command('init-env')
@click.argument('name')
@click.option('--template', default='development', help='Template environment to copy from')
@click.option('--force/--no-force', default=False, help='Overwrite if exists')
def init_environment(name, template, force):
    """Initialize a new deployment environment."""
    env_dir = 'deployment/environments'
    template_file = os.path.join(env_dir, f"{template}.env")
    target_file = os.path.join(env_dir, f"{name}.env")

    # Check if template exists
    if not os.path.exists(template_file):
        raise click.ClickException(f"Template environment '{template}' not found")

    # Check if target already exists
    if os.path.exists(target_file) and not force:
        raise click.ClickException(f"Environment '{name}' already exists. Use --force to overwrite.")

    try:
        # Create directory if it doesn't exist
        os.makedirs(env_dir, exist_ok=True)

        # Copy template to new environment file
        with open(template_file, 'r') as src, open(target_file, 'w') as dest:
            content = src.read()
            dest.write(f"# Environment configuration for {name}\n")
            dest.write(f"# Created from template: {template}\n")
            dest.write(f"# Date: {datetime.now().isoformat()}\n\n")
            dest.write(content)

        click.echo(f"✅ Environment '{name}' created successfully")
        click.echo(f"Edit {target_file} to customize configuration")

    except Exception as e:
        logger.error(f"Environment initialization failed: {e}", exc_info=True)
        raise click.ClickException(f"Failed to initialize environment: {str(e)}")

@deploy_cli.command('status')
@click.option('--env', default=None, help='Environment to check (all if not specified)')
def deployment_status(env):
    """Check status of deployments."""
    try:
        environments = [env] if env else [f.replace('.env', '') for f in os.listdir('deployment/environments')
                                        if f.endswith('.env')]

        for current_env in environments:
            click.echo(f"\nChecking deployment status for {current_env}...")

            # Check for resource files that would indicate deployments
            resources = {
                'AWS': os.path.exists(f'deployment/aws/{current_env}-stack.json'),
                'Azure': os.path.exists(f'deployment/azure/{current_env}-deployment.json'),
                'GCP': os.path.exists(f'deployment/gcp/{current_env}-deployment.yaml'),
                'Kubernetes': os.path.exists(f'deployment/kubernetes/overlays/{current_env}'),
                'Docker': os.path.exists(f'deployment/docker/{current_env}.env')
            }

            deployed = [platform for platform, exists in resources.items() if exists]

            if deployed:
                click.echo(f"  Deployed to: {', '.join(deployed)}")
            else:
                click.echo("  No deployments found")

    except Exception as e:
        logger.error(f"Failed to check deployment status: {e}", exc_info=True)
        raise click.ClickException(f"Status check failed: {str(e)}")

@deploy_cli.command('diff')
@click.argument('source_env')
@click.argument('target_env')
@click.option('--output', type=click.Path(), help='Output file for differences')
def diff_environments(source_env, target_env, output):
    """Compare configuration between environments."""
    import difflib
    from pathlib import Path

    source_file = Path(f'deployment/environments/{source_env}.env')
    target_file = Path(f'deployment/environments/{target_env}.env')

    if not source_file.exists():
        raise click.ClickException(f"Source environment '{source_env}' not found")

    if not target_file.exists():
        raise click.ClickException(f"Target environment '{target_env}' not found")

    try:
        with open(source_file) as f:
            source_lines = f.readlines()

        with open(target_file) as f:
            target_lines = f.readlines()

        diff = difflib.unified_diff(
            source_lines,
            target_lines,
            fromfile=f"{source_env}.env",
            tofile=f"{target_env}.env"
        )

        diff_text = ''.join(diff)

        if output:
            with open(output, 'w') as f:
                f.write(diff_text)
            click.echo(f"Differences saved to {output}")
        else:
            if diff_text:
                click.echo(f"Differences between {source_env} and {target_env}:")
                click.echo(diff_text)
            else:
                click.echo(f"No differences found between {source_env} and {target_env}")

    except Exception as e:
        logger.error(f"Environment comparison failed: {e}", exc_info=True)
        raise click.ClickException(f"Comparison failed: {str(e)}")

@deploy_cli.command('cleanup')
@click.option('--env', required=True, help='Environment to clean up')
@click.option('--artifacts/--no-artifacts', default=True, help='Clean up deployment artifacts')
@click.option('--backup/--no-backup', default=True, help='Create backup before cleanup')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompt')
def cleanup_deployment(env, artifacts, backup, force):
    """Clean up deployment artifacts and resources."""
    if not force:
        if not click.confirm(f"This will clean up deployment resources for {env}. Continue?"):
            click.echo("Operation cancelled")
            return

    try:
        # Define paths to clean
        artifact_dir = os.path.join('deployment/artifacts', env)
        temp_dir = os.path.join('deployment/temp', env)

        # Backup if requested
        if backup and (os.path.exists(artifact_dir) or os.path.exists(temp_dir)):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = os.path.join('deployment/backups', f"{env}_{timestamp}")
            os.makedirs(backup_dir, exist_ok=True)

            click.echo(f"Creating backup at {backup_dir}...")

            if os.path.exists(artifact_dir):
                safe_src = sanitize_path(artifact_dir)
                safe_dest = os.path.join(backup_dir, 'artifacts')
                if is_safe_file_operation(safe_src, safe_dest):
                    shutil.copytree(safe_src, safe_dest, dirs_exist_ok=True)

            if os.path.exists(temp_dir):
                safe_src = sanitize_path(temp_dir)
                safe_dest = os.path.join(backup_dir, 'temp')
                if is_safe_file_operation(safe_src, safe_dest):
                    shutil.copytree(safe_src, safe_dest, dirs_exist_ok=True)

        # Clean up artifacts
        if artifacts:
            if os.path.exists(artifact_dir):
                safe_path = sanitize_path(artifact_dir)
                if is_safe_file_operation(safe_path):
                    shutil.rmtree(safe_path)
                    click.echo(f"Removed artifacts directory: {artifact_dir}")

            if os.path.exists(temp_dir):
                safe_path = sanitize_path(temp_dir)
                if is_safe_file_operation(safe_path):
                    shutil.rmtree(safe_path)
                    click.echo(f"Removed temporary directory: {temp_dir}")

        click.echo(f"Cleanup completed for {env} environment")

    except Exception as e:
        logger.error(f"Cleanup failed: {e}", exc_info=True)
        raise click.ClickException(f"Cleanup failed: {str(e)}")
