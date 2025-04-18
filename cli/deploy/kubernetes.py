"""
Kubernetes deployment CLI commands.

This module provides commands for deploying and managing application components
in Kubernetes clusters.
"""

import os
import subprocess
import time
import logging
import click
from flask.cli import AppGroup
from core.loggings import get_logger

# Initialize CLI group and logger
k8s_cli = AppGroup('k8s', help='Kubernetes deployment commands')
logger = get_logger(app=None)  # type: ignore

@k8s_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.option('--manifests', default='deployment/kubernetes', help='Directory containing K8s manifests')
def deploy_k8s(env, namespace, context, manifests):
    """Deploy application to Kubernetes cluster."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"
    
    click.echo(f"Deploying to Kubernetes namespace: {namespace}, environment: {env}")
    
    try:
        # Check if kubectl is installed
        result = subprocess.run(['kubectl', 'version', '--client'], capture_output=True, text=True)
        if result.returncode != 0:
            raise click.ClickException("kubectl not found. Please install it first.")
        
        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)
        
        # Create namespace if it doesn't exist
        subprocess.run([
            'kubectl', 'create', 'namespace', namespace, '--dry-run=client', '-o', 'yaml'
        ], capture_output=True, text=True, check=True)
        
        # Apply ConfigMap with environment-specific settings
        config_map = f"{manifests}/configmap-{env}.yaml"
        if os.path.exists(config_map):
            click.echo(f"Applying ConfigMap for {env} environment")
            subprocess.run([
                'kubectl', 'apply', '-f', config_map, '-n', namespace
            ], check=True)
        
        # Apply secrets
        secrets = f"{manifests}/secrets-{env}.yaml"
        if os.path.exists(secrets):
            click.echo("Applying Secrets")
            subprocess.run([
                'kubectl', 'apply', '-f', secrets, '-n', namespace
            ], check=True)
        
        # Apply deployments, services, etc.
        click.echo("Applying Kubernetes manifests")
        for manifest in sorted(os.listdir(manifests)):
            if manifest.endswith('.yaml') and not manifest.startswith('configmap-') and not manifest.startswith('secrets-'):
                manifest_path = os.path.join(manifests, manifest)
                click.echo(f"Applying {manifest}")
                subprocess.run([
                    'kubectl', 'apply', '-f', manifest_path, '-n', namespace
                ], check=True)
        
        click.echo(f"Deployment to {namespace} completed successfully")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Kubernetes deployment failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Deployment failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Kubernetes deployment failed: {e}", exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@k8s_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
def check_status(env, namespace, context):
    """Check deployment status in Kubernetes."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"
    
    try:
        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)
        
        click.echo(f"Status for namespace: {namespace}")
        
        # Check pods
        click.echo("\n=== Pods ===")
        pods = subprocess.run([
            'kubectl', 'get', 'pods', '-n', namespace
        ], capture_output=True, text=True, check=True)
        click.echo(pods.stdout)
        
        # Check services
        click.echo("\n=== Services ===")
        services = subprocess.run([
            'kubectl', 'get', 'services', '-n', namespace
        ], capture_output=True, text=True, check=True)
        click.echo(services.stdout)
        
        # Check deployments
        click.echo("\n=== Deployments ===")
        deployments = subprocess.run([
            'kubectl', 'get', 'deployments', '-n', namespace
        ], capture_output=True, text=True, check=True)
        click.echo(deployments.stdout)
        
    except subprocess.CalledProcessError as e:
        if "NotFound" in e.stderr:
            click.echo(f"Namespace {namespace} not found")
            return
        logger.error(f"Kubernetes status check failed: {e.stderr}")
        raise click.ClickException(f"Status check failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Kubernetes status check failed: {e}", exc_info=True)
        raise click.ClickException(f"Status check failed: {str(e)}")

@k8s_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_k8s(env, namespace, context):
    """Tear down Kubernetes deployment."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"
    
    try:
        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)
        
        click.echo(f"Deleting namespace: {namespace}")
        subprocess.run([
            'kubectl', 'delete', 'namespace', namespace
        ], check=True)
        click.echo(f"Namespace {namespace} deleted")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Kubernetes teardown failed: {e.stderr}")
        raise click.ClickException(f"Teardown failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Kubernetes teardown failed: {e}", exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")
