"""
Google Cloud Platform deployment CLI commands.

This module provides commands for deploying and managing cloud infrastructure
resources in GCP environments.
"""

import os
import json
import subprocess
import time
import logging
import click
from flask.cli import AppGroup
from core.loggings import get_logger

# Initialize CLI group and logger
gcp_cli = AppGroup('gcp', help='GCP deployment commands')
logger = get_logger(app=None)  # type: ignore

@gcp_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--project', required=True, help='GCP project ID')
@click.option('--region', default='us-central1', help='GCP region')
@click.option('--template', default='deployment/gcp/deployment-config.yaml', help='Deployment Manager template')
def deploy_gcp(env, project, region, template):
    """Deploy application to GCP using Deployment Manager."""
    deployment_name = f"cloud-platform-{env}"
    
    click.echo(f"Deploying to GCP project {project} in {region}, environment: {env}")
    
    try:
        # Check if gcloud CLI is installed
        result = subprocess.run(['gcloud', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            raise click.ClickException("Google Cloud SDK not found. Please install it first.")
        
        # Set GCP project
        subprocess.run(['gcloud', 'config', 'set', 'project', project], check=True)
        
        # Check if deployment exists
        result = subprocess.run([
            'gcloud', 'deployment-manager', 'deployments', 'describe', deployment_name
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Update existing deployment
            click.echo(f"Updating existing deployment: {deployment_name}")
            cmd = ['gcloud', 'deployment-manager', 'deployments', 'update', deployment_name]
        else:
            # Create new deployment
            click.echo(f"Creating new deployment: {deployment_name}")
            cmd = ['gcloud', 'deployment-manager', 'deployments', 'create', deployment_name]
        
        # Add template file
        cmd.extend(['--config', template])
        
        # Execute deployment
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            click.echo(f"Deployment {deployment_name} initiated successfully")
        else:
            raise click.ClickException(f"Deployment failed: {result.stderr}")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"GCP deployment failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Deployment failed: {e.stderr}")
    except Exception as e:
        logger.error(f"GCP deployment failed: {e}", exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@gcp_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--project', required=True, help='GCP project ID')
def check_status(env, project):
    """Check deployment status in GCP."""
    deployment_name = f"cloud-platform-{env}"
    
    try:
        # Set GCP project
        subprocess.run(['gcloud', 'config', 'set', 'project', project], check=True)
        
        # Get deployment status
        result = subprocess.run([
            'gcloud', 'deployment-manager', 'deployments', 'describe', deployment_name,
            '--format', 'json'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            deployment = json.loads(result.stdout)
            click.echo(f"Deployment: {deployment_name}")
            click.echo(f"Status: {deployment.get('operation', {}).get('status')}")
            click.echo(f"Last updated: {deployment.get('update_time')}")
            
            # Show resources
            click.echo("\nResources:")
            resources_result = subprocess.run([
                'gcloud', 'deployment-manager', 'resources', 'list',
                '--deployment', deployment_name,
                '--format', 'table(name,type,update_time,state.yesno(no="COMPLETED"):label=PENDING)'
            ], capture_output=True, text=True, check=True)
            click.echo(resources_result.stdout)
        else:
            click.echo(f"Deployment {deployment_name} not found")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"GCP status check failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Status check failed: {e.stderr}")
    except Exception as e:
        logger.error(f"GCP status check failed: {e}", exc_info=True)
        raise click.ClickException(f"Status check failed: {str(e)}")

@gcp_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--project', required=True, help='GCP project ID')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_gcp(env, project):
    """Tear down GCP deployment."""
    deployment_name = f"cloud-platform-{env}"
    
    try:
        # Set GCP project
        subprocess.run(['gcloud', 'config', 'set', 'project', project], check=True)
        
        # Delete deployment
        click.echo(f"Deleting deployment: {deployment_name}")
        subprocess.run([
            'gcloud', 'deployment-manager', 'deployments', 'delete', deployment_name,
            '--quiet'  # Skip confirmation
        ], check=True)
        click.echo(f"Deployment {deployment_name} deletion initiated")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"GCP teardown failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Teardown failed: {e.stderr}")
    except Exception as e:
        logger.error(f"GCP teardown failed: {e}", exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")
