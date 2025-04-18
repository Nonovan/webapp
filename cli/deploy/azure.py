"""
Azure deployment CLI commands.

This module provides commands for deploying and managing cloud infrastructure
resources in Azure environments.
"""

import os
import json
import logging
import click
from flask.cli import AppGroup
from core.loggings import get_logger

# Initialize CLI group and logger
azure_cli = AppGroup('azure', help='Azure deployment commands')
logger = get_logger(app=None)  # type: ignore

@azure_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--location', default='westus2', help='Azure region')
@click.option('--template', default='deployment/azure/arm-template.json', help='ARM template')
@click.option('--params', default='deployment/azure/parameters.json', help='Parameters file')
@click.option('--resource-group', default=None, help='Azure resource group name')
def deploy_azure(env, location, template, params, resource_group):
    """Deploy application to Azure using ARM templates."""
    if resource_group is None:
        resource_group = f"cloud-platform-{env}"
    
    click.echo(f"Deploying to Azure {location} environment: {env}")
    
    try:
        # Check if Azure CLI is installed
        import subprocess
        result = subprocess.run(['az', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            raise click.ClickException("Azure CLI not found. Please install it first.")
        
        # Create resource group if it doesn't exist
        subprocess.run([
            'az', 'group', 'create',
            '--name', resource_group,
            '--location', location
        ], check=True)
        
        click.echo(f"Deploying ARM template: {template}")
        
        # Deploy ARM template
        deployment_name = f"deployment-{env}-{int(time.time())}"
        result = subprocess.run([
            'az', 'deployment', 'group', 'create',
            '--resource-group', resource_group,
            '--name', deployment_name,
            '--template-file', template,
            '--parameters', params
        ], capture_output=True, text=True, check=True)
        
        click.echo(f"Deployment {deployment_name} initiated")
        click.echo("Check Azure portal for deployment status")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Azure deployment failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Deployment failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Azure deployment failed: {e}", exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@azure_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--resource-group', default=None, help='Azure resource group name')
def check_status(env, resource_group):
    """Check deployment status in Azure."""
    if resource_group is None:
        resource_group = f"cloud-platform-{env}"
    
    try:
        import subprocess
        result = subprocess.run([
            'az', 'deployment', 'group', 'list',
            '--resource-group', resource_group,
            '--query', '[0]'
        ], capture_output=True, text=True, check=True)
        
        deployment = json.loads(result.stdout)
        if not deployment:
            click.echo(f"No deployments found in resource group {resource_group}")
            return
        
        click.echo(f"Deployment name: {deployment.get('name')}")
        click.echo(f"Status: {deployment.get('properties', {}).get('provisioningState')}")
        click.echo(f"Timestamp: {deployment.get('properties', {}).get('timestamp')}")
        
    except subprocess.CalledProcessError as e:
        if "ResourceGroupNotFound" in str(e.stderr):
            raise click.ClickException(f"Resource group {resource_group} does not exist")
        raise click.ClickException(f"Error checking status: {e.stderr}")
    except Exception as e:
        logger.error(f"Error checking Azure status: {e}", exc_info=True)
        raise click.ClickException(f"Error checking status: {str(e)}")

@azure_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--resource-group', default=None, help='Azure resource group name')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_azure(env, resource_group):
    """Tear down Azure deployment."""
    if resource_group is None:
        resource_group = f"cloud-platform-{env}"
    
    try:
        import subprocess
        click.echo(f"Deleting resource group: {resource_group}")
        subprocess.run([
            'az', 'group', 'delete',
            '--name', resource_group,
            '--yes'
        ], check=True)
        click.echo(f"Resource group {resource_group} deletion initiated")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Azure teardown failed: {e.stdout} {e.stderr}")
        raise click.ClickException(f"Teardown failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Azure teardown failed: {e}", exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")
