"""
AWS deployment CLI commands.

This module provides commands for deploying and managing cloud infrastructure
resources in AWS environments.
"""

import os
import logging
import click
from flask.cli import AppGroup
import boto3
from botocore.exceptions import ClientError
from core.loggings import get_logger

# Initialize CLI group and logger
aws_cli = AppGroup('aws', help='AWS deployment commands')
logger = get_logger(app=None)  # type: ignore

@aws_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--template', default='deployment/aws/cloudformation.yaml', help='CloudFormation template')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
def deploy_aws(env, region, template, stack_name):
    """Deploy application to AWS using CloudFormation."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"
    
    click.echo(f"Deploying to AWS {region} environment: {env}")
    
    try:
        # Load CloudFormation template
        with open(template, 'r') as f:
            template_body = f.read()
        
        # Initialize CloudFormation client
        cf_client = boto3.client('cloudformation', region_name=region)
        
        # Check if stack exists
        try:
            cf_client.describe_stacks(StackName=stack_name)
            stack_exists = True
        except ClientError:
            stack_exists = False
        
        # Deploy or update stack
        if stack_exists:
            click.echo(f"Updating existing stack: {stack_name}")
            response = cf_client.update_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            )
        else:
            click.echo(f"Creating new stack: {stack_name}")
            response = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                OnFailure='ROLLBACK'
            )
        
        click.echo(f"Stack ID: {response['StackId']}")
        click.echo("Deployment initiated. Check AWS CloudFormation console for status.")
        
    except Exception as e:
        logger.error(f"AWS deployment failed: {e}", exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@aws_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
def check_status(env, region, stack_name):
    """Check deployment status in AWS."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"
    
    try:
        # Initialize CloudFormation client
        cf_client = boto3.client('cloudformation', region_name=region)
        
        # Get stack status
        response = cf_client.describe_stacks(StackName=stack_name)
        stack = response['Stacks'][0]
        
        click.echo(f"Stack: {stack['StackName']}")
        click.echo(f"Status: {stack['StackStatus']}")
        click.echo(f"Created: {stack['CreationTime']}")
        
        if 'Outputs' in stack:
            click.echo("\nOutputs:")
            for output in stack['Outputs']:
                click.echo(f"  {output['OutputKey']}: {output['OutputValue']}")
        
    except ClientError as e:
        if "does not exist" in str(e):
            raise click.ClickException(f"Stack {stack_name} does not exist")
        raise click.ClickException(f"Error checking status: {str(e)}")
    except Exception as e:
        logger.error(f"Error checking AWS status: {e}", exc_info=True)
        raise click.ClickException(f"Error checking status: {str(e)}")

@aws_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_aws(env, region, stack_name):
    """Tear down AWS deployment."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"
    
    try:
        # Initialize CloudFormation client
        cf_client = boto3.client('cloudformation', region_name=region)
        
        # Delete stack
        click.echo(f"Deleting stack: {stack_name}")
        cf_client.delete_stack(StackName=stack_name)
        click.echo(f"Stack deletion initiated for {stack_name}")
        
    except Exception as e:
        logger.error(f"AWS teardown failed: {e}", exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")
