"""
AWS deployment CLI commands.

This module provides commands for deploying and managing cloud infrastructure
resources in AWS environments.
"""

import os
import logging
import json
import click
from flask.cli import AppGroup
import boto3
from botocore.exceptions import ClientError
from core.utils import get_logger
from core.security import is_safe_file_operation, sanitize_path
from cli.common.security import verify_file_signature

# Initialize CLI group and logger
aws_cli = AppGroup('aws', help='AWS deployment commands')
logger = get_logger(app=None)  # type: ignore

@aws_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--template', default='deployment/aws/cloudformation.yaml', help='CloudFormation template')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
@click.option('--verify/--no-verify', default=True, help='Verify template integrity before deployment')
def deploy_aws(env, region, template, stack_name, verify):
    """Deploy application to AWS using CloudFormation."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"

    click.echo(f"Deploying to AWS {region} environment: {env}")

    try:
        # Verify template path safety
        if not is_safe_file_operation('read', template):
            raise click.ClickException(f"Invalid template path: {template}")

        # Optionally verify file integrity
        if verify:
            template_path = sanitize_path(template)
            if not verify_file_signature(template_path):
                click.confirm("Template integrity check failed. Continue anyway?", abort=True)

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
        params = {
            'StackName': stack_name,
            'TemplateBody': template_body,
            'Capabilities': ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            'Tags': [
                {'Key': 'Environment', 'Value': env},
                {'Key': 'ManagedBy', 'Value': 'CloudInfrastructurePlatform'}
            ]
        }

        if stack_exists:
            click.echo(f"Updating existing stack: {stack_name}")
            response = cf_client.update_stack(**params)
        else:
            click.echo(f"Creating new stack: {stack_name}")
            params['OnFailure'] = 'ROLLBACK'
            response = cf_client.create_stack(**params)

        click.echo(f"Stack ID: {response['StackId']}")
        click.echo("Deployment initiated. Check AWS CloudFormation console for status.")

    except Exception as e:
        # Using lazy formatting with logger.error()
        logger.error("AWS deployment failed: %s", e, exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@aws_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
@click.option('--detailed/--summary', default=False, help='Show detailed resources')
def check_status(env, region, stack_name, detailed):
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
        if 'LastUpdatedTime' in stack:
            click.echo(f"Last Updated: {stack['LastUpdatedTime']}")

        if 'Outputs' in stack:
            click.echo("\nOutputs:")
            for output in stack['Outputs']:
                click.echo(f"  {output['OutputKey']}: {output['OutputValue']}")
                if 'Description' in output and detailed:
                    click.echo(f"    Description: {output['Description']}")

        if detailed:
            click.echo("\nResources:")
            resources = cf_client.list_stack_resources(StackName=stack_name)
            for resource in resources['StackResourceSummaries']:
                click.echo(f"  {resource['LogicalResourceId']} ({resource['ResourceType']}): {resource['ResourceStatus']}")

    except ClientError as e:
        if "does not exist" in str(e):
            raise click.ClickException(f"Stack {stack_name} does not exist")
        raise click.ClickException(f"Error checking status: {str(e)}")
    except Exception as e:
        # Using lazy formatting with logger.error()
        logger.error("Error checking AWS status: %s", e, exc_info=True)
        raise click.ClickException(f"Error checking status: {str(e)}")

@aws_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
@click.option('--retain-resources', multiple=True, help='Resources to retain')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_aws(env, region, stack_name, retain_resources):
    """Tear down AWS deployment."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"

    try:
        # Initialize CloudFormation client
        cf_client = boto3.client('cloudformation', region_name=region)

        # Check if stack exists before attempting to delete
        try:
            cf_client.describe_stacks(StackName=stack_name)
        except ClientError as e:
            if "does not exist" in str(e):
                raise click.ClickException(f"Stack {stack_name} does not exist")
            raise

        # Prepare delete parameters
        params = {'StackName': stack_name}
        if retain_resources:
            params['RetainResources'] = list(retain_resources)

        # Delete stack
        click.echo(f"Deleting stack: {stack_name}")
        cf_client.delete_stack(**params)
        click.echo(f"Stack deletion initiated for {stack_name}")

    except Exception as e:
        # Using lazy formatting with logger.error()
        logger.error("AWS teardown failed: %s", e, exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")

@aws_cli.command('export')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--stack-name', default=None, help='CloudFormation stack name')
@click.option('--output', default='deployment/aws/exported-template.yaml', help='Output file path')
def export_template(env, region, stack_name, output):
    """Export the template of an existing CloudFormation stack."""
    if stack_name is None:
        stack_name = f"cloud-platform-{env}"

    try:
        # Verify output path safety
        output_path = sanitize_path(output)
        if not is_safe_file_operation('write', output_path):
            raise click.ClickException(f"Invalid output path: {output}")

        # Initialize CloudFormation client
        cf_client = boto3.client('cloudformation', region_name=region)

        # Get template
        response = cf_client.get_template(
            StackName=stack_name,
            TemplateStage='Original'
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(output), exist_ok=True)

        # Save template to file
        with open(output, 'w') as f:
            f.write(response['TemplateBody'])

        click.echo(f"Template exported to {output}")

    except Exception as e:
        # Using lazy formatting with logger.error()
        logger.error("AWS template export failed: %s", e, exc_info=True)
        raise click.ClickException(f"Export failed: {str(e)}")

# Expose all commands
__all__ = ['aws_cli']
