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
from core.utils import get_logger
from core.security import is_safe_file_operation, sanitize_path

# Initialize CLI group and logger
k8s_cli = AppGroup('k8s', help='Kubernetes deployment commands')
logger = get_logger(app=None)  # type: ignore

@k8s_cli.command('deploy')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.option('--manifests', default='deployment/kubernetes', help='Directory containing K8s manifests')
@click.option('--verify/--no-verify', default=True, help='Verify manifests integrity before deployment')
def deploy_k8s(env, namespace, context, manifests, verify):
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

        # Check if manifests directory exists
        if not os.path.exists(manifests):
            raise click.ClickException(f"Manifests directory '{manifests}' not found")

        # Optionally verify file integrity
        if verify:
            try:
                from cli.common.security import verify_file_signature
                click.echo("Verifying manifest integrity...")

                for root, _, files in os.walk(manifests):
                    for file in files:
                        if file.endswith('.yaml'):
                            file_path = os.path.join(root, file)
                            if not verify_file_signature(file_path):
                                click.echo(f"⚠️  Warning: Integrity check failed for {file}")
                                if not click.confirm("Continue with deployment?"):
                                    raise click.Abort()
            except ImportError:
                click.echo("⚠️  Warning: Integrity verification not available")

        # Create namespace if it doesn't exist
        click.echo(f"Creating namespace if it doesn't exist: {namespace}")
        subprocess.run([
            'kubectl', 'create', 'namespace', namespace, '--dry-run=client', '-o', 'yaml'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        subprocess.run([
            'kubectl', 'apply', '-f', '-'
        ], input=f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n".encode(),
           check=True)

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
        logger.error("Kubernetes deployment failed: %s %s", e.stdout, e.stderr)
        raise click.ClickException(f"Deployment failed: {e.stderr}")
    except click.Abort:
        click.echo("Deployment aborted by user")
        return
    except Exception as e:
        logger.error("Kubernetes deployment failed: %s", e, exc_info=True)
        raise click.ClickException(f"Deployment failed: {str(e)}")

@k8s_cli.command('status')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.option('--detailed/--summary', default=False, help='Show detailed resources')
def check_status(env, namespace, context, detailed):
    """Check deployment status in Kubernetes."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"

    try:
        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)

        click.echo(f"Status for namespace: {namespace}")

        # Check if namespace exists
        ns_result = subprocess.run([
            'kubectl', 'get', 'namespace', namespace
        ], capture_output=True, text=True)

        if ns_result.returncode != 0:
            click.echo(f"Namespace {namespace} not found")
            return

        # Check pods
        click.echo("\n=== Pods ===")
        pods_cmd = ['kubectl', 'get', 'pods', '-n', namespace]
        if detailed:
            pods_cmd.extend(['-o', 'wide'])

        pods = subprocess.run(pods_cmd, capture_output=True, text=True, check=True)
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

        # If detailed, show additional resources
        if detailed:
            # Show ingress if any
            click.echo("\n=== Ingress ===")
            ingress = subprocess.run([
                'kubectl', 'get', 'ingress', '-n', namespace
            ], capture_output=True, text=True)
            if ingress.returncode == 0:
                click.echo(ingress.stdout)
            else:
                click.echo("No ingress resources found")

            # Show configmaps
            click.echo("\n=== ConfigMaps ===")
            configmaps = subprocess.run([
                'kubectl', 'get', 'configmaps', '-n', namespace
            ], capture_output=True, text=True, check=True)
            click.echo(configmaps.stdout)

            # Show HPA if enabled
            click.echo("\n=== Horizontal Pod Autoscalers ===")
            hpa = subprocess.run([
                'kubectl', 'get', 'hpa', '-n', namespace
            ], capture_output=True, text=True)
            if hpa.returncode == 0:
                click.echo(hpa.stdout)
            else:
                click.echo("No autoscalers found")

    except subprocess.CalledProcessError as e:
        if "NotFound" in e.stderr:
            click.echo(f"Namespace {namespace} not found")
            return
        logger.error("Kubernetes status check failed: %s", e.stderr)
        raise click.ClickException(f"Status check failed: {e.stderr}")
    except Exception as e:
        logger.error("Kubernetes status check failed: %s", e, exc_info=True)
        raise click.ClickException(f"Status check failed: {str(e)}")

@k8s_cli.command('teardown')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.option('--retain-resources', multiple=True, help='Resources to retain')
@click.confirmation_option(prompt='Are you sure you want to tear down this environment?')
def teardown_k8s(env, namespace, context, retain_resources):
    """Tear down Kubernetes deployment."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"

    try:
        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)

        # Check if namespace exists
        ns_result = subprocess.run([
            'kubectl', 'get', 'namespace', namespace
        ], capture_output=True, text=True)

        if ns_result.returncode != 0:
            click.echo(f"Namespace {namespace} not found")
            return

        if retain_resources:
            # Selectively delete resources instead of the whole namespace
            click.echo(f"Selectively removing resources from namespace: {namespace}")

            # Get all resource types in the namespace except those to retain
            resource_types = ['deployments', 'services', 'configmaps', 'secrets',
                             'ingress', 'horizontalpodautoscalers']

            for res_type in resource_types:
                if res_type in retain_resources:
                    click.echo(f"Skipping {res_type} (retained)")
                    continue

                click.echo(f"Removing {res_type}...")
                subprocess.run([
                    'kubectl', 'delete', res_type, '--all', '-n', namespace
                ], capture_output=True, text=True)
        else:
            # Delete the entire namespace
            click.echo(f"Deleting namespace: {namespace}")
            subprocess.run([
                'kubectl', 'delete', 'namespace', namespace
            ], check=True)
            click.echo(f"Namespace {namespace} deleted")

    except subprocess.CalledProcessError as e:
        logger.error("Kubernetes teardown failed: %s", e.stderr)
        raise click.ClickException(f"Teardown failed: {e.stderr}")
    except Exception as e:
        logger.error("Kubernetes teardown failed: %s", e, exc_info=True)
        raise click.ClickException(f"Teardown failed: {str(e)}")

@k8s_cli.command('apply')
@click.option('--env', default='development', help='Deployment environment')
@click.option('--namespace', default=None, help='Kubernetes namespace')
@click.option('--context', default=None, help='Kubernetes context')
@click.option('--file', '-f', required=True, help='Manifest file to apply')
@click.option('--verify/--no-verify', default=True, help='Verify manifest integrity before applying')
def apply_manifest(env, namespace, context, file, verify):
    """Apply a single Kubernetes manifest file."""
    if namespace is None:
        namespace = f"cloud-platform-{env}"

    try:
        # Check if file exists and is valid
        if not os.path.exists(file):
            raise click.ClickException(f"Manifest file not found: {file}")

        # Verify path safety
        safe_path = sanitize_path(file)
        if not is_safe_file_operation('read', safe_path):
            raise click.ClickException(f"Invalid file path: {file}")

        # Optionally verify file integrity
        if verify:
            try:
                from cli.common.security import verify_file_signature
                if not verify_file_signature(safe_path):
                    click.echo(f"⚠️  Warning: Integrity check failed for {file}")
                    if not click.confirm("Continue with apply?"):
                        raise click.Abort()
            except ImportError:
                click.echo("⚠️  Warning: Integrity verification not available")

        # Set context if provided
        if context:
            subprocess.run(['kubectl', 'config', 'use-context', context], check=True)

        click.echo(f"Applying manifest {file} to namespace {namespace}")
        subprocess.run([
            'kubectl', 'apply', '-f', file, '-n', namespace
        ], check=True)

        click.echo(f"Manifest applied successfully")

    except subprocess.CalledProcessError as e:
        logger.error("Kubernetes apply failed: %s", e.stderr)
        raise click.ClickException(f"Apply failed: {e.stderr}")
    except click.Abort:
        click.echo("Operation aborted by user")
        return
    except Exception as e:
        logger.error("Kubernetes apply failed: %s", e, exc_info=True)
        raise click.ClickException(f"Apply failed: {str(e)}")

# Export the CLI command group
__all__ = ['k8s_cli']
