"""
Initialization commands for the Cloud Infrastructure Platform CLI.

This module provides command-line utilities for initializing various components
of the application including database schemas, configuration files, security baselines,
and environment setup. These commands streamline the process of setting up new
environments and ensure consistent initialization across development, testing,
and production deployments.

The initialization commands implement proper security checks, environment validation,
and comprehensive logging to ensure safe and auditable system setup. They handle
critical operations like database schema creation, security baseline establishment,
and application configuration with appropriate permission controls and validation.
"""

import os
import sys
import logging
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple

import click
from flask import current_app
from flask.cli import AppGroup
from sqlalchemy.exc import SQLAlchemyError

from core.utils import get_logger
from core.security import audit_log, check_critical_file_integrity
from core.config import Config
from core.seeder import seed_database, seed_development_data, seed_test_data
from extensions import db, metrics, cache
from cli.common import (
    require_permission, handle_error, confirm_action, format_output,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_RESOURCE_ERROR
)
from .commands.db import db_cli
from .commands.maintenance import maintenance_cli
from .commands.monitor import monitor_cli
from .commands.security import security_cli
from .commands.system import system_cli
from .commands.user import user_cli

# Initialize CLI group and logger
init_cli = AppGroup('init', help='Application initialization commands')

# Initialize logger with proper fallback options
try:
    logger = get_logger(app=None)
except (TypeError, AttributeError):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)


@init_cli.command('db')
@click.option('--env', type=click.Choice(['development', 'testing', 'staging', 'production']),
              default='development', help='Target environment')
@click.option('--seed/--no-seed', default=True, help='Seed initial data')
@click.option('--sample-data/--no-sample-data', default=False,
              help='Include sample data (development/testing only)')
@click.option('--reset/--no-reset', default=False,
              help='Drop existing tables before initialization')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompts')
@require_permission('db:admin')
def initialize_database(env: str, seed: bool, sample_data: bool, reset: bool, force: bool) -> int:
    """
    Initialize database schema and seed data.

    This command creates database tables, indexes, and optionally seeds
    the database with initial data for the specified environment.
    It can also reset the database by dropping existing tables first.

    Args:
        env: Target environment (development, testing, staging, production)
        seed: Whether to seed initial data
        sample_data: Whether to include sample data (not for production)
        reset: Whether to drop existing tables before initialization
        force: Skip confirmation prompts

    Examples:
        # Initialize development database with seed data
        $ flask init db --env development --seed

        # Reset and initialize testing database with sample data
        $ flask init db --env testing --reset --sample-data

        # Initialize production database (no sample data)
        $ flask init db --env production --no-sample-data
    """
    if reset and not force and env != 'production':
        warning = f"This will DELETE ALL DATA in the {env} database."
        if not confirm_action(warning + " Continue?", default=False):
            click.echo("Operation cancelled")
            return EXIT_SUCCESS

    try:
        metrics.increment(f'db.init.{env}.attempt')

        with click.progressbar(
            length=4 + bool(sample_data),
            label=f'Initializing {env} database'
        ) as bar_line:
            # Step 1: Drop schema if reset requested
            if reset:
                click.echo("\nDropping existing tables...")
                db.drop_all()
                metrics.increment('db.schema.drop')
            bar_line.update(1)

            # Step 2: Create schema
            click.echo("\nCreating database schema...")
            db.create_all()
            metrics.increment('db.schema.create')
            bar_line.update(1)

            # Step 3: Verify database connection
            click.echo("\nVerifying database connection...")
            db.session.execute('SELECT 1')
            bar_line.update(1)

            # Step 4: Seed core data if requested
            if seed:
                click.echo("\nSeeding core data...")
                seed_success = seed_database(verbose=True)
                if not seed_success:
                    click.echo('Warning: Some core seed data could not be inserted', err=True)
                metrics.increment('db.seed.core')
                bar_line.update(1)
            else:
                # Skip seeding steps
                bar_line.update(1)

            # Step 5: Add sample data if requested (and not production)
            if sample_data and env != 'production':
                click.echo("\nSeeding sample data...")

                # Use appropriate seed function based on environment
                if env == 'testing':
                    sample_success = seed_test_data(verbose=True)
                else:  # development
                    sample_success = seed_development_data(verbose=True)

                if not sample_success:
                    click.echo('Warning: Some sample data could not be inserted', err=True)

                metrics.increment('db.seed.sample')
                bar_line.update(1)

        # Log audit event for accountability
        try:
            audit_log(
                'database',
                'initialized',
                details={
                    'environment': env,
                    'reset': reset,
                    'seed': seed,
                    'sample_data': sample_data
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        metrics.increment(f'db.init.{env}.success')
        logger.info(f"Database initialized in {env} environment")
        click.echo(f"\nDatabase initialized successfully for {env} environment")

        # Show additional info for developers in development environment
        if env == 'development':
            click.echo("\nNext steps:")
            click.echo("  - Run 'flask run' to start the development server")
            click.echo("  - Run 'flask system status' to verify system health")

        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment(f'db.init.{env}.failure')
        logger.error(f"Database initialization failed: {e}")
        db.session.rollback()
        handle_error(e, "Database initialization failed")
        return EXIT_ERROR


@init_cli.command('config')
@click.option('--env', type=click.Choice(['development', 'testing', 'staging', 'production']), default='development',
              help='Target environment')
@click.option('--template', type=click.Path(exists=True), default=None,
              help='Configuration template file')
@click.option('--output', type=click.Path(), default='.env.local',
              help='Output configuration file')
@click.option('--force/--no-force', default=False,
              help='Overwrite existing configuration file if present')
@require_permission('system:admin')
def initialize_config(env: str, template: Optional[str], output: str, force: bool) -> int:
    """
    Initialize application configuration from a template.

    This command creates a configuration file for the specified environment
    using either a provided template or environment-specific defaults.

    Args:
        env: Target environment (development, testing, staging, production)
        template: Path to template configuration file (optional)
        output: Output path for the generated configuration
        force: Overwrite output file if it exists

    Examples:
        # Create development configuration
        $ flask init config --env development

        # Create production configuration from template
        $ flask init config --env production --template production.env.template

        # Force overwrite existing configuration
        $ flask init config --env testing --force
    """
    try:
        # Check if output file already exists
        output_path = Path(output).absolute()

        if output_path.exists() and not force:
            click.echo(f"Configuration file {output} already exists. Use --force to overwrite.")
            return EXIT_RESOURCE_ERROR

        # Determine template file to use
        if template:
            template_path = Path(template).absolute()
            if not template_path.exists():
                raise click.ClickException(f"Template file not found: {template}")

            click.echo(f"Using template file: {template}")
        else:
            # Use built-in templates based on environment
            base_dir = Path(__file__).parent.parent.parent.parent  # Go up to project root
            template_path = base_dir / 'config' / 'templates' / f'{env}.env.template'
            if not template_path.exists():
                raise click.ClickException(f"No template found for {env} environment")

            click.echo(f"Using default template for {env} environment")

        # Read template content
        with open(template_path, 'r') as f:
            config_content = f.read()

        # Replace placeholders with environment-specific values
        replacements = {
            '{{environment}}': env,
            '{{timestamp}}': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            '{{secret_key}}': secrets.token_hex(32),
            '{{csrf_secret_key}}': secrets.token_hex(16),
            '{{jwt_secret_key}}': secrets.token_hex(32),
            '{{session_key}}': secrets.token_hex(16),
            '{{server_name}}': f"localhost:{5000 + (100 if env == 'testing' else 0)}"
        }

        for placeholder, value in replacements.items():
            config_content = config_content.replace(placeholder, value)

        # Create directory if needed
        os.makedirs(output_path.parent, exist_ok=True)

        # Write output file
        with open(output_path, 'w') as f:
            f.write(config_content)

        # Log action
        metrics.increment(f'config.init.{env}.success')
        logger.info(f"Configuration initialized for {env} environment")
        click.echo(f"Configuration file created at {output}")

        # Log audit event
        try:
            audit_log(
                'configuration',
                'initialized',
                details={
                    'environment': env,
                    'output_file': str(output_path),
                    'source_template': str(template_path)
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment(f'config.init.{env}.failure')
        handle_error(e, "Failed to initialize configuration")
        return EXIT_ERROR


@init_cli.command('security')
@click.option('--baseline/--no-baseline', default=True,
              help='Create file integrity baseline')
@click.option('--admin-user/--no-admin-user', default=True,
              help='Create administrator user account')
@click.option('--admin-password',
              help='Administrator password (will prompt if not provided)')
@click.option('--force/--no-force', default=False,
              help='Skip confirmation prompts')
@require_permission('security:admin')
def initialize_security(baseline: bool, admin_user: bool,
                       admin_password: Optional[str], force: bool) -> int:
    """
    Initialize security components and administrator account.

    This command sets up security components including the file integrity baseline
    and optionally creates an administrator user account with MFA requirement.

    Args:
        baseline: Whether to create file integrity baseline
        admin_user: Whether to create administrator account
        admin_password: Administrator password (will prompt if not provided)
        force: Skip confirmation prompts

    Examples:
        # Initialize all security components
        $ flask init security

        # Only create file integrity baseline
        $ flask init security --no-admin-user

        # Only create admin user with specific password
        $ flask init security --no-baseline --admin-password "secure-password"
    """
    try:
        metrics.increment('security.init.attempt')

        # Create file integrity baseline if requested
        if baseline:
            click.echo("Creating file integrity baseline...")
            try:
                from models import FileIntegrityBaseline

                # Check if baseline already exists
                existing_baseline = FileIntegrityBaseline.query.first()

                if existing_baseline and not force:
                    if not confirm_action("File integrity baseline already exists. Update it?", default=False):
                        click.echo("Skipping baseline creation")
                    else:
                        status, changes = check_critical_file_integrity(current_app)
                        click.echo(f"Updating baseline with {len(changes)} changes")
                        from core.security import update_file_integrity_baseline
                        update_file_integrity_baseline(current_app, current_app.config.get('FILE_BASELINE_PATH'), changes)
                        click.echo("File integrity baseline updated successfully")
                else:
                    # Create new baseline
                    from core.security import create_file_hash_baseline
                    baseline_path = create_file_hash_baseline(current_app)
                    click.echo(f"File integrity baseline created successfully at {baseline_path}")

                # Track metrics
                metrics.increment('security.baseline.created')

            except (ImportError, AttributeError) as e:
                click.echo(f"Warning: Could not create file integrity baseline: {e}")
                logger.warning(f"Failed to create file integrity baseline: {e}")

        # Create admin user if requested
        if admin_user:
            click.echo("Creating administrator account...")
            try:
                from models import User

                # Check if admin user already exists
                admin = User.query.filter_by(username='admin').first()

                if admin and not force:
                    if not confirm_action("Administrator account already exists. Recreate?", default=False):
                        click.echo("Skipping administrator account creation")
                    else:
                        db.session.delete(admin)
                        db.session.commit()
                        admin = None

                if admin is None:
                    # Get password securely
                    if not admin_password:
                        admin_password = click.prompt("Enter administrator password",
                                                   hide_input=True, confirmation_prompt=True)

                    # Create the admin user
                    admin = User()
                    admin.username = 'admin'
                    admin.email = 'admin@example.com'
                    admin.role = 'admin'
                    admin.status = 'active'
                    admin.require_mfa = True
                    admin.set_password(admin_password)

                    db.session.add(admin)
                    db.session.commit()

                    click.echo("✅ Administrator account created successfully")

                    # Log audit event but don't expose password
                    try:
                        audit_log(
                            'security',
                            'admin_user_created',
                            details={
                                'username': 'admin',
                                'mfa_required': True
                            }
                        )
                    except Exception:
                        # Don't fail if audit logging fails
                        pass

                    # Track metrics
                    metrics.increment('security.admin_user.created')

            except (ImportError, AttributeError, SQLAlchemyError) as e:
                click.echo(f"Warning: Could not create administrator account: {e}")
                logger.warning(f"Failed to create administrator account: {e}")
                db.session.rollback()

        metrics.increment('security.init.success')
        click.echo("Security initialization completed")
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment('security.init.failed')
        logger.error(f"Security initialization failed: {e}")
        handle_error(e, "Security initialization failed")
        return EXIT_ERROR


@init_cli.command('project')
@click.option('--env', type=click.Choice(['development', 'testing', 'staging', 'production']), default='development',
              help='Target environment')
@click.option('--with-db/--no-db', default=True,
              help='Initialize database as part of project setup')
@click.option('--with-config/--no-config', default=True,
              help='Initialize configuration as part of project setup')
@click.option('--sample-data/--no-sample-data', default=False,
              help='Include sample data (development/testing only)')
@click.option('--force/--no-force', default=False, help='Skip confirmation prompts')
@require_permission('system:admin')
def initialize_project(env: str, with_db: bool, with_config: bool,
                      sample_data: bool, force: bool) -> int:
    """
    Initialize complete project environment.

    This is a comprehensive command that initializes multiple components
    including configuration, database schema, and directory structure.
    It's useful for setting up new environments or initializing a fresh
    checkout of the codebase.

    Args:
        env: Target environment (development, testing, staging, production)
        with_db: Initialize database
        with_config: Initialize configuration
        sample_data: Include sample data (only for non-production environments)
        force: Skip confirmation prompts

    Examples:
        # Initialize complete development environment
        $ flask init project --env development

        # Initialize only configuration
        $ flask init project --no-db --with-config

        # Initialize production environment
        $ flask init project --env production --force
    """
    try:
        # Security check for production environments
        if env == 'production' and not force:
            warning = "You are initializing a PRODUCTION environment. Continue?"
            if not confirm_action(warning, default=False):
                click.echo("Operation cancelled")
                return EXIT_SUCCESS

        if env == 'production' and sample_data:
            click.echo("Sample data cannot be used in production environments")
            return EXIT_ERROR

        click.echo(f"Starting {env} environment initialization...")

        # Initialize required directories
        dirs_to_create = [
            'logs',
            'uploads',
            'instance',
            'backups'
        ]

        click.echo("\nCreating required directories...")
        for directory in dirs_to_create:
            os.makedirs(directory, exist_ok=True)
            click.echo(f"  - {directory}/")

        # Initialize configuration if requested
        if with_config:
            click.echo("\nInitializing configuration...")
            config_result = initialize_config(env, None, f'.env.{env}', force)
            if config_result != EXIT_SUCCESS:
                click.echo("Configuration initialization failed")
                return config_result

        # Initialize database if requested
        if with_db:
            click.echo("\nInitializing database...")
            db_result = initialize_database(env, True, sample_data, False, force)
            if db_result != EXIT_SUCCESS:
                click.echo("Database initialization failed")
                return db_result

        # Set appropriate permissions for sensitive directories
        click.echo("\nSetting secure permissions for sensitive directories...")
        try:
            if sys.platform != 'win32':  # Skip on Windows
                os.chmod('logs', 0o750)
                os.chmod('uploads', 0o750)
                os.chmod('instance', 0o750)
                click.echo("  Secure permissions applied")
        except Exception as e:
            click.echo(f"  Warning: Could not set directory permissions: {e}")

        # Log audit event
        try:
            audit_log(
                'project',
                'initialized',
                details={
                    'environment': env,
                    'database_initialized': with_db,
                    'config_initialized': with_config,
                    'sample_data': sample_data
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        # Display success message and next steps
        click.echo(f"\n✅ {env.title()} environment initialized successfully")

        if env == 'development':
            click.echo("\nNext steps:")
            click.echo("  1. Run 'flask run' to start the development server")
            click.echo("  2. Run 'flask system status' to verify system health")
            click.echo("  3. Access the application at http://localhost:5000")

        metrics.increment(f'project.init.{env}.success')
        return EXIT_SUCCESS

    except Exception as e:
        metrics.increment(f'project.init.{env}.failure')
        handle_error(e, "Project initialization failed")
        return EXIT_ERROR


# Version information
__version__ = '0.1.1'

# Export public interface
__all__ = [
    # CLI command group
    'init_cli',
    'db_cli',
    'maintenance_cli',
    'monitor_cli',
    'security_cli',
    'system_cli',
    'user_cli',

    # Initialization commands
    'initialize_database',
    'initialize_config',
    'initialize_security',
    'initialize_project',

    # Version information
    '__version__'
]
