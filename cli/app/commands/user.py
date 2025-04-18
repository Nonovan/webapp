"""
User administration commands for the myproject CLI.

This module provides command-line utilities for managing user accounts, including
creation, listing, password reset, and role management. These commands enable
administrators to perform user management tasks without accessing the application's
web interface, which is particularly useful for initial setup, maintenance, and
emergency access recovery.

These commands handle sensitive operations and require appropriate authorization
to use in production environments.
"""

import logging
import click
from flask import current_app
from flask.cli import AppGroup
from core.loggings import get_logger
from extensions import db
from models import User

try:
    try:
        # Use fallback logger setup to avoid type error with None
        if current_app:
            logger = get_logger(app=current_app)
        else:
            logger = logging.getLogger('cli')
            logger.setLevel(logging.INFO)
    except AttributeError as e:
        logger = None
        print(f"Logger initialization warning: {e}")
except (AttributeError, ImportError):
    logger = None

if logger is None and click.get_current_context().obj:
    logger = click.get_current_context().obj.get('logger', None)
if logger is None:
    raise RuntimeError("Logger initialization failed. Ensure get_logger is configured correctly or provide a fallback logger.")
user_cli = AppGroup('user')

@user_cli.command('create')
@click.option('--username', prompt=True)
@click.option('--email', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
@click.option('--role', type=click.Choice(['user', 'admin', 'operator']), default='user')
def create_user(username: str, email: str, password: str, role: str) -> None:
    """
    Create new user with specified role.

    Creates a new user account in the system with the provided credentials and role.
    This command is interactive by default, prompting for required information if
    not provided as options. The password is hidden during input for security.

    User roles determine the permissions and access levels within the application:
    - user: Standard user with basic permissions
    - admin: Administrator with full system access
    - operator: Operational user with monitoring and maintenance permissions

    Args:
        username: Unique username for the new account
        email: Email address for the new user
        password: Password for the new account (will be securely hashed)
        role: Permission role to assign to the user

    Examples:
        # Interactive creation with prompts
        $ flask user create

        # Non-interactive creation with all parameters
        $ flask user create --username=admin --email=admin@example.com --password=secret --role=admin
    """
    try:
        # Check if logger is defined before using it
        log = logger if logger else None

        # Create the user object correctly
        user = User()
        user.username = username
        user.email = email
        user.role = role
        user.status = 'active'
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        # Use logger safely with conditional check
        if log:
            log.info("Created user: %s with role: %s", username, role)
        click.echo(f"User {username} created successfully")
    except Exception as e:
        # Handle errors with logger safety check
        if logger:
            logger.error("User creation failed: %s", e)
        db.session.rollback()
        raise click.ClickException(str(e))

@user_cli.command('list')
@click.option('--role', help='Filter by role')
@click.option('--status', help='Filter by status')
def list_users(role: str, status: str) -> None:
    """
    List users with optional filters.

    Displays a list of users in the system, optionally filtered by role and/or status.
    This command is useful for auditing user accounts, verifying permissions, and
    troubleshooting access issues.

    The output includes username, role, status, and last login information for
    each user matching the specified filters.

    Args:
        role: Filter users by role (admin, user, operator)
        status: Filter users by account status (active, pending, inactive, suspended)

    Examples:
        # List all users
        $ flask user list

        # List only admin users
        $ flask user list --role=admin

        # List inactive users
        $ flask user list --status=inactive

        # List active admins
        $ flask user list --role=admin --status=active
    """
    try:
        query = User.query
        if role:
            query = query.filter_by(role=role)
        if status:
            query = query.filter_by(status=status)
        users = query.all()

        click.echo("\nUser List:")
        for user in users:
            click.echo(
                f"  {user.username:<20} Role: {user.role:<10} "
                f"Status: {user.status:<10} Last Login: {user.last_login or 'Never'}"
            )
    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("User listing failed: %s", e)
        raise click.ClickException(str(e))

@user_cli.command('reset-password')
@click.argument('username')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def reset_password(username: str, password: str) -> None:
    """
    Reset user password.

    Changes the password for a specified user account. This command is useful
    for administrative password resets when users cannot access the standard
    password recovery process.

    The command prompts for the new password with confirmation to prevent typos,
    and the input is hidden for security. The password will be securely hashed
    before storage.

    Args:
        username: Username of the account to modify
        password: New password to set (prompted securely if not provided)

    Examples:
        # Reset password with prompts
        $ flask user reset-password johndoe

        # Reset password non-interactively (less secure)
        $ flask user reset-password johndoe --password=newpassword
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")
        user.set_password(password)
        db.session.commit()
        # Check if logger is defined before using it
        if logger:
            logger.info("Reset password for user: %s", username)
        click.echo(f"Password reset successful for {username}")
    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("Password reset failed: %s", e)
        db.session.rollback()
        raise click.ClickException(str(e))

@user_cli.command('change-role')
@click.argument('username')
@click.argument('new_role', type=click.Choice(['user', 'admin', 'operator']))
def change_role(username: str, new_role: str) -> None:
    """
    Change user role.

    Updates the permission role for a specified user account. This command
    allows administrators to promote or demote users' access levels without
    modifying other account details.

    Available roles:
    - user: Standard user with basic permissions
    - admin: Administrator with full system access
    - operator: Operational user with monitoring and maintenance permissions

    Args:
        username: Username of the account to modify
        new_role: New role to assign to the user

    Examples:
        # Promote a user to admin
        $ flask user change-role johndoe admin

        # Demote an admin to regular user
        $ flask user change-role admin_user user
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")
        old_role = user.role
        user.role = new_role
        db.session.commit()

        # Check if logger is defined before using it
        if logger:
            logger.info("Changed role for %s: %s -> %s", username, old_role, new_role)

        click.echo(f"Role changed from {old_role} to {new_role} for {username}")
    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("Role change failed: %s", e)

        db.session.rollback()
        raise click.ClickException(str(e))
