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
import sys
from datetime import datetime
from flask import current_app
from flask.cli import AppGroup
from sqlalchemy.exc import SQLAlchemyError
from core.utils.logging_utils import get_logger
from core.security.cs_audit import log_security_event as audit_log
from extensions import db, metrics
from models import User
from cli.common import (
    require_auth, require_permission, handle_error, confirm_action, format_output,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_RESOURCE_ERROR, EXIT_PERMISSION_ERROR
)

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
@click.option('--first-name', help='User\'s first name')
@click.option('--last-name', help='User\'s last name')
@click.option('--require-mfa/--no-require-mfa', default=False, help='Require MFA for this account')
@click.option('--force-password-change/--no-force-password-change', default=True,
              help='Require password change on first login')
@require_permission('user:create')
def create_user(username: str, email: str, password: str, role: str, first_name: str = None,
               last_name: str = None, require_mfa: bool = False,
               force_password_change: bool = True) -> int:
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
        first_name: User's first name (optional)
        last_name: User's last name (optional)
        require_mfa: Whether to enable MFA requirement for this user
        force_password_change: Whether to force password change on first login

    Examples:
        # Interactive creation with prompts
        $ flask user create

        # Non-interactive creation with all parameters
        $ flask user create --username=admin --email=admin@example.com --password=secret --role=admin
    """
    try:
        # Check if logger is defined before using it
        log = logger if logger else None

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            raise click.ClickException(f"Username '{username}' already exists")

        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            raise click.ClickException(f"Email '{email}' already registered")

        # Create the user object correctly
        user = User()
        user.username = username
        user.email = email
        user.role = role
        user.status = 'active'
        user.first_name = first_name
        user.last_name = last_name
        user.require_mfa = require_mfa
        user.password_change_required = force_password_change
        user.created_at = datetime.now()
        user.set_password(password)

        # Track user creation in metrics
        metrics.increment('user_management.user_created')
        metrics.increment(f'user_management.role_assigned.{role}')

        db.session.add(user)
        db.session.commit()

        # Use logger safely with conditional check
        if log:
            log.info("Created user: %s with role: %s", username, role)

        # Log audit event if available
        try:
            audit_log(
                'user_management',
                'user_created',
                details={
                    'username': username,
                    'role': role,
                    'require_mfa': require_mfa
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"User {username} created successfully")
        return EXIT_SUCCESS

    except Exception as e:
        # Handle errors with logger safety check
        if logger:
            logger.error("User creation failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.user_creation_failed')
        raise click.ClickException(str(e))


@user_cli.command('list')
@click.option('--role', help='Filter by role')
@click.option('--status', help='Filter by status')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), default='table',
              help='Output format')
@click.option('--limit', type=int, default=100, help='Maximum number of users to display')
@require_permission('user:read')
def list_users(role: str, status: str, output_format: str, limit: int) -> int:
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
        output_format: Format for the output (table, json, csv)
        limit: Maximum number of results to display

    Examples:
        # List all users
        $ flask user list

        # List only admin users
        $ flask user list --role=admin

        # List inactive users
        $ flask user list --status=inactive

        # List active admins as JSON
        $ flask user list --role=admin --status=active --format=json
    """
    try:
        query = User.query
        if role:
            query = query.filter_by(role=role)
        if status:
            query = query.filter_by(status=status)

        # Apply limit and order by username
        users = query.order_by(User.username).limit(limit).all()

        if output_format == 'table':
            click.echo("\nUser List:")
            # Print header
            click.echo(f"  {'Username':<20} {'Role':<10} {'Status':<10} {'MFA':<6} {'Last Login':<20}")
            click.echo(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*6} {'-'*20}")

            # Print each user
            for user in users:
                mfa_status = "Yes" if getattr(user, 'require_mfa', False) else "No"
                last_login = user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else 'Never'
                click.echo(
                    f"  {user.username:<20} {user.role:<10} "
                    f"{user.status:<10} {mfa_status:<6} {last_login:<20}"
                )

            click.echo(f"\nTotal users displayed: {len(users)}")

        elif output_format in ['json', 'csv']:
            # Prepare data for formatting
            user_data = []
            for user in users:
                user_data.append({
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'status': user.status,
                    'mfa_enabled': getattr(user, 'require_mfa', False),
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                })

            # Format and display output
            formatted_output = format_output(user_data, output_format)
            click.echo(formatted_output)

        # Log the action
        if logger:
            filter_info = []
            if role:
                filter_info.append(f"role={role}")
            if status:
                filter_info.append(f"status={status}")

            filter_str = " AND ".join(filter_info) if filter_info else "no filters"
            logger.info("Listed users with %s: %d results", filter_str, len(users))

        return EXIT_SUCCESS

    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("User listing failed: %s", e)
        metrics.increment('user_management.list_users_failed')
        raise click.ClickException(str(e))


@user_cli.command('info')
@click.argument('username')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table',
              help='Output format')
@require_permission('user:read')
def get_user_info(username: str, output_format: str) -> int:
    """
    Show detailed information for a specific user.

    Displays comprehensive information about a user account, including
    profile details, security settings, and account status.

    Args:
        username: Username of the account to view
        output_format: Format for the output (table, json)

    Examples:
        # View user details
        $ flask user info johndoe

        # Get user details in JSON format
        $ flask user info johndoe --format=json
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        if output_format == 'json':
            # Format as JSON
            user_data = {
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'status': user.status,
                'first_name': getattr(user, 'first_name', None),
                'last_name': getattr(user, 'last_name', None),
                'require_mfa': getattr(user, 'require_mfa', False),
                'password_change_required': getattr(user, 'password_change_required', False),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if getattr(user, 'updated_at', None) else None,
            }
            click.echo(format_output(user_data, 'json'))
        else:
            # Format as table
            click.echo(f"\nUser Details for: {user.username}")
            click.echo(f"  Email:          {user.email}")
            click.echo(f"  Role:           {user.role}")
            click.echo(f"  Status:         {user.status}")

            if hasattr(user, 'first_name') and user.first_name:
                click.echo(f"  First Name:     {user.first_name}")
            if hasattr(user, 'last_name') and user.last_name:
                click.echo(f"  Last Name:      {user.last_name}")

            click.echo(f"  MFA Required:   {'Yes' if getattr(user, 'require_mfa', False) else 'No'}")
            click.echo(f"  Password Reset: {'Required' if getattr(user, 'password_change_required', False) else 'Not required'}")
            click.echo(f"  Last Login:     {user.last_login or 'Never'}")
            click.echo(f"  Created At:     {user.created_at or 'Unknown'}")

            if hasattr(user, 'updated_at') and user.updated_at:
                click.echo(f"  Updated At:     {user.updated_at}")

        if logger:
            logger.info("Retrieved user info: %s", username)

        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("Failed to get user info: %s", e)
        metrics.increment('user_management.get_user_info_failed')
        raise click.ClickException(str(e))


@user_cli.command('reset-password')
@click.argument('username')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--temporary/--permanent', default=True,
              help='Mark password as temporary (requires change on next login)')
@require_permission('user:write')
def reset_password(username: str, password: str, temporary: bool) -> int:
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
        temporary: Mark password as temporary, requiring change on next login

    Examples:
        # Reset password with prompts
        $ flask user reset-password johndoe

        # Reset password non-interactively (less secure)
        $ flask user reset-password johndoe --password=newpassword

        # Reset to a permanent password (no change required)
        $ flask user reset-password johndoe --permanent
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        user.set_password(password)

        # Set password change requirement based on the temporary flag
        if hasattr(user, 'password_change_required'):
            user.password_change_required = temporary

        db.session.commit()

        # Track metric
        metrics.increment('user_management.password_reset')

        # Check if logger is defined before using it
        if logger:
            logger.info("Reset password for user: %s", username)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'password_reset',
                details={
                    'username': username,
                    'temporary': temporary
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"Password reset successful for {username}")
        if temporary:
            click.echo("User will be required to change password on next login")

        return EXIT_SUCCESS

    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("Password reset failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.password_reset_failed')
        raise click.ClickException(str(e))


@user_cli.command('change-role')
@click.argument('username')
@click.argument('new_role', type=click.Choice(['user', 'admin', 'operator']))
@click.option('--reason', required=True, help='Reason for role change (for audit purposes)')
@require_permission('user:admin')
def change_role(username: str, new_role: str, reason: str) -> int:
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
        reason: Justification for the role change (required for audit)

    Examples:
        # Promote a user to admin
        $ flask user change-role johndoe admin --reason="Project lead promotion"

        # Demote an admin to regular user
        $ flask user change-role admin_user user --reason="Role rotation"
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        # Additional security check for admin role assignment
        if new_role == 'admin' and user.role != 'admin':
            proceed = confirm_action(
                "Warning: You are granting ADMIN privileges to this user. Continue?",
                default=False
            )
            if not proceed:
                click.echo("Role change cancelled")
                return EXIT_SUCCESS

            # Track sensitive privilege escalation
            metrics.increment('user_management.admin_role_assigned')

        old_role = user.role
        user.role = new_role
        db.session.commit()

        # Track metrics
        metrics.increment('user_management.role_changed')
        metrics.increment(f'user_management.role_assigned.{new_role}')

        # Check if logger is defined before using it
        if logger:
            logger.info("Changed role for %s: %s -> %s (Reason: %s)",
                       username, old_role, new_role, reason)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'role_changed',
                details={
                    'username': username,
                    'old_role': old_role,
                    'new_role': new_role,
                    'reason': reason
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"Role changed from {old_role} to {new_role} for {username}")
        return EXIT_SUCCESS

    except Exception as e:
        # Check if logger is defined before using it
        if logger:
            logger.error("Role change failed: %s", e)

        db.session.rollback()
        metrics.increment('user_management.role_change_failed')
        raise click.ClickException(str(e))


@user_cli.command('deactivate')
@click.argument('username')
@click.option('--reason', required=True, help='Reason for deactivation (for audit purposes)')
@click.option('--force/--no-force', default=False, help='Force deactivation without confirmation')
@require_permission('user:admin')
def deactivate_user(username: str, reason: str, force: bool) -> int:
    """
    Deactivate a user account.

    Deactivates a user account, preventing the user from logging in while
    preserving their data and account history. This is preferable to deletion
    for most situations.

    Args:
        username: Username of the account to deactivate
        reason: Justification for the deactivation (required for audit)
        force: Skip confirmation prompt

    Examples:
        # Deactivate a user account with confirmation prompt
        $ flask user deactivate johndoe --reason="Extended leave"

        # Force deactivate without confirmation
        $ flask user deactivate johndoe --reason="Security violation" --force
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        if user.status == 'inactive':
            click.echo(f"User {username} is already inactive")
            return EXIT_SUCCESS

        # Special handling for admin users
        if user.role == 'admin' and not force:
            proceed = confirm_action(
                f"Warning: You are deactivating an ADMIN user ({username}). Continue?",
                default=False
            )
            if not proceed:
                click.echo("Deactivation cancelled")
                return EXIT_SUCCESS

        # Ask for confirmation unless --force is used
        if not force:
            proceed = confirm_action(f"Deactivate user {username}?", default=True)
            if not proceed:
                click.echo("Deactivation cancelled")
                return EXIT_SUCCESS

        # Keep track of previous status for reporting
        previous_status = user.status

        # Update user status
        user.status = 'inactive'

        # Store deactivation reason if the model supports it
        if hasattr(user, 'deactivation_reason'):
            user.deactivation_reason = reason

        # Store deactivation timestamp if the model supports it
        if hasattr(user, 'deactivated_at'):
            user.deactivated_at = datetime.now()

        db.session.commit()

        # Track metrics
        metrics.increment('user_management.user_deactivated')

        if logger:
            logger.info("Deactivated user: %s (Reason: %s)", username, reason)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'user_deactivated',
                details={
                    'username': username,
                    'previous_status': previous_status,
                    'reason': reason
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"User {username} has been deactivated")
        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("User deactivation failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.deactivation_failed')
        raise click.ClickException(str(e))


@user_cli.command('activate')
@click.argument('username')
@click.option('--reason', required=True, help='Reason for activation (for audit purposes)')
@require_permission('user:admin')
def activate_user(username: str, reason: str) -> int:
    """
    Activate a previously deactivated user account.

    Restores access for a deactivated user account, allowing the user to log in again.

    Args:
        username: Username of the account to activate
        reason: Justification for the activation (required for audit)

    Examples:
        # Activate a user account
        $ flask user activate johndoe --reason="Returned from leave"
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        if user.status == 'active':
            click.echo(f"User {username} is already active")
            return EXIT_SUCCESS

        # Keep track of previous status for reporting
        previous_status = user.status

        # Update user status
        user.status = 'active'

        # Clear deactivation reason if the model supports it
        if hasattr(user, 'deactivation_reason'):
            user.deactivation_reason = None

        # Clear deactivation timestamp if the model supports it
        if hasattr(user, 'deactivated_at'):
            user.deactivated_at = None

        db.session.commit()

        # Track metrics
        metrics.increment('user_management.user_activated')

        if logger:
            logger.info("Activated user: %s (Reason: %s)", username, reason)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'user_activated',
                details={
                    'username': username,
                    'previous_status': previous_status,
                    'reason': reason
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"User {username} has been activated")
        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("User activation failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.activation_failed')
        raise click.ClickException(str(e))


@user_cli.command('delete')
@click.argument('username')
@click.option('--reason', required=True, help='Reason for deletion (for audit purposes)')
@click.option('--force/--no-force', default=False, help='Force deletion without confirmation')
@click.option('--permanent/--soft-delete', default=False,
              help='Permanently remove all user data (default is soft delete)')
@require_permission('user:admin')
def delete_user(username: str, reason: str, force: bool, permanent: bool) -> int:
    """
    Delete a user account.

    Deletes a user account from the system. By default, this performs a "soft delete"
    that preserves the user's data but prevents login. With --permanent flag,
    completely removes the user and all associated data.

    CAUTION: Permanent deletion cannot be undone. Consider deactivation instead.

    Args:
        username: Username of the account to delete
        reason: Justification for the deletion (required for audit)
        force: Skip confirmation prompts
        permanent: Permanently remove all user data (irreversible)

    Examples:
        # Soft-delete a user (default)
        $ flask user delete johndoe --reason="User requested account removal"

        # Permanently delete user and all associated data
        $ flask user delete johndoe --reason="GDPR removal request" --permanent
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        # Extra caution for admin users
        if user.role == 'admin':
            if not force:
                proceed = confirm_action(
                    f"WARNING: You are deleting an ADMIN user ({username}). Continue?",
                    default=False
                )
                if not proceed:
                    click.echo("Deletion cancelled")
                    return EXIT_SUCCESS
            # Always log admin deletions, even with --force
            if logger:
                logger.warning("Deleting admin user: %s", username)

        # Extra warning and confirmation for permanent deletion
        if permanent:
            if not force:
                click.echo("WARNING: Permanent deletion will remove ALL user data and cannot be undone.")
                click.echo("Consider using account deactivation instead.")
                proceed = confirm_action(
                    f"Permanently delete {username} and all associated data?",
                    default=False
                )
                if not proceed:
                    click.echo("Deletion cancelled")
                    return EXIT_SUCCESS
            # Always log permanent deletions, even with --force
            if logger:
                logger.warning("Permanently deleting user: %s", username)

            # Track metrics for permanent deletion
            metrics.increment('user_management.permanent_user_deletion')
        else:
            # Standard confirmation for soft delete
            if not force:
                proceed = confirm_action(f"Delete user {username}?", default=False)
                if not proceed:
                    click.echo("Deletion cancelled")
                    return EXIT_SUCCESS

        # Log audit event before deletion
        try:
            audit_log(
                'user_management',
                'user_deleted',
                details={
                    'username': username,
                    'email': user.email,
                    'role': user.role,
                    'permanent': permanent,
                    'reason': reason
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        # Perform the deletion
        if permanent:
            # Permanent deletion - actually remove the record
            db.session.delete(user)
        else:
            # Soft deletion - mark as deleted but keep the record
            if hasattr(user, 'deleted'):
                user.deleted = True
            if hasattr(user, 'deleted_at'):
                user.deleted_at = datetime.now()
            if hasattr(user, 'deletion_reason'):
                user.deletion_reason = reason

            # For models without explicit soft delete support
            user.status = 'deleted'

            # Anonymize identifiable data if retaining the record
            if hasattr(user, 'anonymize_data'):
                user.anonymize_data()

        db.session.commit()

        # Track metrics
        metrics.increment('user_management.user_deleted')

        # Log the action
        if logger:
            if permanent:
                logger.info("Permanently deleted user: %s (Reason: %s)", username, reason)
            else:
                logger.info("Soft-deleted user: %s (Reason: %s)", username, reason)

        click.echo(f"User {username} has been {'permanently ' if permanent else ''}deleted")
        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("User deletion failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.deletion_failed')
        raise click.ClickException(str(e))


@user_cli.command('mfa')
@click.argument('username')
@click.option('--enable/--disable', required=True, help='Enable or disable MFA requirement')
@click.option('--reason', required=True, help='Reason for MFA change (for audit purposes)')
@require_permission('user:admin')
def manage_mfa(username: str, enable: bool, reason: str) -> int:
    """
    Manage multi-factor authentication requirement for a user.

    Enables or disables the MFA requirement for a specified user account.
    When MFA is required, the user must set up and use a second authentication
    factor (like a TOTP authenticator app) to log in.

    Args:
        username: Username of the account to modify
        enable: Whether to enable (true) or disable (false) MFA
        reason: Justification for the change (required for audit)

    Examples:
        # Enable MFA requirement
        $ flask user mfa johndoe --enable --reason="Security policy update"

        # Disable MFA requirement
        $ flask user mfa johndoe --disable --reason="Temporary exception for recovery"
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        # Check if the model supports MFA settings
        if not hasattr(user, 'require_mfa'):
            raise click.ClickException("MFA settings are not supported in the current user model")

        # Check if the setting is already correct
        if user.require_mfa == enable:
            status = "enabled" if enable else "disabled"
            click.echo(f"MFA is already {status} for user {username}")
            return EXIT_SUCCESS

        # Update MFA setting
        user.require_mfa = enable

        # If enabling MFA, reset any existing MFA configurations to force setup
        if enable and hasattr(user, 'mfa_secret'):
            user.mfa_secret = None

        # If disabling MFA, clear any existing MFA configurations
        if not enable:
            if hasattr(user, 'mfa_secret'):
                user.mfa_secret = None
            if hasattr(user, 'mfa_backup_codes'):
                user.mfa_backup_codes = None

        db.session.commit()

        # Track metrics
        if enable:
            metrics.increment('user_management.mfa_enabled')
        else:
            metrics.increment('user_management.mfa_disabled')

        # Log the action
        if logger:
            if enable:
                logger.info("Enabled MFA for user: %s (Reason: %s)", username, reason)
            else:
                logger.info("Disabled MFA for user: %s (Reason: %s)", username, reason)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'mfa_setting_changed',
                details={
                    'username': username,
                    'enabled': enable,
                    'reason': reason
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        status = "enabled" if enable else "disabled"
        click.echo(f"MFA requirement {status} for user {username}")

        # Display next steps
        if enable:
            click.echo("User will need to set up MFA on next login")

        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("MFA management failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.mfa_management_failed')
        raise click.ClickException(str(e))


@user_cli.command('bulk-import')
@click.argument('file', type=click.Path(exists=True, readable=True))
@click.option('--format', 'file_format', type=click.Choice(['csv', 'json']), default='csv',
              help='File format (csv or json)')
@click.option('--update/--no-update', default=False,
              help='Update existing users instead of skipping')
@click.option('--dry-run/--execute', default=True,
              help='Preview changes without applying them')
@require_permission('user:admin')
def bulk_import(file: str, file_format: str, update: bool, dry_run: bool) -> int:
    """
    Import multiple users from a file.

    Bulk imports user accounts from a CSV or JSON file. By default, runs in dry-run
    mode to preview changes without applying them.

    The import file must contain the following columns/fields:
    - username: Unique username (required)
    - email: Email address (required)
    - role: User role (user, admin, or operator)
    - password: Initial password (if omitted, a random password will be generated)

    Optional fields:
    - first_name: User's first name
    - last_name: User's last name
    - status: Account status (defaults to 'active')
    - require_mfa: Whether MFA is required (true/false)

    Args:
        file: Path to the import file
        file_format: Format of the import file (csv or json)
        update: Update existing users instead of skipping them
        dry_run: Preview changes without applying them

    Examples:
        # Preview import from CSV (dry-run mode)
        $ flask user bulk-import users.csv

        # Execute import from JSON
        $ flask user bulk-import users.json --execute

        # Import and update existing users
        $ flask user bulk-import users.csv --update --execute
    """
    import csv
    import json
    import secrets
    from pathlib import Path

    try:
        # Track stats
        stats = {
            'total': 0,
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
        }

        # Read the import file
        users_data = []
        file_path = Path(file)

        if file_format == 'csv':
            with open(file_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    users_data.append({k.strip().lower(): v.strip() for k, v in row.items()})
        else:  # JSON
            with open(file_path, 'r') as jsonfile:
                users_data = json.load(jsonfile)

        if not users_data:
            raise click.ClickException("No user data found in the import file")

        stats['total'] = len(users_data)

        # Validate the data and perform import
        if dry_run:
            click.echo(f"DRY RUN: Preview of user import ({stats['total']} users)")
            click.echo("No changes will be applied to the database")
            click.echo()

        # Process each user
        for i, user_data in enumerate(users_data, 1):
            # Extract and validate required fields
            username = user_data.get('username', '')
            email = user_data.get('email', '')

            if not username or not email:
                click.echo(f"Error in record #{i}: Missing required fields (username and email)")
                stats['errors'] += 1
                continue

            # Check if user exists
            existing_user = User.query.filter_by(username=username).first()

            # Handle existing users based on update flag
            if existing_user:
                if not update:
                    if dry_run:
                        click.echo(f"Skip: User '{username}' already exists")
                    stats['skipped'] += 1
                    continue

                # Update mode
                action = "Update"
                mode = "(updating existing user)"
            else:
                action = "Create"
                mode = "(new user)"

            # Extract optional fields with defaults
            role = user_data.get('role', 'user')
            status = user_data.get('status', 'active')

            # Validate role
            if role not in ['user', 'admin', 'operator']:
                click.echo(f"Error in record #{i}: Invalid role '{role}' (must be user, admin, or operator)")
                stats['errors'] += 1
                continue

            # Display import information in dry run mode
            if dry_run:
                click.echo(f"{action}: {username} ({email}) - Role: {role} {mode}")
                if role == 'admin':
                    click.echo(f"  Warning: User will have ADMIN privileges")
                continue

            # Apply changes (when not in dry-run mode)
            try:
                if existing_user:
                    # Update existing user
                    if 'email' in user_data and user_data['email']:
                        existing_user.email = email
                    if 'role' in user_data and user_data['role']:
                        existing_user.role = role
                    if 'status' in user_data and user_data['status']:
                        existing_user.status = status
                    if 'first_name' in user_data and user_data['first_name']:
                        existing_user.first_name = user_data['first_name']
                    if 'last_name' in user_data and user_data['last_name']:
                        existing_user.last_name = user_data['last_name']
                    if 'require_mfa' in user_data:
                        require_mfa_val = user_data['require_mfa']
                        if isinstance(require_mfa_val, str):
                            require_mfa_val = require_mfa_val.lower() in ('true', '1', 'yes')
                        existing_user.require_mfa = require_mfa_val

                    # Update password if provided
                    if 'password' in user_data and user_data['password']:
                        existing_user.set_password(user_data['password'])
                        if hasattr(existing_user, 'password_change_required'):
                            existing_user.password_change_required = True

                    stats['updated'] += 1
                else:
                    # Create new user
                    new_user = User()
                    new_user.username = username
                    new_user.email = email
                    new_user.role = role
                    new_user.status = status

                    # Optional fields
                    if 'first_name' in user_data:
                        new_user.first_name = user_data.get('first_name')
                    if 'last_name' in user_data:
                        new_user.last_name = user_data.get('last_name')
                    if 'require_mfa' in user_data:
                        require_mfa_val = user_data['require_mfa']
                        if isinstance(require_mfa_val, str):
                            require_mfa_val = require_mfa_val.lower() in ('true', '1', 'yes')
                        new_user.require_mfa = require_mfa_val

                    # Set password - if not provided, generate a random one
                    password = user_data.get('password', secrets.token_urlsafe(12))
                    new_user.set_password(password)

                    # Set password change requirement
                    if hasattr(new_user, 'password_change_required'):
                        new_user.password_change_required = True

                    # Set creation timestamp if supported
                    if hasattr(new_user, 'created_at'):
                        new_user.created_at = datetime.now()

                    db.session.add(new_user)
                    stats['created'] += 1

            except Exception as user_error:
                click.echo(f"Error processing user {username}: {str(user_error)}")
                stats['errors'] += 1

        # Commit all changes at once (unless in dry-run mode)
        if not dry_run:
            db.session.commit()

            # Log the bulk operation
            if logger:
                logger.info("Bulk user import: %d created, %d updated, %d skipped, %d errors",
                           stats['created'], stats['updated'], stats['skipped'], stats['errors'])

            # Log audit event
            try:
                audit_log(
                    'user_management',
                    'bulk_user_import',
                    details={
                        'source_file': str(file_path),
                        'created': stats['created'],
                        'updated': stats['updated'],
                        'skipped': stats['skipped'],
                        'errors': stats['errors']
                    }
                )
            except Exception:
                # Don't fail if audit logging fails
                pass

        # Display summary
        click.echo("\nImport Summary:")
        click.echo(f"  Total records: {stats['total']}")
        if dry_run:
            click.echo(f"  Would create: {stats['total'] - stats['skipped'] - stats['errors']}")
            click.echo(f"  Would skip: {stats['skipped']}")
            click.echo(f"  Errors: {stats['errors']}")
            click.echo("\nThis was a dry run. Use --execute to apply changes.")
        else:
            click.echo(f"  Created: {stats['created']}")
            click.echo(f"  Updated: {stats['updated']}")
            click.echo(f"  Skipped: {stats['skipped']}")
            click.echo(f"  Errors: {stats['errors']}")

        return EXIT_SUCCESS if stats['errors'] == 0 else EXIT_ERROR

    except Exception as e:
        if logger:
            logger.error("Bulk user import failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.bulk_import_failed')
        raise click.ClickException(str(e))


@user_cli.command('export')
@click.option('--output', required=True, type=click.Path(writable=True),
              help='Output file path')
@click.option('--format', 'file_format', type=click.Choice(['csv', 'json']), default='csv',
              help='Output format')
@click.option('--role', help='Filter by role')
@click.option('--status', help='Filter by status')
@click.option('--include-sensitive/--exclude-sensitive', default=False,
              help='Include sensitive fields (hashed passwords, MFA data)')
@require_permission('user:admin')
def export_users(output: str, file_format: str, role: str = None,
                status: str = None, include_sensitive: bool = False) -> int:
    """
    Export users to a file.

    Exports user data to a CSV or JSON file. By default, sensitive information
    is excluded from the export.

    Args:
        output: Path to the output file
        file_format: Format of the output file (csv or json)
        role: Filter users by role
        status: Filter users by status
        include_sensitive: Include sensitive fields in the export

    Examples:
        # Export all users to CSV
        $ flask user export --output=users.csv

        # Export active admins to JSON
        $ flask user export --output=admins.json --format=json --role=admin --status=active
    """
    import csv
    import json
    from pathlib import Path

    try:
        # Build query with filters
        query = User.query
        if role:
            query = query.filter_by(role=role)
        if status:
            query = query.filter_by(status=status)

        # Fetch users
        users = query.all()

        if not users:
            click.echo("No users found matching the criteria")
            return EXIT_SUCCESS

        # Prepare output file
        output_path = Path(output)

        # Define the fields to export
        fields = ['username', 'email', 'role', 'status', 'first_name', 'last_name']

        # Add fields that may not be available in all User models
        optional_fields = [
            'created_at', 'updated_at', 'last_login', 'require_mfa',
            'password_change_required'
        ]

        # Include sensitive fields if requested
        if include_sensitive:
            sensitive_fields = ['password_hash', 'mfa_secret', 'mfa_backup_codes']
            optional_fields.extend(sensitive_fields)

        # Prepare data for export
        export_data = []
        for user in users:
            user_data = {}

            # Add required fields
            for field in fields:
                user_data[field] = getattr(user, field, None)

            # Add optional fields if they exist
            for field in optional_fields:
                if hasattr(user, field):
                    value = getattr(user, field)

                    # Format datetime objects
                    if isinstance(value, datetime):
                        value = value.isoformat()

                    user_data[field] = value

            export_data.append(user_data)

        # Write to the output file
        if file_format == 'csv':
            with open(output_path, 'w', newline='') as csvfile:
                if not export_data:
                    click.echo("No data to export")
                    return EXIT_SUCCESS

                # Use all available keys from the first user as fieldnames
                fieldnames = list(export_data[0].keys())

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for user_data in export_data:
                    writer.writerow(user_data)
        else:  # JSON
            with open(output_path, 'w') as jsonfile:
                json.dump(export_data, jsonfile, indent=2)

        # Log the export action
        if logger:
            logger.info("Exported %d users to %s", len(users), output)

        # Log audit event
        try:
            audit_log(
                'user_management',
                'users_exported',
                details={
                    'output_file': str(output_path),
                    'count': len(users),
                    'format': file_format,
                    'role_filter': role,
                    'status_filter': status,
                    'sensitive_data': include_sensitive
                }
            )
        except Exception:
            # Don't fail if audit logging fails
            pass

        click.echo(f"Exported {len(users)} users to {output}")
        return EXIT_SUCCESS

    except Exception as e:
        if logger:
            logger.error("User export failed: %s", e)
        metrics.increment('user_management.export_failed')
        raise click.ClickException(str(e))


@user_cli.command('lock')
@click.argument('username')
@click.option('--reason', required=True, help='Reason for locking (for audit purposes)')
@click.option('--duration', type=int, help='Lock duration in minutes (temporary lock)')
@require_permission('user:admin')
def lock_account(username: str, reason: str, duration: int = None) -> int:
    """
    Lock a user account.

    Locks a user account to prevent login while maintaining the account in the system.
    This is useful for temporary security measures or account recovery procedures.

    Args:
        username: Username of the account to lock
        reason: Justification for the lock (required for audit)
        duration: Optional lock duration in minutes (temporary lock)

    Examples:
        # Lock an account indefinitely
        $ flask user lock johndoe --reason="Suspicious activity detected"

        # Lock an account for 60 minutes
        $ flask user lock johndoe --reason="Password reset requested" --duration=60
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        # Check if the account can be locked
        if hasattr(user, 'locked') or hasattr(user, 'status'):
            # Check if already locked
            if (hasattr(user, 'locked') and user.locked) or (hasattr(user, 'status') and user.status == 'locked'):
                click.echo(f"User account {username} is already locked")
                return EXIT_SUCCESS

            # Lock the account
            if hasattr(user, 'locked'):
                user.locked = True

            if hasattr(user, 'status'):
                user.status = 'locked'

            # Set lock timestamp
            if hasattr(user, 'locked_at'):
                user.locked_at = datetime.now()

            # Set lock reason
            if hasattr(user, 'lock_reason'):
                user.lock_reason = reason

            # Set lock expiry if duration provided
            if duration and hasattr(user, 'lock_expires_at'):
                from datetime import timedelta
                user.lock_expires_at = datetime.now() + timedelta(minutes=duration)

            # Commit changes
            db.session.commit()

            # Log action
            if logger:
                if duration:
                    logger.info("Locked account %s for %d minutes (Reason: %s)",
                               username, duration, reason)
                else:
                    logger.info("Locked account %s indefinitely (Reason: %s)",
                               username, reason)

            # Track metrics
            metrics.increment('user_management.account_locked')

            # Log audit event
            try:
                audit_log(
                    'user_management',
                    'account_locked',
                    details={
                        'username': username,
                        'reason': reason,
                        'duration_minutes': duration,
                        'temporary': duration is not None
                    }
                )
            except Exception:
                # Don't fail if audit logging fails
                pass

            # Success message
            if duration:
                click.echo(f"Account {username} locked for {duration} minutes")
            else:
                click.echo(f"Account {username} locked indefinitely")

            return EXIT_SUCCESS
        else:
            raise click.ClickException("Lock functionality not supported by the User model")

    except Exception as e:
        if logger:
            logger.error("Account lock failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.account_lock_failed')
        raise click.ClickException(str(e))


@user_cli.command('unlock')
@click.argument('username')
@click.option('--reason', required=True, help='Reason for unlocking (for audit purposes)')
@require_permission('user:admin')
def unlock_account(username: str, reason: str) -> int:
    """
    Unlock a user account.

    Unlocks a previously locked user account, allowing the user to log in again.

    Args:
        username: Username of the account to unlock
        reason: Justification for the unlock (required for audit)

    Examples:
        # Unlock a user account
        $ flask user unlock johndoe --reason="Identity verified"
    """
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException(f"User {username} not found")

        # Check if the account can be unlocked
        if hasattr(user, 'locked') or hasattr(user, 'status'):
            # Check if already unlocked
            if (hasattr(user, 'locked') and not user.locked) or (hasattr(user, 'status') and user.status != 'locked'):
                click.echo(f"User account {username} is not locked")
                return EXIT_SUCCESS

            # Unlock the account
            if hasattr(user, 'locked'):
                user.locked = False

            if hasattr(user, 'status') and user.status == 'locked':
                user.status = 'active'

            # Clear lock timestamp
            if hasattr(user, 'locked_at'):
                user.locked_at = None

            # Clear lock reason
            if hasattr(user, 'lock_reason'):
                user.lock_reason = None

            # Clear lock expiry
            if hasattr(user, 'lock_expires_at'):
                user.lock_expires_at = None

            # Commit changes
            db.session.commit()

            # Log action
            if logger:
                logger.info("Unlocked account %s (Reason: %s)", username, reason)

            # Track metrics
            metrics.increment('user_management.account_unlocked')

            # Log audit event
            try:
                audit_log(
                    'user_management',
                    'account_unlocked',
                    details={
                        'username': username,
                        'reason': reason
                    }
                )
            except Exception:
                # Don't fail if audit logging fails
                pass

            # Success message
            click.echo(f"Account {username} unlocked successfully")
            return EXIT_SUCCESS
        else:
            raise click.ClickException("Unlock functionality not supported by the User model")

    except Exception as e:
        if logger:
            logger.error("Account unlock failed: %s", e)
        db.session.rollback()
        metrics.increment('user_management.account_unlock_failed')
        raise click.ClickException(str(e))
