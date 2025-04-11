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
    """Create new user with role."""
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
    """List users with optional filters."""
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
    """Reset user password."""
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
    """Change user role."""
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
