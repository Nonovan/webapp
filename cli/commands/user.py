import os
import click
from flask.cli import AppGroup
from core.loggings import get_logger
from extensions import db
from models import User

logger = get_logger(__name__) or click.get_current_context().obj.get('logger', None)
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
        user = User(
            username=username,
            email=email,
            role=role,
            status='active'
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        logger.info(f"Created user: {username} with role: {role}")
        click.echo(f"User {username} created successfully")
    except Exception as e:
        logger.error(f"User creation failed: {e}")
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
        logger.error(f"User listing failed: {e}")
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
        logger.info(f"Reset password for user: {username}")
        click.echo(f"Password reset successful for {username}")
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
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
        logger.info(f"Changed role for {username}: {old_role} -> {new_role}")
        click.echo(f"Role changed from {old_role} to {new_role} for {username}")
    except Exception as e:
        logger.error(f"Role change failed: {e}")
        db.session.rollback()
        raise click.ClickException(str(e))
