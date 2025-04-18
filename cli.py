"""
Command-line interface module for the myproject application.

This module provides command-line capabilities for managing various aspects of the
application including server execution, database operations, and system health checks.
It uses Flask's CLI integration with Click to create a rich command-line experience
with proper argument parsing, help documentation, and error handling.

The CLI commands enable:
- Running the application server with customizable host and port settings
- Database initialization and seeding for development and testing
- Database backup and restoration for data management
- System health checks to verify application dependencies and configuration
- Deployment preparation and maintenance tasks

The CLI interface is accessible through the 'flask' command when the application
is installed, or directly through this module when executed as a script.
"""

from datetime import datetime
import os
import click
from flask.cli import FlaskGroup

from app import create_app
from extensions import db
from models import User


cli = FlaskGroup(create_app=create_app)

@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug/--no-debug', default=False, help='Enable debug mode')
def run(host: str, port: int, debug: bool) -> None:
    """
    Run the application server.

    Starts the Flask development server with the specified host, port, and debug settings.
    This command is intended for development and testing purposes and should not be
    used for production deployments.

    Args:
        host (str): The hostname or IP address to bind the server to
        port (int): The port number to listen on
        debug (bool): Whether to run the server in debug mode

    Example:
        $ flask run --host=0.0.0.0 --port=8000 --debug
    """
    try:
        app = create_app()
        app.run(host=host, port=port, debug=debug)
    except (RuntimeError, KeyError, db.exc.SQLAlchemyError) as e:
        click.echo(f'Error: {e}', err=True)
        exit(1)

@cli.command()
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
def init_db(seed: bool) -> None:
    """
    Initialize the database.

    Creates all database tables defined in the application models and optionally
    seeds the database with initial data. This command should be run when setting up
    the application for the first time or after significant model changes.

    Args:
        seed (bool): Whether to populate the database with initial data

    Example:
        $ flask init_db --seed
    """
    try:
        app = create_app()
        
        with app.app_context():
            db.create_all()
            click.echo("Database tables created")
            
            if seed:
                # Import models for seeding
                
                # Create admin user if it doesn't exist
                admin = User.query.filter_by(username='admin').first()
                if not admin:
                    admin = User(
                        username='admin',
                        email='admin@example.com',
                        role='admin'
                    )
                    admin.set_password('AdminPassword123!')
                    db.session.add(admin)
                    db.session.commit()
                    click.echo("Admin user created")
                
                click.echo("Database seeded successfully")
    except (RuntimeError, KeyError, db.exc.SQLAlchemyError) as e:
        click.echo(f'Error initializing database: {e}', err=True)
        exit(1)

@cli.command()
@click.option('--backup-dir', default='./backups', help='Backup directory')
def backup_db(backup_dir: str) -> None:
    """
    Backup database.

    Creates a SQL dump of the current database state and saves it to the specified
    directory with a timestamp. This command requires database credentials to be
    properly configured in environment variables.

    Args:
        backup_dir (str): Directory where the backup file will be stored

    Example:
        $ flask backup_db --backup-dir=/var/backups/myproject
    """
    try:
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{backup_dir}/backup_{timestamp}.sql'
        os.system(f'pg_dump $DATABASE_URL > {filename}')
        click.echo(f'Database backed up to {filename}')
    except (OSError, RuntimeError) as e:
        click.echo(f'Backup failed: {e}', err=True)
        exit(1)

@cli.command()
def check() -> None:
    """
    Check application health.

    Performs a comprehensive health check of the application, verifying:
    - Database connectivity
    - Required environment variables
    - Configuration settings

    This command is useful for validating deployments and troubleshooting
    configuration issues.

    Example:
        $ flask check
    """
    try:
        app = create_app()
        with app.app_context():
            # Check database
            db.session.execute('SELECT 1')
            click.echo('Database: OK')

            # Check environment
            required_vars = ['SECRET_KEY', 'DATABASE_URL']
            missing = [var for var in required_vars if not os.getenv(var)]
            if missing:
                raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")
            click.echo('Environment: OK')

            click.echo('Health check passed.')
    except (RuntimeError, db.exc.SQLAlchemyError, KeyError, OSError) as e:
        click.echo(f'Health check failed: {e}', err=True)
        exit(1)

@cli.command()
@click.argument('username')
def unlock_account(username):
    """
    Unlock a user account that has been locked due to failed login attempts.

    Args:
        username: Username of the account to unlock
    """
    try:
        app = create_app()
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            
            if not user:
                click.echo(f"User '{username}' not found.")
                return
                
            if user.is_locked():
                user.locked_until = None
                user.failed_login_count = 0
                db.session.commit()
                click.echo(f"Account for '{username}' has been successfully unlocked.")
            else:
                click.echo(f"Account for '{username}' is not locked.")
    except (RuntimeError, KeyError, db.exc.SQLAlchemyError) as e:
        click.echo(f"Error unlocking account: {e}")

if __name__ == '__main__':
    cli()
