from datetime import datetime
import os
import click
from flask.cli import FlaskGroup
from app import create_app
from extensions import db

cli = FlaskGroup(create_app=create_app)

@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug/--no-debug', default=False, help='Enable debug mode')
def run(host, port, debug):
    """Run the application server."""
    try:
        app = create_app()
        app.run(host=host, port=port, debug=debug)
    except Exception as e:
        click.echo(f'Error: {e}', err=True)
        exit(1)

@cli.command()
@click.option('--seed/--no-seed', default=False, help='Seed initial data')
def init_db(seed):
    """Initialize the database."""
    try:
        with create_app().app_context():
            db.create_all()
            if seed:
                # Add seeding logic here
                pass
            click.echo('Database initialized successfully.')
    except Exception as e:
        click.echo(f'Error initializing database: {e}', err=True)
        exit(1)

@cli.command()
@click.option('--backup-dir', default='./backups', help='Backup directory')
def backup_db(backup_dir):
    """Backup database."""
    try:
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{backup_dir}/backup_{timestamp}.sql'
        os.system(f'pg_dump $DATABASE_URL > {filename}')
        click.echo(f'Database backed up to {filename}')
    except Exception as e:
        click.echo(f'Backup failed: {e}', err=True)
        exit(1)

@cli.command()
def check():
    """Check application health."""
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
    except Exception as e:
        click.echo(f'Health check failed: {e}', err=True)
        exit(1)

if __name__ == '__main__':
    cli()
