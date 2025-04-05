import os
import logging
import uuid
from datetime import timedelta, datetime
from typing import Optional

from flask import Flask, request, g, jsonify
from config import config
from extensions import db, migrate, csrf, limiter, cors, metrics

def validate_environment():
    required_vars = ['SECRET_KEY', 'DATABASE_URL']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

def setup_logging(app):
    formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    app.logger.handlers = [handler]
    app.logger.setLevel(app.config['LOG_LEVEL'])

def register_blueprints(app):
    """Register Flask blueprints."""
    from views.monitoring.routes import monitoring_bp
    from views.auth.routes import auth_bp
    from views.main.routes import main_bp
    
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

def create_app(config_name='default'):
    validate_environment()
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    app.uptime = datetime.utcnow()
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    cors.init_app(app)
    metrics.init_app(app)
    
    setup_logging(app)
    
    @app.before_request
    def before_request():
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        g.start_time = datetime.utcnow()

    @app.after_request
    def after_request(response):
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{(datetime.utcnow() - g.start_time).total_seconds():.3f}s',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        })
        return response

    @app.route('/health')
    def health_check():
        return {
            'status': 'healthy',
            'version': app.config.get('VERSION', '1.0.0'),
            'database': db.engine.execute('SELECT 1').scalar() == 1,
            'uptime': str(datetime.utcnow() - app.uptime)
        }

    register_blueprints(app)
    
    return app

def cli():
    """Flask application CLI."""
    import click
    import psutil
    from datetime import datetime
    
    @click.group()
    def cli_group():
        """Flask application management commands."""
        pass

    # Database commands
    @cli_group.group()
    def db():
        """Database management commands."""
        pass

    @db.command()
    @click.option('--env', default='development', help='Environment to initialize')
    @click.option('--seed/--no-seed', default=False, help='Seed initial data')
    def init(env, seed):
        """Initialize database with progress."""
        app = create_app(env)
        with app.app_context():
            steps = 5 if seed else 4
            with click.progressbar(length=steps, label='Initializing database') as bar:
                try:
                    # Verify environment
                    validate_environment()
                    bar.update(1)
                    
                    # Create tables
                    db.create_all()
                    bar.update(1)
                    
                    # Verify migrations
                    from flask_migrate import current
                    revision = current()
                    bar.update(1)
                    
                    # Verify connectivity
                    db.session.execute('SELECT 1')
                    bar.update(1)
                    
                    if seed:
                        # Add initial data
                        # TODO: Add seeding logic
                        bar.update(1)
                    
                    click.echo('Database initialized successfully')
                    click.echo(f'Current revision: {revision}')
                except Exception as e:
                    click.echo(f'Database init failed: {e}', err=True)
                    exit(1)

    @db.command()
    @click.option('--env', default='development', help='Environment to migrate')
    def migrate(env):
        """Run database migrations."""
        app = create_app(env)
        with app.app_context():
            from flask_migrate import upgrade, current
            try:
                current_rev = current()
                click.echo(f'Current revision: {current_rev}')
                
                with click.progressbar(length=100, label='Running migrations') as bar:
                    upgrade()
                    bar.update(100)
                click.echo('Migrations completed successfully')
            except Exception as e:
                click.echo(f'Migration failed: {e}', err=True)
                exit(1)

    @db.command()
    @click.option('--backup-dir', default='./backups', help='Backup directory')
    def backup(backup_dir):
        """Backup database with compression."""
        try:
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'{backup_dir}/backup_{timestamp}.sql.gz'
            click.echo(f'Creating backup: {filename}')
            result = os.system(f'pg_dump $DATABASE_URL | gzip > {filename}')
            if result == 0:
                click.echo('Backup completed successfully')
            else:
                click.echo('Backup failed', err=True)
                exit(1)
        except Exception as e:
            click.echo(f'Backup failed: {e}', err=True)
            exit(1)

    @db.command()
    @click.argument('backup_file')
    def restore(backup_file):
        """Restore database from backup with progress."""
        if not os.path.exists(backup_file):
            click.echo(f'Backup file not found: {backup_file}', err=True)
            exit(1)
        try:
            click.echo('Starting database restore...')
            with click.progressbar(length=100, label='Restoring database') as bar:
                if backup_file.endswith('.gz'):
                    os.system(f'gunzip -c {backup_file} | psql $DATABASE_URL')
                else:
                    os.system(f'psql $DATABASE_URL < {backup_file}')
                bar.update(100)
            click.echo('Restore completed successfully')
        except Exception as e:
            click.echo(f'Restore failed: {e}', err=True)
            exit(1)

    # User command group
    @cli_group.group()
    def user():
        """User management commands."""
        pass

    @user.command(name='create')
    @click.option('--username', prompt=True)
    @click.option('--password', prompt=True, hide_input=True)
    def create_user(username, password):
        """Create new user."""
        app = create_app()
        with app.app_context():
            if User.query.filter_by(username=username).first():
                click.echo('Error: Username already exists')
                return
            user = User(username=username, role='user')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            click.echo(f'User {username} created successfully')

    @user.command(name='list')
    def list_users():
        """List all users."""
        app = create_app()
        with app.app_context():
            users = User.query.all()
            click.echo('\nUser List:')
            for user in users:
                click.echo(f'  {user.username} (Role: {user.role})')

    # System command group
    @cli_group.group()
    def system():
        """System management commands."""
        pass

    @system.command()
    def health():
        """Comprehensive system health check with progress."""
        app = create_app()
        with app.app_context():
            with click.progressbar(length=5, label='Running health checks') as bar:
                try:
                    # Database connectivity
                    db.session.execute('SELECT 1')
                    click.echo('  Database: Connected')
                    bar.update(1)
                    
                    # Migration status
                    from flask_migrate import current
                    revision = current()
                    click.echo(f'  Migration: {revision}')
                    bar.update(1)
                    
                    # System metrics
                    click.echo(f'  Users: {User.query.count()}')
                    bar.update(1)
                    
                    # Database size
                    db_size = db.session.execute(
                        "SELECT pg_size_pretty(pg_database_size(current_database()))"
                    ).scalar()
                    click.echo(f'  DB Size: {db_size}')
                    bar.update(1)
                    
                    # Resource usage
                    import psutil
                    memory = psutil.Process().memory_info().rss / 1024 / 1024
                    click.echo(f'  Memory: {memory:.1f} MB')
                    click.echo(f'  Uptime: {datetime.utcnow() - app.uptime}')
                    bar.update(1)
                    
                except Exception as e:
                    click.echo(f'Health check failed: {e}', err=True)
                    exit(1)

    @system.command()
    def status():
        """Show detailed application status."""
        app = create_app()
        with app.app_context():
            click.echo('\nApplication Status:')
            click.echo(f'  Version: {app.config.get("VERSION", "1.0.0")}')
            click.echo(f'  Environment: {app.config.get("ENV")}')
            click.echo(f'  Debug: {app.debug}')
            click.echo(f'  Database: {app.config.get("SQLALCHEMY_DATABASE_URI")}')
            click.echo(f'  Users: {User.query.count()}')
            click.echo(f'  Uptime: {datetime.utcnow() - app.uptime}')

    # Monitoring command group
    @cli_group.group()
    def monitor():
        """Monitoring commands."""
        pass

    @monitor.command()
    @click.option('--detailed/--simple', default=False, help='Show detailed metrics')
    def metrics(detailed):
        """Show application metrics."""
        app = create_app()
        with app.app_context():
            click.echo('\nApplication Metrics:')
            click.echo(f'\nDatabase:')
            click.echo(f'  - Size: {db.session.execute("SELECT pg_size_pretty(pg_database_size(current_database()))").scalar()}')
            click.echo(f'  - Tables: {len(db.metadata.tables)}')
            click.echo(f'  - Connections: {len(db.engine.pool._channels)}')
            
            click.echo(f'\nUsers:')
            click.echo(f'  - Total: {User.query.count()}')
            click.echo(f'  - Active: {User.query.filter_by(status="active").count()}')
            
            if detailed:
                click.echo(f'\nSystem:')
                click.echo(f'  - Memory: {psutil.Process().memory_info().rss / 1024 / 1024:.1f} MB')
                click.echo(f'  - CPU Usage: {psutil.cpu_percent()}%')
                click.echo(f'  - Disk Usage: {psutil.disk_usage("/").percent}%')
            
            click.echo(f'\nApplication:')
            click.echo(f'  - Uptime: {datetime.utcnow() - app.uptime}')
            click.echo(f'  - Environment: {app.config.get("ENV")}')
            click.echo(f'  - Debug: {app.debug}')

    @monitor.command()
    @click.option('--lines', default=100, help='Number of lines to show')
    @click.option('--level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO')
    def logs(lines, level):
        """Show application logs with filtering."""
        app = create_app()
        with app.app_context():
            click.echo(f'Application logs (Level: {level}, Lines: {lines}):')
            for handler in app.logger.handlers:
                handler.flush()
                handler.stream.seek(0)
                logs = handler.stream.readlines()
                filtered_logs = [log for log in logs if level in log]
                for log in filtered_logs[-lines:]:
                    click.echo(log.strip())

    return cli_group

if __name__ == '__main__':
    cli()