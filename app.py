"""
Main application entry point for the myproject Flask application.

This module handles the application initialization, configuration loading,
and environment validation. It serves as the WSGI entry point and provides
CLI commands for administrative tasks.

The application uses a factory pattern for initialization to allow for
proper extension setup and blueprint registration. Security checks are
performed before initialization to ensure proper configuration.

Key responsibilities:
- Environment validation for security-critical variables
- Application logging setup
- Blueprint registration for routing
- Database initialization commands
- Application startup sequence
- Security monitoring initialization
"""

import logging
import os
from datetime import datetime, timedelta
from flask import Flask, session, flash, redirect, url_for, request
import click
from sqlalchemy.exc import SQLAlchemyError

from core.factory import create_app
from extensions import db
from models.audit_log import AuditLog
from core.seeder import seed_database, seed_development_data
from core.utils import log_event

# Security constants
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
    'JWT_SECRET_KEY',
    'CSRF_SECRET_KEY',
    'SESSION_KEY'
]

def validate_environment() -> None:
    """
    Validate required environment variables are set.
    
    This function ensures that critical security-related environment variables
    are properly set before the application starts, preventing insecure
    configurations from being deployed.
    
    Raises:
        RuntimeError: If any required variables are missing
    """
    missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing security variables: {', '.join(missing)}")

def setup_logging(flask_app: Flask) -> None:
    """
    Configure application logging with formatting and handlers.
    
    Args:
        flask_app: Flask application instance
    """
    formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    flask_app.logger.handlers = [handler]
    flask_app.logger.setLevel(flask_app.config['LOG_LEVEL'])

# Initialize application
try:
    validate_environment()
    app = create_app()
except SQLAlchemyError as e:
    logging.critical("Application initialization failed: %s", e)
    raise

@app.before_request
def validate_session():
    """
    Validate user session on each request.
    
    Checks session age, user agent consistency, and IP address changes.
    This function implements security controls to detect session hijacking
    and enforce session timeouts.
    
    Returns:
        Response or None: Redirect to login if session is invalid, None otherwise
    """
    if 'user_id' in session:
        # Check for session age
        if 'last_active' in session:
            last_active = datetime.fromisoformat(session['last_active'])
            if datetime.utcnow() - last_active > timedelta(minutes=30):
                # Log session timeout
                log_event('session_timeout', 
                         f"Session timed out for user {session['user_id']}", 
                         user_id=session.get('user_id'),
                         ip_address=request.remote_addr,
                         severity='info')
                
                # Session expired
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('auth.login'))
        
        # Check for IP address change
        if 'ip_address' in session and session['ip_address'] != request.remote_addr:
            # Potential session hijacking
            log_event('session_ip_change', 
                     f"IP address changed during session: {session['ip_address']} -> {request.remote_addr}", 
                     user_id=session.get('user_id'),
                     ip_address=request.remote_addr,
                     severity='warning')
            
            # Record security audit event
            AuditLog.create(
                event_type=AuditLog.EVENT_SESSION_ANOMALY,
                description=f"IP address changed: {session['ip_address']} -> {request.remote_addr}",
                user_id=session.get('user_id'),
                ip_address=request.remote_addr,
                severity=AuditLog.SEVERITY_WARNING
            )
            
            # For critical systems, could invalidate the session here
            if app.config.get('STRICT_SESSION_SECURITY', False):
                session.clear()
                flash('Your session has been terminated due to a security concern.', 'danger')
                return redirect(url_for('auth.login'))
        
        # Update last active time and IP
        session['last_active'] = datetime.utcnow().isoformat()
        session['ip_address'] = request.remote_addr

@app.cli.command()
def init_db() -> None:
    """
    Initialize database tables and indexes.
    
    Creates all database tables defined in the application models.
    This command should be run during initial application setup.
    """
    try:
        db.create_all()
        click.echo('Database initialized successfully')
    except SQLAlchemyError as e:
        app.logger.error("Database initialization failed: %s", exc_info=e)
        click.echo(f'Database initialization failed: {e}', err=True)
        exit(1)

@app.cli.command()
@click.option('--dev-data/--no-dev-data', default=False, 
             help='Seed development data for testing')
def seed_db(dev_data: bool) -> None:
    """
    Seed the database with initial data.
    
    Args:
        dev_data: Whether to include additional development test data
    """
    try:
        success = seed_database()
        if success:
            click.echo('Database seeded successfully')
        else:
            click.echo('Database already seeded or seeding failed')
            
        if dev_data and app.config.get('ENVIRONMENT') == 'development':
            dev_success = seed_development_data()
            if dev_success:
                click.echo('Development data seeded successfully')
            else:
                click.echo('Development data seeding skipped or failed')
                
    except (RuntimeError, ValueError, KeyError) as e:
        app.logger.error("Database seeding failed: %s", exc_info=e)
        click.echo(f'Database seeding failed: {e}', err=True)
        exit(1)

@app.cli.command()
def verify_integrity() -> None:
    """Verify the integrity of critical application files."""
    from core.utils import detect_file_changes
    
    app_root = os.path.dirname(os.path.abspath(__file__))
    ref_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
    
    try:
        changes = detect_file_changes(app_root, ref_hashes)
        if changes:
            click.echo(f'WARNING: {len(changes)} critical files have been modified:')
            for change in changes:
                click.echo(f"  - {change['path']} ({change['status']})")
            exit(1)
        else:
            click.echo('All critical files verified. Integrity check passed.')
    except (RuntimeError, ValueError, KeyError, ImportError) as e:
        app.logger.error("File integrity check failed: %s", exc_info=e)
        click.echo(f'File integrity check failed: {e}', err=True)
        exit(1)

@app.cli.command()
def security_scan() -> None:
    """Run a comprehensive security scan."""
    from blueprints.monitoring.routes import (
        detect_login_anomalies,
        detect_database_anomalies,
        detect_session_anomalies,
        detect_file_access_anomalies
    )

    click.echo("Starting security scan...")

    try:
        with app.app_context():
            # Run various security detection functions
            login_anomalies = detect_login_anomalies()
            db_anomalies = detect_database_anomalies()
            session_anomalies = detect_session_anomalies()
            file_access_anomalies = detect_file_access_anomalies()

            # Check for issues in each category
            issues = []

            if login_anomalies.get('suspicious_ips'):
                issues.append(f"Found {len(login_anomalies['suspicious_ips'])} suspicious IPs")

            if db_anomalies.get('sensitive_tables'):
                issues.append(f"Found {len(db_anomalies['sensitive_tables'])} sensitive table access events")

            if session_anomalies.get('ip_changes'):
                issues.append(f"Found {len(session_anomalies['ip_changes'])} session IP changes")

            if file_access_anomalies.get('sensitive_files'):
                issues.append(f"Found {len(file_access_anomalies['sensitive_files'])} sensitive file access events")

            if issues:
                click.echo("Security scan complete. Issues found:")
                for issue in issues:
                    click.echo(f"  - {issue}")
                exit(1)
            else:
                click.echo("Security scan complete. No issues found.")
    except (RuntimeError, ValueError, KeyError, ImportError) as e:
        app.logger.error("Security scan failed: %s", e, exc_info=True)
        click.echo(f"Security scan failed: {e}", err=True)
        exit(1)

if __name__ == '__main__':
    app.run()