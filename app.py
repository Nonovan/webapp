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
- Application startup sequence
- Security monitoring initialization
"""

import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union, List

from flask import Flask, session, flash, redirect, url_for, request, Response
import click
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.security import AuditLog
from core.factory import create_app
from core.seeder import seed_database, seed_development_data
from core.security import check_critical_file_integrity, log_security_event

# Security constants
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
    'JWT_SECRET_KEY',
    'CSRF_SECRET_KEY',
    'SESSION_KEY'
]

# Session configuration
SESSION_TIMEOUT_MINUTES = 30
SESSION_INACTIVE_MESSAGE = 'Your session has expired. Please log in again.'
SESSION_SECURITY_MESSAGE = 'Your session has been terminated due to a security concern.'

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

def validate_user_session() -> Optional[Response]:
    """
    Validate user session on each request.

    Checks session age, user agent consistency, and IP address changes.
    This function implements security controls to detect session hijacking
    and enforce session timeouts.

    Returns:
        Response or None: Redirect to login if session is invalid, None otherwise
    """
    if 'user_id' not in session:
        return None

    # Check for session age
    if 'last_active' in session:
        last_active = datetime.fromisoformat(session['last_active'])
        if datetime.utcnow() - last_active > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            return _handle_session_expiration('session_timeout',
                                             f"Session timed out for user {session['user_id']}",
                                             'info',
                                             SESSION_INACTIVE_MESSAGE,
                                             'warning')

    # Check for IP address change
    if 'ip_address' in session and session['ip_address'] != request.remote_addr:
        return _handle_ip_change()

    # Update last active time and IP
    session['last_active'] = datetime.utcnow().isoformat()
    session['ip_address'] = request.remote_addr
    return None

def _handle_session_expiration(event_type: str, description: str, severity: str,
                              message: str, flash_category: str) -> Response:
    """Handle session expiration or termination."""
    log_security_event(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=session.get('user_id'),
        ip_address=request.remote_addr,
    )

    session.clear()
    flash(message, flash_category)
    return redirect(url_for('auth.login'))

def _handle_ip_change() -> Optional[Response]:
    """Handle IP address change in user session."""
    old_ip = session['ip_address']
    new_ip = request.remote_addr

    # Log the IP change
    log_security_event(
        event_type='session_ip_change',
        description=f"IP address changed during session: {old_ip} -> {new_ip}",
        severity='warning',
        user_id=session.get('user_id'),
        ip_address=new_ip,
    )

    # Record security audit event
    log_security_event(
        event_type=AuditLog.EVENT_SESSION_ANOMALY,
        description=f"IP address changed: {old_ip} -> {new_ip}",
        user_id=session.get('user_id'),
        ip_address=new_ip,
        severity='warning'
    )

    # For critical systems, invalidate the session
    if request.app.config.get('STRICT_SESSION_SECURITY', False):
        return _handle_session_expiration(
            'session_terminated',
            f"Session terminated due to IP change: {old_ip} -> {new_ip}",
            'warning',
            SESSION_SECURITY_MESSAGE,
            'danger'
        )

    return None

def register_cli_commands(app: Flask) -> None:
    """Register command line interface commands with the application."""

    @app.cli.command()
    def init_db() -> None:
        """Initialize database tables and indexes."""
        try:
            db.create_all()
            click.echo('Database initialized successfully')
        except SQLAlchemyError as e:
            app.logger.error("Database initialization failed", exc_info=e)
            click.echo(f'Database initialization failed: {e}', err=True)
            sys.exit(1)

    @app.cli.command()
    @click.option('--dev-data/--no-dev-data', default=False,
                 help='Seed development data for testing')
    def seed_db(dev_data: bool) -> None:
        """Seed the database with initial data."""
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
            app.logger.error("Database seeding failed", exc_info=e)
            click.echo(f'Database seeding failed: {e}', err=True)
            sys.exit(1)

    @app.cli.command()
    def verify_integrity() -> None:
        """Verify the integrity of critical application files."""
        try:
            if not check_critical_file_integrity(app):
                click.echo('WARNING: Critical file integrity check failed')
                sys.exit(1)
            else:
                click.echo('All critical files verified. Integrity check passed.')
        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            app.logger.error("File integrity check failed", exc_info=e)
            click.echo(f'File integrity check failed: {e}', err=True)
            sys.exit(1)

    @app.cli.command()
    def security_scan() -> None:
        """Run a comprehensive security scan."""
        try:
            from blueprints.monitoring.routes import (
                detect_login_anomalies,
                detect_database_anomalies,
                detect_session_anomalies,
                detect_file_access_anomalies
            )

            click.echo("Starting security scan...")

            with app.app_context():
                # Run various security detection functions
                scan_results = _run_security_scans(
                    detect_login_anomalies,
                    detect_database_anomalies,
                    detect_session_anomalies,
                    detect_file_access_anomalies
                )

                # Check for issues in each category
                issues = _analyze_security_scan_results(scan_results)

                if issues:
                    click.echo("Security scan complete. Issues found:")
                    for issue in issues:
                        click.echo(f"  - {issue}")
                    sys.exit(1)
                else:
                    click.echo("Security scan complete. No issues found.")
        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            app.logger.error("Security scan failed", exc_info=e)
            click.echo(f"Security scan failed: {e}", err=True)
            sys.exit(1)

def _run_security_scans(*detection_functions) -> Dict[str, Any]:
    """Run multiple security detection functions and collect results."""
    results = {}
    for func in detection_functions:
        results[func.__name__] = func()
    return results

def _analyze_security_scan_results(scan_results: Dict[str, Dict[str, Any]]) -> List[str]:
    """Analyze security scan results and return list of issues."""
    issues = []

    login_anomalies = scan_results.get('detect_login_anomalies', {})
    if login_anomalies.get('suspicious_ips'):
        issues.append(f"Found {len(login_anomalies['suspicious_ips'])} suspicious IPs")

    db_anomalies = scan_results.get('detect_database_anomalies', {})
    if db_anomalies.get('sensitive_tables'):
        issues.append(f"Found {len(db_anomalies['sensitive_tables'])} sensitive table access events")

    session_anomalies = scan_results.get('detect_session_anomalies', {})
    if session_anomalies.get('ip_changes'):
        issues.append(f"Found {len(session_anomalies['ip_changes'])} session IP changes")

    file_access_anomalies = scan_results.get('detect_file_access_anomalies', {})
    if file_access_anomalies.get('sensitive_files'):
        issues.append(f"Found {len(file_access_anomalies['sensitive_files'])} sensitive file access events")

    return issues

# Initialize application
try:
    validate_environment()
    app = create_app()

    # Register request handlers
    @app.before_request
    def validate_session():
        return validate_user_session()

    # Register CLI commands
    register_cli_commands(app)

except SQLAlchemyError as e:
    logging.critical("Application initialization failed: %s", e)
    raise

if __name__ == '__main__':
    app.run()
