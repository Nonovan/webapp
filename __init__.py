"""
The myproject application package.

This module serves as the entry point for the myproject Flask application,
providing the application factory pattern for proper application initialization.
It coordinates the core configuration, blueprint registration, and error handling
to create a fully configured Flask instance.

Key components:
- Application factory function that assembles all app components
- Version tracking for deployment management
- Blueprint registration for modular feature organization
- Error handling and logging configuration
- Security monitoring initialization
- Enhanced file integrity verification with notification capabilities
- SMS notification integration for critical security events
- Automatic baseline management for development environments
- Intelligent baseline repair for corrupted or inconsistent states

The application follows Flask best practices with a modular structure,
separation of concerns, and dependency injection to facilitate testing
and maintenance.
"""

import logging
import os
import sys
import time
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

from flask import Flask, g, request
from core.factory import create_app as core_create_app
from core import generate_request_id
from views import register_blueprints
from services import (
    check_integrity, SECURITY_SERVICE_AVAILABLE, SMS_SERVICE_AVAILABLE,
    update_file_integrity_baseline_with_notifications, validate_baseline_consistency
)

__version__ = '1.0.0'

# Configure logger early for initialization errors
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """
    Create and configure the Flask application.

    This function implements the application factory pattern, creating a new Flask
    instance with all the necessary configuration, extensions, and blueprints. It
    separates application creation from usage to enable better testability
    and configuration flexibility.

    The factory handles:
    - Core configuration loading
    - Blueprint registration
    - Extension initialization
    - Error handling setup
    - Security monitoring initialization
    - File integrity verification
    - Notification service setup
    - Baseline management with notifications
    - Baseline repair for development environments

    Returns:
        Flask: A fully configured Flask application instance ready to serve requests

    Raises:
        Exception: If application initialization fails, with detailed error logging
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Create base app
        app = Flask(__name__)

        # Configure via core factory
        app = core_create_app(None)

        # Register blueprints
        register_blueprints(app)

        # Set version
        app.config['VERSION'] = __version__

        # Store application startup time for uptime tracking
        app.uptime = datetime.utcnow()

        # Set up request tracking middleware
        @app.before_request
        def set_request_context():
            """Set up context for request tracking and monitoring."""
            # Generate unique request ID
            g.request_id = request.headers.get('X-Request-ID', generate_request_id())
            g.start_time = datetime.utcnow()

            # Make CSP nonce available for this request
            g.csp_nonce = os.urandom(16).hex()

        # Set up file integrity monitoring if enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            # Check if SecurityService is available (via services package)
            if SECURITY_SERVICE_AVAILABLE:
                # Verify baseline consistency before running integrity checks
                if app.config.get('VERIFY_BASELINE_CONSISTENCY', True):
                    try:
                        # Get baseline path
                        baseline_path = app.config.get('FILE_BASELINE_PATH')
                        if not baseline_path:
                            # Use default if not configured
                            baseline_path = os.path.join(app.instance_path, 'security', 'baseline.json')
                            app.config['FILE_BASELINE_PATH'] = baseline_path
                            app.logger.info(f"Using default baseline path: {baseline_path}")

                        # Ensure baseline directory exists
                        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

                        # Check if baseline exists, create if missing in development
                        if not os.path.exists(baseline_path):
                            if app.config.get('ENVIRONMENT') == 'development':
                                app.logger.warning(f"Baseline file not found at {baseline_path}, creating initial baseline")
                                success = _create_initial_baseline(app, baseline_path)
                                if success:
                                    app.logger.info("Initial baseline created successfully")
                                else:
                                    app.logger.warning("Failed to create initial baseline")
                            else:
                                app.logger.warning(f"Baseline file not found at {baseline_path} in {app.config.get('ENVIRONMENT')} environment")

                        # Validate the structure and format of the baseline
                        is_consistent, consistency_issues = validate_baseline_consistency(baseline_path)
                        if not is_consistent:
                            app.logger.warning(
                                "Baseline consistency check failed: %s",
                                consistency_issues.get('message', 'Unknown issue')
                            )
                            # Don't automatically repair in production/staging
                            if app.config.get('ENVIRONMENT') == 'development' and app.config.get('AUTO_REPAIR_BASELINE', False):
                                app.logger.info("Attempting to repair baseline inconsistencies")
                                repair_success = _repair_baseline(app, baseline_path, consistency_issues)
                                if repair_success:
                                    app.logger.info("Baseline repaired successfully")
                                    # Re-check consistency after repair
                                    is_consistent, _ = validate_baseline_consistency(baseline_path)
                                    if is_consistent:
                                        app.logger.info("Baseline consistency verified after repair")
                                    else:
                                        app.logger.warning("Baseline still inconsistent after repair attempt")
                                else:
                                    app.logger.warning("Failed to repair baseline")
                    except Exception as consistency_err:
                        app.logger.error(f"Error during baseline consistency check: {consistency_err}")

                # Perform initial integrity check
                integrity_status, changes = check_integrity()

                # Log results appropriately
                if not integrity_status:
                    # Categorize changes by severity for appropriate handling
                    critical_changes = [c for c in changes if c.get('severity') == 'critical']
                    high_changes = [c for c in changes if c.get('severity') == 'high']
                    medium_changes = [c for c in changes if c.get('severity') == 'medium']
                    low_changes = [c for c in changes if c.get('severity', 'low') == 'low']

                    # Process critical integrity violations
                    if critical_changes and app.config.get('ENVIRONMENT') in ['production', 'staging']:
                        app.logger.critical(
                            "Critical integrity violations detected during startup (%d changes)",
                            len(critical_changes)
                        )

                        # Notify security team about critical violations via SMS if available
                        if SMS_SERVICE_AVAILABLE and app.config.get('NOTIFY_CRITICAL_VIOLATIONS', True):
                            try:
                                from services import send_sms
                                security_phone = app.config.get('SECURITY_ALERT_PHONE')
                                if security_phone:
                                    # Enhanced message with more details
                                    critical_files = ", ".join([c.get('path', 'unknown') for c in critical_changes[:3]])
                                    if len(critical_changes) > 3:
                                        critical_files += f" and {len(critical_changes) - 3} more"

                                    send_sms(
                                        to=security_phone,
                                        message=(
                                            f"CRITICAL: File integrity violations on {app.config.get('ENVIRONMENT')} - "
                                            f"{len(critical_changes)} critical files affected: {critical_files}. "
                                            f"Immediate action required."
                                        ),
                                        priority="critical",
                                        category="security"
                                    )
                                    app.logger.info("SMS security alert sent successfully")
                            except Exception as sms_err:
                                app.logger.error(f"Failed to send SMS notification: {sms_err}")

                        # Also send alerts via additional configured channels if available
                        _send_additional_alerts(app, critical_changes, 'critical')

                        # Abort startup in production/staging unless explicitly ignored
                        if not app.config.get('IGNORE_INTEGRITY_FAILURES', False):
                            app.logger.critical("Application startup aborted due to integrity violations")
                            sys.exit(1)

                    # Process high severity violations
                    elif high_changes:
                        app.logger.error(
                            "High severity integrity violations detected (%d changes)",
                            len(high_changes)
                        )

                        # Send high severity alerts via configured channels if available
                        _send_additional_alerts(app, high_changes, 'high')

                        # Consider auto-updating baseline in development environment
                        if (app.config.get('ENVIRONMENT') == 'development' and
                            app.config.get('AUTO_UPDATE_BASELINE', False)):
                            try:
                                # Update baseline with notifications for development environment
                                baseline_path = app.config.get('FILE_BASELINE_PATH')

                                # Skip critical and high severity changes - only auto-update medium and low risk files
                                update_changes = medium_changes + low_changes

                                # Verify updates don't exceed configured limits
                                max_files = app.config.get('BASELINE_UPDATE_MAX_FILES', 50)
                                if len(update_changes) > max_files:
                                    app.logger.warning(
                                        f"Auto-update would modify {len(update_changes)} files, "
                                        f"exceeding limit of {max_files}. Trimming to limit."
                                    )
                                    # Truncated to limit, with medium severity first, then low
                                    update_changes = sorted(
                                        update_changes,
                                        key=lambda x: 0 if x.get('severity') == 'medium' else 1
                                    )[:max_files]

                                # Only update if we have changes to apply
                                if update_changes:
                                    app.logger.info(f"Auto-updating baseline with {len(update_changes)} non-critical changes")

                                    # We'll log excluded high severity files for reference
                                    if high_changes:
                                        high_files = ", ".join([c.get('path', 'unknown') for c in high_changes[:3]])
                                        if len(high_changes) > 3:
                                            high_files += f" and {len(high_changes) - 3} more"
                                        app.logger.info(f"Skipping {len(high_changes)} high severity files: {high_files}")

                                    # Create backup before updating
                                    _backup_baseline(app, baseline_path)

                                    # Perform the update with notifications
                                    success, message, stats = update_file_integrity_baseline_with_notifications(
                                        baseline_path=baseline_path,
                                        changes=update_changes,
                                        remove_missing=True,
                                        notify=app.config.get('FILE_INTEGRITY_NOTIFY_ON_UPDATE', True),
                                        audit=app.config.get('AUDIT_BASELINE_UPDATES', True),
                                        severity_threshold=app.config.get('NOTIFICATION_THRESHOLD', 'medium'),
                                        update_limit=max_files
                                    )

                                    # Log results with detailed stats
                                    if success:
                                        app.logger.info(
                                            f"Baseline auto-updated: {message} "
                                            f"({stats.get('changes_applied', 0)} changes applied, "
                                            f"{stats.get('removed_entries', 0)} entries removed)"
                                        )
                                    else:
                                        app.logger.warning(f"Baseline auto-update failed: {message}")
                                else:
                                    app.logger.info("No appropriate changes to auto-update")
                            except Exception as e:
                                app.logger.error(f"Error during baseline auto-update: {e}")

                    # Handle medium/low severity violations
                    else:
                        app.logger.warning(
                            "File integrity check failed with %d changes detected",
                            len(changes)
                        )

                        # For development environments, consider auto-updating even these changes
                        if (app.config.get('ENVIRONMENT') == 'development' and
                            app.config.get('AUTO_UPDATE_MINOR_CHANGES', True)):
                            try:
                                # Similar auto-update logic but with lower risk threshold
                                baseline_path = app.config.get('FILE_BASELINE_PATH')
                                if changes:
                                    # Create backup before updating
                                    _backup_baseline(app, baseline_path)

                                    success, message, stats = update_file_integrity_baseline_with_notifications(
                                        baseline_path=baseline_path,
                                        changes=changes,
                                        remove_missing=True,
                                        notify=False,  # No notifications for minor changes
                                        audit=True,
                                        severity_threshold='low',
                                        update_limit=app.config.get('BASELINE_UPDATE_MAX_FILES', 50)
                                    )
                                    if success:
                                        app.logger.info(f"Baseline silently updated with minor changes: {message}")
                                    else:
                                        app.logger.debug(f"Minor baseline update failed: {message}")
                            except Exception as minor_err:
                                app.logger.debug(f"Error during minor baseline update: {minor_err}")
                else:
                    app.logger.info("File integrity check passed")
            else:
                # Fall back to basic file integrity checks
                from core.config import Config
                app.config = Config.initialize_file_hashes(
                    app.config,
                    os.path.dirname(os.path.abspath(__file__))
                )
                app.logger.info("Basic file integrity monitoring initialized")

        # Calculate and log initialization time
        init_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        app.logger.info(
            "Application initialized successfully in %.2f seconds (version: %s)",
            init_duration,
            __version__
        )

        return app

    except Exception as e:
        # Log critical error
        logging.critical("Failed to create application: %s", e)
        raise

def _create_initial_baseline(app: Flask, baseline_path: str) -> bool:
    """
    Create an initial file integrity baseline for the application.

    Args:
        app: The Flask application instance
        baseline_path: Path where the baseline file should be created

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get the critical file patterns from config
        patterns = app.config.get('CRITICAL_FILES_PATTERN', ['*.py', 'config/*.py', 'core/security/*.py'])

        # Create baseline directory if it doesn't exist
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

        # Check if we can use the core security implementation
        try:
            from core.security.cs_file_integrity import create_file_hash_baseline
            success = create_file_hash_baseline(
                app=app,
                basedir=app.root_path,
                patterns=patterns,
                output_file=baseline_path
            )
            return success
        except ImportError:
            app.logger.warning("Core security module not available for baseline creation, using fallback")

        # Fallback implementation
        from services import SecurityService

        # Generate a basic structure for the baseline
        baseline_data = {
            "files": {},
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated_at": datetime.now(timezone.utc).isoformat(),
                "hash_algorithm": app.config.get('FILE_HASH_ALGORITHM', 'sha256'),
                "environment": app.config.get('ENVIRONMENT', 'development')
            }
        }

        # Write the basic structure to file
        with open(baseline_path, 'w') as f:
            json.dump(baseline_data, f, indent=2)

        return True

    except Exception as e:
        app.logger.error(f"Error creating initial baseline: {e}")
        return False

def _repair_baseline(app: Flask, baseline_path: str, issues: Dict[str, Any]) -> bool:
    """
    Repair a corrupted or inconsistent baseline file.

    Args:
        app: Flask application instance
        baseline_path: Path to the baseline file
        issues: Dictionary with consistency issues details

    Returns:
        bool: True if repair was successful, False otherwise
    """
    try:
        # Create a backup of the current baseline
        backup_file = _backup_baseline(app, baseline_path)
        if not backup_file:
            app.logger.error("Failed to create baseline backup before repair")
            return False

        # Determine repair strategy based on issues
        errors = issues.get('errors', [])
        warnings = issues.get('warnings', [])

        # Complete rebuild is needed for serious errors
        needs_rebuild = any([
            "Baseline file not found" in errors,
            "Invalid JSON format" in errors,
            "Missing 'files' key" in errors
        ])

        if needs_rebuild:
            app.logger.info("Baseline requires complete rebuilding")
            return _create_initial_baseline(app, baseline_path)

        # For less severe issues, try to repair the existing baseline
        try:
            # Read the baseline
            with open(baseline_path, 'r') as f:
                baseline_data = json.load(f)

            # Fix missing metadata
            if "metadata" not in baseline_data or not isinstance(baseline_data.get("metadata"), dict):
                baseline_data["metadata"] = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_updated_at": datetime.now(timezone.utc).isoformat(),
                    "hash_algorithm": app.config.get('FILE_HASH_ALGORITHM', 'sha256'),
                    "environment": app.config.get('ENVIRONMENT', 'development')
                }
                app.logger.info("Added missing metadata section to baseline")
            else:
                # Update required metadata fields
                metadata = baseline_data["metadata"]

                if "last_updated_at" not in metadata:
                    metadata["last_updated_at"] = datetime.now(timezone.utc).isoformat()

                if "hash_algorithm" not in metadata:
                    metadata["hash_algorithm"] = app.config.get('FILE_HASH_ALGORITHM', 'sha256')

            # Fix missing files section
            if "files" not in baseline_data or not isinstance(baseline_data.get("files"), dict):
                baseline_data["files"] = {}
                app.logger.info("Added missing files section to baseline")

            # Fix invalid file entries
            files = baseline_data["files"]
            invalid_entries = []

            for file_path, file_hash in files.items():
                if not isinstance(file_path, str) or not file_path:
                    invalid_entries.append(file_path)
                elif not isinstance(file_hash, str) or not file_hash:
                    invalid_entries.append(file_path)

            # Remove invalid entries
            for entry in invalid_entries:
                if entry in files:
                    del files[entry]

            if invalid_entries:
                app.logger.info(f"Removed {len(invalid_entries)} invalid entries from baseline")

            # Write repaired baseline
            with open(baseline_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            app.logger.info("Baseline repaired successfully")
            return True

        except (json.JSONDecodeError, IOError) as e:
            app.logger.error(f"Error repairing baseline, falling back to full rebuild: {e}")
            return _create_initial_baseline(app, baseline_path)

    except Exception as e:
        app.logger.error(f"Error during baseline repair: {e}")
        return False

def _backup_baseline(app: Flask, baseline_path: str) -> Optional[str]:
    """
    Create a backup of the baseline file before modifications.

    Args:
        app: Flask application instance
        baseline_path: Path to baseline file

    Returns:
        Optional[str]: Path to backup file if successful, None otherwise
    """
    try:
        if not os.path.exists(baseline_path):
            return None

        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path_template = app.config.get(
            'BASELINE_BACKUP_PATH_TEMPLATE',
            'instance/security/baseline_backups/{timestamp}_{environment}.json'
        )

        # Format the backup path
        environment = app.config.get('ENVIRONMENT', 'development')
        backup_path = backup_path_template.format(
            timestamp=timestamp,
            environment=environment
        )

        # Ensure backup is stored relative to app root if not absolute
        if not os.path.isabs(backup_path):
            backup_path = os.path.join(app.root_path, backup_path)

        # Create backup directory if needed
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)

        # Copy baseline to backup
        import shutil
        shutil.copy2(baseline_path, backup_path)

        app.logger.debug(f"Created baseline backup at {backup_path}")

        # Clean up old backups if configured
        retention = app.config.get('BASELINE_UPDATE_RETENTION', 5)
        if retention > 0:
            _cleanup_old_backups(app, os.path.dirname(backup_path), retention)

        return backup_path

    except Exception as e:
        app.logger.error(f"Failed to create baseline backup: {e}")
        return None

def _cleanup_old_backups(app: Flask, backup_dir: str, retain: int) -> None:
    """
    Remove old baseline backups exceeding the retention count.

    Args:
        app: Flask application instance
        backup_dir: Directory containing backups
        retain: Number of backups to retain
    """
    try:
        if not os.path.exists(backup_dir):
            return

        # List all backup files
        files = []
        env = app.config.get('ENVIRONMENT', 'development')

        for filename in os.listdir(backup_dir):
            if filename.endswith('.json') and env in filename:
                file_path = os.path.join(backup_dir, filename)
                files.append((file_path, os.path.getmtime(file_path)))

        # Sort by modification time (newest first)
        files.sort(key=lambda x: x[1], reverse=True)

        # Remove excess files
        if len(files) > retain:
            for file_path, _ in files[retain:]:
                try:
                    os.remove(file_path)
                    app.logger.debug(f"Removed old baseline backup: {file_path}")
                except OSError as e:
                    app.logger.warning(f"Failed to remove old baseline backup {file_path}: {e}")

    except Exception as e:
        app.logger.warning(f"Error cleaning up old baseline backups: {e}")

def _send_additional_alerts(app: Flask, changes: List[Dict[str, Any]], severity: str) -> None:
    """
    Send integrity violation alerts through configured notification channels.

    Args:
        app: Flask application instance
        changes: List of integrity violations
        severity: Severity of the violations ('critical' or 'high')
    """
    try:
        # Check if notification service is available
        if not app.config.get('ENABLE_INTEGRITY_NOTIFICATIONS', True):
            return

        # Get alert configuration
        alert_channels = app.config.get('INTEGRITY_ALERT_CHANNELS', ['email'])

        if 'email' in alert_channels:
            _send_email_alert(app, changes, severity)

        # Add additional notification channels here as needed

    except Exception as e:
        app.logger.error(f"Error sending additional integrity alerts: {e}")

def _send_email_alert(app: Flask, changes: List[Dict[str, Any]], severity: str) -> None:
    """
    Send integrity violation notification via email.

    Args:
        app: Flask application instance
        changes: List of integrity violations
        severity: Severity of the violations ('critical' or 'high')
    """
    try:
        # Check if email service is available
        if not app.config.get('EMAIL_SERVICE_AVAILABLE', False):
            app.logger.debug("Email service not available for integrity alerts")
            return

        # Import email service
        try:
            from services import send_email, EmailService
        except ImportError:
            app.logger.warning("Email service not properly configured")
            return

        # Get email configuration
        recipients = app.config.get('INTEGRITY_ALERT_EMAIL_RECIPIENTS', [])
        if not recipients:
            app.logger.debug("No email recipients configured for integrity alerts")
            return

        # Format file list for email
        file_list = "\n".join([
            f"- {c.get('path', 'unknown')} ({c.get('status', 'modified')})"
            for c in changes[:10]
        ])

        if len(changes) > 10:
            file_list += f"\n- ...and {len(changes) - 10} more files"

        # Send the email
        subject = f"{severity.upper()} Integrity Alert: {len(changes)} files affected"
        environment = app.config.get('ENVIRONMENT', 'unknown')

        message = f"""
        File Integrity Alert

        Severity: {severity.upper()}
        Environment: {environment}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Files Affected: {len(changes)}

        Affected Files:
        {file_list}

        This message was generated automatically by the file integrity monitoring system.
        """

        send_email(
            subject=subject,
            recipients=recipients,
            body=message,
            priority='high',
            category='security'
        )

        app.logger.info(f"Sent integrity email alert to {len(recipients)} recipients")

    except Exception as e:
        app.logger.error(f"Error sending email integrity alert: {e}")
