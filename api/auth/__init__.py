"""
Authentication API module for the myproject application.

This module provides RESTful endpoints for user authentication, registration,
token management, and session handling. It serves as the entry point for
programmatic authentication with the application's cloud infrastructure and ICS systems.

Key endpoints:
- /api/auth/login: Authenticate and obtain JWT token with proper role validation
- /api/auth/register: Create new user accounts with secure password handling
- /api/auth/extend_session: Extend existing session duration with device fingerprinting
- /api/auth/verify: Verify token validity and authorization scope
- /api/auth/logout: Invalidate current token and terminate active sessions
- /api/auth/mfa/setup: Configure multi-factor authentication
- /api/auth/mfa/verify: Verify MFA challenges
- /api/auth/password/reset: Initiate password reset workflow
- /api/auth/session/status: Check current session status and permissions

All endpoints implement appropriate input validation, rate limiting, suspicious IP
detection, request logging, and comprehensive error handling to ensure secure
authentication operations in high-security cloud environments.

Authentication mechanisms support:
- JWT token-based authentication with role-based permissions
- Session-based authentication for web interfaces
- API key authentication for service integrations
- Multi-factor authentication using TOTP
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from flask import Blueprint, current_app, request, g

# Create blueprint for authentication API routes
auth_api = Blueprint('auth_api', __name__)

# Initialize module logger
logger = logging.getLogger(__name__)

# Module version for tracking in security audit logs
__version__ = '0.1.1'

# Import route handlers and components
from . import routes
from . import decorators
from .extend_session import SessionManager

# Import security helpers from the new module structure
try:
    from core.security.cs_metrics import setup_auth_metrics
    from core.security.cs_audit import register_event_handlers as register_auth_event_handlers
    from core.security.cs_audit import log_security_event
    from core.security.cs_file_integrity import (
        update_file_integrity_baseline,
        check_critical_file_integrity,
        calculate_file_hash
    )
    from extensions import metrics

    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    logger.error("Failed to import security helpers. Authentication metrics and event handlers will not be registered.")
    SECURITY_UTILS_AVAILABLE = False

    # Define placeholder functions if imports fail
    def setup_auth_metrics(blueprint):
        logger.warning("Auth metrics setup function not available")

    def register_auth_event_handlers():
        logger.warning("Auth event handlers registration function not available")

# Create session manager instance for the application
def get_session_manager():
    """
    Get or create a SessionManager instance configured with application settings.

    Returns:
        SessionManager: Configured session manager instance
    """
    if not hasattr(current_app, 'session_manager'):
        current_app.session_manager = SessionManager(
            session_duration_minutes=current_app.config.get('SESSION_DURATION_MINUTES', 30),
            max_sessions_per_user=current_app.config.get('MAX_SESSIONS_PER_USER', 5),
            enable_ip_binding=current_app.config.get('ENABLE_SESSION_IP_BINDING', False),
            enable_fingerprint_binding=current_app.config.get('ENABLE_SESSION_FINGERPRINT_BINDING', True),
            high_security_mode=current_app.config.get('HIGH_SECURITY_MODE', False),
            regeneration_interval=current_app.config.get('SESSION_REGENERATION_INTERVAL', 30)
        )
    return current_app.session_manager

def update_auth_module_baseline(app=None, auto_update_limit: int = 10) -> Tuple[bool, str]:
    """
    Update the file integrity baseline for authentication module files.

    This function ensures that the authentication module's file integrity baseline
    is up-to-date with authorized changes. It follows security best practices
    by limiting updates, validating critical files, and providing audit logging.

    Args:
        app: Flask application instance (uses current_app if None)
        auto_update_limit: Maximum number of files to auto-update (safety limit)

    Returns:
        Tuple containing (success, message)
    """
    if not SECURITY_UTILS_AVAILABLE:
        return False, "Security utilities not available"

    try:
        app = app or current_app
        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            return False, "Baseline path not configured"

        # Define auth module critical files
        auth_dir = os.path.dirname(os.path.abspath(__file__))
        auth_files = [
            os.path.join(auth_dir, '__init__.py'),
            os.path.join(auth_dir, 'routes.py'),
            os.path.join(auth_dir, 'decorators.py'),
            os.path.join(auth_dir, 'extend_session.py'),
            os.path.join(auth_dir, 'password_reset.py'),
            os.path.join(auth_dir, 'mfa.py'),
            os.path.join(auth_dir, 'session_status.py')
        ]

        # Calculate current hashes
        changes = []
        for file_path in auth_files:
            if os.path.exists(file_path):
                try:
                    # Get relative path for baseline
                    rel_path = os.path.relpath(file_path, os.path.dirname(app.root_path))

                    # Calculate current hash
                    current_hash = calculate_file_hash(file_path)

                    # Add to changes list for baseline update
                    changes.append({
                        'path': rel_path,
                        'current_hash': current_hash,
                        'severity': 'medium' if 'password_reset.py' in file_path or '__init__.py' in file_path else 'low'
                    })
                except Exception as e:
                    logger.error(f"Error calculating hash for {file_path}: {str(e)}")

        # Check if we have too many changes
        if len(changes) > auto_update_limit:
            return False, f"Too many files to update ({len(changes)} exceeds limit of {auto_update_limit})"

        # Update baseline
        success = update_file_integrity_baseline(
            app=app,
            baseline_path=baseline_path,
            updates=changes
        )

        if success:
            # Log security event for successful baseline update
            if hasattr(log_security_event, '__call__'):
                log_security_event(
                    event_type="auth_baseline_updated",
                    description=f"Authentication module baseline updated with {len(changes)} changes",
                    severity="info",
                    user_id=g.user.id if hasattr(g, 'user') else None,
                    details={
                        "module": "auth",
                        "files_updated": len(changes),
                        "initiated_by": request.remote_addr if request else "system",
                        "version": __version__
                    }
                )

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('security.auth_baseline_updated')

            return True, f"Successfully updated authentication baseline with {len(changes)} changes"
        else:
            return False, "Failed to update authentication module baseline"

    except Exception as e:
        logger.error(f"Error updating authentication module baseline: {str(e)}")
        if hasattr(metrics, 'increment'):
            metrics.increment('security.auth_baseline_error')
        return False, f"Error updating baseline: {str(e)}"

# Register application lifecycle callbacks
@auth_api.record_once
def on_register(state):
    """
    Called when the blueprint is registered to the application.

    Args:
        state: Flask blueprint state object
    """
    app = state.app

    # Register the authentication metrics collectors
    try:
        setup_auth_metrics(auth_api)
        logger.info("Authentication metrics registered successfully")
    except Exception as e:
        logger.error(f"Failed to register authentication metrics: {e}")

    # Register authentication event handlers
    try:
        register_auth_event_handlers()
        logger.info("Authentication event handlers registered successfully")
    except Exception as e:
        logger.error(f"Failed to register authentication event handlers: {e}")

    # Check if baseline verification is enabled on startup
    if SECURITY_UTILS_AVAILABLE and app.config.get('AUTH_VERIFY_INTEGRITY_ON_STARTUP', False):
        try:
            # Use a separate thread to avoid blocking startup
            from threading import Thread
            thread = Thread(target=lambda: check_critical_file_integrity(app))
            thread.daemon = True
            thread.start()
        except Exception as e:
            logger.error(f"Failed to schedule baseline verification: {e}")

    # Log initialization with security event
    logger.info("Authentication API initialized successfully")
    if SECURITY_UTILS_AVAILABLE and hasattr(log_security_event, '__call__'):
        log_security_event(
            event_type="auth_module_initialized",
            description="Authentication module initialized successfully",
            severity="info",
            details={"version": __version__}
        )

# Export public objects
__all__ = [
    'auth_api',
    'get_session_manager',
    'SessionManager',
    'decorators',
    'update_auth_module_baseline',
    '__version__'
]
