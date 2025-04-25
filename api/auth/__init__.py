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
- Hardware security key integration (FIDO2/WebAuthn)
"""

import logging
from flask import Blueprint, current_app

# Create blueprint for authentication API routes
auth_api = Blueprint('auth_api', __name__)

# Initialize module logger
logger = logging.getLogger(__name__)

# Import route handlers
from . import routes
from .extend_session import SessionManager

# Import security helpers from the new module structure
try:
    from core.security.cs_metrics import setup_auth_metrics
    from core.security.cs_audit import register_event_handlers as register_auth_event_handlers
except ImportError:
    logger.error("Failed to import security helpers. Authentication metrics and event handlers will not be registered.")

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

    # Log initialization
    logger.info("Authentication API initialized successfully")

# Export public objects
__all__ = ['auth_api', 'get_session_manager', 'SessionManager']
