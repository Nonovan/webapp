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

from flask import Blueprint

# Create blueprint for authentication API routes
auth_api = Blueprint('auth_api', __name__)

# Import route handlers
from . import routes

# Import security helpers
from core.security_utils import setup_auth_metrics, register_auth_event_handlers

# Register the authentication metrics collectors
setup_auth_metrics(auth_api)

# Export all defined routes
__all__ = ['auth_api']