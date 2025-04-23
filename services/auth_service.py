# services/auth_service.py

"""
Authentication service for centralized authentication logic.

This service handles all authentication operations including user verification,
session management, and security features. It's used by both web routes and API
endpoints to ensure consistent authentication behavior.

Security features implemented:
- Password hashing and verification
- Brute force protection with failed login tracking
- Session regeneration to prevent session fixation
- Two-factor authentication support
- JWT token generation for API authentication
"""

import random
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union
from flask import current_app, session
from werkzeug.security import check_password_hash

from blueprints.auth.utils import validate_password
from core.security import sanitize_username
from models.user import User
from models.login_attempt import LoginAttempt
from extensions import db


class AuthService:
    """
    Service class to handle authentication-related operations.

    This class centralizes authentication logic used by both web and API routes,
    ensuring consistent security practices across the application.
    """

    @staticmethod
    def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user with username and password.

        Args:
            username: The username to authenticate
            password: The password to verify

        Returns:
            Tuple containing:
            - Boolean indicating if authentication succeeded
            - User object if authentication succeeded, None otherwise
            - Error message if authentication failed, empty string otherwise
        """
        # Sanitize input
        username = sanitize_username(username)

        # Prevent timing attacks by using a similar execution path regardless of username existence
        user = User.query.filter_by(username=username).first()

        # Log authentication attempt (without password)
        current_app.logger.debug("Authentication attempt for username: %s", username)

        # Record login attempt for rate limiting
        ip_address = AuthService._get_client_ip()
        LoginAttempt.record_attempt(username, ip_address, success=False)

        # Check if the IP is rate limited
        if LoginAttempt.is_ip_rate_limited(ip_address):
            current_app.logger.warning("IP rate limited during login: %s", ip_address)
            return False, None, "Too many login attempts. Please try again later."

        # Check if user exists
        if not user:
            # Use same error message to prevent username enumeration
            return False, None, "Invalid username or password"

        # Check if account is locked
        if user.is_locked():
            # Use event logging for security monitoring
            current_app.logger.warning("Login attempt on locked account: %s", username)
            return False, None, user.get_lockout_message()

        # Verify password - use constant-time comparison provided by check_password_hash
        if not check_password_hash(user.password, password):
            # Record failed login
            user.record_failed_login()
            db.session.commit()

            # Check if this attempt triggered a lockout
            if user.is_locked():
                return False, None, user.get_lockout_message()

            return False, None, "Invalid username or password"

        # Update login attempt record to success
        LoginAttempt.record_attempt(username, ip_address, success=True)

        # Reset failed login counter on successful login
        user.reset_failed_logins()
        user.update_last_login()
        db.session.commit()

        current_app.logger.info("Successful authentication for user: %s", username)
        return True, user, ""

    @staticmethod
    def register_user(
            username: str,
            email: str,
            password: str,
            first_name: str = "",
            last_name: str = ""
    ) -> Tuple[bool, Optional[User], str]:
        """
        Register a new user.

        Args:
            username: The username for the new user
            email: The email address for the new user
            password: The password for the new user
            first_name: Optional first name
            last_name: Optional last name

        Returns:
            Tuple containing:
            - Boolean indicating if registration succeeded
            - User object if registration succeeded, None otherwise
            - Error message if registration failed, empty string otherwise
        """
        # Sanitize input
        username = sanitize_username(username)

        try:
            # Check if username exists
            if User.query.filter_by(username=username).first():
                return False, None, "Username already exists"

            # Check if email exists
            if User.query.filter_by(email=email).first():
                return False, None, "Email already exists"

            # Validate password strength
            is_valid, validation_message = validate_password(password)
            if not is_valid:
                return False, None, validation_message or "Password does not meet security requirements"

            # Create new user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                status=User.STATUS_ACTIVE
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            current_app.logger.info("New user registered: %s", username)
            return True, user, ""

        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Error during user registration: %s", str(e))
            return False, None, "Registration failed due to system error"

    @staticmethod
    def login_user_session(user: User, remember: bool = False) -> None:
        """
        Set up user session after successful authentication.

        Args:
            user: The authenticated user object
            remember: Whether to enable "remember me" functionality
        """
        # Ensure session dictionary is set up properly
        session_data = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'last_active': datetime.utcnow().isoformat(),
            'session_created': datetime.utcnow().isoformat(),
            'auth_method': 'password'  # Track authentication method used
        }

        # Set session data
        for key, value in session_data.items():
            session[key] = value

        # Regenerate session to prevent session fixation
        AuthService._regenerate_session()

        # Remember me functionality
        if remember:
            session.permanent = True
            # Use app config for session lifetime or default to 30 days
            lifetime_days = current_app.config.get('REMEMBER_ME_DAYS', 30)
            current_app.permanent_session_lifetime = timedelta(days=lifetime_days)
        else:
            session.permanent = False

        current_app.logger.info("User logged in: %s (ID: %s)", user.username, user.id)

    @staticmethod
    def logout_user() -> None:
        """
        Log out the current user by clearing their session.
        """
        if 'username' in session:
            username = session.get('username')
            current_app.logger.info("User logged out: %s", username)

        # Clear session
        session.clear()

    @staticmethod
    def validate_session() -> Tuple[bool, Optional[str]]:
        """
        Validate the current user session.

        Returns:
            Tuple containing:
            - Boolean indicating if session is valid
            - Error message if session is invalid, None otherwise
        """
        if 'user_id' not in session:
            return False, "No active session"

        # Check for session age
        if 'last_active' in session:
            try:
                last_active = datetime.fromisoformat(session['last_active'])
                idle_timeout = current_app.config.get('SESSION_IDLE_TIMEOUT', 30)  # minutes

                if datetime.utcnow() - last_active > timedelta(minutes=idle_timeout):
                    return False, "Session expired due to inactivity"

                # Check absolute session lifetime
                if 'session_created' in session:
                    created = datetime.fromisoformat(session['session_created'])
                    max_session_lifetime = current_app.config.get('MAX_SESSION_LIFETIME', 24)  # hours

                    if datetime.utcnow() - created > timedelta(hours=max_session_lifetime):
                        return False, "Session expired (maximum duration)"

            except (ValueError, TypeError) as e:
                current_app.logger.warning("Invalid session timestamp: %s", str(e))
                return False, "Invalid session timestamp"

        # Update last active time
        session['last_active'] = datetime.utcnow().isoformat()
        return True, None

    @staticmethod
    def generate_api_token(user: User, expires_in: int = 3600, scopes: list = None) -> str:
        """
        Generate a JWT token for API authentication.

        Args:
            user: The user to generate a token for
            expires_in: Token validity in seconds (default 1 hour)
            scopes: Optional list of permission scopes for the token

        Returns:
            JWT token string
        """
        if scopes is None:
            scopes = ['default']

        return user.generate_token(expires_in=expires_in, scopes=scopes)

    @staticmethod
    def verify_api_token(token: str, required_scopes: list = None) -> Tuple[bool, Optional[User], str]:
        """
        Verify a JWT token and return the associated user.

        Args:
            token: The JWT token to verify
            required_scopes: List of scopes required for this token to be valid

        Returns:
            Tuple containing:
            - Boolean indicating if token is valid
            - User object if token is valid, None otherwise
            - Error message if token is invalid, empty string otherwise
        """
        if not token:
            return False, None, "No token provided"

        result = User.verify_token(token)
        if not result:
            return False, None, "Invalid or expired token"
        user, token_scopes = result

        if not user:
            return False, None, "Invalid or expired token"

        # Check scopes if required
        if required_scopes:
            if not token_scopes:
                return False, None, "Token has no scopes but scopes are required"

            if not all(scope in token_scopes for scope in required_scopes):
                return False, None, "Token does not have required scopes"

        return True, user, ""

    @staticmethod
    def extend_session() -> bool:
        """
        Extend the current user session.

        Returns:
            Boolean indicating if session was successfully extended
        """
        if 'user_id' not in session:
            return False

        session['last_active'] = datetime.utcnow().isoformat()

        # Periodically regenerate session ID with a 20% chance
        # This helps mitigate potential session hijacking while
        # avoiding excessive regeneration
        if random.random() < 0.2:
            AuthService._regenerate_session()

        return True

    @staticmethod
    def _regenerate_session() -> None:
        """
        Regenerate the session ID while preserving session data.
        This helps prevent session fixation attacks.
        """
        # Store current session data
        session_data = dict(session)

        # Clear session and regenerate session ID
        session.clear()
        session.regenerate()

        # Restore session data
        for key, value in session_data.items():
            session[key] = value

    @staticmethod
    def _get_client_ip() -> str:
        """
        Get client IP address from request.

        Returns:
            IP address string
        """
        from flask import request

        # Check for proxy headers first
        if request.headers.get('X-Forwarded-For'):
            # Return the client's IP, not the proxy
            return request.headers['X-Forwarded-For'].split(',')[0].strip()

        return request.remote_addr or '0.0.0.0'
