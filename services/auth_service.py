"""
Authentication service for centralized authentication logic.

This service handles all authentication operations including user verification,
session management, and security features. It's used by both web routes and API
endpoints to ensure consistent authentication behavior.

Security features implemented:
- Password hashing and verification
- Brute force protection with failed login tracking
- Session regeneration to prevent session fixation
- Two-factor authentication support with TOTP and backup codes
- JWT token generation for API authentication
- Session anomaly detection
- IP-based security controls
- Integration with notification services
"""

import base64
import os
import pyotp
import random
import logging
import hashlib
from datetime import datetime, timedelta, timezone
import uuid
from typing import Dict, List, Optional, Tuple, Union, Any
from flask import current_app, session, request, g
from werkzeug.security import check_password_hash, generate_password_hash

from blueprints.auth.utils import validate_password
from core.security import (
    log_security_event, sanitize_username, generate_secure_token,
    regenerate_session as security_regenerate_session
)
from models import AuditLog, LoginAttempt, User, UserSession
from extensions import db, metrics

# Import notification services if available
try:
    from services.notification import notification_manager
    from services.notification import (
        NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER
    )
    NOTIFICATION_AVAILABLE = True
except ImportError:
    NOTIFICATION_AVAILABLE = False

# Import constants from service_constants if available
try:
    from services.service_constants import (
        AUTH_NOTIFICATION_ENABLED,
        AUTH_SECURITY_EVENT_NOTIFICATION_DELAY,
        AUTH_MAX_SESSIONS_PER_USER
    )
except ImportError:
    # Default values if service_constants is not available
    AUTH_NOTIFICATION_ENABLED = True
    AUTH_SECURITY_EVENT_NOTIFICATION_DELAY = 0  # No delay by default
    AUTH_MAX_SESSIONS_PER_USER = 5

# Import audit service if available
try:
    from services.audit_service import AuditService
    AUDIT_SERVICE_AVAILABLE = True
except ImportError:
    AUDIT_SERVICE_AVAILABLE = False

logger = logging.getLogger(__name__)


class AuthService:
    """
    Service class to handle authentication-related operations.

    This class centralizes authentication logic used by both web and API routes,
    ensuring consistent security practices across the application.
    """

    @staticmethod
    def authenticate_user(
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user with username and password.

        Args:
            username: The username to authenticate
            password: The password to verify
            ip_address: The IP address of the client (optional)
            user_agent: The user agent string of the client (optional)

        Returns:
            Tuple containing:
            - Boolean indicating if authentication succeeded
            - User object if authentication succeeded, None otherwise
            - Error message if authentication failed, empty string otherwise
        """
        # Sanitize input
        username = sanitize_username(username)

        if not ip_address:
            ip_address = AuthService._get_client_ip()

        # Prevent timing attacks by using a similar execution path regardless of username existence
        user = User.query.filter_by(username=username).first()

        # Log authentication attempt (without password)
        current_app.logger.debug("Authentication attempt for username: %s", username)

        # Record login attempt for rate limiting
        LoginAttempt.record_attempt(username, ip_address, success=False)

        # Check if the IP is rate limited
        if LoginAttempt.is_ip_rate_limited(ip_address):
            # Log the security event
            log_security_event(
                event_type=AuditLog.EVENT_RATE_LIMIT,
                description=f"IP rate limited during login: {ip_address}",
                severity="warning",
                ip_address=ip_address,
                details={"username": username}
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id if user else None,
                    action=AuditService.EVENT_ACCESS_DENIED,
                    target_resource="authentication",
                    status="failure",
                    ip_address=ip_address,
                    details={
                        "reason": "rate_limited",
                        "username": username
                    },
                    severity="warning"
                )

            # Send security notification if available
            if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                notification_manager.send_to_stakeholders(
                    subject="Authentication rate limit triggered",
                    message=f"IP address {ip_address} has been rate limited due to excessive login attempts.",
                    level="warning",
                    category=NOTIFICATION_CATEGORY_SECURITY
                )

            current_app.logger.warning("IP rate limited during login: %s", ip_address)
            metrics.increment('security.auth_rate_limited')
            return False, None, "Too many login attempts. Please try again later."

        # Check if user exists
        if not user:
            # Use same error message to prevent username enumeration
            return False, None, "Invalid username or password"

        # Check if account is locked
        if user.is_locked():
            # Log security event for audit
            log_security_event(
                event_type=AuditLog.EVENT_AUTH_FAILED,
                description=f"Login attempt on locked account: {username}",
                severity="warning",
                ip_address=ip_address,
                user_id=user.id
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_ACCESS_DENIED,
                    target_resource="authentication",
                    status="locked",
                    ip_address=ip_address,
                    details={
                        "reason": "account_locked"
                    },
                    severity="warning"
                )

            # Use event logging for security monitoring
            current_app.logger.warning("Login attempt on locked account: %s", username)
            metrics.increment('security.auth_locked_account')
            return False, None, user.get_lockout_message()

        # Check if account is inactive or suspended
        if user.status != User.STATUS_ACTIVE:
            log_security_event(
                event_type=AuditLog.EVENT_AUTH_FAILED,
                description=f"Login attempt on {user.status} account: {username}",
                severity="warning",
                ip_address=ip_address,
                user_id=user.id
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_ACCESS_DENIED,
                    target_resource="authentication",
                    status="inactive",
                    ip_address=ip_address,
                    details={
                        "reason": f"account_{user.status}"
                    },
                    severity="warning"
                )

            return False, None, f"This account is {user.status}. Please contact an administrator."

        # Verify password - use constant-time comparison provided by check_password_hash
        if not check_password_hash(user.password, password):
            # Record failed login
            user.record_failed_login()
            db.session.commit()

            # Track failed login metric
            metrics.increment('security.auth_failed_password')

            # Check if this attempt triggered a lockout
            if user.is_locked():
                log_security_event(
                    event_type=AuditLog.EVENT_ACCOUNT_LOCKED,
                    description=f"Account locked due to failed attempts: {username}",
                    severity="warning",
                    ip_address=ip_address,
                    user_id=user.id
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user.id,
                        action=AuditService.EVENT_ACCESS_DENIED,
                        target_resource="authentication",
                        status="locked",
                        ip_address=ip_address,
                        details={
                            "reason": "locked_after_failed_attempts",
                            "attempt_count": user.failed_login_count
                        },
                        severity="warning"
                    )

                # Send security notification if available
                if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                    notification_manager.send_to_stakeholders(
                        subject=f"Account locked: {username}",
                        message=f"User account {username} has been locked after multiple failed login attempts. IP: {ip_address}",
                        level="warning",
                        category=NOTIFICATION_CATEGORY_SECURITY
                    )

                return False, None, user.get_lockout_message()

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_ACCESS_DENIED,
                    target_resource="authentication",
                    status="failure",
                    ip_address=ip_address,
                    details={
                        "reason": "invalid_password",
                        "attempt_count": user.failed_login_count
                    },
                    severity="warning"
                )

            return False, None, "Invalid username or password"

        # Check for password expiration if feature is enabled
        if current_app.config.get('ENFORCE_PASSWORD_EXPIRATION', False) and user.should_change_password():
            # Allow login but set flag to force password change
            session['force_password_change'] = True
            # This will be checked after login to redirect to change password page

        # Check if accessing from a new location and MFA is enabled
        if (user.two_factor_enabled and
            current_app.config.get('ENFORCE_MFA_NEW_LOCATION', True) and
            AuthService._is_new_location(user, ip_address)):
            # If this is a new location, require MFA verification
            session['awaiting_mfa'] = True
            session['mfa_redirect_to'] = request.path  # Remember desired destination

        # Update login attempt record to success
        LoginAttempt.record_attempt(username, ip_address, success=True)

        # Reset failed login counter on successful login
        user.reset_failed_logins()
        user.update_last_login()
        db.session.commit()

        # Log the successful authentication
        log_security_event(
            event_type=AuditLog.EVENT_LOGIN,
            description=f"User login successful: {username}",
            severity="info",
            ip_address=ip_address,
            user_id=user.id,
            details={
                "user_agent": user_agent,
                "method": "password"
            }
        )

        # Add to audit log if available
        if AUDIT_SERVICE_AVAILABLE:
            AuditService.log_event(
                user_id=user.id,
                action=AuditService.EVENT_USER_LOGIN,
                target_resource="authentication",
                status="success",
                ip_address=ip_address,
                details={
                    "user_agent": user_agent,
                    "method": "password",
                    "mfa_required": session.get('awaiting_mfa', False)
                },
                severity="info"
            )

        current_app.logger.info("Successful authentication for user: %s", username)
        metrics.increment('security.auth_successful')
        return True, user, ""

    @staticmethod
    def register_user(
            username: str,
            email: str,
            password: str,
            first_name: str = "",
            last_name: str = "",
            ip_address: Optional[str] = None
    ) -> Tuple[bool, Optional[User], str]:
        """
        Register a new user.

        Args:
            username: The username for the new user
            email: The email address for the new user
            password: The password for the new user
            first_name: Optional first name
            last_name: Optional last name
            ip_address: The IP address of the registering client

        Returns:
            Tuple containing:
            - Boolean indicating if registration succeeded
            - User object if registration succeeded, None otherwise
            - Error message if registration failed, empty string otherwise
        """
        # Sanitize input
        username = sanitize_username(username)

        if not ip_address:
            ip_address = AuthService._get_client_ip()

        try:
            # Check if registration is allowed
            if not current_app.config.get('REGISTRATION_ENABLED', True):
                log_security_event(
                    event_type=AuditLog.EVENT_REGISTRATION_ATTEMPT,
                    description=f"Registration attempt when disabled: {username}",
                    severity="warning",
                    ip_address=ip_address
                )
                return False, None, "Registration is currently disabled"

            # Check if username exists
            if User.query.filter_by(username=username).first():
                # Track metric but don't reveal if username exists
                metrics.increment('security.registration_duplicate_username')
                return False, None, "Username already exists"

            # Check if email exists
            if User.query.filter_by(email=email).first():
                # Track metric but don't reveal if email exists
                metrics.increment('security.registration_duplicate_email')
                return False, None, "Email already exists"

            # Validate password strength
            is_valid, validation_message = validate_password(password)
            if not is_valid:
                metrics.increment('security.registration_weak_password')
                return False, None, validation_message or "Password does not meet security requirements"

            # Get initial status (default active or pending depending on configuration)
            initial_status = User.STATUS_PENDING
            if current_app.config.get('AUTO_ACTIVATE_USERS', True):
                initial_status = User.STATUS_ACTIVE

            # Create new user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                status=initial_status,
                created_at=datetime.now(timezone.utc)
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            # Log the successful registration
            log_security_event(
                event_type=AuditLog.EVENT_REGISTRATION,
                description=f"New user registered: {username}",
                severity="info",
                ip_address=ip_address,
                user_id=user.id
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_USER_CREATE,
                    target_resource="user",
                    target_id=str(user.id),
                    status="success",
                    ip_address=ip_address,
                    details={
                        "username": username,
                        "status": initial_status,
                        "auto_activated": current_app.config.get('AUTO_ACTIVATE_USERS', True)
                    },
                    severity="info"
                )

            # Send notification to admins about new user registration
            if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                notification_manager.send_to_stakeholders(
                    subject="New user registration",
                    message=f"New user '{username}' ({email}) has registered. Initial status: {initial_status}.",
                    level="info",
                    category=NOTIFICATION_CATEGORY_USER
                )

            current_app.logger.info("New user registered: %s (ID: %d)", username, user.id)
            metrics.increment('security.registration_successful')
            return True, user, ""

        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Error during user registration: %s", str(e))
            metrics.increment('security.registration_error')
            return False, None, "Registration failed due to system error"

    @staticmethod
    def login_user_session(user: User, remember: bool = False) -> Dict[str, Any]:
        """
        Set up user session after successful authentication.

        Args:
            user: The authenticated user object
            remember: Whether to enable "remember me" functionality

        Returns:
            Dict with session information
        """
        # Generate a unique session ID
        session_id = AuthService._generate_session_id()

        # Ensure session dictionary is set up properly
        session_data = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'permissions': user.get_all_permissions(),
            'session_id': session_id,
            'last_active': datetime.now(timezone.utc).isoformat(),
            'session_created': datetime.now(timezone.utc).isoformat(),
            'auth_method': 'password',  # Track authentication method used
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.user_agent.string if request and request.user_agent else None
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
            # Set default session timeout
            session_timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            current_app.permanent_session_lifetime = timedelta(minutes=session_timeout_minutes)

        # Create a session record in the database
        try:
            user_session = UserSession(
                user_id=user.id,
                session_id=session_id,
                ip_address=request.remote_addr if request else None,
                user_agent=request.user_agent.string if request and request.user_agent else None,
                fingerprint=AuthService._generate_browser_fingerprint(),
                login_method=UserSession.LOGIN_METHOD_PASSWORD,
                client_type=UserSession.SESSION_CLIENT_TYPE_WEB,
                is_active=True
            )
            db.session.add(user_session)
            db.session.commit()

            # Trim old sessions to prevent session buildup - use service constant if available
            AuthService._trim_old_sessions(user.id, max_sessions=AUTH_MAX_SESSIONS_PER_USER)

        except Exception as e:
            current_app.logger.error("Error recording user session: %s", str(e))
            # Continue anyway, this is not critical for user login

        current_app.logger.info("User logged in: %s (ID: %s)", user.username, user.id)
        return session_data

    @staticmethod
    def logout_user() -> bool:
        """
        Log out the current user by clearing their session.

        Returns:
            bool: True if logout was successful, False otherwise
        """
        try:
            # Get user info before clearing session
            user_id = session.get('user_id')
            username = session.get('username')
            session_id = session.get('session_id')
            ip_address = request.remote_addr if request else None

            if session_id:
                # Mark the session as inactive in the database
                try:
                    user_session = UserSession.query.filter_by(session_id=session_id).first()
                    if user_session:
                        user_session.is_active = False
                        user_session.ended_at = datetime.now(timezone.utc)
                        db.session.commit()
                except Exception as e:
                    current_app.logger.error("Error updating session record during logout: %s", str(e))
                    db.session.rollback()

            # Log the security event
            if user_id:
                log_security_event(
                    event_type=AuditLog.EVENT_LOGOUT,
                    description=f"User logged out: {username or 'Unknown'}",
                    severity="info",
                    user_id=user_id,
                    ip_address=ip_address
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user_id,
                        action=AuditService.EVENT_USER_LOGOUT,
                        target_resource="session",
                        target_id=session_id,
                        status="success",
                        ip_address=ip_address,
                        details={
                            "username": username
                        },
                        severity="info"
                    )

            # Clear session
            session.clear()

            if username:
                current_app.logger.info("User logged out: %s", username)
                metrics.increment('security.logout_successful')

            return True

        except Exception as e:
            current_app.logger.error("Error during logout: %s", str(e))
            metrics.increment('security.logout_error')
            # Still clear session even on error
            session.clear()
            return False

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
                    metrics.increment('security.session_timeout')
                    return False, "Session expired due to inactivity"

                # Check absolute session lifetime
                if 'session_created' in session:
                    created = datetime.fromisoformat(session['session_created'])
                    max_session_lifetime = current_app.config.get('MAX_SESSION_LIFETIME', 24)  # hours

                    if datetime.utcnow() - created > timedelta(hours=max_session_lifetime):
                        metrics.increment('security.session_max_lifetime')
                        return False, "Session expired (maximum duration)"

            except (ValueError, TypeError) as e:
                current_app.logger.warning("Invalid session timestamp: %s", str(e))
                metrics.increment('security.session_invalid_timestamp')
                return False, "Invalid session timestamp"

            # Check for session hijacking attempt by validating IP address if enabled
            if current_app.config.get('STRICT_SESSION_IP_BINDING', False):
                if session.get('ip_address') != (request.remote_addr if request else None):
                    log_security_event(
                        event_type=AuditLog.EVENT_SESSION_HIJACK_ATTEMPT,
                        description="Session IP address mismatch detected",
                        severity="warning",
                        user_id=session.get('user_id'),
                        ip_address=request.remote_addr if request else None,
                        details={
                            "session_ip": session.get('ip_address'),
                            "current_ip": request.remote_addr if request else None
                        }
                    )

                    # Add to audit log if available
                    if AUDIT_SERVICE_AVAILABLE:
                        AuditService.log_event(
                            user_id=session.get('user_id'),
                            action=AuditService.EVENT_SECURITY_ALERT,
                            target_resource="session",
                            target_id=session.get('session_id'),
                            status="hijacking_attempt",
                            ip_address=request.remote_addr if request else None,
                            details={
                                "reason": "ip_mismatch",
                                "session_ip": session.get('ip_address'),
                                "current_ip": request.remote_addr if request else None
                            },
                            severity="warning"
                        )

                    # Send security notification if available
                    if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                        # Apply optional notification delay to avoid alert fatigue
                        notification_manager.send_to_stakeholders(
                            subject="Possible session hijacking attempt",
                            message=(
                                f"Session hijacking attempt detected for user {session.get('username')}\n"
                                f"Session IP: {session.get('ip_address')}\n"
                                f"Current IP: {request.remote_addr if request else 'unknown'}"
                            ),
                            level="warning",
                            category=NOTIFICATION_CATEGORY_SECURITY
                        )

                    metrics.increment('security.session_ip_mismatch')
                    return False, "Session IP validation failed"

            # Check for browser fingerprint if enabled
            if current_app.config.get('ENABLE_BROWSER_FINGERPRINTING', True):
                current_fingerprint = AuthService._generate_browser_fingerprint()
                stored_fingerprint = session.get('browser_fingerprint')

                if stored_fingerprint and stored_fingerprint != current_fingerprint:
                    log_security_event(
                        event_type=AuditLog.EVENT_SESSION_HIJACK_ATTEMPT,
                        description="Session fingerprint mismatch detected",
                        severity="warning",
                        user_id=session.get('user_id'),
                        ip_address=request.remote_addr if request else None
                    )

                    # Add to audit log if available
                    if AUDIT_SERVICE_AVAILABLE:
                        AuditService.log_event(
                            user_id=session.get('user_id'),
                            action=AuditService.EVENT_SECURITY_ALERT,
                            target_resource="session",
                            target_id=session.get('session_id'),
                            status="hijacking_attempt",
                            ip_address=request.remote_addr if request else None,
                            details={
                                "reason": "fingerprint_mismatch"
                            },
                            severity="warning"
                        )

                    metrics.increment('security.session_fingerprint_mismatch')
                    return False, "Session validation failed"

        # Update last active time
        session['last_active'] = datetime.utcnow().isoformat()

        # Update session in database periodically (10% of requests)
        if session.get('session_id') and random.random() < 0.1:
            try:
                user_session = UserSession.query.filter_by(session_id=session.get('session_id')).first()
                if user_session:
                    user_session.record_activity(request.path if request else None)
                    db.session.commit()
            except Exception as e:
                current_app.logger.warning("Error updating session activity: %s", str(e))
                # Non-critical, continue without error

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

        # Log the token generation event
        log_security_event(
            event_type=AuditLog.EVENT_TOKEN_GENERATED,
            description=f"API token generated for user: {user.username}",
            severity="info",
            user_id=user.id,
            ip_address=request.remote_addr if request else None,
            details={
                "expires_in": expires_in,
                "scopes": scopes
            }
        )

        # Add to audit log if available
        if AUDIT_SERVICE_AVAILABLE:
            AuditService.log_event(
                user_id=user.id,
                action=AuditService.EVENT_API_KEY_CREATE,
                target_resource="api_token",
                status="success",
                ip_address=request.remote_addr if request else None,
                details={
                    "scopes": scopes,
                    "expires_in": expires_in
                },
                severity="info"
            )

        metrics.increment('security.api_token_generated')

        # Generate the token
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
            metrics.increment('security.api_token_missing')
            return False, None, "No token provided"

        result = User.verify_token(token)
        if not result:
            metrics.increment('security.api_token_invalid')
            return False, None, "Invalid or expired token"

        user, token_scopes = result

        if not user:
            metrics.increment('security.api_token_invalid_user')
            return False, None, "Invalid or expired token"

        # Check scopes if required
        if required_scopes:
            if not token_scopes:
                metrics.increment('security.api_token_no_scopes')
                return False, None, "Token has no scopes but scopes are required"

            if not all(scope in token_scopes for scope in required_scopes):
                metrics.increment('security.api_token_insufficient_scope')
                log_security_event(
                    event_type=AuditLog.EVENT_INSUFFICIENT_SCOPE,
                    description="Token with insufficient scope used",
                    severity="warning",
                    user_id=user.id,
                    ip_address=request.remote_addr if request else None,
                    details={
                        "required_scopes": required_scopes,
                        "token_scopes": token_scopes
                    }
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user.id,
                        action=AuditService.EVENT_ACCESS_DENIED,
                        target_resource="api",
                        status="insufficient_scope",
                        ip_address=request.remote_addr if request else None,
                        details={
                            "required_scopes": required_scopes,
                            "token_scopes": token_scopes
                        },
                        severity="warning"
                    )

                return False, None, "Token does not have required scopes"

        # Log successful token verification for sensitive operations
        if required_scopes and any(scope.startswith(('admin:', 'security:')) for scope in required_scopes):
            log_security_event(
                event_type=AuditLog.EVENT_TOKEN_VERIFIED,
                description="Privileged API token verified successfully",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None,
                details={
                    "scopes": token_scopes
                }
            )

        metrics.increment('security.api_token_valid')
        return True, user, ""

    @staticmethod
    def invalidate_token(token: str) -> bool:
        """
        Invalidate a JWT token.

        Args:
            token: The JWT token to invalidate

        Returns:
            Boolean indicating if invalidation succeeded
        """
        try:
            result = User.verify_token(token, verify_only=True)
            if not result:
                return False

            user, _ = result

            # Add token to blacklist
            from models.auth.token_blacklist import TokenBlacklist

            # Extract jti (JWT ID) from token
            import jwt

            try:
                secret = current_app.config['SECRET_KEY']
                decoded = jwt.decode(token, secret, algorithms=['HS256'])
                jti = decoded.get('jti')

                if not jti:
                    return False

                # Calculate expiration
                exp = decoded.get('exp')
                if not exp:
                    return False

                expires_at = datetime.fromtimestamp(exp, timezone.utc)

                # Add to blacklist
                blacklist_entry = TokenBlacklist(
                    jti=jti,
                    user_id=user.id,
                    expires_at=expires_at
                )
                db.session.add(blacklist_entry)
                db.session.commit()

                log_security_event(
                    event_type=AuditLog.EVENT_TOKEN_REVOKED,
                    description=f"API token revoked for user: {user.username}",
                    severity="info",
                    user_id=user.id,
                    ip_address=request.remote_addr if request else None
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user.id,
                        action=AuditService.EVENT_API_KEY_REVOKE,
                        target_resource="api_token",
                        target_id=jti,
                        status="success",
                        ip_address=request.remote_addr if request else None,
                        details={
                            "jti": jti,
                            "expires_at": expires_at.isoformat()
                        },
                        severity="info"
                    )

                metrics.increment('security.api_token_revoked')
                return True

            except (jwt.PyJWTError, KeyError) as e:
                current_app.logger.error(f"Error decoding token during invalidation: {str(e)}")
                return False

        except Exception as e:
            current_app.logger.error(f"Error invalidating token: {str(e)}")
            return False

    @staticmethod
    def extend_session() -> Dict[str, Any]:
        """
        Extend the current user session.

        Returns:
            Dict with information about the session extension
        """
        if 'user_id' not in session:
            return {'result': False, 'message': 'No active session'}

        result = {
            'result': True,
            'message': 'Session extended'
        }

        # Update last active time
        now = datetime.utcnow()
        session['last_active'] = now.isoformat()

        # Calculate new expiration time
        if session.permanent:
            lifetime_days = current_app.config.get('REMEMBER_ME_DAYS', 30)
            expires_at = now + timedelta(days=lifetime_days)
        else:
            session_timeout = current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            expires_at = now + timedelta(minutes=session_timeout)

        result['expires_at'] = expires_at

        # Periodically regenerate session ID with a 10% chance
        # This helps mitigate potential session hijacking while
        # avoiding excessive regeneration
        if random.random() < 0.1:
            AuthService._regenerate_session()
            result['regenerated'] = True

        # Update database record if relevant
        if session.get('session_id'):
            try:
                user_session = UserSession.query.filter_by(session_id=session.get('session_id')).first()
                if user_session:
                    user_session.extend_session()
                    db.session.commit()
            except Exception as e:
                current_app.logger.warning(f"Error extending session in database: {str(e)}")
                # Non-critical, continue without error

        metrics.increment('security.session_extended')
        return result

    @staticmethod
    def change_password(
        user_id: int,
        current_password: str,
        new_password: str
    ) -> Tuple[bool, str]:
        """
        Change a user's password with verification.

        Args:
            user_id: ID of the user
            current_password: Current password for verification
            new_password: New password to set

        Returns:
            Tuple of (success, message)
        """
        try:
            # Find the user
            user = User.query.get(user_id)
            if not user:
                metrics.increment('security.change_password_invalid_user')
                return False, "User not found"

            # Verify current password
            if not user.check_password(current_password):
                metrics.increment('security.change_password_invalid_current')
                # Log failed password change attempt
                log_security_event(
                    event_type=AuditLog.EVENT_PASSWORD_CHANGE_FAILED,
                    description="Failed password change - invalid current password",
                    severity="warning",
                    user_id=user.id,
                    ip_address=request.remote_addr if request else None
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user.id,
                        action=AuditService.EVENT_PASSWORD_CHANGE,
                        target_resource="user_password",
                        target_id=str(user.id),
                        status="failure",
                        ip_address=request.remote_addr if request else None,
                        details={
                            "reason": "invalid_current_password",
                            "username": user.username
                        },
                        severity="warning"
                    )

                return False, "Current password is incorrect"

            # Validate new password
            is_valid, validation_message = validate_password(new_password)
            if not is_valid:
                metrics.increment('security.change_password_invalid_new')
                return False, validation_message or "New password does not meet security requirements"

            # Check if new password is the same as current
            if user.check_password(new_password):
                metrics.increment('security.change_password_reuse')
                return False, "New password cannot be the same as the current password"

            # Check if this password was previously used (if history tracking is enabled)
            if hasattr(user, 'has_used_password') and user.has_used_password(new_password):
                metrics.increment('security.change_password_history')
                return False, "This password was used previously. Please choose a different password."

            # Update the password
            user.set_password(new_password)
            user.last_password_change = datetime.now(timezone.utc)

            # Clear any force password change flag
            if hasattr(user, 'force_password_change'):
                user.force_password_change = False

            # Store password in history if enabled
            if hasattr(user, 'add_password_to_history'):
                user.add_password_to_history()

            db.session.commit()

            # Invalidate all other sessions for security
            if current_app.config.get('INVALIDATE_SESSIONS_ON_PASSWORD_CHANGE', True):
                # Keep current session active
                current_session_id = session.get('session_id')
                AuthService._invalidate_all_sessions(user.id, exclude_session_id=current_session_id)

            # Log the password change
            log_security_event(
                event_type=AuditLog.EVENT_PASSWORD_CHANGED,
                description=f"Password changed for user: {user.username}",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_PASSWORD_CHANGE,
                    target_resource="user_password",
                    target_id=str(user.id),
                    status="success",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "username": user.username,
                        "sessions_invalidated": current_app.config.get('INVALIDATE_SESSIONS_ON_PASSWORD_CHANGE', True)
                    },
                    severity="info"
                )

            metrics.increment('security.change_password_success')
            return True, "Password changed successfully"

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error changing password: {str(e)}")
            metrics.increment('security.change_password_error')
            return False, "An error occurred while changing your password"

    @staticmethod
    def reset_password(token: str, new_password: str) -> Tuple[bool, str]:
        """
        Reset a user's password using a reset token.

        Args:
            token: Password reset token
            new_password: New password to set

        Returns:
            Tuple of (success, message)
        """
        try:
            # Validate password before checking token to prevent token enumeration attacks
            is_valid, validation_message = validate_password(new_password)
            if not is_valid:
                metrics.increment('security.reset_password_invalid')
                return False, validation_message or "Password does not meet security requirements"

            # Find user by reset token
            user = User.query.filter_by(password_reset_token=token).first()
            if not user:
                metrics.increment('security.reset_password_invalid_token')
                return False, "Invalid or expired password reset token"

            # Verify token is not expired
            if not user.password_reset_expires or user.password_reset_expires < datetime.now(timezone.utc):
                metrics.increment('security.reset_password_expired_token')
                return False, "Password reset token has expired"

            # Set new password
            user.set_password(new_password)
            user.last_password_change = datetime.now(timezone.utc)

            # Clear reset token and expiration
            user.password_reset_token = None
            user.password_reset_expires = None

            # Clear any force password change flag
            if hasattr(user, 'force_password_change'):
                user.force_password_change = False

            # Store in password history if enabled
            if hasattr(user, 'add_password_to_history'):
                user.add_password_to_history()

            db.session.commit()

            # Invalidate all sessions for security
            AuthService._invalidate_all_sessions(user.id)

            # Log the password reset
            log_security_event(
                event_type=AuditLog.EVENT_PASSWORD_RESET,
                description=f"Password reset completed for user: {user.username}",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_PASSWORD_RESET,
                    target_resource="user_password",
                    target_id=str(user.id),
                    status="success",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "username": user.username,
                        "sessions_invalidated": True
                    },
                    severity="info"
                )

            # Send notification to user about password reset
            if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                notification_manager.send(
                    subject="Your password has been reset",
                    body=f"Your password for {user.username} has been successfully reset. If you didn't request this change, please contact support immediately.",
                    level="info",
                    recipients=user.email,
                    tags={
                        "category": NOTIFICATION_CATEGORY_USER,
                        "event_type": "password_reset"
                    }
                )

            metrics.increment('security.reset_password_success')
            return True, "Password reset successful"

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error resetting password: {str(e)}")
            metrics.increment('security.reset_password_error')
            return False, "An error occurred while resetting your password"

    @staticmethod
    def verify_reset_token(token: str) -> Tuple[bool, Optional[int]]:
        """
        Verify if a password reset token is valid.

        Args:
            token: Password reset token to verify

        Returns:
            Tuple of (valid, user_id)
        """
        if not token or not isinstance(token, str):
            return False, None

        try:
            user = User.query.filter_by(password_reset_token=token).first()
            if not user:
                return False, None

            # Check if token is expired
            if not user.password_reset_expires or user.password_reset_expires < datetime.now(timezone.utc):
                return False, None

            return True, user.id

        except Exception as e:
            current_app.logger.error(f"Error verifying reset token: {str(e)}")
            return False, None

    @staticmethod
    def request_password_reset(email: str) -> Tuple[bool, str, Optional[str]]:
        """
        Generate a password reset token for a user.

        Args:
            email: Email address of the user

        Returns:
            Tuple of (success, message, token)
        """
        try:
            # Find user by email
            user = User.query.filter_by(email=email).first()
            if not user:
                # Return success but don't send email
                # This prevents email enumeration
                return True, "If your email address is registered, you will receive password reset instructions.", None

            # Check if user is active
            if user.status != User.STATUS_ACTIVE:
                # Return success but don't send email
                # This prevents account status enumeration
                return True, "If your email address is registered, you will receive password reset instructions.", None

            # Generate a secure token
            token = generate_secure_token()

            # Store token in user record with expiration
            expiration_hours = current_app.config.get('PASSWORD_RESET_EXPIRATION_HOURS', 24)
            user.password_reset_token = token
            user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=expiration_hours)
            db.session.commit()

            # Log the password reset request
            log_security_event(
                event_type=AuditLog.EVENT_PASSWORD_RESET_REQUESTED,
                description=f"Password reset requested for user: {user.username}",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_PASSWORD_RESET,
                    target_resource="user_password",
                    target_id=str(user.id),
                    status="requested",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "username": user.username,
                        "expiration_hours": expiration_hours
                    },
                    severity="info"
                )

            metrics.increment('security.password_reset_requested')
            return True, "Password reset instructions have been sent to your email address.", token

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error requesting password reset: {str(e)}")
            metrics.increment('security.password_reset_error')
            # Return success anyway to prevent enumeration
            return True, "If your email address is registered, you will receive password reset instructions.", None

    # MFA related methods

    @staticmethod
    def generate_totp_secret() -> str:
        """
        Generate a new TOTP secret for MFA setup.

        Returns:
            str: Base32 encoded secret ready for TOTP apps
        """
        return pyotp.random_base32()

    @staticmethod
    def get_totp_qr_code(username: str, secret: str) -> str:
        """
        Generate a QR code URL for TOTP setup.

        Args:
            username: Username for the account
            secret: TOTP secret

        Returns:
            str: URL for QR code image
        """
        issuer = current_app.config.get('MFA_TOTP_ISSUER', 'Cloud Platform')
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(username, issuer_name=issuer)

    @staticmethod
    def verify_totp_code(secret: str, code: str) -> bool:
        """
        Verify a TOTP verification code.

        Args:
            secret: TOTP secret
            code: Verification code from authenticator app

        Returns:
            bool: True if code is valid
        """
        if not secret or not code:
            return False

        # Clean the code (remove spaces and non-digits)
        code = ''.join(c for c in code if c.isdigit())

        # Verify code
        try:
            totp = pyotp.TOTP(secret)
            result = totp.verify(code)

            if not result:
                metrics.increment('security.mfa_code_invalid')

            return result
        except Exception as e:
            current_app.logger.error(f"Error verifying TOTP code: {str(e)}")
            metrics.increment('security.mfa_verify_error')
            return False

    @staticmethod
    def enable_totp_mfa(user_id: int, secret: str) -> bool:
        """
        Enable TOTP-based MFA for a user.

        Args:
            user_id: User ID
            secret: TOTP secret

        Returns:
            bool: True if MFA was enabled successfully
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False

            user.two_factor_enabled = True
            user.two_factor_secret = secret
            db.session.commit()

            # Log the MFA enablement
            log_security_event(
                event_type=AuditLog.EVENT_MFA_ENABLED,
                description=f"MFA enabled for user: {user.username}",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_MFA_CHANGE,
                    target_resource="user_mfa",
                    target_id=str(user.id),
                    status="enabled",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "username": user.username,
                        "mfa_type": "totp"
                    },
                    severity="info"
                )

            metrics.increment('security.mfa_enabled')
            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error enabling MFA: {str(e)}")
            metrics.increment('security.mfa_enable_error')
            return False

    @staticmethod
    def disable_mfa(user_id: int) -> bool:
        """
        Disable MFA for a user.

        Args:
            user_id: User ID

        Returns:
            bool: True if MFA was disabled successfully
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False

            # Store values for logging
            was_enabled = user.two_factor_enabled

            # Disable MFA
            user.two_factor_enabled = False
            user.two_factor_secret = None

            # Clear backup codes
            if hasattr(user, 'mfa_backup_codes'):
                user.mfa_backup_codes = None

            db.session.commit()

            # Only log if MFA was actually enabled
            if was_enabled:
                # Log the MFA disablement
                log_security_event(
                    event_type=AuditLog.EVENT_MFA_DISABLED,
                    description=f"MFA disabled for user: {user.username}",
                    severity="warning",
                    user_id=user.id,
                    ip_address=request.remote_addr if request else None
                )

                # Add to audit log if available
                if AUDIT_SERVICE_AVAILABLE:
                    AuditService.log_event(
                        user_id=user.id,
                        action=AuditService.EVENT_MFA_CHANGE,
                        target_resource="user_mfa",
                        target_id=str(user.id),
                        status="disabled",
                        ip_address=request.remote_addr if request else None,
                        details={
                            "username": user.username
                        },
                        severity="warning"
                    )

                # Send security notification if available
                if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED:
                    notification_manager.send_to_stakeholders(
                        subject=f"MFA disabled for user: {user.username}",
                        message=(
                            f"Multi-factor authentication has been disabled for user {user.username}.\n"
                            f"IP Address: {request.remote_addr if request else 'unknown'}\n"
                            "This may indicate a security risk if unexpected."
                        ),
                        level="warning",
                        category=NOTIFICATION_CATEGORY_SECURITY
                    )

                metrics.increment('security.mfa_disabled')

            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error disabling MFA: {str(e)}")
            metrics.increment('security.mfa_disable_error')
            return False

    @staticmethod
    def verify_mfa(user_id: int, verification_code: str, use_backup: bool = False) -> bool:
        """
        Verify MFA code during authentication.

        Args:
            user_id: User ID
            verification_code: TOTP code or backup code
            use_backup: Whether to check backup codes instead of TOTP

        Returns:
            bool: True if verification is successful
        """
        try:
            user = User.query.get(user_id)
            if not user or not user.two_factor_enabled:
                return False

            if use_backup:
                # Verify backup code
                if not hasattr(user, 'verify_backup_code'):
                    metrics.increment('security.mfa_backup_not_supported')
                    return False

                result = user.verify_backup_code(verification_code)
                if result:
                    # Log backup code usage
                    log_security_event(
                        event_type=AuditLog.EVENT_MFA_BACKUP_USED,
                        description=f"MFA backup code used for user: {user.username}",
                        severity="warning",
                        user_id=user.id,
                        ip_address=request.remote_addr if request else None
                    )

                    # Add to audit log if available
                    if AUDIT_SERVICE_AVAILABLE:
                        AuditService.log_event(
                            user_id=user.id,
                            action=AuditService.EVENT_MFA_CHANGE,
                            target_resource="user_mfa_verification",
                            target_id=str(user.id),
                            status="backup_used",
                            ip_address=request.remote_addr if request else None,
                            details={
                                "username": user.username,
                                "method": "backup_code"
                            },
                            severity="warning"
                        )

                    db.session.commit()
                    metrics.increment('security.mfa_backup_used')
                else:
                    metrics.increment('security.mfa_backup_invalid')

                return result
            else:
                # Verify TOTP code
                if not user.two_factor_secret:
                    return False

                result = AuthService.verify_totp_code(user.two_factor_secret, verification_code)
                if result:
                    # Add to audit log if available
                    if AUDIT_SERVICE_AVAILABLE:
                        AuditService.log_event(
                            user_id=user.id,
                            action=AuditService.EVENT_MFA_CHANGE,
                            target_resource="user_mfa_verification",
                            target_id=str(user.id),
                            status="success",
                            ip_address=request.remote_addr if request else None,
                            details={
                                "username": user.username,
                                "method": "totp"
                            },
                            severity="info"
                        )

                    metrics.increment('security.mfa_verified')

                return result

        except Exception as e:
            current_app.logger.error(f"Error verifying MFA: {str(e)}")
            metrics.increment('security.mfa_verify_error')
            return False

    @staticmethod
    def generate_backup_codes(user_id: int) -> List[str]:
        """
        Generate backup codes for MFA recovery.

        Args:
            user_id: User ID

        Returns:
            List[str]: List of backup codes
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return []

            # Check if user model supports backup codes
            if not hasattr(user, 'generate_backup_codes'):
                return []

            # Generate codes
            codes = user.generate_backup_codes()
            db.session.commit()

            # Log backup code generation
            log_security_event(
                event_type=AuditLog.EVENT_MFA_BACKUP_GENERATED,
                description=f"MFA backup codes generated for user: {user.username}",
                severity="info",
                user_id=user.id,
                ip_address=request.remote_addr if request else None
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user.id,
                    action=AuditService.EVENT_MFA_CHANGE,
                    target_resource="user_mfa_backup",
                    target_id=str(user.id),
                    status="generated",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "username": user.username,
                        "codes_count": len(codes) if codes else 0
                    },
                    severity="info"
                )

            metrics.increment('security.mfa_backup_generated')
            return codes
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error generating backup codes: {str(e)}")
            metrics.increment('security.mfa_backup_error')
            return []

    # Private methods

    @staticmethod
    def _regenerate_session() -> None:
        """
        Regenerate the session ID while preserving session data.
        This helps prevent session fixation attacks.
        """
        try:
            # Try using the core security implementation first
            if security_regenerate_session():
                return

            # Fallback to our own implementation
            # Store current session data
            session_data = dict(session)

            # Clear session and regenerate session ID
            session.clear()
            session.regenerate()

            # Restore session data
            for key, value in session_data.items():
                session[key] = value
        except Exception as e:
            # Log error but continue - this isn't critical
            current_app.logger.warning(f"Error regenerating session: {str(e)}")

    @staticmethod
    def _generate_session_id() -> str:
        """
        Generate a secure unique session ID.

        Returns:
            str: Secure random session ID
        """
        return str(uuid.uuid4())

    @staticmethod
    def _generate_browser_fingerprint() -> str:
        """
        Generate a fingerprint from browser headers.

        Returns:
            str: Browser fingerprint hash
        """
        if not request:
            return ""

        # Collect browser characteristics
        components = [
            request.user_agent.string if request.user_agent else "",
            request.accept_languages.to_header() if request.accept_languages else "",
            request.headers.get('Accept', ''),
            request.headers.get('Accept-Encoding', '')
        ]

        # Generate a hash
        fingerprint = hashlib.sha256('|'.join(components).encode()).hexdigest()
        return fingerprint

    @staticmethod
    def _is_new_location(user: User, ip_address: str) -> bool:
        """
        Check if this is a new login location for the user.

        Args:
            user: User object
            ip_address: Current IP address

        Returns:
            bool: True if this appears to be a new location
        """
        if not ip_address or not hasattr(UserSession, 'query'):
            return False

        try:
            # Check if this IP has been used before by this user
            previous_session = UserSession.query.filter_by(
                user_id=user.id,
                ip_address=ip_address
            ).first()

            # If no previous session from this IP, consider it new
            return previous_session is None
        except Exception as e:
            current_app.logger.warning(f"Error checking login location: {str(e)}")
            return False

    @staticmethod
    def _invalidate_all_sessions(user_id: int, exclude_session_id: str = None) -> int:
        """
        Invalidate all sessions for a user.

        Args:
            user_id: User ID
            exclude_session_id: Optional session ID to exclude from invalidation

        Returns:
            int: Number of sessions invalidated
        """
        try:
            # Build query
            query = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            )

            # Exclude current session if needed
            if exclude_session_id:
                query = query.filter(UserSession.session_id != exclude_session_id)

            # Update sessions
            count = query.update({
                'is_active': False,
                'revoked': True,
                'revocation_reason': 'security_action',
                'ended_at': datetime.now(timezone.utc)
            })

            db.session.commit()
            return count
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error invalidating sessions: {str(e)}")
            return 0

    @staticmethod
    def _trim_old_sessions(user_id: int, max_sessions: int = AUTH_MAX_SESSIONS_PER_USER) -> None:
        """
        Trim old sessions when a user has too many.

        Args:
            user_id: User ID
            max_sessions: Maximum number of active sessions to keep
        """
        try:
            # Get count of active sessions
            active_count = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).count()

            # If under the limit, do nothing
            if active_count <= max_sessions:
                return

            # Get IDs of oldest sessions to remove
            old_sessions = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).order_by(
                UserSession.created_at.asc()
            ).limit(active_count - max_sessions)

            # Mark old sessions as inactive
            for session in old_sessions:
                session.is_active = False
                session.revoked = True
                session.revocation_reason = 'session_limit_exceeded'
                session.ended_at = datetime.now(timezone.utc)

            db.session.commit()

            # Log the session trimming for security audit
            user = User.query.get(user_id)
            username = user.username if user else f"User #{user_id}"

            log_security_event(
                event_type=AuditLog.EVENT_SESSION_LIMIT,
                description=f"Old sessions trimmed for user: {username}",
                severity="info",
                user_id=user_id,
                details={
                    "max_sessions": max_sessions,
                    "sessions_removed": active_count - max_sessions
                }
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=user_id,
                    action="user.session.trim",
                    target_resource="user_sessions",
                    target_id=str(user_id),
                    status="success",
                    details={
                        "username": username,
                        "max_sessions": max_sessions,
                        "sessions_removed": active_count - max_sessions
                    },
                    severity="info"
                )

            # Track metric
            metrics.increment('security.sessions_trimmed')
            metrics.gauge('security.active_sessions_per_user', max_sessions, tags={"user_id": user_id})

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error trimming old sessions: {str(e)}")
            metrics.increment('security.session_trim_error')

    @staticmethod
    def _get_client_ip() -> str:
        """
        Get the client IP address from the request.
        Handles proxy forwarding.

        Returns:
            str: Client IP address
        """
        if not request:
            return ""

        # Check for forwarded IP (handle proxies)
        if request.headers.get('X-Forwarded-For'):
            # X-Forwarded-For format: client, proxy1, proxy2, ...
            # We want the client IP, which is the first one
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()

        return request.remote_addr or ""

    @staticmethod
    def get_active_sessions(user_id: int) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of session information dictionaries
        """
        try:
            sessions = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).order_by(UserSession.created_at.desc()).all()

            result = []
            for session in sessions:
                # Create a sanitized session info dict
                session_info = {
                    "id": session.id,
                    "session_id": session.session_id,
                    "created_at": session.created_at.isoformat() if session.created_at else None,
                    "last_active": session.last_active.isoformat() if session.last_active else None,
                    "ip_address": session.ip_address,
                    "client_type": session.client_type,
                    "device": session.get_device_info(),
                    "login_method": session.login_method,
                    "is_current": session.session_id == flask.session.get('session_id')
                }
                result.append(session_info)

            return result

        except Exception as e:
            current_app.logger.error(f"Error getting active sessions: {str(e)}")
            return []

    @staticmethod
    def revoke_session(user_id: int, session_id: str) -> bool:
        """
        Revoke a specific session.

        Args:
            user_id: User ID (for authorization check)
            session_id: Session ID to revoke

        Returns:
            bool: True if session was revoked
        """
        try:
            # Get the session
            session_record = UserSession.query.filter_by(
                session_id=session_id,
                is_active=True
            ).first()

            if not session_record:
                return False

            # Security check - ensure user can only revoke their own sessions
            # unless they have elevated permissions
            current_user_id = session.get('user_id')
            is_admin = session.get('role') == 'admin'

            if session_record.user_id != user_id and session_record.user_id != current_user_id and not is_admin:
                log_security_event(
                    event_type=AuditLog.EVENT_UNAUTHORIZED_ACCESS,
                    description=f"Unauthorized attempt to revoke session",
                    severity="warning",
                    user_id=current_user_id,
                    ip_address=request.remote_addr if request else None,
                    details={
                        "target_user_id": user_id,
                        "target_session_id": session_id
                    }
                )
                return False

            # Revoke the session
            session_record.is_active = False
            session_record.revoked = True
            session_record.revocation_reason = 'user_revoked'
            session_record.ended_at = datetime.now(timezone.utc)
            db.session.commit()

            # Log security event for successful revocation
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_REVOKED,
                description=f"Session revoked for user #{session_record.user_id}",
                severity="info",
                user_id=current_user_id,
                ip_address=request.remote_addr if request else None,
                details={
                    "revoked_session_id": session_id,
                    "target_user_id": session_record.user_id
                }
            )

            # Add to audit log if available
            if AUDIT_SERVICE_AVAILABLE:
                AuditService.log_event(
                    user_id=current_user_id,
                    action="user.session.revoke",
                    target_resource="user_session",
                    target_id=session_id,
                    status="success",
                    ip_address=request.remote_addr if request else None,
                    details={
                        "revoked_user_id": session_record.user_id,
                        "revoked_by_self": session_record.user_id == current_user_id
                    },
                    severity="info"
                )

            # Send security notification for suspicious session revocation
            # (if admin revoked someone else's session)
            if NOTIFICATION_AVAILABLE and AUTH_NOTIFICATION_ENABLED and is_admin and session_record.user_id != current_user_id:
                notification_manager.send(
                    subject="Your session was revoked by administrator",
                    body=f"One of your login sessions was revoked by an administrator at {datetime.now(timezone.utc).isoformat()}.",
                    level="info",
                    recipients=session_record.user_id,
                    tags={
                        "category": NOTIFICATION_CATEGORY_SECURITY,
                        "event_type": "session_revoked"
                    }
                )

            metrics.increment('security.session_revoked')
            return True

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error revoking session: {str(e)}")
            metrics.increment('security.session_revoke_error')
            return False

    @staticmethod
    def get_session_security_stats(user_id: int) -> Dict[str, Any]:
        """
        Get security statistics for user sessions.

        Args:
            user_id: User ID to get statistics for

        Returns:
            Dictionary with session security statistics
        """
        stats = {
            "active_sessions": 0,
            "locations": [],
            "devices": {},
            "suspicious_activity": False,
            "last_password_change": None,
            "mfa_enabled": False,
            "recent_ip_changes": False,
            "session_history": {
                "last_30_days": 0,
                "suspicious": 0
            }
        }

        try:
            # Get basic user info including security settings
            user = User.query.get(user_id)
            if not user:
                return stats

            # Add MFA status
            stats["mfa_enabled"] = user.two_factor_enabled if hasattr(user, "two_factor_enabled") else False

            # Add password change date
            if hasattr(user, "last_password_change") and user.last_password_change:
                stats["last_password_change"] = user.last_password_change.isoformat()

            # Get active sessions
            active_sessions = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).all()

            stats["active_sessions"] = len(active_sessions)

            # Get locations and devices
            locations = set()
            devices = {}

            for session in active_sessions:
                if session.ip_address:
                    locations.add(session.ip_address)

                device = session.get_device_info() if hasattr(session, "get_device_info") else session.user_agent
                device_type = device.get('type', 'unknown') if isinstance(device, dict) else 'unknown'

                if device_type not in devices:
                    devices[device_type] = 0
                devices[device_type] += 1

            stats["locations"] = list(locations)
            stats["devices"] = devices

            # Get session history statistics
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            recent_sessions = UserSession.query.filter(
                UserSession.user_id == user_id,
                UserSession.created_at >= thirty_days_ago
            ).all()

            stats["session_history"]["last_30_days"] = len(recent_sessions)
            stats["session_history"]["suspicious"] = len([
                s for s in recent_sessions if s.is_suspicious
            ])

            # Check for recent IP changes
            if len(active_sessions) > 1 and len(locations) > 1:
                stats["recent_ip_changes"] = True

            # Set suspicious activity flag if any suspicious sessions exist
            stats["suspicious_activity"] = any(s.is_suspicious for s in active_sessions if hasattr(s, "is_suspicious"))

            return stats

        except Exception as e:
            current_app.logger.error(f"Error getting session security stats: {str(e)}")
            return stats

    @classmethod
    def detect_suspicious_behavior(cls, user_id: int, ip_address: str = None) -> Dict[str, Any]:
        """
        Detect suspicious behavior for a user based on login patterns.

        Args:
            user_id: User ID to analyze
            ip_address: Current IP address (optional)

        Returns:
            Dictionary with suspicious behavior flags and details
        """
        result = {
            "suspicious": False,
            "reasons": [],
            "risk_level": "low",
            "details": {}
        }

        if not user_id:
            return result

        try:
            # Get the current IP if not provided
            if not ip_address and request:
                ip_address = cls._get_client_ip()

            # Get user's recent login history
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            recent_logins = UserSession.query.filter(
                UserSession.user_id == user_id,
                UserSession.created_at >= thirty_days_ago
            ).order_by(UserSession.created_at.desc()).all()

            if not recent_logins:
                # No history to analyze
                return result

            # Check for unusual login locations
            user_locations = set(s.ip_address for s in recent_logins if s.ip_address)

            # If current IP is new and we have history, that's potentially suspicious
            if ip_address and len(user_locations) > 0 and ip_address not in user_locations:
                result["suspicious"] = True
                result["reasons"].append("new_location")
                result["details"]["new_ip"] = ip_address
                result["details"]["known_ips"] = list(user_locations)

            # Check for rapid location changes
            if len(recent_logins) >= 2:
                recent_locations = []
                for session in recent_logins[:5]:  # Check the 5 most recent sessions
                    if session.ip_address:
                        recent_locations.append({
                            'ip': session.ip_address,
                            'time': session.created_at
                        })

                # Look for impossible travel (significant location changes in a short time)
                for i in range(len(recent_locations) - 1):
                    if recent_locations[i]['ip'] != recent_locations[i+1]['ip']:
                        time_diff = (recent_locations[i]['time'] - recent_locations[i+1]['time']).total_seconds() / 3600
                        if time_diff < 2:  # Less than 2 hours between logins from different IPs
                            result["suspicious"] = True
                            result["reasons"].append("impossible_travel")
                            result["risk_level"] = "high"
                            result["details"]["rapid_location_change"] = {
                                "ip1": recent_locations[i+1]['ip'],
                                "ip2": recent_locations[i]['ip'],
                                "hours_between": round(time_diff, 1)
                            }
                            break

            # Check for unusual time of day
            if hasattr(user_id, 'typical_login_times'):
                # This would be a more complex analysis based on user's normal patterns
                pass

            # Determine risk level based on number of suspicious factors
            if len(result["reasons"]) > 1:
                result["risk_level"] = "high"
            elif len(result["reasons"]) == 1 and "impossible_travel" not in result["reasons"]:
                result["risk_level"] = "medium"

            return result

        except Exception as e:
            current_app.logger.error(f"Error detecting suspicious behavior: {str(e)}")
            return result

    @staticmethod
    def check_password_reuse(user_id: int, new_password: str) -> bool:
        """
        Check if a password has been previously used by this user.

        Args:
            user_id: User ID
            new_password: Password to check for reuse

        Returns:
            True if password has been used before, False otherwise
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False

            # If the user model supports password history checking
            if hasattr(user, 'has_used_password'):
                return user.has_used_password(new_password)

            # Fallback to just checking current password
            return user.check_password(new_password)

        except Exception as e:
            current_app.logger.error(f"Error checking password reuse: {str(e)}")
            return False

    @staticmethod
    def get_login_history(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get login history for a user.

        Args:
            user_id: User ID
            limit: Maximum number of history entries to return

        Returns:
            List of login history entries
        """
        result = []

        try:
            sessions = UserSession.query.filter_by(
                user_id=user_id
            ).order_by(UserSession.created_at.desc()).limit(limit).all()

            for session in sessions:
                entry = {
                    "timestamp": session.created_at.isoformat() if session.created_at else None,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "success": True,  # All sessions were successful logins
                    "method": session.login_method,
                    "active": session.is_active,
                    "device_info": session.get_device_info() if hasattr(session, "get_device_info") else None
                }
                result.append(entry)

            # If audit service is available, also fetch failed login attempts
            if AUDIT_SERVICE_AVAILABLE and AuditService:
                failed_logins = AuditService.get_logs(
                    user_id=user_id,
                    action="user.login",
                    status="failure",
                    limit=limit,
                    order_by="timestamp",
                    order_direction="desc"
                )[0]  # First element is the list of logs

                for log in failed_logins:
                    entry = {
                        "timestamp": log.get("timestamp"),
                        "ip_address": log.get("ip_address"),
                        "user_agent": log.get("details", {}).get("user_agent"),
                        "success": False,
                        "method": log.get("details", {}).get("method", "password"),
                        "active": False,
                        "reason": log.get("details", {}).get("reason")
                    }
                    result.append(entry)

            # Sort combined results by timestamp (newest first)
            result.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

            # Limit to specified number
            return result[:limit]

        except Exception as e:
            current_app.logger.error(f"Error getting login history: {str(e)}")
            return result
