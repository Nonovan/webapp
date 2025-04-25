"""
API authentication routes for the application.

This module provides RESTful API endpoints for authentication operations including
login, registration, session management, and token validation. It uses the AuthService
for centralized authentication logic and security enforcement.

All endpoints return JSON responses with appropriate HTTP status codes and follow
REST best practices. Authentication is handled via JWT tokens for stateless API access.

Routes:
    /login: Authenticate user and issue JWT token
    /register: Create new user account
    /extend_session: Extend existing session lifetime
    /verify: Verify token validity
    /refresh: Refresh an existing JWT token
    /logout: Invalidate current token
"""

import json
import random
from datetime import datetime
from flask import Blueprint, request, jsonify, session, current_app, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError

from services.auth_service import AuthService
from core.security.cs_audit import log_security_event
from core.security.cs_utils import is_suspicious_ip
from extensions import db
from models.audit_log import AuditLog
from models.user_activity import UserActivity
from models.user_session import UserSession

# Initialize Limiter (ensure this matches your app's configuration)
limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def regenerate_session():
    """
    Regenerate the session ID for security purposes.

    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks.

    Note: This is a wrapper around the core security_utils implementation
    to maintain consistent session security across the application.
    """
    from core.security.cs_session import regenerate_session as core_regenerate_session
    core_regenerate_session()

# Create auth API blueprint
auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/login', methods=['POST'])
@limiter.limit("10/minute")
def login():
    """
    API endpoint for user authentication.

    Authenticates user credentials and issues a JWT token upon successful authentication.

    Request Body:
        {
            "username": "string",
            "password": "string"
        }

    Returns:
        200 OK: Authentication successful
            {
                "token": "jwt_token_string",
                "user": {
                    "id": int,
                    "username": "string",
                    "role": "string"
                }
            }
        400 BAD REQUEST: Missing credentials
        401 UNAUTHORIZED: Invalid credentials
        423 LOCKED: Account locked due to too many failed attempts
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    # Record login attempt IP for security monitoring
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    # Use AuthService to authenticate
    success, user, error_message = AuthService.authenticate_user(username, password, ip_address, user_agent)

    if success and user:
        # Generate API token
        token = AuthService.generate_api_token(user)

        # Log successful login event
        log_security_event(
            event_type=AuditLog.EVENT_LOGIN,
            description=f"User login successful: {username}",
            user_id=user.id,
            ip_address=ip_address,
            severity=AuditLog.SEVERITY_INFO,
            details={
                "method": "api",
                "user_agent": user_agent
            }
        )

        return jsonify({
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }), 200
    else:
        # Check if this is a lockout situation
        if "locked" in error_message.lower():
            return jsonify({"error": error_message, "locked": True}), 423  # 423 Locked status code
        else:
            return jsonify({"error": error_message}), 401

@auth_api.route('/register', methods=['POST'])
@limiter.limit("5/hour")
def register():
    """
    Register a new user account.

    This endpoint creates a new user account based on the information
    provided in the JSON request body. Password strength verification
    and duplicate username/email checks are performed.

    Request Body:
        {
            "username": "string",
            "email": "string",
            "password": "string",
            "first_name": "string", (optional)
            "last_name": "string"    (optional)
        }

    Returns:
        201 CREATED: Registration successful
            {
                "message": "Registration successful",
                "user_id": int
            }
        400 BAD REQUEST: Invalid or missing fields
        409 CONFLICT: Username or email already exists

    Security:
        - Password strength requirements are enforced
        - Email verification may be required depending on configuration
        - Rate limiting is applied to prevent abuse
    """
    # Handle user registration
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')

    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    # Use AuthService to register user
    success, user, error_message = AuthService.register_user(
        username, email, password, first_name, last_name
    )

    if success:
        if user:
            # Log successful registration
            log_security_event(
                event_type=AuditLog.EVENT_REGISTRATION,
                description=f"New user registered: {username}",
                user_id=user.id,
                ip_address=request.remote_addr,
                severity=AuditLog.SEVERITY_INFO
            )

            return jsonify({
                "message": "Registration successful",
                "user_id": user.id
            }), 201
        else:
            return jsonify({"error": "User registration failed"}), 500
    else:
        status_code = 409 if "exists" in error_message.lower() else 400
        return jsonify({"error": error_message}), status_code

@auth_api.route('/extend_session', methods=['POST'])
@limiter.limit("30/minute")
def extend_session():
    """
    Extend the current user's session.

    This endpoint is typically called via AJAX to keep a user's session
    alive during periods of inactivity. It updates the last_active
    timestamp and may regenerate the session ID as a security measure.

    Request:
        No request body required. User must have valid session.

    Returns:
        200 OK: Session successfully extended
            {
                "success": true,
                "message": "Session extended successfully",
                "expires_at": "2023-01-01T12:00:00Z"  // ISO format timestamp
            }
        401 UNAUTHORIZED: No active session
            {
                "success": false,
                "message": "No active session"
            }
        403 FORBIDDEN: Session extension denied
            {
                "success": false,
                "message": "Session extension denied"
            }
        500 INTERNAL SERVER ERROR: Server error during session extension

    Security:
        - Session ID is periodically regenerated to prevent fixation attacks
        - Session validation ensures only valid sessions can be extended
        - IP binding validation can optionally restrict session to original IP
        - Fingerprinting can detect browser/device changes during session
    """
    try:
        # Get user information for security logging
        user_id = session.get('user_id')
        username = session.get('username')

        # Validate user agent against session data to detect potential session hijacking
        current_user_agent = request.headers.get('User-Agent', '')
        session_user_agent = session.get('user_agent', '')

        if user_id and current_app.config.get('STRICT_SESSION_SECURITY', False):
            if session_user_agent and session_user_agent != current_user_agent:
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ERROR,
                    description="Session extension denied - User agent mismatch",
                    user_id=user_id,
                    ip_address=request.remote_addr,
                    severity=AuditLog.SEVERITY_WARNING,
                    details={
                        'expected_user_agent': session_user_agent,
                        'actual_user_agent': current_user_agent
                    }
                )
                return jsonify({'success': False, 'message': 'Session extension denied'}), 403

        # Check for suspicious IP address
        if user_id and is_suspicious_ip(request.remote_addr):
            log_security_event(
                event_type=AuditLog.EVENT_SUSPICIOUS_ACCESS,
                description=f"Session extension from suspicious IP: {request.remote_addr}",
                user_id=user_id,
                ip_address=request.remote_addr,
                severity=AuditLog.SEVERITY_WARNING
            )
            # We'll still extend but log the suspicious activity

        # Pass the request object to allow for IP validation if enabled
        extend_session_result = AuthService.extend_session()
        result = extend_session_result.get('result', False)
        expires_at = extend_session_result.get('expires_at', None)

        if result:
            # Also update the user's last active timestamp in database if logged in
            if user_id:
                UserActivity.update_last_active(user_id)

                # Log successful session extension (only occasionally to avoid flooding logs)
                if random.random() < 0.1:  # Log approximately 10% of extensions
                    current_app.logger.debug(f"Session extended for user: {username}")

            # Return success with expiration timestamp
            return jsonify({
                'success': True,
                'message': 'Session extended successfully',
                'expires_at': expires_at.isoformat() if expires_at else None
            }), 200

        # Session not found or expired
        return jsonify({'success': False, 'message': 'No active session'}), 401

    except KeyError as e:
        current_app.logger.error(f"Session extension error - KeyError: {e}")
        return jsonify({'success': False, 'message': 'Invalid session data'}), 400
    except ValueError as e:
        current_app.logger.error(f"Session extension error - ValueError: {e}")
        return jsonify({'success': False, 'message': 'Invalid input value'}), 400
    except (RuntimeError, TypeError, AttributeError) as e:
        current_app.logger.error(f"Unexpected session extension error: {e}")
        log_security_event(
            event_type=AuditLog.EVENT_SYSTEM_ERROR,
            description=f"Session extension system error: {str(e)}",
            user_id=session.get('user_id'),
            ip_address=request.remote_addr,
            severity=AuditLog.SEVERITY_ERROR
        )
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500

@auth_api.route('/verify', methods=['POST'])
@limiter.limit("60/minute")
def verify_token():
    """
    Verify a JWT token's validity.

    This endpoint checks if a provided token is valid, not expired, and belongs to an active user.

    Request Body:
        {
            "token": "string"
        }

    Returns:
        200 OK: Token is valid
            {
                "valid": true,
                "user": {
                    "id": int,
                    "username": "string",
                    "role": "string"
                }
            }
        401 UNAUTHORIZED: Invalid token
            {
                "valid": false,
                "error": "string"
            }
    """
    data = request.get_json()

    if not data:
        return jsonify({"valid": False, "error": "Invalid JSON"}), 400

    token = data.get('token')

    if not token:
        return jsonify({"valid": False, "error": "No token provided"}), 400

    # Verify the token
    is_valid, user_data, error = AuthService.verify_api_token(token)

    if is_valid:
        return jsonify({
            "valid": True,
            "user": user_data
        }), 200
    else:
        return jsonify({
            "valid": False,
            "error": error
        }), 401

@auth_api.route('/refresh', methods=['POST'])
@limiter.limit("20/minute")
def refresh_token():
    """
    Refresh an existing JWT token.

    This endpoint issues a new JWT token based on a valid refresh token.

    Request Body:
        {
            "refresh_token": "string"
        }

    Returns:
        200 OK: New token issued
            {
                "token": "string",
                "refresh_token": "string"
            }
        401 UNAUTHORIZED: Invalid refresh token
            {
                "error": "string"
            }
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({"error": "No refresh token provided"}), 400

    # Process token refresh
    success, new_token, new_refresh_token, error = AuthService.refresh_api_token(refresh_token)

    if success:
        return jsonify({
            "token": new_token,
            "refresh_token": new_refresh_token
        }), 200
    else:
        return jsonify({"error": error}), 401

@auth_api.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    Log out the user and invalidate their session.

    For GET requests, this redirects to the login page.
    For POST requests (API usage), this returns a JSON response.

    Returns:
        302 REDIRECT: Redirect to login page (GET requests)
        200 OK: Successfully logged out (POST requests)
    """
    # Get user information before clearing session
    user_id = session.get('user_id')
    username = session.get('username')
    session_id = session.get('session_id')

    # Record detailed logout information for security monitoring
    if user_id:
        log_security_event(
            event_type=AuditLog.EVENT_LOGOUT,
            description=f"User logged out: {username}",
            user_id=user_id,
            ip_address=request.remote_addr,
            severity=AuditLog.SEVERITY_INFO
        )

        # Also update user_sessions table if using persistent sessions
        if session_id:
            try:
                UserSession.query.filter_by(
                    user_id=user_id,
                    session_id=session_id,
                    is_active=True
                ).update({
                    'is_active': False,
                    'ended_at': datetime.utcnow()
                })
                db.session.commit()
            except SQLAlchemyError as e:
                current_app.logger.error(f"Failed to update session record: {e}")
                db.session.rollback()

    # Handle token invalidation for API requests
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        if token:
            AuthService.invalidate_token(token)

    # Clear session
    session.clear()

    # Return response based on request type
    if request.method == 'POST':
        return jsonify({'success': True, 'message': 'Successfully logged out'}), 200

    # Default to redirect for GET requests
    return redirect(url_for('auth.login'))
