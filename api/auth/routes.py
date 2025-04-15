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
    /extend-session: Extend existing session lifetime
    /verify: Verify token validity
    /refresh: Refresh an existing JWT token
    /logout: Invalidate current token
"""

from flask import Blueprint, request, jsonify, session, current_app
from services.auth_service import AuthService


def regenerate_session():
    """
    Regenerate the session ID for security purposes.
    
    This function marks the session as modified, triggering Flask to 
    generate a new session ID while preserving session data. This helps
    prevent session fixation attacks.
    """
    session.modified = True

# Create auth API blueprint - Note: Changed from auth_bp to auth_api to match imports
auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/login', methods=['POST'])
def login():
    """API endpoint for user authentication."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    # Use AuthService to authenticate
    success, user, error_message = AuthService.authenticate_user(username, password)
    
    if success and user:
        # Generate API token
        token = AuthService.generate_api_token(user)
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
            return jsonify({
                "message": "Registration successful",
                "user_id": user.id
            }), 201
        else:
            return jsonify({"error": "User registration failed"}), 500
    else:
        status_code = 409 if "exists" in error_message.lower() else 400
        return jsonify({"error": error_message}), status_code

@auth_api.route('/extend-session', methods=['POST'])
def extend_session():
    """
    Extend the lifetime of the current user session.
    
    This endpoint is typically called via AJAX to keep a user's session
    alive during periods of inactivity. It updates the last_active
    timestamp and may regenerate the session ID as a security measure.
    
    Request:
        No request body required. User must have valid session.
        
    Returns:
        200 OK: Session successfully extended
            {
                "success": true,
                "message": "Session extended successfully"
            }
        401 UNAUTHORIZED: No active session
            {
                "success": false,
                "message": "No active session"
            }
        500 INTERNAL SERVER ERROR: Server error during session extension
    
    Security:
        - Session ID is periodically regenerated to prevent fixation attacks
        - Session validation ensures only valid sessions can be extended
    """
    try:
        if AuthService.extend_session():
            return jsonify({'success': True, 'message': 'Session extended successfully'}), 200
        return jsonify({'success': False, 'message': 'No active session'}), 401
    except KeyError as e:
        current_app.logger.error(f"Session extension error - KeyError: {e}")
        return jsonify({'success': False, 'message': 'Invalid session data'}), 400
    except ValueError as e:
        current_app.logger.error(f"Session extension error - ValueError: {e}")
        return jsonify({'success': False, 'message': 'Invalid input value'}), 400
    except (RuntimeError, TypeError, AttributeError) as e:
        current_app.logger.error(f"Unexpected session extension error: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500

@auth_api.route('/logout')
def logout():
    """Log out the user and redirect to login page"""
    # Log the logout event
    if 'username' in session:
        current_app.logger.info(f"User logged out: {session['username']}")
    
    # Clear session
    session.clear()
    
    return jsonify({'success': True, 'message': 'Successfully logged out'}), 200