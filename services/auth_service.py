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
import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple, Union
from flask import current_app, session

from blueprints.auth.utils import validate_password
from models.user import User
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
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists
        if not user:
            return False, None, "Invalid username or password"
            
        # Check if account is locked
        if user.failed_login_count >= 5 and user.last_failed_login:
            lockout_time = user.last_failed_login + timedelta(minutes=15)
            if datetime.utcnow() < lockout_time:
                return False, None, "Account temporarily locked due to multiple failed attempts"
        
        # Verify password
        if not user.check_password(password):
            # Record failed login
            user.record_failed_login()
            db.session.commit()
            return False, None, "Invalid username or password"
            
        # Reset failed login counter on successful login
        user.failed_login_count = 0
        user.update_last_login()
        db.session.commit()
        
        return True, user, ""
    
    @staticmethod
    def register_user(username: str, email: str, password: str, 
                      first_name: str = "", last_name: str = "") -> Tuple[bool, Union[User, None], str]:
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
        
        return True, user, ""
    
    @staticmethod
    def login_user_session(user: User, remember: bool = False) -> None:
        """
        Set up user session after successful authentication.

        Args:
            user: The authenticated user object
            remember: Whether to enable "remember me" functionality
        """
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['last_active'] = datetime.utcnow().isoformat()
        
        # Regenerate session to prevent session fixation
        AuthService.regenerate_session()
        
        # Remember me functionality
        if remember:
            session.permanent = True
            current_app.permanent_session_lifetime = timedelta(days=30)
        
        current_app.logger.info(f"User logged in: {user.username} (ID: {user.id})")
    
    @staticmethod
    def logout_user() -> None:
        """
        Log out the current user by clearing their session.
        """
        if 'username' in session:
            username = session.get('username')
            current_app.logger.info(f"User logged out: {username}")
            
        # Clear session
        session.clear()
    
    @staticmethod
    def regenerate_session() -> None:
        """
        Regenerate the session to prevent session fixation attacks.
        
        This function preserves important session data while creating a new
        session ID, effectively preventing session fixation attacks.
        """
        # Save the important session values
        saved_data = {}
        keys_to_preserve = ['user_id', 'username', 'role', 'last_active', 'csrf_token']
        
        for key in keys_to_preserve:
            if key in session:
                saved_data[key] = session[key]
        
        # Clear the current session
        session.clear()
        
        # Generate a new session ID
        session['session_id'] = str(uuid.uuid4())
        
        # Restore the saved values
        for key, value in saved_data.items():
            session[key] = value
        
        # Generate new CSRF token
        if hasattr(current_app, 'csrf'):
            session['csrf_token'] = current_app.csrf.generate_csrf_token()
            
        # Log the event
        user_id = saved_data.get('user_id', 'unknown')
        current_app.logger.info(f"Session regenerated for user_id={user_id}")
    
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
                if datetime.utcnow() - last_active > timedelta(minutes=30):
                    return False, "Session expired"
            except (ValueError, TypeError):
                return False, "Invalid session timestamp"
        
        # Update last active time
        session['last_active'] = datetime.utcnow().isoformat()
        return True, None
    
    @staticmethod
    def generate_api_token(user: User, expires_in: int = 3600) -> str:
        """
        Generate a JWT token for API authentication.
        
        Args:
            user: The user to generate a token for
            expires_in: Token validity in seconds (default 1 hour)
            
        Returns:
            JWT token string
        """
        return user.generate_token(expires_in=expires_in)

    @staticmethod
    def verify_api_token(token: str) -> Tuple[bool, Optional[User], str]:
        """
        Verify a JWT token and return the associated user.
        
        Args:
            token: The JWT token to verify
            
        Returns:
            Tuple containing:
            - Boolean indicating if token is valid
            - User object if token is valid, None otherwise
            - Error message if token is invalid, empty string otherwise
        """
        user = User.verify_token(token)
        if not user:
            return False, None, "Invalid or expired token"
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
        
        # Periodically regenerate session ID
        if random.random() < 0.2:  # 20% chance
            AuthService.regenerate_session()
            
        return True