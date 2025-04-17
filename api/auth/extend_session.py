"""
Session extension module for API authentication.

This module provides functionality for managing and extending session lifetimes
in the application. It handles the validation, extension, and regeneration of
user sessions to maintain both security and user experience.

The primary goals are:
1. Ensure sessions expire after periods of inactivity for security
2. Allow active users to maintain their sessions without disruption
3. Implement security best practices like session regeneration
4. Track session metrics for security auditing
5. Provide IP binding options for high-security environments

Classes:
    SessionManager: Handles all session lifetime management operations

Usage:
    To extend a session:
    
    ```
    manager = SessionManager()
    updated_session = manager.extend_session(session, request)
    ```
"""

import uuid
import logging
from datetime import datetime, timedelta
import hashlib
from typing import Dict, Any, Tuple
from flask import current_app, request

from extensions import db
from models.user_session import UserSession
from models.audit_log import AuditLog
from core.security_utils import log_security_event, is_suspicious_ip


class SessionManager:
    """
    Manages user session lifetimes and security.
    
    This class provides methods to validate, extend, and regenerate user sessions,
    implementing security best practices while maintaining a smooth user experience.
    
    Attributes:
        session_duration (timedelta): The amount of time a session should be extended
        max_sessions_per_user (int): Maximum number of concurrent sessions per user
        enable_ip_binding (bool): Whether to bind sessions to IP addresses
        enable_fingerprint_binding (bool): Whether to bind sessions to browser fingerprints
        high_security_mode (bool): Whether to use stricter security settings
    """

    def __init__(self, 
                 session_duration_minutes: int = 30,
                 max_sessions_per_user: int = 5,
                 enable_ip_binding: bool = False,
                 enable_fingerprint_binding: bool = True,
                 high_security_mode: bool = False):
        """
        Initialize a new SessionManager.
        
        Args:
            session_duration_minutes (int): Number of minutes to extend sessions by.
                                           Default is 30 minutes.
            max_sessions_per_user (int): Maximum number of concurrent sessions per user.
            enable_ip_binding (bool): Whether to bind sessions to IP addresses.
            enable_fingerprint_binding (bool): Whether to bind sessions to browser fingerprints.
            high_security_mode (bool): Whether to use stricter security settings.
        """
        self.session_duration = timedelta(minutes=session_duration_minutes)
        self.max_sessions_per_user = max_sessions_per_user
        self.enable_ip_binding = enable_ip_binding
        self.enable_fingerprint_binding = enable_fingerprint_binding
        self.high_security_mode = high_security_mode
        self.logger = logging.getLogger(__name__)

    def extend_session(self, session_data: Dict[str, Any], request_obj=None) -> Tuple[Dict[str, Any], bool]:
        """
        Extend a user's session lifetime.
        
        This method validates the current session, extends its lifetime, and
        regenerates session tokens periodically for security. It also handles IP
        binding validation when enabled.
        
        Args:
            session: The current session dictionary
            request_obj: The request object containing IP and user agent info
            
        Returns:
            Tuple containing the updated session and a boolean indicating success
            
        Raises:
            ValueError: If the session is invalid or has been tampered with
        """
        # Extract session information
        user_id = session_data.get('user_id')
        session_id = session_data.get('session_id')

        if not user_id or not session_id:
            self.logger.warning("Attempt to extend invalid session")
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_ERROR, 
                description="Invalid session extension attempt",
                severity=AuditLog.SEVERITY_WARNING,
                ip_address=request.remote_addr if request_obj else None
            )
            return session, False

        # Initialize db_session to avoid unbound variable error
        db_session = None

        # Check for session in database if we're using persistent sessions
        if current_app.config.get('SESSION_TYPE') != 'filesystem':
            db_session = UserSession.query.filter_by(
                session_id=session_id, 
                user_id=user_id, 
                is_active=True
            ).first()

            if not db_session:
                self.logger.warning("Session not found in database: %s", session_id)
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ERROR, 
                    description=f"Session not found in database: {session_id}",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=user_id,
                    ip_address=request.remote_addr if request_obj else None
                )
                return session, False

            # Check session expiration
            if db_session.expires_at and db_session.expires_at < datetime.utcnow():
                self.logger.info("Session expired: %s", session_id)
                db_session.is_active = False
                db.session.commit()
                return session, False

        # Validate IP binding if enabled
        if self.enable_ip_binding and request_obj:
            original_ip = session_data.get('ip_address')
            current_ip = request_obj.remote_addr

            if original_ip and original_ip != current_ip:
                self.logger.warning(
                    "IP address mismatch for session %s. Original: %s, Current: %s",
                    session_id, original_ip, current_ip
                )
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ERROR, 
                    description=f"IP address mismatch for session {session_id}",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=user_id,
                    ip_address=current_ip
                )
                return session, False

        # Validate fingerprint binding if enabled
        if self.enable_fingerprint_binding and request_obj:
            original_fp = session_data.get('fingerprint')
            current_fp = self._generate_fingerprint(request_obj)

            if original_fp and original_fp != current_fp:
                self.logger.warning("Browser fingerprint mismatch for session %s", session_id)
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ERROR, 
                    description=f"Browser fingerprint mismatch for session {session_id}",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=user_id,
                    ip_address=request.remote_addr if request_obj else None
                )
                return session, False

        # Check for suspicious IP
        if request_obj and is_suspicious_ip(request_obj.remote_addr):
            self.logger.warning("Session extension from suspicious IP: %s", request_obj.remote_addr)
            # We allow the extension but log it
            log_security_event(
                event_type=AuditLog.EVENT_SUSPICIOUS_ACCESS,
                description=f"Session extension from suspicious IP: {request_obj.remote_addr}",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=user_id,
                ip_address=request_obj.remote_addr
            )

        # Determine if we should regenerate the session ID (every 30 minutes)
        last_regenerated = session_data.get('last_regenerated', datetime.min)
        should_regenerate = (
            (datetime.utcnow() - last_regenerated) > timedelta(minutes=30)
            if isinstance(last_regenerated, datetime)
            else True
        )

        # Update session
        if should_regenerate:
            # Generate a new session ID
            new_session_id = str(uuid.uuid4())

            # Update database if using persistent sessions
            if current_app.config.get('SESSION_TYPE') != 'filesystem' and db_session:
                db_session.session_id = new_session_id
                db_session.expires_at = datetime.utcnow() + self.session_duration
                db_session.updated_at = datetime.utcnow()
                db.session.commit()

            # Update the session dictionary
            session_data['session_id'] = new_session_id
            session_data['last_regenerated'] = datetime.utcnow()
            session_data['expires_at'] = datetime.utcnow() + self.session_duration

            # Store additional security information
            if request_obj:
                session_data['ip_address'] = request_obj.remote_addr
                session_data['user_agent'] = request_obj.user_agent.string if hasattr(request_obj.user_agent, 'string') else str(request_obj.user_agent)
                session_data['fingerprint'] = self._generate_fingerprint(request_obj)

            self.logger.info("Regenerated session ID for user %s", user_id)
        else:
            # Just extend the expiration
            session['expires_at'] = datetime.utcnow() + self.session_duration

            # Update database if using persistent sessions
            if current_app.config.get('SESSION_TYPE') != 'filesystem' and 'db_session' in locals():
                db_session.expires_at = session['expires_at']
                db_session.updated_at = datetime.utcnow()
                db.session.commit()

            self.logger.info("Extended session for user %s", user_id)

        return session, True

    def validate_session(self, session_data: Dict[str, Any], request_obj=None) -> bool:
        """
        Validate that a session is active and legitimate.
        
        Args:
            session_data: The session dictionary to validate
            request_obj: The request object for additional validation
            
        Returns:
            bool: True if the session is valid, False otherwise
        """
        # Basic validation
        user_id = session_data.get('user_id')
        session_id = session_data.get('session_id')
        expires_at = session_data.get('expires_at')

        if not user_id or not session_id:
            return False

        # Check expiration
        if expires_at and isinstance(expires_at, datetime):
            if expires_at < datetime.utcnow():
                return False

        # Validate IP binding if enabled
        if self.enable_ip_binding and request_obj:
            original_ip = session_data.get('ip_address')
            current_ip = request_obj.remote_addr

            if original_ip and original_ip != current_ip:
                return False

        # Validate fingerprint binding if enabled
        if self.enable_fingerprint_binding and request_obj:
            original_fp = session_data.get('fingerprint')
            current_fp = self._generate_fingerprint(request_obj)
            
            if original_fp and original_fp != current_fp:
                return False

        return True

    def _generate_fingerprint(self, request_obj) -> str:
        """
        Generate a browser fingerprint based on request information.
        
        Args:
            request_obj: The request object
            
        Returns:
            str: A hash representing the browser fingerprint
        """
        components = [
            request_obj.user_agent.string if hasattr(request_obj.user_agent, 'string') else str(request_obj.user_agent),
            request_obj.accept_languages.to_header() if hasattr(request_obj, 'accept_languages') else '',
            request_obj.accept_encodings.to_header() if hasattr(request_obj, 'accept_encodings') else '',
        ]

        # Add more components if in high security mode
        if self.high_security_mode:
            # Add additional headers that are typically consistent
            for header in ['Accept', 'Sec-Ch-Ua', 'Sec-Ch-Ua-Platform']:
                if header in request_obj.headers:
                    components.append(request_obj.headers.get(header))

        fingerprint = hashlib.sha256(''.join(components).encode()).hexdigest()
        return fingerprint

    def create_session(self, user_id: int, request_obj=None) -> Dict[str, Any]:
        """
        Create a new session for a user.
        
        Args:
            user_id: The user ID to create a session for
            request_obj: The request object for binding info
            
        Returns:
            Dict: New session information
        """
        new_session = {
            'user_id': user_id,
            'session_id': str(uuid.uuid4()),
            'created_at': datetime.utcnow(),
            'last_regenerated': datetime.utcnow(),
            'expires_at': datetime.utcnow() + self.session_duration
        }

        # Add binding information if request provided
        if request_obj:
            new_session['ip_address'] = request_obj.remote_addr
            new_session['user_agent'] = request_obj.user_agent.string if hasattr(request_obj.user_agent, 'string') else str(request_obj.user_agent)
            new_session['fingerprint'] = self._generate_fingerprint(request_obj)

        # Store in database if using persistent sessions
        if current_app.config.get('SESSION_TYPE') != 'filesystem':
            # Enforce maximum sessions per user
            self._enforce_session_limits(user_id)

            # Create new session record
            db_session = UserSession(
                user_id=user_id,
                session_id=new_session['session_id'],
                ip_address=new_session.get('ip_address'),
                user_agent=new_session.get('user_agent'),
                fingerprint=new_session.get('fingerprint'),
                expires_at=new_session['expires_at'],
                is_active=True
            )
            db.session.add(db_session)
            db.session.commit()
            
        return session

    def _enforce_session_limits(self, user_id: int) -> None:
        """
        Enforce the maximum number of sessions per user by invalidating old sessions.
        
        Args:
            user_id: The user ID to check sessions for
        """
        active_sessions = UserSession.query.filter_by(
            user_id=user_id, 
            is_active=True
        ).order_by(UserSession.created_at.asc()).all()

        # If we're over the limit, invalidate the oldest sessions
        if len(active_sessions) >= self.max_sessions_per_user:
            sessions_to_invalidate = active_sessions[:len(active_sessions) - self.max_sessions_per_user + 1]

            for old_session in sessions_to_invalidate:
                old_session.is_active = False
                self.logger.info("Invalidating old session %s for user %s due to session limit", old_session.session_id, user_id)

            db.session.commit()

            # Log security event for multiple concurrent sessions
            if len(active_sessions) > self.max_sessions_per_user + 2:  # If significantly over limit
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_LIMIT_REACHED,
                    description=f"User {user_id} exceeded maximum concurrent sessions ({len(active_sessions)})",
                    severity=AuditLog.SEVERITY_WARNING,
                    user_id=user_id
                )

    def _regenerate_session_id(self, session_data):
        """
        Regenerates the session ID to prevent session fixation attacks.
        
        This private method creates a new session ID while preserving all other
        session data. This helps protect against session fixation attacks where
        an attacker might force a user to use a known session ID.
        
        Args:
            session (dict): The session dictionary to update with a new ID.
            
        Returns:
            dict: The updated session dictionary with a new session ID.
        """

        # Generate a new session ID
        session_data['session_id'] = str(uuid.uuid4())

        # Update the regeneration timestamp
        session_data['regenerated_at'] = datetime.now().isoformat()

        return session_data

    def is_valid(self, session_data):
        """
        Validates whether a session is still active and not expired.
        
        Args:
            session_data (dict): The session dictionary to validate.
            
        Returns:
            bool: True if the session is valid, False otherwise.
        """
        if not session_data or 'expires_at' not in session_data:
            return False

        try:
            expiration = datetime.fromisoformat(session_data['expires_at'])
            return datetime.now() < expiration
        except (ValueError, TypeError):
            # Handle invalid date format
            return False


# Example usage
if __name__ == "__main__":
    # Example demonstrating how to use the SessionManager class.
    # This creates a sample session, extends it, and prints the result.
    session = {
        "user_id": 123,
        "expires_at": (datetime.now() + timedelta(minutes=30)).isoformat()
    }

    manager = SessionManager(session_duration_minutes=15)
    updated_session = manager.extend_session(session)
    print("Updated session:", updated_session)

    # Demonstrate validation
    valid = manager.is_valid(updated_session)
    print(f"Session valid: {valid}")
