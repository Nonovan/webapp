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
    result = manager.extend_session(session)
    ```
"""

import uuid
import logging
from datetime import datetime, timedelta
import hashlib
from typing import Dict, Any, Tuple, Optional
from flask import current_app, request, has_request_context

from extensions import db, metrics
from models import UserSession
from models.security import AuditLog
from core.security import is_suspicious_ip, log_security_event


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
                 session_duration_minutes: int = None,
                 max_sessions_per_user: int = None,
                 enable_ip_binding: bool = None,
                 enable_fingerprint_binding: bool = None,
                 high_security_mode: bool = None):
        """
        Initialize a new SessionManager.

        Args:
            session_duration_minutes (int): Number of minutes to extend sessions by.
                                           Default from config or 30 minutes.
            max_sessions_per_user (int): Maximum number of concurrent sessions per user.
            enable_ip_binding (bool): Whether to bind sessions to IP addresses.
            enable_fingerprint_binding (bool): Whether to bind sessions to browser fingerprints.
            high_security_mode (bool): Whether to use stricter security settings.
        """
        # Use parameters if provided, otherwise fall back to config values
        config = current_app.config if has_request_context() else {}

        self.session_duration = timedelta(minutes=
            session_duration_minutes if session_duration_minutes is not None
            else config.get('SESSION_DURATION_MINUTES', 30))

        self.max_sessions_per_user = (
            max_sessions_per_user if max_sessions_per_user is not None
            else config.get('MAX_SESSIONS_PER_USER', 5))

        self.enable_ip_binding = (
            enable_ip_binding if enable_ip_binding is not None
            else config.get('ENABLE_SESSION_IP_BINDING', False))

        self.enable_fingerprint_binding = (
            enable_fingerprint_binding if enable_fingerprint_binding is not None
            else config.get('ENABLE_SESSION_FINGERPRINT_BINDING', True))

        self.high_security_mode = (
            high_security_mode if high_security_mode is not None
            else config.get('HIGH_SECURITY_MODE', False))

        # Set up logging
        self.logger = logging.getLogger(__name__)

    def extend_session(self, session_data: Dict[str, Any], request_obj=None) -> Dict[str, Any]:
        """
        Extend a user's session lifetime.

        This method validates the current session, extends its lifetime, and
        regenerates session tokens periodically for security. It also handles IP
        binding validation when enabled.

        Args:
            session_data: The current session dictionary
            request_obj: The request object containing IP and user agent info

        Returns:
            Dict containing the result:
                - success (bool): Whether the session was extended successfully
                - session (dict): The updated session data
                - expires_at (datetime): When the session will expire
                - message (str): Information about the session extension
        """
        result = {
            'success': False,
            'session': session_data,
            'expires_at': None,
            'message': 'Session extension failed'
        }

        if not session_data:
            self.logger.warning("Cannot extend empty session")
            result['message'] = 'Invalid session data'
            return result

        # Extract session information
        user_id = session_data.get('user_id')
        session_id = session_data.get('session_id')
        username = session_data.get('username')

        # Use request object if not provided but available in context
        if request_obj is None and has_request_context():
            request_obj = request

        if not user_id or not session_id:
            self.logger.warning("Attempt to extend invalid session")
            self._log_session_error(
                "Invalid session extension attempt",
                user_id=user_id,
                session_id=session_id,
                request_obj=request_obj,
                severity=AuditLog.SEVERITY_WARNING
            )
            result['message'] = 'Missing user_id or session_id'
            return result

        # Initialize db_session to avoid unbound variable error
        db_session = None

        # Check for session in database if we're using persistent sessions
        if current_app and current_app.config.get('SESSION_TYPE') != 'filesystem':
            try:
                db_session = UserSession.query.filter_by(
                    session_id=session_id,
                    user_id=user_id,
                    is_active=True
                ).first()

                if not db_session:
                    self.logger.warning("Session not found in database: %s", session_id)
                    self._log_session_error(
                        f"Session not found in database: {session_id}",
                        user_id=user_id,
                        session_id=session_id,
                        request_obj=request_obj,
                        severity=AuditLog.SEVERITY_WARNING
                    )
                    result['message'] = 'Session record not found'
                    return result

                # Check session expiration
                if db_session.expires_at and db_session.expires_at < datetime.utcnow():
                    self.logger.info("Session expired: %s for user %s", session_id, user_id)
                    db_session.is_active = False
                    db.session.commit()
                    result['message'] = 'Session expired'
                    return result

            except Exception as e:
                self.logger.error("Database error checking session: %s", str(e))
                # Continue with memory-based session

        # Validate IP binding if enabled
        if self.enable_ip_binding and request_obj:
            original_ip = session_data.get('ip_address')
            current_ip = request_obj.remote_addr

            if original_ip and original_ip != current_ip:
                self.logger.warning(
                    "IP address mismatch for session %s. Original: %s, Current: %s",
                    session_id, original_ip, current_ip
                )
                self._log_session_error(
                    f"IP address mismatch for session",
                    user_id=user_id,
                    session_id=session_id,
                    request_obj=request_obj,
                    severity=AuditLog.SEVERITY_WARNING,
                    details={
                        'original_ip': original_ip,
                        'current_ip': current_ip
                    }
                )
                result['message'] = 'IP address changed'
                return result

        # Validate fingerprint binding if enabled
        if self.enable_fingerprint_binding and request_obj:
            original_fp = session_data.get('fingerprint')
            current_fp = self._generate_fingerprint(request_obj)

            if original_fp and original_fp != current_fp:
                self.logger.warning("Browser fingerprint mismatch for session %s", session_id)
                self._log_session_error(
                    f"Browser fingerprint mismatch for session",
                    user_id=user_id,
                    session_id=session_id,
                    request_obj=request_obj,
                    severity=AuditLog.SEVERITY_WARNING
                )
                result['message'] = 'Browser fingerprint changed'
                return result

        # Check for suspicious IP
        if request_obj and is_suspicious_ip(request_obj.remote_addr):
            self.logger.warning("Session extension from suspicious IP: %s", request_obj.remote_addr)
            # We allow the extension but log it
            log_security_event(
                event_type=AuditLog.EVENT_SUSPICIOUS_ACCESS,
                description=f"Session extension from suspicious IP",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=user_id,
                ip_address=request_obj.remote_addr if request_obj else None,
                details={
                    'username': username,
                    'session_id': session_id
                }
            )

        # Determine if we should regenerate the session ID
        last_regenerated_str = session_data.get('last_regenerated')
        last_regenerated = None

        # Parse the last_regenerated timestamp
        if isinstance(last_regenerated_str, str):
            try:
                last_regenerated = datetime.fromisoformat(last_regenerated_str)
            except ValueError:
                last_regenerated = datetime.min
        elif isinstance(last_regenerated_str, datetime):
            last_regenerated = last_regenerated_str
        else:
            last_regenerated = datetime.min

        # Determine if regeneration is needed (every 30 minutes)
        should_regenerate = (datetime.utcnow() - last_regenerated) > timedelta(minutes=30)

        # Update session
        new_expires_at = datetime.utcnow() + self.session_duration

        if should_regenerate:
            # Generate a new session ID
            new_session_id = str(uuid.uuid4())

            # Update database if using persistent sessions
            if current_app and current_app.config.get('SESSION_TYPE') != 'filesystem' and db_session:
                try:
                    db_session.session_id = new_session_id
                    db_session.expires_at = new_expires_at
                    db_session.updated_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    self.logger.error("Error updating session in database: %s", str(e))
                    # Continue with memory-based session

            # Update the session dictionary
            session_data['session_id'] = new_session_id
            session_data['last_regenerated'] = datetime.utcnow().isoformat()
            session_data['expires_at'] = new_expires_at.isoformat()

            # Store additional security information
            if request_obj:
                session_data['ip_address'] = request_obj.remote_addr
                session_data['user_agent'] = self._get_user_agent(request_obj)
                session_data['fingerprint'] = self._generate_fingerprint(request_obj)

            self.logger.info("Regenerated session ID for user %s", user_id)

            # Track metrics
            if current_app and hasattr(current_app, 'metrics'):
                try:
                    metrics.gauge('security.session.regenerations', 1, labels={
                        'user_id': str(user_id)
                    })
                except Exception:
                    pass
        else:
            # Just extend the expiration
            session_data['expires_at'] = new_expires_at.isoformat()

            # Update database if using persistent sessions
            if current_app and current_app.config.get('SESSION_TYPE') != 'filesystem' and db_session:
                try:
                    db_session.expires_at = new_expires_at
                    db_session.updated_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    self.logger.error("Error extending session in database: %s", str(e))
                    # Continue with memory-based session

            self.logger.info("Extended session for user %s", user_id)

        # Prepare successful result
        result['success'] = True
        result['session'] = session_data
        result['expires_at'] = new_expires_at
        result['message'] = 'Session extended successfully'

        # Track metrics for successful extensions
        if current_app and hasattr(current_app, 'metrics'):
            try:
                metrics.info('security.session.extensions', 1, labels={
                    'user_id': str(user_id),
                    'regenerated': str(should_regenerate).lower()
                })
            except Exception:
                pass

        return result

    def validate_session(self, session_data: Dict[str, Any], request_obj=None) -> bool:
        """
        Validate that a session is active and legitimate.

        Args:
            session_data: The session dictionary to validate
            request_obj: The request object for additional validation

        Returns:
            bool: True if the session is valid, False otherwise
        """
        # Use request object if not provided but available in context
        if request_obj is None and has_request_context():
            request_obj = request

        # Basic validation
        user_id = session_data.get('user_id')
        session_id = session_data.get('session_id')
        expires_at_str = session_data.get('expires_at')

        if not user_id or not session_id or not expires_at_str:
            return False

        # Check expiration
        expires_at = None
        try:
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str)
            elif isinstance(expires_at_str, datetime):
                expires_at = expires_at_str

            if expires_at and expires_at < datetime.utcnow():
                return False
        except (ValueError, TypeError):
            # Handle invalid date format
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

    def create_session(self, user_id: int, username: str = None, request_obj=None) -> Dict[str, Any]:
        """
        Create a new session for a user.

        Args:
            user_id: The user ID to create a session for
            username: Optional username for logging
            request_obj: The request object for binding info

        Returns:
            Dict: New session information
        """
        # Use request object if not provided but available in context
        if request_obj is None and has_request_context():
            request_obj = request

        # Generate current timestamps
        now = datetime.utcnow()
        expires_at = now + self.session_duration

        new_session = {
            'user_id': user_id,
            'username': username,
            'session_id': str(uuid.uuid4()),
            'created_at': now.isoformat(),
            'last_regenerated': now.isoformat(),
            'expires_at': expires_at.isoformat()
        }

        # Add binding information if request provided
        if request_obj:
            new_session['ip_address'] = request_obj.remote_addr
            new_session['user_agent'] = self._get_user_agent(request_obj)
            new_session['fingerprint'] = self._generate_fingerprint(request_obj)

        # Store in database if using persistent sessions
        if current_app and current_app.config.get('SESSION_TYPE') != 'filesystem':
            try:
                # Enforce maximum sessions per user
                self._enforce_session_limits(user_id)

                # Create new session record
                db_session = UserSession(
                    user_id=user_id,
                    session_id=new_session['session_id'],
                    ip_address=new_session.get('ip_address'),
                    user_agent=new_session.get('user_agent'),
                    fingerprint=new_session.get('fingerprint'),
                    expires_at=expires_at,
                    is_active=True
                )
                db.session.add(db_session)
                db.session.commit()
            except Exception as e:
                self.logger.error("Error creating session in database: %s", str(e))
                # Continue with memory-based session

        # Log session creation
        self.logger.info("Created new session for user %s", user_id)

        # Track metrics
        if current_app and hasattr(current_app, 'metrics'):
            try:
                metrics.info('security.session.created', 1, labels={
                    'user_id': str(user_id)
                })
            except Exception:
                pass

        return new_session

    def invalidate_session(self, session_data: Dict[str, Any]) -> bool:
        """
        Invalidate a session both in memory and in the database.

        Args:
            session_data: The session data to invalidate

        Returns:
            bool: True if invalidation was successful, False otherwise
        """
        if not session_data:
            return False

        user_id = session_data.get('user_id')
        session_id = session_data.get('session_id')

        if not user_id or not session_id:
            return False

        # Invalidate in the database if possible
        if current_app and current_app.config.get('SESSION_TYPE') != 'filesystem':
            try:
                db_session = UserSession.query.filter_by(
                    session_id=session_id,
                    user_id=user_id,
                    is_active=True
                ).first()

                if db_session:
                    db_session.is_active = False
                    db_session.ended_at = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                self.logger.error("Error invalidating session in database: %s", str(e))

        # Clear session data
        session_data.clear()

        # Log invalidation
        self.logger.info("Invalidated session for user %s", user_id)

        # Track metrics
        if current_app and hasattr(current_app, 'metrics'):
            try:
                metrics.info('security.session.invalidated', 1, labels={
                    'user_id': str(user_id)
                })
            except Exception:
                pass

        return True

    def _enforce_session_limits(self, user_id: int) -> None:
        """
        Enforce the maximum number of sessions per user by invalidating old sessions.

        Args:
            user_id: The user ID to check sessions for
        """
        try:
            active_sessions = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).order_by(UserSession.created_at.asc()).all()

            # If we're over the limit, invalidate the oldest sessions
            if len(active_sessions) >= self.max_sessions_per_user:
                sessions_to_invalidate = active_sessions[:len(active_sessions) - self.max_sessions_per_user + 1]

                for old_session in sessions_to_invalidate:
                    old_session.is_active = False
                    old_session.ended_at = datetime.utcnow()
                    self.logger.info("Invalidating old session %s for user %s due to session limit",
                                     old_session.session_id, user_id)

                db.session.commit()

                # Log security event for multiple concurrent sessions
                if len(active_sessions) > self.max_sessions_per_user + 2:  # If significantly over limit
                    log_security_event(
                        event_type=AuditLog.EVENT_SESSION_LIMIT,
                        description=f"User exceeded maximum concurrent sessions ({len(active_sessions)})",
                        severity=AuditLog.SEVERITY_WARNING,
                        user_id=user_id,
                        details={
                            'active_sessions': len(active_sessions),
                            'max_allowed': self.max_sessions_per_user,
                            'invalidated': len(sessions_to_invalidate)
                        }
                    )

                # Track metrics
                if current_app and hasattr(current_app, 'metrics'):
                    try:
                        metrics.gauge('security.session.limit_triggered', 1, labels={
                            'user_id': str(user_id),
                            'count': str(len(active_sessions))
                        })
                    except Exception:
                        pass
        except Exception as e:
            self.logger.error("Error enforcing session limits: %s", str(e))

    def _generate_fingerprint(self, request_obj) -> str:
        """
        Generate a browser fingerprint based on request information.

        Args:
            request_obj: The request object

        Returns:
            str: A hash representing the browser fingerprint
        """
        try:
            components = [
                self._get_user_agent(request_obj),
                self._get_accept_languages(request_obj),
                self._get_accept_encodings(request_obj),
            ]

            # Add more components if in high security mode
            if self.high_security_mode:
                # Add additional headers that are typically consistent
                for header in ['Accept', 'Sec-Ch-Ua', 'Sec-Ch-Ua-Platform']:
                    if header in request_obj.headers:
                        components.append(request_obj.headers.get(header))

            fingerprint = hashlib.sha256(''.join([c for c in components if c]).encode()).hexdigest()
            return fingerprint
        except Exception as e:
            self.logger.error("Error generating fingerprint: %s", str(e))
            # Return a fallback fingerprint
            return hashlib.sha256(
                (request_obj.remote_addr + self._get_user_agent(request_obj)).encode()
            ).hexdigest()

    def _get_user_agent(self, request_obj) -> str:
        """
        Safely extract the user agent from a request.

        Args:
            request_obj: The request object

        Returns:
            str: User agent string
        """
        if not request_obj:
            return ""

        try:
            if hasattr(request_obj, 'user_agent'):
                if hasattr(request_obj.user_agent, 'string'):
                    return request_obj.user_agent.string
                return str(request_obj.user_agent)
            elif 'User-Agent' in request_obj.headers:
                return request_obj.headers.get('User-Agent')
            return ""
        except Exception:
            return ""

    def _get_accept_languages(self, request_obj) -> str:
        """
        Safely extract the accept languages from a request.

        Args:
            request_obj: The request object

        Returns:
            str: Accept languages string
        """
        if not request_obj:
            return ""

        try:
            if hasattr(request_obj, 'accept_languages') and hasattr(request_obj.accept_languages, 'to_header'):
                return request_obj.accept_languages.to_header()
            elif 'Accept-Language' in request_obj.headers:
                return request_obj.headers.get('Accept-Language')
            return ""
        except Exception:
            return ""

    def _get_accept_encodings(self, request_obj) -> str:
        """
        Safely extract the accept encodings from a request.

        Args:
            request_obj: The request object

        Returns:
            str: Accept encodings string
        """
        if not request_obj:
            return ""

        try:
            if hasattr(request_obj, 'accept_encodings') and hasattr(request_obj.accept_encodings, 'to_header'):
                return request_obj.accept_encodings.to_header()
            elif 'Accept-Encoding' in request_obj.headers:
                return request_obj.headers.get('Accept-Encoding')
            return ""
        except Exception:
            return ""

    def _log_session_error(self, message: str, user_id: Optional[int] = None,
                          session_id: Optional[str] = None, request_obj=None,
                          severity: str = AuditLog.SEVERITY_INFO,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a session error with appropriate metadata.

        Args:
            message: The error message
            user_id: User ID associated with the session
            session_id: Session ID
            request_obj: The request object for IP address
            severity: Severity level for the log
            details: Additional details to log
        """
        if details is None:
            details = {}

        if session_id:
            details['session_id'] = session_id

        log_security_event(
            event_type=AuditLog.EVENT_SESSION_ERROR,
            description=message,
            severity=severity,
            user_id=user_id,
            ip_address=request_obj.remote_addr if request_obj else None,
            details=details
        )
