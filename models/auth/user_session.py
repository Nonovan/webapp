"""
User session model for tracking active user sessions.

This module provides the UserSession model which tracks active user sessions across
the application. It's used for session management, concurrent session limiting,
and security monitoring of user activity.

The session tracking system provides:
- Session lifecycle management (creation, extension, termination)
- Security monitoring for suspicious activity
- Concurrent session limiting
- Device fingerprinting
- Geographic location tracking
- Automatic cleanup of expired sessions
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Union, Tuple
import uuid
import hashlib
import json
from flask import current_app
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship
import logging

from extensions import db
from models.base import BaseModel
from core.security import log_security_event


class UserSession(BaseModel):
    """
    Model representing an active user session.

    This model tracks user sessions including their creation, expiration,
    and associated metadata like IP address and user agent. It's used for
    monitoring active users, enforcing session limits, and detecting
    potential session anomalies.

    Attributes:
        id: Primary key
        user_id: Foreign key to user
        session_id: Unique session identifier
        ip_address: IP address where session originated
        user_agent: Browser/client user agent string
        fingerprint: Browser fingerprint hash
        is_active: Whether the session is currently active
        created_at: When the session was created
        last_active: When the session was last accessed
        expires_at: When the session expires
        ended_at: When the session was explicitly ended
        cloud_region: AWS/Azure/GCP region the session is accessing
        access_level: User's access level during this session
        device_info: Additional device identification information
        client_type: Type of client (web, mobile, api)
        last_location: Geographic location based on IP (country/city)
        login_method: Method used for authentication
        revoked: Whether the session was explicitly revoked for security reasons
        revocation_reason: Reason for revocation if applicable
        is_suspicious: Flag for suspicious sessions based on anomaly detection
    """
    __tablename__ = 'user_sessions'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['is_active', 'access_level', 'is_suspicious', 'revoked']

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                       nullable=False, index=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Session metadata
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    fingerprint = db.Column(db.String(64), nullable=True)

    # Session state
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Timestamp fields with timezone awareness
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_active = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    ended_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Additional fields for cloud infrastructure monitoring
    cloud_region = db.Column(db.String(32), nullable=True)
    access_level = db.Column(db.String(16), nullable=True, default='standard')
    device_info = db.Column(db.JSON, nullable=True)
    client_type = db.Column(db.String(16), nullable=True, default='web')
    last_location = db.Column(db.String(128), nullable=True)

    # Security-related fields
    login_method = db.Column(db.String(20), nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    revocation_reason = db.Column(db.String(255), nullable=True)
    is_suspicious = db.Column(db.Boolean, default=False, nullable=False)

    # Activity tracking
    activity_count = db.Column(db.Integer, default=0, nullable=False)
    last_page_visited = db.Column(db.String(255), nullable=True)
    last_action = db.Column(db.String(64), nullable=True)

    # Constants
    SESSION_CLIENT_TYPE_WEB = 'web'
    SESSION_CLIENT_TYPE_MOBILE = 'mobile'
    SESSION_CLIENT_TYPE_API = 'api'
    SESSION_CLIENT_TYPE_CLI = 'cli'

    SESSION_ACCESS_LEVEL_STANDARD = 'standard'
    SESSION_ACCESS_LEVEL_ELEVATED = 'elevated'
    SESSION_ACCESS_LEVEL_ADMIN = 'admin'
    SESSION_ACCESS_LEVEL_READONLY = 'readonly'

    LOGIN_METHOD_PASSWORD = 'password'
    LOGIN_METHOD_SSO = 'sso'
    LOGIN_METHOD_MFA = 'mfa'
    LOGIN_METHOD_TOKEN = 'token'
    LOGIN_METHOD_API_KEY = 'api_key'

    REVOCATION_REASON_USER_REQUEST = 'user_request'
    REVOCATION_REASON_ADMIN_ACTION = 'admin_action'
    REVOCATION_REASON_SUSPICIOUS = 'suspicious_activity'
    REVOCATION_REASON_PASSWORD_CHANGE = 'password_change'
    REVOCATION_REASON_ROLE_CHANGE = 'role_change'
    REVOCATION_REASON_SYSTEM = 'system_action'

    VALID_CLIENT_TYPES = [
        SESSION_CLIENT_TYPE_WEB,
        SESSION_CLIENT_TYPE_MOBILE,
        SESSION_CLIENT_TYPE_API,
        SESSION_CLIENT_TYPE_CLI
    ]

    VALID_ACCESS_LEVELS = [
        SESSION_ACCESS_LEVEL_STANDARD,
        SESSION_ACCESS_LEVEL_ELEVATED,
        SESSION_ACCESS_LEVEL_ADMIN,
        SESSION_ACCESS_LEVEL_READONLY
    ]

    VALID_LOGIN_METHODS = [
        LOGIN_METHOD_PASSWORD,
        LOGIN_METHOD_SSO,
        LOGIN_METHOD_MFA,
        LOGIN_METHOD_TOKEN,
        LOGIN_METHOD_API_KEY
    ]

    # Relationship with User model
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, user_id: int, session_id: str = None, ip_address: Optional[str] = None,
                user_agent: Optional[str] = None, fingerprint: Optional[str] = None,
                expires_at: Optional[datetime] = None, is_active: bool = True,
                cloud_region: Optional[str] = None, client_type: Optional[str] = None,
                access_level: Optional[str] = None, login_method: Optional[str] = None,
                device_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a new user session.

        Args:
            user_id: The ID of the user owning this session
            session_id: Unique identifier for the session (auto-generated if None)
            ip_address: IP address where the session originated
            user_agent: Browser/client user agent string
            fingerprint: Browser fingerprint hash for added security
            expires_at: When the session expires (uses config default if None)
            is_active: Whether the session is active
            cloud_region: Cloud region where the session is accessing from
            client_type: Type of client (web, mobile, api, cli)
            access_level: Access level for this session
            login_method: Method used for authentication
            device_info: Additional device information as dictionary
        """
        self.user_id = user_id
        self.session_id = session_id or self._generate_session_id()
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.fingerprint = fingerprint
        self.is_active = is_active
        self.cloud_region = cloud_region
        self.login_method = login_method if login_method in self.VALID_LOGIN_METHODS else None
        self.device_info = device_info or {}
        self.activity_count = 0

        # Validate and set client type
        if client_type and client_type in self.VALID_CLIENT_TYPES:
            self.client_type = client_type
        else:
            self.client_type = self.SESSION_CLIENT_TYPE_WEB

        # Validate and set access level
        if access_level and access_level in self.VALID_ACCESS_LEVELS:
            self.access_level = access_level
        else:
            self.access_level = self.SESSION_ACCESS_LEVEL_STANDARD

        # Set expiration timestamp
        if expires_at:
            self.expires_at = expires_at
        else:
            try:
                # Default expiration from config or 30 minutes
                session_lifetime = current_app.config.get('SESSION_LIFETIME_MINUTES', 30)
                self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=session_lifetime)
            except (RuntimeError, AttributeError):
                # Fallback if no app context
                self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    @staticmethod
    def _generate_session_id() -> str:
        """
        Generate a secure unique session ID.

        Returns:
            str: Unique session identifier
        """
        # Use a combination of UUID and timestamp for uniqueness
        base = f"{uuid.uuid4().hex}{datetime.now(timezone.utc).timestamp()}"
        return hashlib.sha256(base.encode()).hexdigest()

    def is_valid(self, current_time: Optional[datetime] = None) -> bool:
        """
        Check if session is valid (active and not expired).

        Args:
            current_time: The time to compare against (default: current UTC time)

        Returns:
            bool: True if session is active and not expired, False otherwise
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)
        return self.is_active and not self.revoked and self.expires_at > current_time

    def extend_session(self, minutes: Optional[int] = None) -> bool:
        """
        Extend the session expiration time.

        Args:
            minutes: Number of minutes to extend (uses config default if None)

        Returns:
            bool: True if successful, False otherwise
        """
        if self.revoked:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(
                    f"Attempted to extend revoked session {self.session_id} for user {self.user_id}"
                )
            return False

        try:
            # Get session extension from config or use default
            if minutes is None:
                try:
                    minutes = current_app.config.get('SESSION_EXTEND_MINUTES', 30)
                except (RuntimeError, AttributeError):
                    # Fallback if no app context
                    minutes = 30

            current_time = datetime.now(timezone.utc)
            self.last_active = current_time
            self.expires_at = current_time + timedelta(minutes=minutes)

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to extend session {self.session_id}: {str(e)}")
            return False

    def record_activity(self, page: Optional[str] = None, action: Optional[str] = None) -> bool:
        """
        Record user activity to extend session and track analytics.

        Args:
            page: Page or endpoint being accessed
            action: Action being performed

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_active or self.revoked:
            return False

        try:
            current_time = datetime.now(timezone.utc)
            self.last_active = current_time
            self.activity_count += 1

            if page:
                self.last_page_visited = page
            if action:
                self.last_action = action

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Failed to record activity for session {self.session_id}: {str(e)}"
                )
            return False

    def end_session(self) -> bool:
        """
        End this session by marking it as inactive.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.is_active:
                return True  # Session already ended

            self.is_active = False
            self.ended_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log session end event
            self._log_session_event("session_ended", "User session ended normally")

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to end session {self.session_id}: {str(e)}")
            return False

    def revoke_session(self, reason: str = REVOCATION_REASON_SYSTEM) -> bool:
        """
        Revoke session explicitly for security purposes.

        Args:
            reason: Reason for revocation

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.revoked:
                return True  # Already revoked

            self.is_active = False
            self.revoked = True
            self.revocation_reason = reason
            self.ended_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event for session revocation
            self._log_session_event(
                "session_revoked",
                f"Session revoked: {reason}",
                "warning"
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to revoke session {self.session_id}: {str(e)}")
            return False

    def elevate_privileges(self, new_level: str) -> bool:
        """
        Elevate session privileges to a higher access level.

        Args:
            new_level: New access level to set

        Returns:
            bool: True if successful, False otherwise
        """
        if new_level not in self.VALID_ACCESS_LEVELS:
            return False

        try:
            old_level = self.access_level
            self.access_level = new_level
            self.last_active = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event for privilege elevation
            self._log_session_event(
                "session_privileges_changed",
                f"Session privileges changed from {old_level} to {new_level}",
                "warning"
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Failed to elevate privileges for session {self.session_id}: {str(e)}"
                )
            return False

    def flag_as_suspicious(self, reason: str = "Anomaly detected") -> bool:
        """
        Flag session as suspicious for security monitoring.

        Args:
            reason: Reason for flagging

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_suspicious = True

            db.session.add(self)
            db.session.commit()

            # Log security event
            self._log_session_event(
                "suspicious_session_flagged",
                f"Session flagged as suspicious: {reason}",
                "warning"
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Failed to flag suspicious session {self.session_id}: {str(e)}"
                )
            return False

    def update_device_info(self, device_info: Dict[str, Any]) -> bool:
        """
        Update device information for this session.

        Args:
            device_info: Dictionary with device details

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Merge new device info with existing (don't overwrite completely)
            current_info = self.device_info or {}
            updated_info = {**current_info, **device_info}

            self.device_info = updated_info
            self.last_active = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Failed to update device info for session {self.session_id}: {str(e)}"
                )
            return False

    def update_location(self, location: str) -> bool:
        """
        Update geographic location information.

        Args:
            location: String representing geographical location (e.g., "US/New York")

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            old_location = self.last_location
            self.last_location = location
            db.session.add(self)
            db.session.commit()

            # If location changed significantly, log it as it could be suspicious
            if old_location and old_location != location and self.is_active:
                self._log_session_event(
                    "session_location_changed",
                    f"Session location changed from {old_location} to {location}",
                    "info"
                )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Failed to update location for session {self.session_id}: {str(e)}"
                )
            return False

    def _log_session_event(self, event_type: str, description: str, severity: str = "info") -> None:
        """
        Log session event for security monitoring.

        Args:
            event_type: Type of event
            description: Event description
            severity: Event severity (info, warning, error)
        """
        try:
            log_security_event(
                event_type=event_type,
                description=description,
                severity=severity,
                details={
                    "session_id": self.session_id,
                    "user_id": self.user_id,
                    "ip_address": self.ip_address,
                    "user_agent": self.user_agent,
                    "access_level": self.access_level,
                    "client_type": self.client_type,
                    "location": self.last_location
                }
            )
        except Exception as e:
            # Fail silently but log if possible
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to log session event: {str(e)}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert session to dictionary representation.

        Returns:
            Dict: Session data in dictionary format
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'fingerprint': self.fingerprint,
            'is_active': self.is_active,
            'revoked': self.revoked,
            'revocation_reason': self.revocation_reason,
            'is_suspicious': self.is_suspicious,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_active': self.last_active.isoformat() if self.last_active else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'cloud_region': self.cloud_region,
            'access_level': self.access_level,
            'client_type': self.client_type,
            'last_location': self.last_location,
            'login_method': self.login_method,
            'device_info': self.device_info,
            'activity_count': self.activity_count,
            'last_page_visited': self.last_page_visited,
            'last_action': self.last_action,
            'is_valid': self.is_valid()
        }

    def to_safe_dict(self) -> Dict[str, Any]:
        """
        Convert session to dictionary with reduced sensitive information for user-facing contexts.

        Returns:
            Dict: Session data with limited fields
        """
        return {
            'session_id': self.session_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_active': self.last_active.isoformat() if self.last_active else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active,
            'client_type': self.client_type,
            'device_info': {
                'device': self.device_info.get('device') if self.device_info else None,
                'os': self.device_info.get('os') if self.device_info else None,
                'browser': self.device_info.get('browser') if self.device_info else None
            },
            'location': self.last_location
        }

    @classmethod
    def get_active_sessions_count(cls, minutes: int = 15) -> int:
        """
        Get count of active sessions in the last X minutes.

        Args:
            minutes: Number of minutes to look back

        Returns:
            int: Number of active sessions
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            return cls.query.filter(
                cls.is_active == True,  # Using == for SQLAlchemy comparison
                cls.revoked == False,
                cls.last_active >= cutoff
            ).count()
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error counting active sessions: {str(e)}")
            return 0

    @classmethod
    def get_active_sessions_by_user(cls, user_id: int) -> List["UserSession"]:
        """
        Get all active sessions for a specific user.

        Args:
            user_id: User ID to query sessions for

        Returns:
            List[UserSession]: List of active user sessions
        """
        try:
            return cls.query.filter(
                cls.user_id == user_id,
                cls.is_active == True,  # Using == for SQLAlchemy comparison
                cls.revoked == False
            ).order_by(db.desc(cls.last_active)).all()
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error retrieving sessions for user {user_id}: {str(e)}")
            return []

    @classmethod
    def end_all_sessions_for_user(cls, user_id: int,
                                 exclude_session_id: Optional[str] = None) -> int:
        """
        End all active sessions for a user, optionally excluding one session.

        Args:
            user_id: User ID to end sessions for
            exclude_session_id: Session ID to exclude from ending (e.g., current session)

        Returns:
            int: Number of sessions ended
        """
        try:
            query = cls.query.filter(
                cls.user_id == user_id,
                cls.is_active == True,  # Using == for SQLAlchemy comparison
                cls.revoked == False
            )

            if exclude_session_id:
                query = query.filter(cls.session_id != exclude_session_id)

            current_time = datetime.now(timezone.utc)
            result = query.update({
                'is_active': False,
                'ended_at': current_time
            }, synchronize_session=False)

            db.session.commit()
            return result
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to end sessions for user {user_id}: {str(e)}")
            return 0

    @classmethod
    def revoke_all_sessions_for_user(cls, user_id: int, reason: str,
                                 exclude_session_id: Optional[str] = None) -> int:
        """
        Revoke all active sessions for a user, optionally excluding one session.

        Args:
            user_id: User ID to revoke sessions for
            reason: Reason for revocation
            exclude_session_id: Session ID to exclude from revoking (e.g., current session)

        Returns:
            int: Number of sessions revoked
        """
        try:
            query = cls.query.filter(
                cls.user_id == user_id,
                cls.is_active == True,  # Using == for SQLAlchemy comparison
                cls.revoked == False
            )

            if exclude_session_id:
                query = query.filter(cls.session_id != exclude_session_id)

            current_time = datetime.now(timezone.utc)
            result = query.update({
                'is_active': False,
                'revoked': True,
                'revocation_reason': reason,
                'ended_at': current_time
            }, synchronize_session=False)

            db.session.commit()

            # Log security event for mass session revocation
            if result > 0:
                try:
                    log_security_event(
                        event_type="user_sessions_revoked",
                        description=f"All sessions revoked for user {user_id}: {reason}",
                        severity="warning",
                        details={
                            "user_id": user_id,
                            "sessions_revoked": result,
                            "reason": reason,
                            "excluded_session": exclude_session_id
                        }
                    )
                except Exception:
                    pass  # Don't let logging failure break the operation

            return result
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to revoke sessions for user {user_id}: {str(e)}")
            return 0

    @classmethod
    def cleanup_expired_sessions(cls) -> int:
        """
        Clean up expired sessions and return count of affected rows.

        Returns:
            int: Number of sessions cleaned up
        """
        try:
            current_time = datetime.now(timezone.utc)
            result = cls.query.filter(
                cls.is_active == True,  # Using == for SQLAlchemy comparison
                cls.expires_at < current_time
            ).update({
                'is_active': False,
                'ended_at': current_time
            }, synchronize_session=False)

            db.session.commit()
            return result
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to cleanup expired sessions: {str(e)}")
            return 0

    @classmethod
    def get_session_by_id(cls, session_id: str) -> Optional["UserSession"]:
        """
        Get session by session ID.

        Args:
            session_id: Unique session identifier

        Returns:
            Optional[UserSession]: Session if found, None otherwise
        """
        try:
            return cls.query.filter(cls.session_id == session_id).first()
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error retrieving session {session_id}: {str(e)}")
            return None

    @classmethod
    def get_user_session_stats(cls, user_id: int) -> Dict[str, Any]:
        """
        Get session statistics for a specific user.

        Args:
            user_id: User ID to get statistics for

        Returns:
            Dict: Dictionary with session statistics
        """
        try:
            # Get total session count
            total_sessions = cls.query.filter(cls.user_id == user_id).count()

            # Get active sessions
            active_sessions = cls.query.filter(
                cls.user_id == user_id,
                cls.is_active == True,
                cls.revoked == False
            ).count()

            # Get last activity time
            latest_session = cls.query.filter(
                cls.user_id == user_id
            ).order_by(db.desc(cls.last_active)).first()

            # Get count by client type
            client_counts = {}
            for client_type in cls.VALID_CLIENT_TYPES:
                count = cls.query.filter(
                    cls.user_id == user_id,
                    cls.client_type == client_type
                ).count()
                if count > 0:
                    client_counts[client_type] = count

            # Check for suspicious activity
            suspicious_sessions = cls.query.filter(
                cls.user_id == user_id,
                cls.is_suspicious == True
            ).count()

            return {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'suspicious_sessions': suspicious_sessions,
                'last_activity': latest_session.last_active.isoformat() if latest_session else None,
                'client_types': client_counts
            }
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error getting session stats for user {user_id}: {str(e)}")
            return {
                'total_sessions': 0,
                'active_sessions': 0,
                'suspicious_sessions': 0
            }

    @classmethod
    def check_concurrent_sessions(cls, user_id: int, max_sessions: int = 5) -> Tuple[bool, int]:
        """
        Check if a user has too many concurrent active sessions.

        Args:
            user_id: User ID to check
            max_sessions: Maximum allowed concurrent sessions

        Returns:
            Tuple[bool, int]: (has_too_many, current_count)
        """
        try:
            active_count = cls.query.filter(
                cls.user_id == user_id,
                cls.is_active == True,
                cls.revoked == False
            ).count()

            return (active_count >= max_sessions, active_count)
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Error checking concurrent sessions for user {user_id}: {str(e)}"
                )
            # Be conservative and assume too many sessions on error
            return (True, max_sessions)

    @classmethod
    def detect_suspicious_sessions(cls, user_id: int) -> List["UserSession"]:
        """
        Detect potentially suspicious sessions for a user.

        This looks for multiple sessions from different locations,
        unusual client types, or unusual activity patterns.

        Args:
            user_id: User ID to check

        Returns:
            List[UserSession]: List of suspicious sessions
        """
        try:
            suspicious_sessions = []
            active_sessions = cls.get_active_sessions_by_user(user_id)

            if not active_sessions:
                return []

            # Get most common location
            locations = {}
            for session in active_sessions:
                if session.last_location:
                    locations[session.last_location] = locations.get(session.last_location, 0) + 1

            common_location = max(locations.items(), key=lambda x: x[1])[0] if locations else None

            # Check each session for suspicious attributes
            for session in active_sessions:
                # Different location than most common
                if (common_location and session.last_location and
                    session.last_location != common_location):
                    suspicious_sessions.append(session)
                    continue

                # API or CLI access from web-only user
                if session.client_type in (cls.SESSION_CLIENT_TYPE_API, cls.SESSION_CLIENT_TYPE_CLI):
                    # Check if user normally uses these client types
                    # This would need to reference user profile or history
                    suspicious_sessions.append(session)
                    continue

                # Check for concurrent admin access
                if (session.access_level == cls.SESSION_ACCESS_LEVEL_ADMIN and
                    sum(1 for s in active_sessions if s.access_level == cls.SESSION_ACCESS_LEVEL_ADMIN) > 1):
                    suspicious_sessions.append(session)
                    continue

            return suspicious_sessions
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(
                    f"Error detecting suspicious sessions for user {user_id}: {str(e)}"
                )
            return []

    def __repr__(self) -> str:
        """String representation of the session."""
        status = "active" if self.is_active else "inactive"
        if self.revoked:
            status = "revoked"
        elif self.is_suspicious:
            status = "suspicious"

        return f'<UserSession id={self.id} user_id={self.user_id} status={status}>'
