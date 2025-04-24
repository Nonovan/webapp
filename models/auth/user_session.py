"""
User session model for tracking active user sessions.

This module provides the UserSession model which tracks active user sessions across
the application. It's used for session management, concurrent session limiting,
and security monitoring of user activity.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Union
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
import logging

from extensions import db
from models.base import BaseModel

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
    """
    __tablename__ = 'user_sessions'

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

    # Constants
    SESSION_CLIENT_TYPE_WEB = 'web'
    SESSION_CLIENT_TYPE_MOBILE = 'mobile'
    SESSION_CLIENT_TYPE_API = 'api'
    SESSION_CLIENT_TYPE_CLI = 'cli'

    SESSION_ACCESS_LEVEL_STANDARD = 'standard'
    SESSION_ACCESS_LEVEL_ELEVATED = 'elevated'
    SESSION_ACCESS_LEVEL_ADMIN = 'admin'
    SESSION_ACCESS_LEVEL_READONLY = 'readonly'

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

    # Relationship with User model
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, user_id: int, session_id: str, ip_address: Optional[str] = None,
                user_agent: Optional[str] = None, fingerprint: Optional[str] = None,
                expires_at: Optional[datetime] = None, is_active: bool = True,
                cloud_region: Optional[str] = None, client_type: Optional[str] = None,
                access_level: Optional[str] = None) -> None:
        """
        Initialize a new user session.

        Args:
            user_id: The ID of the user owning this session
            session_id: Unique identifier for the session
            ip_address: IP address where the session originated
            user_agent: Browser/client user agent string
            fingerprint: Browser fingerprint hash for added security
            expires_at: When the session expires (uses config default if None)
            is_active: Whether the session is active
            cloud_region: Cloud region where the session is accessing from
            client_type: Type of client (web, mobile, api, cli)
            access_level: Access level for this session
        """
        self.user_id = user_id
        self.session_id = session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.fingerprint = fingerprint
        self.is_active = is_active
        self.cloud_region = cloud_region

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
            except RuntimeError:
                # Fallback if no app context
                self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

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
        return self.is_active and self.expires_at > current_time

    def extend_session(self, minutes: Optional[int] = None) -> bool:
        """
        Extend the session expiration time.

        Args:
            minutes: Number of minutes to extend (uses config default if None)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get session extension from config or use default
            if minutes is None:
                try:
                    minutes = current_app.config.get('SESSION_EXTEND_MINUTES', 30)
                except RuntimeError:
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
                current_app.logger.error("Failed to extend session %s: %s", self.session_id, str(e))
            return False

    def end_session(self) -> bool:
        """
        End this session by marking it as inactive.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_active = False
            self.ended_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error("Failed to end session %s: %s", self.session_id, str(e))
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
            self.device_info = device_info
            self.last_active = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error("Failed to update device info for session %s: %s",
                                        self.session_id, str(e))
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
            self.last_location = location
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error("Failed to update location for session %s: %s",
                                        self.session_id, str(e))
            return False

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
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_active': self.last_active.isoformat() if self.last_active else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'cloud_region': self.cloud_region,
            'access_level': self.access_level,
            'client_type': self.client_type,
            'last_location': self.last_location,
            'device_info': self.device_info
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
                cls.last_active >= cutoff
            ).count()
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error("Error counting active sessions: %s", str(e))
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
                cls.is_active == True  # Using == for SQLAlchemy comparison
            ).order_by(db.desc(cls.last_active)).all()
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error("Error retrieving sessions for user %s: %s",
                                        user_id, str(e))
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
                cls.is_active == True  # Using == for SQLAlchemy comparison
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
                current_app.logger.error("Failed to end sessions for user %s: %s", user_id, str(e))
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
                current_app.logger.error("Failed to cleanup expired sessions: %s", str(e))
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
                current_app.logger.error("Error retrieving session %s: %s", session_id, str(e))
            return None

    def __repr__(self) -> str:
        """String representation of the session."""
        return f'<UserSession id={self.id} user_id={self.user_id} session_id={self.session_id}>'
