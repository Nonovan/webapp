"""
User session model for tracking active user sessions.

This module provides the UserSession model which tracks active user sessions across
the application. It's used for session management, concurrent session limiting,
and security monitoring of user activity.
"""

from datetime import datetime, timedelta
from typing import List
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

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

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    fingerprint = db.Column(db.String(64), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_active = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    ended_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Additional fields for cloud infrastructure monitoring
    cloud_region = db.Column(db.String(32), nullable=True)
    access_level = db.Column(db.String(16), nullable=True, default='standard')
    device_info = db.Column(db.JSON, nullable=True)
    client_type = db.Column(db.String(16), nullable=True, default='web')
    last_location = db.Column(db.String(128), nullable=True)

    # Relationship with User model
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic'))

    def __init__(self, user_id, session_id, ip_address=None, user_agent=None, 
                fingerprint=None, expires_at=None, is_active=True, cloud_region=None):
        """Initialize a new user session."""
        self.user_id = user_id
        self.session_id = session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.fingerprint = fingerprint
        self.is_active = is_active
        self.cloud_region = cloud_region

        if expires_at:
            self.expires_at = expires_at
        else:
            # Default expiration from config or 30 minutes
            session_lifetime = current_app.config.get('SESSION_LIFETIME_MINUTES', 30)
            self.expires_at = datetime.utcnow() + timedelta(minutes=session_lifetime)

    def is_valid(self, current_time=None) -> bool:
        """Check if session is valid (active and not expired)."""
        if current_time is None:
            current_time = datetime.utcnow()
        return self.is_active and self.expires_at > current_time

    def extend_session(self, minutes=None) -> bool:
        """Extend the session expiration time."""
        try:
            if minutes is None:
                minutes = current_app.config.get('SESSION_EXTEND_MINUTES', 30)

            self.last_active = datetime.utcnow()
            self.expires_at = datetime.utcnow() + timedelta(minutes=minutes)

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    def end_session(self) -> bool:
        """End this session."""
        try:
            self.is_active = False
            self.ended_at = datetime.utcnow()

            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    @classmethod
    def get_active_sessions_count(cls, minutes=15) -> int:
        """Get count of active sessions in the last X minutes."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return cls.query.filter(
            cls.is_active is True,
            cls.last_active >= cutoff
        ).count()

    @classmethod
    def get_active_sessions_by_user(cls, user_id) -> List["UserSession"]:
        """Get all active sessions for a specific user."""
        return cls.query.filter(
            cls.user_id == user_id,
            cls.is_active is True
        ).order_by(db.desc(cls.last_active)).all()

    @classmethod
    def cleanup_expired_sessions(cls) -> int:
        """Clean up expired sessions and return count of affected rows."""
        try:
            result = cls.query.filter(
                cls.is_active is True,
                cls.expires_at < datetime.utcnow()
            ).update({
                'is_active': False,
                'ended_at': datetime.utcnow()
            }, synchronize_session=False)

            db.session.commit()
            return result
        except SQLAlchemyError:
            db.session.rollback()
            return 0
