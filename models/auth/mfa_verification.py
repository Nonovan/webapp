"""
MFA verification tracking model for the Cloud Infrastructure Platform.

This module tracks multi-factor authentication verification attempts
to prevent bypass attacks and provide audit trail for security events.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.base import BaseModel

class MFAVerification(BaseModel):
    """Model for tracking MFA verification attempts."""

    __tablename__ = 'mfa_verifications'

    # Status constants
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_EXPIRED = 'expired'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                      nullable=False, index=True)
    mfa_method_id = db.Column(db.Integer, db.ForeignKey('mfa_methods.id', ondelete='SET NULL'),
                           nullable=True)
    verification_type = db.Column(db.String(20), nullable=False, index=True)  # 'totp', 'backup_code', etc.
    status = db.Column(db.String(20), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    session_id = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        nullable=False, index=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('mfa_verifications', lazy='dynamic'))
    mfa_method = db.relationship('MFAMethod', backref=db.backref('verifications', lazy='dynamic'))

    def __init__(self, user_id: int, verification_type: str, status: str,
                ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                session_id: Optional[str] = None, mfa_method_id: Optional[int] = None):
        """Initialize a new MFA verification record."""
        self.user_id = user_id
        self.verification_type = verification_type
        self.status = status
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id
        self.mfa_method_id = mfa_method_id

    @classmethod
    def log_verification(cls, user_id: int, verification_type: str, success: bool,
                       ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                       session_id: Optional[str] = None,
                       mfa_method_id: Optional[int] = None) -> Optional['MFAVerification']:
        """
        Log an MFA verification attempt.

        Args:
            user_id: ID of the user
            verification_type: Type of verification (totp, backup_code, etc.)
            success: Whether the verification was successful
            ip_address: Source IP address
            user_agent: User agent string
            session_id: Current session ID
            mfa_method_id: ID of the MFA method used

        Returns:
            Optional[MFAVerification]: The created verification record or None if error
        """
        try:
            status = cls.STATUS_SUCCESS if success else cls.STATUS_FAILED

            verification = cls(
                user_id=user_id,
                verification_type=verification_type,
                status=status,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                mfa_method_id=mfa_method_id
            )

            db.session.add(verification)
            db.session.commit()

            # Log security event for failed verifications
            if not success:
                from core.security_utils import log_security_event
                log_security_event(
                    'mfa_verification_failed',
                    f"Failed MFA verification for user ID: {user_id}, type: {verification_type}",
                    user_id=user_id,
                    severity="warning",
                    ip_address=ip_address,
                    details={
                        "verification_type": verification_type,
                        "mfa_method_id": mfa_method_id
                    }
                )

            return verification

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to log MFA verification: {str(e)}")
            return None

    @classmethod
    def get_recent_failures(cls, user_id: int, minutes: int = 15) -> int:
        """
        Get count of recent failed verification attempts.

        Args:
            user_id: User ID to check
            minutes: Timeframe in minutes to check

        Returns:
            int: Number of failed verification attempts
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return cls.query.filter(
            cls.user_id == user_id,
            cls.status == cls.STATUS_FAILED,
            cls.timestamp >= cutoff
        ).count()

    @classmethod
    def clear_old_verifications(cls, days: int = 90) -> int:
        """Remove old verification records."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            count = cls.query.filter(cls.timestamp < cutoff).delete(synchronize_session=False)
            db.session.commit()
            return count
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error clearing old MFA verifications: {str(e)}")
            return 0
