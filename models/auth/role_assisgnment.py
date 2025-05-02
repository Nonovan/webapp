"""
Role assignment history model for the Cloud Infrastructure Platform.

This module provides tracking of role assignments and changes over time,
supporting audit requirements and temporary role assignments.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from flask import current_app, request
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event

class RoleAssignment(BaseModel, AuditableMixin):
    """
    Model to track role assignments and their history.

    Provides an audit trail of role changes and supports temporary role assignments.
    """

    __tablename__ = 'role_assignments'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['role_id', 'is_active', 'expires_at']

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                       nullable=False, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'),
                      nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                          nullable=True)

    # Assignment status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    reason = db.Column(db.String(255), nullable=True)  # Reason for assignment

    # Temporary assignments
    is_temporary = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Timestamps
    assigned_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                               nullable=True)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id],
                         backref=db.backref('role_assignments', lazy='dynamic'))
    role = db.relationship('Role')
    assigner = db.relationship('User', foreign_keys=[assigned_by])
    reviewer = db.relationship('User', foreign_keys=[last_reviewed_by])

    def __init__(self, user_id: int, role_id: int, assigned_by: Optional[int] = None,
               reason: Optional[str] = None, is_temporary: bool = False,
               expires_at: Optional[datetime] = None):
        """
        Initialize a new role assignment.

        Args:
            user_id: ID of the user receiving the role
            role_id: ID of the role being assigned
            assigned_by: ID of the user making the assignment (optional)
            reason: Reason for the assignment (optional)
            is_temporary: Whether this is a temporary assignment
            expires_at: When the assignment expires (for temporary assignments)
        """
        self.user_id = user_id
        self.role_id = role_id
        self.assigned_by = assigned_by
        self.reason = reason
        self.is_temporary = is_temporary
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        """Check if a temporary assignment has expired."""
        if not self.is_temporary or not self.expires_at:
            return False

        return datetime.now(timezone.utc) >= self.expires_at

    def is_valid(self) -> bool:
        """Check if the assignment is currently valid."""
        return self.is_active and not self.is_expired()

    def revoke(self, revoked_by: Optional[int] = None, reason: Optional[str] = None) -> bool:
        """
        Revoke this role assignment.

        Args:
            revoked_by: ID of the user revoking the assignment
            reason: Reason for revocation

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_active = False
            self.revoked_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event
            from core.security_utils import log_security_event
            log_security_event(
                'role_assignment_revoked',
                f"Role {self.role_id} revoked from user {self.user_id}",
                user_id=revoked_by,
                severity="info",
                details={
                    "user_id": self.user_id,
                    "role_id": self.role_id,
                    "reason": reason or "Not specified"
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to revoke role assignment: {str(e)}")
            return False

    def extend(self, new_expiry: datetime, extended_by: Optional[int] = None,
              reason: Optional[str] = None) -> bool:
        """
        Extend a temporary assignment.

        Args:
            new_expiry: New expiration date
            extended_by: ID of the user extending the assignment
            reason: Reason for extension

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_temporary:
            return False

        try:
            self.expires_at = new_expiry

            db.session.add(self)
            db.session.commit()

            # Log security event
            from core.security_utils import log_security_event
            log_security_event(
                'role_assignment_extended',
                f"Temporary role {self.role_id} extended for user {self.user_id}",
                user_id=extended_by,
                severity="info",
                details={
                    "user_id": self.user_id,
                    "role_id": self.role_id,
                    "new_expiry": new_expiry.isoformat(),
                    "reason": reason or "Not specified"
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to extend role assignment: {str(e)}")
            return False

    def mark_reviewed(self, reviewer_id: int) -> bool:
        """
        Mark this role assignment as reviewed.

        Args:
            reviewer_id: ID of the user performing the review

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.last_reviewed_at = datetime.now(timezone.utc)
            self.last_reviewed_by = reviewer_id

            db.session.add(self)
            db.session.commit()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to mark role assignment as reviewed: {str(e)}")
            return False

    @classmethod
    def get_active_for_user(cls, user_id: int) -> List['RoleAssignment']:
        """Get all active role assignments for a user."""
        now = datetime.now(timezone.utc)
        return cls.query.filter(
            cls.user_id == user_id,
            cls.is_active == True,
            db.or_(
                cls.is_temporary == False,
                db.and_(cls.is_temporary == True, cls.expires_at > now)
            )
        ).all()

    @classmethod
    def get_history_for_user(cls, user_id: int) -> List['RoleAssignment']:
        """Get full role assignment history for a user."""
        return cls.query.filter(
            cls.user_id == user_id
        ).order_by(cls.assigned_at.desc()).all()

    @classmethod
    def get_expiring_soon(cls, days: int = 7) -> List['RoleAssignment']:
        """Get temporary assignments expiring within specified days."""
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=days)

        return cls.query.filter(
            cls.is_active == True,
            cls.is_temporary == True,
            cls.expires_at <= cutoff,
            cls.expires_at > now
        ).all()

    @classmethod
    def cleanup_expired(cls) -> Tuple[int, int]:
        """
        Deactivate expired role assignments.

        Returns:
            Tuple[int, int]: (count_updated, error_count)
        """
        try:
            now = datetime.now(timezone.utc)
            expired = cls.query.filter(
                cls.is_active == True,
                cls.is_temporary == True,
                cls.expires_at <= now
            ).all()

            updated = 0
            errors = 0

            for assignment in expired:
                assignment.is_active = False
                assignment.revoked_at = now

                try:
                    db.session.add(assignment)
                    db.session.commit()
                    updated += 1

                    log_security_event(
                        'role_assignment_expired',
                        f"Temporary role {assignment.role_id} expired for user {assignment.user_id}",
                        severity="info",
                        details={
                            "user_id": assignment.user_id,
                            "role_id": assignment.role_id
                        }
                    )
                except SQLAlchemyError:
                    db.session.rollback()
                    errors += 1

            return updated, errors

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to cleanup expired role assignments: {str(e)}")
            return 0, 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'role_id': self.role_id,
            'assigned_by': self.assigned_by,
            'reason': self.reason,
            'is_active': self.is_active,
            'is_temporary': self.is_temporary,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'last_reviewed_at': self.last_reviewed_at.isoformat() if self.last_reviewed_at else None,
            'last_reviewed_by': self.last_reviewed_by
        }
